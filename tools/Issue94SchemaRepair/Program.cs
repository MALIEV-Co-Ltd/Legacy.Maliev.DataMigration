using System.Data;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration;
using Npgsql;

if (args.Length != 3 || args[1] is not ("local" or "production"))
{
    throw new InvalidOperationException("Expected owner-only run directory, local|production, and exact database name.");
}

string run = args[0];
string mode = args[1];
string database = args[2];
if (!DatabaseInventory.ActiveDatabases.Contains(database, StringComparer.Ordinal))
{
    throw new InvalidOperationException("Database is not in exact canonical inventory.");
}

FreshSchemaPlan schema = JsonSerializer.Deserialize<FreshSchemaPlan>(
    File.ReadAllText(Path.Combine(run, "source-schema-plan-v2.json")),
    new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? throw new InvalidOperationException("Schema plan unavailable.");
using JsonDocument catalog = JsonDocument.Parse(File.ReadAllText(
    Path.Combine(run, "production-catalog-v2-preimage.json")));
JsonElement root = catalog.RootElement;
if (schema.Databases.Count != 23 || root.GetProperty("databases").GetArrayLength() != 23 ||
    root.GetProperty("schemaPlanSha256").GetString() != SchemaPlanCanonicalizer.ComputeSha256(schema) ||
    root.GetProperty("targetAuthority").GetProperty("authorityId").GetString() !=
        "gke://maliev-website/us-central1-a/maliev-legacy/legacy-postgres-main/6e0426c3-3426-4d6d-aa9b-64228f0af20f")
{
    throw new InvalidOperationException("Production catalog is not bound to the exact source plan and authorized cluster.");
}

DateTimeOffset observation = root.GetProperty("completedAtUtc").GetDateTimeOffset();
if (observation > DateTimeOffset.UtcNow || DateTimeOffset.UtcNow - observation > TimeSpan.FromHours(2))
{
    throw new InvalidOperationException("Production schema observation is stale.");
}

DatabaseSchemaPlan plan = schema.Databases.Single(db => db.Database == database);
JsonElement dbCatalog = root.GetProperty("databases").EnumerateArray()
    .Single(db => db.GetProperty("database").GetString() == database);
string expectedPreimage = dbCatalog.GetProperty("schemaSha256").GetString()!;
string expectedFinal = plan.TargetSchemaSha256;
string productionSystemHash = root.GetProperty("targetAuthority")
    .GetProperty("systemIdentifierSha256").GetString()!;
var statements = new List<(string Name, string Sha256, string Sql)>();
using JsonDocument scriptManifest = JsonDocument.Parse(File.ReadAllText(
    Path.Combine(run, "repair-scripts-proof-manifest.json")));
var approvedScripts = scriptManifest.RootElement.EnumerateArray().ToDictionary(
    item => item.GetProperty("name").GetString()!,
    item => item.GetProperty("sha256").GetString()!, StringComparer.Ordinal);
foreach (string fileName in new[] { database is "Customer" or "Employee" ? "repair-bangkok-defaults.sql" : "",
    $"repair-additive-{database}.sql" }.Where(name => name.Length > 0))
{
    string path = Path.Combine(run, fileName);
    if (!File.Exists(path))
    {
        continue;
    }

    string original = File.ReadAllText(path).Replace("\r\n", "\n", StringComparison.Ordinal);
    if (!original.StartsWith("BEGIN;\n", StringComparison.Ordinal) ||
        !original.TrimEnd('\n').EndsWith("COMMIT;", StringComparison.Ordinal))
    {
        throw new InvalidOperationException("Reviewed SQL transaction envelope changed.");
    }

    string body = original["BEGIN;\n".Length..].TrimEnd('\n');
    body = body[..^"COMMIT;".Length];
    string hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
    if (!approvedScripts.TryGetValue(fileName, out string? approvedHash) || hash != approvedHash)
    {
        throw new InvalidOperationException("Reviewed additive SQL bytes changed after disposable proof.");
    }

    statements.Add((fileName, hash, body));
}
LockoutCapture[] captures = [];
if (database is "CustomerIdentity" or "EmployeeIdentity")
{
    string capturePath = Path.Combine(run, "source-lockoutend-exact.json");
    if (DateTime.UtcNow - File.GetLastWriteTimeUtc(capturePath) > TimeSpan.FromHours(2))
    {
        throw new InvalidOperationException("Exact identity source capture is stale.");
    }

    captures = JsonSerializer.Deserialize<LockoutCapture[]>(File.ReadAllText(capturePath),
        new JsonSerializerOptions(JsonSerializerDefaults.Web))!
        .Where(item => item.Database == database).ToArray();
    if (captures.Length != (database == "CustomerIdentity" ? 11 : 1))
    {
        throw new InvalidOperationException("Exact identity source capture row count changed.");
    }
}
string connectionText = mode == "production"
    ? File.ReadAllText(Path.Combine(run, "target-connection.txt")).Trim()
    : new NpgsqlConnectionStringBuilder { Host = "127.0.0.1", Port = 15440, Username = "postgres", Password = File.ReadAllLines(Path.Combine(run, "disposable-postgres.env")).Single(line => line.StartsWith("POSTGRES_PASSWORD=", StringComparison.Ordinal))["POSTGRES_PASSWORD=".Length..], Database = "postgres", Pooling = false }.ConnectionString;
var builder = new NpgsqlConnectionStringBuilder(connectionText) { Database = database, Pooling = false };
if (builder.Host != "127.0.0.1" || builder.Port != (mode == "production" ? 15438 : 15440))
{
    throw new InvalidOperationException("Unexpected repair transport.");
}

await using var connection = new NpgsqlConnection(builder.ConnectionString);
await connection.OpenAsync();
await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
await using (var settings = new NpgsqlCommand(
    "SET LOCAL lock_timeout = '15s'; SET LOCAL statement_timeout = '5min';", connection, transaction))
{
    _ = await settings.ExecuteNonQueryAsync();
}

await using (var identity = new NpgsqlCommand(
    "SELECT system_identifier::text FROM pg_control_system();", connection, transaction))
{
    string observed = (string)(await identity.ExecuteScalarAsync() ?? throw new InvalidOperationException("System ID missing."));
    string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(observed))).ToLowerInvariant();
    if (mode == "production" ? hash != productionSystemHash : hash == productionSystemHash)
    {
        throw new InvalidOperationException("Target PostgreSQL system identity is invalid for this lane.");
    }
}
await using (var lockCommand = new NpgsqlCommand(
    "SELECT pg_advisory_xact_lock(hashtext($1));", connection, transaction))
{
    _ = lockCommand.Parameters.AddWithValue($"legacy-schema-repair:{database}");
    _ = await lockCommand.ExecuteScalarAsync();
}
Type inspectorType = typeof(FreshSchemaPlan).Assembly.GetType(
    "Legacy.Maliev.DataMigration.PostgreSqlWholeDatabaseTransaction")!;
object inspector = Activator.CreateInstance(inspectorType,
    BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
    null, [connection, transaction, false], null)!;
MethodInfo inspect = inspectorType.GetMethod("InspectSchemaAsync", BindingFlags.Instance | BindingFlags.Public)!;
async Task<string> InspectAsync()
{
    return await (Task<string>)inspect.Invoke(inspector, [plan, CancellationToken.None])!;
}

string before = await InspectAsync();
bool alreadyCurrent = before == expectedFinal;
if (!alreadyCurrent && before != expectedPreimage)
{
    throw new InvalidOperationException($"Exact production preimage changed: {database}");
}

IEnumerable<(string Name, string Sha256, string Sql)> pendingStatements = alreadyCurrent
    ? [] : statements;
foreach ((string fileName, string hash, string sql) in pendingStatements)
{
    await using var command = new NpgsqlCommand(sql, connection, transaction);
    _ = await command.ExecuteNonQueryAsync();
    Console.WriteLine($"executed:{database}:{fileName}:{hash}");
}
if (captures.Length > 0)
{
    foreach (LockoutCapture item in captures)
    {
        await using var check = new NpgsqlCommand(
            "SELECT \"LockoutEnd\" FROM public.\"AspNetUsers\" WHERE \"Id\"=$1;", connection, transaction);
        _ = check.Parameters.AddWithValue(item.UserId);
        DateTime? actual = (DateTime?)await check.ExecuteScalarAsync();
        DateTime expected = new(item.UtcTicks - (item.UtcTicks % 10), DateTimeKind.Utc);
        if (actual != expected)
        {
            throw new InvalidOperationException($"Runtime timestamp projection mismatch: {database}");
        }
    }
    await using (var create = new NpgsqlCommand("""
        CREATE SCHEMA IF NOT EXISTS legacy_migration_internal;
        CREATE TABLE IF NOT EXISTS legacy_migration_internal."AspNetUserLockoutEndExact" (
          "UserId" text PRIMARY KEY, "ExactValue" text NOT NULL);
        """, connection, transaction))
    {
        _ = await create.ExecuteNonQueryAsync();
    }

    foreach (LockoutCapture item in captures)
    {
        await using var insert = new NpgsqlCommand("""
            INSERT INTO legacy_migration_internal."AspNetUserLockoutEndExact" ("UserId","ExactValue")
            VALUES ($1,$2) ON CONFLICT ("UserId") DO NOTHING;
            """, connection, transaction);
        _ = insert.Parameters.AddWithValue(item.UserId);
        _ = insert.Parameters.AddWithValue(item.ExactText);
        _ = await insert.ExecuteNonQueryAsync();
        await using var check = new NpgsqlCommand("""
            SELECT "ExactValue" FROM legacy_migration_internal."AspNetUserLockoutEndExact"
            WHERE "UserId"=$1;
            """, connection, transaction);
        _ = check.Parameters.AddWithValue(item.UserId);
        if ((string?)await check.ExecuteScalarAsync() != item.ExactText)
        {
            throw new InvalidOperationException($"Exact companion mismatch: {database}");
        }
    }
}
string after = await InspectAsync();
if (after != expectedFinal)
{
    throw new InvalidOperationException($"Final schema fingerprint differs: {database}");
}

await transaction.CommitAsync();
var independent = new PostgreSqlDeltaReconciliationInspector(
    new PostgreSqlDeltaReconciliationInspectorOptions(builder.ConnectionString));
if (await independent.InspectSchemaAsync(plan, CancellationToken.None) != expectedFinal)
{
    throw new InvalidOperationException($"Post-commit schema fingerprint differs: {database}");
}

Console.WriteLine($"repair_complete:{mode}:{database}:already_current={alreadyCurrent}:companion_rows={captures.Length}:hash={expectedFinal}");
if (mode == "production")
{
    string receipt = JsonSerializer.Serialize(new
    {
        database,
        completedAtUtc = DateTimeOffset.UtcNow,
        preimage = before,
        final = after,
        alreadyCurrent,
        sourcePlanSha256 = root.GetProperty("schemaPlanSha256").GetString(),
        scripts = statements.Select(s => new { name = s.Name, sha256 = s.Sha256 }).ToArray(),
        companionRows = captures.Length,
    });
    File.AppendAllText(Path.Combine(run, "production-repair-receipts.jsonl"), receipt + "\n");
}

internal sealed record LockoutCapture(string Database, string UserId, string ExactText, long UtcTicks);
