using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

// Only this accepted runtime's authenticated actual target can produce these held generated archives.
internal sealed class OrderSubtotalCloneSource : IDisposable
{
    private readonly OrderSubtotalRuntime _runtime;
    private readonly WindowsLocalRunAuthority _authority;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly DualTargetNativeProofTools _tools;
    private readonly Dictionary<string, (FileStream Archive, string Sha256, DualTargetNativeProofDatabase Logical)> _databases = new(StringComparer.Ordinal);
    private readonly string[] _roles;
    private OrderSubtotalCloneSource(OrderSubtotalRuntime runtime, WindowsLocalRunAuthority authority, CurrentAppOwnedRepairCustody files,
        DualTargetNativeProofTools tools, string[] roles)
    { _runtime = runtime; _authority = authority; _files = files; _tools = tools; _roles = roles; }
    internal string LogicalSha256 => OrderSubtotalRepairProtocol.Hash(_databases.OrderBy(x => x.Key, StringComparer.Ordinal)
        .Select(x => new { Database = x.Key, Sha256 = DualTargetNativeProofPreimage.Hash(x.Value.Logical) }));
    internal static async Task<OrderSubtotalCloneSource> CreateAsync(OrderSubtotalRuntime runtime, CancellationToken ct)
    {
        await runtime.VerifyAsync(ct).ConfigureAwait(false);
        var input = runtime.Inputs; string root = Path.Combine(input.Configuration.ProofParent, "order-source-" + Guid.NewGuid().ToString("N"));
        _ = input.Read(input.Configuration.ToolPins, 1024 * 1024);
        SecureSnapshotFileCreation.CreateRestrictedDirectory(root);
        WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(root);
        CurrentAppOwnedRepairCustody? files = null;
        DualTargetNativeProofTools? tools = null; OrderSubtotalCloneSource? result = null;
        try
        {
            files = new CurrentAppOwnedRepairCustody(authority);
            tools = DualTargetNativeProofTools.Acquire(input.Files, input.Configuration.ToolPins.Path, input.Intent.SourceCommitSha);
            await tools.RequireVersionsAsync(ct).ConfigureAwait(false);
            var roles = new List<string>();
            await using (var connection = runtime.Connect("postgres"))
            {
                await connection.OpenAsync(ct).ConfigureAwait(false); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
                await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, tx, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
                await using var query = new NpgsqlCommand("SELECT rolname FROM pg_roles WHERE rolname NOT LIKE 'pg\\_%' ESCAPE '\\' ORDER BY rolname;", connection, tx);
                await using (var reader = await query.ExecuteReaderAsync(ct).ConfigureAwait(false))
                { while (await reader.ReadAsync(ct).ConfigureAwait(false)) { roles.Add(reader.GetString(0)); } }
                await tx.RollbackAsync(ct).ConfigureAwait(false);
            }
            result = new(runtime, authority, files, tools, roles.ToArray());
            int ordinal = 0;
            foreach (string database in input.Intent.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))
            {
                await runtime.RequireAsync(ct).ConfigureAwait(false);
                await using var connection = runtime.Connect(database); await connection.OpenAsync(ct).ConfigureAwait(false);
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
                await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, tx, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
                await OrderSubtotalRuntime.RequirePolicyAsync(connection, tx, input.Intent.Maintenance, input.Intent.Target, ct).ConfigureAwait(false);
                if (await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, tx, "SHOW server_version_num;", ct).ConfigureAwait(false) != "180004") { throw Invalid(); }
                string snapshot = await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, tx, "SELECT pg_export_snapshot();", ct).ConfigureAwait(false);
                var logical = await DualTargetNativeProofLogicalCapture.ReadAsync(connection, tx, tools, runtime.DirectConnection, database, snapshot, ct).ConfigureAwait(false);
                string path = Path.Combine(root, "original-" + (++ordinal).ToString("D3", System.Globalization.CultureInfo.InvariantCulture) + ".dump");
                DateTimeOffset began = DateTimeOffset.UtcNow;
                await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.WriteThrough))
                { await tools.DumpAsync(runtime.DirectConnection, database, snapshot, output, definition: false, ct).ConfigureAwait(false); await output.FlushAsync(ct).ConfigureAwait(false); output.Flush(true); }
                FileStream archive = files.BorrowReadStream(path); string digest = Convert.ToHexStringLower(await SHA256.HashDataAsync(archive, ct).ConfigureAwait(false)); archive.Position = 0;
                result._databases.Add(database, (archive, digest, logical));
                await tx.RollbackAsync(ct).ConfigureAwait(false);
                await files.WriteNewAsync(Path.Combine(root, "window-" + ordinal + ".json"), JsonSerializer.SerializeToUtf8Bytes(new
                {
                    database,
                    began,
                    completedAtUtc = DateTimeOffset.UtcNow,
                    sourceSystemSha256 = input.Intent.Target.SystemIdentifierSha256,
                    logicalSha256 = DualTargetNativeProofPreimage.Hash(logical),
                    dumpSha256 = digest,
                    dumpBytes = archive.Length
                }), ct).ConfigureAwait(false);
            }
            await runtime.VerifyAsync(ct).ConfigureAwait(false); return result;
        }
        catch (Exception primary)
        {
            var failures = new List<Exception>();
            if (result is not null)
            { try { result.Dispose(); } catch (Exception cleanup) { failures.Add(cleanup); } }
            else
            {
                try { tools?.Dispose(); } catch (Exception cleanup) { failures.Add(cleanup); }
                try { files?.Dispose(); } catch (Exception cleanup) { failures.Add(cleanup); }
                try { authority.Dispose(); } catch (Exception cleanup) { failures.Add(cleanup); }
            }
            if (failures.Count != 0) { failures.Insert(0, primary); throw new AggregateException("Order source setup and custody cleanup failed.", failures); }
            throw;
        }
    }
    internal async Task<(DualTargetNativeProofClone Clone, CurrentAppOwnedMaintenancePin Maintenance, string LogicalSha256)> CreateCloneAsync(CancellationToken ct)
    {
        _authority.ValidateHeld(); _files.Require(); await _runtime.VerifyAsync(ct).ConfigureAwait(false);
        DualTargetNativeProofPreimage.RequireRoleNames(_roles, "clone_admin");
        var clone = await DualTargetNativeProofClone.CreateAsync(_runtime.Inputs.Configuration.ProofParent, ct).ConfigureAwait(false);
        try
        {
            using var life = CancellationTokenSource.CreateLinkedTokenSource(ct, clone.Token); ct = life.Token;
            await using (var admin = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(clone.AdminConnection) { Database = "clone_control" }.ConnectionString))
            {
                await admin.OpenAsync(ct).ConfigureAwait(false);
                await DualTargetNativeProofLogicalCapture.ExecuteAsync(admin, null, "DROP DATABASE postgres;", ct).ConfigureAwait(false);
                foreach (string role in _roles)
                {
                    await DualTargetNativeProofLogicalCapture.ExecuteAsync(admin, null, (role == "postgres" ? "ALTER ROLE " : "CREATE ROLE ") +
                    DualTargetNativeProofLogicalCapture.Quote(role) + " NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD NULL;", ct).ConfigureAwait(false);
                }
            }
            foreach (var database in _databases.OrderBy(x => x.Key, StringComparer.Ordinal))
            {
                await clone.RequireOwnedAsync(ct).ConfigureAwait(false); _files.Require(); database.Value.Archive.Position = 0;
                if (Convert.ToHexStringLower(await SHA256.HashDataAsync(database.Value.Archive, ct).ConfigureAwait(false)) != database.Value.Sha256) { throw Invalid(); }
                database.Value.Archive.Position = 0; await _tools.RestoreAsync(clone, database.Value.Archive, ct).ConfigureAwait(false); _files.Require();
            }
            await using (var admin = new NpgsqlConnection(clone.AdminConnection))
            { await admin.OpenAsync(ct).ConfigureAwait(false); await DualTargetNativeProofLogicalCapture.ExecuteAsync(admin, null, "DROP DATABASE clone_control;", ct).ConfigureAwait(false); clone.MarkControlDropped(); }
            var maintenance = await DualTargetNativeProofPolicy.InstallAsync(clone, clone.ExpiresAtUtc, ct).ConfigureAwait(false);
            var actual = new Dictionary<string, DualTargetNativeProofDatabase>(StringComparer.Ordinal);
            foreach (var database in _databases)
            {
                var readback = await ReadAsync(clone, database.Key, ct).ConfigureAwait(false);
                DualTargetNativeProofPreimage.RequireClone(database.Value.Logical, readback); actual.Add(database.Key, readback);
            }
            string actualSha256 = OrderSubtotalRepairProtocol.Hash(actual.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new { Database = x.Key, Sha256 = DualTargetNativeProofPreimage.Hash(x.Value) }));
            await _runtime.VerifyAsync(ct).ConfigureAwait(false); return (clone, maintenance, actualSha256);
        }
        catch (Exception primary)
        { try { await clone.DisposeAsync().ConfigureAwait(false); } catch (Exception cleanup) { primary.Data["OrderCloneCleanup"] = cleanup; } throw; }
    }
    private async Task<DualTargetNativeProofDatabase> ReadAsync(DualTargetNativeProofClone clone, string database, CancellationToken ct)
    {
        var settings = new NpgsqlConnectionStringBuilder(clone.Connection) { Database = database };
        await using var connection = new NpgsqlConnection(settings.ConnectionString); await connection.OpenAsync(ct).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
        await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, tx, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
        string snapshot = await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, tx, "SELECT pg_export_snapshot();", ct).ConfigureAwait(false);
        var logical = await DualTargetNativeProofLogicalCapture.ReadAsync(connection, tx, _tools, settings.ConnectionString, database, snapshot, ct).ConfigureAwait(false);
        await tx.RollbackAsync(ct).ConfigureAwait(false); return logical;
    }
    public void Dispose()
    {
        var failures = new List<Exception>();
        try { _tools.Dispose(); } catch (Exception cleanup) { failures.Add(cleanup); }
        try { _files.Dispose(); } catch (Exception cleanup) { failures.Add(cleanup); }
        try { _authority.Dispose(); } catch (Exception cleanup) { failures.Add(cleanup); }
        if (failures.Count != 0) { throw new AggregateException("Order source custody cleanup failed.", failures); }
    }
    private static MigrationExecutionException Invalid()
    {
        return OrderSubtotalRepairProtocol.Invalid();
    }
}
