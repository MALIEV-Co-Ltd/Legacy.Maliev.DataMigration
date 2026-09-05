using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class LocalArchiveVerificationFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:18")
        .WithCreateParameterModifier(parameters =>
        {
            foreach (IList<Docker.DotNet.Models.PortBinding> bindings in parameters.HostConfig!.PortBindings!.Values)
            {
                foreach (Docker.DotNet.Models.PortBinding binding in bindings) { binding.HostIP = "127.0.0.1"; }
            }
        }).Build();
    private readonly string _password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    private readonly ECDsa _signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public const string RestoreRole = "local_archive_restore";
    public string Admin => new NpgsqlConnectionStringBuilder(_container.GetConnectionString()) { Host = "127.0.0.1", Database = "postgres", Pooling = false }.ConnectionString;
    public LocalPostgreSqlArchiveVerificationOptions Options { get; private set; } = null!;
    public DatabaseMigrationCheckpointVerificationOptions CheckpointOptions { get; private set; } = null!;
    public DatabaseMigrationCheckpoint Checkpoint { get; private set; } = null!;
    public DatabaseSchemaPlan Plan { get; private set; } = null!;
    public byte[] Archive { get; private set; } = [];
    public static bool Enabled => Environment.GetEnvironmentVariable("MALIEV_RUN_PG18_SNAPSHOT_INTEGRATION") == "1";
    public static string Tool(string name)
    {
        return Environment.GetEnvironmentVariable(name) ?? throw new InvalidOperationException(name + " is required.");
    }

    public async Task InitializeAsync()
    {
        if (!Enabled) { return; }
        await _container.StartAsync();
        await ExecuteAsync("postgres", $"CREATE ROLE {RestoreRole} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{_password}';");
        string[] databases = (await CatalogAsync()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (string name in databases) { await ExecuteAsync("postgres", $"REVOKE CONNECT ON DATABASE {Quote(name)} FROM PUBLIC;"); }
        await ExecuteAsync("postgres", "CREATE DATABASE protected_archive_fixture;");
        await ExecuteAsync("postgres", "REVOKE CONNECT ON DATABASE protected_archive_fixture FROM PUBLIC;");
        await ExecuteAsync("protected_archive_fixture", "CREATE TABLE sentinel(value integer); INSERT INTO sentinel VALUES(42);");
        // This is fixture setup only, not production role/global ACL repair.
        var docker = new LocalDockerResourceObserver();
        LocalDockerResourceState resource = await docker.ObserveAsync(_container.Id, default);
        string systemId = (string)(await ScalarAsync("postgres", "SELECT system_identifier::text FROM pg_control_system();"))!;
        Options = new(Admin, new NpgsqlConnectionStringBuilder(Admin) { Username = RestoreRole, Password = _password }.ConnectionString,
            _container.Id, resource.Image.Id, systemId, Tool("PG_RESTORE_PATH"));
        TableCopyPlan parent = new("dbo", "Parent", "sales", "parents", ["Id", "Name"], ["Id"])
        {
            SourceColumnTypes = new Dictionary<string, string> { ["Id"] = "int", ["Name"] = "nvarchar" },
            ColumnTypes = new Dictionary<string, string> { ["Id"] = "integer", ["Name"] = "text" },
            NullableColumns = ["Name"],
            PrimaryKey = new("PK_parents", ["Id"]),
            IdentityColumns = ["Id"],
            Identities = [new("Id", 1, 1, 2, true)],
        };
        TableCopyPlan child = new("dbo", "Child", "sales", "children", ["Id", "ParentId"], ["Id"])
        {
            SourceColumnTypes = new Dictionary<string, string> { ["Id"] = "int", ["ParentId"] = "int" },
            ColumnTypes = new Dictionary<string, string> { ["Id"] = "integer", ["ParentId"] = "integer" },
            NullableColumns = ["ParentId"],
            PrimaryKey = new("PK_children", ["Id"]),
            ForeignKeys = [new("FK_child_parent", ["ParentId"], "sales", "parents", ["Id"])],
        };
        var draft = new DatabaseSchemaPlan(DatabaseInventory.ActiveDatabases[0], "1.0", new string('a', 64), "", [parent, child]);
        Plan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        var plan = new FreshSchemaPlan("2.0", DateTimeOffset.UtcNow.AddMinutes(-1), new string('a', 40), [Plan]);
        var identity = new MigrationRunIdentity(Guid.NewGuid(), plan.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(plan), new string('b', 64), new string('c', 64), "local-pg18-fixture");
        CheckpointOptions = new(identity, plan, new ReceiptAttestationTrustStore([new("local-fixture", _signer.ExportSubjectPublicKeyInfo())]));
        var shadow = new ShadowDatabase(GuardedShadowMigrationRunner.CreateShadowName(Plan.Database, identity.RunId), identity.RunId.ToString("D"), Plan.Database) { OwnerAttempt = 1, FencingToken = Guid.NewGuid() };
        await ExecuteAsync("postgres", $"CREATE DATABASE {Quote(shadow.Name)};");
        await ExecuteAsync("postgres", $"REVOKE CONNECT ON DATABASE {Quote(shadow.Name)} FROM PUBLIC;");
        var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(Admin) { Database = shadow.Name }.ConnectionString);
        await connection.OpenAsync();
        var transaction = await connection.BeginTransactionAsync();
        MigrationRow[] parents = [new(new Dictionary<string, object?> { ["Id"] = 1, ["Name"] = "ไทย" }), new(new Dictionary<string, object?> { ["Id"] = 2, ["Name"] = null })];
        MigrationRow[] children = [new(new Dictionary<string, object?> { ["Id"] = 10, ["ParentId"] = 1 }), new(new Dictionary<string, object?> { ["Id"] = 20, ["ParentId"] = null })];
        await using (var writer = new PostgreSqlWholeDatabaseTransaction(connection, transaction))
        {
            await writer.ApplySchemaAsync(Plan, default);
            _ = await writer.CopyBatchAsync(parent, parents, default);
            _ = await writer.CopyBatchAsync(child, children, default);
            await writer.FinalizeSchemaAsync(Plan, default);
            _ = await writer.InspectSchemaAsync(Plan, default);
            _ = await writer.InspectTableAsync(parent, default);
            _ = await writer.InspectTableAsync(child, default);
            await writer.CommitAsync(default);
        }
        using var parentCollector = new TableEvidenceCollector(parent);
        foreach (MigrationRow row in parents) { parentCollector.Append(row); }
        using var childCollector = new TableEvidenceCollector(child);
        foreach (MigrationRow row in children) { childCollector.Append(row); }
        TableReconciliationEvidence[] tables = [parentCollector.Finish(), childCollector.Finish() with
        {
            ForeignKeyOrphanCounts = new Dictionary<string, long> { ["FK_child_parent"] = 0 },
            ForeignKeyRelationshipCounts = new Dictionary<string, long> { ["FK_child_parent"] = 1 },
        }];
        string content = string.Join('\n', tables.OrderBy(t => t.Table, StringComparer.Ordinal).Select(t => $"{t.Table}|{t.RowCount}|{t.ContentSha256}|{t.AggregateSha256}"));
        Checkpoint = Sign(new(identity, shadow, new(Plan.Database, shadow.Name, 4, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content))).ToLowerInvariant()) { OwnerAttempt = 1, FencingToken = shadow.FencingToken },
            new(Plan.Database, Plan.SourceSchemaSha256, Plan.TargetSchemaSha256, tables) { SequenceNextValues = new Dictionary<string, long> { ["sales.parents.Id"] = 3 } }, DateTimeOffset.UtcNow, "local-fixture", null));
        Archive = await DumpAsync();
    }

    public LocalPostgreSqlArchiveVerifier Verifier(LocalPostgreSqlArchiveVerificationOptions? options = null)
    {
        return new(options ?? Options, CheckpointOptions);
    }

    public DatabaseMigrationCheckpoint Sign(DatabaseMigrationCheckpoint checkpoint)
    {
        return checkpoint with { AttestationSignature = Convert.ToBase64String(_signer.SignData(MigrationEvidenceAttestation.CreatePayload(checkpoint), HashAlgorithmName.SHA256)) };
    }

    public async Task<byte[]> DumpAsync()
    {
        await using Stream stream = await new PgDumpSource(Tool("PG_DUMP_PATH"), Admin).OpenDumpAsync(Plan.Database, Checkpoint.Shadow.Name, default);
        using var memory = new MemoryStream();
        await stream.CopyToAsync(memory);
        return memory.ToArray();
    }
    public async Task ExecuteAsync(string database, string sql)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(Admin) { Database = database }.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }
    public async Task<object?> ScalarAsync(string database, string sql)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(Admin) { Database = database }.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        return await command.ExecuteScalarAsync();
    }
    public async Task<string> CatalogAsync()
    {
        return (string)(await ScalarAsync("postgres", "SELECT string_agg(datname, E'\\n' ORDER BY datname) FROM pg_database;"))!;
    }

    public async Task DisposeAsync() { await _container.DisposeAsync(); _signer.Dispose(); }
    private static string Quote(string name)
    {
        return PostgreSqlShadowTarget.QuoteIdentifier(name);
    }
}
