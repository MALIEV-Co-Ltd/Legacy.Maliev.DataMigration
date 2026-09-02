using System.Diagnostics;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class PostgreSql18SnapshotIntegrationFactAttribute : FactAttribute
{
    public PostgreSql18SnapshotIntegrationFactAttribute()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("MALIEV_RUN_PG18_SNAPSHOT_INTEGRATION"), "1", StringComparison.Ordinal))
        {
            Skip = "Set MALIEV_RUN_PG18_SNAPSHOT_INTEGRATION=1, PG_DUMP_PATH and PG_RESTORE_PATH for disposable PostgreSQL 18 snapshot integration.";
        }
    }
}

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PgDumpPgRestoreCompatibilityIntegrationTests(PostgreSqlAdapterFixture fixture)
{
    private static readonly string[] ExpectedLocalFiles = [".store.lock", "archive.aes256", "artifact.json"];
    [PostgreSql18SnapshotIntegrationFact]
    public async Task ProducerCustomArchive_EncryptedDeliveryAndReplayRestoreSchemaRowsAndEvidenceWithoutPlaintextFiles()
    {
        string pgDump = RequiredEnvironment("PG_DUMP_PATH"), pgRestore = RequiredEnvironment("PG_RESTORE_PATH");
        AssertPostgreSql18Tool(pgDump, "pg_dump");
        AssertPostgreSql18Tool(pgRestore, "pg_restore");
        using var data = new LocalArtifactTestData();
        DatabaseMigrationCheckpoint checkpoint = data.Checkpoints[0];
        string root = Path.Combine(Path.GetTempPath(), $"snapshot-encrypted-{Guid.NewGuid():N}");
        string shadow = checkpoint.Shadow.Name;
        try
        {
            await ExecuteAdministrativeCommandAsync($"CREATE DATABASE \"{shadow}\"");
            var sourceConnection = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = shadow };
            await using (var connection = new NpgsqlConnection(sourceConnection.ConnectionString))
            {
                await connection.OpenAsync();
                await using var setup = new NpgsqlCommand("CREATE TABLE snapshot_probe (id integer PRIMARY KEY, value text NOT NULL); INSERT INTO snapshot_probe VALUES (1, 'pg18')", connection);
                _ = await setup.ExecuteNonQueryAsync();
            }
            var source = new CountedDumpSource(new PgDumpSource(pgDump, fixture.ConnectionString));
            var verifier = new RestoreVerifier(pgRestore, fixture.ConnectionString);
            using (var store = new IncrementalLocalSnapshotStore(root, "pg18-streaming", data.Key, data.Verifier, source, verifier, _ => Task.CompletedTask))
            {
                await store.DeliverAndVerifyAsync(checkpoint, default);
            }
            string archivePath = Path.Combine(root, checkpoint.Database.Database, "archive.aes256");
            byte[] before = await File.ReadAllBytesAsync(archivePath);
            Assert.Equal("MLVSNP02"u8.ToArray(), before[..8]);
            // Remove the source completely: replay must work from encrypted local bytes alone.
            await ExecuteAdministrativeCommandAsync($"DROP DATABASE \"{shadow}\" WITH (FORCE)");
            using (var restarted = new IncrementalLocalSnapshotStore(root, "pg18-streaming", data.Key, data.Verifier, source, verifier, _ => Task.CompletedTask))
            {
                await restarted.DeliverAndVerifyAsync(checkpoint, default);
                _ = Assert.Single(await restarted.ReadVerifiedCheckpointsAsync(default));
            }
            Assert.Equal(1, source.Opens);
            Assert.Equal(2, verifier.VerifiedRestores);
            Assert.Equal(before, await File.ReadAllBytesAsync(archivePath));
            Assert.Equal(ExpectedLocalFiles,
                Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Select(Path.GetFileName).Order(StringComparer.Ordinal));
        }
        finally
        {
            await ExecuteAdministrativeCommandAsync($"DROP DATABASE IF EXISTS \"{shadow}\" WITH (FORCE)");
            if (Directory.Exists(root)) { Directory.Delete(root, recursive: true); }
        }
    }

    [PostgreSql18SnapshotIntegrationFact]
    public async Task ProducerNonzeroExit_PreventsArtifactPublicationAndRestore()
    {
        using var data = new LocalArtifactTestData();
        string root = Path.Combine(Path.GetTempPath(), $"snapshot-failed-dump-{Guid.NewGuid():N}");
        var verifier = new RestoreVerifier(RequiredEnvironment("PG_RESTORE_PATH"), fixture.ConnectionString);
        try
        {
            using var store = new IncrementalLocalSnapshotStore(root, "pg18-failed", data.Key, data.Verifier,
                new PgDumpSource(RequiredEnvironment("PG_DUMP_PATH"), fixture.ConnectionString), verifier, _ => Task.CompletedTask);
            MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => store.DeliverAndVerifyAsync(data.Checkpoints[0], default));
            Assert.Equal("snapshot_dump_failed", failure.Code);
            Assert.Equal(0, verifier.VerifiedRestores);
            Assert.Empty(await store.ReadVerifiedCheckpointsAsync(default));
        }
        finally { if (Directory.Exists(root)) { Directory.Delete(root, recursive: true); } }
    }

    private Task ExecuteAdministrativeCommandAsync(string sql)
    {
        return ExecuteAdministrativeCommandAsync(fixture.ConnectionString, sql);
    }

    private static async Task ExecuteAdministrativeCommandAsync(string connectionString, string sql)
    {
        var builder = new NpgsqlConnectionStringBuilder(connectionString) { Database = "postgres" };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private sealed class CountedDumpSource(IPostgreSqlDumpSource inner) : IPostgreSqlDumpSource
    {
        public int Opens { get; private set; }
        public Task<Stream> OpenDumpAsync(string database, string shadowDatabase, CancellationToken cancellationToken)
        {
            Opens++;
            return inner.OpenDumpAsync(database, shadowDatabase, cancellationToken);
        }
    }

    private sealed class RestoreVerifier(string executable, string connectionString) : ILocalDatabaseArchiveVerifier
    {
        public int VerifiedRestores { get; private set; }

        public async Task VerifyAsync(Stream plaintext, DatabaseMigrationCheckpoint checkpoint, CancellationToken cancellationToken)
        {
            string database = $"local_snapshot_verify_{Guid.NewGuid():N}";
            await ExecuteAdministrativeCommandAsync(connectionString, $"CREATE DATABASE \"{database}\"");
            try
            {
                var target = new NpgsqlConnectionStringBuilder(connectionString) { Database = database };
                var start = new ProcessStartInfo(executable)
                {
                    UseShellExecute = false,
                    RedirectStandardInput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                };
                foreach (string argument in new[]
                {
                    "--exit-on-error", "--no-owner", "--no-privileges", "--single-transaction", "--no-password",
                    "--host", target.Host!, "--port", target.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    "--username", target.Username!, "--dbname", database,
                }) { start.ArgumentList.Add(argument); }
                start.Environment["PGPASSWORD"] = target.Password;
                using Process process = Process.Start(start) ?? throw new InvalidOperationException("pg_restore did not start.");
                Task<string> error = process.StandardError.ReadToEndAsync(cancellationToken);
                try
                {
                    await plaintext.CopyToAsync(process.StandardInput.BaseStream, cancellationToken);
                    await process.StandardInput.DisposeAsync();
                    await process.WaitForExitAsync(cancellationToken).WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);
                    Assert.True(process.ExitCode == 0, await error);
                }
                finally
                {
                    if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(CancellationToken.None); }
                    _ = await error;
                }
                await using var restored = new NpgsqlConnection(target.ConnectionString);
                await restored.OpenAsync(cancellationToken);
                await using (var schema = new NpgsqlCommand("SELECT string_agg(column_name || ':' || data_type || ':' || is_nullable, ',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name='snapshot_probe'", restored))
                {
                    Assert.Equal("id:integer:NO,value:text:NO", await schema.ExecuteScalarAsync(cancellationToken));
                }
                var tablePlan = new TableCopyPlan("dbo", "snapshot_probe", "public", "snapshot_probe", ["id", "value"], ["id"]);
                using var collector = new TableEvidenceCollector(tablePlan);
                await using (var query = new NpgsqlCommand("SELECT id,value FROM snapshot_probe ORDER BY id", restored))
                await using (NpgsqlDataReader rows = await query.ExecuteReaderAsync(cancellationToken))
                {
                    while (await rows.ReadAsync(cancellationToken))
                    {
                        collector.Append(new(new Dictionary<string, object?> { ["id"] = rows.GetInt32(0), ["value"] = rows.GetString(1) }));
                    }
                }
                TableReconciliationEvidence actual = collector.Finish(), expected = Assert.Single(checkpoint.Reconciliation.Tables);
                Assert.Equal(expected.RowCount, actual.RowCount);
                Assert.Equal(expected.ContentSha256, actual.ContentSha256);
                Assert.Equal(expected.AggregateSha256, actual.AggregateSha256);
                Assert.Equal(expected.NullCounts.OrderBy(item => item.Key), actual.NullCounts.OrderBy(item => item.Key));
                VerifiedRestores++;
            }
            finally { await ExecuteAdministrativeCommandAsync(connectionString, $"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)"); }
        }
    }

    private static string RequiredEnvironment(string name)
    {
        return Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
        ? value : throw new InvalidOperationException($"{name} is required for PostgreSQL 18 snapshot integration.");
    }

    private static void AssertPostgreSql18Tool(string executable, string tool)
    {
        var start = new ProcessStartInfo(executable, "--version")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        using Process process = Process.Start(start) ?? throw new InvalidOperationException($"{tool} did not start.");
        string output = process.StandardOutput.ReadToEnd(), error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, error);
        Assert.Contains("18.", output, StringComparison.Ordinal);
    }
}
