using Microsoft.Data.SqlClient;
using Testcontainers.MsSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class AdmittedRealPipelineFactAttribute : FactAttribute
{
    public AdmittedRealPipelineFactAttribute()
    {
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("MALIEV_RUN_SQLSERVER_INTEGRATION") != "1" || !LocalArchiveVerificationFixture.Enabled)
        { Skip = "Requires Windows NTFS and both SQL Server / PostgreSQL 18 integration gates with native dump/restore paths."; }
    }
}

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class AdmittedCoordinatorRealPipelineTests
{
    [AdmittedRealPipelineFact]
    public async Task RealSqlPgNative_LaterFailureAndNewCoordinator_RevalidatesAndPreservesWithoutRecopyOrRedump()
    {
        Assert.True(OperatingSystem.IsWindows());
        Assert.True(LocalArchiveVerificationFixture.Enabled);
        await using var sql = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04").Build();
        var postgres = new PostgreSqlAdapterFixture();
        var local = new LocalArchiveVerificationFixture();
        await sql.StartAsync();
        await postgres.InitializeAsync();
        await local.InitializeAsync();
        try
        {
            await using (var connection = new SqlConnection(sql.GetConnectionString()))
            {
                await connection.OpenAsync();
                foreach (string database in DatabaseInventory.ActiveDatabases)
                {
                    await ExecuteAsync($"CREATE DATABASE [{database}];");
                    await ExecuteAsync($"ALTER DATABASE [{database}] SET ALLOW_SNAPSHOT_ISOLATION ON;");
                    await ExecuteAsync($"CREATE TABLE [{database}].dbo.Rows(ID int IDENTITY(1,1) NOT NULL CONSTRAINT PK_Rows PRIMARY KEY, Value nvarchar(max) NULL, ParentID int NULL, CONSTRAINT FK_Rows_Parent FOREIGN KEY (ParentID) REFERENCES [{database}].dbo.Rows(ID)); INSERT [{database}].dbo.Rows(Value,ParentID) VALUES(REPLICATE(CAST(N'ไทย' AS nvarchar(max)),40000),NULL),(NULL,1);");
                    await ExecuteAsync($"ALTER DATABASE [{database}] SET READ_ONLY;");
                }
                async Task ExecuteAsync(string commandText)
                { await using var command = new SqlCommand(commandText, connection) { CommandTimeout = 60 }; _ = await command.ExecuteNonQueryAsync(); }
            }
            string sourceConnection = new SqlConnectionStringBuilder(sql.GetConnectionString()) { ApplicationIntent = ApplicationIntent.ReadOnly }.ConnectionString;
            FreshSchemaPlan plan;
            await using (var planning = new SqlServerMigrationSource(new(sourceConnection)))
            { plan = await FreshSchemaPlanProducer.ProduceAsync(planning, new string('a', 40), DateTimeOffset.UtcNow, default); }
            using AdmittedCoordinatorTestHarness harness = await AdmittedCoordinatorTestHarness.CreateAsync();
            harness.BindPlan(plan);
            var policy = new RecoveryAuthorityVerificationOptions(new(plan.SourceCommitSha, harness.Data.AdmissionPayload.Identity.RunnerDigestSha256), RecoveryAuthorityTestData.Roles, harness.Data.Trust);
            var checkpointOptions = new DatabaseMigrationCheckpointVerificationOptions(harness.Data.AdmissionPayload.Identity, plan, harness.Data.Trust);
            string schema = "coordinator_" + Guid.NewGuid().ToString("N");
            PostgreSqlMigrationRunJournal Journal()
            {
                return new(new(postgres.ControlConnectionString, schema, CheckpointVerification: checkpointOptions, RecoveryVerification: policy));
            }

            var target = new CountingTarget(postgres.CreateShadowTarget());
            var dump = new CountingDump(new PgDumpSource(LocalArchiveVerificationFixture.Tool("PG_DUMP_PATH"), postgres.ShadowAdminConnectionString));
            var localVerifier = new LocalPostgreSqlArchiveVerifier(local.Options, checkpointOptions);
            string first = DatabaseInventory.ActiveDatabases[0], second = DatabaseInventory.ActiveDatabases[1], third = DatabaseInventory.ActiveDatabases[2];
            var starts = new List<string>();

            AdmittedSequentialMigrationCoordinator Coordinator(string stopDatabase)
            {
                var source = new StoppingSource(new(new(sourceConnection)), database =>
                {
                    if (database == stopDatabase) { throw new IOException("controlled later database interruption"); }
                    if (starts.Count > 0 && database != first) { Assert.True(File.Exists(harness.Archive(starts[^1]))); }
                    starts.Add(database);
                });
                // Current signed Docker/runner/Kubernetes observations are controlled fixture seams.
                // SQL source, target transactions/recovery, journal, native dump, local Docker/PG restore and storage are real.
                var runtime = new AdmittedCoordinatorRuntime(source, target, target, Journal(), dump, localVerifier,
                    localVerifier.VerifyExecutionReadinessAsync,
                    _ => Task.FromResult(harness.Data.Source with { ObservedAtUtc = DateTimeOffset.UtcNow }),
                    _ => Task.FromResult(harness.Data.Runner with { ObservedAtUtc = DateTimeOffset.UtcNow }),
                    _ => Task.FromResult(harness.Data.Target with { ObservedAtUtc = DateTimeOffset.UtcNow }),
                    (shadow, _) => Task.FromResult(new CloudNativePgShadowSettlement(shadow, "fixture-resource", "1", 1, true)),
                    source.DisposeAsync);
                return new(harness.Data.Admission, policy, harness.Data.Signers[2], runtime, "coordinator-real", harness.RootKey, harness.Output, harness.Progress.Add);
            }

            _ = await Assert.ThrowsAsync<IOException>(() => Coordinator(second).ExecuteInitialAsync(harness.Authority, default));
            byte[] archive = await File.ReadAllBytesAsync(harness.Archive(first));
            byte[] metadata = await File.ReadAllBytesAsync(Path.Combine(harness.Staging, first, "artifact.json"));
            DateTime timestamp = File.GetLastWriteTimeUtc(harness.Archive(first));
            RecoveryJournalSnapshot before = await Journal().ReadRecoverySnapshotAsync(harness.Data.AdmissionPayload.Identity, default);
            Assert.Equal("failed", before.Baseline.Status); _ = Assert.Single(before.Baseline.Checkpoints);
            ShadowDatabase originalOwner = Assert.Single(before.Baseline.Shadows).Shadow;
            var (continuity, authorization) = harness.ResumeAuthority(before.Baseline);
            starts.Clear();
            _ = await Assert.ThrowsAsync<IOException>(() => Coordinator(third).ResumeAsync(continuity, authorization, default));
            Assert.Equal(archive, await File.ReadAllBytesAsync(harness.Archive(first)));
            Assert.Equal(metadata, await File.ReadAllBytesAsync(Path.Combine(harness.Staging, first, "artifact.json")));
            Assert.Equal(timestamp, File.GetLastWriteTimeUtc(harness.Archive(first)));
            Assert.Equal(1, target.Created[first]); Assert.Equal(1, target.Copied[first]); Assert.Equal(1, dump.Counts[first]);
            Assert.Equal(1, target.Copied[second]); Assert.Equal(1, dump.Counts[second]);
            Assert.Equal(new[] { first, second }, starts);
            RecoveryJournalSnapshot after = await Journal().ReadRecoverySnapshotAsync(harness.Data.AdmissionPayload.Identity, default);
            Assert.Equal(2, after.Baseline.Checkpoints.Length);
            Assert.Equal(originalOwner, after.Baseline.Shadows.Single(item => item.Shadow.Database == first).Shadow);
            Assert.Equal(before.Baseline.Checkpoints[0].SignedCheckpointJson, after.Baseline.Checkpoints.Single(item => item.Database == first).SignedCheckpointJson);
            Assert.Contains(harness.Progress, value => value.Database == first && value.LocalVerified == 1 && value.Downloaded == 0);
            Assert.Equal(2, harness.Progress[^1].RemoteCommitted); Assert.Equal(2, harness.Progress[^1].LocalVerified);
            Assert.Equal(1, harness.Progress[^1].Downloaded);
        }
        finally { await local.DisposeAsync(); await postgres.DisposeAsync(); }
    }

    private sealed class CountingDump(IPostgreSqlDumpSource inner) : IPostgreSqlDumpSource
    {
        internal Dictionary<string, int> Counts { get; } = new(StringComparer.Ordinal);
        public Task<Stream> OpenDumpAsync(string database, string shadowDatabase, CancellationToken token)
        { Counts[database] = Counts.GetValueOrDefault(database) + 1; return inner.OpenDumpAsync(database, shadowDatabase, token); }
    }
    private sealed class CountingTarget(PostgreSqlShadowTarget inner) : IPostgreSqlShadowTarget, IPostgreSqlShadowRecoveryTarget
    {
        internal Dictionary<string, int> Created { get; } = new(StringComparer.Ordinal);
        internal Dictionary<string, int> Copied { get; } = new(StringComparer.Ordinal);
        public Task<ShadowDatabase> CreateUniqueEmptyShadowAsync(ShadowDatabase shadow, CancellationToken token)
        { Created[shadow.Database] = Created.GetValueOrDefault(shadow.Database) + 1; return inner.CreateUniqueEmptyShadowAsync(shadow, token); }
        public Task<IPostgreSqlWholeDatabaseTransaction> BeginWholeDatabaseTransactionAsync(ShadowDatabase shadow, CancellationToken token)
        { Copied[shadow.Database] = Copied.GetValueOrDefault(shadow.Database) + 1; return inner.BeginWholeDatabaseTransactionAsync(shadow, token); }
        public Task<IPostgreSqlShadowRecoverySession> BeginReadOnlyRecoveryAsync(ShadowDatabase shadow, CancellationToken token)
        {
            return inner.BeginReadOnlyRecoveryAsync(shadow, token);
        }

        public Task<bool> IsEmptyAsync(ShadowDatabase shadow, CancellationToken token)
        {
            throw new InvalidOperationException("weak empty check");
        }

        public Task DeleteRunOwnedShadowAsync(ShadowDatabase shadow, CancellationToken token)
        {
            throw new InvalidOperationException("automatic delete");
        }
    }
    private sealed class StoppingSource(SqlServerMigrationSource inner, Action<string> begin) : IReadOnlySqlServerMigrationSource, IAsyncDisposable
    {
        public Task BeginDatabaseSnapshotAsync(string database, CancellationToken token) { begin(database); return inner.BeginDatabaseSnapshotAsync(database, token); }
        public Task<SourceSchemaEvidence> InspectSchemaAsync(string database, CancellationToken token)
        {
            return inner.InspectSchemaAsync(database, token);
        }

        public IAsyncEnumerable<MigrationRow> ReadTableAsync(string database, TableCopyPlan table, CancellationToken token)
        {
            return inner.ReadTableAsync(database, table, token);
        }

        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyOrphansAsync(string database, TableCopyPlan table, CancellationToken token)
        {
            return inner.InspectForeignKeyOrphansAsync(database, table, token);
        }

        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyRelationshipsAsync(string database, TableCopyPlan table, CancellationToken token)
        {
            return inner.InspectForeignKeyRelationshipsAsync(database, table, token);
        }

        public Task<IReadOnlyDictionary<string, long>> InspectSequenceNextValuesAsync(string database, DatabaseSchemaPlan plan, CancellationToken token)
        {
            return inner.InspectSequenceNextValuesAsync(database, plan, token);
        }

        public Task CompleteDatabaseSnapshotAsync(string database, CancellationToken token)
        {
            return inner.CompleteDatabaseSnapshotAsync(database, token);
        }

        public Task RollbackDatabaseSnapshotAsync(string database, CancellationToken token)
        {
            return inner.RollbackDatabaseSnapshotAsync(database, token);
        }

        public ValueTask DisposeAsync()
        {
            return inner.DisposeAsync();
        }
    }
}
