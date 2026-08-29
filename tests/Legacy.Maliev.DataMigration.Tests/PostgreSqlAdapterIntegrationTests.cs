using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

[CollectionDefinition(Name)]
public sealed class PostgreSqlAdapterTestGroup : ICollectionFixture<PostgreSqlAdapterFixture>
{
    public const string Name = "PostgreSQL adapter";
}

public sealed class PostgreSqlAdapterFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:18-alpine").Build();

    public string ConnectionString => _container.GetConnectionString();

    public Task InitializeAsync()
    {
        return _container.StartAsync();
    }

    public Task DisposeAsync()
    {
        return _container.DisposeAsync().AsTask();
    }
}

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlShadowTargetIntegrationTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public void Constructor_EmptyConnectionString_FailsClosed()
    {
        _ = Assert.Throws<ArgumentException>(() =>
            new PostgreSqlShadowTarget(new PostgreSqlShadowTargetOptions(string.Empty)));
    }

    [Fact]
    public async Task WholeDatabaseTransaction_CopiesAndReconcilesBeforeCommit()
    {
        var target = new PostgreSqlShadowTarget(new PostgreSqlShadowTargetOptions(fixture.ConnectionString));
        string runId = Guid.NewGuid().ToString("D");
        string shadowName = $"legacy_shadow_order_{Guid.NewGuid():N}";
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Order", shadowName, runId, CancellationToken.None);

        try
        {
            Assert.True(await target.IsEmptyAsync(shadow, CancellationToken.None));
            var table = CreateTablePlan();
            var draftPlan = new DatabaseSchemaPlan("Order", "1.0", Hash("source"), Hash("placeholder"), [table]);
            DatabaseSchemaPlan plan = draftPlan with
            {
                TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draftPlan),
            };
            await using IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await transaction.ApplySchemaAsync(plan, CancellationToken.None);
            long rows = await transaction.CopyBatchAsync(
                table,
                Rows(),
                CancellationToken.None);
            string schemaHash = await transaction.InspectSchemaAsync(plan, CancellationToken.None);
            TableReconciliationEvidence reconciliation = await transaction.InspectTableAsync(
                table,
                CancellationToken.None);
            await transaction.CommitAsync(CancellationToken.None);

            Assert.Equal(2, rows);
            Assert.Equal(plan.TargetSchemaSha256, schemaHash);
            Assert.Equal(2, reconciliation.RowCount);
            Assert.Matches("^[0-9a-f]{64}$", reconciliation.ContentSha256);
            Assert.Equal(1, reconciliation.NullCounts["Name"]);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task DeleteRunOwnedShadowAsync_RejectsForgedOwnership()
    {
        var target = new PostgreSqlShadowTarget(new PostgreSqlShadowTargetOptions(fixture.ConnectionString));
        string runId = Guid.NewGuid().ToString("D");
        string shadowName = $"legacy_shadow_order_{Guid.NewGuid():N}";
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Order", shadowName, runId, CancellationToken.None);

        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            target.DeleteRunOwnedShadowAsync(
                shadow with { OwnerRunId = Guid.NewGuid().ToString("D") },
                CancellationToken.None));

        await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
    }

    [Fact]
    public async Task CommitAsync_BeforeEveryTableInspection_FailsClosedAndRollsBack()
    {
        var target = new PostgreSqlShadowTarget(new PostgreSqlShadowTargetOptions(fixture.ConnectionString));
        string runId = Guid.NewGuid().ToString("D");
        string shadowName = $"legacy_shadow_order_{Guid.NewGuid():N}";
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Order", shadowName, runId, CancellationToken.None);

        try
        {
            TableCopyPlan table = CreateTablePlan();
            var draftPlan = new DatabaseSchemaPlan("Order", "1.0", Hash("source"), Hash("placeholder"), [table]);
            DatabaseSchemaPlan plan = draftPlan with
            {
                TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draftPlan),
            };
            await using IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await transaction.ApplySchemaAsync(plan, CancellationToken.None);
            _ = await transaction.InspectSchemaAsync(plan, CancellationToken.None);

            MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                transaction.CommitAsync(CancellationToken.None));

            Assert.Equal("shadow_commit_without_reconciliation", exception.Code);
            await transaction.RollbackAsync(CancellationToken.None);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public void TypePolicy_ArbitrarySqlType_FailsClosed()
    {
        MigrationExecutionException exception = Assert.Throws<MigrationExecutionException>(() =>
            PostgreSqlTypePolicy.Validate("text); DROP DATABASE production; --"));

        Assert.Equal("target_type_forbidden", exception.Code);
    }

    private static TableCopyPlan CreateTablePlan()
    {
        return new TableCopyPlan("dbo", "Order", "public", "orders", ["Id", "Name"], ["Id"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "integer",
                ["Name"] = "text",
            },
            NullableColumns = ["Name"],
        };
    }

    private static IReadOnlyList<MigrationRow> Rows()
    {
        return
        [
            new MigrationRow(new Dictionary<string, object?> { ["Id"] = 1, ["Name"] = "ไทย" }),
            new MigrationRow(new Dictionary<string, object?> { ["Id"] = 2, ["Name"] = null }),
        ];
    }

    private static string Hash(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }
}

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlMigrationRunJournalIntegrationTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public void Constructor_UnsafeSchema_FailsClosed()
    {
        _ = Assert.Throws<ArgumentException>(() => new PostgreSqlMigrationRunJournal(
            new PostgreSqlMigrationRunJournalOptions(fixture.ConnectionString, "public; DROP SCHEMA public")));
    }

    [Fact]
    public async Task TryBeginAsync_ConcurrentSameRun_GrantsOneLeaseAndReportsInProgress()
    {
        var journal = new PostgreSqlMigrationRunJournal(
            new PostgreSqlMigrationRunJournalOptions(fixture.ConnectionString, $"journal_{Guid.NewGuid():N}"));
        MigrationRunIdentity identity = Identity(Guid.NewGuid());

        MigrationRunStartResult[] results = await Task.WhenAll(
            journal.TryBeginAsync(identity, CancellationToken.None),
            journal.TryBeginAsync(identity, CancellationToken.None));

        _ = Assert.Single(results, result => result.Status == MigrationRunStartStatus.Acquired);
        _ = Assert.Single(results, result => result.Status == MigrationRunStartStatus.InProgress);
    }

    [Fact]
    public async Task CompletedRun_PersistsAcrossJournalInstancesAndRejectsMismatchedReplay()
    {
        string schema = $"journal_{Guid.NewGuid():N}";
        var first = new PostgreSqlMigrationRunJournal(
            new PostgreSqlMigrationRunJournalOptions(fixture.ConnectionString, schema));
        MigrationRunIdentity identity = Identity(Guid.NewGuid());
        Assert.Equal(
            MigrationRunStartStatus.Acquired,
            (await first.TryBeginAsync(identity, CancellationToken.None)).Status);
        var receipt = new MigrationExecutionReceipt(
            identity.RunId,
            identity.SourceCommitSha,
            identity.SchemaPlanSha256,
            identity.BackupManifestSha256,
            identity.RunnerDigestSha256,
            identity.TargetGeneration,
            DateTimeOffset.UtcNow,
            [],
            [],
            "test-key",
            "test-signature");
        await first.RecordCompletedAsync(receipt, CancellationToken.None);

        var restarted = new PostgreSqlMigrationRunJournal(
            new PostgreSqlMigrationRunJournalOptions(fixture.ConnectionString, schema));
        MigrationRunStartResult replay = await restarted.TryBeginAsync(identity, CancellationToken.None);
        MigrationRunStartResult conflict = await restarted.TryBeginAsync(
            identity with { TargetGeneration = "different" },
            CancellationToken.None);

        Assert.Equal(MigrationRunStartStatus.AlreadyCompleted, replay.Status);
        Assert.NotNull(replay.CompletedReceipt);
        Assert.Equal(MigrationRunIdentity.FromReceipt(receipt), MigrationRunIdentity.FromReceipt(replay.CompletedReceipt));
        Assert.Equal(receipt.CompletedAtUtc, replay.CompletedReceipt.CompletedAtUtc);
        Assert.Empty(replay.CompletedReceipt.Databases);
        Assert.Equal(MigrationRunStartStatus.Conflict, conflict.Status);
    }

    [Fact]
    public async Task FailedRun_PersistsSignedFailureAndAllowsSameIdentityRetry()
    {
        string schema = $"journal_{Guid.NewGuid():N}";
        var journal = new PostgreSqlMigrationRunJournal(
            new PostgreSqlMigrationRunJournalOptions(fixture.ConnectionString, schema));
        MigrationRunIdentity identity = Identity(Guid.NewGuid());
        Assert.Equal(
            MigrationRunStartStatus.Acquired,
            (await journal.TryBeginAsync(identity, CancellationToken.None)).Status);
        var failure = new MigrationFailureReceipt(
            identity.RunId,
            identity.SourceCommitSha,
            identity.SchemaPlanSha256,
            identity.BackupManifestSha256,
            identity.RunnerDigestSha256,
            identity.TargetGeneration,
            DateTimeOffset.UtcNow,
            "test_failure",
            [],
            [],
            "test-key",
            "test-signature");

        await journal.RecordFailedAsync(failure, CancellationToken.None);
        MigrationRunStartResult retry = await journal.TryBeginAsync(identity, CancellationToken.None);
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync(CancellationToken.None);
        await using var command = new NpgsqlCommand(
            $"SELECT jsonb_array_length(failure_receipts) FROM \"{schema}\".migration_runs WHERE run_id = $1;",
            connection);
        _ = command.Parameters.AddWithValue(identity.RunId);
        int retainedFailures = Convert.ToInt32(
            await command.ExecuteScalarAsync(CancellationToken.None),
            System.Globalization.CultureInfo.InvariantCulture);

        Assert.Equal(MigrationRunStartStatus.Acquired, retry.Status);
        Assert.Equal(1, retainedFailures);
    }

    private static MigrationRunIdentity Identity(Guid runId)
    {
        return new(
        runId,
        new string('a', 40),
        new string('b', 64),
        new string('c', 64),
        new string('d', 64),
        "generation-test");
    }
}

public sealed class ShadowMigrationRuntimeTests
{
    [Fact]
    public async Task Create_ComposesOnlyShadowTargetAndReadOnlySource()
    {
        ShadowMigrationRuntime runtime = ShadowMigrationRuntime.Create(new ShadowMigrationRuntimeOptions(
            new SqlServerMigrationSourceOptions(
                "Server=sql.example;Database=master;Integrated Security=True;Encrypt=True"),
            new PostgreSqlShadowTargetOptions(
                "Host=postgres.example;Database=postgres;Username=reviewer;Password=not-used"),
            new PostgreSqlMigrationRunJournalOptions(
                "Host=postgres.example;Database=journal;Username=reviewer;Password=not-used")));

        _ = Assert.IsType<SqlServerMigrationSource>(runtime.Source);
        _ = Assert.IsType<PostgreSqlShadowTarget>(runtime.ShadowTarget);
        _ = Assert.IsType<PostgreSqlMigrationRunJournal>(runtime.Journal);
        await runtime.DisposeAsync();
    }
}
