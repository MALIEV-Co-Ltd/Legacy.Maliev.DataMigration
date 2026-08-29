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
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ApplySchema_NullableSqlServerUniqueObject_UsesNullsNotDistinctSemantics(bool constraint)
    {
        var target = new PostgreSqlShadowTarget(new PostgreSqlShadowTargetOptions(fixture.ConnectionString));
        string runId = Guid.NewGuid().ToString("D");
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Order", $"legacy_shadow_order_{Guid.NewGuid():N}", runId, CancellationToken.None);

        try
        {
            TableCopyPlan table = CreateTablePlan() with
            {
                UniqueConstraints = constraint ? [new UniqueConstraintCopyPlan("UQ_orders_name", ["Name"])] : [],
                Indexes = constraint ? [] : [new IndexCopyPlan("UX_orders_name", ["Name"], true)],
            };
            var plan = new DatabaseSchemaPlan("Order", "1.0", Hash("source"), Hash("target"), [table]);
            await using IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await transaction.ApplySchemaAsync(plan, CancellationToken.None);
            _ = await transaction.CopyBatchAsync(
                table,
                [new MigrationRow(new Dictionary<string, object?> { ["Id"] = 1, ["Name"] = null })],
                CancellationToken.None);

            _ = await Assert.ThrowsAsync<PostgresException>(() => transaction.CopyBatchAsync(
                table,
                [new MigrationRow(new Dictionary<string, object?> { ["Id"] = 2, ["Name"] = null })],
                CancellationToken.None));
            await transaction.RollbackAsync(CancellationToken.None);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }
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
            MigrationExecutionException lateCopy = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                transaction.CopyBatchAsync(
                    table,
                    [new MigrationRow(new Dictionary<string, object?> { ["Id"] = 3, ["Name"] = "late" })],
                    CancellationToken.None));
            await transaction.CommitAsync(CancellationToken.None);

            Assert.Equal(2, rows);
            Assert.Equal("shadow_copy_after_inspection", lateCopy.Code);
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
    public async Task WholeDatabaseTransaction_CreatesAndReconcilesEverySignedSchemaObject()
    {
        var target = new PostgreSqlShadowTarget(new PostgreSqlShadowTargetOptions(fixture.ConnectionString));
        string runId = Guid.NewGuid().ToString("D");
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Order",
            $"legacy_shadow_order_{Guid.NewGuid():N}",
            runId,
            CancellationToken.None);

        try
        {
            TableCopyPlan table = SchemaPlanSemanticsTests.CreateTable() with
            {
                OrderedColumns = ["Id", "Quantity", "CreatedAt", "Code", "NormalizedCode"],
                SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["Id"] = "int",
                    ["Quantity"] = "int",
                    ["CreatedAt"] = "datetime2",
                    ["Code"] = "nvarchar",
                    ["NormalizedCode"] = "nvarchar",
                },
                ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["Id"] = "integer",
                    ["Quantity"] = "integer",
                    ["CreatedAt"] = "timestamp without time zone",
                    ["Code"] = "text",
                    ["NormalizedCode"] = "text",
                },
                NullableColumns = ["CreatedAt"],
                Collations = new Dictionary<string, string>(StringComparer.Ordinal) { ["Code"] = "C" },
                GeneratedColumns = [new GeneratedColumnCopyPlan("NormalizedCode", "lower(\"Code\")")],
                IdentityColumns = ["Id"],
                Identities = [new IdentityCopyPlan("Id", 100, 5, 145, true)],
                Indexes =
                [
                    new IndexCopyPlan("IX_orders_quantity", ["Quantity"], false)
                    {
                        DescendingColumns = ["Quantity"],
                        IncludedColumns = ["CreatedAt"],
                        FilterPredicate = "\"Quantity\" > 0",
                    },
                ],
                ForeignKeys =
                [
                    new ForeignKeyCopyPlan("FK_orders_self", ["Id"], "sales", "orders", ["Id"])
                    {
                        OnDelete = ReferentialAction.Cascade,
                        OnUpdate = ReferentialAction.Restrict,
                    },
                ],
            };
            var draft = new DatabaseSchemaPlan("Order", "1.0", Hash("source"), Hash("target"), [table]);
            DatabaseSchemaPlan plan = draft with
            {
                TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft),
            };
            await using IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);

            await transaction.ApplySchemaAsync(plan, CancellationToken.None);
            _ = await transaction.CopyBatchAsync(
                table,
                [
                    SchemaRow(100, 1, "A", "a"),
                    SchemaRow(110, 2, "B", "b"),
                ],
                CancellationToken.None);
            string actual = await transaction.InspectSchemaAsync(plan, CancellationToken.None);
            _ = await transaction.InspectTableAsync(table, CancellationToken.None);
            await transaction.CommitAsync(CancellationToken.None);

            Assert.Equal(plan.TargetSchemaSha256, actual);
            var shadowConnection = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = shadow.Name };
            await using var connection = new NpgsqlConnection(shadowConnection.ConnectionString);
            await connection.OpenAsync();
            await using var sequenceNameCommand = new NpgsqlCommand(
                "SELECT pg_get_serial_sequence('sales.orders', 'Id');",
                connection);
            string sequenceName = Assert.IsType<string>(await sequenceNameCommand.ExecuteScalarAsync());
            await using var state = new NpgsqlCommand(
                $"SELECT last_value, is_called FROM {sequenceName}; SELECT array_agg(\"Id\" ORDER BY \"Id\") FROM sales.orders;",
                connection);
            await using NpgsqlDataReader reader = await state.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(145, reader.GetInt64(0));
            Assert.True(reader.GetBoolean(1));
            Assert.True(await reader.NextResultAsync());
            Assert.True(await reader.ReadAsync());
            Assert.Equal([100, 110], reader.GetFieldValue<int[]>(0));
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
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "int",
                ["Name"] = "nvarchar",
            },
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "integer",
                ["Name"] = "text",
            },
            NullableColumns = ["Name"],
            PrimaryKey = new PrimaryKeyCopyPlan("PK_orders", ["Id"]),
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

    private static MigrationRow SchemaRow(int id, int quantity, string code, string normalizedCode)
    {
        return new MigrationRow(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["Id"] = id,
            ["Quantity"] = quantity,
            ["CreatedAt"] = new DateTime(2026, 8, 29, 12, 0, id % 60, DateTimeKind.Unspecified),
            ["Code"] = code,
            ["NormalizedCode"] = normalizedCode,
        });
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
