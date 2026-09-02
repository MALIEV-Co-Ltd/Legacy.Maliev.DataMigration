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

    private readonly string _controlPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    private readonly string _shadowAdminPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));

    public string ConnectionString => _container.GetConnectionString();

    public string AdministratorUsername => new NpgsqlConnectionStringBuilder(ConnectionString).Username!;

    public string AdministratorPassword => new NpgsqlConnectionStringBuilder(ConnectionString).Password!;

    public string ControlRole { get; } = "legacy_migration_control_test";

    public string ShadowAdminRole { get; } = "legacy_migration_shadow_test";

    public string CanonicalDatabase { get; } = "legacy_canonical_test";

    public string ControlConnectionString => new NpgsqlConnectionStringBuilder(ConnectionString)
    {
        Database = PostgreSqlMigrationRuntimeBoundaryValidator.ControlDatabase,
        Username = ControlRole,
        Password = _controlPassword,
    }.ConnectionString;

    public string ShadowAdminConnectionString => new NpgsqlConnectionStringBuilder(ConnectionString)
    {
        Database = "postgres",
        Username = ShadowAdminRole,
        Password = _shadowAdminPassword,
    }.ConnectionString;

    public PostgreSqlShadowTarget CreateShadowTarget()
    {
        return new PostgreSqlShadowTarget(new PostgreSqlShadowTargetOptions(
            ShadowAdminConnectionString,
            new TestcontainerShadowDatabaseProvisioner(ConnectionString)));
    }

    public async Task InitializeAsync()
    {
        await _container.StartAsync();
        await using var connection = new NpgsqlConnection(ConnectionString);
        await connection.OpenAsync();
        await ExecuteAsync(connection, $"CREATE ROLE {ControlRole} LOGIN PASSWORD '{_controlPassword}';");
        await ExecuteAsync(connection, $"CREATE ROLE {ShadowAdminRole} LOGIN NOCREATEDB PASSWORD '{_shadowAdminPassword}';");
        await ExecuteAsync(connection,
            $"CREATE DATABASE {PostgreSqlMigrationRuntimeBoundaryValidator.ControlDatabase} OWNER {ControlRole};");
        await ExecuteAsync(connection, $"CREATE DATABASE {CanonicalDatabase};");
        await ExecuteAsync(connection, "REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;");
        await ExecuteAsync(connection, "REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;");
        await ExecuteAsync(connection,
            $"REVOKE CONNECT ON DATABASE {PostgreSqlMigrationRuntimeBoundaryValidator.ControlDatabase} FROM PUBLIC;");
        await ExecuteAsync(connection, $"REVOKE CONNECT ON DATABASE {CanonicalDatabase} FROM PUBLIC;");
        await ExecuteAsync(connection,
            $"GRANT CONNECT, CREATE ON DATABASE {PostgreSqlMigrationRuntimeBoundaryValidator.ControlDatabase} TO {ControlRole};");
        await ExecuteAsync(connection, $"GRANT CONNECT ON DATABASE postgres TO {ShadowAdminRole};");
    }

    public Task DisposeAsync()
    {
        return _container.DisposeAsync().AsTask();
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }
}

internal sealed class TestcontainerShadowDatabaseProvisioner(string administratorConnectionString)
    : IPostgreSqlShadowDatabaseProvisioner
{
    public async Task ProvisionWithConnectionsDisabledAsync(
        ShadowDatabase shadow,
        string ownerRole,
        CancellationToken cancellationToken)
    {
        await ExecuteAsync(
            $"CREATE DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(shadow.Name)} OWNER {PostgreSqlShadowTarget.QuoteIdentifier(ownerRole)} ALLOW_CONNECTIONS false TEMPLATE template0;",
            cancellationToken);
    }

    public Task EnableConnectionsAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
    {
        return ExecuteAsync(
            $"ALTER DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(shadow.Name)} ALLOW_CONNECTIONS true;",
            cancellationToken);
    }

    public Task DeleteAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
    {
        return ExecuteAsync(
            $"DROP DATABASE IF EXISTS {PostgreSqlShadowTarget.QuoteIdentifier(shadow.Name)} WITH (FORCE);",
            cancellationToken);
    }

    private async Task ExecuteAsync(string sql, CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(administratorConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync(cancellationToken);
    }
}

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlShadowTargetIntegrationTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task ApplySchema_TranslatedComputedColumns_AreImmutableAndReconcileOnPostgreSql18()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        string runId = Guid.NewGuid().ToString("D");
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "ComputedColumns",
            $"legacy_shadow_compute_{Guid.NewGuid():N}",
            runId,
            CancellationToken.None);

        try
        {
            var columnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ID"] = "integer",
                ["FirstName"] = "character varying(256)",
                ["LastName"] = "character varying(256)",
                ["FullName"] = "character varying(513)",
                ["UnitPrice"] = "numeric(18,2)",
                ["Quantity"] = "integer",
                ["Manufactured"] = "integer",
                ["Remaining"] = "integer",
                ["DiscountPercent"] = "numeric(5,2)",
                ["Subtotal"] = "numeric(18,2)",
                ["Total"] = "numeric(18,2)",
                ["WithholdingTax"] = "numeric(18,2)",
                ["QuotedAmount"] = "numeric(18,2)",
                ["CreatedDate"] = "timestamp without time zone",
                ["FinishedDate"] = "date",
                ["Turnaround"] = "integer",
            };
            var sourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ID"] = "int",
                ["FirstName"] = "nvarchar(256)",
                ["LastName"] = "nvarchar(256)",
                ["FullName"] = "nvarchar(513)",
                ["UnitPrice"] = "decimal(18,2)",
                ["Quantity"] = "int",
                ["Manufactured"] = "int",
                ["Remaining"] = "int",
                ["DiscountPercent"] = "decimal(5,2)",
                ["Subtotal"] = "decimal(18,2)",
                ["Total"] = "decimal(18,2)",
                ["WithholdingTax"] = "decimal(18,2)",
                ["QuotedAmount"] = "decimal(18,2)",
                ["CreatedDate"] = "datetime2(6)",
                ["FinishedDate"] = "date",
                ["Turnaround"] = "int",
            };
            var table = new TableCopyPlan(
                "dbo",
                "ComputedColumns",
                "public",
                "ComputedColumns",
                ["ID", "FirstName", "LastName", "FullName", "UnitPrice", "Quantity", "Manufactured", "Remaining", "DiscountPercent", "Subtotal", "Total", "WithholdingTax", "QuotedAmount", "CreatedDate", "FinishedDate", "Turnaround"],
                ["ID"])
            {
                SourceColumnTypes = sourceColumnTypes,
                ColumnTypes = columnTypes,
                NullableColumns = ["FirstName", "LastName", "FullName", "FinishedDate", "Turnaround"],
                PrimaryKey = new PrimaryKeyCopyPlan("PK_ComputedColumns", ["ID"]),
                GeneratedColumns =
                [
                    new("FullName", SqlServerMigrationSource.TranslateGeneratedExpressionForPostgreSql("(Trim(concat([FirstName],N' ',[LastName])))", sourceColumnTypes, columnTypes)),
                    new("Remaining", SqlServerMigrationSource.TranslateGeneratedExpressionForPostgreSql("([Quantity]-[Manufactured])", sourceColumnTypes, columnTypes)),
                    new("Subtotal", SqlServerMigrationSource.TranslateGeneratedExpressionForPostgreSql("(CONVERT([decimal](18,2),[UnitPrice]*[Quantity]-(([UnitPrice]*[Quantity])*[DiscountPercent])/(100)))", sourceColumnTypes, columnTypes)),
                    new("QuotedAmount", SqlServerMigrationSource.TranslateGeneratedExpressionForPostgreSql("(CONVERT([decimal](18,2),[Total]-[WithholdingTax]))", sourceColumnTypes, columnTypes)),
                    new("Turnaround", SqlServerMigrationSource.TranslateGeneratedExpressionForPostgreSql("(datediff(day,[CreatedDate],[FinishedDate]))", sourceColumnTypes, columnTypes)),
                ],
            };
            var draft = new DatabaseSchemaPlan("ComputedColumns", "1.0", Hash("source"), Hash("target"), [table]);
            DatabaseSchemaPlan plan = draft with
            {
                TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft),
            };

            await using IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await transaction.ApplySchemaAsync(plan, CancellationToken.None);

            var row = new MigrationRow(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["ID"] = 1,
                ["FirstName"] = null,
                ["LastName"] = "Doe",
                ["FullName"] = "Doe",
                ["UnitPrice"] = 0.15m,
                ["Quantity"] = 1,
                ["Manufactured"] = 0,
                ["Remaining"] = 1,
                ["DiscountPercent"] = 10.00m,
                ["Subtotal"] = 0.14m,
                ["Total"] = 100.00m,
                ["WithholdingTax"] = 7.00m,
                ["QuotedAmount"] = 93.00m,
                ["CreatedDate"] = new DateTime(2026, 1, 1, 23, 59, 0, DateTimeKind.Unspecified),
                ["FinishedDate"] = new DateTime(2026, 1, 2),
                ["Turnaround"] = 1,
            });
            Assert.Equal(1L, await transaction.CopyBatchAsync(table, [row], CancellationToken.None));
            await transaction.FinalizeSchemaAsync(plan, CancellationToken.None);
            Assert.Equal(
                plan.TargetSchemaSha256,
                await transaction.InspectSchemaAsync(plan, CancellationToken.None));
            Assert.Equal(1L, (await transaction.InspectTableAsync(table, CancellationToken.None)).RowCount);
            Assert.Empty(await transaction.InspectSequenceNextValuesAsync(plan, CancellationToken.None));
            await transaction.CommitAsync(CancellationToken.None);

            await using var verification = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString)
            {
                Database = shadow.Name,
            }.ConnectionString);
            await verification.OpenAsync();
            await using var command = new NpgsqlCommand(
                "SELECT \"FullName\", \"Subtotal\", \"Remaining\", \"QuotedAmount\", \"Turnaround\" FROM \"public\".\"ComputedColumns\" WHERE \"ID\" = 1;",
                verification);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal("Doe", reader.GetString(0));
            Assert.Equal(0.14m, reader.GetDecimal(1));
            Assert.Equal(1, reader.GetInt32(2));
            Assert.Equal(93.00m, reader.GetDecimal(3));
            Assert.Equal(1, reader.GetInt32(4));
            Assert.False(await reader.ReadAsync());
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task ApplySchema_UtcClockDefault_ReconcilesWithPostgreSqlDeparser()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        string runId = Guid.NewGuid().ToString("D");
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Contact",
            $"legacy_shadow_contact_{Guid.NewGuid():N}",
            runId,
            CancellationToken.None);

        try
        {
            var table = new TableCopyPlan(
                "dbo",
                "Message",
                "public",
                "Message",
                ["ID", "CreatedDate"],
                ["ID"])
            {
                SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["ID"] = "int",
                    ["CreatedDate"] = "datetime2",
                },
                ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["ID"] = "integer",
                    ["CreatedDate"] = "timestamp without time zone",
                },
                NullableColumns = ["CreatedDate"],
                PrimaryKey = new PrimaryKeyCopyPlan("PK_Message", ["ID"]),
                DefaultExpressions = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["CreatedDate"] = SqlServerMigrationSource.TranslateExpressionForPostgreSql("(getutcdate())"),
                },
            };
            var draft = new DatabaseSchemaPlan("Contact", "1.0", Hash("source"), Hash("target"), [table]);
            DatabaseSchemaPlan plan = draft with
            {
                TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft),
            };

            await using IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await transaction.ApplySchemaAsync(plan, CancellationToken.None);

            Assert.Equal(
                plan.TargetSchemaSha256,
                await transaction.InspectSchemaAsync(plan, CancellationToken.None));

            await transaction.RollbackAsync(CancellationToken.None);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task WholeDatabaseTransaction_DisposeClosesEphemeralShadowSessionBeforeCleanup()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        string runId = Guid.NewGuid().ToString("D");
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Contact",
            $"legacy_shadow_contact_{Guid.NewGuid():N}",
            runId,
            CancellationToken.None);

        try
        {
            await using (IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None))
            {
                await transaction.RollbackAsync(CancellationToken.None);
            }

            await using var observer = new NpgsqlConnection(fixture.ConnectionString);
            await observer.OpenAsync();
            await using var command = new NpgsqlCommand(
                "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE datname = $1;",
                observer);
            _ = command.Parameters.AddWithValue(shadow.Name);

            Assert.Equal(0L, (long)(await command.ExecuteScalarAsync() ?? -1L));
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task Exact25DeterministicShadowNames_CreateAndDeleteWithoutPostgresTruncation()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        Guid runId = Guid.NewGuid();
        var created = new List<ShadowDatabase>();
        try
        {
            foreach (string database in DatabaseInventory.ActiveDatabases)
            {
                string shadowName = GuardedShadowMigrationRunner.CreateShadowName(database, runId);
                ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
                    database, shadowName, runId.ToString("D"), CancellationToken.None);
                created.Add(shadow);
                Assert.Equal(shadowName, shadow.Name);
                Assert.True(Encoding.UTF8.GetByteCount(shadow.Name) <= 63);
            }
        }
        finally
        {
            foreach (ShadowDatabase shadow in created)
            {
                await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
            }
        }
    }

    [Fact]
    public async Task FinalizeSchema_CyclicForeignKeys_AreAddedOnlyAfterAllDataAndIdentityReseeds()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Order", $"legacy_shadow_order_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), CancellationToken.None);
        try
        {
            TableCopyPlan left = CyclicTable("Left", "Right", "FK_Left_Right");
            TableCopyPlan right = CyclicTable("Right", "Left", "FK_Right_Left");
            var draft = new DatabaseSchemaPlan("Order", "1.0", Hash("source"), Hash("target"), [left, right]);
            DatabaseSchemaPlan plan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
            await using IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);

            await transaction.ApplySchemaAsync(plan, CancellationToken.None);
            Assert.Equal(1, await transaction.CopyBatchAsync(left,
                [new MigrationRow(new Dictionary<string, object?> { ["Id"] = 1, ["OtherId"] = 1 })], CancellationToken.None));
            Assert.Equal(1, await transaction.CopyBatchAsync(right,
                [new MigrationRow(new Dictionary<string, object?> { ["Id"] = 1, ["OtherId"] = 1 })], CancellationToken.None));
            await transaction.FinalizeSchemaAsync(plan, CancellationToken.None);

            Assert.Equal(plan.TargetSchemaSha256, await transaction.InspectSchemaAsync(plan, CancellationToken.None));
            await transaction.RollbackAsync(CancellationToken.None);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task CopyAndReconcile_LargeTextValue_StreamsWithoutFourMiBRejection()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Order", $"legacy_shadow_order_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), CancellationToken.None);
        try
        {
            TableCopyPlan table = new TableCopyPlan("dbo", "Order", "public", "orders", ["Id", "Name", "Payload"], ["Id"])
            {
                SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["Id"] = "int",
                    ["Name"] = "nvarchar(max)",
                    ["Payload"] = "varbinary(max)",
                },
                ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["Id"] = "integer",
                    ["Name"] = "text",
                    ["Payload"] = "bytea",
                },
                PrimaryKey = new PrimaryKeyCopyPlan("PK_orders", ["Id"]),
                SourceColumns =
                [
                    new("Id", "int", Hash("Id:int"), null),
                    new("Name", "nvarchar(max)", Hash("Name:nvarchar(max)"), 10 * 1024 * 1024),
                    new("Payload", "varbinary(max)", Hash("Payload:varbinary(max)"), 6 * 1024 * 1024),
                ],
            };
            var draft = new DatabaseSchemaPlan("Order", "1.0", Hash("source"), Hash("target"), [table]);
            DatabaseSchemaPlan plan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
            string largeText = new('ก', 3 * 1024 * 1024);
            var lob = new StreamingLob(StreamingLobKind.Text, 9L * 1024 * 1024, async (destination, cancellationToken) =>
            {
                await using var writer = new StreamWriter(destination, new UTF8Encoding(false, true), 32 * 1024, leaveOpen: true);
                await writer.WriteAsync(largeText.AsMemory(), cancellationToken);
                await writer.FlushAsync(cancellationToken);
            });
            byte[] largeBinary = Enumerable.Range(0, 5 * 1024 * 1024).Select(index => (byte)(index % 251)).ToArray();
            var binaryLob = new StreamingLob(StreamingLobKind.Binary, largeBinary.LongLength, async (destination, cancellationToken) =>
            {
                await using var source = new MemoryStream(largeBinary, writable: false);
                await source.CopyToAsync(destination, 64 * 1024, cancellationToken);
            });
            var row = new MigrationRow(new Dictionary<string, object?> { ["Id"] = 1, ["Name"] = lob, ["Payload"] = binaryLob });

            await using IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await transaction.ApplySchemaAsync(plan, CancellationToken.None);
            Assert.Equal(1, await transaction.CopyBatchAsync(table, [row], CancellationToken.None));
            using var expectedCollector = new TableEvidenceCollector(table);
            expectedCollector.Append(row);
            string expected = expectedCollector.Finish().ContentSha256;
            _ = await transaction.InspectSchemaAsync(plan, CancellationToken.None);
            TableReconciliationEvidence evidence = await transaction.InspectTableAsync(table, CancellationToken.None);
            Assert.Equal(expected, evidence.ContentSha256);
            await transaction.RollbackAsync(CancellationToken.None);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    private static TableCopyPlan CyclicTable(string tableName, string referencedTable, string foreignKeyName)
    {
        return new TableCopyPlan("dbo", tableName, "public", tableName.ToLowerInvariant(), ["Id", "OtherId"], ["Id"])
        {
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["Id"] = "int", ["OtherId"] = "int" },
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["Id"] = "integer", ["OtherId"] = "integer" },
            SourceColumns = [new("Id", "int", Hash($"{tableName}.Id"), null), new("OtherId", "int", Hash($"{tableName}.OtherId"), null)],
            IdentityColumns = ["Id"],
            Identities = [new("Id", 1, 1, 1, true)],
            PrimaryKey = new PrimaryKeyCopyPlan($"PK_{tableName}", ["Id"]),
            ForeignKeys =
            [
                new ForeignKeyCopyPlan(foreignKeyName, ["OtherId"], "public", referencedTable.ToLowerInvariant(), ["Id"])
                {
                    SourceReferencedSchema = "dbo",
                    SourceReferencedTable = referencedTable,
                    SourceReferencedColumns = ["Id"],
                },
            ],
        };
    }

    [Fact]
    public async Task CopyBatch_LaterStreamingColumnFailure_RollsBackWithoutRowsOrLargeObjects()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Order", $"legacy_shadow_order_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), CancellationToken.None);
        try
        {
            TableCopyPlan table = CreateStreamingTablePlan();
            var draft = new DatabaseSchemaPlan("Order", "1.0", Hash("source"), Hash("target"), [table]);
            DatabaseSchemaPlan plan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
            var first = new StreamingLob(StreamingLobKind.Text, 4, async (destination, cancellationToken) =>
            {
                await destination.WriteAsync("safe"u8.ToArray(), cancellationToken);
            });
            var second = new StreamingLob(StreamingLobKind.Binary, 4, async (destination, cancellationToken) =>
            {
                await destination.WriteAsync(new byte[] { 1, 2 }, cancellationToken);
                throw new InvalidOperationException("later source column failed");
            });
            await using IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await transaction.ApplySchemaAsync(plan, CancellationToken.None);

            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => transaction.CopyBatchAsync(
                table,
                [new MigrationRow(new Dictionary<string, object?> { ["Id"] = 1, ["Name"] = first, ["Payload"] = second })],
                CancellationToken.None));
            await transaction.RollbackAsync(CancellationToken.None);

            Assert.True(first.IsConsumed);
            Assert.False(second.IsConsumed);
            await AssertShadowHasNoMigrationArtifactsAsync(shadow);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task CopyBatch_QueryCancellation_RollsBackWithoutRowsOrLargeObjects()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Order", $"legacy_shadow_order_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), CancellationToken.None);
        try
        {
            TableCopyPlan table = CreateStreamingTablePlan();
            var draft = new DatabaseSchemaPlan("Order", "1.0", Hash("source"), Hash("target"), [table]);
            DatabaseSchemaPlan plan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
            var producerStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var lob = new StreamingLob(StreamingLobKind.Text, 9L * 1024 * 1024, async (destination, cancellationToken) =>
            {
                producerStarted.SetResult();
                byte[] chunk = new byte[64 * 1024];
                while (true)
                {
                    await destination.WriteAsync(chunk, cancellationToken);
                }
            });
            await using IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await transaction.ApplySchemaAsync(plan, CancellationToken.None);
            using var cancellation = new CancellationTokenSource();
            Task<long> copy = transaction.CopyBatchAsync(
                table,
                [new MigrationRow(new Dictionary<string, object?> { ["Id"] = 1, ["Name"] = lob, ["Payload"] = null })],
                cancellation.Token);
            await producerStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await cancellation.CancelAsync();

            _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => copy);
            await transaction.RollbackAsync(CancellationToken.None);

            Assert.False(lob.IsConsumed);
            await AssertShadowHasNoMigrationArtifactsAsync(shadow);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task CopyBatch_SuccessThenTransactionRollback_PersistsNoRowsOrLargeObjects()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Order", $"legacy_shadow_order_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), CancellationToken.None);
        try
        {
            TableCopyPlan table = CreateStreamingTablePlan();
            var draft = new DatabaseSchemaPlan("Order", "1.0", Hash("source"), Hash("target"), [table]);
            DatabaseSchemaPlan plan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
            var text = new StreamingLob(StreamingLobKind.Text, 4, async (destination, cancellationToken) =>
                await destination.WriteAsync("safe"u8.ToArray(), cancellationToken));
            await using IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await transaction.ApplySchemaAsync(plan, CancellationToken.None);
            Assert.Equal(1, await transaction.CopyBatchAsync(
                table,
                [new MigrationRow(new Dictionary<string, object?> { ["Id"] = 1, ["Name"] = text, ["Payload"] = null })],
                CancellationToken.None));
            await transaction.RollbackAsync(CancellationToken.None);

            await AssertShadowHasNoMigrationArtifactsAsync(shadow);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task CopyBatch_UnsafeSignedTextMaximum_FailsBeforeOpeningProducer()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Order", $"legacy_shadow_order_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), CancellationToken.None);
        try
        {
            TableCopyPlan table = CreateStreamingTablePlan() with
            {
                SourceColumns =
                [
                    new("Id", "int", Hash("Id:int"), null),
                    new("Name", "nvarchar(max)", Hash("Name:nvarchar(max)"), 500_000_001),
                    new("Payload", "varbinary(max)", Hash("Payload:varbinary(max)"), 10 * 1024 * 1024),
                ],
            };
            var draft = new DatabaseSchemaPlan("Order", "1.0", Hash("source"), Hash("target"), [table]);
            DatabaseSchemaPlan plan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
            var opened = false;
            var lob = new StreamingLob(StreamingLobKind.Text, 4, async (destination, cancellationToken) =>
            {
                opened = true;
                await destination.WriteAsync("safe"u8.ToArray(), cancellationToken);
            });
            await using IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await transaction.ApplySchemaAsync(plan, CancellationToken.None);

            MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                transaction.CopyBatchAsync(
                    table,
                    [new MigrationRow(new Dictionary<string, object?> { ["Id"] = 1, ["Name"] = lob, ["Payload"] = null })],
                    CancellationToken.None));
            await transaction.RollbackAsync(CancellationToken.None);

            Assert.Equal("streaming_lob_target_limit_invalid", exception.Code);
            Assert.False(opened);
            await AssertShadowHasNoMigrationArtifactsAsync(shadow);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ApplySchema_NullableSqlServerUniqueObject_UsesNullsNotDistinctSemantics(bool constraint)
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
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
            new PostgreSqlShadowTarget(new PostgreSqlShadowTargetOptions(string.Empty, null!)));
    }

    [Fact]
    public async Task WholeDatabaseTransaction_CopiesAndReconcilesBeforeCommit()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
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
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
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
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
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
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
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
            await transaction.FinalizeSchemaAsync(plan, CancellationToken.None);
            string actual = await transaction.InspectSchemaAsync(plan, CancellationToken.None);
            _ = await transaction.InspectTableAsync(table, CancellationToken.None);
            IReadOnlyDictionary<string, long> sequences = await transaction.InspectSequenceNextValuesAsync(plan, CancellationToken.None);
            await transaction.CommitAsync(CancellationToken.None);

            Assert.Equal(plan.TargetSchemaSha256, actual);
            Assert.Equal(150, sequences["sales.orders.Id"]);
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

    private static TableCopyPlan CreateStreamingTablePlan()
    {
        return new TableCopyPlan("dbo", "Order", "public", "orders", ["Id", "Name", "Payload"], ["Id"])
        {
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "int",
                ["Name"] = "nvarchar(max)",
                ["Payload"] = "varbinary(max)",
            },
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "integer",
                ["Name"] = "text",
                ["Payload"] = "bytea",
            },
            NullableColumns = ["Name", "Payload"],
            PrimaryKey = new PrimaryKeyCopyPlan("PK_orders", ["Id"]),
            SourceColumns =
            [
                new("Id", "int", Hash("Id:int"), null),
                new("Name", "nvarchar(max)", Hash("Name:nvarchar(max)"), 10 * 1024 * 1024),
                new("Payload", "varbinary(max)", Hash("Payload:varbinary(max)"), 10 * 1024 * 1024),
            ],
        };
    }

    private async Task AssertShadowHasNoMigrationArtifactsAsync(ShadowDatabase shadow)
    {
        var builder = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = shadow.Name };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            "SELECT count(*) FROM pg_largeobject_metadata; SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%';",
            connection);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(0, reader.GetInt64(0));
        Assert.True(await reader.NextResultAsync());
        Assert.True(await reader.ReadAsync());
        Assert.Equal(0, reader.GetInt64(0));
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
    public void Constructor_NonControlDatabase_FailsClosed()
    {
        _ = Assert.Throws<ArgumentException>(() => new PostgreSqlMigrationRunJournal(
            new PostgreSqlMigrationRunJournalOptions(fixture.ConnectionString)));
    }

    [Fact]
    public async Task CreateShadow_RevokesPublicWhileConnectionsRemainDisabled()
    {
        var provisioner = new BoundaryObservingProvisioner(fixture.ConnectionString, failEnable: false);
        var target = new PostgreSqlShadowTarget(new(
            fixture.ShadowAdminConnectionString,
            provisioner,
            fixture.ShadowAdminRole));
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Order", $"legacy_shadow_order_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), CancellationToken.None);
        try
        {
            Assert.True(provisioner.ObservedDisabledBeforeEnable);
            Assert.True(provisioner.ObservedPublicRevokedBeforeEnable);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task CreateShadow_EnableFailure_PreservesDisabledPartialDatabase()
    {
        var provisioner = new BoundaryObservingProvisioner(fixture.ConnectionString, failEnable: true);
        var target = new PostgreSqlShadowTarget(new(
            fixture.ShadowAdminConnectionString,
            provisioner,
            fixture.ShadowAdminRole));
        string shadowName = $"legacy_shadow_order_{Guid.NewGuid():N}";

        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => target.CreateUniqueEmptyShadowAsync(
            "Order", shadowName, Guid.NewGuid().ToString("D"), CancellationToken.None));

        Assert.False(provisioner.DeleteCalled);
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync(CancellationToken.None);
        await using var command = new NpgsqlCommand("SELECT NOT datallowconn FROM pg_database WHERE datname = $1;", connection);
        _ = command.Parameters.AddWithValue(shadowName);
        Assert.True((bool)(await command.ExecuteScalarAsync(CancellationToken.None))!);
    }

    [Fact]
    public void Constructor_UnsafeSchema_FailsClosed()
    {
        _ = Assert.Throws<ArgumentException>(() => new PostgreSqlMigrationRunJournal(
            new PostgreSqlMigrationRunJournalOptions(fixture.ControlConnectionString, "public; DROP SCHEMA public")));
    }

    [Fact]
    public async Task TryBeginAsync_ConcurrentSameRun_GrantsOneLeaseAndReportsInProgress()
    {
        var journal = new PostgreSqlMigrationRunJournal(
            new PostgreSqlMigrationRunJournalOptions(fixture.ControlConnectionString, $"journal_{Guid.NewGuid():N}"));
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
            new PostgreSqlMigrationRunJournalOptions(fixture.ControlConnectionString, schema));
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
            new PostgreSqlMigrationRunJournalOptions(fixture.ControlConnectionString, schema));
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
            new PostgreSqlMigrationRunJournalOptions(fixture.ControlConnectionString, schema));
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
        await using var connection = new NpgsqlConnection(fixture.ControlConnectionString);
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

internal sealed class BoundaryObservingProvisioner(string administratorConnectionString, bool failEnable)
    : IPostgreSqlShadowDatabaseProvisioner
{
    private readonly TestcontainerShadowDatabaseProvisioner _inner = new(administratorConnectionString);

    public bool ObservedDisabledBeforeEnable { get; private set; }

    public bool ObservedPublicRevokedBeforeEnable { get; private set; }

    public bool DeleteCalled { get; private set; }

    public Task ProvisionWithConnectionsDisabledAsync(ShadowDatabase shadow, string ownerRole, CancellationToken cancellationToken)
    {
        return _inner.ProvisionWithConnectionsDisabledAsync(shadow, ownerRole, cancellationToken);
    }

    public async Task EnableConnectionsAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(administratorConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT NOT datallowconn,
                   NOT EXISTS (
                       SELECT 1 FROM aclexplode(COALESCE(datacl, acldefault('d', datdba))) acl
                       WHERE acl.grantee = 0 AND acl.privilege_type = 'CONNECT')
            FROM pg_database WHERE datname = $1;
            """, connection);
        _ = command.Parameters.AddWithValue(shadow.Name);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        Assert.True(await reader.ReadAsync(cancellationToken));
        ObservedDisabledBeforeEnable = reader.GetBoolean(0);
        ObservedPublicRevokedBeforeEnable = reader.GetBoolean(1);
        if (failEnable)
        {
            throw new InvalidOperationException("Injected enable failure.");
        }

        await _inner.EnableConnectionsAsync(shadow, cancellationToken);
    }

    public async Task DeleteAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
    {
        DeleteCalled = true;
        await _inner.DeleteAsync(shadow, cancellationToken);
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
                "Host=postgres.example;Database=postgres;Username=reviewer",
                new TestcontainerShadowDatabaseProvisioner(
                    "Host=postgres.example;Database=postgres;Username=provisioner")),
            new PostgreSqlMigrationRunJournalOptions(
                "Host=postgres.example;Database=legacy_migration_control;Username=control")));

        _ = Assert.IsType<SqlServerMigrationSource>(runtime.Source);
        _ = Assert.IsType<PostgreSqlShadowTarget>(runtime.ShadowTarget);
        _ = Assert.IsType<PostgreSqlMigrationRunJournal>(runtime.Journal);
        await runtime.DisposeAsync();
    }
}
