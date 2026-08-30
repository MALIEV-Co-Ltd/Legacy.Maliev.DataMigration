using Microsoft.Data.SqlClient;
using Testcontainers.MsSql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentQuotationSourceIntegrationTests
{
    [SqlServerIntegrationFact]
    public async Task CurrentScripts_DeriveExactOutboxCatalogAndCopyEveryRowColumnIntoPostgreSql18()
    {
        const string password = "MALIEV_test_Only!123456";
        await using MsSqlContainer sqlServer = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04")
            .WithPassword(password)
            .Build();
        await using PostgreSqlContainer postgres = new PostgreSqlBuilder("postgres:18-alpine").Build();
        await Task.WhenAll(sqlServer.StartAsync(), postgres.StartAsync());

        const string database = "QuotationCurrentSource";
        await using (var master = new SqlConnection(sqlServer.GetConnectionString()))
        {
            await master.OpenAsync();
            await ExecuteAsync(master, $"CREATE DATABASE [{database}]; ALTER DATABASE [{database}] SET ALLOW_SNAPSHOT_ISOLATION ON;");
        }

        var sourceBuilder = new SqlConnectionStringBuilder(sqlServer.GetConnectionString()) { InitialCatalog = database };
        await using (var setup = new SqlConnection(sourceBuilder.ConnectionString))
        {
            await setup.OpenAsync();
            await ExecuteAsync(setup, "CREATE TABLE dbo.Quotation (ID int IDENTITY(1,1) NOT NULL CONSTRAINT PK_Quotation PRIMARY KEY);");
            foreach (SourceScriptContract script in CurrentQuotationSourceContract.SourceScripts)
            {
                await ExecuteAsync(setup, await File.ReadAllTextAsync(FixturePath(script.Path)));
            }

            await ExecuteAsync(setup, """
                SET IDENTITY_INSERT dbo.Quotation ON;
                INSERT dbo.Quotation (ID) VALUES (7001), (7002);
                SET IDENTITY_INSERT dbo.Quotation OFF;

                SET IDENTITY_INSERT dbo.GoogleAnalyticsOutbox ON;
                INSERT dbo.GoogleAnalyticsOutbox
                    (ID, QuotationID, EventKey, EventName, ClientId, SessionId, UserId, Currency, Value,
                     OccurredUtc, AttemptCount, NextAttemptUtc, LeaseToken, LeaseUntilUtc, SentUtc, FailedUtc,
                     LastError, SourceRequestID, SourceJourneyID)
                VALUES
                    (31, 7001, N'ga:7001', N'generate_lead', N'client-1', N'session-1', NULL, 'THB', 1200.25,
                     '2026-08-30T08:09:10.1234567', 0, '2026-08-30T08:09:10.1234567', NULL, NULL, NULL, NULL,
                     NULL, NULL, '11111111-2222-3333-4444-555555555555'),
                    (32, 7002, N'ga:7002', N'generate_lead', N'client-2', N'session-2', N'user-2', 'THB', 99.99,
                     '2026-08-30T09:10:11.7654321', 2, '2026-08-30T10:10:11.7654321',
                     'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', '2026-08-30T09:20:11.7654321',
                     '2026-08-30T09:30:11.7654321', NULL, N'retry', 91, NULL);
                SET IDENTITY_INSERT dbo.GoogleAnalyticsOutbox OFF;

                SET IDENTITY_INSERT dbo.QuotationOutcomeOutbox ON;
                INSERT dbo.QuotationOutcomeOutbox
                    (ID, EventKey, QuotationID, SourceRequestID, SourceJourneyID, AcceptedUtc, AcceptanceOrigin)
                VALUES
                    (41, N'quotation-accepted:7001', 7001, NULL,
                     '11111111-2222-3333-4444-555555555555', '2026-08-30T08:09:10.1234567', 'customer'),
                    (42, N'quotation-accepted:7002', 7002, 91, NULL,
                     '2026-08-30T09:10:11.7654321', 'employee');
                SET IDENTITY_INSERT dbo.QuotationOutcomeOutbox OFF;
                DBCC CHECKIDENT ('dbo.GoogleAnalyticsOutbox', RESEED, 47);
                DBCC CHECKIDENT ('dbo.QuotationOutcomeOutbox', RESEED, 56);
                """);
        }

        await using var source = new SqlServerMigrationSource(new SqlServerMigrationSourceOptions(sourceBuilder.ConnectionString));
        await source.BeginDatabaseSnapshotAsync(database, CancellationToken.None);
        DatabaseSchemaPlan plan = await source.GenerateDatabasePlanAsync(database, CancellationToken.None);
        Assert.Equal(3, plan.Tables.Count);
        AssertTable(plan, CurrentQuotationSourceContract.GoogleAnalyticsOutbox);
        AssertTable(plan, CurrentQuotationSourceContract.QuotationOutcomeOutbox);

        IReadOnlyDictionary<string, long> sourceSequences =
            await source.InspectSequenceNextValuesAsync(database, plan, CancellationToken.None);
        Assert.Contains(sourceSequences, pair => pair.Key.EndsWith("GoogleAnalyticsOutbox.ID", StringComparison.Ordinal) && pair.Value == 48);
        Assert.Contains(sourceSequences, pair => pair.Key.EndsWith("QuotationOutcomeOutbox.ID", StringComparison.Ordinal) && pair.Value == 57);

        var target = new PostgreSqlShadowTarget(new PostgreSqlShadowTargetOptions(postgres.GetConnectionString()));
        string runId = Guid.NewGuid().ToString("D");
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            database,
            $"legacy_shadow_quotation_{Guid.NewGuid():N}",
            runId,
            CancellationToken.None);
        try
        {
            await using IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await transaction.ApplySchemaAsync(plan, CancellationToken.None);
            foreach (TableCopyPlan table in plan.Tables)
            {
                List<MigrationRow> rows = [];
                await foreach (MigrationRow row in source.ReadTableAsync(database, table, CancellationToken.None))
                {
                    rows.Add(row);
                }

                AssertSourceOutboxFacts(table, rows);
                Assert.Equal(rows.Count, await transaction.CopyBatchAsync(table, rows, CancellationToken.None));
            }

            await transaction.FinalizeSchemaAsync(plan, CancellationToken.None);
            Assert.Equal(plan.TargetSchemaSha256, await transaction.InspectSchemaAsync(plan, CancellationToken.None));
            foreach (TableCopyPlan table in plan.Tables)
            {
                TableReconciliationEvidence evidence = await transaction.InspectTableAsync(table, CancellationToken.None);
                Assert.Equal(2, evidence.RowCount);
                Assert.Equal(table.OrderedColumns.Count, evidence.NullCounts.Count);
                AssertTargetOutboxNulls(table, evidence);
            }

            IReadOnlyDictionary<string, long> targetSequences =
                await transaction.InspectSequenceNextValuesAsync(plan, CancellationToken.None);
            Assert.Equal(sourceSequences.OrderBy(pair => pair.Key), targetSequences.OrderBy(pair => pair.Key));
            await transaction.CommitAsync(CancellationToken.None);
            await source.CompleteDatabaseSnapshotAsync(database, CancellationToken.None);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
            await source.RollbackDatabaseSnapshotAsync(database, CancellationToken.None);
        }
    }

    private static void AssertSourceOutboxFacts(TableCopyPlan table, List<MigrationRow> rows)
    {
        if (table.SourceTable == "GoogleAnalyticsOutbox")
        {
            Assert.Equal([31L, 32L], rows.Select(row => Assert.IsType<long>(row.Values["ID"])).ToArray());
            Assert.Equal(
                ["2026-08-30T08:09:10.1234567", "2026-08-30T09:10:11.7654321"],
                rows.Select(row => Assert.IsType<string>(row.Values["OccurredUtc"])).ToArray());
            Assert.Null(rows[0].Values["SourceRequestID"]);
            Assert.Equal(Guid.Parse("11111111-2222-3333-4444-555555555555"), rows[0].Values["SourceJourneyID"]);
            Assert.Equal(91, rows[1].Values["SourceRequestID"]);
            Assert.Null(rows[1].Values["SourceJourneyID"]);
        }
        else if (table.SourceTable == "QuotationOutcomeOutbox")
        {
            Assert.Equal([41L, 42L], rows.Select(row => Assert.IsType<long>(row.Values["ID"])).ToArray());
            Assert.Equal(
                ["2026-08-30T08:09:10.1234567", "2026-08-30T09:10:11.7654321"],
                rows.Select(row => Assert.IsType<string>(row.Values["AcceptedUtc"])).ToArray());
            Assert.Null(rows[0].Values["SourceRequestID"]);
            Assert.Equal(Guid.Parse("11111111-2222-3333-4444-555555555555"), rows[0].Values["SourceJourneyID"]);
            Assert.Equal(91, rows[1].Values["SourceRequestID"]);
            Assert.Null(rows[1].Values["SourceJourneyID"]);
        }
    }

    private static void AssertTargetOutboxNulls(TableCopyPlan table, TableReconciliationEvidence evidence)
    {
        if (table.SourceTable == "GoogleAnalyticsOutbox")
        {
            Assert.Equal(1, evidence.NullCounts["UserId"]);
            Assert.Equal(1, evidence.NullCounts["LeaseToken"]);
            Assert.Equal(1, evidence.NullCounts["LeaseUntilUtc"]);
            Assert.Equal(1, evidence.NullCounts["SentUtc"]);
            Assert.Equal(2, evidence.NullCounts["FailedUtc"]);
            Assert.Equal(1, evidence.NullCounts["LastError"]);
            Assert.Equal(1, evidence.NullCounts["SourceRequestID"]);
            Assert.Equal(1, evidence.NullCounts["SourceJourneyID"]);
        }
        else if (table.SourceTable == "QuotationOutcomeOutbox")
        {
            Assert.Equal(1, evidence.NullCounts["SourceRequestID"]);
            Assert.Equal(1, evidence.NullCounts["SourceJourneyID"]);
        }
    }

    private static void AssertTable(DatabaseSchemaPlan plan, SourceTableContract expected)
    {
        TableCopyPlan actual = Assert.Single(plan.Tables, table =>
            string.Equals($"{table.SourceSchema}.{table.SourceTable}", expected.Name, StringComparison.Ordinal));
        Assert.Equal(expected.Columns.Select(column => column.Name), actual.OrderedColumns);
        foreach (SourceColumnContract column in expected.Columns)
        {
            Assert.Equal(column.StoreType, actual.SourceColumnTypes[column.Name]);
        }

        SourceIdentityContract identity = Assert.IsType<SourceIdentityContract>(expected.Column("ID").Identity);
        IdentityCopyPlan actualIdentity = Assert.Single(actual.Identities);
        Assert.Equal(identity.Seed, actualIdentity.SeedValue);
        Assert.Equal(identity.Increment, actualIdentity.IncrementValue);
    }

    private static async Task ExecuteAsync(SqlConnection connection, string sql)
    {
        await using var command = new SqlCommand(sql, connection) { CommandTimeout = 0 };
        _ = await command.ExecuteNonQueryAsync();
    }

    private static string FixturePath(string sourcePath)
    {
        string fileName = Path.GetFileName(sourcePath);
        string nested = Path.Combine(AppContext.BaseDirectory, "Fixtures", "SourceScripts", fileName);
        return File.Exists(nested) ? nested : Path.Combine(AppContext.BaseDirectory, fileName);
    }
}
