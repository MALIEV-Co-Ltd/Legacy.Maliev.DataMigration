using Microsoft.Data.SqlClient;
using Npgsql;
using Testcontainers.MsSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentQuotationSourceIntegrationTests
{
    [SqlServerIntegrationFact]
    public async Task CurrentScripts_DeriveExactOutboxCatalogAndCopyEveryRowColumnIntoPostgreSql18()
    {
        string password = $"M!{Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(20))}a1";
        await using MsSqlContainer sqlServer = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04")
            .WithPassword(password)
            .Build();
        var postgres = new PostgreSqlAdapterFixture();
        await Task.WhenAll(sqlServer.StartAsync(), postgres.InitializeAsync());

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
                string scriptText = await File.ReadAllTextAsync(FixturePath(script.Path));
                string canonical = scriptText.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
                string observed = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
                Assert.Equal(script.CanonicalTextSha256, observed);
                await ExecuteAsync(setup, scriptText);
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
        TableCopyPlan quotation = Assert.Single(plan.Tables, table => table.SourceTable == "Quotation");
        Assert.Equal(["ID", "SourceRequestID", "SourceJourneyID", "AcceptedUtc", "AcceptanceOrigin"], quotation.OrderedColumns);
        Assert.Equal(["IX_Quotation_SourceJourneyID", "IX_Quotation_SourceRequestID"], quotation.Indexes.Select(index => index.Name).Order());

        TableCopyPlan analytics = Assert.Single(plan.Tables, table => table.SourceTable == "GoogleAnalyticsOutbox");
        Assert.Equal(
            ["IX_GoogleAnalyticsOutbox_Due", "IX_GoogleAnalyticsOutbox_QuotationID", "IX_GoogleAnalyticsOutbox_SourceJourneyID", "IX_GoogleAnalyticsOutbox_SourceRequestID", "UX_GoogleAnalyticsOutbox_EventKey"],
            analytics.Indexes.Select(index => index.Name).Order());
        ForeignKeyCopyPlan analyticsQuotation = Assert.Single(analytics.ForeignKeys);
        Assert.Equal("FK_GoogleAnalyticsOutbox_Quotation", analyticsQuotation.Name);
        Assert.Equal(["QuotationID"], analyticsQuotation.Columns);
        Assert.Equal(["ID"], analyticsQuotation.ReferencedColumns);

        TableCopyPlan outcomes = Assert.Single(plan.Tables, table => table.SourceTable == "QuotationOutcomeOutbox");
        Assert.Equal(["IX_QuotationOutcomeOutbox_QuotationID", "IX_QuotationOutcomeOutbox_SourceJourneyID", "IX_QuotationOutcomeOutbox_SourceRequestID"], outcomes.Indexes.Select(index => index.Name).Order());
        Assert.Equal(["EventKey"], Assert.Single(outcomes.UniqueConstraints).Columns);

        IReadOnlyDictionary<string, long> sourceSequences =
            await source.InspectSequenceNextValuesAsync(database, plan, CancellationToken.None);
        Assert.Contains(sourceSequences, pair => pair.Key.EndsWith("GoogleAnalyticsOutbox.ID", StringComparison.Ordinal) && pair.Value == 48);
        Assert.Contains(sourceSequences, pair => pair.Key.EndsWith("QuotationOutcomeOutbox.ID", StringComparison.Ordinal) && pair.Value == 57);

        PostgreSqlShadowTarget target = postgres.CreateShadowTarget();
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
            await ProveCanonicalAdoptionAndRestrictedArchiveAsync(postgres.ConnectionString, shadow.Name);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
            await source.RollbackDatabaseSnapshotAsync(database, CancellationToken.None);
            await postgres.DisposeAsync();
        }
    }

    private static async Task ProveCanonicalAdoptionAndRestrictedArchiveAsync(string adminConnectionString, string database)
    {
        string role = $"legacy_analytics_reader_{Guid.NewGuid():N}";
        var builder = new NpgsqlConnectionStringBuilder(adminConnectionString) { Database = database };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"""
            CREATE TABLE "QuotationAcceptedOutcome" (
                "ID" bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                "EventKey" character varying(128) NOT NULL UNIQUE,
                "QuotationID" integer NOT NULL,
                "SourceRequestID" integer NULL,
                "SourceJourneyID" uuid NULL,
                "AcceptedUtc" timestamp without time zone NOT NULL,
                "AcceptedUtcSubMicrosecondTicks" smallint NOT NULL DEFAULT 0,
                "AcceptanceOrigin" character varying(16) NOT NULL);
            CREATE SCHEMA legacy_compatibility;
            CREATE TABLE legacy_compatibility."GoogleAnalyticsOutbox"
                AS TABLE public."GoogleAnalyticsOutbox" WITH DATA;
            REVOKE ALL ON legacy_compatibility."GoogleAnalyticsOutbox" FROM PUBLIC;
            CREATE ROLE {role} NOLOGIN;
            GRANT USAGE ON SCHEMA legacy_compatibility TO {role};
            GRANT SELECT ON legacy_compatibility."GoogleAnalyticsOutbox" TO {role};
            INSERT INTO "QuotationAcceptedOutcome"
                ("ID", "EventKey", "QuotationID", "SourceRequestID", "SourceJourneyID", "AcceptedUtc",
                 "AcceptedUtcSubMicrosecondTicks", "AcceptanceOrigin")
            SELECT "ID", "EventKey", "QuotationID", "SourceRequestID", "SourceJourneyID",
                   left("AcceptedUtc", 26)::timestamp without time zone,
                   right("AcceptedUtc", 1)::smallint, "AcceptanceOrigin"
            FROM public."QuotationOutcomeOutbox";
            SELECT setval(pg_get_serial_sequence('"QuotationAcceptedOutcome"', 'ID'), 56, true);
            """;
        _ = await command.ExecuteNonQueryAsync();

        command.CommandText = """
            SELECT COUNT(*) FROM (
                SELECT "ID", "EventKey", "QuotationID", "SourceRequestID", "SourceJourneyID",
                       to_char("AcceptedUtc", 'YYYY-MM-DD"T"HH24:MI:SS.US') || "AcceptedUtcSubMicrosecondTicks"::text AS accepted,
                       "AcceptanceOrigin"
                FROM "QuotationAcceptedOutcome"
                EXCEPT
                SELECT "ID", "EventKey", "QuotationID", "SourceRequestID", "SourceJourneyID", "AcceptedUtc", "AcceptanceOrigin"
                FROM public."QuotationOutcomeOutbox") drift;
            """;
        Assert.Equal(0L, (long)(await command.ExecuteScalarAsync())!);

        command.CommandText = """
            INSERT INTO "QuotationAcceptedOutcome"
                ("ID", "EventKey", "QuotationID", "SourceRequestID", "SourceJourneyID", "AcceptedUtc",
                 "AcceptedUtcSubMicrosecondTicks", "AcceptanceOrigin")
            SELECT "ID", "EventKey", "QuotationID", "SourceRequestID", "SourceJourneyID",
                   left("AcceptedUtc", 26)::timestamp without time zone,
                   right("AcceptedUtc", 1)::smallint, "AcceptanceOrigin"
            FROM public."QuotationOutcomeOutbox" source
            WHERE NOT EXISTS (SELECT 1 FROM "QuotationAcceptedOutcome" target WHERE target."ID" = source."ID");
            """;
        Assert.Equal(0, await command.ExecuteNonQueryAsync());

        command.CommandText = $"""
            SELECT array_agg(privilege_type ORDER BY privilege_type)
            FROM information_schema.role_table_grants
            WHERE grantee = '{role}' AND table_schema = 'legacy_compatibility'
              AND table_name = 'GoogleAnalyticsOutbox';
            """;
        Assert.Equal(["SELECT"], (string[])(await command.ExecuteScalarAsync())!);
        command.CommandText = """
            SELECT
              (SELECT COUNT(*) FROM public."GoogleAnalyticsOutbox") =
              (SELECT COUNT(*) FROM legacy_compatibility."GoogleAnalyticsOutbox")
              AND NOT EXISTS (
                SELECT * FROM public."GoogleAnalyticsOutbox"
                EXCEPT SELECT * FROM legacy_compatibility."GoogleAnalyticsOutbox")
              AND NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname ILIKE '%google%analytics%worker%')
              AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname ILIKE '%google%analytics%credential%');
            """;
        Assert.True((bool)(await command.ExecuteScalarAsync())!);
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
