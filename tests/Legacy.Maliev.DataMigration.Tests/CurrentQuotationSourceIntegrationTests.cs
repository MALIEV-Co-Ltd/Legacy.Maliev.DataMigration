using Microsoft.Data.SqlClient;
using Npgsql;
using System.Security.Cryptography;
using Testcontainers.MsSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentQuotationSourceIntegrationTests
{
    [SqlServerIntegrationFact]
    public async Task CurrentScripts_DeriveExactOutboxCatalogAndCopyEveryRowColumnIntoPostgreSql18()
    {
        string password = $"M!{Convert.ToHexString(RandomNumberGenerator.GetBytes(20))}a1";
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
                string observed = Convert.ToHexString(SHA256.HashData(
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
        string efSql = await File.ReadAllTextAsync(Path.Combine(
            AppContext.BaseDirectory, "Fixtures", "Quotation", "bd201a5-quotation-accepted-outcome.sql"));
        string canonicalEfSql = efSql.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
        Assert.Equal("d1589fae889f025386ecc8dbf01649fb999a7eb33afd0a702d769054a59d7ad1",
            Convert.ToHexString(SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(canonicalEfSql))).ToLowerInvariant());
        command.CommandText = efSql;
        _ = await command.ExecuteNonQueryAsync();

        command.CommandText = $"""
            CREATE SCHEMA legacy_compatibility;
            CREATE TABLE legacy_compatibility."GoogleAnalyticsOutbox"
                AS TABLE public."GoogleAnalyticsOutbox" WITH DATA;
            REVOKE ALL ON legacy_compatibility."GoogleAnalyticsOutbox" FROM PUBLIC;
            CREATE ROLE {role} NOLOGIN;
            GRANT USAGE ON SCHEMA legacy_compatibility TO {role};
            GRANT SELECT ON legacy_compatibility."GoogleAnalyticsOutbox" TO {role};
            """;
        _ = await command.ExecuteNonQueryAsync();

        command.CommandText = """
            SELECT "ID", "EventKey", "QuotationID", "SourceRequestID", "SourceJourneyID", "AcceptedUtc", "AcceptanceOrigin"
            FROM public."QuotationOutcomeOutbox" ORDER BY "ID";
            """;
        List<QuotationOutcomeSourceRow> sourceRows = [];
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync())
        {
            while (await reader.ReadAsync())
            {
                sourceRows.Add(new(reader.GetInt64(0), reader.GetString(1), reader.GetInt32(2),
                    reader.IsDBNull(3) ? null : reader.GetInt32(3), reader.IsDBNull(4) ? null : reader.GetGuid(4),
                    DateTime.ParseExact(reader.GetString(5), "yyyy-MM-dd'T'HH:mm:ss.fffffff", null), reader.GetString(6)));
            }
        }

        string schemaSha = await PostgreSqlQuotationOutcomeAdopter.ComputeCanonicalSchemaSha256Async(connection, CancellationToken.None);
        Assert.Equal("20cec0a7873ce38bab995ac03286e97b047bdd2e40b476a2372013834672d3bb", schemaSha);
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        QuotationOutcomeAdoptionContract unsigned = CurrentQuotationSourceContract.CreateAdoptionContract(
            schemaSha, "quotation-integration-key", sourceRows, [], 57);
        QuotationOutcomeAdoptionContract signed = QuotationOutcomeAdoptionAttestation.Sign(unsigned, signingKey);
        var trust = new ReceiptAttestationTrustStore(
            [new TrustedAttestationKey("quotation-integration-key", signingKey.ExportSubjectPublicKeyInfo())]);
        command.CommandText = $"""
            SELECT array_agg(privilege_type ORDER BY privilege_type)
            FROM information_schema.role_table_grants
            WHERE grantee = '{role}' AND table_schema = 'legacy_compatibility'
              AND table_name = 'GoogleAnalyticsOutbox';
            """;
        string[] archivePrivileges = (string[])(await command.ExecuteScalarAsync())!;
        command.CommandText = """
            SELECT
              EXISTS (SELECT 1 FROM pg_proc WHERE proname ILIKE '%google%analytics%worker%'),
              EXISTS (SELECT 1 FROM pg_roles WHERE rolname ILIKE '%google%analytics%credential%');
            """;
        bool runtimeWorkerConfigured;
        bool directCredentialsConfigured;
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync())
        {
            Assert.True(await reader.ReadAsync());
            runtimeWorkerConfigured = reader.GetBoolean(0);
            directCredentialsConfigured = reader.GetBoolean(1);
        }

        var observation = new QuotationAdoptionObservation(
            signed.SourceCommitSha, signed.SourceContractSha256, schemaSha, true, false,
            archivePrivileges, runtimeWorkerConfigured, directCredentialsConfigured);
        _ = await Assert.ThrowsAsync<QuotationOutcomeAdoptionException>(() =>
            PostgreSqlQuotationOutcomeAdopter.AdoptSignedAsync(
                connection, unsigned, sourceRows, 57, observation, trust, CancellationToken.None));
        command.CommandText = "SELECT COUNT(*) FROM \"QuotationAcceptedOutcome\";";
        Assert.Equal(0L, (long)(await command.ExecuteScalarAsync())!);
        command.CommandText = "SELECT last_value::text || '|' || is_called::text FROM \"QuotationAcceptedOutcome_ID_seq\";";
        string pristineSequence = (string)(await command.ExecuteScalarAsync())!;

        QuotationOutcomeAdoptionContract wrongPartition = QuotationOutcomeAdoptionAttestation.Sign(
            unsigned with
            {
                Data = unsigned.Data! with { InsertIds = [41], ReplayIds = [42] }
            },
            signingKey);
        QuotationOutcomeAdoptionException partitionFailure = await Assert.ThrowsAsync<QuotationOutcomeAdoptionException>(() =>
            PostgreSqlQuotationOutcomeAdopter.AdoptSignedAsync(
                connection, wrongPartition, sourceRows, 57, observation, trust, CancellationToken.None));
        Assert.Equal("quotation_adoption_partition_drift", partitionFailure.Code);
        command.CommandText = "SELECT COUNT(*) FROM \"QuotationAcceptedOutcome\";";
        Assert.Equal(0L, (long)(await command.ExecuteScalarAsync())!);
        command.CommandText = "SELECT last_value::text || '|' || is_called::text FROM \"QuotationAcceptedOutcome_ID_seq\";";
        Assert.Equal(pristineSequence, (string)(await command.ExecuteScalarAsync())!);

        QuotationOutcomeAdoptionContract wrongCanonical = QuotationOutcomeAdoptionAttestation.Sign(
            unsigned with
            {
                Data = unsigned.Data! with
                {
                    ExpectedCanonical = unsigned.Data!.ExpectedCanonical with { NextIdentity = 58 }
                }
            },
            signingKey);
        QuotationOutcomeAdoptionException canonicalFailure = await Assert.ThrowsAsync<QuotationOutcomeAdoptionException>(() =>
            PostgreSqlQuotationOutcomeAdopter.AdoptSignedAsync(
                connection, wrongCanonical, sourceRows, 57, observation, trust, CancellationToken.None));
        Assert.Equal("quotation_adoption_target_drift", canonicalFailure.Code);
        command.CommandText = "SELECT COUNT(*) FROM \"QuotationAcceptedOutcome\";";
        Assert.Equal(0L, (long)(await command.ExecuteScalarAsync())!);
        command.CommandText = "SELECT last_value::text || '|' || is_called::text FROM \"QuotationAcceptedOutcome_ID_seq\";";
        Assert.Equal(pristineSequence, (string)(await command.ExecuteScalarAsync())!);

        QuotationOutcomeAdoptionContract wrongCanonicalContent = QuotationOutcomeAdoptionAttestation.Sign(
            unsigned with
            {
                Data = unsigned.Data! with
                {
                    ExpectedCanonical = unsigned.Data!.ExpectedCanonical with
                    {
                        ContentSha256 = new string('0', 64)
                    }
                }
            },
            signingKey);
        QuotationOutcomeAdoptionException contentFailure = await Assert.ThrowsAsync<QuotationOutcomeAdoptionException>(() =>
            PostgreSqlQuotationOutcomeAdopter.AdoptSignedAsync(
                connection, wrongCanonicalContent, sourceRows, 57, observation, trust, CancellationToken.None));
        Assert.Equal("quotation_adoption_target_drift", contentFailure.Code);
        command.CommandText = "SELECT COUNT(*) FROM \"QuotationAcceptedOutcome\";";
        Assert.Equal(0L, (long)(await command.ExecuteScalarAsync())!);
        command.CommandText = "SELECT last_value::text || '|' || is_called::text FROM \"QuotationAcceptedOutcome_ID_seq\";";
        Assert.Equal(pristineSequence, (string)(await command.ExecuteScalarAsync())!);

        QuotationOutcomeAdoptionResult adopted = await PostgreSqlQuotationOutcomeAdopter.AdoptSignedAsync(
            connection, signed, sourceRows, 57, observation, trust, CancellationToken.None);
        Assert.Equal(2, adopted.InsertedCount);
        QuotationAcceptedOutcomeImportRow[] existingRows = sourceRows.Select(row =>
            new QuotationAcceptedOutcomeImportRow(row.ID, row.EventKey, row.QuotationID, row.SourceRequestID,
                row.SourceJourneyID, row.AcceptedUtc, row.AcceptanceOrigin)).ToArray();
        QuotationOutcomeAdoptionContract replayUnsigned = CurrentQuotationSourceContract.CreateAdoptionContract(
            schemaSha, "quotation-integration-key", sourceRows, existingRows, 57);
        QuotationOutcomeAdoptionContract replaySigned = QuotationOutcomeAdoptionAttestation.Sign(replayUnsigned, signingKey);
        var replayObservation = observation with
        {
            SourceCommitSha = replaySigned.SourceCommitSha,
            SourceContractSha256 = replaySigned.SourceContractSha256
        };
        QuotationOutcomeAdoptionResult replay = await PostgreSqlQuotationOutcomeAdopter.AdoptSignedAsync(
            connection, replaySigned, sourceRows, 57, replayObservation, trust, CancellationToken.None);
        Assert.Equal(0, replay.InsertedCount);
        Assert.Equal(2, replay.ReplayedCount);

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
