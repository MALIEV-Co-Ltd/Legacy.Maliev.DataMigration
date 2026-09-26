using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class ApprovedSourceDispositionTargetIntegrationTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task QuotationDisposition_DisposableRowsRoundTripWithoutTimestampLoss()
    {
        TableCopyPlan[] sourceTables =
        [
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
        ];
        var sourcePlan = new DatabaseSchemaPlan("Quotation", "1.0", new string('a', 64), new string('b', 64), sourceTables)
        {
            SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
            SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", sourceTables),
        };
        QuotationDispositionRowMapper mapper = new(sourcePlan);
        DatabaseSchemaPlan targetDraft = sourcePlan with
        {
            Tables = ApprovedSourceDispositionManifest.TargetTablesFor(sourcePlan),
            SourceDispositionProfile = null,
            SourceTableDispositions = [],
        };
        DatabaseSchemaPlan targetPlan = targetDraft with
        {
            TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(targetDraft),
        };
        DateTime occurred = new DateTime(2026, 9, 26, 12, 34, 56, DateTimeKind.Unspecified).AddTicks(1234567);
        DateTime accepted = occurred.AddTicks(2);
        MigrationRow archiveRow = mapper.MapAnalytics(new MigrationRow(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ID"] = 1L,
            ["QuotationID"] = 42,
            ["EventKey"] = "synthetic-archive-1",
            ["EventName"] = "quote_accepted",
            ["ClientId"] = "synthetic-client",
            ["SessionId"] = "synthetic-session",
            ["UserId"] = null,
            ["Currency"] = "THB",
            ["Value"] = 123.45m,
            ["OccurredUtc"] = occurred,
            ["AttemptCount"] = 0,
            ["NextAttemptUtc"] = occurred.AddTicks(1),
            ["LeaseToken"] = null,
            ["LeaseUntilUtc"] = null,
            ["SentUtc"] = null,
            ["FailedUtc"] = null,
            ["LastError"] = null,
            ["SourceRequestID"] = null,
            ["SourceJourneyID"] = null,
        }));
        MigrationRow outcomeRow = mapper.MapOutcome(new MigrationRow(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ID"] = 1L,
            ["EventKey"] = "synthetic-outcome-1",
            ["QuotationID"] = 42,
            ["SourceRequestID"] = null,
            ["SourceJourneyID"] = null,
            ["AcceptedUtc"] = accepted,
            ["AcceptanceOrigin"] = "customer",
        }));

        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync("Quotation",
            $"legacy_shadow_quote_rows_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), CancellationToken.None);
        try
        {
            await using (IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None))
            {
                await transaction.ApplySchemaAsync(targetPlan, CancellationToken.None);
                Assert.Equal(1L, await transaction.CopyBatchAsync(mapper.AnalyticsArchive, [archiveRow], CancellationToken.None));
                Assert.Equal(1L, await transaction.CopyBatchAsync(mapper.AcceptedOutcome, [outcomeRow], CancellationToken.None));
                await transaction.FinalizeSchemaAsync(targetPlan, CancellationToken.None);
                Assert.Equal(targetPlan.TargetSchemaSha256,
                    await transaction.InspectSchemaAsync(targetPlan, CancellationToken.None));
                Assert.Equal(1, (await transaction.InspectTableAsync(mapper.AnalyticsArchive, CancellationToken.None)).RowCount);
                Assert.Equal(1, (await transaction.InspectTableAsync(mapper.AcceptedOutcome, CancellationToken.None)).RowCount);
                await transaction.CommitAsync(CancellationToken.None);
            }

            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString)
            {
                Database = shadow.Name,
            }.ConnectionString);
            await connection.OpenAsync();
            await using (var read = new NpgsqlCommand("""
                SELECT "OccurredUtc", "OccurredUtcSubMicrosecondTicks", "NextAttemptUtc", "NextAttemptUtcSubMicrosecondTicks"
                FROM legacy_compatibility."GoogleAnalyticsOutbox" WHERE "ID"=1;
                """, connection))
            await using (NpgsqlDataReader reader = await read.ExecuteReaderAsync())
            {
                Assert.True(await reader.ReadAsync());
                Assert.Equal(occurred, reader.GetDateTime(0).AddTicks(reader.GetInt16(1)));
                Assert.Equal(occurred.AddTicks(1), reader.GetDateTime(2).AddTicks(reader.GetInt16(3)));
            }
            await using (var read = new NpgsqlCommand("""
                SELECT "AcceptedUtc", "AcceptedUtcSubMicrosecondTicks" FROM public."QuotationAcceptedOutcome" WHERE "ID"=1;
                """, connection))
            await using (NpgsqlDataReader reader = await read.ExecuteReaderAsync())
            {
                Assert.True(await reader.ReadAsync());
                Assert.Equal(accepted, reader.GetDateTime(0).AddTicks(reader.GetInt16(1)));
            }
            await using (var invalid = new NpgsqlCommand("""
                UPDATE legacy_compatibility."GoogleAnalyticsOutbox"
                SET "OccurredUtcSubMicrosecondTicks"=10 WHERE "ID"=1;
                """, connection))
            {
                PostgresException error = await Assert.ThrowsAsync<PostgresException>(invalid.ExecuteNonQueryAsync);
                Assert.Equal(PostgresErrorCodes.CheckViolation, error.SqlState);
            }
            await using (var absent = new NpgsqlCommand("""
                SELECT to_regclass('public."GoogleAnalyticsOutbox"'), to_regclass('public."QuotationOutcomeOutbox"');
                """, connection))
            await using (NpgsqlDataReader reader = await absent.ExecuteReaderAsync())
            {
                Assert.True(await reader.ReadAsync());
                Assert.True(reader.IsDBNull(0));
                Assert.True(reader.IsDBNull(1));
            }
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task QuotationDisposition_RejectsOrdinaryCopy_AndMatchesReviewedTargetSchema()
    {
        TableCopyPlan[] sourceTables =
        [
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
        ];
        var draft = new DatabaseSchemaPlan("Quotation", "1.0", new string('a', 64), new string('0', 64), sourceTables)
        {
            SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
            SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", sourceTables),
        };
        DatabaseSchemaPlan sourcePlan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        DatabaseSchemaPlan targetDraft = sourcePlan with
        {
            Tables = ApprovedSourceDispositionManifest.TargetTablesFor(sourcePlan),
            SourceDispositionProfile = null,
            SourceTableDispositions = [],
        };
        DatabaseSchemaPlan targetPlan = targetDraft with
        {
            TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(targetDraft),
        };
        Assert.Equal(sourcePlan.TargetSchemaSha256, targetPlan.TargetSchemaSha256);

        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync("Quotation",
            $"legacy_shadow_quote_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), CancellationToken.None);
        try
        {
            await using (IPostgreSqlWholeDatabaseTransaction rejected =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None))
            {
                MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                    rejected.ApplySchemaAsync(sourcePlan, CancellationToken.None));
                Assert.Equal("source_disposition_schema_application_not_ready", failure.Code);
                MigrationExecutionException finalization = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                    rejected.FinalizeSchemaAsync(sourcePlan, CancellationToken.None));
                Assert.Equal("source_disposition_schema_application_not_ready", finalization.Code);
            }

            {
                await using IPostgreSqlWholeDatabaseTransaction transaction =
                    await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
                await transaction.ApplySchemaAsync(targetPlan, CancellationToken.None);
                await transaction.FinalizeSchemaAsync(targetPlan, CancellationToken.None);
                Assert.Equal(sourcePlan.TargetSchemaSha256,
                    await transaction.InspectSchemaAsync(sourcePlan, CancellationToken.None));
            }

            var connectionBuilder = new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString)
            {
                Database = shadow.Name,
            };
            await using var connection = new NpgsqlConnection(connectionBuilder.ConnectionString);
            await connection.OpenAsync();
            string efSql = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures",
                "Quotation", "bd201a5-quotation-accepted-outcome.sql"));
            TableCopyPlan archive = targetPlan.Tables.Single(table => table.TargetSchema == "legacy_compatibility");
            string archiveColumns = string.Join(", ", archive.OrderedColumns.Select(column =>
                $"\"{column}\" {archive.ColumnTypes[column]}" +
                (archive.Identities.Any(identity => identity.Column == column) ? " GENERATED BY DEFAULT AS IDENTITY" : string.Empty) +
                (archive.DefaultExpressions.TryGetValue(column, out string? expression) ? $" DEFAULT {expression}" : string.Empty) +
                (archive.NullableColumns.Contains(column) ? string.Empty : " NOT NULL")));
            string archiveChecks = string.Join(", ", archive.CheckConstraints.Select(check =>
                $"CONSTRAINT \"{check.Name}\" CHECK ({check.Expression})"));
            await using (var create = new NpgsqlCommand($"""
                CREATE SCHEMA legacy_compatibility;
                CREATE TABLE legacy_compatibility."GoogleAnalyticsOutbox" ({archiveColumns},
                    CONSTRAINT "PK_GoogleAnalyticsOutbox" PRIMARY KEY ("ID"), {archiveChecks});
                CREATE UNIQUE INDEX "UX_GoogleAnalyticsOutbox_EventKey"
                    ON legacy_compatibility."GoogleAnalyticsOutbox" ("EventKey");
                {efSql}
                """, connection))
            {
                _ = await create.ExecuteNonQueryAsync();
            }
            await using (IPostgreSqlWholeDatabaseTransaction efObserved =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None))
            {
                Assert.Equal(sourcePlan.TargetSchemaSha256,
                    await efObserved.InspectSchemaAsync(sourcePlan, CancellationToken.None));
            }

            await using (var loosen = new NpgsqlCommand("""
                ALTER TABLE legacy_compatibility."GoogleAnalyticsOutbox"
                    DROP CONSTRAINT "CK_GoogleAnalyticsOutbox_OccurredUtcSubMicrosecondTicks";
                ALTER TABLE legacy_compatibility."GoogleAnalyticsOutbox"
                    ADD CONSTRAINT "CK_GoogleAnalyticsOutbox_OccurredUtcSubMicrosecondTicks"
                    CHECK ("OccurredUtcSubMicrosecondTicks" >= 0 AND "OccurredUtcSubMicrosecondTicks" <= 10);
                """, connection))
            {
                _ = await loosen.ExecuteNonQueryAsync();
            }
            await using IPostgreSqlWholeDatabaseTransaction drifted =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            Assert.NotEqual(sourcePlan.TargetSchemaSha256,
                await drifted.InspectSchemaAsync(sourcePlan, CancellationToken.None));
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }
}
