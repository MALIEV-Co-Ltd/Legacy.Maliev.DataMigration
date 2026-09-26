using System.Globalization;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Exact23DeltaPlanCoordinatorTests : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public async Task Produces_signed_exact_inventory_plan_from_ordered_streams()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-09-08T06:00:00Z", CultureInfo.InvariantCulture);
        FreshSchemaPlan schema = Schema(now);
        var source = new Rows(name => name == DatabaseInventory.ActiveDatabases[0] ? [Row(1, "new"), Row(2, "insert")] : [Row(1, "same")]);
        var target = new Rows(name => name == DatabaseInventory.ActiveDatabases[0] ? [Row(1, "old"), Row(3, "delete")] : [Row(1, "same")]);
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var coordinator = new Exact23DeltaPlanCoordinator(source, target, signer, new FixedTime(now));

        DeltaSynchronizationPlan plan = await coordinator.ProduceAsync(Request(schema, signer, now), CancellationToken.None);

        Assert.Equal(DatabaseInventory.ActiveDatabases, plan.Databases.Select(item => item.Database));
        DeltaTablePlan first = Assert.Single(plan.Databases[0].Tables);
        Assert.Equal((1, 1, 1), (first.InsertCount, first.UpdateCount, first.DeleteCount));
        Assert.All(plan.Databases.Skip(1), database => Assert.Equal(1, Assert.Single(database.Tables).UnchangedCount));
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(plan, trust, now));
    }

    [Fact]
    public async Task Rejects_inventory_missing_one_database_before_reading_rows()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-09-08T06:00:00Z", CultureInfo.InvariantCulture);
        FreshSchemaPlan schema = Schema(now) with { Databases = Schema(now).Databases.Skip(1).ToArray() };
        var rows = new Rows(_ => []);
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var coordinator = new Exact23DeltaPlanCoordinator(rows, rows, signer, new FixedTime(now));

        DeltaPlanException error = await Assert.ThrowsAsync<DeltaPlanException>(() =>
            coordinator.ProduceAsync(Request(schema, signer, now), CancellationToken.None));

        Assert.Equal("delta_plan_inventory_invalid", error.Code);
        Assert.Equal(0, rows.Reads);
    }

    [Fact]
    public async Task Rejects_schema_fingerprint_from_stale_runner_before_reading_rows()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-09-08T06:00:00Z", CultureInfo.InvariantCulture);
        FreshSchemaPlan valid = Schema(now);
        FreshSchemaPlan stale = valid with
        {
            Databases = [valid.Databases[0] with { TargetSchemaSha256 = Hash('b') }, .. valid.Databases.Skip(1)],
        };
        var rows = new Rows(_ => []);
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var coordinator = new Exact23DeltaPlanCoordinator(rows, rows, signer, new FixedTime(now));

        DeltaPlanException error = await Assert.ThrowsAsync<DeltaPlanException>(() =>
            coordinator.ProduceAsync(Request(stale, signer, now), CancellationToken.None));

        Assert.Equal("delta_plan_schema_fingerprint_stale", error.Code);
        Assert.Equal(0, rows.Reads);
    }

    [Theory]
    [InlineData("GoogleAnalyticsOutbox")]
    [InlineData("QuotationOutcomeOutbox")]
    public async Task Rejects_unmapped_quotation_outbox_before_reading_rows(string sourceTable)
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-09-08T06:00:00Z", CultureInfo.InvariantCulture);
        FreshSchemaPlan valid = Schema(now);
        DatabaseSchemaPlan quotation = valid.Databases.Single(database => database.Database == "Quotation");
        TableCopyPlan outbox = Table() with
        {
            SourceSchema = "dbo",
            SourceTable = sourceTable,
            TargetSchema = "public",
            TargetTable = sourceTable,
        };
        DatabaseSchemaPlan revised = quotation with { Tables = [.. quotation.Tables, outbox] };
        FreshSchemaPlan schema = valid with
        {
            Databases = valid.Databases.Select(database => database.Database == "Quotation" ? revised : database).ToArray(),
        };
        var rows = new Rows(_ => []);
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var coordinator = new Exact23DeltaPlanCoordinator(rows, rows, signer, new FixedTime(now));

        DeltaPlanException error = await Assert.ThrowsAsync<DeltaPlanException>(() =>
            coordinator.ProduceAsync(Request(schema, signer, now), CancellationToken.None));

        Assert.Equal("delta_plan_quotation_transformation_required", error.Code);
        Assert.Equal(0, rows.Reads);
    }

    [Fact]
    public async Task Plans_reviewed_quotation_dispositions_against_signed_target_shapes()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-09-26T06:00:00Z", CultureInfo.InvariantCulture);
        FreshSchemaPlan schema = WithQuotationDispositions(Schema(now));
        DatabaseSchemaPlan quotation = schema.Databases.Single(database => database.Database == "Quotation");
        var mapper = new QuotationDispositionRowMapper(quotation);
        MigrationRow analytics = AnalyticsRow();
        MigrationRow outcome = OutcomeRow();
        var source = new TableRows((database, table) => database == "Quotation" ? table.SourceTable switch
        {
            "GoogleAnalyticsOutbox" => [analytics],
            "QuotationOutcomeOutbox" => [outcome],
            _ => [Row(1, "same")],
        } : [Row(1, "same")]);
        var target = new TableRows((database, table) => database == "Quotation" &&
            table.TargetSchema == "legacy_compatibility" ? [mapper.MapAnalytics(analytics)] :
            database == "Quotation" && table.TargetTable == "QuotationAcceptedOutcome" ? [] :
            [Row(1, "same")]);
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var coordinator = new Exact23DeltaPlanCoordinator(source, target, signer, new FixedTime(now));

        DeltaSynchronizationPlan plan = await coordinator.ProduceAsync(Request(schema, signer, now), CancellationToken.None);

        DeltaDatabasePlan plannedQuotation = plan.Databases.Single(database => database.Database == "Quotation");
        Assert.Equal(quotation.Tables.Count, plannedQuotation.Tables.Count);
        Assert.Equal(["legacy_compatibility.GoogleAnalyticsOutbox", "public.QuotationAcceptedOutcome", "public.items"],
            plannedQuotation.Tables.Select(table => table.Table));
        Assert.Equal(1, plannedQuotation.Tables[0].UnchangedCount);
        CanonicalDeltaOperation insert = Assert.Single(plannedQuotation.Tables[1].Operations);
        Assert.Equal(DeltaOperationKind.Insert, insert.Kind);
        Assert.Equal(CanonicalRowFingerprint.Compute(mapper.AcceptedOutcome, [mapper.MapOutcome(outcome)]),
            insert.SourceRowSha256);
        Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpected(quotation), quotation.TargetSchemaSha256);
        Assert.DoesNotContain(plannedQuotation.Tables, table => table.Table is "public.QuotationOutcomeOutbox" or
            "public.GoogleAnalyticsOutbox");
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(plan, trust, now));
        Assert.Contains(source.ReadTables, table => table == "dbo.QuotationOutcomeOutbox=>public.QuotationOutcomeOutbox");
        Assert.Contains(target.ReadTables, table => table == "disposition.QuotationOutcomeOutbox=>public.QuotationAcceptedOutcome");
        var executor = new Exact23DeltaExecutionCoordinator(null!, _ => throw new InvalidOperationException("Execution must remain blocked."));
        DeltaExecutionException blocked = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            executor.ExecuteAsync(plan, schema, CancellationToken.None));
        Assert.Equal("delta_execution_quotation_transformation_required", blocked.Code);
    }

    [Fact]
    public async Task Unknown_quotation_source_table_invalidates_signed_target_inventory_before_rows()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-09-26T06:00:00Z", CultureInfo.InvariantCulture);
        FreshSchemaPlan valid = WithQuotationDispositions(Schema(now));
        FreshSchemaPlan drifted = valid with
        {
            Databases = valid.Databases.Select(database => database.Database == "Quotation"
                ? database with { Tables = [.. database.Tables, Table() with { SourceTable = "UnexpectedOutbox", TargetTable = "UnexpectedOutbox" }] }
                : database).ToArray(),
        };
        var rows = new Rows(_ => []);
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var coordinator = new Exact23DeltaPlanCoordinator(rows, rows, signer, new FixedTime(now));

        DeltaPlanException error = await Assert.ThrowsAsync<DeltaPlanException>(() =>
            coordinator.ProduceAsync(Request(drifted, signer, now), CancellationToken.None));

        Assert.Equal("delta_plan_schema_fingerprint_stale", error.Code);
        Assert.Equal(0, rows.Reads);
    }

    private static FreshSchemaPlan WithQuotationDispositions(FreshSchemaPlan schema)
    {
        return schema with
        {
            Databases = schema.Databases.Select(database =>
            {
                if (database.Database != "Quotation")
                {
                    return database;
                }

                TableCopyPlan[] tables =
                [
                    .. database.Tables,
                    ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                        "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
                    ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                        "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
                ];
                var draft = database with
                {
                    Tables = tables,
                    SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
                    SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables),
                };
                return draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
            }).ToArray(),
        };
    }

    private static MigrationRow AnalyticsRow()
    {
        DateTime occurred = new(2026, 9, 26, 12, 34, 56, DateTimeKind.Unspecified);
        return new(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ID"] = 17L,
            ["QuotationID"] = 41,
            ["EventKey"] = "synthetic-event-17",
            ["EventName"] = "quote_accepted",
            ["ClientId"] = "synthetic-client",
            ["SessionId"] = "synthetic-session",
            ["UserId"] = null,
            ["Currency"] = "THB",
            ["Value"] = 123.45m,
            ["OccurredUtc"] = occurred.AddTicks(7),
            ["AttemptCount"] = 1,
            ["NextAttemptUtc"] = occurred.AddTicks(8),
            ["LeaseToken"] = null,
            ["LeaseUntilUtc"] = null,
            ["SentUtc"] = null,
            ["FailedUtc"] = null,
            ["LastError"] = null,
            ["SourceRequestID"] = null,
            ["SourceJourneyID"] = null,
        });
    }

    private static MigrationRow OutcomeRow()
    {
        DateTime accepted = new(2026, 9, 26, 12, 34, 56, DateTimeKind.Unspecified);
        return new(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ID"] = 30L,
            ["EventKey"] = "synthetic-outcome-30",
            ["QuotationID"] = 41,
            ["SourceRequestID"] = null,
            ["SourceJourneyID"] = null,
            ["AcceptedUtc"] = accepted.AddTicks(7),
            ["AcceptanceOrigin"] = "customer",
        });
    }

    private static Exact23DeltaPlanRequest Request(FreshSchemaPlan schema, P256MigrationEvidenceSigner signer, DateTimeOffset now)
    {
        string distinct = string.Equals(signer.PublicKeyFingerprintSha256, Hash('e'), StringComparison.OrdinalIgnoreCase) ? Hash('1') : Hash('e');
        string authorization = string.Equals(signer.PublicKeyFingerprintSha256, Hash('f'), StringComparison.OrdinalIgnoreCase) ? Hash('2') : Hash('f');
        return new(schema, now.AddMinutes(-1), Hash('a'), Hash('d'), "maliev-legacy", "legacy-postgres-main",
            "generation-1", Hash('c'), distinct, authorization)
        {
            TargetAuthority = new(DeltaTargetAuthorityKind.ProductionCloudNativePg,
                "gke://maliev-website/us-central1-a/maliev-legacy/legacy-postgres-main/uid-1", Hash('8')),
        };
    }

    private static FreshSchemaPlan Schema(DateTimeOffset now)
    {
        return new("2.0", now, new string('1', 40), [.. DatabaseInventory.ActiveDatabases.Select(name =>
        {
            var draft = new DatabaseSchemaPlan(name, "1.0", Hash('a'), string.Empty, [Table()]);
            return draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        })]);
    }

    private static TableCopyPlan Table()
    {
        return new("dbo", "items", "public", "items", ["id", "value"], ["id"])
        {
            ColumnTypes = new Dictionary<string, string> { ["id"] = "integer", ["value"] = "text" },
            PrimaryKey = new("pk_items", ["id"]),
        };
    }

    private static MigrationRow Row(int id, string value)
    {
        return new(new Dictionary<string, object?> { ["id"] = id, ["value"] = value });
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    public void Dispose()
    {
        _key.Dispose();
    }

    private sealed class Rows(Func<string, IReadOnlyList<MigrationRow>> rows) : IDeltaOrderedRowSource
    {
        internal int Reads { get; private set; }
        public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(string database, TableCopyPlan table,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            Reads++;
            foreach (MigrationRow row in rows(database))
            {
                cancellationToken.ThrowIfCancellationRequested();
                await Task.Yield();
                yield return row;
            }
        }
    }

    private sealed class TableRows(Func<string, TableCopyPlan, IReadOnlyList<MigrationRow>> rows) : IDeltaOrderedRowSource
    {
        internal List<string> ReadTables { get; } = [];

        public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(string database, TableCopyPlan table,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            ReadTables.Add($"{table.SourceSchema}.{table.SourceTable}=>{table.TargetSchema}.{table.TargetTable}");
            foreach (MigrationRow row in rows(database, table))
            {
                cancellationToken.ThrowIfCancellationRequested();
                await Task.Yield();
                yield return row;
            }
        }
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
}
