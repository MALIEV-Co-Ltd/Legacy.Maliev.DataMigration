using Npgsql;
using System.Text.Json;
using Xunit.Abstractions;

namespace Legacy.Maliev.DataMigration.Tests;

/// <summary>Consumer-owned schema literals; no source rows, effects or migration history are fabricated.</summary>
[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class ConsumerTargetExtensionProfileTests(PostgreSqlAdapterFixture fixture, ITestOutputHelper output)
{
    [Fact]
    public async Task NativeRecovery_EmptyOwnedMaterialShadowRemainsVerifiedEmptyBeforeSchemaApplication()
    { await CheckEmptyMaterialAsync(false); }

    [Fact]
    public async Task NativeRecovery_CollationOnlyShadowIsNotVerifiedEmpty()
    { await CheckEmptyMaterialAsync(true); }

    private async Task CheckEmptyMaterialAsync(bool collationOnly)
    {
        var source = new TableCopyPlan("dbo", "Probe", "public", "Probe", ["Id"], ["Id"])
        { ColumnTypes = new Dictionary<string, string> { ["Id"] = "integer" }, PrimaryKey = new("PK_Probe", ["Id"]) };
        var draft = Plan("Material", [source]) with { TargetExtensionProfile = "material-catalog-v1" };
        var plan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        var target = fixture.CreateShadowTarget();
        var shadow = await target.CreateUniqueEmptyShadowAsync(plan.Database, $"legacy_shadow_empty_material_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), default);
        try
        {
            if (collationOnly)
            { await ExecuteAsync(shadow, "CREATE COLLATION public.legacy_ci_as (provider=icu,locale='und-u-ks-level2',deterministic=false);"); }
            await using var inspection = await target.BeginReadOnlyRecoveryAsync(shadow, default);
            if (collationOnly)
            {
                var failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => inspection.InspectAsync(plan, default));
                Assert.Equal("shadow_recovery_objects_invalid", failure.Code);
                return;
            }
            var observed = await inspection.InspectAsync(plan, default);
            Assert.True(observed.IsVerifiedEmpty);
            Assert.Null(observed.TargetSchemaSha256);
            Assert.Empty(observed.Tables);
            Assert.Empty(observed.SequenceNextValues);
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, default); }
    }

    [Fact]
    public async Task NativeRecovery_ExistingMaterialProfileAdmitsItsReviewedCollation()
    {
        var source = new TableCopyPlan("dbo", "Probe", "public", "Probe", ["Id"], ["Id"])
        { ColumnTypes = new Dictionary<string, string> { ["Id"] = "integer" }, PrimaryKey = new("PK_Probe", ["Id"]) };
        var draft = Plan("Material", [source]) with { TargetExtensionProfile = "material-catalog-v1" };
        var plan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        await WithSchemaAsync(plan, async (shadow, target, baseline) =>
        {
            await using var c = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString) { Database = shadow.Name }.ConnectionString);
            await c.OpenAsync();
            const string sql = """
                SELECT d.classid::regclass::text, d.objid::text, n.nspname,
                    CASE WHEN d.classid='pg_collation'::regclass THEN (SELECT collname FROM pg_collation WHERE oid=d.objid) ELSE '' END
                FROM pg_depend d JOIN pg_namespace n ON n.oid=d.refobjid
                WHERE d.refclassid='pg_namespace'::regclass AND n.nspname='public'
                    AND d.classid NOT IN ('pg_class'::regclass,'pg_type'::regclass,'pg_constraint'::regclass);
                """;
            await using (var cmd = new NpgsqlCommand(sql, c))
            await using (var r = await cmd.ExecuteReaderAsync())
            {
                while (await r.ReadAsync()) { output.WriteLine(JsonSerializer.Serialize(new { database = plan.Database, catalog = r.GetString(0), oid = r.GetString(1), schema = r.GetString(2), name = r.GetString(3) })); }
            }
            await using var inspection = await target.BeginReadOnlyRecoveryAsync(shadow, default);
            var observed = await inspection.InspectAsync(plan, default);
            Assert.Equal(baseline, observed.TargetSchemaSha256);
        });
    }

    [Theory]
    [InlineData("locale")]
    [InlineData("deterministic")]
    [InlineData("provider")]
    [InlineData("rules")]
    [InlineData("extra")]
    [InlineData("unrequested")]
    [InlineData("missing")]
    public async Task NativeRecovery_UnreviewedCollationFailsClosed(string change)
    {
        var source = new TableCopyPlan("dbo", "Probe", "public", "Probe", ["Id"], ["Id"])
        { ColumnTypes = new Dictionary<string, string> { ["Id"] = "integer" }, PrimaryKey = new("PK_Probe", ["Id"]) };
        var draft = Plan("Material", [source]) with { TargetExtensionProfile = "material-catalog-v1" };
        var plan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        await WithSchemaAsync(plan, async (shadow, target, baseline) =>
        {
            if (change == "extra")
            { await ExecuteAsync(shadow, "CREATE COLLATION public.unrequested_extra FROM public.legacy_ci_as;"); }
            else if (change == "missing")
            {
                foreach (var table in ApprovedTargetExtensionManifest.TablesFor(plan))
                {
                    foreach (string column in table.Collations.Keys)
                    { await ExecuteAsync(shadow, $"ALTER TABLE public.{PostgreSqlShadowTarget.QuoteIdentifier(table.TargetTable)} ALTER COLUMN {PostgreSqlShadowTarget.QuoteIdentifier(column)} TYPE {table.ColumnTypes[column]} COLLATE \"default\";"); }
                }
                await ExecuteAsync(shadow, "DROP COLLATION public.legacy_ci_as;");
            }
            else if (change != "unrequested")
            {
                string definition = change switch
                {
                    "locale" => "provider=icu, locale='und-u-ks-level1', deterministic=false",
                    "deterministic" => "provider=icu, locale='und-u-ks-level2', deterministic=true",
                    "provider" => "provider=libc, locale='C'",
                    "rules" => "provider=icu, locale='und-u-ks-level2', deterministic=false, rules='&a < b'",
                    _ => throw new ArgumentOutOfRangeException(nameof(change)),
                };
                await ExecuteAsync(shadow, $"ALTER COLLATION public.legacy_ci_as RENAME TO old_legacy_ci_as; CREATE COLLATION public.legacy_ci_as ({definition});");
                foreach (var table in ApprovedTargetExtensionManifest.TablesFor(plan))
                {
                    foreach (string column in table.Collations.Keys)
                    {
                        await ExecuteAsync(shadow, $"ALTER TABLE public.{PostgreSqlShadowTarget.QuoteIdentifier(table.TargetTable)} ALTER COLUMN {PostgreSqlShadowTarget.QuoteIdentifier(column)} TYPE {table.ColumnTypes[column]} COLLATE public.legacy_ci_as;");
                    }
                }
                await ExecuteAsync(shadow, "DROP COLLATION public.old_legacy_ci_as;");
            }
            await using var c = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString) { Database = shadow.Name }.ConnectionString);
            await c.OpenAsync();
            await using var tx = await c.BeginTransactionAsync();
            var inspected = change == "unrequested" ? plan with { TargetExtensionProfile = null } : plan;
            var failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => PostgreSqlShadowRecoveryObjects.InspectAsync(c, tx, inspected, default));
            Assert.Equal("shadow_recovery_objects_invalid", failure.Code);
        });
    }

    [PostgreSql18SnapshotIntegrationFact]
    public async Task NativeArchive_ConsumerInvoiceFingerprintPreservesExactReviewedShape()
    { await CheckNativeInvoiceAsync(null); }

    [PostgreSql18SnapshotIntegrationFact]
    public async Task NativeArchive_ChangedCheckValueIsNotAnAlias()
    { await CheckNativeInvoiceAsync("value"); }

    [PostgreSql18SnapshotIntegrationFact]
    public async Task NativeArchive_ChangedCheckGroupIsNotAnAlias()
    { await CheckNativeInvoiceAsync("group"); }

    [PostgreSql18SnapshotIntegrationFact]
    public async Task NativeArchive_ChangedCheckOperatorIsNotAnAlias()
    { await CheckNativeInvoiceAsync("operator"); }

    private async Task CheckNativeInvoiceAsync(string? mutation)
    {
        var plan = Plan("Invoice", ConsumerShapes("Invoice"));
        await WithSchemaAsync(plan, async (shadow, shadowTarget, baseline) =>
        {
            if (mutation is not null)
            {
                string check = mutation == "operator" ? "CK_InvoiceNotificationCorrelation_State" : "CK_InvoiceNotificationCorrelation_ReceiptPhase";
                string original = plan.Tables.Single(t => t.TargetTable == "InvoiceNotificationCorrelation").CheckConstraints.Single(c => c.Name == check).Expression;
                string changed = mutation switch
                {
                    "value" => original.Replace("'Prepared'", "'Changed'", StringComparison.Ordinal),
                    "group" => original.Replace(" OR ", " AND ", StringComparison.Ordinal),
                    "operator" => original.Replace("\"Version\" > 0", "\"Version\" >= 0", StringComparison.Ordinal),
                    _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
                };
                Assert.NotEqual(original, changed);
                await ExecuteAsync(shadow, $"ALTER TABLE public.\"InvoiceNotificationCorrelation\" DROP CONSTRAINT {PostgreSqlShadowTarget.QuoteIdentifier(check)}, ADD CONSTRAINT {PostgreSqlShadowTarget.QuoteIdentifier(check)} CHECK ({changed});");
            }
            string restoredName = $"consumer_archive_{Guid.NewGuid():N}";
            await using var admin = new NpgsqlConnection(fixture.ConnectionString);
            await admin.OpenAsync();
            await using (var create = new NpgsqlCommand($"CREATE DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(restoredName)};", admin))
            { _ = await create.ExecuteNonQueryAsync(); }
            try
            {
                await using Stream archive = await new PgDumpSource(LocalArchiveVerificationFixture.Tool("PG_DUMP_PATH"), fixture.ShadowAdminConnectionString).OpenDumpAsync(plan.Database, shadow.Name, default);
                var target = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = restoredName };
                await LocalPgRestoreProcess.RestoreAsync(LocalPostgreSqlArchiveVerifier.BuildStartInfo(LocalArchiveVerificationFixture.Tool("PG_RESTORE_PATH"), target), archive, default);
                await using var restored = new NpgsqlConnection(target.ConnectionString);
                await restored.OpenAsync();
                await using (var command = new NpgsqlCommand("SELECT c.relname,k.conname,pg_get_expr(k.conbin,k.conrelid) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND k.contype='c' ORDER BY c.relname,k.conname;", restored))
                await using (var reader = await command.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    { output.WriteLine(JsonSerializer.Serialize(new { table = reader.GetString(0), check = reader.GetString(1), expression = reader.GetString(2) })); }
                }
                await using var transaction = await restored.BeginTransactionAsync();
                await using var inspection = new PostgreSqlWholeDatabaseTransaction(restored, transaction);
                var (SchemaSha256, Components, Columns) = await inspection.InspectSchemaWithComponentsAsync(plan, default);
                foreach (var component in Components) { output.WriteLine("restored: " + JsonSerializer.Serialize(component)); }
                foreach (var table in plan.Tables) { output.WriteLine("expected: " + JsonSerializer.Serialize(PostgreSqlSchemaFingerprint.ComputeExpectedComponents(table))); }
                if (mutation is null) { Assert.Equal(baseline, SchemaSha256); }
                else { Assert.NotEqual(baseline, SchemaSha256); }
            }
            finally
            {
                await using var drop = new NpgsqlCommand($"DROP DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(restoredName)} WITH (FORCE);", admin);
                _ = await drop.ExecuteNonQueryAsync();
            }
        });
    }

    [Theory]
    [InlineData("Invoice")]
    [InlineData("EmployeeIdentity")]
    public async Task ReviewedChecks_CaptureExactCatalogPredicatesAndColumnArrays(string database)
    {
        var plan = Plan(database, ConsumerShapes(database));
        await WithSchemaAsync(plan, async (shadow, _, _) =>
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString) { Database = shadow.Name }.ConnectionString);
            await connection.OpenAsync();
            const string sql = """
                SELECT c.relname, k.conname, pg_get_expr(k.conbin, k.conrelid),
                    ARRAY(SELECT a.attname FROM unnest(k.conkey) WITH ORDINALITY AS x(attnum, ordinal)
                        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = x.attnum ORDER BY x.ordinal)
                FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND k.contype = 'c' ORDER BY c.relname, k.conname;
                """;
            await using var command = new NpgsqlCommand(sql, connection);
            await using var reader = await command.ExecuteReaderAsync();
            var observed = new HashSet<(string Table, string Check)>();
            while (await reader.ReadAsync())
            {
                string table = reader.GetString(0);
                string check = reader.GetString(1);
                string expression = reader.GetString(2);
                string[] columns = reader.GetFieldValue<string[]>(3);
                output.WriteLine(JsonSerializer.Serialize(new { database, table, check, expression, columns }));
                var expected = plan.Tables.Single(x => x.TargetTable == table).CheckConstraints.Single(x => x.Name == check);
                Assert.Equal(expected.Columns, columns);
                Assert.Equal(CapturedCatalogPredicates[check], expression);
                Assert.True(observed.Add((table, check)));
            }
            Assert.Equal(plan.Tables.Sum(x => x.CheckConstraints.Count), observed.Count);
        });
    }

    // Exact PG18 pg_get_expr readback from the independently transcribed owner specimens.
    // This is diagnostic expected evidence, not a runtime SQL-equivalence implementation.
    private static readonly Dictionary<string, string> CapturedCatalogPredicates =
        new(StringComparer.Ordinal)
        {
            ["CK_InvoiceCreationAdmission_Quotation"] = """
                ("QuotationID" > 0)
                """,
            ["CK_InvoiceNotificationCorrelation_Identity"] = """
                (("InvoiceID" > 0) AND ("QuotationID" > 0) AND (("Purpose")::text = 'invoice-issued'::text) AND (("SenderServiceSubject")::text = 'service:legacy-accounting'::text) AND ("IntentID" <> '00000000-0000-0000-0000-000000000000'::uuid) AND ("WorkflowOperationID" <> '00000000-0000-0000-0000-000000000000'::uuid) AND ("IntentID" <> "WorkflowOperationID") AND (octet_length("PayloadBinding") = 32) AND (length(("OriginIssuer")::text) > 0) AND (length(("OriginEmployeeSubject")::text) > 0) AND (length(("OriginServiceSubject")::text) > 0) AND (length(("SenderIssuer")::text) > 0) AND (length(("BindingKeyID")::text) > 0) AND (("PayloadFrameVersion")::text = 'notification-payload-v1'::text) AND (("BindingVersion")::text = 'accounting-invoice-notification-hmac-v1'::text))
                """,
            ["CK_InvoiceNotificationCorrelation_Receipt"] = """
                ((("RemoteVersion" IS NULL) AND ("RemoteState" IS NULL) AND ("RemoteAdmittedAt" IS NULL) AND ("RemoteUpdatedAt" IS NULL) AND ("RemoteReceiptBinding" IS NULL)) OR (("RemoteVersion" IS NOT NULL) AND ("RemoteVersion" > 0) AND ("RemoteState" IS NOT NULL) AND ("RemoteAdmittedAt" IS NOT NULL) AND ("RemoteUpdatedAt" IS NOT NULL) AND ("RemoteReceiptBinding" IS NOT NULL) AND (octet_length("RemoteReceiptBinding") = 32) AND ("RemoteUpdatedAt" >= "RemoteAdmittedAt") AND (((("RemoteState")::text = 'admitted'::text) AND ("RemoteVersion" = 1)) OR ((("RemoteState")::text = 'submitting'::text) AND ("RemoteVersion" = 2)) OR ((("RemoteState")::text = ANY ((ARRAY['outcomeUnknown'::character varying, 'providerAccepted'::character varying])::text[])) AND ("RemoteVersion" = 3)))))
                """,
            ["CK_InvoiceNotificationCorrelation_ReceiptPhase"] = """
                (((("Phase")::text = ANY ((ARRAY['Prepared'::character varying, 'AdmissionIssued'::character varying])::text[])) AND ("RemoteVersion" IS NULL)) OR ((("Phase")::text = ANY ((ARRAY['Admitted'::character varying, 'ExecutionIssued'::character varying])::text[])) AND ("RemoteVersion" IS NOT NULL) AND (("RemoteState")::text = 'admitted'::text)) OR ((("Phase")::text = 'OutcomeUnknown'::text) AND ("RemoteVersion" IS NOT NULL) AND (("RemoteState")::text = ANY ((ARRAY['submitting'::character varying, 'outcomeUnknown'::character varying])::text[]))) OR ((("Phase")::text = 'ProviderAccepted'::text) AND ("RemoteVersion" IS NOT NULL) AND (("RemoteState")::text = 'providerAccepted'::text)))
                """,
            ["CK_InvoiceNotificationCorrelation_State"] = """
                (("Version" > 0) AND (("RemoteVersion" IS NULL) OR ("RemoteVersion" > 0)) AND ("UpdatedAt" >= "CreatedAt") AND (("Phase")::text = ANY ((ARRAY['Prepared'::character varying, 'AdmissionIssued'::character varying, 'Admitted'::character varying, 'ExecutionIssued'::character varying, 'OutcomeUnknown'::character varying, 'ProviderAccepted'::character varying, 'RejectedBeforeSubmission'::character varying])::text[])) AND (("AdmissionIssuedAt" IS NULL) OR ("AdmissionIssuedAt" >= "CreatedAt")) AND (("ExecutionIssuedAt" IS NULL) OR (("AdmissionIssuedAt" IS NOT NULL) AND ("ExecutionIssuedAt" >= "AdmissionIssuedAt"))) AND ((("Phase")::text = 'Prepared'::text) OR ("AdmissionIssuedAt" IS NOT NULL)) AND ((("Phase")::text <> 'Prepared'::text) OR (("AdmissionIssuedAt" IS NULL) AND ("ExecutionIssuedAt" IS NULL) AND ("RemoteVersion" IS NULL))) AND ((("Phase")::text <> 'AdmissionIssued'::text) OR (("AdmissionIssuedAt" IS NOT NULL) AND ("ExecutionIssuedAt" IS NULL))) AND ((("Phase")::text <> 'Admitted'::text) OR (("AdmissionIssuedAt" IS NOT NULL) AND ("ExecutionIssuedAt" IS NULL) AND ("RemoteVersion" IS NOT NULL))) AND ((("Phase")::text <> 'ExecutionIssued'::text) OR (("ExecutionIssuedAt" IS NOT NULL) AND ("RemoteVersion" IS NOT NULL))) AND ((("Phase")::text <> ALL ((ARRAY['OutcomeUnknown'::character varying, 'ProviderAccepted'::character varying])::text[])) OR (("ExecutionIssuedAt" IS NOT NULL) AND ("RemoteVersion" IS NOT NULL))) AND ((("Phase")::text <> ALL ((ARRAY['ProviderAccepted'::character varying, 'RejectedBeforeSubmission'::character varying])::text[])) OR ("RemoteVersion" IS NOT NULL)))
                """,
            ["CK_EmployeeRecoveryEffects_Binding"] = """
                ((length(("TokenSha256")::text) = 64) AND (length(("OwnerSubject")::text) > 0) AND (length("BeforeSecurityStamp") > 0) AND (length("AfterSecurityStamp") > 0))
                """,
            ["CK_EmployeeRecoveryEffects_PurposePayload"] = """
                (((("Purpose")::text = 'employee-password-reset'::text) AND ("PasswordPayloadHash" IS NOT NULL)) OR ((("Purpose")::text = 'employee-email-confirmation'::text) AND ("PasswordPayloadHash" IS NULL)))
                """,
        };

    [Theory]
    [InlineData("Material", "material-catalog-v1", "Country,Currency")]
    [InlineData("QuotationRequest", "quotation-request-idempotency-v1", "RequestCreateIdempotency")]
    public void ExistingProfile_SemanticsRemainUnchanged(string database, string profile, string tables)
    {
        Assert.Equal(profile, ApprovedTargetExtensionManifest.ProfileForDatabase(database));
        var plan = Plan(database, []) with { TargetExtensionProfile = profile };
        Assert.Equal(tables.Split(','), ApprovedTargetExtensionManifest.TablesFor(plan).Select(x => x.TargetTable));
    }

    [Theory]
    [InlineData("Material", "material-catalog-v1", "Country")]
    [InlineData("QuotationRequest", "quotation-request-idempotency-v1", "RequestCreateIdempotency")]
    public void ExistingProfile_SourceCollisionStillFailsClosed(string database, string profile, string table)
    {
        var source = Shape(table, [("ID", "integer")], "ID", []) with { SourceSchema = "dbo" };
        var plan = Plan(database, [source]) with { TargetExtensionProfile = profile };
        var failure = Assert.Throws<MigrationExecutionException>(() => ApprovedTargetExtensionManifest.TablesFor(plan));
        Assert.Equal("target_extension_source_overlap", failure.Code);
    }

    [Theory]
    [InlineData("Invoice", "accounting-invoice-authority-v1")]
    [InlineData("CustomerIdentity", "auth-customer-create-authority-v1")]
    [InlineData("EmployeeIdentity", "auth-employee-recovery-authority-v1")]
    public void HistoricalUnprofiledPlan_IsNotSilentlyUpgraded(string database, string profile)
    {
        var historical = Plan(database, []);
        string historicalHash = historical.TargetSchemaSha256;
        Assert.Empty(ApprovedTargetExtensionManifest.TablesFor(historical));
        Assert.Equal(historicalHash, PostgreSqlSchemaFingerprint.ComputeExpected(historical));
        var selected = historical with { TargetExtensionProfile = profile };
        Assert.NotEqual(historicalHash, PostgreSqlSchemaFingerprint.ComputeExpected(selected));
        var signed = new FreshSchemaPlan("2.0", new DateTimeOffset(2031, 1, 1, 0, 0, 0, TimeSpan.Zero), new string('a', 40), [historical]);
        Assert.NotEqual(SchemaPlanCanonicalizer.ComputeSha256(signed), SchemaPlanCanonicalizer.ComputeSha256(signed with { Databases = [selected] }));
        Assert.Equal(historicalHash, historical.TargetSchemaSha256);
    }

    [Fact]
    public void HistoricalQuotationProfile_HashMatchesIndependentOldLiteralInventory()
    {
        var literal = Shape("RequestCreateIdempotency", [("KeyHash", "character(64)"), ("Fingerprint", "character(64)"), ("RequestID", "integer")], "KeyHash", []);
        var historical = Plan("QuotationRequest", []) with { TargetExtensionProfile = "quotation-request-idempotency-v1" };
        Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpectedTables([literal]), PostgreSqlSchemaFingerprint.ComputeExpected(historical));
    }

    [Theory]
    [InlineData("Invoice", "accounting-invoice-authority-v1", "InvoiceCreationAdmission,InvoiceNotificationCorrelation")]
    [InlineData("CustomerIdentity", "auth-customer-create-authority-v1", "CustomerIdentityCreateOperations")]
    [InlineData("EmployeeIdentity", "auth-employee-recovery-authority-v1", "EmployeeRecoveryEffects")]
    public void ReviewedProfile_IsRecognizedAndIncludesOnlyItsConsumerTables(string database, string profile, string tables)
    {
        Assert.Equal(profile, ApprovedTargetExtensionManifest.ProfileForDatabase(database));
        var plan = Plan(database, []) with { TargetExtensionProfile = profile };
        Assert.Equal(tables.Split(','), ApprovedTargetExtensionManifest.TablesFor(plan).Select(x => x.TargetTable));
    }

    [Theory]
    [InlineData("Invoice", "accounting-invoice-authority-v1", "InvoiceCreationAdmission")]
    [InlineData("CustomerIdentity", "auth-customer-create-authority-v1", "CustomerIdentityCreateOperations")]
    [InlineData("EmployeeIdentity", "auth-employee-recovery-authority-v1", "EmployeeRecoveryEffects")]
    public void ReviewedProfile_RejectsSourceTableCollisionBeforeClassification(string database, string profile, string table)
    {
        var source = ConsumerShapes(database).Single(x => x.TargetTable == table) with { SourceSchema = "dbo" };
        var plan = Plan(database, [source]) with { TargetExtensionProfile = profile };
        var failure = Assert.Throws<MigrationExecutionException>(() => ApprovedTargetExtensionManifest.TablesFor(plan));
        Assert.Equal("target_extension_source_overlap", failure.Code);
    }

    [Theory]
    [InlineData("Receipt", "accounting-invoice-authority-v1")]
    [InlineData("EmployeeIdentity", "auth-customer-create-authority-v1")]
    [InlineData("CustomerIdentity", "auth-employee-recovery-authority-v1")]
    public void WrongDatabaseProfile_RejectsWithoutInventingTables(string database, string profile)
    {
        var plan = Plan(database, []) with { TargetExtensionProfile = profile };
        var failure = Assert.Throws<MigrationExecutionException>(() => ApprovedTargetExtensionManifest.TablesFor(plan));
        Assert.Equal("target_extension_profile_invalid", failure.Code);
    }

    [Theory]
    [InlineData("Invoice", "unvalidated-check")]
    [InlineData("Invoice", "partitioned-relation")]
    [InlineData("EmployeeIdentity", "rewrite-rule")]
    [InlineData("CustomerIdentity", "nondefault-opclass")]
    public async Task ConsumerAuthorityPhysicalDrift_ChangesObservedFingerprint(string database, string drift)
    {
        var tables = ConsumerShapes(database);
        var plan = Plan(database, tables);
        await WithSchemaAsync(plan, async (shadow, target, baseline) =>
        {
            string sql = drift switch
            {
                "unvalidated-check" => "ALTER TABLE public.\"InvoiceCreationAdmission\" DROP CONSTRAINT \"CK_InvoiceCreationAdmission_Quotation\"; ALTER TABLE public.\"InvoiceCreationAdmission\" ADD CONSTRAINT \"CK_InvoiceCreationAdmission_Quotation\" CHECK (\"QuotationID\" > 0) NOT VALID;",
                "partitioned-relation" => "ALTER TABLE public.\"InvoiceCreationAdmission\" RENAME TO \"AdmissionOld\"; CREATE TABLE public.\"InvoiceCreationAdmission\" (LIKE public.\"AdmissionOld\" INCLUDING ALL) PARTITION BY HASH (\"OperationID\"); DROP TABLE public.\"AdmissionOld\"; ALTER TABLE public.\"InvoiceCreationAdmission\" RENAME CONSTRAINT \"InvoiceCreationAdmission_pkey\" TO \"PK_InvoiceCreationAdmission\";",
                "rewrite-rule" => "CREATE RULE consumer_deny_insert AS ON INSERT TO public.\"EmployeeRecoveryEffects\" DO INSTEAD NOTHING;",
                "nondefault-opclass" => "DROP INDEX public.\"IX_CustomerIdentityCreateOperations_ServiceSubject_OperationKey\"; CREATE UNIQUE INDEX \"IX_CustomerIdentityCreateOperations_ServiceSubject_OperationKey\" ON public.\"CustomerIdentityCreateOperations\" (\"ServiceSubject\" varchar_pattern_ops, \"OperationKey\");",
                _ => throw new ArgumentOutOfRangeException(nameof(drift)),
            };
            await ExecuteAsync(shadow, sql);
            await using var inspection = await target.BeginWholeDatabaseTransactionAsync(shadow, default);
            var failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => inspection.InspectSchemaAsync(plan, default));
            Assert.Equal(drift switch
            {
                "unvalidated-check" => "target_schema_unvalidated_check",
                "partitioned-relation" => "target_schema_relation_unsupported",
                "rewrite-rule" => "target_schema_rewrite_rule_unsupported",
                "nondefault-opclass" => "target_schema_index_semantics_unsupported",
                _ => throw new ArgumentOutOfRangeException(nameof(drift)),
            }, failure.Code);
        });
    }

    [Theory]
    [InlineData("Invoice")]
    [InlineData("CustomerIdentity")]
    [InlineData("EmployeeIdentity")]
    public async Task LiteralConsumerShape_ExtraColumnIsNotIgnored(string database)
    {
        var plan = Plan(database, ConsumerShapes(database));
        await WithSchemaAsync(plan, async (shadow, target, baseline) =>
        {
            await ExecuteAsync(shadow, $"ALTER TABLE public.\"{plan.Tables[0].TargetTable}\" ADD COLUMN \"UnreviewedGenerated\" integer GENERATED ALWAYS AS (1) STORED;");
            await using var inspection = await target.BeginWholeDatabaseTransactionAsync(shadow, default);
            Assert.NotEqual(baseline, await inspection.InspectSchemaAsync(plan, default));
        });
    }

    [Theory]
    [InlineData("Invoice")]
    [InlineData("CustomerIdentity")]
    [InlineData("EmployeeIdentity")]
    public async Task LiteralConsumerShape_ExpectedFingerprintMatchesActualCatalog(string database)
    {
        var plan = Plan(database, ConsumerShapes(database));
        await WithSchemaAsync(plan, (_, _, baseline) =>
        {
            Assert.Equal(plan.TargetSchemaSha256, baseline);
            return Task.CompletedTask;
        });
    }

    [Theory]
    [InlineData("increment", "ALTER SEQUENCE public.\"CustomerIdentityCreateOperations_Id_seq\" INCREMENT BY 2;")]
    [InlineData("start", "ALTER SEQUENCE public.\"CustomerIdentityCreateOperations_Id_seq\" START WITH 2;")]
    [InlineData("cache", "ALTER SEQUENCE public.\"CustomerIdentityCreateOperations_Id_seq\" CACHE 2;")]
    [InlineData("cycle", "ALTER SEQUENCE public.\"CustomerIdentityCreateOperations_Id_seq\" CYCLE;")]
    [InlineData("type", "ALTER SEQUENCE public.\"CustomerIdentityCreateOperations_Id_seq\" AS integer;")]
    [InlineData("minimum", "ALTER SEQUENCE public.\"CustomerIdentityCreateOperations_Id_seq\" MINVALUE 0;")]
    [InlineData("maximum", "ALTER SEQUENCE public.\"CustomerIdentityCreateOperations_Id_seq\" MAXVALUE 9223372036854775806;")]
    [InlineData("mode", "ALTER TABLE public.\"CustomerIdentityCreateOperations\" ALTER COLUMN \"Id\" SET GENERATED ALWAYS;")]
    [InlineData("ownership", "ALTER TABLE public.\"CustomerIdentityCreateOperations\" ALTER COLUMN \"Id\" DROP IDENTITY; CREATE SEQUENCE public.\"CustomerIdentityCreateOperations_Id_seq\" AS bigint; ALTER TABLE public.\"CustomerIdentityCreateOperations\" ALTER COLUMN \"Id\" SET DEFAULT nextval('public.\"CustomerIdentityCreateOperations_Id_seq\"'::regclass);")]
    public async Task ConsumerState_RejectsChangedIdentitySequenceDefinition(string facet, string sql)
    {
        var draft = Plan("CustomerIdentity", []) with { TargetExtensionProfile = "auth-customer-create-authority-v1" };
        var plan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        await WithSchemaAsync(plan, async (shadow, _, _) =>
        {
            await using var c = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString) { Database = shadow.Name }.ConnectionString);
            await c.OpenAsync();
            string before = await CaptureSequenceDefinitionAsync(c);
            output.WriteLine("baseline: " + before);
            await ExecuteAsync(shadow, sql);
            string after = await CaptureSequenceDefinitionAsync(c);
            output.WriteLine(facet + ": " + after);
            Assert.NotEqual(before, after); // Mutation reached the actual catalog, not a DDL/setup failure.
            await using var tx = await c.BeginTransactionAsync();
            var failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => ApprovedTargetExtensionStateInspector.InspectAsync(c, tx, plan, default));
            Assert.Equal("target_extension_sequence_definition_invalid", failure.Code);
        });
    }

    [Theory]
    [InlineData("supported")]
    [InlineData("arbitrary")]
    [InlineData("drift")]
    public async Task NativeRecovery_AdmitsOnlyReviewedConsumerIdentitySequence(string variant)
    {
        var draft = Plan("CustomerIdentity", []) with { TargetExtensionProfile = "auth-customer-create-authority-v1" };
        var plan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        await WithSchemaAsync(plan, async (shadow, _, _) =>
        {
            await using var c = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString) { Database = shadow.Name }.ConnectionString);
            await c.OpenAsync();
            await using (var tx = await c.BeginTransactionAsync())
            {
                Assert.False(await PostgreSqlShadowRecoveryObjects.InspectAsync(c, tx, plan, default));
                await tx.RollbackAsync();
            }
            if (variant == "supported") { return; }
            await ExecuteAsync(shadow, variant == "arbitrary" ? "CREATE SEQUENCE public.\"Arbitrary\";" : "ALTER SEQUENCE public.\"CustomerIdentityCreateOperations_Id_seq\" INCREMENT BY 2;");
            await using var rejected = await c.BeginTransactionAsync();
            var failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => PostgreSqlShadowRecoveryObjects.InspectAsync(c, rejected, plan, default));
            Assert.Equal("shadow_recovery_objects_invalid", failure.Code);
        });
    }

    [Theory]
    [InlineData("missing-table", "DROP TABLE public.\"CustomerIdentityCreateOperations\";")]
    [InlineData("missing-column", "ALTER TABLE public.\"CustomerIdentityCreateOperations\" DROP COLUMN \"Id\";")]
    [InlineData("foreign-alias", "ALTER TABLE public.\"CustomerIdentityCreateOperations\" ALTER COLUMN \"Id\" DROP IDENTITY; CREATE TABLE public.\"AliasOwner\" (\"Id\" bigint GENERATED BY DEFAULT AS IDENTITY); ALTER TABLE public.\"CustomerIdentityCreateOperations\" ALTER COLUMN \"Id\" SET DEFAULT nextval('public.\"AliasOwner_Id_seq\"'::regclass);")]
    public async Task ConsumerState_RejectsMissingOrForeignAliasIdentity(string boundary, string sql)
    {
        var draft = Plan("CustomerIdentity", []) with { TargetExtensionProfile = "auth-customer-create-authority-v1" };
        var plan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        await WithSchemaAsync(plan, async (shadow, _, _) =>
        {
            await ExecuteAsync(shadow, sql);
            await using var c = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString) { Database = shadow.Name }.ConnectionString);
            await c.OpenAsync();
            await using var tx = await c.BeginTransactionAsync();
            var failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => ApprovedTargetExtensionStateInspector.InspectAsync(c, tx, plan, default));
            Assert.Equal("target_extension_sequence_definition_invalid", failure.Code);
            Assert.DoesNotContain(boundary, failure.Message, StringComparison.Ordinal);
        });
    }

    private static async Task<string> CaptureSequenceDefinitionAsync(NpgsqlConnection c)
    {
        const string sql = """
            SELECT format_type(q.seqtypid,NULL), q.seqstart, q.seqincrement, q.seqmin, q.seqmax, q.seqcache, q.seqcycle,
                (SELECT a.attidentity::text FROM pg_attribute a WHERE a.attrelid='public."CustomerIdentityCreateOperations"'::regclass AND a.attname='Id'),
                (SELECT count(*) FROM pg_depend d WHERE d.classid='pg_class'::regclass AND d.objid=q.seqrelid
                    AND d.refclassid='pg_class'::regclass AND d.refobjid='public."CustomerIdentityCreateOperations"'::regclass AND d.deptype='i')
            FROM pg_sequence q WHERE q.seqrelid='public."CustomerIdentityCreateOperations_Id_seq"'::regclass;
            """;
        await using var cmd = new NpgsqlCommand(sql, c);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        object[] values = new object[reader.FieldCount];
        _ = reader.GetValues(values);
        Assert.False(await reader.ReadAsync());
        return JsonSerializer.Serialize(values);
    }

    [Theory]
    [InlineData("Invoice", "predicate")]
    [InlineData("Invoice", "name")]
    [InlineData("Invoice", "schema")]
    [InlineData("Invoice", "default")]
    [InlineData("EmployeeIdentity", "predicate")]
    [InlineData("EmployeeIdentity", "null-logic")]
    [InlineData("EmployeeIdentity", "collation")]
    public async Task UnreviewedConsumerShape_DoesNotMatchImmutableFingerprint(string database, string change)
    {
        var plan = Plan(database, ConsumerShapes(database));
        await WithSchemaAsync(plan, async (shadow, target, baseline) =>
        {
            string sql = change switch
            {
                "predicate" when database == "Invoice" => "ALTER TABLE public.\"InvoiceCreationAdmission\" DROP CONSTRAINT \"CK_InvoiceCreationAdmission_Quotation\"; ALTER TABLE public.\"InvoiceCreationAdmission\" ADD CONSTRAINT \"CK_InvoiceCreationAdmission_Quotation\" CHECK (\"QuotationID\" >= 0);",
                "predicate" => "ALTER TABLE public.\"EmployeeRecoveryEffects\" DROP CONSTRAINT \"CK_EmployeeRecoveryEffects_Binding\"; ALTER TABLE public.\"EmployeeRecoveryEffects\" ADD CONSTRAINT \"CK_EmployeeRecoveryEffects_Binding\" CHECK (length(\"TokenSha256\") = 63);",
                "null-logic" => "ALTER TABLE public.\"EmployeeRecoveryEffects\" DROP CONSTRAINT \"CK_EmployeeRecoveryEffects_PurposePayload\"; ALTER TABLE public.\"EmployeeRecoveryEffects\" ADD CONSTRAINT \"CK_EmployeeRecoveryEffects_PurposePayload\" CHECK (\"PasswordPayloadHash\" IS NULL);",
                "name" => "ALTER TABLE public.\"InvoiceNotificationCorrelation\" RENAME CONSTRAINT \"CK_InvoiceNotificationCorrelation_Identity\" TO \"UnknownIdentity\";",
                "schema" => "CREATE SCHEMA other; ALTER TABLE public.\"InvoiceNotificationCorrelation\" SET SCHEMA other;",
                "default" => "ALTER TABLE public.\"InvoiceCreationAdmission\" ALTER COLUMN \"State\" SET DEFAULT 'Prepared';",
                "collation" => "ALTER TABLE public.\"EmployeeRecoveryEffects\" ALTER COLUMN \"OwnerSubject\" TYPE character varying(256) COLLATE \"C\";",
                _ => throw new ArgumentOutOfRangeException(nameof(change)),
            };
            await ExecuteAsync(shadow, sql);
            await using var inspection = await target.BeginWholeDatabaseTransactionAsync(shadow, default);
            Assert.NotEqual(baseline, await inspection.InspectSchemaAsync(plan, default));
        });
    }

    [Theory]
    [InlineData("Invoice")]
    [InlineData("EmployeeIdentity")]
    public void Compatibility_IsBoundToEveryOrderedCheckColumn(string database)
    {
        foreach (var table in ConsumerShapes(database))
        {
            foreach (var check in table.CheckConstraints.Where(x => CapturedCatalogPredicates.ContainsKey(x.Name) && table.TargetTable != "InvoiceCreationAdmission"))
            {
                var shape = new PostgreSqlSchemaFingerprint.ConstraintShape("public", table.TargetTable, check.Name, 'c', check.Columns, CapturedCatalogPredicates[check.Name]);
                Assert.Equal(SchemaExpressionCanonicalizer.Canonicalize(check.Expression), ConsumerCheckPredicateCompatibility.Canonicalize(shape));
                if (check.Columns.Count > 1)
                {
                    Assert.NotEqual(ConsumerCheckPredicateCompatibility.Canonicalize(shape), ConsumerCheckPredicateCompatibility.Canonicalize(shape with { Columns = check.Columns.Reverse().ToArray() }));
                }
                Assert.NotEqual(ConsumerCheckPredicateCompatibility.Canonicalize(shape), ConsumerCheckPredicateCompatibility.Canonicalize(shape with { Columns = ["Unreviewed"] }));
            }
        }
    }

    private async Task WithSchemaAsync(DatabaseSchemaPlan plan, Func<ShadowDatabase, PostgreSqlShadowTarget, string, Task> proof)
    {
        var target = fixture.CreateShadowTarget();
        var shadow = await target.CreateUniqueEmptyShadowAsync(plan.Database, $"legacy_shadow_consumer_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), default);
        try
        {
            string baseline;
            await using (var create = await target.BeginWholeDatabaseTransactionAsync(shadow, default))
            {
                await create.ApplySchemaAsync(plan, default);
                await create.FinalizeSchemaAsync(plan, default);
                baseline = await create.InspectSchemaAsync(plan, default);
                Assert.Equal(64, baseline.Length);
                foreach (var table in plan.Tables)
                {
                    Assert.Equal(0, (await create.InspectTableAsync(table, default)).RowCount);
                }

                await create.CommitAsync(default);
            }
            await proof(shadow, target, baseline);
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, default); }
    }

    private async Task ExecuteAsync(ShadowDatabase shadow, string sql)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString) { Database = shadow.Name }.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static DatabaseSchemaPlan Plan(string database, IReadOnlyList<TableCopyPlan> tables)
    {
        var plan = new DatabaseSchemaPlan(database, "1.0", new string('a', 64), new string('0', 64), tables);
        return plan with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(plan) };
    }

    // Independently transcribed from owner commits/migrations listed in the design.
    // These are disposable catalog specimens, NOT actual execution of owner EF migrations.
    internal static IReadOnlyList<TableCopyPlan> ConsumerShapes(string database)
    {
        return database switch
        {
            "Invoice" => [Admission(), Correlation()],
            "CustomerIdentity" => [CustomerOperation()],
            "EmployeeIdentity" => [EmployeeEffect()],
            _ => throw new ArgumentOutOfRangeException(nameof(database)),
        };
    }

    private static TableCopyPlan Shape(string table, (string Name, string Type)[] columns, string key, string[] nullable)
    {
        return new("consumer-specimen", table, "public", table, columns.Select(x => x.Name).ToArray(), [key])
        {
            ColumnTypes = columns.ToDictionary(x => x.Name, x => x.Type, StringComparer.Ordinal),
            NullableColumns = nullable,
            PrimaryKey = new($"PK_{table}", [key]),
        };
    }

    private static TableCopyPlan Admission()
    {
        return Shape("InvoiceCreationAdmission",
        [("OperationID", "uuid"), ("QuotationID", "integer"), ("EmployeeSubject", "character varying(256)"),
         ("ServiceSubject", "character varying(128)"), ("IntentFingerprint", "character varying(64)"),
         ("State", "character varying(32)"), ("ResultJson", "text"), ("CreatedAt", "timestamp with time zone"),
         ("UpdatedAt", "timestamp with time zone")], "OperationID", ["ResultJson"]) with
        { CheckConstraints = [new("CK_InvoiceCreationAdmission_Quotation", "\"QuotationID\" > 0") { Columns = ["QuotationID"] }] };
    }

    private static TableCopyPlan CustomerOperation()
    {
        return Shape("CustomerIdentityCreateOperations",
        [("Id", "bigint"), ("ServiceSubject", "character varying(256)"), ("OperationKey", "uuid"),
         ("DatabaseId", "integer"), ("IdentityId", "character varying(450)"), ("PayloadSalt", "bytea"), ("PayloadHash", "bytea")], "Id", []) with
        {
            Identities = [new("Id", 1, 1, 1, false)],
            Indexes = [new("IX_CustomerIdentityCreateOperations_ServiceSubject_OperationKey", ["ServiceSubject", "OperationKey"], true),
                new("IX_CustomerIdentityCreateOperations_DatabaseId", ["DatabaseId"], true)],
        };
    }

    private static TableCopyPlan EmployeeEffect()
    {
        return Shape("EmployeeRecoveryEffects",
        [("ActionId", "uuid"), ("TokenSha256", "character varying(64)"), ("Purpose", "character varying(32)"),
         ("OwnerSubject", "character varying(256)"), ("IdentityId", "character varying(450)"),
         ("NormalizedEmail", "character varying(256)"), ("BeforeSecurityStamp", "text"), ("AfterSecurityStamp", "text"),
         ("AfterConcurrencyStamp", "text"), ("PasswordPayloadHash", "text"), ("AppliedAt", "timestamp with time zone"),
         ("FinalizedAcknowledgedAt", "timestamp with time zone")], "ActionId", ["PasswordPayloadHash", "FinalizedAcknowledgedAt"]) with
        {
            CheckConstraints =
            [new("CK_EmployeeRecoveryEffects_PurposePayload", "(\"Purpose\" = 'employee-password-reset' AND \"PasswordPayloadHash\" IS NOT NULL) OR (\"Purpose\" = 'employee-email-confirmation' AND \"PasswordPayloadHash\" IS NULL)") { Columns = ["Purpose", "PasswordPayloadHash"] },
             new("CK_EmployeeRecoveryEffects_Binding", "length(\"TokenSha256\") = 64 AND length(\"OwnerSubject\") > 0 AND length(\"BeforeSecurityStamp\") > 0 AND length(\"AfterSecurityStamp\") > 0") { Columns = ["TokenSha256", "OwnerSubject", "BeforeSecurityStamp", "AfterSecurityStamp"] }],
            Indexes = [new("IX_EmployeeRecoveryEffects_TokenSha256_Purpose", ["TokenSha256", "Purpose"], true),
                new("IX_EmployeeRecoveryEffects_IdentityId_FinalizedAcknowledgedAt", ["IdentityId", "FinalizedAcknowledgedAt"], false),
                new("IX_EmployeeRecoveryEffects_FinalizedAcknowledgedAt_AppliedAt", ["FinalizedAcknowledgedAt", "AppliedAt"], false)],
        };
    }

    private static TableCopyPlan Correlation()
    {
        return Shape("InvoiceNotificationCorrelation",
        [("IntentID", "uuid"), ("InvoiceID", "integer"), ("Purpose", "character varying(32)"), ("QuotationID", "integer"),
         ("WorkflowOperationID", "uuid"), ("OriginIssuer", "character varying(512)"), ("OriginEmployeeSubject", "character varying(256)"),
         ("OriginServiceSubject", "character varying(128)"), ("SenderIssuer", "character varying(512)"),
         ("SenderServiceSubject", "character varying(128)"), ("PayloadFrameVersion", "character varying(64)"),
         ("BindingVersion", "character varying(64)"), ("BindingKeyID", "character varying(64)"), ("PayloadBinding", "bytea"),
         ("Phase", "character varying(32)"), ("Version", "bigint"), ("RemoteVersion", "bigint"), ("CreatedAt", "timestamp with time zone"),
         ("UpdatedAt", "timestamp with time zone"), ("AdmissionIssuedAt", "timestamp with time zone"), ("ExecutionIssuedAt", "timestamp with time zone"),
         ("RemoteAdmittedAt", "timestamp with time zone"), ("RemoteReceiptBinding", "bytea"), ("RemoteState", "character varying(32)"),
         ("RemoteUpdatedAt", "timestamp with time zone")], "IntentID",
        ["RemoteVersion", "AdmissionIssuedAt", "ExecutionIssuedAt", "RemoteAdmittedAt", "RemoteReceiptBinding", "RemoteState", "RemoteUpdatedAt"]) with
        {
            UniqueConstraints = [new("UQ_InvoiceNotificationCorrelation_InvoicePurpose", ["InvoiceID", "Purpose"])],
            CheckConstraints =
            [new("CK_InvoiceNotificationCorrelation_Identity", "\"InvoiceID\" > 0 AND \"QuotationID\" > 0 AND \"Purpose\" = 'invoice-issued' AND \"SenderServiceSubject\" = 'service:legacy-accounting' AND \"IntentID\" <> '00000000-0000-0000-0000-000000000000'::uuid AND \"WorkflowOperationID\" <> '00000000-0000-0000-0000-000000000000'::uuid AND \"IntentID\" <> \"WorkflowOperationID\" AND octet_length(\"PayloadBinding\") = 32 AND length(\"OriginIssuer\") > 0 AND length(\"OriginEmployeeSubject\") > 0 AND length(\"OriginServiceSubject\") > 0 AND length(\"SenderIssuer\") > 0 AND length(\"BindingKeyID\") > 0 AND \"PayloadFrameVersion\" = 'notification-payload-v1' AND \"BindingVersion\" = 'accounting-invoice-notification-hmac-v1'") { Columns = ["InvoiceID", "QuotationID", "Purpose", "SenderServiceSubject", "IntentID", "WorkflowOperationID", "PayloadBinding", "OriginIssuer", "OriginEmployeeSubject", "OriginServiceSubject", "SenderIssuer", "BindingKeyID", "PayloadFrameVersion", "BindingVersion"] },
             new("CK_InvoiceNotificationCorrelation_State", "\"Version\" > 0 AND (\"RemoteVersion\" IS NULL OR \"RemoteVersion\" > 0) AND \"UpdatedAt\" >= \"CreatedAt\" AND \"Phase\" IN ('Prepared','AdmissionIssued','Admitted','ExecutionIssued','OutcomeUnknown','ProviderAccepted','RejectedBeforeSubmission') AND (\"AdmissionIssuedAt\" IS NULL OR \"AdmissionIssuedAt\" >= \"CreatedAt\") AND (\"ExecutionIssuedAt\" IS NULL OR (\"AdmissionIssuedAt\" IS NOT NULL AND \"ExecutionIssuedAt\" >= \"AdmissionIssuedAt\")) AND (\"Phase\" = 'Prepared' OR \"AdmissionIssuedAt\" IS NOT NULL) AND (\"Phase\" <> 'Prepared' OR (\"AdmissionIssuedAt\" IS NULL AND \"ExecutionIssuedAt\" IS NULL AND \"RemoteVersion\" IS NULL)) AND (\"Phase\" <> 'AdmissionIssued' OR (\"AdmissionIssuedAt\" IS NOT NULL AND \"ExecutionIssuedAt\" IS NULL)) AND (\"Phase\" <> 'Admitted' OR (\"AdmissionIssuedAt\" IS NOT NULL AND \"ExecutionIssuedAt\" IS NULL AND \"RemoteVersion\" IS NOT NULL)) AND (\"Phase\" <> 'ExecutionIssued' OR (\"ExecutionIssuedAt\" IS NOT NULL AND \"RemoteVersion\" IS NOT NULL)) AND (\"Phase\" NOT IN ('OutcomeUnknown','ProviderAccepted') OR (\"ExecutionIssuedAt\" IS NOT NULL AND \"RemoteVersion\" IS NOT NULL)) AND (\"Phase\" NOT IN ('ProviderAccepted','RejectedBeforeSubmission') OR \"RemoteVersion\" IS NOT NULL)") { Columns = ["Version", "RemoteVersion", "UpdatedAt", "CreatedAt", "Phase", "AdmissionIssuedAt", "ExecutionIssuedAt"] },
             new("CK_InvoiceNotificationCorrelation_Receipt", "(\"RemoteVersion\" IS NULL AND \"RemoteState\" IS NULL AND \"RemoteAdmittedAt\" IS NULL AND \"RemoteUpdatedAt\" IS NULL AND \"RemoteReceiptBinding\" IS NULL) OR (\"RemoteVersion\" IS NOT NULL AND \"RemoteVersion\">0 AND \"RemoteState\" IS NOT NULL AND \"RemoteAdmittedAt\" IS NOT NULL AND \"RemoteUpdatedAt\" IS NOT NULL AND \"RemoteReceiptBinding\" IS NOT NULL AND octet_length(\"RemoteReceiptBinding\")=32 AND \"RemoteUpdatedAt\">=\"RemoteAdmittedAt\" AND ((\"RemoteState\"='admitted' AND \"RemoteVersion\"=1) OR (\"RemoteState\"='submitting' AND \"RemoteVersion\"=2) OR (\"RemoteState\" IN ('outcomeUnknown','providerAccepted') AND \"RemoteVersion\"=3)))") { Columns = ["RemoteVersion", "RemoteState", "RemoteAdmittedAt", "RemoteUpdatedAt", "RemoteReceiptBinding"] },
             new("CK_InvoiceNotificationCorrelation_ReceiptPhase", "(\"Phase\" IN ('Prepared','AdmissionIssued') AND \"RemoteVersion\" IS NULL) OR (\"Phase\" IN ('Admitted','ExecutionIssued') AND \"RemoteVersion\" IS NOT NULL AND \"RemoteState\"='admitted') OR (\"Phase\"='OutcomeUnknown' AND \"RemoteVersion\" IS NOT NULL AND \"RemoteState\" IN ('submitting','outcomeUnknown')) OR (\"Phase\"='ProviderAccepted' AND \"RemoteVersion\" IS NOT NULL AND \"RemoteState\"='providerAccepted')") { Columns = ["Phase", "RemoteVersion", "RemoteState"] }],
        };
    }
}
