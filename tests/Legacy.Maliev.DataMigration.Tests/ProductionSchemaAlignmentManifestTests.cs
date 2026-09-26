namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ProductionSchemaAlignmentManifestTests
{
    private static readonly HashSet<string> SysdiagramsDatabases = new(StringComparer.Ordinal)
    {
        "Country", "Currency", "Customer", "CustomerIdentity", "DataProtectionKeys",
        "Employee", "EmployeeIdentity", "Invoice", "JobOffers", "Material", "Message",
        "Order", "OrderStatus", "Payment", "PurchaseOrder", "Quotation", "Receipt", "Supplier",
    };

    private static readonly Dictionary<string, string[]> MissingColumns =
        new(StringComparer.Ordinal)
        {
            ["Invoice"] = ["SourceJourneyID", "SourceRequestID"],
            ["Quotation"] = ["AcceptanceOrigin", "AcceptedUtc", "SourceJourneyID", "SourceRequestID"],
            ["QuotationRequest"] = ["JourneyId", "QualificationState", "QualificationStateChangedUtc",
                "QualificationVersion", "TransactionId"],
        };

    [Fact]
    public void Exact_reviewed_production_preimage_is_read_only_and_preserves_sysdiagrams()
    {
        (FreshSchemaPlan schema, ProductionSchemaObservation[] observed) = Fixture();

        ProductionSchemaAlignmentReview review = ProductionSchemaAlignmentManifest.Plan(schema,
            Authority(), observed, DateTimeOffset.UtcNow);

        Assert.Equal(DatabaseInventory.ActiveDatabases, review.Databases.Select(item => item.Database));
        Assert.Equal(18, review.Databases.SelectMany(item => item.Steps)
            .Count(item => item.ObjectName == "public.sysdiagrams" && item.PreserveSourceRows));
        Assert.Equal(["legacy_compatibility.GoogleAnalyticsOutbox", "public.QuotationAcceptedOutcome",
            "public.sysdiagrams"], review.Databases.Single(item => item.Database == "Quotation")
            .Steps.Where(item => item.Kind == "add-table").Select(item => item.ObjectName));
        Assert.Contains(review.Databases.Single(item => item.Database == "QuotationRequest").Steps,
            item => item.Kind == "add-table" && item.ObjectName == "public.RequestQualificationAudit");
        Assert.All(review.Databases, item =>
        {
            Assert.Matches("^[0-9a-f]{64}$", item.PreimageSchemaSha256);
            Assert.Matches("^[0-9a-f]{64}$", item.StepsSha256);
            Assert.NotNull(item.Steps);
        });
    }

    [Theory]
    [InlineData("unknown-table")]
    [InlineData("partial-sysdiagrams")]
    [InlineData("partial-invoice-column")]
    [InlineData("partial-mapped-outbox")]
    [InlineData("source-shaped-outbox")]
    [InlineData("missing-approved-extension")]
    public void Unreviewed_or_partial_name_inventory_fails_closed(string change)
    {
        (FreshSchemaPlan schema, ProductionSchemaObservation[] observed) = Fixture();
        int index = Array.FindIndex(observed, item => item.Database ==
            change switch
            {
                "partial-invoice-column" => "Invoice",
                "missing-approved-extension" => "Material",
                _ => "Quotation",
            });
        ProductionSchemaObservation current = observed[index];
        ObservedTargetTable[] tables = change switch
        {
            "unknown-table" => [.. current.Tables, new("public", "Unknown", ["ID"])],
            "partial-sysdiagrams" => [.. current.Tables, new("public", "sysdiagrams", ["name"])],
            "partial-invoice-column" => [.. current.Tables.Select(table => table.Table == "Invoice"
                ? table with { Columns = [.. table.Columns, "SourceRequestID"] } : table)],
            "partial-mapped-outbox" => [.. current.Tables,
                new("public", "QuotationAcceptedOutcome", ["ID"])],
            "source-shaped-outbox" => [.. current.Tables, new("public", "GoogleAnalyticsOutbox", ["ID"])],
            "missing-approved-extension" => [.. current.Tables.Where(table => table.Table != "Country")],
            _ => throw new ArgumentOutOfRangeException(nameof(change)),
        };
        observed[index] = current with { Tables = tables };

        MigrationExecutionException failure = Assert.Throws<MigrationExecutionException>(() =>
            ProductionSchemaAlignmentManifest.Plan(schema, Authority(), observed, DateTimeOffset.UtcNow));
        Assert.Equal("production_schema_alignment_name_drift", failure.Code);
    }

    [Fact]
    public void Names_match_but_changed_complete_schema_fingerprint_fails_closed()
    {
        (FreshSchemaPlan schema, ProductionSchemaObservation[] observed) = Fixture();
        int index = Array.FindIndex(observed, item => item.Database == "Invoice");
        observed[index] = observed[index] with { SchemaSha256 = new string('f', 64) };

        MigrationExecutionException failure = Assert.Throws<MigrationExecutionException>(() =>
            ProductionSchemaAlignmentManifest.Plan(schema, Authority(), observed, DateTimeOffset.UtcNow));
        Assert.Equal("production_schema_alignment_shape_drift", failure.Code);
    }

    [Fact]
    public void Wrong_authority_stale_plan_or_untrusted_target_shape_fails_closed()
    {
        (FreshSchemaPlan schema, ProductionSchemaObservation[] observed) = Fixture();
        DeltaTargetAuthority local = new(DeltaTargetAuthorityKind.LocalAspire,
            "aspire://legacy-postgres-main-local/persistent-test", new string('b', 64));
        Assert.Equal("production_schema_alignment_boundary_invalid",
            Assert.Throws<MigrationExecutionException>(() => ProductionSchemaAlignmentManifest.Plan(
                schema, local, observed, DateTimeOffset.UtcNow)).Code);
        Assert.Equal("production_schema_alignment_boundary_invalid",
            Assert.Throws<MigrationExecutionException>(() => ProductionSchemaAlignmentManifest.Plan(
                schema with { CapturedAtUtc = DateTimeOffset.UtcNow.AddHours(-3) }, Authority(),
                observed, DateTimeOffset.UtcNow)).Code);
        DatabaseSchemaPlan[] databases = [.. schema.Databases];
        int invoice = Array.FindIndex(databases, item => item.Database == "Invoice");
        databases[invoice] = databases[invoice] with { TargetSchemaSha256 = new string('0', 64) };
        Assert.Equal("production_schema_alignment_plan_invalid",
            Assert.Throws<MigrationExecutionException>(() => ProductionSchemaAlignmentManifest.Plan(
                schema with { Databases = databases }, Authority(), observed, DateTimeOffset.UtcNow)).Code);
        databases[invoice] = schema.Databases[invoice] with { SourceSchemaSha256 = "untrusted" };
        Assert.Equal("production_schema_alignment_plan_invalid",
            Assert.Throws<MigrationExecutionException>(() => ProductionSchemaAlignmentManifest.Plan(
                schema with { Databases = databases }, Authority(), observed, DateTimeOffset.UtcNow)).Code);
    }

    [Fact]
    public void Changed_service_column_contract_or_marked_empty_sysdiagrams_fails_closed()
    {
        (FreshSchemaPlan schema, ProductionSchemaObservation[] observed) = Fixture();
        DatabaseSchemaPlan[] databases = [.. schema.Databases];
        int invoice = Array.FindIndex(databases, item => item.Database == "Invoice");
        TableCopyPlan changedInvoice = databases[invoice].Tables.Single(item => item.TargetTable == "Invoice")
            with
        {
            ColumnTypes = new Dictionary<string, string>(databases[invoice].Tables
                    .Single(item => item.TargetTable == "Invoice").ColumnTypes, StringComparer.Ordinal)
            {
                ["SourceJourneyID"] = "text",
            },
        };
        DatabaseSchemaPlan changed = databases[invoice] with
        {
            Tables = [changedInvoice, .. databases[invoice].Tables.Where(item => item.TargetTable != "Invoice")],
        };
        databases[invoice] = changed with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(changed) };
        Assert.Equal("production_schema_alignment_column_shape_invalid",
            Assert.Throws<MigrationExecutionException>(() => ProductionSchemaAlignmentManifest.Plan(
                schema with { Databases = databases }, Authority(), observed, DateTimeOffset.UtcNow)).Code);

        databases = [.. schema.Databases];
        int country = Array.FindIndex(databases, item => item.Database == "Country");
        TableCopyPlan diagram = databases[country].Tables.Single(item => item.TargetTable == "sysdiagrams")
            with
        { SourceKnownEmpty = true };
        changed = databases[country] with
        {
            Tables = [.. databases[country].Tables.Where(item => item.TargetTable != "sysdiagrams"), diagram],
        };
        databases[country] = changed with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(changed) };
        Assert.Equal("production_schema_alignment_sysdiagrams_shape_invalid",
            Assert.Throws<MigrationExecutionException>(() => ProductionSchemaAlignmentManifest.Plan(
                schema with { Databases = databases }, Authority(), observed, DateTimeOffset.UtcNow)).Code);
    }

    [Fact]
    public void Quotation_accepted_utc_requires_lossless_datetime2_7_text_mapping()
    {
        (FreshSchemaPlan schema, ProductionSchemaObservation[] observed) = Fixture();
        DatabaseSchemaPlan[] databases = [.. schema.Databases];
        int quotation = Array.FindIndex(databases, item => item.Database == "Quotation");
        TableCopyPlan source = databases[quotation].Tables.Single(item => item.TargetTable == "Quotation");
        Assert.Equal("text", source.ColumnTypes["AcceptedUtc"]);
        TableCopyPlan changedTable = source with
        {
            ColumnTypes = new Dictionary<string, string>(source.ColumnTypes, StringComparer.Ordinal)
            {
                ["AcceptedUtc"] = "timestamp without time zone",
            },
        };
        DatabaseSchemaPlan changed = databases[quotation] with
        {
            Tables = [changedTable, .. databases[quotation].Tables.Where(item => item.TargetTable != "Quotation")],
        };
        databases[quotation] = changed with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(changed) };
        Assert.Equal("production_schema_alignment_column_shape_invalid",
            Assert.Throws<MigrationExecutionException>(() => ProductionSchemaAlignmentManifest.Plan(
                schema with { Databases = databases }, Authority(), observed, DateTimeOffset.UtcNow)).Code);
    }

    [Theory]
    [InlineData("QualificationState", "('qualified')")]
    [InlineData("QualificationVersion", "((1))")]
    public void Changed_qualification_default_fails_even_when_default_still_exists(
        string column, string alteredDefault)
    {
        (FreshSchemaPlan schema, ProductionSchemaObservation[] observed) = Fixture();
        DatabaseSchemaPlan[] databases = [.. schema.Databases];
        int request = Array.FindIndex(databases, item => item.Database == "QuotationRequest");
        TableCopyPlan source = databases[request].Tables.Single(item => item.TargetTable == "Request");
        TableCopyPlan changedTable = source with
        {
            DefaultExpressions = new Dictionary<string, string>(source.DefaultExpressions, StringComparer.Ordinal)
            {
                [column] = alteredDefault,
            },
        };
        DatabaseSchemaPlan changed = databases[request] with
        {
            Tables = [changedTable, .. databases[request].Tables.Where(item => item.TargetTable != "Request")],
        };
        databases[request] = changed with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(changed) };
        Assert.Equal("production_schema_alignment_column_shape_invalid",
            Assert.Throws<MigrationExecutionException>(() => ProductionSchemaAlignmentManifest.Plan(
                schema with { Databases = databases }, Authority(), observed, DateTimeOffset.UtcNow)).Code);
    }

    private static (FreshSchemaPlan, ProductionSchemaObservation[]) Fixture()
    {
        DatabaseSchemaPlan[] databases = [.. DatabaseInventory.ActiveDatabases.Select(Database)];
        var schema = new FreshSchemaPlan("2.0", DateTimeOffset.UtcNow.AddMinutes(-2), new string('a', 40), databases);
        ProductionSchemaObservation[] observed = [.. databases.Select(database =>
        {
            TableCopyPlan[] mapped = [.. ApprovedSourceDispositionManifest.TargetTablesFor(database),
                .. ApprovedTargetExtensionManifest.TablesFor(database)];
            TableCopyPlan[] preimage = [.. mapped
                .Where(table => !MissingTable(database.Database, table))
                .Select(table => RemoveColumns(database.Database, table))];
            return new ProductionSchemaObservation(database.Database,
                [.. preimage.Select(table => new ObservedTargetTable(table.TargetSchema,
                    table.TargetTable, table.OrderedColumns))],
                PostgreSqlSchemaFingerprint.ComputeExpectedTables(preimage));
        })];
        return (schema, observed);
    }

    private static DatabaseSchemaPlan Database(string name)
    {
        var tables = new List<TableCopyPlan>();
        if (name == "Invoice")
        {
            tables.Add(Table("Invoice", ["ID", "SourceJourneyID", "SourceRequestID"],
                ["integer", "uuid", "integer"], ["SourceJourneyID", "SourceRequestID"]) with
            {
                Indexes = [new("IX_Invoice_SourceJourneyID", ["SourceJourneyID"], false),
                    new("IX_Invoice_SourceRequestID", ["SourceRequestID"], false)],
            });
        }
        else if (name == "Quotation")
        {
            tables.Add(Table("Quotation", ["ID", "AcceptanceOrigin", "AcceptedUtc",
                    "SourceJourneyID", "SourceRequestID"],
                ["integer", "character varying(16)", "text", "uuid", "integer"],
                ["AcceptanceOrigin", "AcceptedUtc", "SourceJourneyID", "SourceRequestID"]) with
            {
                Indexes = [new("IX_Quotation_SourceJourneyID", ["SourceJourneyID"], false),
                    new("IX_Quotation_SourceRequestID", ["SourceRequestID"], false)],
            });
            tables.Add(ApprovedSourceDispositionManifestTests.Outbox(
                CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true));
            tables.Add(ApprovedSourceDispositionManifestTests.Outbox(
                CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false));
        }
        else if (name == "QuotationRequest")
        {
            tables.Add(Table("Request", ["ID", "JourneyId", "QualificationState",
                    "QualificationStateChangedUtc", "QualificationVersion", "TransactionId"],
                ["integer", "uuid", "character varying(32)", "text", "integer", "character varying(128)"],
                ["JourneyId", "QualificationStateChangedUtc", "TransactionId"]) with
            {
                DefaultExpressions = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["QualificationState"] = "('unreviewed')",
                    ["QualificationVersion"] = "((0))",
                },
                Indexes = [new("IX_Request_JourneyId", ["JourneyId"], false),
                    new("UX_Request_TransactionId", ["TransactionId"], true)],
                CheckConstraints = [new("CK_Request_QualificationState", "\"QualificationState\"='unreviewed'")
                { Columns = ["QualificationState"] }],
            });
            string[] auditColumns = ["ID", "RequestID", "JourneyId", "TransactionId", "IdempotencyKey",
                "PreviousState", "NewState", "Completeness", "DuplicateCount", "UnmatchedClassification",
                "ChangedBy", "ChangedUtc", "Reason", "Version"];
            tables.Add(Table("RequestQualificationAudit", auditColumns,
                ["bigint", "integer", "uuid", "character varying(128)", "character varying(128)",
                    "character varying(32)", "character varying(32)", "character varying(32)", "integer",
                    "character varying(64)", "character varying(256)", "text", "character varying(512)",
                    "integer"], ["JourneyId", "Completeness", "UnmatchedClassification", "Reason"]));
        }
        else
        {
            tables.Add(Table("Probe", ["ID"], ["integer"], []));
        }
        if (SysdiagramsDatabases.Contains(name))
        {
            tables.Add(Table("sysdiagrams", ["name", "principal_id", "diagram_id", "version", "definition"],
                ["character varying(128)", "integer", "integer", "integer", "bytea"], ["version", "definition"]));
        }
        var plan = new DatabaseSchemaPlan(name, "1.0", new string('c', 64), string.Empty, tables)
        {
            TargetExtensionProfile = ApprovedTargetExtensionManifest.ProfileForDatabase(name),
            SourceDispositionProfile = ApprovedSourceDispositionManifest.ProfileForDatabase(name, tables),
            SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase(name, tables),
        };
        return plan with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(plan) };
    }

    private static TableCopyPlan Table(string name, string[] columns, string[] types, string[] nullable)
    {
        return new TableCopyPlan("dbo", name, "public", name, columns, [columns[0]])
        {
            ColumnTypes = columns.Zip(types).ToDictionary(item => item.First, item => item.Second,
                StringComparer.Ordinal),
            NullableColumns = nullable,
            PrimaryKey = new PrimaryKeyCopyPlan("PK_" + name, [columns[0]]),
        };
    }

    private static bool MissingTable(string database, TableCopyPlan table)
    {
        return (SysdiagramsDatabases.Contains(database) && table.TargetTable == "sysdiagrams") ||
            (database == "Quotation" && (table.TargetSchema, table.TargetTable) is
                ("legacy_compatibility", "GoogleAnalyticsOutbox") or ("public", "QuotationAcceptedOutcome")) ||
            (database == "QuotationRequest" && table.TargetTable == "RequestQualificationAudit");
    }

    private static TableCopyPlan RemoveColumns(string database, TableCopyPlan table)
    {
        if (!((database == "Invoice" && table.TargetTable == "Invoice") ||
            (database == "Quotation" && table.TargetTable == "Quotation") ||
            (database == "QuotationRequest" && table.TargetTable == "Request")))
        {
            return table;
        }
        HashSet<string> removed = [.. MissingColumns[database]];
        return table with
        {
            OrderedColumns = [.. table.OrderedColumns.Where(column => !removed.Contains(column))],
            ColumnTypes = table.ColumnTypes.Where(item => !removed.Contains(item.Key))
                .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal),
            NullableColumns = [.. table.NullableColumns.Where(column => !removed.Contains(column))],
            DefaultExpressions = table.DefaultExpressions.Where(item => !removed.Contains(item.Key))
                .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal),
            Indexes = [.. table.Indexes.Where(item => !item.Columns.Any(removed.Contains))],
            CheckConstraints = [.. table.CheckConstraints.Where(item => !item.Columns.Any(removed.Contains))],
        };
    }

    private static DeltaTargetAuthority Authority()
    {
        return new(
        DeltaTargetAuthorityKind.ProductionCloudNativePg,
        "gke://maliev-website/legacy-postgres-main/test", new string('b', 64));
    }
}
