using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration;

/// <summary>Authenticated catalog data must be supplied by a separate read-only observer.</summary>
public sealed record ProductionSchemaObservation(
    string Database, IReadOnlyList<ObservedTargetTable> Tables, string SchemaSha256);

/// <summary>A reviewed object name; this is diagnostic, never executable SQL or DDL permission.</summary>
public sealed record ProductionSchemaAlignmentStep(string Kind, string ObjectName, bool PreserveSourceRows = false);

/// <summary>One exact preimage and additive target shape for owner review only.</summary>
public sealed record ProductionDatabaseSchemaAlignment(
    string Database, string PreimageSchemaSha256, string FinalSchemaSha256,
    string StepsSha256, IReadOnlyList<ProductionSchemaAlignmentStep> Steps);

/// <summary>PII-free review document. No signature or execution authorization is implied.</summary>
public sealed record ProductionSchemaAlignmentReview(
    string SchemaPlanSha256, string SourceCommitSha, DeltaTargetAuthority TargetAuthority,
    IReadOnlyList<ProductionDatabaseSchemaAlignment> Databases);

/// <summary>
/// Fixed #94 production preimage: preserve the eighteen populated source sysdiagrams tables,
/// align reviewed service columns, and create only the mapped Quotation disposition targets.
/// This class never opens a connection or constructs executable SQL.
/// </summary>
public static class ProductionSchemaAlignmentManifest
{
    private static readonly HashSet<string> SysdiagramsDatabases = new(StringComparer.Ordinal)
    {
        "Country", "Currency", "Customer", "CustomerIdentity", "DataProtectionKeys",
        "Employee", "EmployeeIdentity", "Invoice", "JobOffers", "Material", "Message",
        "Order", "OrderStatus", "Payment", "PurchaseOrder", "Quotation", "Receipt", "Supplier",
    };

    private static readonly IReadOnlyDictionary<string, string[]> MissingColumns =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["Invoice"] = ["public.Invoice.SourceJourneyID", "public.Invoice.SourceRequestID"],
            ["Quotation"] = ["public.Quotation.AcceptanceOrigin", "public.Quotation.AcceptedUtc",
                "public.Quotation.SourceJourneyID", "public.Quotation.SourceRequestID"],
            ["QuotationRequest"] = ["public.Request.JourneyId", "public.Request.QualificationState",
                "public.Request.QualificationStateChangedUtc", "public.Request.QualificationVersion",
                "public.Request.TransactionId"],
        };

    private static readonly IReadOnlyDictionary<string, string[]> DependentIndexes =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["Invoice"] = ["IX_Invoice_SourceJourneyID", "IX_Invoice_SourceRequestID"],
            ["Quotation"] = ["IX_Quotation_SourceJourneyID", "IX_Quotation_SourceRequestID"],
            ["QuotationRequest"] = ["IX_Request_JourneyId", "UX_Request_TransactionId"],
        };

    private static readonly Dictionary<string, (string Type, bool Nullable, bool HasDefault)> ReviewedColumns =
        new(StringComparer.Ordinal)
        {
            ["public.Invoice.SourceJourneyID"] = ("uuid", true, false),
            ["public.Invoice.SourceRequestID"] = ("integer", true, false),
            ["public.Quotation.AcceptanceOrigin"] = ("character varying(16)", true, false),
            ["public.Quotation.AcceptedUtc"] = ("text", true, false),
            ["public.Quotation.SourceJourneyID"] = ("uuid", true, false),
            ["public.Quotation.SourceRequestID"] = ("integer", true, false),
            ["public.Request.JourneyId"] = ("uuid", true, false),
            ["public.Request.QualificationState"] = ("character varying(32)", false, true),
            ["public.Request.QualificationStateChangedUtc"] = ("text", true, false),
            ["public.Request.QualificationVersion"] = ("integer", false, true),
            ["public.Request.TransactionId"] = ("character varying(128)", true, false),
        };

    private static readonly Dictionary<string, string> ReviewedDefaults =
        new(StringComparer.Ordinal)
        {
            ["public.Request.QualificationState"] = "('unreviewed')",
            ["public.Request.QualificationVersion"] = "((0))",
        };

    /// <summary>
    /// Requires one fresh exact-23 source plan, one exact production identity, and each database's
    /// complete observed schema fingerprint matching the reviewed preimage. Names alone never pass.
    /// </summary>
    public static ProductionSchemaAlignmentReview Plan(FreshSchemaPlan schema,
        DeltaTargetAuthority authority, IReadOnlyList<ProductionSchemaObservation> observations,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(observations);
        if (schema.SchemaVersion != "2.0" || schema.CapturedAtUtc.Offset != TimeSpan.Zero ||
            nowUtc.Offset != TimeSpan.Zero || schema.CapturedAtUtc > nowUtc ||
            nowUtc - schema.CapturedAtUtc > TimeSpan.FromHours(2) ||
            schema.SourceCommitSha.Length != 40 || !schema.SourceCommitSha.All(char.IsAsciiHexDigit) ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(authority, "maliev-legacy", "legacy-postgres-main") ||
            authority.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg ||
            !schema.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases,
                StringComparer.Ordinal) ||
            !observations.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases,
                StringComparer.Ordinal))
        {
            throw Invalid("production_schema_alignment_boundary_invalid");
        }

        var results = new List<ProductionDatabaseSchemaAlignment>(schema.Databases.Count);
        foreach ((DatabaseSchemaPlan database, ProductionSchemaObservation observation) in
            schema.Databases.Zip(observations))
        {
            if (database.TargetSchemaVersion != "1.0" ||
                database.SourceSchemaSha256.Length != 64 ||
                !database.SourceSchemaSha256.All(char.IsAsciiHexDigit) ||
                database.TargetExtensionProfile != ApprovedTargetExtensionManifest.ProfileForDatabase(database.Database) ||
                database.TargetSchemaSha256 != PostgreSqlSchemaFingerprint.ComputeExpected(database) ||
                observation.SchemaSha256.Length != 64 || !observation.SchemaSha256.All(char.IsAsciiHexDigit))
            {
                throw Invalid("production_schema_alignment_plan_invalid");
            }

            TableCopyPlan[] targetTables =
            [
                .. ApprovedSourceDispositionManifest.TargetTablesFor(database),
                .. ApprovedTargetExtensionManifest.TablesFor(database),
            ];
            ValidateReviewedShapes(database, targetTables);
            string[] missingTables = MissingTableNames(database.Database);
            string[] missingColumns = MissingColumns.GetValueOrDefault(database.Database) ?? [];
            TargetSchemaGap gap = TargetSchemaGapAnalyzer.Analyze(database, observation.Tables);
            if (!gap.MissingTables.SequenceEqual(missingTables, StringComparer.Ordinal) ||
                !gap.MissingColumns.SequenceEqual(missingColumns, StringComparer.Ordinal) ||
                gap.TargetOnlyTables.Count != 0 || gap.TargetOnlyColumns.Count != 0 ||
                gap.MissingApprovedTargetExtensions.Count != 0 ||
                gap.RetainedSourceTransitionTables.Count != 0)
            {
                throw Invalid("production_schema_alignment_name_drift");
            }

            TableCopyPlan[] preimage = [.. targetTables
                .Where(table => !missingTables.Contains(Qualified(table), StringComparer.Ordinal))
                .Select(table => RemoveReviewedColumns(database.Database, table))];
            string expectedPreimage = PostgreSqlSchemaFingerprint.ComputeExpectedTables(preimage);
            if (observation.SchemaSha256 != expectedPreimage)
            {
                throw Invalid("production_schema_alignment_shape_drift");
            }

            ProductionSchemaAlignmentStep[] steps =
            [
                .. missingTables.Select(table => new ProductionSchemaAlignmentStep(
                    "add-table", table, table == "public.sysdiagrams")),
                .. missingColumns.Select(column => new ProductionSchemaAlignmentStep("add-column", column)),
                .. DependentIndexes.GetValueOrDefault(database.Database, [])
                    .Select(index => new ProductionSchemaAlignmentStep("add-index", index)),
                .. database.Database == "QuotationRequest"
                    ? [new ProductionSchemaAlignmentStep("add-check", "CK_Request_QualificationState")]
                    : Array.Empty<ProductionSchemaAlignmentStep>(),
            ];
            string canonical = string.Join('\n', steps.Select(step =>
                $"{step.Kind}|{step.ObjectName}|{step.PreserveSourceRows}"));
            string stepsSha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                $"{database.Database}|{expectedPreimage}|{database.TargetSchemaSha256}\n{canonical}")))
                .ToLowerInvariant();
            results.Add(new(database.Database, expectedPreimage, database.TargetSchemaSha256,
                stepsSha, steps));
        }
        return new(SchemaPlanCanonicalizer.ComputeSha256(schema), schema.SourceCommitSha,
            authority, results);
    }

    private static string[] MissingTableNames(string database)
    {
        string[] tables = database switch
        {
            "Quotation" => ["legacy_compatibility.GoogleAnalyticsOutbox", "public.QuotationAcceptedOutcome"],
            "QuotationRequest" => ["public.RequestQualificationAudit"],
            _ => [],
        };
        return [.. (SysdiagramsDatabases.Contains(database)
            ? tables.Append("public.sysdiagrams") : tables).Order(StringComparer.Ordinal)];
    }

    private static void ValidateReviewedShapes(DatabaseSchemaPlan database, IReadOnlyList<TableCopyPlan> targetTables)
    {
        foreach (string name in MissingColumns.GetValueOrDefault(database.Database) ?? [])
        {
            string tableName = name[..name.LastIndexOf('.')];
            string column = name[(name.LastIndexOf('.') + 1)..];
            TableCopyPlan table = targetTables.SingleOrDefault(item => Qualified(item) == tableName)
                ?? throw Invalid("production_schema_alignment_column_shape_invalid");
            (string type, bool nullable, bool hasDefault) = ReviewedColumns[name];
            if (!table.OrderedColumns.Contains(column, StringComparer.Ordinal) ||
                table.ColumnTypes.GetValueOrDefault(column) != type ||
                table.NullableColumns.Contains(column, StringComparer.Ordinal) != nullable ||
                table.DefaultExpressions.ContainsKey(column) != hasDefault ||
                (hasDefault && table.DefaultExpressions[column] != ReviewedDefaults[name]))
            {
                throw Invalid("production_schema_alignment_column_shape_invalid");
            }
        }
        if (SysdiagramsDatabases.Contains(database.Database))
        {
            TableCopyPlan diagram = targetTables.SingleOrDefault(table => Qualified(table) == "public.sysdiagrams")
                ?? throw Invalid("production_schema_alignment_sysdiagrams_missing");
            if (diagram.SourceSchema != "dbo" || diagram.SourceTable != "sysdiagrams" ||
                diagram.SourceKnownEmpty || diagram.OrderedColumns.Count != 5 ||
                !diagram.OrderedColumns.ToHashSet(StringComparer.Ordinal).SetEquals(
                    ["name", "principal_id", "diagram_id", "version", "definition"]) ||
                diagram.ColumnTypes.GetValueOrDefault("name") != "character varying(128)" ||
                diagram.ColumnTypes.GetValueOrDefault("principal_id") != "integer" ||
                diagram.ColumnTypes.GetValueOrDefault("diagram_id") != "integer" ||
                diagram.ColumnTypes.GetValueOrDefault("version") != "integer" ||
                diagram.ColumnTypes.GetValueOrDefault("definition") != "bytea")
            {
                throw Invalid("production_schema_alignment_sysdiagrams_shape_invalid");
            }
        }
        if (database.Database == "Quotation")
        {
            if (database.SourceDispositionProfile != ApprovedSourceDispositionManifest.QuotationOutboxesV1 ||
                !targetTables.Any(table => Qualified(table) == "legacy_compatibility.GoogleAnalyticsOutbox") ||
                !targetTables.Any(table => Qualified(table) == "public.QuotationAcceptedOutcome"))
            {
                throw Invalid("production_schema_alignment_disposition_invalid");
            }
        }
        if (database.Database == "QuotationRequest")
        {
            TableCopyPlan audit = targetTables.SingleOrDefault(table => Qualified(table) ==
                "public.RequestQualificationAudit") ?? throw Invalid("production_schema_alignment_audit_missing");
            if (audit.SourceSchema != "dbo" || audit.SourceTable != "RequestQualificationAudit" ||
                audit.OrderedColumns.Count != 14)
            {
                throw Invalid("production_schema_alignment_audit_shape_invalid");
            }
        }
    }

    private static TableCopyPlan RemoveReviewedColumns(string database, TableCopyPlan table)
    {
        string prefix = Qualified(table) + ".";
        string[] removed = [.. (MissingColumns.GetValueOrDefault(database) ?? [])
            .Where(name => name.StartsWith(prefix, StringComparison.Ordinal))
            .Select(name => name[prefix.Length..])];
        if (removed.Length == 0) { return table; }
        HashSet<string> names = [.. removed];
        if (!names.All(table.OrderedColumns.Contains) ||
            table.PrimaryKey?.Columns.Any(names.Contains) == true ||
            table.UniqueConstraints.Any(item => item.Columns.Any(names.Contains)) ||
            table.ForeignKeys.Any(item => item.Columns.Any(names.Contains)) ||
            table.Identities.Any(item => names.Contains(item.Column)) ||
            table.GeneratedColumns.Any(item => names.Contains(item.Column)))
        {
            throw Invalid("production_schema_alignment_column_dependency_invalid");
        }
        string[] allowedIndexes = DependentIndexes.GetValueOrDefault(database, []);
        IndexCopyPlan[] affectedIndexes = [.. table.Indexes.Where(item =>
            item.Columns.Any(names.Contains) || item.IncludedColumns.Any(names.Contains))];
        EnsureReviewedDependencies(database, table, names, allowedIndexes, affectedIndexes);
        return table with
        {
            OrderedColumns = [.. table.OrderedColumns.Where(column => !names.Contains(column))],
            ColumnTypes = table.ColumnTypes.Where(item => !names.Contains(item.Key))
                .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal),
            NullableColumns = [.. table.NullableColumns.Where(column => !names.Contains(column))],
            DefaultExpressions = table.DefaultExpressions.Where(item => !names.Contains(item.Key))
                .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal),
            Collations = table.Collations.Where(item => !names.Contains(item.Key))
                .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal),
            Indexes = [.. table.Indexes.Where(item => !affectedIndexes.Contains(item))],
            CheckConstraints = [.. table.CheckConstraints.Where(item => !item.Columns.Any(names.Contains))],
        };
    }

    private static void EnsureReviewedDependencies(string database, TableCopyPlan table, HashSet<string> names,
        string[] allowedIndexes, IndexCopyPlan[] affectedIndexes)
    {
        if (!affectedIndexes.Select(item => item.Name).Order(StringComparer.Ordinal)
            .SequenceEqual(allowedIndexes.Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
            !table.CheckConstraints.Where(item => item.Columns.Any(names.Contains))
                .Select(item => item.Name).Order(StringComparer.Ordinal)
                .SequenceEqual(database == "QuotationRequest" ? ["CK_Request_QualificationState"] : [],
                    StringComparer.Ordinal))
        {
            throw Invalid("production_schema_alignment_column_dependency_invalid");
        }
    }

    private static string Qualified(TableCopyPlan table)
    {
        return $"{table.TargetSchema}.{table.TargetTable}";
    }

    private static MigrationExecutionException Invalid(string code)
    {
        return new(code, "The production schema does not match the reviewed additive preimage.");
    }
}
