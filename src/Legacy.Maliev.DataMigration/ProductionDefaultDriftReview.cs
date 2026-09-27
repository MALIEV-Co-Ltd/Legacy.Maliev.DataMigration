using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration;

/// <summary>A fixed-kind expression facet without the source or target SQL expression.</summary>
public sealed record ProductionExpressionDriftColumnReview(
    string Column, string Kind, bool OtherColumnShapeDriftPresent);

/// <summary>One observed table preimage and its expected final shape; no executable DDL is present.</summary>
public sealed record ProductionDefaultDriftTableReview(
    string Schema, string Table, string ObservedWholeTableSha256, string ExpectedFinalWholeTableSha256,
    ImmutableArray<string> Columns, bool OtherShapeDriftPresent)
{
    /// <summary>Default and generated facets; Columns remains the default-only compatibility view.</summary>
    public ImmutableArray<ProductionExpressionDriftColumnReview> Expressions { get; init; } = [];
}

/// <summary>One database's immutable review evidence, including its complete observed preimage.</summary>
public sealed record ProductionDefaultDriftDatabaseReview(
    string Database, string ObservedSchemaSha256, string ExpectedFinalSchemaSha256,
    ImmutableArray<ProductionDefaultDriftTableReview> Tables);

/// <summary>PII-free, non-executable review document bound to one source plan and target identity.</summary>
public sealed record ProductionDefaultDriftReview(
    string SchemaPlanSha256, string SourceCommitSha, DeltaTargetAuthority TargetAuthority,
    ImmutableArray<ProductionDefaultDriftDatabaseReview> Databases, string ReviewSha256);

/// <summary>Records present-but-different default and generated facets; never derives or executes repair SQL.</summary>
public static class ProductionDefaultDriftReviewPlanner
{
    /// <summary>Requires a fresh exact-23 source plan and complete read-only production catalog.</summary>
    public static ProductionDefaultDriftReview Plan(FreshSchemaPlan schema, DeltaTargetAuthority authority,
        IReadOnlyList<ProductionSchemaObservation> observations, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(observations);
        ProductionSchemaCatalogInspector.ValidatePlan(schema, nowUtc);
        if (authority.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(authority, "maliev-legacy", "legacy-postgres-main") ||
            !observations.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases,
                StringComparer.Ordinal))
        {
            throw Invalid();
        }

        ImmutableArray<ProductionDefaultDriftDatabaseReview> databases =
        [.. schema.Databases.Zip(observations, PlanDatabase)];
        string schemaHash = SchemaPlanCanonicalizer.ComputeSha256(schema);
        string reviewHash = ComputeReviewHash(schemaHash, schema.SourceCommitSha, authority, databases);
        return new(schemaHash, schema.SourceCommitSha, authority, databases, reviewHash);
    }

    internal static ProductionDefaultDriftDatabaseReview PlanDatabase(DatabaseSchemaPlan database,
        ProductionSchemaObservation observed)
    {
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(observed);
        if (database.Database != observed.Database || !ValidHash(observed.SchemaSha256) ||
            database.TargetSchemaSha256 != PostgreSqlSchemaFingerprint.ComputeExpected(database))
        {
            throw Invalid();
        }
        TableCopyPlan[] expectedTables =
        [
            .. ApprovedSourceDispositionManifest.TargetTablesFor(database),
            .. ApprovedTargetExtensionManifest.TablesFor(database),
        ];
        IReadOnlyList<ProductionSchemaTableDiagnostic> recomputed =
            ProductionSchemaComponentDiagnostics.Compare(expectedTables, observed);
        if (recomputed.Count != observed.TableDiagnostics.Count ||
            recomputed.Zip(observed.TableDiagnostics).Any(pair =>
                pair.First.Schema != pair.Second.Schema || pair.First.Table != pair.Second.Table ||
                pair.First.Status != pair.Second.Status ||
                !pair.First.ChangedComponents.SequenceEqual(pair.Second.ChangedComponents, StringComparer.Ordinal)))
        {
            throw Invalid();
        }

        var actualTables = observed.Tables.ToDictionary(item => (item.Schema, item.Table));
        var expected = expectedTables.ToDictionary(item => (item.TargetSchema, item.TargetTable));
        var allowedColumns = new HashSet<(string Schema, string Table, string Column)>();
        foreach (ObservedTargetTable table in observed.Tables)
        {
            foreach (string column in table.Columns)
            {
                _ = allowedColumns.Add((table.Schema, table.Table, column));
            }
            if (expected.TryGetValue((table.Schema, table.Table), out TableCopyPlan? plan))
            {
                foreach (string column in plan.OrderedColumns)
                {
                    _ = allowedColumns.Add((table.Schema, table.Table, column));
                }
            }
        }
        if (observed.ColumnDiagnostics.Count != allowedColumns.Count ||
            !observed.ColumnDiagnostics.Select(item => (item.Schema, item.Table, item.Column))
                .ToHashSet().SetEquals(allowedColumns))
        {
            throw Invalid();
        }

        var reviews = new List<ProductionDefaultDriftTableReview>();
        foreach (TableCopyPlan table in expectedTables.OrderBy(item => item.TargetSchema, StringComparer.Ordinal)
            .ThenBy(item => item.TargetTable, StringComparer.Ordinal))
        {
            var key = (table.TargetSchema, table.TargetTable);
            if (!actualTables.TryGetValue(key, out ObservedTargetTable? actual)) { continue; }
            ProductionSchemaColumnDiagnostic[] defaults = [.. observed.ColumnDiagnostics.Where(item =>
                item.Schema == key.TargetSchema && item.Table == key.TargetTable &&
                item.Status == "shape-drift" && item.ChangedComponents.Contains("default",
                    StringComparer.Ordinal) && item.DefaultState == "present-different")];
            ProductionSchemaColumnDiagnostic[] generated = [.. observed.ColumnDiagnostics.Where(item =>
                item.Schema == key.TargetSchema && item.Table == key.TargetTable &&
                item.Status == "shape-drift" && item.ChangedComponents.Contains("generated",
                    StringComparer.Ordinal) && item.GeneratedState == "present-different")];
            if (defaults.Length == 0 && generated.Length == 0) { continue; }
            if (defaults.Any(item => !actual.Columns.Contains(item.Column, StringComparer.Ordinal) ||
                !table.DefaultExpressions.TryGetValue(item.Column, out string? expression) ||
                string.IsNullOrWhiteSpace(expression)) ||
                generated.Any(item => !actual.Columns.Contains(item.Column, StringComparer.Ordinal) ||
                    !table.GeneratedColumns.Any(column => column.Column == item.Column &&
                        !string.IsNullOrWhiteSpace(column.Expression))))
            {
                throw Invalid();
            }
            ProductionSchemaTableDiagnostic tableDiagnostic = recomputed.Single(item =>
                item.Schema == key.TargetSchema && item.Table == key.TargetTable);
            if (tableDiagnostic.Status != "shape-drift" ||
                !tableDiagnostic.ChangedComponents.Contains("columns", StringComparer.Ordinal))
            {
                throw Invalid();
            }
            ProductionSchemaTableComponents component = observed.TableComponents.Single(item =>
                item.Schema == key.TargetSchema && item.Table == key.TargetTable);
            ProductionExpressionDriftColumnReview[] expressions =
            [
                .. defaults.Select(item => new ProductionExpressionDriftColumnReview(item.Column, "default",
                    item.ChangedComponents.Any(component => component != "default"))),
                .. generated.Select(item => new ProductionExpressionDriftColumnReview(item.Column, "generated",
                    item.ChangedComponents.Any(component => component != "generated"))),
            ];
            expressions = [.. expressions.OrderBy(item => item.Column, StringComparer.Ordinal)
                .ThenBy(item => item.Kind, StringComparer.Ordinal)];
            bool otherDrift = tableDiagnostic.ChangedComponents.Any(item =>
                    item is not ("columns" or "whole-table")) ||
                observed.ColumnDiagnostics.Any(item => item.Schema == key.TargetSchema &&
                    item.Table == key.TargetTable && item.Status != "match" &&
                    !defaults.Contains(item) && !generated.Contains(item)) ||
                expressions.Any(item => item.OtherColumnShapeDriftPresent);
            reviews.Add(new(key.TargetSchema, key.TargetTable, component.WholeTableSha256,
                PostgreSqlSchemaFingerprint.ComputeExpectedComponents(table).WholeTableSha256,
                [.. defaults.Select(item => item.Column).Order(StringComparer.Ordinal)], otherDrift)
            {
                Expressions = [.. expressions],
            });
        }
        return new(database.Database, observed.SchemaSha256, database.TargetSchemaSha256, [.. reviews]);
    }

    private static string ComputeReviewHash(string schemaHash, string sourceCommit, DeltaTargetAuthority authority,
        ImmutableArray<ProductionDefaultDriftDatabaseReview> databases)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            Write(writer, schemaHash); Write(writer, sourceCommit); Write(writer, authority.Kind);
            Write(writer, authority.AuthorityId); Write(writer, authority.SystemIdentifierSha256);
            writer.Write(databases.Length);
            foreach (ProductionDefaultDriftDatabaseReview database in databases)
            {
                Write(writer, database.Database); Write(writer, database.ObservedSchemaSha256);
                Write(writer, database.ExpectedFinalSchemaSha256);
                writer.Write(database.Tables.Length);
                foreach (ProductionDefaultDriftTableReview table in database.Tables)
                {
                    Write(writer, table.Schema); Write(writer, table.Table);
                    Write(writer, table.ObservedWholeTableSha256); Write(writer, table.ExpectedFinalWholeTableSha256);
                    writer.Write(table.OtherShapeDriftPresent);
                    writer.Write(table.Columns.Length);
                    foreach (string column in table.Columns) { Write(writer, column); }
                    writer.Write(table.Expressions.Length);
                    foreach (ProductionExpressionDriftColumnReview expression in table.Expressions)
                    {
                        Write(writer, expression.Column); Write(writer, expression.Kind);
                        writer.Write(expression.OtherColumnShapeDriftPresent);
                    }
                }
            }
        }
        return Convert.ToHexString(SHA256.HashData(stream.ToArray())).ToLowerInvariant();
    }

    private static void Write(BinaryWriter writer, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value.Normalize(NormalizationForm.FormC));
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }

    private static bool ValidHash(string? value)
    {
        return value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
    }

    private static MigrationExecutionException Invalid()
    {
        return new("production_default_drift_review_invalid",
            "The default-drift catalog does not match the fresh source plan and complete target preimage.");
    }
}
