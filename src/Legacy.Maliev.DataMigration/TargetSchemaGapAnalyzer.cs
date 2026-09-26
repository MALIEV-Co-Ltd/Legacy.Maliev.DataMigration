namespace Legacy.Maliev.DataMigration;

/// <summary>PII-free structural differences used to review additive target schema repairs.</summary>
public sealed record TargetSchemaGap(
    string Database,
    IReadOnlyList<string> MissingTables,
    IReadOnlyList<string> MissingColumns,
    IReadOnlyList<string> TargetOnlyTables,
    IReadOnlyList<string> TargetOnlyColumns)
{
    /// <summary>Approved PostgreSQL-only tables present in the target.</summary>
    public IReadOnlyList<string> ApprovedTargetExtensions { get; init; } = [];

    /// <summary>Approved PostgreSQL-only tables absent from the target.</summary>
    public IReadOnlyList<string> MissingApprovedTargetExtensions { get; init; } = [];

    /// <summary>Retained source-shaped tables superseded by reviewed target dispositions; diagnostic only.</summary>
    public IReadOnlyList<string> RetainedSourceTransitionTables { get; init; } = [];

    /// <summary>Whether observed names differ from the reviewed target inventory.</summary>
    public bool HasDifferences => MissingTables.Count != 0 || MissingColumns.Count != 0 ||
        TargetOnlyTables.Count != 0 || TargetOnlyColumns.Count != 0 ||
        MissingApprovedTargetExtensions.Count != 0;
}

/// <summary>Read-only table and column names observed in one PostgreSQL database.</summary>
public sealed record ObservedTargetTable(string Schema, string Table, IReadOnlyList<string> Columns);

/// <summary>
/// Compares names only. A clean result is not a schema fingerprint or permission to apply a delta:
/// types, constraints, indexes, defaults, and sequences still require the guarded inspector.
/// </summary>
public static class TargetSchemaGapAnalyzer
{
    /// <summary>Finds missing and target-only objects without discarding target-owned tables.</summary>
    public static TargetSchemaGap Analyze(DatabaseSchemaPlan desired, IReadOnlyList<ObservedTargetTable> observed)
    {
        ArgumentNullException.ThrowIfNull(desired);
        ArgumentNullException.ThrowIfNull(observed);

        IReadOnlyList<TableCopyPlan> targetTables = ApprovedSourceDispositionManifest.TargetTablesFor(desired);
        Dictionary<string, TableCopyPlan> planned = targetTables.ToDictionary(
            table => Qualified(table.TargetSchema, table.TargetTable), StringComparer.Ordinal);
        Dictionary<string, ObservedTargetTable> actual = observed.ToDictionary(
            table => Qualified(table.Schema, table.Table), StringComparer.Ordinal);
        HashSet<string> approved = [.. ApprovedTargetExtensionManifest.TablesFor(desired)
            .Select(table => Qualified(table.TargetSchema, table.TargetTable))];
        if (planned.Count == 0 || targetTables.Any(table => table.OrderedColumns.Count == 0) ||
            observed.Any(table => table.Columns.Distinct(StringComparer.Ordinal).Count() != table.Columns.Count))
        {
            throw new ArgumentException("Target schema inventory is incomplete or ambiguous.", nameof(observed));
        }

        string[] missingTables = [.. planned.Keys.Except(actual.Keys, StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];
        string[] targetOnlyTables = [.. actual.Keys.Except(planned.Keys, StringComparer.Ordinal)
            .Except(approved, StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];
        string[] retainedSourceTransitionTables = desired.SourceDispositionProfile is null ? [] :
            [.. desired.Tables.Select(table => Qualified(table.TargetSchema, table.TargetTable))
                .Except(planned.Keys, StringComparer.Ordinal)
                .Intersect(targetOnlyTables, StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)];
        string[] approvedPresent = [.. approved.Intersect(actual.Keys, StringComparer.Ordinal).Order(StringComparer.Ordinal)];
        string[] approvedMissing = [.. approved.Except(actual.Keys, StringComparer.Ordinal).Order(StringComparer.Ordinal)];
        var missingColumns = new List<string>();
        var targetOnlyColumns = new List<string>();
        foreach ((string tableName, TableCopyPlan table) in planned.OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            if (!actual.TryGetValue(tableName, out ObservedTargetTable? target))
            {
                continue;
            }

            missingColumns.AddRange(table.OrderedColumns.Except(target.Columns, StringComparer.Ordinal)
                .Select(column => $"{tableName}.{column}"));
            targetOnlyColumns.AddRange(target.Columns.Except(table.OrderedColumns, StringComparer.Ordinal)
                .Select(column => $"{tableName}.{column}"));
        }

        return new(desired.Database, missingTables, [.. missingColumns.Order(StringComparer.Ordinal)],
            targetOnlyTables, [.. targetOnlyColumns.Order(StringComparer.Ordinal)])
        {
            ApprovedTargetExtensions = approvedPresent,
            MissingApprovedTargetExtensions = approvedMissing,
            RetainedSourceTransitionTables = retainedSourceTransitionTables,
        };
    }

    private static string Qualified(string schema, string table)
    {
        return string.IsNullOrWhiteSpace(schema) || string.IsNullOrWhiteSpace(table) ||
            schema.Contains('.', StringComparison.Ordinal) || table.Contains('.', StringComparison.Ordinal)
            ? throw new ArgumentException("Schema and table names must be unambiguous.")
            : $"{schema}.{table}";
    }
}
