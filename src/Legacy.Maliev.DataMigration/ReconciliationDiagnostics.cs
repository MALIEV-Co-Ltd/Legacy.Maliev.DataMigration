using System.Globalization;

namespace Legacy.Maliev.DataMigration;

// Exception-only diagnostics: deliberately excluded from historical signed receipt payloads.
public sealed record ReconciliationDiagnostic(
    string Database,
    string? Table,
    string Check,
    string? Expected,
    string? Observed)
{
    public string? Field { get; init; }
}

internal static class ReconciliationDiagnostics
{
    internal static void CompareSchema(string database, string expected, string observed)
    {
        CompareHash(database, null, "schema", expected, observed);
    }

    internal static void CompareTable(string database, TableReconciliationEvidence expected, TableReconciliationEvidence observed)
    {
        if (expected.RowCount != observed.RowCount)
        {
            throw Failure(new(database, expected.Table, "row-count", Count(expected.RowCount), Count(observed.RowCount)));
        }

        CompareHash(database, expected.Table, "ordered-content", expected.ContentSha256, observed.ContentSha256);
        CompareHash(database, expected.Table, "aggregate", expected.AggregateSha256, observed.AggregateSha256);
        CompareCounts(database, expected.Table, "null-count", expected.NullCounts, observed.NullCounts);
        CompareCounts(database, expected.Table, "orphan", expected.ForeignKeyOrphanCounts, observed.ForeignKeyOrphanCounts);
        CompareCounts(database, expected.Table, "relationship", expected.ForeignKeyRelationshipCounts, observed.ForeignKeyRelationshipCounts);
    }

    internal static void CompareSequences(DatabaseSchemaPlan plan, IReadOnlyDictionary<string, long> expected, IReadOnlyDictionary<string, long> observed)
    {
        CompareCounts(plan.Database, null, "sequence", expected, observed, field =>
            plan.Tables.FirstOrDefault(table => table.Identities.Any(identity =>
                string.Equals($"{table.TargetSchema}.{table.TargetTable}.{identity.Column}", field, StringComparison.Ordinal))) is { } table
                ? $"{table.TargetSchema}.{table.TargetTable}"
                : null);
    }

    private static void CompareHash(string database, string? table, string check, string expected, string observed)
    {
        if (!string.Equals(expected, observed, StringComparison.OrdinalIgnoreCase))
        {
            throw Failure(new(database, table, check, expected, observed));
        }
    }

    private static void CompareCounts(
        string database,
        string? table,
        string check,
        IReadOnlyDictionary<string, long> expected,
        IReadOnlyDictionary<string, long> observed,
        Func<string, string?>? resolveTable = null)
    {
        // Match the previous ordinal key comparison even for dictionaries with different comparers.
        var expectedOrdinal = new Dictionary<string, long>(expected, StringComparer.Ordinal);
        var observedOrdinal = new Dictionary<string, long>(observed, StringComparer.Ordinal);
        foreach (string field in expectedOrdinal.Keys.Union(observedOrdinal.Keys, StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            bool hasExpected = expectedOrdinal.TryGetValue(field, out long expectedValue);
            bool hasObserved = observedOrdinal.TryGetValue(field, out long observedValue);
            if (hasExpected != hasObserved || expectedValue != observedValue)
            {
                throw Failure(new(database, resolveTable?.Invoke(field) ?? table, check,
                    hasExpected ? Count(expectedValue) : null, hasObserved ? Count(observedValue) : null)
                {
                    Field = field,
                });
            }
        }
    }

    private static string Count(long value)
    {
        return value.ToString(CultureInfo.InvariantCulture);
    }

    private static MigrationExecutionException Failure(ReconciliationDiagnostic diagnostic)
    {
        return new("shadow_reconciliation_failed", $"{diagnostic.Database} failed {diagnostic.Check} reconciliation.")
        {
            Reconciliation = diagnostic,
        };
    }
}
