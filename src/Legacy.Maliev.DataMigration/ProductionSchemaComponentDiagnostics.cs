namespace Legacy.Maliev.DataMigration;

/// <summary>Classifies observed catalog shapes against a plan without authorizing any change.</summary>
public static class ProductionSchemaComponentDiagnostics
{
    /// <summary>Requires a complete per-table catalog from the same read-only observation.</summary>
    public static IReadOnlyList<ProductionSchemaTableDiagnostic> Compare(
        IReadOnlyList<TableCopyPlan> expectedTables, ProductionSchemaObservation observation)
    {
        ArgumentNullException.ThrowIfNull(expectedTables);
        ArgumentNullException.ThrowIfNull(observation);
        if (observation.TableComponents.Count != observation.Tables.Count ||
            observation.TableComponents.Any(item => !Valid(item)) ||
            observation.Tables.Any(item => string.IsNullOrWhiteSpace(item.Schema) ||
                string.IsNullOrWhiteSpace(item.Table)) ||
            expectedTables.GroupBy(item => (item.TargetSchema, item.TargetTable)).Any(group => group.Count() != 1) ||
            observation.TableComponents.GroupBy(item => (item.Schema, item.Table)).Any(group => group.Count() != 1) ||
            observation.Tables.GroupBy(item => (item.Schema, item.Table)).Any(group => group.Count() != 1) ||
            !observation.TableComponents.Select(item => (item.Schema, item.Table)).ToHashSet()
                .SetEquals(observation.Tables.Select(item => (item.Schema, item.Table))))
        {
            throw new MigrationExecutionException("production_schema_components_incomplete",
                "A complete read-only table component catalog is required for diagnosis.");
        }

        var expected = expectedTables.ToDictionary(item => (item.TargetSchema, item.TargetTable));
        var actual = observation.TableComponents.ToDictionary(item => (item.Schema, item.Table));
        var result = new List<ProductionSchemaTableDiagnostic>();
        foreach (((string schema, string table) key, TableCopyPlan planned) in expected.OrderBy(item => item.Key))
        {
            if (!actual.TryGetValue(key, out ProductionSchemaTableComponents? observed))
            {
                result.Add(new(key.schema, key.table, "missing-table", []));
                continue;
            }
            ProductionSchemaTableComponents wanted = PostgreSqlSchemaFingerprint.ComputeExpectedComponents(planned);
            string[] changed =
            [
                .. wanted.ColumnsSha256 == observed.ColumnsSha256 ? [] : new[] { "columns" },
                .. wanted.ConstraintsSha256 == observed.ConstraintsSha256 ? [] : new[] { "constraints" },
                .. wanted.IndexesSha256 == observed.IndexesSha256 ? [] : new[] { "indexes" },
                .. wanted.ForeignKeysSha256 == observed.ForeignKeysSha256 ? [] : new[] { "foreign-keys" },
                .. wanted.WholeTableSha256 == observed.WholeTableSha256 ? [] : new[] { "whole-table" },
            ];
            result.Add(new(key.schema, key.table, changed.Length == 0 ? "match" : "shape-drift", changed));
        }
        foreach ((string schema, string table) key in actual.Keys.Except(expected.Keys).Order())
        {
            result.Add(new(key.schema, key.table, "target-only-table", []));
        }
        return result;
    }

    private static bool Valid(ProductionSchemaTableComponents item)
    {
        return !string.IsNullOrWhiteSpace(item.Schema) && !string.IsNullOrWhiteSpace(item.Table) &&
            new[] { item.ColumnsSha256, item.ConstraintsSha256, item.IndexesSha256,
                item.ForeignKeysSha256, item.WholeTableSha256 }
                .All(hash => hash.Length == 64 && hash.All(char.IsAsciiHexDigit));
    }
}
