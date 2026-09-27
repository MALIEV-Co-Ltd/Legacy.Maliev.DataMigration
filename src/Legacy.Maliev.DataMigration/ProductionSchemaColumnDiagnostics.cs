namespace Legacy.Maliev.DataMigration;

/// <summary>Names structural column differences without publishing stored SQL expressions.</summary>
internal static class ProductionSchemaColumnDiagnostics
{
    internal static IReadOnlyList<ProductionSchemaColumnDiagnostic> Compare(
        IReadOnlyList<TableCopyPlan> expectedTables, ProductionSchemaObservation observation,
        IReadOnlyList<PostgreSqlSchemaFingerprint.ColumnShape> actualColumns)
    {
        ArgumentNullException.ThrowIfNull(expectedTables);
        ArgumentNullException.ThrowIfNull(observation);
        ArgumentNullException.ThrowIfNull(actualColumns);
        var expected = expectedTables.ToDictionary(table => (table.TargetSchema, table.TargetTable));
        var actual = actualColumns.GroupBy(column => (column.Schema, column.Table))
            .ToDictionary(group => group.Key, group => group.ToArray());
        if (expected.Count != expectedTables.Count ||
            observation.Tables.GroupBy(table => (table.Schema, table.Table)).Any(group => group.Count() != 1) ||
            actualColumns.Any(column => string.IsNullOrWhiteSpace(column.Schema) ||
                string.IsNullOrWhiteSpace(column.Table) || string.IsNullOrWhiteSpace(column.Column)) ||
            actualColumns.GroupBy(column => (column.Schema, column.Table, column.Column))
                .Any(group => group.Count() != 1) ||
            observation.Tables.Any(table => !actual.GetValueOrDefault((table.Schema, table.Table), [])
                .Select(column => column.Column).ToHashSet(StringComparer.Ordinal)
                .SetEquals(table.Columns)) ||
            !actual.Keys.ToHashSet().SetEquals(observation.Tables
                .Where(table => table.Columns.Count != 0).Select(table => (table.Schema, table.Table))))
        {
            throw new MigrationExecutionException("production_schema_columns_incomplete",
                "A complete read-only column catalog is required for diagnosis.");
        }

        var result = new List<ProductionSchemaColumnDiagnostic>();
        foreach (ObservedTargetTable table in observation.Tables.OrderBy(item => item.Schema, StringComparer.Ordinal)
            .ThenBy(item => item.Table, StringComparer.Ordinal))
        {
            PostgreSqlSchemaFingerprint.ColumnShape[] columns =
                actual.GetValueOrDefault((table.Schema, table.Table), []);
            if (!expected.TryGetValue((table.Schema, table.Table), out TableCopyPlan? planned))
            {
                result.AddRange(columns.Select(column => new ProductionSchemaColumnDiagnostic(
                    column.Schema, column.Table, column.Column, "target-only-column", [])));
                continue;
            }
            var observed = columns.ToDictionary(column => column.Column, StringComparer.Ordinal);
            foreach (string name in planned.OrderedColumns.Order(StringComparer.Ordinal))
            {
                if (!observed.TryGetValue(name, out PostgreSqlSchemaFingerprint.ColumnShape? column))
                {
                    result.Add(new(table.Schema, table.Table, name, "missing-column", []));
                    continue;
                }
                PostgreSqlSchemaFingerprint.ColumnShape wanted = PostgreSqlSchemaFingerprint.ExpectedColumn(
                    planned, name, 0);
                string[] changed =
                [
                    .. wanted.Type == column.Type ? [] : new[] { "type" },
                    .. wanted.Nullable == column.Nullable ? [] : new[] { "nullability" },
                    .. wanted.Identity == column.Identity ? [] : new[] { "identity" },
                    .. PostgreSqlDefaultExpressionCanonicalizer.Canonicalize(wanted.DefaultExpression) ==
                        PostgreSqlDefaultExpressionCanonicalizer.Canonicalize(column.DefaultExpression)
                        ? [] : new[] { "default" },
                    .. SchemaExpressionCanonicalizer.Canonicalize(wanted.GeneratedExpression) ==
                        SchemaExpressionCanonicalizer.Canonicalize(column.GeneratedExpression)
                        ? [] : new[] { "generated" },
                    .. wanted.Collation == column.Collation ? [] : new[] { "collation" },
                ];
                result.Add(new(table.Schema, table.Table, name,
                    changed.Length == 0 ? "match" : "shape-drift", changed));
            }
            result.AddRange(columns.Where(column => !planned.OrderedColumns.Contains(column.Column,
                StringComparer.Ordinal)).Select(column => new ProductionSchemaColumnDiagnostic(
                column.Schema, column.Table, column.Column, "target-only-column", [])));
        }
        return result;
    }
}
