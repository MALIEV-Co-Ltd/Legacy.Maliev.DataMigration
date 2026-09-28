namespace Legacy.Maliev.DataMigration;

/// <summary>Names structural column differences without publishing stored SQL expressions.</summary>
internal static class ProductionSchemaColumnDiagnostics
{
    internal static IReadOnlyList<ProductionSchemaColumnDiagnostic> Compare(
        IReadOnlyList<TableCopyPlan> expectedTables, ProductionSchemaObservation observation,
        IReadOnlyList<PostgreSqlSchemaFingerprint.ColumnShape> actualColumns,
        IReadOnlyList<ProductionCollationMetadata> collations)
    {
        ArgumentNullException.ThrowIfNull(expectedTables);
        ArgumentNullException.ThrowIfNull(observation);
        ArgumentNullException.ThrowIfNull(actualColumns);
        ArgumentNullException.ThrowIfNull(collations);
        var expected = expectedTables.ToDictionary(table => (table.TargetSchema, table.TargetTable));
        var actual = actualColumns.GroupBy(column => (column.Schema, column.Table))
            .ToDictionary(group => group.Key, group => group.ToArray());
        if (expected.Count != expectedTables.Count ||
            collations.GroupBy(item => (item.Schema, item.Table, item.Column)).Any(group => group.Count() != 1) ||
            !collations.Select(item => (item.Schema, item.Table, item.Column)).ToHashSet()
                .SetEquals(actualColumns.Where(item => item.Collation.Length != 0)
                    .Select(item => (item.Schema, item.Table, item.Column))) ||
            collations.Any(item => item.Encoding != -1 && item.Encoding != item.DatabaseEncoding) ||
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
        if (collations.Any(item => item.Provider is not ("b" or "c" or "i" or "d")))
        {
            throw new MigrationExecutionException("production_schema_collation_metadata_unreviewed",
                "The observed collation provider is not approved for diagnostic output.");
        }

        var collationByColumn = collations.ToDictionary(item => (item.Schema, item.Table, item.Column));

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
                    .. PostgreSqlGeneratedExpressionCanonicalizer.Canonicalize(wanted.GeneratedExpression) ==
                        PostgreSqlGeneratedExpressionCanonicalizer.Canonicalize(column.GeneratedExpression)
                        ? [] : new[] { "generated" },
                    .. wanted.Collation == column.Collation ? [] : new[] { "collation" },
                ];
                result.Add(new(table.Schema, table.Table, name,
                    changed.Length == 0 ? "match" : "shape-drift", changed)
                {
                    ActualTypeCategory = TypeCategory(column.Type),
                    ActualCollationMode = column.Collation.Length == 0 ? "inherited" : "explicit",
                    ActualCollationIdentity = CollationIdentity(column.Collation),
                    ActualCollationProvider = column.Collation.Length == 0 ? "inherited" :
                        CollationProvider(collationByColumn[(column.Schema, column.Table, column.Column)].Provider),
                    ActualCollationDeterminism = column.Collation.Length == 0 ? "inherited" :
                        collationByColumn[(column.Schema, column.Table, column.Column)].Deterministic
                            ? "deterministic" : "nondeterministic",
                    ActualCollationVersionState = column.Collation.Length == 0 ? "inherited" :
                        CollationVersionState(collationByColumn[(column.Schema, column.Table, column.Column)]),
                    ActualCollationCatalogScope = column.Collation.Length == 0 ? "inherited" :
                        collationByColumn[(column.Schema, column.Table, column.Column)].CatalogSchema == "pg_catalog"
                            ? "pg-catalog" : "non-pg-catalog",
                    DefaultState = ExpressionState(wanted.DefaultExpression, column.DefaultExpression,
                        PostgreSqlDefaultExpressionCanonicalizer.Canonicalize),
                    GeneratedState = ExpressionState(wanted.GeneratedExpression, column.GeneratedExpression,
                        PostgreSqlGeneratedExpressionCanonicalizer.Canonicalize),
                });
            }
            result.AddRange(columns.Where(column => !planned.OrderedColumns.Contains(column.Column,
                StringComparer.Ordinal)).Select(column => new ProductionSchemaColumnDiagnostic(
                column.Schema, column.Table, column.Column, "target-only-column", [])));
        }
        return result;
    }

    private static string CollationProvider(string provider)
    {
        return provider switch
        {
            "b" => "builtin",
            "c" => "libc",
            "i" => "icu",
            "d" => "database-default",
            _ => throw new MigrationExecutionException("production_schema_collation_metadata_unreviewed",
                "The observed collation provider is not approved for diagnostic output."),
        };
    }

    private static string CollationVersionState(ProductionCollationMetadata metadata)
    {
        return (metadata.RecordedVersion, metadata.ActualVersion) switch
        {
            (null, null) => "unversioned",
            (null, _) or (_, null) => "unverifiable",
            var (recorded, actual) when recorded == actual => "current",
            _ => "mismatch",
        };
    }

    private static string TypeCategory(string type)
    {
        string approved = PostgreSqlTypePolicy.Validate(type);
        return approved switch
        {
            string value when value.StartsWith("numeric(", StringComparison.Ordinal) => "numeric",
            string value when value.StartsWith("character varying(", StringComparison.Ordinal) =>
                "character-varying",
            string value when value.StartsWith("character(", StringComparison.Ordinal) => "character",
            "double precision" => "double-precision",
            "timestamp with time zone" => "timestamp-with-time-zone",
            "timestamp without time zone" => "timestamp-without-time-zone",
            "smallint" or "integer" or "bigint" or "boolean" or "text" or "bytea" or "uuid" or
                "date" or "real" or "jsonb" => approved,
            _ => throw new MigrationExecutionException("production_schema_type_category_unreviewed",
                "The observed type has no approved diagnostic category."),
        };
    }

    private static string CollationIdentity(string collation)
    {
        return collation switch
        {
            "" => "inherited",
            "C" => "C",
            "POSIX" => "POSIX",
            "C.utf8" => "C.utf8",
            "ucs_basic" => "ucs_basic",
            "pg_unicode_fast" => "pg_unicode_fast",
            _ => "explicit-unreviewed",
        };
    }

    private static string ExpressionState(string expected, string actual, Func<string, string> canonicalize)
    {
        return (expected.Length == 0, actual.Length == 0) switch
        {
            (true, true) => "absent-both",
            (false, true) => "observed-absent",
            (true, false) => "unexpected-present",
            _ => canonicalize(expected) == canonicalize(actual) ? "match" : "present-different",
        };
    }
}
