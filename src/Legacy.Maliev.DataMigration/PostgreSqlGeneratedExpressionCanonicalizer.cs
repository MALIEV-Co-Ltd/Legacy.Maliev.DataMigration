namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Recognizes only the reviewed SQL Server precision casts that are redundant for the
/// corresponding PostgreSQL numeric input types. Unknown expressions remain distinct.
/// </summary>
internal static class PostgreSqlGeneratedExpressionCanonicalizer
{
    private static readonly (string Source, string Catalog)[] Known =
    [
        Pair(
            "(((\"UnitPrice\" * (\"Quantity\")::numeric))::numeric(29,2))::numeric(18,2)",
            "((\"UnitPrice\" * (\"Quantity\")::numeric))::numeric(18,2)"),
        Pair(
            "(((\"Total\" - \"WithholdingTax\"))::numeric(19,2))::numeric(18,2)",
            "((\"Total\" - \"WithholdingTax\"))::numeric(18,2)"),
        Pair(
            "(((((\"UnitPrice\" * (\"Quantity\")::numeric))::numeric(29,2) - ((((((\"UnitPrice\" * (\"Quantity\")::numeric))::numeric(29,2) * \"DiscountPercent\"))::numeric(35,4) / (100)::numeric))::numeric(38,7)))::numeric(38,6))::numeric(18,2)",
            "(((\"UnitPrice\" * (\"Quantity\")::numeric) - (((\"UnitPrice\" * (\"Quantity\")::numeric) * \"DiscountPercent\") / (100)::numeric)))::numeric(18,2)"),
    ];

    internal static string Canonicalize(string expression)
    {
        string normalized = SchemaExpressionCanonicalizer.Canonicalize(expression);
        foreach ((string source, string catalog) in Known)
        {
            if (normalized == source || normalized == catalog)
            {
                return source;
            }
        }

        return normalized;
    }

    private static (string Source, string Catalog) Pair(string source, string catalog)
    {
        return (SchemaExpressionCanonicalizer.Canonicalize(source),
            SchemaExpressionCanonicalizer.Canonicalize(catalog));
    }
}
