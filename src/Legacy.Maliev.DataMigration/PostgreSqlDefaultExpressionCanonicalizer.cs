using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

internal static partial class PostgreSqlDefaultExpressionCanonicalizer
{
    internal static string Expected(string expression, string type)
    {
        string unwrapped = Unwrap(expression);
        // pg_get_expr adds this exact cast for an untyped literal assigned to a varchar column.
        // Explicit casts (including length-limiting casts) and other expressions remain significant.
        return (type == "character varying" || type.StartsWith("character varying(", StringComparison.Ordinal)) &&
            StringLiteral().IsMatch(unwrapped)
            ? unwrapped + "::character varying"
            : expression;
    }

    internal static string Canonicalize(string expression)
    {
        string unwrapped = Unwrap(expression);
        // Keep quoted defaults verbatim, including explicit casts and escaped literals. Being
        // conservative about surrounding whitespace is preferable to accepting a changed value.
        return unwrapped.Contains('\'', StringComparison.Ordinal)
            ? unwrapped
            : SchemaExpressionCanonicalizer.Canonicalize(expression);
    }

    private static string Unwrap(string expression)
    {
        string result = expression.Trim();
        while (SchemaExpressionCanonicalizer.HasSingleEnclosingParenthesisPair(result))
        {
            result = result[1..^1].Trim();
        }
        return result;
    }

    [GeneratedRegex("^'(?:[^']|'')*'$", RegexOptions.CultureInvariant)]
    private static partial Regex StringLiteral();
}
