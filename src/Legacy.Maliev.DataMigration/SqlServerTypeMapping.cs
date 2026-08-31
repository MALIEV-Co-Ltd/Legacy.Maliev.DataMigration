using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public static partial class SqlServerTypeMapping
{
    public static string Map(string declaredType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(declaredType);
        string source = declaredType.Trim().ToLowerInvariant();
        Match parameterized = ParameterizedType().Match(source);
        string name = parameterized.Success ? parameterized.Groups[1].Value : source;
        string parameters = parameterized.Success ? parameterized.Groups[2].Value : string.Empty;
        return name switch
        {
            "bigint" => "bigint",
            "int" => "integer",
            "smallint" or "tinyint" => "smallint",
            "bit" => "boolean",
            "decimal" or "numeric" when PrecisionScale().IsMatch(parameters) => $"numeric({parameters})",
            "money" => "numeric(19,4)",
            "smallmoney" => "numeric(10,4)",
            "float" => "double precision",
            "real" => "real",
            "uniqueidentifier" => "uuid",
            "sysname" => "character varying(128)",
            "date" => "date",
            "time" => "time without time zone",
            "datetime" or "smalldatetime" => "timestamp without time zone",
            "datetime2" when Precision(parameters) is >= 0 and <= 6 => "timestamp without time zone",
            "datetime2" when Precision(parameters) == 7 => "text",
            "datetimeoffset" => "text",
            "char" when Length(parameters) is int charLength => $"character({charLength})",
            "nchar" when Length(parameters) is int ncharLength => $"character({ncharLength})",
            "varchar" when parameters == "max" => "text",
            "nvarchar" when parameters == "max" => "text",
            "varchar" when Length(parameters) is int varcharLength => $"character varying({varcharLength})",
            "nvarchar" when Length(parameters) is int nvarcharLength => $"character varying({nvarcharLength})",
            "text" or "ntext" or "xml" => "text",
            "binary" or "varbinary" or "image" or "timestamp" or "rowversion" => "bytea",
            _ => throw new MigrationExecutionException(
                "source_type_mapping_unsupported",
                "The source schema contains a type without an approved lossless PostgreSQL mapping."),
        };
    }

    private static int Precision(string value)
    {
        return int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int precision)
            ? precision
            : -1;
    }

    private static int? Length(string value)
    {
        return int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int length) && length > 0
            ? length
            : null;
    }

    [GeneratedRegex("^([a-z0-9_]+)\\(([^)]+)\\)$", RegexOptions.CultureInvariant)]
    private static partial Regex ParameterizedType();

    [GeneratedRegex("^[1-9][0-9]?,[0-9]+$", RegexOptions.CultureInvariant)]
    private static partial Regex PrecisionScale();
}
