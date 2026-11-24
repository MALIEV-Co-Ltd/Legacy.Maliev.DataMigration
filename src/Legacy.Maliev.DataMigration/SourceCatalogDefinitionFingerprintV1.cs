using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Counter-neutral complete source definition for new proof families only; never source execution authority.</summary>
internal static class SourceCatalogDefinitionFingerprintV1
{
    internal static string Compute(FreshSchemaPlan source, string expectedAcceptedCommitSha, string sourceIdentitySha256, DateTimeOffset actualInvocationUtc)
    {
        if (sourceIdentitySha256 is not { Length: 64 } || !sourceIdentitySha256.All(char.IsAsciiHexDigitLower) ||
            SchemaPlanCanonicalizer.Validate(source, new(expectedAcceptedCommitSha, new string('0', 64)), actualInvocationUtc, TimeSpan.FromHours(2)).Count != 0 ||
            source.Databases.Count != 23 || source.Databases.Sum(database => database.Tables.Count) != 100)
        { throw Invalid(); }
        ProductionSchemaCatalogInspector.ValidatePlan(source, actualInvocationUtc);
        var definition = new
        {
            Kind = "source-catalog-definition-v1",
            source.SchemaVersion,
            source.SourceCommitSha,
            SourceIdentitySha256 = sourceIdentitySha256,
            Databases = source.Databases.Select(database => new
            {
                database.Database,
                database.TargetSchemaVersion,
                database.SourceSchemaSha256,
                database.TargetSchemaSha256,
                database.TargetExtensionProfile,
                database.SourceDispositionProfile,
                database.SourceTableDispositions,
                Tables = database.Tables.Select(ProjectTable).ToArray(),
            }).ToArray(),
        };
        return Convert.ToHexStringLower(SHA256.HashData([.. "Legacy.Maliev.SourceCatalog.Definition.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(definition)]));
    }

    // Excludes only the outer capture clock and identity CurrentValue/IsCalled.
    // SourceKnownEmpty and observed LOB lengths remain bound: they influence eligibility/sizing.
    // The complete unchanged source plan and all clocks/counters remain separately bound evidence.
    // Source metadata hashes already neutralize SQL identity last_value in the source provider.
    internal static object ProjectTable(TableCopyPlan table)
    {
        return new
        {
            table.SourceSchema,
            table.SourceTable,
            table.TargetSchema,
            table.TargetTable,
            table.OrderedColumns,
            table.OrderByColumns,
            table.BatchSize,
            table.SourceKnownEmpty,
            table.ColumnTypes,
            table.SourceColumnTypes,
            SourceColumns = table.SourceColumns.Select(column => new { column.Column, column.DeclaredType, column.MetadataSha256, column.MaxObservedDataLength }).ToArray(),
            table.IdentityColumns,
            SqlIdentityDefinitions = table.Identities.Select(identity => Identity(table, identity)).ToArray(),
            table.NullableColumns,
            table.ForeignKeys,
            table.PrimaryKey,
            table.UniqueConstraints,
            table.Indexes,
            table.DefaultExpressions,
            table.CheckConstraints,
            table.GeneratedColumns,
            table.Collations,
        };
    }

    private static object Identity(TableCopyPlan table, IdentityCopyPlan identity)
    {
        if (!table.SourceColumnTypes.TryGetValue(identity.Column, out string? declared)) { throw Invalid(); }
        (BigInteger Minimum, BigInteger Maximum) = declared switch
        {
            "tinyint" => (BigInteger.Zero, new BigInteger(byte.MaxValue)),
            "smallint" => (new BigInteger(short.MinValue), new BigInteger(short.MaxValue)),
            "int" => (new BigInteger(int.MinValue), new BigInteger(int.MaxValue)),
            "bigint" => (new BigInteger(long.MinValue), new BigInteger(long.MaxValue)),
            _ => DecimalBounds(declared),
        };
        if (identity.IncrementValue == 0 || identity.SeedValue < Minimum || identity.SeedValue > Maximum) { throw Invalid(); }
        // SQL IDENTITY bounds/no-cycle derive from the declared type. Native PostgreSQL Start,
        // Increment, Min, Max, Cache, Cycle and current tuples remain full per-case/target facts.
        return new
        {
            identity.Column,
            DeclaredType = declared,
            identity.SeedValue,
            identity.IncrementValue,
            Minimum = Minimum.ToString(CultureInfo.InvariantCulture),
            Maximum = Maximum.ToString(CultureInfo.InvariantCulture),
            Cycle = false
        };
    }

    private static (BigInteger Minimum, BigInteger Maximum) DecimalBounds(string declared)
    {
        string? precision = declared.StartsWith("decimal(", StringComparison.Ordinal) || declared.StartsWith("numeric(", StringComparison.Ordinal) ? declared[8..] : null;
        if (precision is null || !precision.EndsWith(",0)", StringComparison.Ordinal) ||
            !int.TryParse(precision[..^3], NumberStyles.None, CultureInfo.InvariantCulture, out int value) || value is < 1 or > 38 ||
            precision[..^3] != value.ToString(CultureInfo.InvariantCulture)) { throw Invalid(); }
        BigInteger maximum = BigInteger.Pow(10, value) - 1;
        return (-maximum, maximum);
    }

    private static MigrationExecutionException Invalid()
    {
        return new("source_definition_fingerprint_invalid", "The complete source definition could not be bound in the new proof domain.");
    }
}
