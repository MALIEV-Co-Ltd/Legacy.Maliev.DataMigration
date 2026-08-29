using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public sealed record TableCopyPlan(
    string SourceSchema,
    string SourceTable,
    string TargetSchema,
    string TargetTable,
    IReadOnlyList<string> OrderedColumns,
    IReadOnlyList<string> OrderByColumns)
{
    public int BatchSize { get; init; } = 10_000;

    public IReadOnlyDictionary<string, string> ColumnTypes { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    public IReadOnlyList<string> IdentityColumns { get; init; } = [];

    public IReadOnlyList<string> NullableColumns { get; init; } = [];

    public IReadOnlyList<ForeignKeyCopyPlan> ForeignKeys { get; init; } = [];
}

public sealed record ForeignKeyCopyPlan(
    string Name,
    IReadOnlyList<string> Columns,
    string ReferencedSchema,
    string ReferencedTable,
    IReadOnlyList<string> ReferencedColumns);

public sealed record DatabaseSchemaPlan(
    string Database,
    string TargetSchemaVersion,
    string SourceSchemaSha256,
    string TargetSchemaSha256,
    IReadOnlyList<TableCopyPlan> Tables);

public sealed record FreshSchemaPlan(
    string SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    string SourceCommitSha,
    IReadOnlyList<DatabaseSchemaPlan> Databases);

public static partial class SchemaPlanCanonicalizer
{
    private const string DomainSeparator = "Legacy.Maliev.DataMigration.SchemaPlan.v2";

    public static string ComputeSha256(FreshSchemaPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        byte[] payload = CreatePayload(plan);
        return Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
    }

    internal static IReadOnlyList<PreflightError> Validate(
        FreshSchemaPlan plan,
        GuardedRunnerPolicy policy,
        DateTimeOffset nowUtc,
        TimeSpan maximumAge)
    {
        List<PreflightError> errors = [];
        if (!string.Equals(plan.SchemaVersion, "2.0", StringComparison.Ordinal))
        {
            errors.Add(new("schema_plan_version_unknown", "The schema plan version is not approved."));
        }

        if (maximumAge <= TimeSpan.Zero || plan.CapturedAtUtc > nowUtc || nowUtc - plan.CapturedAtUtc > maximumAge)
        {
            errors.Add(new("schema_plan_stale", "The schema plan is stale or dated in the future."));
        }

        if (!CommitSha().IsMatch(plan.SourceCommitSha) ||
            !string.Equals(plan.SourceCommitSha, policy.ExpectedSourceCommitSha, StringComparison.Ordinal))
        {
            errors.Add(new("schema_plan_source_commit_stale", "The schema plan is not bound to the expected current source commit."));
        }

        string[] actualDatabases = [.. plan.Databases.Select(database => database.Database)];
        if (actualDatabases.Length != DatabaseInventory.ActiveDatabases.Count ||
            actualDatabases.Distinct(StringComparer.Ordinal).Count() != actualDatabases.Length ||
            !actualDatabases.OrderBy(database => database, StringComparer.Ordinal)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            errors.Add(new("schema_plan_database_coverage_invalid", "The schema plan must cover exactly the approved migrate disposition."));
        }

        foreach (DatabaseSchemaPlan database in plan.Databases)
        {
            if (!string.Equals(database.TargetSchemaVersion, "1.0", StringComparison.Ordinal))
            {
                errors.Add(new("target_schema_version_unknown", $"{database.Database} has an unapproved target schema version."));
            }

            if (!Sha256().IsMatch(database.SourceSchemaSha256) || !Sha256().IsMatch(database.TargetSchemaSha256))
            {
                errors.Add(new("schema_fingerprint_invalid", $"{database.Database} has an invalid schema fingerprint."));
            }

            if (database.Tables.Count == 0 ||
                database.Tables.Select(table => $"{table.SourceSchema}.{table.SourceTable}")
                    .Distinct(StringComparer.Ordinal).Count() != database.Tables.Count ||
                database.Tables.Select(table => $"{table.TargetSchema}.{table.TargetTable}")
                    .Distinct(StringComparer.Ordinal).Count() != database.Tables.Count)
            {
                errors.Add(new("table_plan_invalid", $"{database.Database} must contain unique source and target table mappings."));
            }

            foreach (TableCopyPlan table in database.Tables)
            {
                if (string.IsNullOrWhiteSpace(table.SourceSchema) ||
                    string.IsNullOrWhiteSpace(table.SourceTable) ||
                    string.IsNullOrWhiteSpace(table.TargetSchema) ||
                    string.IsNullOrWhiteSpace(table.TargetTable) ||
                    table.OrderedColumns.Count == 0 ||
                    table.BatchSize is < 1 or > 100_000 ||
                    table.OrderedColumns.Any(string.IsNullOrWhiteSpace) ||
                    table.OrderedColumns.Distinct(StringComparer.Ordinal).Count() != table.OrderedColumns.Count ||
                    table.ColumnTypes.Count != table.OrderedColumns.Count ||
                    table.OrderedColumns.Any(column => !table.ColumnTypes.ContainsKey(column)) ||
                    table.OrderByColumns.Count == 0 ||
                    table.OrderByColumns.Any(column => !table.OrderedColumns.Contains(column, StringComparer.Ordinal)) ||
                    table.IdentityColumns.Any(column => !table.OrderedColumns.Contains(column, StringComparer.Ordinal)) ||
                    table.NullableColumns.Any(column => !table.OrderedColumns.Contains(column, StringComparer.Ordinal)) ||
                    table.ForeignKeys.Any(foreignKey => foreignKey.Columns.Count == 0 ||
                        foreignKey.Columns.Count != foreignKey.ReferencedColumns.Count ||
                        foreignKey.Columns.Any(column => !table.OrderedColumns.Contains(column, StringComparer.Ordinal))))
                {
                    errors.Add(new("table_plan_invalid", $"{database.Database} contains an invalid deterministic table mapping."));
                }
            }
        }

        return errors;
    }

    private static byte[] CreatePayload(FreshSchemaPlan plan)
    {
        using MemoryStream stream = new();
        using (BinaryWriter writer = new(stream, new UTF8Encoding(false), leaveOpen: true))
        {
            WriteString(writer, DomainSeparator);
            WriteString(writer, plan.SchemaVersion);
            WriteString(writer, plan.CapturedAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            WriteString(writer, plan.SourceCommitSha);
            DatabaseSchemaPlan[] databases = [.. plan.Databases.OrderBy(database => database.Database, StringComparer.Ordinal)];
            writer.Write(databases.Length);
            foreach (DatabaseSchemaPlan database in databases)
            {
                WriteString(writer, database.Database);
                WriteString(writer, database.TargetSchemaVersion);
                WriteString(writer, database.SourceSchemaSha256.ToLowerInvariant());
                WriteString(writer, database.TargetSchemaSha256.ToLowerInvariant());
                TableCopyPlan[] tables = [.. database.Tables
                    .OrderBy(table => table.SourceSchema, StringComparer.Ordinal)
                    .ThenBy(table => table.SourceTable, StringComparer.Ordinal)];
                writer.Write(tables.Length);
                foreach (TableCopyPlan table in tables)
                {
                    WriteString(writer, table.SourceSchema);
                    WriteString(writer, table.SourceTable);
                    WriteString(writer, table.TargetSchema);
                    WriteString(writer, table.TargetTable);
                    WriteStrings(writer, table.OrderedColumns);
                    WriteStrings(writer, table.OrderByColumns);
                    writer.Write(table.BatchSize);
                    foreach (string column in table.OrderedColumns)
                    {
                        WriteString(writer, table.ColumnTypes.GetValueOrDefault(column, string.Empty));
                    }
                    WriteStrings(writer, table.IdentityColumns);
                    WriteStrings(writer, table.NullableColumns);
                    writer.Write(table.ForeignKeys.Count);
                    foreach (ForeignKeyCopyPlan foreignKey in table.ForeignKeys.OrderBy(item => item.Name, StringComparer.Ordinal))
                    {
                        WriteString(writer, foreignKey.Name);
                        WriteStrings(writer, foreignKey.Columns);
                        WriteString(writer, foreignKey.ReferencedSchema);
                        WriteString(writer, foreignKey.ReferencedTable);
                        WriteStrings(writer, foreignKey.ReferencedColumns);
                    }
                }
            }
        }

        return stream.ToArray();
    }

    private static void WriteStrings(BinaryWriter writer, IReadOnlyList<string> values)
    {
        writer.Write(values.Count);
        foreach (string value in values)
        {
            WriteString(writer, value);
        }
    }

    private static void WriteString(BinaryWriter writer, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }

    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex CommitSha();

    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256();
}
