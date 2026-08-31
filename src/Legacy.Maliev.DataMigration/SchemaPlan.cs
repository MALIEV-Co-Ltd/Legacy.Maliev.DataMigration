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

    public bool SourceKnownEmpty { get; init; }

    public IReadOnlyDictionary<string, string> ColumnTypes { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    public IReadOnlyDictionary<string, string> SourceColumnTypes { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    public IReadOnlyList<SourceColumnInventory> SourceColumns { get; init; } = [];

    public IReadOnlyList<string> IdentityColumns { get; init; } = [];

    public IReadOnlyList<IdentityCopyPlan> Identities { get; init; } = [];

    public IReadOnlyList<string> NullableColumns { get; init; } = [];

    public IReadOnlyList<ForeignKeyCopyPlan> ForeignKeys { get; init; } = [];

    public PrimaryKeyCopyPlan? PrimaryKey { get; init; }

    public IReadOnlyList<UniqueConstraintCopyPlan> UniqueConstraints { get; init; } = [];

    public IReadOnlyList<IndexCopyPlan> Indexes { get; init; } = [];

    public IReadOnlyDictionary<string, string> DefaultExpressions { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    public IReadOnlyList<CheckConstraintCopyPlan> CheckConstraints { get; init; } = [];

    public IReadOnlyList<GeneratedColumnCopyPlan> GeneratedColumns { get; init; } = [];

    public IReadOnlyDictionary<string, string> Collations { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);
}

public sealed record PrimaryKeyCopyPlan(string Name, IReadOnlyList<string> Columns);

public sealed record UniqueConstraintCopyPlan(string Name, IReadOnlyList<string> Columns);

public sealed record IdentityCopyPlan(
    string Column,
    long SeedValue,
    long IncrementValue,
    long CurrentValue,
    bool IsCalled);

public sealed record IndexCopyPlan(string Name, IReadOnlyList<string> Columns, bool Unique)
{
    public IReadOnlyList<string> DescendingColumns { get; init; } = [];

    public IReadOnlyList<string> IncludedColumns { get; init; } = [];

    public string? FilterPredicate { get; init; }
}

public enum ReferentialAction
{
    NoAction = 0,
    Cascade = 1,
    SetNull = 2,
    SetDefault = 3,
    Restrict = 4,
}

public sealed record CheckConstraintCopyPlan(string Name, string Expression)
{
    public IReadOnlyList<string> Columns { get; init; } = [];
}

public sealed record GeneratedColumnCopyPlan(string Column, string Expression, bool Stored = true);

public sealed record ForeignKeyCopyPlan(
    string Name,
    IReadOnlyList<string> Columns,
    string ReferencedSchema,
    string ReferencedTable,
    IReadOnlyList<string> ReferencedColumns)
{
    public string? SourceReferencedSchema { get; init; }

    public string? SourceReferencedTable { get; init; }

    public IReadOnlyList<string>? SourceReferencedColumns { get; init; }

    public ReferentialAction OnDelete { get; init; } = ReferentialAction.NoAction;

    public ReferentialAction OnUpdate { get; init; } = ReferentialAction.NoAction;

    public bool SourceEnabled { get; init; } = true;

    public bool SourceTrusted { get; init; } = true;
}

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
    private const string DomainSeparator = "Legacy.Maliev.DataMigration.SchemaPlan.v5";

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
                string[] primaryKeyNames = table.PrimaryKey is null ? [] : [table.PrimaryKey.Name];
                string[] constraintNames =
                [
                    .. primaryKeyNames,
                    .. table.UniqueConstraints.Select(item => item.Name),
                    .. table.CheckConstraints.Select(item => item.Name),
                    .. table.ForeignKeys.Select(item => item.Name),
                ];
                if (string.IsNullOrWhiteSpace(table.SourceSchema) ||
                    string.IsNullOrWhiteSpace(table.SourceTable) ||
                    string.IsNullOrWhiteSpace(table.TargetSchema) ||
                    string.IsNullOrWhiteSpace(table.TargetTable) ||
                    table.OrderedColumns.Count == 0 ||
                    table.BatchSize is < 1 or > 100_000 ||
                    table.OrderedColumns.Any(string.IsNullOrWhiteSpace) ||
                    table.OrderedColumns.Distinct(StringComparer.Ordinal).Count() != table.OrderedColumns.Count ||
                    table.ColumnTypes.Count != table.OrderedColumns.Count ||
                    table.OrderedColumns.Any(column =>
                        !table.ColumnTypes.ContainsKey(column) ||
                        !ValidTargetType(table.ColumnTypes[column])) ||
                    table.SourceColumnTypes.Count != table.OrderedColumns.Count ||
                    table.SourceColumns.Count != table.OrderedColumns.Count ||
                    !table.SourceColumns.Select(column => column.Column)
                        .SequenceEqual(table.OrderedColumns, StringComparer.Ordinal) ||
                    table.SourceColumns.Any(column =>
                        string.IsNullOrWhiteSpace(column.DeclaredType) ||
                        !Sha256().IsMatch(column.MetadataSha256) ||
                        column.MaxObservedDataLength is < 0 ||
                        !table.SourceColumnTypes.TryGetValue(column.Column, out string? declaredType) ||
                        !string.Equals(declaredType, column.DeclaredType, StringComparison.OrdinalIgnoreCase)) ||
                    table.OrderedColumns.Any(column =>
                        !table.SourceColumnTypes.TryGetValue(column, out string? sourceType) ||
                        string.IsNullOrWhiteSpace(sourceType)) ||
                    table.OrderByColumns.Count == 0 ||
                    table.OrderByColumns.Any(column => !table.OrderedColumns.Contains(column, StringComparer.Ordinal)) ||
                    table.IdentityColumns.Any(column => !table.OrderedColumns.Contains(column, StringComparer.Ordinal)) ||
                    table.Identities.Any(identity =>
                        !table.OrderedColumns.Contains(identity.Column, StringComparer.Ordinal) ||
                        identity.IncrementValue == 0) ||
                    table.Identities.Select(identity => identity.Column).Distinct(StringComparer.Ordinal).Count() != table.Identities.Count ||
                    table.IdentityColumns.Except(table.Identities.Select(identity => identity.Column), StringComparer.Ordinal).Any() ||
                    table.NullableColumns.Any(column => !table.OrderedColumns.Contains(column, StringComparer.Ordinal)) ||
                    table.ForeignKeys.Any(foreignKey => !ValidNamedColumns(foreignKey.Name, foreignKey.Columns, table) ||
                        foreignKey.Columns.Count != foreignKey.ReferencedColumns.Count ||
                        (foreignKey.SourceReferencedColumns is not null &&
                            foreignKey.Columns.Count != foreignKey.SourceReferencedColumns.Count) ||
                        string.IsNullOrWhiteSpace(foreignKey.ReferencedSchema) ||
                        string.IsNullOrWhiteSpace(foreignKey.ReferencedTable) ||
                        foreignKey.ReferencedColumns.Any(string.IsNullOrWhiteSpace)) ||
                    (table.PrimaryKey is not null && !ValidNamedColumns(table.PrimaryKey.Name, table.PrimaryKey.Columns, table)) ||
                    table.UniqueConstraints.Any(item => !ValidNamedColumns(item.Name, item.Columns, table)) ||
                    table.Indexes.Any(item => !ValidNamedColumns(item.Name, item.Columns, table) ||
                        item.DescendingColumns.Any(column => !item.Columns.Contains(column, StringComparer.Ordinal)) ||
                        item.IncludedColumns.Any(column => !table.OrderedColumns.Contains(column, StringComparer.Ordinal)) ||
                        item.IncludedColumns.Intersect(item.Columns, StringComparer.Ordinal).Any() ||
                        (item.FilterPredicate is not null && !ValidExpression(item.FilterPredicate))) ||
                    table.DefaultExpressions.Any(item =>
                        !table.OrderedColumns.Contains(item.Key, StringComparer.Ordinal) || !ValidExpression(item.Value)) ||
                    table.CheckConstraints.Any(item =>
                        string.IsNullOrWhiteSpace(item.Name) ||
                        !ValidExpression(item.Expression) ||
                        item.Columns.Count == 0 ||
                        item.Columns.Any(column => !table.OrderedColumns.Contains(column, StringComparer.Ordinal))) ||
                    table.GeneratedColumns.Any(item =>
                        !table.OrderedColumns.Contains(item.Column, StringComparer.Ordinal) ||
                        !item.Stored ||
                        !ValidExpression(item.Expression)) ||
                    table.GeneratedColumns.Select(item => item.Column).Distinct(StringComparer.Ordinal).Count() != table.GeneratedColumns.Count ||
                    table.Collations.Any(item =>
                        !table.OrderedColumns.Contains(item.Key, StringComparer.Ordinal) ||
                        string.IsNullOrWhiteSpace(item.Value) ||
                        item.Value.Contains('\0', StringComparison.Ordinal) ||
                        !IsCollatableType(table.ColumnTypes[item.Key])) ||
                    table.IdentityColumns.Intersect(table.GeneratedColumns.Select(item => item.Column), StringComparer.Ordinal).Any() ||
                    table.DefaultExpressions.Keys.Intersect(table.GeneratedColumns.Select(item => item.Column), StringComparer.Ordinal).Any() ||
                    table.DefaultExpressions.Keys.Intersect(table.IdentityColumns, StringComparer.Ordinal).Any() ||
                    constraintNames.Distinct(StringComparer.Ordinal).Count() != constraintNames.Length)
                {
                    errors.Add(new("table_plan_invalid", $"{database.Database} contains an invalid deterministic table mapping."));
                }

                var totalKeys = new List<IReadOnlyList<string>>();
                if (table.PrimaryKey is not null)
                {
                    totalKeys.Add(table.PrimaryKey.Columns);
                }

                totalKeys.AddRange(table.UniqueConstraints
                    .Where(unique => !unique.Columns.Intersect(table.NullableColumns, StringComparer.Ordinal).Any())
                    .Select(unique => unique.Columns));
                bool hasProvenTotalKey = totalKeys.Any(key => key.All(column => table.OrderByColumns.Contains(column, StringComparer.Ordinal)));
                bool hasProvenEmptyOrdering = table.SourceKnownEmpty &&
                    table.OrderByColumns.SequenceEqual(table.OrderedColumns, StringComparer.Ordinal);
                if (!hasProvenTotalKey && !hasProvenEmptyOrdering)
                {
                    errors.Add(new("order_by_not_total", $"{database.Database}.{table.SourceTable} ordering is not proven unique."));
                }

                if (table.ForeignKeys.Any(foreignKey => !foreignKey.SourceEnabled || !foreignKey.SourceTrusted))
                {
                    errors.Add(new("foreign_key_disposition_unsupported", $"{database.Database}.{table.SourceTable} contains a disabled or untrusted foreign key."));
                }

                foreach ((string column, string sourceType) in table.SourceColumnTypes)
                {
                    if (!ValidTemporalMapping(sourceType, table.ColumnTypes.GetValueOrDefault(column, string.Empty)))
                    {
                        errors.Add(new("temporal_mapping_invalid", $"{database.Database}.{table.SourceTable}.{column} has an unsafe temporal mapping."));
                    }
                }
            }

            string[] indexNames = [.. database.Tables.SelectMany(table => table.Indexes.Select(index =>
                $"{table.TargetSchema}.{index.Name}"))];
            if (indexNames.Distinct(StringComparer.Ordinal).Count() != indexNames.Length)
            {
                errors.Add(new("table_plan_invalid", $"{database.Database} contains duplicate target index names."));
            }

            foreach ((TableCopyPlan table, ForeignKeyCopyPlan foreignKey) in database.Tables.SelectMany(
                table => table.ForeignKeys.Select(foreignKey => (table, foreignKey))))
            {
                TableCopyPlan? sourceReference = database.Tables.SingleOrDefault(candidate =>
                    string.Equals(
                        candidate.SourceSchema,
                        foreignKey.SourceReferencedSchema ?? foreignKey.ReferencedSchema,
                        StringComparison.Ordinal) &&
                    string.Equals(
                        candidate.SourceTable,
                        foreignKey.SourceReferencedTable ?? foreignKey.ReferencedTable,
                        StringComparison.Ordinal));
                TableCopyPlan? targetReference = database.Tables.SingleOrDefault(candidate =>
                    string.Equals(candidate.TargetSchema, foreignKey.ReferencedSchema, StringComparison.Ordinal) &&
                    string.Equals(candidate.TargetTable, foreignKey.ReferencedTable, StringComparison.Ordinal));
                if (sourceReference is null || targetReference is null ||
                    (foreignKey.SourceReferencedColumns ?? foreignKey.ReferencedColumns).Any(column =>
                        !sourceReference.OrderedColumns.Contains(column, StringComparer.Ordinal)) ||
                    foreignKey.ReferencedColumns.Any(column =>
                        !targetReference.OrderedColumns.Contains(column, StringComparer.Ordinal)))
                {
                    errors.Add(new(
                        "table_plan_invalid",
                        $"{database.Database}.{table.SourceTable}.{foreignKey.Name} references a table outside the signed plan."));
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
                    writer.Write(table.SourceKnownEmpty);
                    writer.Write(table.BatchSize);
                    foreach (string column in table.OrderedColumns)
                    {
                        SourceColumnInventory sourceColumn = table.SourceColumns.FirstOrDefault(item => item.Column == column)
                            ?? new SourceColumnInventory(column, string.Empty, string.Empty, null);
                        WriteString(writer, table.SourceColumnTypes.GetValueOrDefault(column, string.Empty));
                        WriteString(writer, sourceColumn.DeclaredType);
                        WriteString(writer, sourceColumn.MetadataSha256.ToLowerInvariant());
                        writer.Write(sourceColumn.MaxObservedDataLength.HasValue);
                        if (sourceColumn.MaxObservedDataLength.HasValue)
                        {
                            writer.Write(sourceColumn.MaxObservedDataLength.Value);
                        }
                        WriteString(writer, table.ColumnTypes.GetValueOrDefault(column, string.Empty));
                    }
                    WriteStrings(writer, table.IdentityColumns);
                    IdentityCopyPlan[] identities = [.. table.Identities.OrderBy(item => item.Column, StringComparer.Ordinal)];
                    writer.Write(identities.Length);
                    foreach (IdentityCopyPlan identity in identities)
                    {
                        WriteString(writer, identity.Column);
                        writer.Write(identity.SeedValue);
                        writer.Write(identity.IncrementValue);
                        writer.Write(identity.CurrentValue);
                        writer.Write(identity.IsCalled);
                    }
                    WriteStrings(writer, table.NullableColumns);
                    writer.Write(table.ForeignKeys.Count);
                    foreach (ForeignKeyCopyPlan foreignKey in table.ForeignKeys.OrderBy(item => item.Name, StringComparer.Ordinal))
                    {
                        WriteString(writer, foreignKey.Name);
                        WriteStrings(writer, foreignKey.Columns);
                        WriteString(writer, foreignKey.ReferencedSchema);
                        WriteString(writer, foreignKey.ReferencedTable);
                        WriteStrings(writer, foreignKey.ReferencedColumns);
                        WriteString(writer, foreignKey.SourceReferencedSchema ?? foreignKey.ReferencedSchema);
                        WriteString(writer, foreignKey.SourceReferencedTable ?? foreignKey.ReferencedTable);
                        WriteStrings(writer, foreignKey.SourceReferencedColumns ?? foreignKey.ReferencedColumns);
                        writer.Write((int)foreignKey.OnDelete);
                        writer.Write((int)foreignKey.OnUpdate);
                        writer.Write(foreignKey.SourceEnabled);
                        writer.Write(foreignKey.SourceTrusted);
                    }
                    writer.Write(table.PrimaryKey is not null);
                    if (table.PrimaryKey is not null)
                    {
                        WriteString(writer, table.PrimaryKey.Name);
                        WriteStrings(writer, table.PrimaryKey.Columns);
                    }
                    WriteNamedColumns(writer, table.UniqueConstraints.Select(item => (item.Name, item.Columns)));
                    IndexCopyPlan[] indexes = [.. table.Indexes.OrderBy(item => item.Name, StringComparer.Ordinal)];
                    writer.Write(indexes.Length);
                    foreach (IndexCopyPlan index in indexes)
                    {
                        WriteString(writer, index.Name);
                        WriteStrings(writer, index.Columns);
                        writer.Write(index.Unique);
                        WriteStrings(writer, index.DescendingColumns);
                        WriteStrings(writer, index.IncludedColumns);
                        WriteString(writer, index.FilterPredicate ?? string.Empty);
                    }
                    WriteDictionary(writer, table.DefaultExpressions);
                    CheckConstraintCopyPlan[] checks = [.. table.CheckConstraints.OrderBy(item => item.Name, StringComparer.Ordinal)];
                    writer.Write(checks.Length);
                    foreach (CheckConstraintCopyPlan check in checks)
                    {
                        WriteString(writer, check.Name);
                        WriteString(writer, check.Expression);
                        WriteStrings(writer, check.Columns);
                    }
                    GeneratedColumnCopyPlan[] generated = [.. table.GeneratedColumns.OrderBy(item => item.Column, StringComparer.Ordinal)];
                    writer.Write(generated.Length);
                    foreach (GeneratedColumnCopyPlan column in generated)
                    {
                        WriteString(writer, column.Column);
                        WriteString(writer, column.Expression);
                        writer.Write(column.Stored);
                    }
                    WriteDictionary(writer, table.Collations);
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

    private static void WriteNamedColumns(
        BinaryWriter writer,
        IEnumerable<(string Name, IReadOnlyList<string> Columns)> values)
    {
        (string Name, IReadOnlyList<string> Columns)[] ordered = [.. values.OrderBy(item => item.Name, StringComparer.Ordinal)];
        writer.Write(ordered.Length);
        foreach ((string name, IReadOnlyList<string> columns) in ordered)
        {
            WriteString(writer, name);
            WriteStrings(writer, columns);
        }
    }

    private static void WriteDictionary(BinaryWriter writer, IReadOnlyDictionary<string, string> values)
    {
        KeyValuePair<string, string>[] ordered = [.. values.OrderBy(item => item.Key, StringComparer.Ordinal)];
        writer.Write(ordered.Length);
        foreach ((string key, string value) in ordered)
        {
            WriteString(writer, key);
            WriteString(writer, value);
        }
    }

    private static bool ValidNamedColumns(string name, IReadOnlyList<string> columns, TableCopyPlan table)
    {
        return !string.IsNullOrWhiteSpace(name) &&
            columns.Count > 0 &&
            columns.Distinct(StringComparer.Ordinal).Count() == columns.Count &&
            columns.All(column => table.OrderedColumns.Contains(column, StringComparer.Ordinal));
    }

    private static bool ValidExpression(string expression)
    {
        return !string.IsNullOrWhiteSpace(expression) &&
            !expression.Contains('\0', StringComparison.Ordinal) &&
            !expression.Contains(';', StringComparison.Ordinal) &&
            !expression.Contains("--", StringComparison.Ordinal) &&
            !expression.Contains("/*", StringComparison.Ordinal) &&
            !expression.Contains("*/", StringComparison.Ordinal) &&
            !ForbiddenExpressionKeyword().IsMatch(expression);
    }

    private static bool ValidTargetType(string type)
    {
        try
        {
            _ = PostgreSqlTypePolicy.Validate(type);
            return true;
        }
        catch (MigrationExecutionException)
        {
            return false;
        }
    }

    private static bool IsCollatableType(string type)
    {
        string normalized = type.Trim().ToLowerInvariant();
        return normalized == "text" ||
            normalized.StartsWith("character varying(", StringComparison.Ordinal) ||
            normalized.StartsWith("character(", StringComparison.Ordinal);
    }

    private static bool ValidTemporalMapping(string sourceType, string targetType)
    {
        string source = sourceType.Split('(', 2)[0].Trim().ToLowerInvariant();
        return source switch
        {
            "datetime" or "smalldatetime" =>
                string.Equals(targetType, "timestamp without time zone", StringComparison.Ordinal) ||
                string.Equals(targetType, "text", StringComparison.Ordinal),
            "datetime2" => string.Equals(targetType, "text", StringComparison.Ordinal) ||
                (TemporalPrecision(sourceType) is >= 0 and <= 6 &&
                    string.Equals(targetType, "timestamp without time zone", StringComparison.Ordinal)),
            "datetimeoffset" => string.Equals(targetType, "text", StringComparison.Ordinal),
            "date" => string.Equals(targetType, "date", StringComparison.Ordinal),
            _ => true,
        };
    }

    private static int TemporalPrecision(string sourceType)
    {
        int open = sourceType.IndexOf('(');
        int close = sourceType.IndexOf(')', open + 1);
        return open >= 0 && close > open + 1 &&
            int.TryParse(sourceType.AsSpan(open + 1, close - open - 1), NumberStyles.None, CultureInfo.InvariantCulture, out int precision)
            ? precision
            : -1;
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

    [GeneratedRegex("\\b(CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|COPY|DO|CALL)\\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ForbiddenExpressionKeyword();
}
