using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record Retained31IndexContract(string Database, string Schema, string Table, string Name,
    string Kind, IReadOnlyList<string> Columns, bool Unique, IReadOnlyList<int> ChangedPositions);

/// <summary>Pure derived preparation contract. No permission, provider, DDL or catalog transition bypass.</summary>
internal sealed class CurrentAppOwnedRetained31Contract
{
    private readonly FreshSchemaPlan _old;
    private readonly FreshSchemaPlan _current;
    private readonly string _digest;
    private readonly CurrentAppOwnedCollationOperand[] _operands;
    private static readonly string[] IndexNames =
    [
        "IX_CustomerIdentityCreateOperations_ServiceSubject_OperationKey",
        "IX_EmployeeRecoveryEffects_IdentityId_FinalizedAcknowledgedAt",
        "IX_EmployeeRecoveryEffects_TokenSha256_Purpose",
        "IX_QuotationAcceptedOutcome_EventKey",
        "PK_RequestCreateIdempotency",
        "UQ_InvoiceNotificationCorrelation_InvoicePurpose",
    ];

    private CurrentAppOwnedRetained31Contract(FreshSchemaPlan old, FreshSchemaPlan current)
    {
        _old = old;
        _current = current;
        _operands = CurrentAppOwnedRepairManifest.RetainedOperands();
        var physical = DatabaseInventory.ActiveDatabases.Select(name => new
        {
            Database = name,
            Before = BeforeForDatabase(name).TargetSchemaSha256,
            After = AfterForDatabase(name).TargetSchemaSha256,
        }).ToArray();
        byte[] payload = [.. "Legacy.Maliev.CurrentAppOwnedRetained31.Preparation.v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(new
            {
                Source = current.SourceCommitSha,
                Old = SchemaPlanCanonicalizer.ComputeSha256(old),
                Current = SchemaPlanCanonicalizer.ComputeSha256(current),
                Operation = CurrentAppOwnedRepairManifest.OperationSha256(CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations),
                Physical = physical,
                Operands = _operands,
                Indexes = DeriveIndexes(current),
            })];
        _digest = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
    }

    internal string SourceCommitSha => _current.SourceCommitSha;

    internal string ComputeSha256()
    {
        return _digest;
    }

    internal CurrentAppOwnedCollationOperand[] Operands()
    {
        return _operands.ToArray();
    }

    internal IReadOnlyList<Retained31IndexContract> Indexes()
    {
        return DeriveIndexes(_current);
    }

    // This is a phase physical inventory, never a newly approved mixed FreshSchemaPlan.
    internal DatabaseSchemaPlan BeforeForDatabase(string database)
    {
        RequireDatabase(database);
        FreshSchemaPlan selected = RetainedDatabases().Contains(database, StringComparer.Ordinal) ? _old : _current;
        return Clone(selected.Databases.Single(x => x.Database == database));
    }

    internal DatabaseSchemaPlan AfterForDatabase(string database)
    {
        RequireDatabase(database);
        return Clone(_current.Databases.Single(x => x.Database == database));
    }

    internal void RequireTableContract(string database, TableCopyPlan observed, bool after)
    {
        DatabaseSchemaPlan plan = after ? AfterForDatabase(database) : BeforeForDatabase(database);
        TableCopyPlan[] matches = [.. ApprovedConsumerColumnOverlayManifest.ComposePhysical(plan)
            .Where(x => x.TargetSchema == observed.TargetSchema && x.TargetTable == observed.TargetTable)];
        if (matches.Length != 1 || JsonSerializer.Serialize(matches[0]) != JsonSerializer.Serialize(observed))
        { throw Invalid(); }
    }

    internal static CurrentAppOwnedRetained31Contract Create(FreshSchemaPlan old, FreshSchemaPlan current,
        string expectedSourceCommitSha, DateTimeOffset nowUtc)
    {
        // The source pin must come from independent accepted-source observation by the future caller.
        if (expectedSourceCommitSha.Length != 40 ||
            !expectedSourceCommitSha.All(x => x is (>= '0' and <= '9') or (>= 'a' and <= 'f')) ||
            old.SourceCommitSha != expectedSourceCommitSha || current.SourceCommitSha != expectedSourceCommitSha)
        { throw Invalid(); }
        old = Clone(old);
        current = Clone(current);
        CurrentAppOwnedRepairManifest.RequireSchemaPair(old, current, nowUtc);
        CurrentAppOwnedCollationOperand[] operands = CurrentAppOwnedRepairManifest.RetainedOperands();
        if (operands.Length != 31 || operands.Distinct().Count() != 31 ||
            operands.Select(x => (x.Database, x.Schema, x.Table)).Distinct().Count() != 6)
        { throw Invalid(); }
        foreach (string database in RetainedDatabases())
        {
            TableCopyPlan[] before = [.. ApprovedConsumerColumnOverlayManifest.ComposePhysical(old.Databases.Single(x => x.Database == database))];
            TableCopyPlan[] after = [.. ApprovedConsumerColumnOverlayManifest.ComposePhysical(current.Databases.Single(x => x.Database == database))];
            if (!before.Select(x => (x.TargetSchema, x.TargetTable)).SequenceEqual(after.Select(x => (x.TargetSchema, x.TargetTable))))
            { throw Invalid(); }
            foreach ((TableCopyPlan left, TableCopyPlan right) in before.Zip(after))
            {
                string[] changed = [.. right.OrderedColumns.Where(column =>
                    left.Collations.GetValueOrDefault(column) != right.Collations.GetValueOrDefault(column))];
                CurrentAppOwnedCollationOperand[] required = [.. operands.Where(x =>
                    x.Database == database && x.Schema == right.TargetSchema && x.Table == right.TargetTable)];
                if (!changed.Order(StringComparer.Ordinal).SequenceEqual(required.Select(x => x.Column).Order(StringComparer.Ordinal)) ||
                    required.Any(x => right.ColumnTypes.GetValueOrDefault(x.Column) != x.PostgreSqlType ||
                        left.ColumnTypes.GetValueOrDefault(x.Column) != x.PostgreSqlType ||
                        left.Collations.ContainsKey(x.Column) || right.Collations.GetValueOrDefault(x.Column) != "C") ||
                    JsonSerializer.Serialize(left with { Collations = right.Collations }) != JsonSerializer.Serialize(right))
                { throw Invalid(); }
            }
        }
        // Includes the mapped quotation outcome: absence of its approved source disposition fails here.
        foreach (CurrentAppOwnedCollationOperand operand in operands)
        {
            IReadOnlyList<TableCopyPlan> physical = ApprovedConsumerColumnOverlayManifest.ComposePhysical(
                current.Databases.Single(x => x.Database == operand.Database));
            if (physical.Count(x => x.TargetSchema == operand.Schema && x.TargetTable == operand.Table &&
                x.OrderedColumns.Contains(operand.Column, StringComparer.Ordinal) &&
                x.ColumnTypes.GetValueOrDefault(operand.Column) == operand.PostgreSqlType) != 1)
            { throw Invalid(); }
        }
        _ = DeriveIndexes(current);
        return new(old, current);
    }

    private static ReadOnlyCollection<Retained31IndexContract> DeriveIndexes(FreshSchemaPlan current)
    {
        var result = new List<Retained31IndexContract>();
        foreach (string database in RetainedDatabases())
        {
            foreach (TableCopyPlan table in ApprovedConsumerColumnOverlayManifest.ComposePhysical(current.Databases.Single(x => x.Database == database)))
            {
                string[] columns = [.. CurrentAppOwnedRepairManifest.RetainedOperands().Where(x =>
                    x.Database == database && x.Schema == table.TargetSchema && x.Table == table.TargetTable).Select(x => x.Column)];
                var declared = table.Indexes.Select(x => (x.Name, Kind: "index", x.Columns, x.Unique))
                    .Concat(table.UniqueConstraints.Select(x => (x.Name, Kind: "unique-constraint", x.Columns, Unique: true)))
                    .Concat(table.PrimaryKey is { } key ? [(key.Name, Kind: "primary-key", key.Columns, Unique: true)] : []);
                foreach (var (Name, Kind, Columns, Unique) in declared)
                {
                    int[] positions = [.. Columns.Select((column, position) => (column, position))
                        .Where(x => columns.Contains(x.column, StringComparer.Ordinal)).Select(x => x.position)];
                    if (positions.Length == 0) { continue; }
                    result.Add(new(database, table.TargetSchema, table.TargetTable, Name, Kind,
                        Array.AsReadOnly(Columns.ToArray()), Unique, Array.AsReadOnly(positions)));
                }
            }
        }
        return !result.Select(x => x.Name).Order(StringComparer.Ordinal).SequenceEqual(IndexNames, StringComparer.Ordinal)
            ? throw Invalid()
            : Array.AsReadOnly(result.OrderBy(x => x.Database, StringComparer.Ordinal).ThenBy(x => x.Name, StringComparer.Ordinal).ToArray());
    }

    private static string[] RetainedDatabases()
    {
        return CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations);
    }

    private static void RequireDatabase(string database)
    {
        if (!DatabaseInventory.ActiveDatabases.Contains(database, StringComparer.Ordinal)) { throw Invalid(); }
    }

    private static T Clone<T>(T value)
    {
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value)) ?? throw Invalid();
    }

    private static MigrationExecutionException Invalid()
    {
        return new("current_app_owned_retained31_contract_invalid", "The fixed retained31 preparation contract is invalid.");
    }
}
