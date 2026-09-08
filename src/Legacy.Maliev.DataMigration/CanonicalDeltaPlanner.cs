using System.Collections.ObjectModel;
using System.Globalization;

namespace Legacy.Maliev.DataMigration;

public enum DeltaOperationKind
{
    Insert,
    Update,
    Delete,
}

public sealed record CanonicalDeltaOperation(
    DeltaOperationKind Kind,
    string KeySha256,
    string? SourceRowSha256,
    string? TargetRowSha256);

public sealed record CanonicalTableDelta(
    string Table,
    IReadOnlyList<CanonicalDeltaOperation> Operations,
    long UnchangedCount)
{
    public long InsertCount => Operations.LongCount(operation => operation.Kind == DeltaOperationKind.Insert);

    public long UpdateCount => Operations.LongCount(operation => operation.Kind == DeltaOperationKind.Update);

    public long DeleteCount => Operations.LongCount(operation => operation.Kind == DeltaOperationKind.Delete);
}

public sealed class DeltaPlanningException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public static class CanonicalDeltaPlanner
{
    public static CanonicalTableDelta Plan(
        TableCopyPlan table,
        IEnumerable<MigrationRow> sourceRows,
        IEnumerable<MigrationRow> targetRows)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(sourceRows);
        ArgumentNullException.ThrowIfNull(targetRows);
        ValidateTable(table);

        using IEnumerator<MigrationRow> source = sourceRows.GetEnumerator();
        using IEnumerator<MigrationRow> target = targetRows.GetEnumerator();
        var sourceCursor = new OrderedRowCursor(table, source, "source");
        var targetCursor = new OrderedRowCursor(table, target, "target");
        var operations = new List<CanonicalDeltaOperation>();
        long unchanged = 0;

        while (sourceCursor.HasValue || targetCursor.HasValue)
        {
            if (!targetCursor.HasValue)
            {
                operations.Add(Create(DeltaOperationKind.Insert, table, sourceCursor.Current!, null));
                sourceCursor.Advance();
                continue;
            }

            if (!sourceCursor.HasValue)
            {
                operations.Add(Create(DeltaOperationKind.Delete, table, null, targetCursor.Current!));
                targetCursor.Advance();
                continue;
            }

            int comparison = CompareKeys(table, sourceCursor.Current!, targetCursor.Current!);
            if (comparison < 0)
            {
                operations.Add(Create(DeltaOperationKind.Insert, table, sourceCursor.Current!, null));
                sourceCursor.Advance();
            }
            else if (comparison > 0)
            {
                operations.Add(Create(DeltaOperationKind.Delete, table, null, targetCursor.Current!));
                targetCursor.Advance();
            }
            else
            {
                string sourceHash = CanonicalRowFingerprint.Compute(table, [sourceCursor.Current!]);
                string targetHash = CanonicalRowFingerprint.Compute(table, [targetCursor.Current!]);
                if (string.Equals(sourceHash, targetHash, StringComparison.Ordinal))
                {
                    unchanged++;
                }
                else
                {
                    operations.Add(new CanonicalDeltaOperation(
                        DeltaOperationKind.Update,
                        ComputeKeySha256(table, sourceCursor.Current!),
                        sourceHash,
                        targetHash));
                }

                sourceCursor.Advance();
                targetCursor.Advance();
            }
        }

        return new CanonicalTableDelta(
            $"{table.TargetSchema}.{table.TargetTable}",
            new ReadOnlyCollection<CanonicalDeltaOperation>(operations),
            unchanged);
    }

    private static CanonicalDeltaOperation Create(
        DeltaOperationKind kind,
        TableCopyPlan table,
        MigrationRow? source,
        MigrationRow? target)
    {
        MigrationRow keyRow = source ?? target ?? throw new InvalidOperationException("A delta operation requires a row identity.");
        return new(
            kind,
            ComputeKeySha256(table, keyRow),
            source is null ? null : CanonicalRowFingerprint.Compute(table, [source]),
            target is null ? null : CanonicalRowFingerprint.Compute(table, [target]));
    }

    public static string ComputeKeySha256(TableCopyPlan table, MigrationRow row)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(row);
        ValidateTable(table);
        ValidateRow(table, row, "key");
        IReadOnlyList<string> keys = table.PrimaryKey!.Columns;
        var values = new ReadOnlyDictionary<string, object?>(keys.ToDictionary(
            key => key,
            key => row.Values[key],
            StringComparer.Ordinal));
        var keyPlan = new TableCopyPlan(
            table.SourceSchema,
            table.SourceTable,
            table.TargetSchema,
            table.TargetTable,
            keys,
            keys)
        {
            ColumnTypes = new ReadOnlyDictionary<string, string>(keys.ToDictionary(
                key => key,
                key => table.ColumnTypes[key],
                StringComparer.Ordinal)),
            PrimaryKey = new PrimaryKeyCopyPlan(table.PrimaryKey.Name, keys),
        };
        return CanonicalRowFingerprint.Compute(keyPlan, [new MigrationRow(values)]);
    }

    private static int CompareKeys(TableCopyPlan table, MigrationRow left, MigrationRow right)
    {
        foreach (string column in table.PrimaryKey!.Columns)
        {
            int comparison = CompareValue(left.Values[column]!, right.Values[column]!);
            if (comparison != 0)
            {
                return comparison;
            }
        }

        return 0;
    }

    private static int CompareValue(object left, object right)
    {
        return (left, right) switch
        {
            (string leftText, string rightText) => string.Compare(leftText, rightText, StringComparison.Ordinal),
            _ when IsNumber(left) && IsNumber(right) => Convert.ToDecimal(left, CultureInfo.InvariantCulture)
                .CompareTo(Convert.ToDecimal(right, CultureInfo.InvariantCulture)),
            (byte[] leftBytes, byte[] rightBytes) => leftBytes.AsSpan().SequenceCompareTo(rightBytes),
            _ when left.GetType() == right.GetType() && left is IComparable comparable => comparable.CompareTo(right),
            _ => throw Error("delta_key_type_invalid", "A primary-key value does not have a compatible deterministic comparison type."),
        };
    }

    private static bool IsNumber(object value)
    {
        return value is byte or sbyte or short or ushort or int or uint or long or ulong or decimal;
    }

    private static void ValidateTable(TableCopyPlan table)
    {
        if (table.PrimaryKey is null || table.PrimaryKey.Columns.Count == 0 ||
            table.PrimaryKey.Columns.Distinct(StringComparer.Ordinal).Count() != table.PrimaryKey.Columns.Count ||
            table.PrimaryKey.Columns.Any(column => !table.OrderedColumns.Contains(column, StringComparer.Ordinal) ||
                !table.ColumnTypes.ContainsKey(column)))
        {
            throw Error("delta_primary_key_required", "The signed table plan must contain a complete non-null primary key.");
        }
    }

    private static DeltaPlanningException Error(string code, string message)
    {
        return new(code, message);
    }

    private sealed class OrderedRowCursor
    {
        private readonly IEnumerator<MigrationRow> _rows;
        private readonly string _side;
        private readonly TableCopyPlan _table;
        private MigrationRow? _previous;

        internal OrderedRowCursor(TableCopyPlan table, IEnumerator<MigrationRow> rows, string side)
        {
            _table = table;
            _rows = rows;
            _side = side;
            Advance();
        }

        internal MigrationRow? Current { get; private set; }

        internal bool HasValue => Current is not null;

        internal void Advance()
        {
            if (!_rows.MoveNext())
            {
                Current = null;
                return;
            }

            MigrationRow row = _rows.Current;
            ValidateRow(_table, row, _side);
            if (_previous is not null)
            {
                int comparison = CompareKeys(_table, _previous, row);
                if (comparison == 0)
                {
                    throw Error("delta_duplicate_key", $"The {_side} row stream contains a duplicate primary key.");
                }

                if (comparison > 0)
                {
                    throw Error("delta_key_order_invalid", $"The {_side} row stream is not ordered by its primary key.");
                }
            }

            _previous = row;
            Current = row;
        }
    }

    private static void ValidateRow(TableCopyPlan table, MigrationRow row, string side)
    {
        if (row.Values.Count != table.OrderedColumns.Count ||
            table.OrderedColumns.Any(column => !row.Values.ContainsKey(column)))
        {
            throw Error("delta_row_shape_invalid", $"The {side} row does not match the signed table shape.");
        }

        if (table.PrimaryKey!.Columns.Any(column => row.Values[column] is null or DBNull))
        {
            throw Error("delta_primary_key_null", $"The {side} row contains a null primary-key value.");
        }
    }
}
