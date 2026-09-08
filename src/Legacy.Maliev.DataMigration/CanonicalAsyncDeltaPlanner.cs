using System.Collections.ObjectModel;

namespace Legacy.Maliev.DataMigration;

public static class CanonicalAsyncDeltaPlanner
{
    public static async Task<CanonicalTableDelta> PlanAsync(
        TableCopyPlan table,
        IAsyncEnumerable<MigrationRow> sourceRows,
        IAsyncEnumerable<MigrationRow> targetRows,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(sourceRows);
        ArgumentNullException.ThrowIfNull(targetRows);
        CanonicalDeltaPlanner.ValidateTable(table);
        await using IAsyncEnumerator<MigrationRow> source = sourceRows.GetAsyncEnumerator(cancellationToken);
        await using IAsyncEnumerator<MigrationRow> target = targetRows.GetAsyncEnumerator(cancellationToken);
        MigrationRow? sourceRow = await NextAsync(table, source, null, "source", cancellationToken).ConfigureAwait(false);
        MigrationRow? targetRow = await NextAsync(table, target, null, "target", cancellationToken).ConfigureAwait(false);
        MigrationRow? previousSource = null;
        MigrationRow? previousTarget = null;
        var operations = new List<CanonicalDeltaOperation>();
        long unchanged = 0;

        while (sourceRow is not null || targetRow is not null)
        {
            if (targetRow is null || (sourceRow is not null && CanonicalDeltaPlanner.CompareKeys(table, sourceRow, targetRow) < 0))
            {
                operations.Add(CanonicalDeltaPlanner.Create(DeltaOperationKind.Insert, table, sourceRow, null));
                previousSource = sourceRow;
                sourceRow = await NextAsync(table, source, previousSource, "source", cancellationToken).ConfigureAwait(false);
            }
            else if (sourceRow is null || CanonicalDeltaPlanner.CompareKeys(table, sourceRow, targetRow) > 0)
            {
                operations.Add(CanonicalDeltaPlanner.Create(DeltaOperationKind.Delete, table, null, targetRow));
                previousTarget = targetRow;
                targetRow = await NextAsync(table, target, previousTarget, "target", cancellationToken).ConfigureAwait(false);
            }
            else
            {
                string sourceHash = CanonicalRowFingerprint.Compute(table, [sourceRow]);
                string targetHash = CanonicalRowFingerprint.Compute(table, [targetRow]);
                if (string.Equals(sourceHash, targetHash, StringComparison.Ordinal))
                {
                    unchanged++;
                }
                else
                {
                    operations.Add(new(DeltaOperationKind.Update,
                        CanonicalDeltaPlanner.ComputeKeySha256(table, sourceRow), sourceHash, targetHash));
                }
                previousSource = sourceRow;
                previousTarget = targetRow;
                sourceRow = await NextAsync(table, source, previousSource, "source", cancellationToken).ConfigureAwait(false);
                targetRow = await NextAsync(table, target, previousTarget, "target", cancellationToken).ConfigureAwait(false);
            }
        }

        return new($"{table.TargetSchema}.{table.TargetTable}",
            new ReadOnlyCollection<CanonicalDeltaOperation>(operations), unchanged);
    }

    private static async Task<MigrationRow?> NextAsync(
        TableCopyPlan table,
        IAsyncEnumerator<MigrationRow> rows,
        MigrationRow? previous,
        string side,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!await rows.MoveNextAsync().ConfigureAwait(false))
        {
            return null;
        }
        MigrationRow row = rows.Current;
        CanonicalDeltaPlanner.ValidateRow(table, row, side);
        await ConsumeStreamingValuesAsync(row, cancellationToken).ConfigureAwait(false);
        if (previous is not null)
        {
            int comparison = CanonicalDeltaPlanner.CompareKeys(table, previous, row);
            if (comparison == 0)
            {
                throw new DeltaPlanningException("delta_duplicate_key", $"The {side} row stream contains a duplicate primary key.");
            }
            if (comparison > 0)
            {
                throw new DeltaPlanningException("delta_key_order_invalid", $"The {side} row stream is not ordered by its primary key.");
            }
        }
        return row;
    }

    private static async Task ConsumeStreamingValuesAsync(
        MigrationRow row,
        CancellationToken cancellationToken)
    {
        foreach (StreamingLob value in row.Values.Values.OfType<StreamingLob>())
        {
            await value.ConsumeAsync(Stream.Null, cancellationToken).ConfigureAwait(false);
        }
    }
}
