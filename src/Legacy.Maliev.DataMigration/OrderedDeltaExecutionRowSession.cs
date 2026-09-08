using System.Runtime.CompilerServices;

namespace Legacy.Maliev.DataMigration;

public sealed class OrderedDeltaExecutionRowSessionProvider(
    IDeltaOrderedRowSource source,
    IDeltaOrderedRowSource target) : IDeltaExecutionRowSessionProvider
{
    public Task<IDeltaExecutionRowSession> OpenAsync(
        string database,
        TableCopyPlan table,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(database);
        ArgumentNullException.ThrowIfNull(table);
        return Task.FromResult<IDeltaExecutionRowSession>(new Session(
            table,
            source.ReadOrderedAsync(database, table, cancellationToken),
            target.ReadOrderedAsync(database, table, cancellationToken)));
    }

    private sealed class Session(
        TableCopyPlan table,
        IAsyncEnumerable<MigrationRow> source,
        IAsyncEnumerable<MigrationRow> target) : IDeltaExecutionRowSession
    {
        private int _started;

        public async IAsyncEnumerable<ResolvedDeltaRow> ResolveAsync(
            DeltaTablePlan plan,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(plan);
            if (Interlocked.Exchange(ref _started, 1) != 0)
            {
                throw Error("delta_execution_session_reused", "An ordered delta row session can be consumed exactly once.");
            }
            if (!string.Equals(plan.Table, $"{table.TargetSchema}.{table.TargetTable}", StringComparison.Ordinal))
            {
                throw Error("delta_execution_table_plan_invalid", "The ordered row session does not match the signed table plan.");
            }

            await using IAsyncEnumerator<MigrationRow> sourceRows = source.GetAsyncEnumerator(cancellationToken);
            await using IAsyncEnumerator<MigrationRow> targetRows = target.GetAsyncEnumerator(cancellationToken);
            var sourceCursor = new Cursor(table, sourceRows, "source");
            var targetCursor = new Cursor(table, targetRows, "target");
            await sourceCursor.AdvanceAsync().ConfigureAwait(false);
            await targetCursor.AdvanceAsync().ConfigureAwait(false);
            var operations = new Dictionary<string, CanonicalDeltaOperation>(StringComparer.Ordinal);
            foreach (CanonicalDeltaOperation operation in plan.Operations)
            {
                if (!operations.TryAdd(operation.KeySha256, operation))
                {
                    throw Error("delta_execution_operation_duplicate", "The signed delta plan contains a duplicate row key.");
                }
            }
            var resolvedOperations = 0;
            while (sourceCursor.HasValue || targetCursor.HasValue)
            {
                cancellationToken.ThrowIfCancellationRequested();
                MigrationRow? sourceRow = sourceCursor.Current;
                MigrationRow? targetRow = targetCursor.Current;
                int comparison = sourceRow is null ? 1 : targetRow is null ? -1 : CanonicalDeltaPlanner.CompareKeys(table, sourceRow, targetRow);
                DeltaOperationKind inferred = comparison < 0 ? DeltaOperationKind.Insert : comparison > 0 ? DeltaOperationKind.Delete : DeltaOperationKind.Update;
                MigrationRow keyRow = comparison <= 0 ? sourceRow! : targetRow!;
                MigrationRow? resolvedSource = comparison <= 0 ? sourceRow : null;
                MigrationRow? resolvedTarget = comparison >= 0 ? targetRow : null;
                string keySha256 = CanonicalDeltaPlanner.ComputeKeySha256(table, keyRow);
                bool plannedKey = operations.TryGetValue(keySha256, out CanonicalDeltaOperation? operation);

                if (comparison == 0 && !plannedKey)
                {
                    await ConsumeStreamingAsync(sourceRow!, cancellationToken).ConfigureAwait(false);
                    await ConsumeStreamingAsync(targetRow!, cancellationToken).ConfigureAwait(false);
                    string sourceHash = CanonicalRowFingerprint.Compute(table, [sourceRow!]);
                    string targetHash = CanonicalRowFingerprint.Compute(table, [targetRow!]);
                    if (!string.Equals(sourceHash, targetHash, StringComparison.Ordinal))
                    {
                        throw Error("delta_execution_operation_missing", "A changed row is absent from the signed delta operations.");
                    }
                    await sourceCursor.AdvanceAsync().ConfigureAwait(false);
                    await targetCursor.AdvanceAsync().ConfigureAwait(false);
                    continue;
                }

                if (!plannedKey || operation!.Kind != inferred)
                {
                    throw Error("delta_execution_operation_mismatch", "The ordered rows do not match the signed delta operation sequence.");
                }

                if (resolvedTarget is not null)
                {
                    await ConsumeStreamingAsync(resolvedTarget, cancellationToken).ConfigureAwait(false);
                    DeltaExecutionCoordinator.VerifyRow(table, resolvedTarget, operation.KeySha256, operation.TargetRowSha256, "target");
                }
                if (resolvedSource is not null && !HasStreaming(resolvedSource))
                {
                    DeltaExecutionCoordinator.VerifyRow(table, resolvedSource, operation.KeySha256, operation.SourceRowSha256, "source");
                }

                yield return new(operation, resolvedSource, resolvedTarget);
                resolvedOperations++;
                if (comparison <= 0)
                {
                    await sourceCursor.AdvanceAsync().ConfigureAwait(false);
                }

                if (comparison >= 0)
                {
                    await targetCursor.AdvanceAsync().ConfigureAwait(false);
                }
            }
            if (resolvedOperations != plan.Operations.Count)
            {
                throw Error("delta_execution_operation_missing", "The signed delta plan contains operations absent from the ordered row streams.");
            }
        }

        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }

        private static bool HasStreaming(MigrationRow row)
        {
            return row.Values.Values.Any(value => value is StreamingLob);
        }

        private static async Task ConsumeStreamingAsync(MigrationRow row, CancellationToken cancellationToken)
        {
            foreach (StreamingLob lob in row.Values.Values.OfType<StreamingLob>())
            {
                await lob.ConsumeAsync(Stream.Null, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private sealed class Cursor(TableCopyPlan table, IAsyncEnumerator<MigrationRow> rows, string side)
    {
        private MigrationRow? _previous;
        internal MigrationRow? Current { get; private set; }
        internal bool HasValue => Current is not null;

        internal async Task AdvanceAsync()
        {
            if (!await rows.MoveNextAsync().ConfigureAwait(false))
            {
                Current = null;
                return;
            }
            MigrationRow current = rows.Current;
            ValidateRow(table, current, side);
            if (_previous is not null)
            {
                int comparison = CanonicalDeltaPlanner.CompareKeys(table, _previous, current);
                if (comparison == 0)
                {
                    throw Error("delta_execution_duplicate_key", $"The {side} execution stream contains a duplicate key.");
                }

                if (comparison > 0)
                {
                    throw Error("delta_execution_key_order_invalid", $"The {side} execution stream is not primary-key ordered.");
                }
            }
            _previous = current;
            Current = current;
        }
    }

    private static void ValidateRow(TableCopyPlan table, MigrationRow row, string side)
    {
        if (row.Values.Count != table.OrderedColumns.Count || table.OrderedColumns.Any(column => !row.Values.ContainsKey(column)) ||
            table.PrimaryKey is null || table.PrimaryKey.Columns.Any(column => row.Values[column] is null or DBNull))
        {
            throw Error($"delta_execution_{side}_row_invalid", $"The {side} execution row does not match the signed table shape.");
        }
    }

    private static DeltaExecutionException Error(string code, string message)
    {
        return new(code, message);
    }
}
