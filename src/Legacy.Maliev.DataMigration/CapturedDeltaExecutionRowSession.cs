using System.Runtime.CompilerServices;

namespace Legacy.Maliev.DataMigration;

/// <summary>Resolves signed captured source rows without consulting mutable SQL Server rows.</summary>
public sealed class CapturedDeltaExecutionRowSessionProvider(
    DeltaCapturedTableRowSource source,
    IDeltaOrderedRowSource target) : IDeltaExecutionRowSessionProvider
{
    public Task<IDeltaExecutionRowSession> OpenAsync(
        string database, TableCopyPlan table, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(database);
        ArgumentNullException.ThrowIfNull(table);
        return Task.FromResult<IDeltaExecutionRowSession>(new Session(source, target, database, table));
    }

    private sealed class Session(
        DeltaCapturedTableRowSource source,
        IDeltaOrderedRowSource target,
        string database,
        TableCopyPlan table) : IDeltaExecutionRowSession
    {
        private int _started;

        public async IAsyncEnumerable<ResolvedDeltaRow> ResolveAsync(
            DeltaTablePlan plan, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(plan);
            if (Interlocked.Exchange(ref _started, 1) != 0 ||
                !string.Equals(plan.Table, $"{table.TargetSchema}.{table.TargetTable}", StringComparison.Ordinal))
            {
                throw Error("delta_capture_session_invalid", "The captured row session cannot be reused or paired with another table.");
            }

            var operations = new Dictionary<string, CanonicalDeltaOperation>(StringComparer.Ordinal);
            foreach (CanonicalDeltaOperation operation in plan.Operations)
            {
                if (!operations.TryAdd(operation.KeySha256, operation))
                {
                    throw Error("delta_capture_operation_duplicate", "The signed plan repeats a row identity.");
                }
            }

            var plannedTargets = new Dictionary<string, MigrationRow>(StringComparer.Ordinal);
            MigrationRow? previousTarget = null;
            await foreach (MigrationRow row in target.ReadOrderedAsync(database, table, cancellationToken)
                .WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                ValidateShape(row);
                if (previousTarget is not null && CanonicalDeltaPlanner.CompareKeys(table, previousTarget, row) >= 0)
                {
                    throw Error("delta_capture_target_order_invalid", "The target row stream has duplicate or unordered keys.");
                }
                previousTarget = row;
                string key = CanonicalDeltaPlanner.ComputeKeySha256(table, row);
                if (!operations.TryGetValue(key, out CanonicalDeltaOperation? operation))
                {
                    await ConsumeStreamingAsync(row, cancellationToken).ConfigureAwait(false);
                    continue;
                }
                if (operation.Kind == DeltaOperationKind.Insert)
                {
                    throw Error("delta_capture_target_drift", "A planned insert already exists on the target.");
                }
                await ConsumeStreamingAsync(row, cancellationToken).ConfigureAwait(false);
                DeltaExecutionCoordinator.VerifyRow(table, row, key, operation.TargetRowSha256, "target");
                if (!plannedTargets.TryAdd(key, row))
                {
                    throw Error("delta_capture_target_duplicate", "The target contains a duplicate planned identity.");
                }
            }
            if (operations.Values.Any(operation => operation.Kind != DeltaOperationKind.Insert &&
                !plannedTargets.ContainsKey(operation.KeySha256)))
            {
                throw Error("delta_capture_target_missing", "A planned update or deletion is absent from the target.");
            }

            var seenSource = new HashSet<string>(StringComparer.Ordinal);
            await foreach (MigrationRow row in source.ReadOrderedAsync(database, table, cancellationToken)
                .WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                ValidateShape(row);
                string key = CanonicalDeltaPlanner.ComputeKeySha256(table, row);
                yield return !seenSource.Add(key) || !operations.TryGetValue(key, out CanonicalDeltaOperation? operation) ||
                    operation.Kind == DeltaOperationKind.Delete ||
                    (operation.Kind == DeltaOperationKind.Update && !plannedTargets.ContainsKey(key))
                    ? throw Error("delta_capture_source_mismatch", "A captured source row is absent from its signed operation set.")
                    : new(operation, row, plannedTargets.GetValueOrDefault(key));
            }

            if (seenSource.Count != checked(plan.InsertCount + plan.UpdateCount))
            {
                throw Error("delta_capture_source_missing", "The encrypted capture is missing a planned source row.");
            }
            foreach (CanonicalDeltaOperation operation in plan.Operations.Where(item => item.Kind == DeltaOperationKind.Delete))
            {
                yield return !plannedTargets.TryGetValue(operation.KeySha256, out MigrationRow? row)
                    ? throw Error("delta_capture_target_missing", "A planned deletion is absent from the target.")
                    : new(operation, null, row);
            }
            if (plannedTargets.Count != checked(plan.UpdateCount + plan.DeleteCount))
            {
                throw Error("delta_capture_target_mismatch", "The target rows do not match the signed operations.");
            }
        }

        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }

        private void ValidateShape(MigrationRow row)
        {
            if (row.Values.Count != table.OrderedColumns.Count ||
                table.OrderedColumns.Any(column => !row.Values.ContainsKey(column)) ||
                table.PrimaryKey is null || table.PrimaryKey.Columns.Any(column => row.Values[column] is null or DBNull))
            {
                throw Error("delta_capture_row_invalid", "A captured or target row does not match the signed table shape.");
            }
        }

        private static async Task ConsumeStreamingAsync(MigrationRow row, CancellationToken cancellationToken)
        {
            foreach (StreamingLob lob in row.Values.Values.OfType<StreamingLob>())
            {
                await lob.ConsumeAsync(Stream.Null, cancellationToken).ConfigureAwait(false);
            }
        }

        private static DeltaExecutionException Error(string code, string message)
        {
            return new(code, message);
        }
    }
}
