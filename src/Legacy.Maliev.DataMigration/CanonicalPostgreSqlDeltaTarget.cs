using System.Data;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public sealed record PostgreSqlDeltaCanonicalTargetOptions(
    string ConnectionString,
    string ExpectedDatabase,
    string ExpectedTargetGeneration);

internal sealed record CanonicalDeltaTargetBinding(Guid PlanId, string PlanSha256, DateTimeOffset SourceCutoffUtc,
    string Database, string SchemaPlanSha256, string TargetSchemaSha256, string TargetGeneration, string TargetObservationSha256);

public sealed class PostgreSqlDeltaCanonicalTarget(PostgreSqlDeltaCanonicalTargetOptions options)
    : IDeltaCanonicalTarget
{
    public async Task<IDeltaCanonicalTransaction> BeginAsync(
        DeltaSynchronizationPlan plan,
        DatabaseSchemaPlan schema,
        string database,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(schema);
        string planSha256 = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
        var binding = new CanonicalDeltaTargetBinding(plan.PlanId, planSha256, plan.SourceCutoffUtc, database,
            plan.SchemaPlanSha256, schema.TargetSchemaSha256, plan.TargetGeneration, plan.TargetObservationSha256);
        ValidateBinding(binding);

        var builder = new NpgsqlConnectionStringBuilder(options.ConnectionString);
        if (!string.Equals(builder.Database, options.ExpectedDatabase, StringComparison.Ordinal) ||
            !string.Equals(binding.Database, options.ExpectedDatabase, StringComparison.Ordinal) ||
            !string.Equals(schema.Database, options.ExpectedDatabase, StringComparison.Ordinal))
        {
            throw Error("canonical_delta_database_invalid", "The canonical delta connection and signed database binding do not match.");
        }

        var connection = new NpgsqlConnection(builder.ConnectionString);
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            if (!string.Equals(connection.Database, options.ExpectedDatabase, StringComparison.Ordinal))
            {
                throw Error("canonical_delta_database_invalid", "The opened PostgreSQL database does not match the expected canonical database.");
            }

            NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken)
                .ConfigureAwait(false);
            try
            {
                await AcquireLocksAsync(connection, transaction, binding, schema, cancellationToken).ConfigureAwait(false);
                await ValidateFenceAsync(connection, transaction, binding, cancellationToken).ConfigureAwait(false);
                bool replay = await ValidateReplayAsync(connection, transaction, binding, cancellationToken).ConfigureAwait(false);
                IReadOnlyDictionary<string, int> upsertOrder = CanonicalForeignKeyOrder.Build(schema);
                return new PostgreSqlDeltaCanonicalTransaction(connection, transaction, binding, schema, replay, upsertOrder,
                    ComputeOperationsSha256(plan, database));
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
                await transaction.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private void ValidateBinding(CanonicalDeltaTargetBinding binding)
    {
        if (binding.PlanId == Guid.Empty || binding.SourceCutoffUtc.Offset != TimeSpan.Zero ||
            !Hash(binding.PlanSha256) || !Hash(binding.SchemaPlanSha256) || !Hash(binding.TargetSchemaSha256) ||
            !Hash(binding.TargetObservationSha256) ||
            !string.Equals(binding.TargetGeneration, options.ExpectedTargetGeneration, StringComparison.Ordinal))
        {
            throw Error("canonical_delta_binding_invalid", "The canonical delta execution binding is invalid or stale.");
        }
    }

    private static async Task AcquireLocksAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CanonicalDeltaTargetBinding binding,
        DatabaseSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes($"{binding.PlanSha256}\0{binding.Database}"));
        long advisoryKey = BitConverter.ToInt64(digest, 0);
        await using (var advisory = new NpgsqlCommand("SELECT pg_advisory_xact_lock($1);", connection, transaction))
        {
            _ = advisory.Parameters.AddWithValue(advisoryKey);
            _ = await advisory.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        }

        string tables = string.Join(", ", schema.Tables
            .Select(table => Qualified(table.TargetSchema, table.TargetTable))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal));
        if (tables.Length == 0)
        {
            throw Error("canonical_delta_table_inventory_invalid", "The signed canonical table inventory is empty.");
        }

        await using var tableLocks = new NpgsqlCommand($"LOCK TABLE {tables} IN ACCESS EXCLUSIVE MODE;", connection, transaction);
        _ = await tableLocks.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task ValidateFenceAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CanonicalDeltaTargetBinding binding,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            SELECT schema_plan_sha256, target_schema_sha256, target_generation, target_observation_sha256
            FROM legacy_migration_internal.delta_fence
            WHERE database_name=$1
            FOR UPDATE;
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(binding.Database);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
            !Fixed(reader.GetString(0), binding.SchemaPlanSha256) ||
            !Fixed(reader.GetString(1), binding.TargetSchemaSha256) ||
            !string.Equals(reader.GetString(2), binding.TargetGeneration, StringComparison.Ordinal) ||
            !Fixed(reader.GetString(3), binding.TargetObservationSha256))
        {
            throw Error("canonical_delta_fence_stale", "The pre-provisioned canonical target fence is absent or stale.");
        }
    }

    private static async Task<bool> ValidateReplayAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CanonicalDeltaTargetBinding binding,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            SELECT plan_sha256, source_cutoff_utc, target_observation_sha256
            FROM legacy_migration_internal.delta_journal
            WHERE plan_sha256=$1 OR plan_id=$2
            FOR UPDATE;
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(binding.PlanSha256);
        _ = command.Parameters.AddWithValue(binding.PlanId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) &&
            (!Fixed(reader.GetString(0), binding.PlanSha256) || reader.GetFieldValue<DateTimeOffset>(1) != binding.SourceCutoffUtc ||
            !Fixed(reader.GetString(2), binding.TargetObservationSha256)
            ? throw Error("canonical_delta_replay_conflict", "A conflicting canonical delta execution already uses this plan identity.")
            : true);
    }

    private static string ComputeOperationsSha256(DeltaSynchronizationPlan plan, string database)
    {
        DeltaDatabasePlan selected = plan.Databases.Single(item => string.Equals(item.Database, database, StringComparison.Ordinal));
        string joined = string.Join('|', selected.Tables.OrderBy(item => item.Table, StringComparer.Ordinal)
            .Select(item => $"{item.Table}:{item.OperationsSha256}"));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(joined))).ToLowerInvariant();
    }

    internal static string Qualified(string schema, string table)
    {
        return $"{PostgreSqlShadowTarget.QuoteIdentifier(schema)}.{PostgreSqlShadowTarget.QuoteIdentifier(table)}";
    }

    internal static bool Hash(string value)
    {
        return value.Length == 64 && value.All(char.IsAsciiHexDigit);
    }

    internal static bool Fixed(string left, string right)
    {
        return Hash(left) && Hash(right) &&
        CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(left.ToLowerInvariant()), Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    internal static DeltaExecutionException Error(string code, string message)
    {
        return new(code, message);
    }
}

internal sealed class PostgreSqlDeltaCanonicalTransaction(
    NpgsqlConnection connection,
    NpgsqlTransaction transaction,
    CanonicalDeltaTargetBinding binding,
    DatabaseSchemaPlan schema,
    bool replay,
    IReadOnlyDictionary<string, int> upsertOrder,
    string operationsSha256) : IDeltaCanonicalTransaction
{
    private bool _completed;
    private bool _checkpointRecorded;
    private int _lastUpsertOrder = -1;
    private int _lastDeleteOrder = -1;

    public DeltaExecutionDisposition Disposition => replay ? DeltaExecutionDisposition.AlreadyCommitted : DeltaExecutionDisposition.Pending;

    public async Task ApplyAsync(TableCopyPlan table, CanonicalDeltaOperation operation, MigrationRow? source, MigrationRow? target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(table);
        if (Disposition != DeltaExecutionDisposition.Pending || _checkpointRecorded || !schema.Tables.Contains(table))
        {
            throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_state_invalid", "The canonical delta transaction cannot accept this operation in its current state.");
        }

        ValidateTable(table);
        string tableName = $"{table.TargetSchema}.{table.TargetTable}";
        int upsertRank = upsertOrder[tableName];
        int deleteRank = schema.Tables.Count - 1 - upsertRank;
        if ((operation.Kind is DeltaOperationKind.Insert or DeltaOperationKind.Update && upsertRank < _lastUpsertOrder) ||
            (operation.Kind == DeltaOperationKind.Delete && deleteRank < _lastDeleteOrder))
        {
            throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_foreign_key_order_invalid", "Canonical delta operations are outside signed foreign-key order.");
        }
        if (operation.Kind is DeltaOperationKind.Insert or DeltaOperationKind.Update)
        {
            _lastUpsertOrder = upsertRank;
        }

        if (operation.Kind == DeltaOperationKind.Delete)
        {
            _lastDeleteOrder = deleteRank;
        }

        MigrationRow row = source ?? target ?? throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_row_missing", "The resolved canonical row is missing.");
        {
            ValidateRow(table, row);
            string sourceHash = CanonicalRowFingerprint.Compute(table, [row]);
            if (operation.Kind is DeltaOperationKind.Insert or DeltaOperationKind.Update &&
                (!PostgreSqlDeltaCanonicalTarget.Hash(operation.SourceRowSha256 ?? string.Empty) ||
                 !PostgreSqlDeltaCanonicalTarget.Fixed(sourceHash, operation.SourceRowSha256!)))
            {
                throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_source_row_drift", "A resolved source row does not match its signed fingerprint.");
            }

            if (operation.Kind is DeltaOperationKind.Update or DeltaOperationKind.Delete)
            {
                MigrationRow current = await ReadCurrentAsync(table, target!, cancellationToken).ConfigureAwait(false);
                string currentHash = CanonicalRowFingerprint.Compute(table, [current]);
                if (!PostgreSqlDeltaCanonicalTarget.Hash(operation.TargetRowSha256 ?? string.Empty) ||
                    !PostgreSqlDeltaCanonicalTarget.Fixed(currentHash, operation.TargetRowSha256!))
                {
                    throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_target_row_drift", "A canonical target row changed after planning.");
                }
            }

            int affected = operation.Kind switch
            {
                DeltaOperationKind.Insert => await InsertAsync(table, source!, cancellationToken).ConfigureAwait(false),
                DeltaOperationKind.Update => await UpdateAsync(table, source!, cancellationToken).ConfigureAwait(false),
                DeltaOperationKind.Delete => await DeleteAsync(table, target!, cancellationToken).ConfigureAwait(false),
                _ => throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_operation_invalid", "The delta operation is unsupported."),
            };
            if (affected != 1)
            {
                throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_affected_count_invalid", "A canonical row operation did not affect exactly one row.");
            }
        }
    }

    private async Task RecordCheckpointAsync(CancellationToken cancellationToken)
    {
        if (Disposition != DeltaExecutionDisposition.Pending || _checkpointRecorded || !PostgreSqlDeltaCanonicalTarget.Hash(operationsSha256))
        {
            throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_checkpoint_invalid", "The atomic canonical checkpoint is invalid or duplicated.");
        }

        await using var command = new NpgsqlCommand("""
            INSERT INTO legacy_migration_internal.delta_journal
                (plan_sha256, plan_id, source_cutoff_utc, target_observation_sha256, operations_sha256, committed_at_utc)
            VALUES ($1,$2,$3,$4,$5,clock_timestamp());
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(binding.PlanSha256);
        _ = command.Parameters.AddWithValue(binding.PlanId);
        _ = command.Parameters.AddWithValue(binding.SourceCutoffUtc);
        _ = command.Parameters.AddWithValue(binding.TargetObservationSha256);
        _ = command.Parameters.AddWithValue(operationsSha256);
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
        {
            throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_checkpoint_write_failed", "The atomic canonical checkpoint was not written.");
        }
        _checkpointRecorded = true;
    }

    public async Task CommitAsync(string planSha256, CancellationToken cancellationToken)
    {
        if (_completed || !PostgreSqlDeltaCanonicalTarget.Fixed(planSha256, binding.PlanSha256))
        {
            throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_commit_invalid", "Canonical delta commit does not match the opened signed plan.");
        }
        if (Disposition == DeltaExecutionDisposition.Pending)
        {
            await RecordCheckpointAsync(cancellationToken).ConfigureAwait(false);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        _completed = true;
    }

    public async ValueTask DisposeAsync()
    {
        if (!_completed)
        {
            try { await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false); }
            catch (ObjectDisposedException) { }
        }
        await transaction.DisposeAsync().ConfigureAwait(false);
        await connection.DisposeAsync().ConfigureAwait(false);
        _completed = true;
    }

    private async Task<MigrationRow> ReadCurrentAsync(TableCopyPlan table, MigrationRow row, CancellationToken token)
    {
        string columns = string.Join(", ", table.OrderedColumns.Select(PostgreSqlShadowTarget.QuoteIdentifier));
        await using var command = new NpgsqlCommand($"SELECT {columns} FROM {PostgreSqlDeltaCanonicalTarget.Qualified(table.TargetSchema, table.TargetTable)} WHERE {WhereKey(table)} FOR UPDATE;", connection, transaction);
        AddKeys(command, table, row);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
        if (!await reader.ReadAsync(token).ConfigureAwait(false))
        {
            throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_target_row_missing", "The planned canonical target row is missing.");
        }

        var values = new Dictionary<string, object?>(StringComparer.Ordinal);
        for (var index = 0; index < table.OrderedColumns.Count; index++)
        {
            values.Add(table.OrderedColumns[index], await reader.IsDBNullAsync(index, token).ConfigureAwait(false) ? null : reader.GetValue(index));
        }

        return new(values);
    }

    private async Task<int> InsertAsync(TableCopyPlan table, MigrationRow row, CancellationToken token)
    {
        string[] columns = [.. table.OrderedColumns.Except(table.GeneratedColumns.Select(item => item.Column), StringComparer.Ordinal)];
        string names = string.Join(", ", columns.Select(PostgreSqlShadowTarget.QuoteIdentifier));
        string parameters = string.Join(", ", columns.Select((_, index) => $"${index + 1}"));
        await using var command = new NpgsqlCommand($"INSERT INTO {PostgreSqlDeltaCanonicalTarget.Qualified(table.TargetSchema, table.TargetTable)} ({names}) VALUES ({parameters});", connection, transaction);
        foreach (string column in columns)
        {
            _ = command.Parameters.AddWithValue(row.Values[column] ?? DBNull.Value);
        }

        return await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
    }

    private async Task<int> UpdateAsync(TableCopyPlan table, MigrationRow row, CancellationToken token)
    {
        string[] columns = [.. table.OrderedColumns.Except(table.PrimaryKey!.Columns, StringComparer.Ordinal).Except(table.GeneratedColumns.Select(item => item.Column), StringComparer.Ordinal)];
        if (columns.Length == 0)
        {
            throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_update_empty", "A canonical update has no mutable columns.");
        }

        string set = string.Join(", ", columns.Select((column, index) => $"{PostgreSqlShadowTarget.QuoteIdentifier(column)}=${index + 1}"));
        await using var command = new NpgsqlCommand($"UPDATE {PostgreSqlDeltaCanonicalTarget.Qualified(table.TargetSchema, table.TargetTable)} SET {set} WHERE {WhereKey(table, columns.Length)};", connection, transaction);
        foreach (string column in columns)
        {
            _ = command.Parameters.AddWithValue(row.Values[column] ?? DBNull.Value);
        }

        AddKeys(command, table, row);
        return await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
    }

    private async Task<int> DeleteAsync(TableCopyPlan table, MigrationRow row, CancellationToken token)
    {
        await using var command = new NpgsqlCommand($"DELETE FROM {PostgreSqlDeltaCanonicalTarget.Qualified(table.TargetSchema, table.TargetTable)} WHERE {WhereKey(table)};", connection, transaction);
        AddKeys(command, table, row);
        return await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
    }

    private static string WhereKey(TableCopyPlan table, int offset = 0)
    {
        return string.Join(" AND ", table.PrimaryKey!.Columns.Select((column, index) => $"{PostgreSqlShadowTarget.QuoteIdentifier(column)}=${offset + index + 1}"));
    }

    private static void AddKeys(NpgsqlCommand command, TableCopyPlan table, MigrationRow row)
    {
        foreach (string key in table.PrimaryKey!.Columns)
        {
            _ = command.Parameters.AddWithValue(row.Values[key] ?? DBNull.Value);
        }
    }

    private static void ValidateTable(TableCopyPlan table)
    {
        if (table.PrimaryKey is null || table.PrimaryKey.Columns.Count == 0)
        {
            throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_primary_key_required", "Canonical delta DML requires a primary key.");
        }
    }

    private static void ValidateRow(TableCopyPlan table, MigrationRow row)
    {
        if (row.Values.Count != table.OrderedColumns.Count || table.OrderedColumns.Any(column => !row.Values.ContainsKey(column)) || table.PrimaryKey!.Columns.Any(column => row.Values[column] is null or DBNull))
        {
            throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_row_invalid", "The resolved canonical row does not match the signed table shape.");
        }
    }
}

internal static class CanonicalForeignKeyOrder
{
    internal static IReadOnlyDictionary<string, int> Build(DatabaseSchemaPlan schema)
    {
        string[] names = [.. schema.Tables.Select(Name).OrderBy(value => value, StringComparer.Ordinal)];
        var outgoing = names.ToDictionary(name => name, _ => new HashSet<string>(StringComparer.Ordinal), StringComparer.Ordinal);
        var indegree = names.ToDictionary(name => name, _ => 0, StringComparer.Ordinal);
        foreach (TableCopyPlan child in schema.Tables)
        {
            string childName = Name(child);
            foreach (ForeignKeyCopyPlan foreignKey in child.ForeignKeys)
            {
                string parentName = $"{foreignKey.ReferencedSchema}.{foreignKey.ReferencedTable}";
                if (!outgoing.TryGetValue(parentName, out HashSet<string>? children) || !children.Add(childName))
                {
                    continue;
                }

                indegree[childName]++;
            }
        }

        var ready = new SortedSet<string>(indegree.Where(item => item.Value == 0).Select(item => item.Key), StringComparer.Ordinal);
        var ordered = new List<string>(names.Length);
        while (ready.Count != 0)
        {
            string current = ready.Min!;
            _ = ready.Remove(current);
            ordered.Add(current);
            foreach (string child in outgoing[current].OrderBy(value => value, StringComparer.Ordinal))
            {
                if (--indegree[child] == 0)
                {
                    _ = ready.Add(child);
                }
            }
        }
        return ordered.Count != names.Length
            ? throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_foreign_key_cycle", "The canonical schema contains a non-deferrable foreign-key cycle.")
            : (IReadOnlyDictionary<string, int>)ordered.Select((name, index) => (name, index)).ToDictionary(item => item.name, item => item.index, StringComparer.Ordinal);
    }

    private static string Name(TableCopyPlan table)
    {
        return $"{table.TargetSchema}.{table.TargetTable}";
    }
}
