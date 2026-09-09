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
                string? replayReconciliationSha256 = await ValidateReplayAsync(connection, transaction, binding, cancellationToken).ConfigureAwait(false);
                IReadOnlyDictionary<string, int> upsertOrder = CanonicalForeignKeyOrder.Build(schema);
                return new PostgreSqlDeltaCanonicalTransaction(connection, transaction, binding, schema, replayReconciliationSha256, upsertOrder,
                    DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(
                        plan.Databases.Single(item => string.Equals(item.Database, database, StringComparison.Ordinal))));
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

        // Block every concurrent writer while still allowing the separately opened, read-only
        // ordered target cursor to take its single ACCESS SHARE scan.
        await using var tableLocks = new NpgsqlCommand($"LOCK TABLE {tables} IN SHARE ROW EXCLUSIVE MODE;", connection, transaction);
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

    private static async Task<string?> ValidateReplayAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CanonicalDeltaTargetBinding binding,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            SELECT plan_sha256, source_cutoff_utc, target_observation_sha256, reconciliation_sha256
            FROM legacy_migration_internal.delta_journal
            WHERE plan_sha256=$1 OR plan_id=$2
            FOR UPDATE;
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(binding.PlanSha256);
        _ = command.Parameters.AddWithValue(binding.PlanId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? ValidateReplayRow(reader, binding)
            : null;
    }

    private static string ValidateReplayRow(NpgsqlDataReader reader, CanonicalDeltaTargetBinding binding)
    {
        return Fixed(reader.GetString(0), binding.PlanSha256) && SamePostgreSqlTimestamp(reader.GetFieldValue<DateTimeOffset>(1), binding.SourceCutoffUtc) &&
            Fixed(reader.GetString(2), binding.TargetObservationSha256) && Hash(reader.GetString(3))
            ? reader.GetString(3).ToLowerInvariant()
            : throw Error("canonical_delta_replay_conflict", "A conflicting canonical delta execution already uses this plan identity.");
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

    private static bool SamePostgreSqlTimestamp(DateTimeOffset stored, DateTimeOffset expected)
    {
        const long ticksPerMicrosecond = TimeSpan.TicksPerMillisecond / 1000;
        long storedTicks = stored.ToUniversalTime().Ticks;
        long expectedTicks = expected.ToUniversalTime().Ticks;
        return (storedTicks - (storedTicks % ticksPerMicrosecond)) ==
            (expectedTicks - (expectedTicks % ticksPerMicrosecond));
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
    string? replayReconciliationSha256,
    IReadOnlyDictionary<string, int> upsertOrder,
    string operationsSha256) : IDeltaCanonicalTransaction
{
    private bool _completed;
    private bool _checkpointRecorded;
    private string? _reconciliationSha256;
    private int _lastUpsertOrder = -1;
    private int _lastDeleteOrder = -1;

    public DeltaExecutionDisposition Disposition => replayReconciliationSha256 is not null
        ? DeltaExecutionDisposition.AlreadyCommitted
        : DeltaExecutionDisposition.Pending;

    public string? ReconciliationSha256 => replayReconciliationSha256 ?? _reconciliationSha256;

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
            bool sourceContainsStreamingLob = source?.Values.Values.Any(value => value is StreamingLob) == true;
            string? sourceHash = sourceContainsStreamingLob ? null : CanonicalRowFingerprint.Compute(table, [row]);
            if (operation.Kind is DeltaOperationKind.Insert or DeltaOperationKind.Update && !sourceContainsStreamingLob &&
                (!PostgreSqlDeltaCanonicalTarget.Hash(operation.SourceRowSha256 ?? string.Empty) ||
                 !PostgreSqlDeltaCanonicalTarget.Fixed(sourceHash!, operation.SourceRowSha256!)))
            {
                throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_source_row_drift", "A resolved source row does not match its signed fingerprint.");
            }

            if (operation.Kind is DeltaOperationKind.Update or DeltaOperationKind.Delete)
            {
                string currentHash = CanonicalRowFingerprint.Compute(table, [target!]);
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
            if (sourceContainsStreamingLob)
            {
                string consumedHash = CanonicalRowFingerprint.Compute(table, [source!]);
                if (!PostgreSqlDeltaCanonicalTarget.Hash(operation.SourceRowSha256 ?? string.Empty) ||
                    !PostgreSqlDeltaCanonicalTarget.Fixed(consumedHash, operation.SourceRowSha256!))
                {
                    throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_source_row_drift", "A streamed source row does not match its signed fingerprint.");
                }
            }
        }
    }

    public async Task<string> ReconcileAsync(
        DatabaseReconciliationEvidence expected,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expected);
        if (Disposition != DeltaExecutionDisposition.Pending || _checkpointRecorded || _reconciliationSha256 is not null)
        {
            throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_reconciliation_invalid", "Canonical reconciliation is unavailable in the current transaction state.");
        }

        ValidateExpectedReconciliation(expected);
        await AlignSequencesAsync(expected.SequenceNextValues, cancellationToken).ConfigureAwait(false);
        await using var inspection = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
        string targetSchemaSha256 = await inspection.InspectSchemaAsync(schema, cancellationToken).ConfigureAwait(false);
        ReconciliationDiagnostics.CompareSchema(schema.Database, schema.TargetSchemaSha256, targetSchemaSha256);
        var tables = new List<TableReconciliationEvidence>(schema.Tables.Count);
        foreach (TableCopyPlan table in schema.Tables)
        {
            TableReconciliationEvidence observed = await inspection.InspectTableAsync(table, cancellationToken).ConfigureAwait(false);
            TableReconciliationEvidence expectedTable = expected.Tables.Single(item =>
                string.Equals(item.Table, $"{table.TargetSchema}.{table.TargetTable}", StringComparison.Ordinal));
            ReconciliationDiagnostics.CompareTable(schema.Database, expectedTable, observed);
            tables.Add(observed);
        }

        IReadOnlyDictionary<string, long> sequences = await inspection
            .InspectSequenceNextValuesAsync(schema, cancellationToken).ConfigureAwait(false);
        ReconciliationDiagnostics.CompareSequences(schema, expected.SequenceNextValues, sequences);
        var observedEvidence = new DatabaseReconciliationEvidence(
            schema.Database,
            schema.SourceSchemaSha256,
            targetSchemaSha256,
            tables.AsReadOnly())
        {
            SequenceNextValues = sequences,
        };
        _reconciliationSha256 = DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(observedEvidence);
        return _reconciliationSha256;
    }

    private void ValidateExpectedReconciliation(DatabaseReconciliationEvidence expected)
    {
        string[] expectedTables = [.. schema.Tables.Select(table => $"{table.TargetSchema}.{table.TargetTable}").Order(StringComparer.Ordinal)];
        string[] observedTables = [.. expected.Tables.Select(table => table.Table).Order(StringComparer.Ordinal)];
        if (!string.Equals(expected.Database, schema.Database, StringComparison.Ordinal) ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(expected.SourceSchemaSha256, schema.SourceSchemaSha256) ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(expected.TargetSchemaSha256, schema.TargetSchemaSha256) ||
            !expectedTables.SequenceEqual(observedTables, StringComparer.Ordinal) ||
            observedTables.Distinct(StringComparer.Ordinal).Count() != observedTables.Length)
        {
            throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_reconciliation_shape_invalid", "Source reconciliation evidence does not match the signed database schema.");
        }
    }

    private async Task AlignSequencesAsync(
        IReadOnlyDictionary<string, long> expected,
        CancellationToken cancellationToken)
    {
        string[] planned = [.. schema.Tables.SelectMany(table => table.Identities.Select(identity =>
            $"{table.TargetSchema}.{table.TargetTable}.{identity.Column}")).Order(StringComparer.Ordinal)];
        if (!planned.SequenceEqual(expected.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal))
        {
            throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_sequence_shape_invalid", "Source sequence evidence does not cover the signed identity inventory.");
        }

        foreach (TableCopyPlan table in schema.Tables)
        {
            foreach (IdentityCopyPlan identity in table.Identities.OrderBy(item => item.Column, StringComparer.Ordinal))
            {
                string key = $"{table.TargetSchema}.{table.TargetTable}.{identity.Column}";
                const string sequenceSql = "SELECT pg_get_serial_sequence($1, $2);";
                await using var sequence = new NpgsqlCommand(sequenceSql, connection, transaction);
                _ = sequence.Parameters.AddWithValue(PostgreSqlDeltaCanonicalTarget.Qualified(table.TargetSchema, table.TargetTable));
                _ = sequence.Parameters.AddWithValue(identity.Column);
                string? sequenceName = (string?)await sequence.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(sequenceName))
                {
                    throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_sequence_missing", "A signed identity sequence is unavailable on the target.");
                }

                string restart = expected[key].ToString(System.Globalization.CultureInfo.InvariantCulture);
                await using var setValue = new NpgsqlCommand(
                    $"ALTER SEQUENCE {PostgreSqlShadowTarget.QuoteQualifiedIdentifier(sequenceName)} RESTART WITH {restart};",
                    connection,
                    transaction);
                _ = await setValue.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
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
                (plan_sha256, plan_id, source_cutoff_utc, target_observation_sha256, operations_sha256, reconciliation_sha256, committed_at_utc)
            VALUES ($1,$2,$3,$4,$5,$6,clock_timestamp());
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(binding.PlanSha256);
        _ = command.Parameters.AddWithValue(binding.PlanId);
        _ = command.Parameters.AddWithValue(binding.SourceCutoffUtc);
        _ = command.Parameters.AddWithValue(binding.TargetObservationSha256);
        _ = command.Parameters.AddWithValue(operationsSha256);
        _ = command.Parameters.AddWithValue(_reconciliationSha256!);
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
        {
            throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_checkpoint_write_failed", "The atomic canonical checkpoint was not written.");
        }
        _checkpointRecorded = true;
    }

    public async Task CommitAsync(string planSha256, string reconciliationSha256, CancellationToken cancellationToken)
    {
        if (_completed || !PostgreSqlDeltaCanonicalTarget.Fixed(planSha256, binding.PlanSha256) ||
            _reconciliationSha256 is null || !PostgreSqlDeltaCanonicalTarget.Fixed(reconciliationSha256, _reconciliationSha256))
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

    private async Task<int> InsertAsync(TableCopyPlan table, MigrationRow row, CancellationToken token)
    {
        string[] columns = [.. table.OrderedColumns.Except(table.GeneratedColumns.Select(item => item.Column), StringComparer.Ordinal)];
        string names = string.Join(", ", columns.Select(PostgreSqlShadowTarget.QuoteIdentifier));
        string parameters = string.Join(", ", columns.Select((column, index) => ParameterExpression(row, column, index + 1)));
        await using var command = new NpgsqlCommand($"INSERT INTO {PostgreSqlDeltaCanonicalTarget.Qualified(table.TargetSchema, table.TargetTable)} ({names}) VALUES ({parameters});", connection, transaction);
        await using ParameterResources resources = await AddValuesAsync(command, row, columns, token).ConfigureAwait(false);
        return await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
    }

    private async Task<int> UpdateAsync(TableCopyPlan table, MigrationRow row, CancellationToken token)
    {
        string[] columns = [.. table.OrderedColumns.Except(table.PrimaryKey!.Columns, StringComparer.Ordinal).Except(table.GeneratedColumns.Select(item => item.Column), StringComparer.Ordinal)];
        if (columns.Length == 0)
        {
            throw PostgreSqlDeltaCanonicalTarget.Error("canonical_delta_update_empty", "A canonical update has no mutable columns.");
        }

        string set = string.Join(", ", columns.Select((column, index) => $"{PostgreSqlShadowTarget.QuoteIdentifier(column)}={ParameterExpression(row, column, index + 1)}"));
        await using var command = new NpgsqlCommand($"UPDATE {PostgreSqlDeltaCanonicalTarget.Qualified(table.TargetSchema, table.TargetTable)} SET {set} WHERE {WhereKey(table, columns.Length)};", connection, transaction);
        await using ParameterResources resources = await AddValuesAsync(command, row, columns, token).ConfigureAwait(false);

        AddKeys(command, table, row);
        return await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
    }

    private static async Task<ParameterResources> AddValuesAsync(
        NpgsqlCommand command,
        MigrationRow row,
        IEnumerable<string> columns,
        CancellationToken token)
    {
        var resources = new ParameterResources();
        try
        {
            foreach (string column in columns)
            {
                object? value = row.Values[column];
                if (value is StreamingLob streaming)
                {
                    Stream stream = await streaming.OpenReadAsync(token).ConfigureAwait(false);
                    resources.Add(stream);
                    _ = command.Parameters.Add(new NpgsqlParameter
                    {
                        DataTypeName = "bytea",
                        Value = stream,
                    });
                }
                else if (value is BufferedStreamingLob buffered)
                {
                    Stream stream = buffered.OpenRead();
                    resources.Add(stream);
                    _ = command.Parameters.Add(new NpgsqlParameter
                    {
                        DataTypeName = "bytea",
                        Value = stream,
                    });
                }
                else
                {
                    _ = command.Parameters.AddWithValue(value ?? DBNull.Value);
                }
            }
            return resources;
        }
        catch
        {
            await resources.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private sealed class ParameterResources : IAsyncDisposable
    {
        private readonly List<Stream> _resources = [];

        internal void Add(Stream stream)
        {
            _resources.Add(stream);
        }

        public async ValueTask DisposeAsync()
        {
            foreach (Stream stream in _resources)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private static string ParameterExpression(MigrationRow row, string column, int ordinal)
    {
        object? value = row.Values[column];
        StreamingLobKind? kind = value switch
        {
            StreamingLob streaming => streaming.Kind,
            BufferedStreamingLob buffered => buffered.Kind,
            _ => null,
        };
        return kind == StreamingLobKind.Text ? $"convert_from(${ordinal},'UTF8')" : $"${ordinal}";
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
        return ForeignKeyExecutionOrder.Create(schema.Tables)
            .Select((table, index) => (name: Name(table), index))
            .ToDictionary(item => item.name, item => item.index, StringComparer.Ordinal);
    }

    private static string Name(TableCopyPlan table)
    {
        return $"{table.TargetSchema}.{table.TargetTable}";
    }
}
