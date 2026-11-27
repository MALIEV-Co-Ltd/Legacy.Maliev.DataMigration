using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record DualTargetCapturedTargetObservation(string RuntimeSha256, DeltaTargetAuthority Authority,
    string Generation, CurrentAppOwnedMaintenancePin Maintenance, IReadOnlyDictionary<string, string> NativeBeforeSha256)
{
    internal string Sha256 => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
    {
        Domain = "dual-target-captured-runtime-identity-v1",
        RuntimeSha256,
        Authority,
        Generation,
        Maintenance
    }))).ToLowerInvariant();
}
internal sealed record DualTargetCapturedStorage(uint FileNode, long Blocks);

// Fixed companion to the real Npgsql transaction. No callback, connection or SQL is exposed.
internal sealed class DualTargetCapturedDeltaNativeGuard
{
    private static readonly string[] MetadataTables = ["delta_fence", "delta_journal"];
    private sealed record Before(CurrentAppOwnedRetained31Observation Native, IReadOnlyDictionary<string, DualTargetCapturedStorage> Storage,
        string Journal, string OtherFences,
        IReadOnlyDictionary<string, long> SequenceNext, DateTimeOffset Began);
    private readonly DeltaSynchronizationPlan _plan;
    private readonly DualTargetCapturedTargetObservation _observation;
    private readonly Dictionary<string, Before> _before = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _settled = new(StringComparer.Ordinal);
    private readonly HashSet<string> _completed = new(StringComparer.Ordinal);
    private readonly DateTimeOffset _expires;

    private DualTargetCapturedDeltaNativeGuard(DeltaSynchronizationPlan plan, DualTargetCapturedTargetObservation observation,
        DateTimeOffset expires)
    {
        _plan = JsonSerializer.Deserialize<DeltaSynchronizationPlan>(JsonSerializer.SerializeToUtf8Bytes(plan)) ?? throw DualTargetCapturedDeltaContract.Invalid();
        _observation = observation with { NativeBeforeSha256 = observation.NativeBeforeSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal) };
        _expires = expires;
    }

    internal static DualTargetCapturedDeltaNativeGuard ForDisposable(DualTargetCapturedDeltaBundle bundle,
        DualTargetCapturedDeltaPurpose purpose, DualTargetCapturedTargetObservation observation, FreshSchemaPlan schema,
        IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        if (purpose is not (DualTargetCapturedDeltaPurpose.ProductionProof or DualTargetCapturedDeltaPurpose.LocalProof))
        { throw DualTargetCapturedDeltaContract.Invalid(); }
        DualTargetCapturedDeltaContract.Verify(bundle, schema, trust, now);
        DeltaSynchronizationPlan plan = bundle.Plans.Single(x => x.Purpose == purpose).Plan;
        RequireObservation(bundle.Plans.Single(x => x.Purpose == purpose), observation, purpose);
        return new(plan, observation, now.AddMinutes(15));
    }

    internal static DualTargetCapturedDeltaNativeGuard ForPersistent(DualTargetCapturedDeltaReview review,
        DualTargetCapturedDeltaBundle bundle, DualTargetCapturedDeltaPurpose purpose,
        Exact23DeltaReconciliationResult proof, DualTargetCapturedTargetObservation observation, FreshSchemaPlan schema,
        IReceiptAttestationTrustStore trust, string reviewKeyFingerprintSha256, string acceptedMain, DateTimeOffset now)
    {
        DualTargetCapturedDeltaAdmission.Require(review, bundle, purpose, proof, schema, trust,
            reviewKeyFingerprintSha256, observation.RuntimeSha256, acceptedMain, now);
        DeltaSynchronizationPlan plan = bundle.Plans.Single(x => x.Purpose == purpose).Plan;
        RequireObservation(bundle.Plans.Single(x => x.Purpose == purpose), observation, purpose);
        return !review.NativeBeforeSha256.OrderBy(x => x.Key, StringComparer.Ordinal).SequenceEqual(
            observation.NativeBeforeSha256.OrderBy(x => x.Key, StringComparer.Ordinal))
            ? throw DualTargetCapturedDeltaContract.Invalid()
            : new(plan, observation, review.ExpiresAtUtc);
    }

    private static void RequireObservation(DualTargetCapturedDeltaPlan member, DualTargetCapturedTargetObservation observation, DualTargetCapturedDeltaPurpose purpose)
    {
        DeltaSynchronizationPlan plan = member.Plan;
        string kind = purpose is DualTargetCapturedDeltaPurpose.Production or DualTargetCapturedDeltaPurpose.ProductionProof ?
            DeltaTargetAuthorityKind.ProductionCloudNativePg : DeltaTargetAuthorityKind.LocalAspire;
        if (plan.TargetAuthority != observation.Authority || plan.TargetGeneration != observation.Generation ||
            plan.TargetObservationSha256 != observation.Sha256 ||
            !ReviewedProductionRepairInventory.MatchesKeys(kind, observation.NativeBeforeSha256.Keys) ||
            !member.Observation.NativeBeforeSha256.OrderBy(x => x.Key, StringComparer.Ordinal).SequenceEqual(
                observation.NativeBeforeSha256.OrderBy(x => x.Key, StringComparer.Ordinal)))
        { throw DualTargetCapturedDeltaContract.Invalid(); }
    }

    internal async Task BeginAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        DeltaSynchronizationPlan plan, DatabaseSchemaPlan schema, CancellationToken ct)
    {
        if (DateTimeOffset.UtcNow >= _expires || DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan) !=
            DeltaSynchronizationPlanCanonicalizer.ComputeSha256(_plan) || _before.ContainsKey(schema.Database) || _completed.Contains(schema.Database) ||
            connection.Database != schema.Database || transaction.Connection != connection || transaction.IsolationLevel != System.Data.IsolationLevel.Serializable)
        { throw DualTargetCapturedDeltaContract.Invalid(); }
        DualTargetCapturedDeltaContract.RequireZeroDeleteAndEffects(schema, plan.Databases.Single(x => x.Database == schema.Database).Tables);
        await DualTargetCapturedDeltaMaintenance.RequireInstalledAsync(connection, transaction, _observation.Authority, _observation.Maintenance, ct).ConfigureAwait(false);
        await using (var system = new NpgsqlCommand("SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex') FROM pg_control_system();", connection, transaction))
        {
            if ((string?)await system.ExecuteScalarAsync(ct).ConfigureAwait(false) != _observation.Authority.SystemIdentifierSha256)
            { throw DualTargetCapturedDeltaContract.Invalid(); }
        }
        var tables = new List<(string Schema, string Table)>();
        await using (var query = new NpgsqlCommand("SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' ORDER BY n.nspname COLLATE \"C\",c.relname COLLATE \"C\";", connection, transaction))
        await using (var reader = await query.ExecuteReaderAsync(ct).ConfigureAwait(false))
        { while (await reader.ReadAsync(ct).ConfigureAwait(false)) { tables.Add((reader.GetString(0), reader.GetString(1))); } }
        foreach (var (Schema, Table) in tables)
        {
            await using var locked = new NpgsqlCommand("LOCK TABLE " + Qualified(Schema, Table) + " IN SHARE ROW EXCLUSIVE MODE;", connection, transaction);
            _ = await locked.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        CurrentAppOwnedRetained31Observation before = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
        IReadOnlyDictionary<string, DualTargetCapturedStorage> storageBefore = await StorageAsync(connection, transaction, ct).ConfigureAwait(false);
        if (PreimageHash(before.Snapshot.Sha256, storageBefore) != _observation.NativeBeforeSha256[schema.Database]) { throw DualTargetCapturedDeltaContract.Invalid(); }
        RequireMetadataColumns(before);
        string journal = await RowsAsync(connection, transaction, "delta_journal", "plan_sha256<>$1", plan.PlanId, ct).ConfigureAwait(false);
        string fences = await RowsAsync(connection, transaction, "delta_fence", "database_name<>$2", plan.PlanId, ct).ConfigureAwait(false);
        await using (var existing = new NpgsqlCommand("SELECT count(*) FROM legacy_migration_internal.delta_journal WHERE plan_sha256=$1;", connection, transaction))
        {
            _ = existing.Parameters.AddWithValue(DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan));
            if ((long)(await existing.ExecuteScalarAsync(ct).ConfigureAwait(false))! != 0) { throw DualTargetCapturedDeltaContract.Invalid(); }
        }
        var next = plan.SourceCaptureManifest!.Databases.Single(x => x.Database == schema.Database).SourceReconciliation.SequenceNextValues;
        foreach (TableCopyPlan table in schema.Tables)
        {
            foreach (IdentityCopyPlan identity in table.Identities)
            {
                await using var lookup = new NpgsqlCommand("SELECT pg_get_serial_sequence($1,$2);", connection, transaction);
                _ = lookup.Parameters.AddWithValue(Qualified(table.TargetSchema, table.TargetTable)); _ = lookup.Parameters.AddWithValue(identity.Column);
                string sequence = (string?)await lookup.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? throw DualTargetCapturedDeltaContract.Invalid();
                await using var bound = new NpgsqlCommand("SELECT CASE WHEN is_called THEN last_value+$1 ELSE last_value END <= $2 FROM " + PostgreSqlShadowTarget.QuoteQualifiedIdentifier(sequence) + ";", connection, transaction);
                _ = bound.Parameters.AddWithValue(identity.IncrementValue);
                _ = bound.Parameters.AddWithValue(next[table.TargetSchema + "." + table.TargetTable + "." + identity.Column]);
                if (identity.IncrementValue <= 0 || await bound.ExecuteScalarAsync(ct).ConfigureAwait(false) is not true) { throw DualTargetCapturedDeltaContract.Invalid(); }
            }
        }

        DateTimeOffset began;
        await using (var clock = new NpgsqlCommand("SELECT clock_timestamp();", connection, transaction))
        await using (var reader = await clock.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw DualTargetCapturedDeltaContract.Invalid(); }
            began = reader.GetFieldValue<DateTimeOffset>(0);
        }
        _before.Add(schema.Database, new(before, storageBefore, journal, fences, next, began));
        // Existing metadata only. A generation rollover, absent fence or legacy journal needs its own reviewed route.
        await using var fence = new NpgsqlCommand("UPDATE legacy_migration_internal.delta_fence SET schema_plan_sha256=$1,target_schema_sha256=$2,target_observation_sha256=$3 WHERE database_name=$4 AND target_generation=$5;", connection, transaction);
        _ = fence.Parameters.AddWithValue(plan.SchemaPlanSha256); _ = fence.Parameters.AddWithValue(schema.TargetSchemaSha256);
        _ = fence.Parameters.AddWithValue(plan.TargetObservationSha256); _ = fence.Parameters.AddWithValue(schema.Database);
        _ = fence.Parameters.AddWithValue(plan.TargetGeneration);
        if (await fence.ExecuteNonQueryAsync(ct).ConfigureAwait(false) != 1) { throw DualTargetCapturedDeltaContract.Invalid(); }
    }

    internal async Task BeforeCommitAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CanonicalDeltaTargetBinding binding, DatabaseSchemaPlan schema, string reconciliationSha256, CancellationToken ct)
    {
        if (!_before.TryGetValue(schema.Database, out Before? before) || !_completed.Add(schema.Database) || DateTimeOffset.UtcNow >= _expires ||
            binding.PlanSha256 != DeltaSynchronizationPlanCanonicalizer.ComputeSha256(_plan)) { throw DualTargetCapturedDeltaContract.Invalid(); }
        await DualTargetCapturedDeltaMaintenance.RequireInstalledAsync(connection, transaction, _observation.Authority, _observation.Maintenance, ct).ConfigureAwait(false);
        CurrentAppOwnedRetained31Observation after = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
        var sequenceIds = new HashSet<string>(StringComparer.Ordinal);
        var sequenceNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (TableCopyPlan table in schema.Tables)
        {
            foreach (IdentityCopyPlan identity in table.Identities)
            {
                string key = table.TargetSchema + "." + table.TargetTable + "." + identity.Column;
                await using var find = new NpgsqlCommand("SELECT c.oid::text,n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=pg_get_serial_sequence($1,$2)::regclass AND c.relkind='S';", connection, transaction);
                _ = find.Parameters.AddWithValue(Qualified(table.TargetSchema, table.TargetTable)); _ = find.Parameters.AddWithValue(identity.Column);
                string id, space, name;
                await using (var reader = await find.ExecuteReaderAsync(ct).ConfigureAwait(false))
                {
                    if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw DualTargetCapturedDeltaContract.Invalid(); }
                    id = reader.GetString(0); space = reader.GetString(1); name = reader.GetString(2);
                    if (await reader.ReadAsync(ct).ConfigureAwait(false)) { throw DualTargetCapturedDeltaContract.Invalid(); }
                }
                if (!sequenceIds.Add(id) || !sequenceNames.Add(space + "." + name)) { throw DualTargetCapturedDeltaContract.Invalid(); }
                await using var tuple = new NpgsqlCommand("SELECT last_value=$1 AND log_cnt=0 AND NOT is_called FROM " + Qualified(space, name) + ";", connection, transaction);
                _ = tuple.Parameters.AddWithValue(before.SequenceNext[key]);
                if (await tuple.ExecuteScalarAsync(ct).ConfigureAwait(false) is not true) { throw DualTargetCapturedDeltaContract.Invalid(); }
                JsonObject oldClass = before.Native.Read("pg_class").Single(x => Value(x, "oid") == id);
                JsonObject newClass = after.Read("pg_class").Single(x => Value(x, "oid") == id);
                if (Value(oldClass, "relfilenode") == "0" || Value(newClass, "relfilenode") == "0" ||
                    Value(oldClass, "relfilenode") == Value(newClass, "relfilenode") ||
                    before.Native.Read("pg_class").Any(x => Value(x, "relfilenode") == Value(newClass, "relfilenode")))
                { throw DualTargetCapturedDeltaContract.Invalid(); }
            }
        }

        RequireNative(before.Native, after, schema, sequenceIds, sequenceNames);
        IReadOnlyDictionary<string, DualTargetCapturedStorage> afterStorage = await StorageAsync(connection, transaction, ct).ConfigureAwait(false);
        if (!before.Storage.Keys.Order(StringComparer.Ordinal).SequenceEqual(afterStorage.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal))
        { throw DualTargetCapturedDeltaContract.Invalid(); }
        var changedTables = _plan.Databases.Single(x => x.Database == schema.Database).Tables.Where(x => x.InsertCount + x.UpdateCount != 0)
            .Select(x => x.Table).ToHashSet(StringComparer.Ordinal);
        foreach (var storage in before.Storage)
        {
            JsonObject relation = before.Native.Read("pg_class").Single(x => Value(x, "oid") == storage.Key);
            JsonObject space = before.Native.Read("pg_namespace").Single(x => Value(x, "oid") == Value(relation, "relnamespace"));
            string name = Value(space, "nspname") + "." + Value(relation, "relname");
            bool changedHeap = Value(relation, "relkind") == "r" && changedTables.Contains(name);
            bool ownMetadataHeap = Value(relation, "relkind") == "r" && name is
                "legacy_migration_internal.delta_journal" or "legacy_migration_internal.delta_fence";
            if (sequenceIds.Contains(storage.Key))
            {
                if (afterStorage[storage.Key].Blocks != storage.Value.Blocks || storage.Value.FileNode == 0 || afterStorage[storage.Key].FileNode == 0 ||
                    Value(relation, "relfilenode") != storage.Value.FileNode.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
                    after.Read("pg_class").Single(x => Value(x, "oid") == storage.Key)["relfilenode"]?.ToString() != afterStorage[storage.Key].FileNode.ToString(System.Globalization.CultureInfo.InvariantCulture))
                { throw DualTargetCapturedDeltaContract.Invalid(); }
                continue;
            }
            if (ownMetadataHeap)
            {
                // One exact bounded journal insert or fence update; their full logical predicates below must also pass.
                if (afterStorage[storage.Key].FileNode != storage.Value.FileNode || afterStorage[storage.Key].Blocks < storage.Value.Blocks ||
                    afterStorage[storage.Key].Blocks > storage.Value.Blocks + 1) { throw DualTargetCapturedDeltaContract.Invalid(); }
                continue;
            }
            if (changedHeap ? afterStorage[storage.Key].FileNode != storage.Value.FileNode || afterStorage[storage.Key].Blocks < storage.Value.Blocks :
                afterStorage[storage.Key] != storage.Value) { throw DualTargetCapturedDeltaContract.Invalid(); }
        }
        if (before.Journal != await RowsAsync(connection, transaction, "delta_journal", "plan_sha256<>$1", _plan.PlanId, ct).ConfigureAwait(false) ||
            before.OtherFences != await RowsAsync(connection, transaction, "delta_fence", "database_name<>$2", _plan.PlanId, ct).ConfigureAwait(false))
        { throw DualTargetCapturedDeltaContract.Invalid(); }
        await using var journal = new NpgsqlCommand("""
            SELECT count(*)=1 AND bool_and(plan_id=$2 AND source_cutoff_utc=$3 AND target_observation_sha256=$4
              AND operations_sha256=$5 AND reconciliation_sha256=$6 AND committed_at_utc>=$7 AND committed_at_utc<=clock_timestamp())
            FROM legacy_migration_internal.delta_journal WHERE plan_sha256=$1;
            """, connection, transaction);
        _ = journal.Parameters.AddWithValue(binding.PlanSha256); _ = journal.Parameters.AddWithValue(binding.PlanId);
        _ = journal.Parameters.AddWithValue(binding.SourceCutoffUtc); _ = journal.Parameters.AddWithValue(binding.TargetObservationSha256);
        _ = journal.Parameters.AddWithValue(DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(_plan.Databases.Single(x => x.Database == schema.Database)));
        _ = journal.Parameters.AddWithValue(reconciliationSha256); _ = journal.Parameters.AddWithValue(before.Began);
        if (await journal.ExecuteScalarAsync(ct).ConfigureAwait(false) is not true) { throw DualTargetCapturedDeltaContract.Invalid(); }
        await using var fence = new NpgsqlCommand("SELECT count(*)=1 AND bool_and(schema_plan_sha256=$2 AND target_schema_sha256=$3 AND target_generation=$4 AND target_observation_sha256=$5) FROM legacy_migration_internal.delta_fence WHERE database_name=$1;", connection, transaction);
        _ = fence.Parameters.AddWithValue(schema.Database); _ = fence.Parameters.AddWithValue(binding.SchemaPlanSha256);
        _ = fence.Parameters.AddWithValue(binding.TargetSchemaSha256); _ = fence.Parameters.AddWithValue(binding.TargetGeneration);
        _ = fence.Parameters.AddWithValue(binding.TargetObservationSha256);
        if (await fence.ExecuteScalarAsync(ct).ConfigureAwait(false) is not true) { throw DualTargetCapturedDeltaContract.Invalid(); }
        // Independent read-only connections observe the complete other-database fleet while
        // this database's transaction can still roll back. Previously committed candidates stay pinned.
        foreach (var database in _observation.NativeBeforeSha256.Where(x => x.Key != schema.Database).OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            var settings = new NpgsqlConnectionStringBuilder(connection.ConnectionString)
            { Database = database.Key, Pooling = false, Options = "-c default_transaction_read_only=on" };
            await using NpgsqlConnection other = connection.CloneWith(settings.ConnectionString);
            await other.OpenAsync(ct).ConfigureAwait(false);
            await using NpgsqlTransaction readback = await other.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            string actual = await CapturePreimageAsync(other, readback, ct).ConfigureAwait(false);
            if (actual != _settled.GetValueOrDefault(database.Key, database.Value)) { throw DualTargetCapturedDeltaContract.Invalid(); }
            await readback.RollbackAsync(ct).ConfigureAwait(false);
        }
        await DualTargetCapturedDeltaMaintenance.RequireInstalledAsync(connection, transaction, _observation.Authority, _observation.Maintenance, ct).ConfigureAwait(false);
        _settled.Add(schema.Database, PreimageHash(after.Snapshot.Sha256, afterStorage));
        _ = _before.Remove(schema.Database);
    }

    internal static void RequireNative(CurrentAppOwnedRetained31Observation before, CurrentAppOwnedRetained31Observation after,
        DatabaseSchemaPlan schema, IReadOnlySet<string> sequenceIds, IReadOnlySet<string> sequenceNames)
    {
        var mutable = schema.Tables.Select(x => x.TargetSchema + "." + x.TargetTable).ToHashSet(StringComparer.Ordinal);
        _ = mutable.Add("legacy_migration_internal.delta_journal"); _ = mutable.Add("legacy_migration_internal.delta_fence");
        if (before.Snapshot.Database != after.Snapshot.Database ||
            !before.Snapshot.Relations.Where(x => !mutable.Contains(x.Schema + "." + x.Name)).SequenceEqual(after.Snapshot.Relations.Where(x => !mutable.Contains(x.Schema + "." + x.Name))) ||
            !before.Snapshot.Sequences.Where(x => !sequenceNames.Contains(x.Schema + "." + x.Name)).SequenceEqual(after.Snapshot.Sequences.Where(x => !sequenceNames.Contains(x.Schema + "." + x.Name))))
        { throw DualTargetCapturedDeltaContract.Invalid(); }
        foreach (string catalog in ConsumerColumnBootstrapNativePreservation.CatalogNames)
        {
            string[] Normalize(CurrentAppOwnedRetained31Observation value)
            {
                return [.. value.Read(catalog).Select(row =>
            {
                if (catalog == "pg_class" && sequenceIds.Contains(Value(row, "oid"))) { row["relfilenode"] = "<verified-sequence-restart>"; }
                return row.ToJsonString();
            }).Order(StringComparer.Ordinal)];
            }

            if (!Normalize(before).SequenceEqual(Normalize(after), StringComparer.Ordinal)) { throw DualTargetCapturedDeltaContract.Invalid(); }
        }
        foreach (JsonObject index in before.Read("pg_class").Where(x => Value(x, "relkind") == "i"))
        {
            string id = Value(index, "oid");
            if (before.Storage(id) != after.Storage(id)) { throw DualTargetCapturedDeltaContract.Invalid(); }
        }
    }

    private async Task<string> RowsAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string table,
        string predicate, Guid planId, CancellationToken ct)
    {
        if (planId != _plan.PlanId || table is not ("delta_journal" or "delta_fence")) { throw DualTargetCapturedDeltaContract.Invalid(); }
        await using var query = new NpgsqlCommand("SELECT encode(sha256(convert_to(coalesce(string_agg(h,'' ORDER BY h COLLATE \"C\"),''),'UTF8')),'hex') FROM (SELECT encode(sha256(convert_to(to_jsonb(x)::text,'UTF8')),'hex') h FROM legacy_migration_internal." + table + " x WHERE " + predicate + ") rows;", connection, transaction);
        _ = query.Parameters.AddWithValue(DeltaSynchronizationPlanCanonicalizer.ComputeSha256(_plan));
        _ = query.Parameters.AddWithValue(connection.Database);
        return (string)(await query.ExecuteScalarAsync(ct).ConfigureAwait(false))!;
    }
    private static string Value(JsonObject row, string name)
    {
        return row[name]?.ToString() ?? "null";
    }

    private static void RequireMetadataColumns(CurrentAppOwnedRetained31Observation native)
    {
        string space = Value(native.Read("pg_namespace").Single(x => Value(x, "nspname") == "legacy_migration_internal"), "oid");
        foreach (string table in MetadataTables)
        {
            string id = Value(native.Read("pg_class").Single(x => Value(x, "relnamespace") == space && Value(x, "relname") == table && Value(x, "relkind") == "r"), "oid");
            string[] expected = table == "delta_fence" ?
                ["database_name", "schema_plan_sha256", "target_schema_sha256", "target_generation", "target_observation_sha256"] :
                ["plan_sha256", "plan_id", "source_cutoff_utc", "target_observation_sha256", "operations_sha256", "reconciliation_sha256", "committed_at_utc"];
            string[] actual = [.. native.Read("pg_attribute").Where(x => Value(x, "attrelid") == id &&
                int.Parse(Value(x, "attnum"), System.Globalization.CultureInfo.InvariantCulture) > 0).Select(x => Value(x, "attname")).Order(StringComparer.Ordinal)];
            if (!actual.SequenceEqual(expected.Order(StringComparer.Ordinal), StringComparer.Ordinal)) { throw DualTargetCapturedDeltaContract.Invalid(); }
        }
    }
    private static async Task<IReadOnlyDictionary<string, DualTargetCapturedStorage>> StorageAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken ct)
    {
        var result = new Dictionary<string, DualTargetCapturedStorage>(StringComparer.Ordinal);
        await using var query = new NpgsqlCommand("SELECT oid::text,coalesce(pg_relation_filenode(oid),0::oid),pg_relation_size(oid)/current_setting('block_size')::bigint FROM pg_class WHERE relkind IN ('r','i','t','S') ORDER BY oid;", connection, transaction);
        await using var reader = await query.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) { result.Add(reader.GetString(0), new(reader.GetFieldValue<uint>(1), reader.GetInt64(2))); }
        return result;
    }
    internal static string PreimageHash(string snapshotSha256, IReadOnlyDictionary<string, DualTargetCapturedStorage> storage)
    {
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
        {
            SnapshotSha256 = snapshotSha256,
            Storage = storage.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new { Oid = x.Key, x.Value.FileNode, x.Value.Blocks }).ToArray()
        }))).ToLowerInvariant();
    }

    internal static async Task<string> CapturePreimageAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    {
        CurrentAppOwnedRetained31Observation native = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
        return PreimageHash(native.Snapshot.Sha256, await StorageAsync(connection, transaction, ct).ConfigureAwait(false));
    }
    internal void RequireCompletedReadback(DualTargetCapturedTargetObservation actual)
    {
        if (_completed.Count != DatabaseInventory.ActiveDatabases.Count || _settled.Count != DatabaseInventory.ActiveDatabases.Count ||
            actual.Authority != _observation.Authority || actual.Generation != _observation.Generation ||
            actual.RuntimeSha256 != _observation.RuntimeSha256 || actual.Maintenance != _observation.Maintenance ||
            actual.NativeBeforeSha256.Count != _observation.NativeBeforeSha256.Count || actual.NativeBeforeSha256.Any(x =>
                x.Value != (_settled.TryGetValue(x.Key, out string? settled) ? settled : _observation.NativeBeforeSha256.GetValueOrDefault(x.Key))))
        { throw DualTargetCapturedDeltaContract.Invalid(); }
    }
    private static string Qualified(string space, string name)
    {
        return PostgreSqlShadowTarget.QuoteIdentifier(space) + "." + PostgreSqlShadowTarget.QuoteIdentifier(name);
    }
}
