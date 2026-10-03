using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Atomic fresh source repair only. All pre-existing internal state is retained.</summary>
internal sealed class PostgreSqlSourceBackedLocalRepair
{
    private const string Marker = "legacy_migration_internal.delta_source_backed_repair";
    private readonly SourceBackedLocalRepairExecutionPermit _permit;
    private readonly SourceBackedLocalRepairDatabasePreimage _prior;
    private readonly string _journal;
    private readonly string _fence;

    private PostgreSqlSourceBackedLocalRepair(SourceBackedLocalRepairExecutionPermit permit,
        SourceBackedLocalRepairDatabasePreimage prior, string journal, string fence)
    { _permit = permit; _prior = prior; _journal = journal; _fence = fence; }

    /// <summary>Separately reviewed staging DDL, before locked capture. Never invoked by row execution.</summary>
    internal static async Task StageAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        if (transaction.Connection != connection || transaction.IsolationLevel != System.Data.IsolationLevel.Serializable ||
            !DatabaseInventory.ActiveDatabases.Contains(connection.Database, StringComparer.Ordinal))
        { throw SourceBackedLocalRepairExecutionPermit.Invalid(); }
        await using (var exists = new NpgsqlCommand($"SELECT to_regclass('{Marker}') IS NOT NULL;", connection, transaction))
        {
            if (await exists.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is true)
            {
                await using var markerLock = new NpgsqlCommand($"LOCK TABLE ONLY {Marker} IN SHARE ROW EXCLUSIVE MODE NOWAIT;", connection, transaction);
                _ = await markerLock.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                await SourceBackedLocalRepairPreimage.RequireMarkerCatalogAsync(connection, transaction, 0, cancellationToken).ConfigureAwait(false);
                return;
            }
        }
        await using var create = new NpgsqlCommand($"""
            CREATE TABLE {Marker} (
                database_name text NOT NULL PRIMARY KEY, admission_sha256 text NOT NULL,
                claim_id uuid NOT NULL, preimage_sha256 text NOT NULL, source_capture_sha256 text NOT NULL,
                future_plan_sha256 text NOT NULL, continuation_ordinal bigint NOT NULL,
                continuation_sha256 text NOT NULL, authorization_sha256 text NOT NULL,
                prior_internal_sha256 text NOT NULL, checkpoint_sha256 text NOT NULL,
                reconciliation_sha256 text NOT NULL);
            """, connection, transaction);
        _ = await create.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await using var owner = new NpgsqlCommand("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='legacy_migration_internal.delta_journal'::regclass;", connection, transaction);
        string role = (string)(await owner.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false)
            ?? throw SourceBackedLocalRepairExecutionPermit.Invalid());
        await using var setOwner = new NpgsqlCommand($"ALTER TABLE {Marker} OWNER TO {PostgreSqlShadowTarget.QuoteIdentifier(role)};", connection, transaction);
        _ = await setOwner.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await SourceBackedLocalRepairPreimage.RequireMarkerCatalogAsync(connection, transaction, 0, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<PostgreSqlSourceBackedLocalRepair> AdoptAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, DeltaSynchronizationPlan plan, DatabaseSchemaPlan schema,
        SourceBackedLocalRepairExecutionPermit permit, CanonicalDeltaTargetBinding binding, CancellationToken cancellationToken)
    {
        SourceBackedLocalRepairDatabasePreimage prior = permit.Require(plan, schema);
        // Caller already acquired and compared the full preimage as the first transaction SQL.
        // Every old journal entry is retained verbatim, including timestamp precision.
        string journal = await JournalAsync(connection, transaction, null, cancellationToken).ConfigureAwait(false);
        string fence = await FencePreservedAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        await SourceBackedLocalRepairPreimage.RequireMarkerCatalogAsync(connection, transaction, 0, cancellationToken).ConfigureAwait(false);
        await using var update = new NpgsqlCommand("""
            UPDATE legacy_migration_internal.delta_fence SET schema_plan_sha256=$1,
                target_schema_sha256=$2,target_generation=$3,target_observation_sha256=$4
            WHERE database_name=$5;
            """, connection, transaction);
        _ = update.Parameters.AddWithValue(plan.SchemaPlanSha256);
        _ = update.Parameters.AddWithValue(binding.TargetSchemaSha256);
        _ = update.Parameters.AddWithValue(plan.TargetGeneration);
        _ = update.Parameters.AddWithValue(plan.TargetObservationSha256);
        _ = update.Parameters.AddWithValue(schema.Database);
        return await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1
            ? throw SourceBackedLocalRepairExecutionPermit.Invalid()
            : new(permit, prior, journal, fence);
    }

    internal async Task RecordAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CanonicalDeltaTargetBinding binding, DatabaseSchemaPlan schema, string reconciliationSha256,
        CancellationToken cancellationToken)
    {
        _ = _permit.RequirePlanBinding(binding);
        SourceBackedLocalRepairDatabasePreimage observed = await SourceBackedLocalRepairPreimage
            .InspectAsync(connection, transaction, schema, cancellationToken).ConfigureAwait(false);
        if (observed.CatalogObjectsSha256 != _prior.CatalogObjectsSha256 ||
            observed.ObservedPhysicalSchemaSha256 != _prior.ObservedPhysicalSchemaSha256)
        { throw SourceBackedLocalRepairExecutionPermit.Invalid(); }
        foreach (SourceRepairRelationPreimage relation in _prior.Relations)
        {
            SourceRepairRelationPreimage? actual = observed.Relations.SingleOrDefault(item => item.Schema == relation.Schema && item.Table == relation.Table);
            if (actual is null || actual.CatalogSha256 != relation.CatalogSha256)
            { throw SourceBackedLocalRepairExecutionPermit.Invalid(); }
            if (relation.Schema == "legacy_migration_internal" && relation.Table is "delta_fence" or "delta_journal" or "delta_source_backed_repair") { continue; }
            bool mapped = schema.Tables.Any(item => item.TargetSchema == relation.Schema && item.TargetTable == relation.Table);
            if (!mapped && actual != relation)
            { throw SourceBackedLocalRepairExecutionPermit.Invalid(); }
        }
        if (observed.Relations.Count != _prior.Relations.Count ||
            await JournalAsync(connection, transaction, binding.PlanSha256, cancellationToken).ConfigureAwait(false) != _journal ||
            await FencePreservedAsync(connection, transaction, cancellationToken).ConfigureAwait(false) != _fence)
        { throw SourceBackedLocalRepairExecutionPermit.Invalid(); }
        foreach (SourceRepairSequencePreimage sequence in _prior.Sequences)
        {
            SourceRepairSequencePreimage? actual = observed.Sequences.SingleOrDefault(item => item.Schema == sequence.Schema && item.Name == sequence.Name);
            if (actual is null || actual with { LastValue = sequence.LastValue, IsCalled = sequence.IsCalled } != sequence)
            { throw SourceBackedLocalRepairExecutionPermit.Invalid(); }
            bool sourceIdentity = false;
            foreach (TableCopyPlan table in schema.Tables)
            {
                foreach (IdentityCopyPlan identity in table.Identities)
                {
                    await using var resolve = new NpgsqlCommand("SELECT pg_get_serial_sequence($1,$2)::regclass=$3::regclass;", connection, transaction);
                    _ = resolve.Parameters.AddWithValue(PostgreSqlDeltaCanonicalTarget.Qualified(table.TargetSchema, table.TargetTable));
                    _ = resolve.Parameters.AddWithValue(identity.Column);
                    _ = resolve.Parameters.AddWithValue(PostgreSqlDeltaCanonicalTarget.Qualified(sequence.Schema, sequence.Name));
                    sourceIdentity |= await resolve.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is true;
                }
            }
            if (!sourceIdentity && actual != sequence) { throw SourceBackedLocalRepairExecutionPermit.Invalid(); }
        }
        if (observed.Sequences.Count != _prior.Sequences.Count) { throw SourceBackedLocalRepairExecutionPermit.Invalid(); }
        await SourceBackedLocalRepairPreimage.RequireMarkerCatalogAsync(connection, transaction, 0, cancellationToken).ConfigureAwait(false);
        string checkpoint;
        await using (var checkpointCommand = new NpgsqlCommand("""
            SELECT encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex')
            FROM legacy_migration_internal.delta_journal j WHERE plan_sha256=$1 AND plan_id=$2
                AND source_cutoff_utc=$3 AND target_observation_sha256=$4 AND reconciliation_sha256=$5;
            """, connection, transaction))
        {
            _ = checkpointCommand.Parameters.AddWithValue(binding.PlanSha256);
            _ = checkpointCommand.Parameters.AddWithValue(binding.PlanId);
            _ = checkpointCommand.Parameters.AddWithValue(binding.SourceCutoffUtc);
            _ = checkpointCommand.Parameters.AddWithValue(binding.TargetObservationSha256);
            _ = checkpointCommand.Parameters.AddWithValue(reconciliationSha256);
            checkpoint = (string)(await checkpointCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false)
                ?? throw SourceBackedLocalRepairExecutionPermit.Invalid());
        }
        SourceBackedLocalRepairAdmission admission = _permit.Admission;
        await using var insert = new NpgsqlCommand($"INSERT INTO {Marker} VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12);", connection, transaction);
        object[] values = [schema.Database, SourceBackedLocalRepairAdmissionPolicy.ComputeSha256(admission), admission.ClaimId,
            admission.PreimageSha256, admission.SourceCaptureSha256, binding.PlanSha256, _permit.Continuation.Ordinal,
            SourceBackedLocalRepairContinuationStore.ComputeSha256(_permit.Continuation), _permit.ActiveAuthorizationSha256,
            admission.InitialMetadata.Single(item => item.Database == schema.Database).FingerprintSha256,
            checkpoint, reconciliationSha256];
        foreach (object value in values) { _ = insert.Parameters.AddWithValue(value); }
        if (await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
        { throw SourceBackedLocalRepairExecutionPermit.Invalid(); }
        await SourceBackedLocalRepairPreimage.RequireMarkerCatalogAsync(connection, transaction, 1, cancellationToken).ConfigureAwait(false);
        await _permit.RequireFreshAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> FencePreservedAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            SELECT (to_jsonb(f)-ARRAY['schema_plan_sha256','target_schema_sha256','target_generation','target_observation_sha256'])::text
            FROM legacy_migration_internal.delta_fence f;
            """, connection, transaction);
        return (string)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false)
            ?? throw SourceBackedLocalRepairExecutionPermit.Invalid());
    }

    private static async Task<string> JournalAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string? exceptPlan, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            SELECT COALESCE(jsonb_agg(to_jsonb(j) ORDER BY to_jsonb(j)::text),'[]'::jsonb)::text
            FROM legacy_migration_internal.delta_journal j WHERE $1::text IS NULL OR plan_sha256<>$1;
            """, connection, transaction);
        _ = command.Parameters.AddWithValue((object?)exceptPlan ?? DBNull.Value);
        return (string)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false)
            ?? throw SourceBackedLocalRepairExecutionPermit.Invalid());
    }
}
