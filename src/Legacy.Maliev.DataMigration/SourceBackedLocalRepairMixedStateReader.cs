using System.Data;
using System.Globalization;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Actual LOCAL exact-23 observer. Retained signatures alone do not prove current database
/// state. Trusted maintenance must exclude new clients and global/catalog DDL throughout.
/// No persistent database mutation is committed by this reader.
/// </summary>
internal sealed class SourceBackedLocalRepairMixedStateReader(string localConnectionString,
    SourceBackedLocalRepairAdmissionStore admissions, SourceBackedLocalRepairContinuationStore continuations,
    Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observeTarget,
    ISourceBackedLocalRepairMaintenance maintenance, TimeProvider clock,
    SourceBackedLocalRepairRenewalStore? renewals = null)
{
    private static readonly object ProofToken = new();
    private SourceBackedLocalRepairRenewalStore RenewalStore => renewals ?? admissions.Renewals;
    internal sealed class Observation
    {
        private readonly SourceBackedLocalRepairContinuation _continuation;
        internal Observation(object token, string admissionSha256, SourceBackedLocalRepairContinuation continuation,
            HistoricalCurrentLocalObservation identity, DateTimeOffset verifiedAtUtc,
            SourceBackedLocalRepairRenewalStore.ActiveGrant? activeGrant = null)
        {
            if (!ReferenceEquals(token, ProofToken)) { throw Invalid(); }
            AdmissionSha256 = admissionSha256;
            _continuation = Snapshot(continuation);
            Identity = identity;
            VerifiedAtUtc = verifiedAtUtc;
            ActiveGrant = activeGrant;
        }

        internal string AdmissionSha256 { get; }
        internal SourceBackedLocalRepairContinuation Continuation => Snapshot(_continuation);
        internal HistoricalCurrentLocalObservation Identity { get; }
        internal DateTimeOffset VerifiedAtUtc { get; }
        internal SourceBackedLocalRepairRenewalStore.ActiveGrant? ActiveGrant { get; }
        internal bool IsTerminal => Continuation.Ordinal == 24;
        internal static bool AuthorizesExecution => false;

    }

    internal sealed class RenewalObservation
    {
        private readonly SourceBackedLocalRepairContinuation? _basis;
        private readonly SourceBackedLocalRepairState[] _states;
        internal RenewalObservation(object token, string admissionSha256, SourceBackedLocalRepairContinuation? basis,
            IReadOnlyList<SourceBackedLocalRepairState> states, HistoricalCurrentLocalObservation identity, DateTimeOffset verifiedAtUtc)
        {
            if (!ReferenceEquals(token, ProofToken)) { throw Invalid(); }
            AdmissionSha256 = admissionSha256; _basis = basis is null ? null : Snapshot(basis);
            _states = Snapshot(states.ToArray()); Identity = identity; VerifiedAtUtc = verifiedAtUtc;
        }
        internal string AdmissionSha256 { get; }
        internal SourceBackedLocalRepairContinuation? Basis => _basis is null ? null : Snapshot(_basis);
        internal IReadOnlyList<SourceBackedLocalRepairState> Databases => Snapshot(_states);
        internal HistoricalCurrentLocalObservation Identity { get; }
        internal DateTimeOffset VerifiedAtUtc { get; }
        internal static bool AuthorizesExecution => false;
    }

    internal async Task<Observation> ObserveAndAdvanceAsync(SourceBackedLocalRepairAdmissionBundle bundle,
        PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        PairedLocalTransitionAuthorization authorization, long retainedOrdinal,
        P256MigrationEvidenceSigner signer, CancellationToken cancellationToken,
        SourceBackedLocalRepairRenewalStore.ActiveGrant? activeGrant = null)
    {
        return (await ObserveCoreAsync(bundle, plans, proof, schema, authorization, retainedOrdinal, signer,
            activeGrant, false, 0, cancellationToken).ConfigureAwait(false)).Observation ?? throw Invalid();
    }

    internal async Task<SourceBackedLocalRepairRenewalStore.ActiveGrant> RenewAsync(
        SourceBackedLocalRepairAdmissionBundle bundle, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        PairedLocalTransitionAuthorization freshAuthorization, long retainedOrdinal, long previousCounter,
        P256MigrationEvidenceSigner signer, CancellationToken cancellationToken)
    {
        SourceBackedLocalRepairRenewalStore.ActiveGrant? existing = await RenewalStore.TryReadPublishedAsync(
            bundle, plans, proof, schema, checked(previousCounter + 1), cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            if (SourceBackedLocalRepairContinuationStore.AuthorizationHash(existing.Authorization) !=
                SourceBackedLocalRepairContinuationStore.AuthorizationHash(freshAuthorization)) { throw Invalid(); }
            _ = await ObserveAndAdvanceAsync(bundle, plans, proof, schema, freshAuthorization, retainedOrdinal,
                signer, cancellationToken, existing).ConfigureAwait(false);
            return existing;
        }
        return (await ObserveCoreAsync(bundle, plans, proof, schema, freshAuthorization, retainedOrdinal,
            signer, null, true, previousCounter, cancellationToken).ConfigureAwait(false)).Grant ?? throw Invalid();
    }

    private async Task<CoreResult> ObserveCoreAsync(SourceBackedLocalRepairAdmissionBundle bundle,
        PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        PairedLocalTransitionAuthorization authorization, long retainedOrdinal, P256MigrationEvidenceSigner signer,
        SourceBackedLocalRepairRenewalStore.ActiveGrant? activeGrant,
        bool renewing, long previousCounter, CancellationToken cancellationToken)
    {
        bundle = Snapshot(bundle);
        plans = Snapshot(plans);
        proof = Snapshot(proof);
        schema = Snapshot(schema);
        authorization = Snapshot(authorization);
        if (retainedOrdinal is < 0 or > 24) { throw Invalid(); }
        if (maintenance is SourceBackedLocalRepairMaintenance concrete)
        {
            concrete.RequireConnection(localConnectionString);
        }
        var endpoint = LocalPostgreSqlResourceAuthority.Connection(localConnectionString);
        async Task<SourceBackedLocalRepairClaim> VerifyAuthorityAsync()
        {
            if (renewing)
            {
                return await RenewalStore.VerifyRenewalInputsAsync(bundle, plans, proof, schema,
                    authorization, cancellationToken).ConfigureAwait(false);
            }
            return activeGrant is null ? await admissions.VerifyRetainedAsync(bundle.Admission,
                bundle.Capsule, plans, proof, schema, authorization, cancellationToken).ConfigureAwait(false) :
                await admissions.VerifyRetainedAsync(bundle.Admission, bundle.Capsule, plans, proof, schema,
                    authorization, activeGrant, cancellationToken).ConfigureAwait(false);
        }
        SourceBackedLocalRepairClaim claim = await VerifyAuthorityAsync().ConfigureAwait(false);
        IReadOnlyList<SourceBackedLocalRepairAuthorizationEpoch> epochs = renewing ?
            await RenewalStore.ReadEpochsProvenanceAsync(bundle, plans, proof, schema, previousCounter, cancellationToken).ConfigureAwait(false) :
            activeGrant?.Epochs ?? [new(authorization, 1, bundle.Admission.IssuedAtUtc,
                new[] { bundle.Admission.ExpiresAtUtc, bundle.Capsule.ExpiresAtUtc, authorization.ExpiresAtUtc }.Min())];
        async Task<SourceBackedLocalRepairContinuation> ReadPredecessorAsync(long ordinal) =>
            await continuations.ReadProvenanceAsync(claim.ClaimId, claim.AdmissionSha256, ordinal,
                epochs[0].Authorization, clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
        HistoricalCurrentLocalObservation before = await observeTarget(cancellationToken).ConfigureAwait(false);
        if (before != bundle.Admission.TargetIdentity) { throw Invalid(); }
        SourceBackedLocalRepairContinuation? retained = retainedOrdinal == 0 ? null : renewing ?
            await ReadPredecessorAsync(retainedOrdinal).ConfigureAwait(false) : await continuations.ReadAsync(claim.ClaimId,
                claim.AdmissionSha256, retainedOrdinal, authorization, clock.GetUtcNow(), cancellationToken, activeGrant).ConfigureAwait(false);
        await using ISourceBackedLocalRepairMaintenanceLease maintenanceLease =
            await maintenance.AcquireAsync(before, cancellationToken).ConfigureAwait(false);
        await maintenanceLease.RequireStillQuiescentAsync(before, cancellationToken).ConfigureAwait(false);
        var leases = new List<(NpgsqlConnection Connection, NpgsqlTransaction Transaction)>();
        CoreResult? result = null;
        Exception? failure = null;
        try
        {
            var states = new List<SourceBackedLocalRepairState>();
            for (int index = 0; index < DatabaseInventory.ActiveDatabases.Count; index++)
            {
                _ = await VerifyAuthorityAsync().ConfigureAwait(false);
                DatabaseSchemaPlan database = schema.Databases[index];
                SourceBackedLocalRepairDatabasePreimage prior = bundle.Capsule.Databases[index];
                // A signed opaque preimage is not proof of the application's declared physical
                // contract. This also rejects undeclared columns hidden by mapped-row projection.
                string expectedPhysical = database.Database == "Quotation" ?
                    plans.Persistent.QuotationTransitionSchemaSha256! : database.TargetSchemaSha256;
                if (prior.ObservedPhysicalSchemaSha256 != expectedPhysical) { throw Invalid(); }
                SourceRepairRelationPreimage marker = prior.Relations.Single(item =>
                    item.Schema == "legacy_migration_internal" && item.Table == "delta_source_backed_repair");
                if (marker.Rows != 0) { throw Invalid(); }
                endpoint.Database = database.Database;
                if (maintenance is SourceBackedLocalRepairMaintenance currentMaintenance)
                {
                    currentMaintenance.RequireConnection(localConnectionString);
                }
                var connection = new NpgsqlConnection(endpoint.ConnectionString);
                NpgsqlTransaction transaction;
                try
                {
                    await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
                    await using var control = new NpgsqlCommand("SELECT system_identifier::text FROM pg_control_system(); SET timezone='UTC'; SET datestyle='ISO,YMD'; SET extra_float_digits=3;", connection);
                    string system = (string)(await control.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? throw Invalid());
                    if (Hash(system) != before.SystemIdentifierSha256) { throw Invalid(); }
                    transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
                }
                catch { await connection.DisposeAsync().ConfigureAwait(false); throw; }
                leases.Add((connection, transaction));
                // Fresh transaction: signed complete inventory locks are its FIRST SQL.
                SourceBackedLocalRepairDatabasePreimage actual = await SourceBackedLocalRepairLockSet
                    .AcquireForInspectionAsync(connection, transaction, database, prior, cancellationToken).ConfigureAwait(false);
                SourceRepairRelationPreimage actualMarker = actual.Relations.Single(item =>
                    item.Schema == "legacy_migration_internal" && item.Table == "delta_source_backed_repair");
                await SourceBackedLocalRepairPreimage.RequireMarkerCatalogAsync(connection, transaction,
                    actualMarker.Rows, cancellationToken).ConfigureAwait(false);
                string metadata = claim.InitialMetadata[index].FingerprintSha256;
                if (actualMarker.Rows == 0)
                {
                    SourceBackedLocalRepairPreimage.RequireMatches(prior, actual);
                    states.Add(new(database.Database, SourceBackedLocalRepairPhase.Prior, metadata, null, null, null));
                }
                else
                {
                    if (retained is null || index >= retained.Ordinal) { throw Invalid(); }
                    SourceBackedLocalRepairContinuation predecessor = index + 1 == retained.Ordinal ? retained :
                        await ReadPredecessorAsync(index + 1).ConfigureAwait(false);
                    states.Add(await InspectAppliedAsync(connection, transaction, database, plans.Persistent,
                        bundle.Admission, prior, actual, predecessor, metadata, epochs, cancellationToken).ConfigureAwait(false));
                }
            }
            HistoricalCurrentLocalObservation after = await observeTarget(cancellationToken).ConfigureAwait(false);
            if (after != before) { throw Invalid(); }
            await maintenanceLease.RequireStillQuiescentAsync(after, cancellationToken).ConfigureAwait(false);
            _ = await VerifyAuthorityAsync().ConfigureAwait(false);
            SourceBackedLocalRepairContinuation? current = null;
            SourceBackedLocalRepairRenewalStore.ActiveGrant? createdGrant = null;
            if (renewing)
            {
                var renewalObservation = new RenewalObservation(ProofToken, claim.AdmissionSha256, retained,
                    states, after, clock.GetUtcNow());
                createdGrant = await RenewalStore.CreateAsync(renewalObservation, bundle, plans, proof, schema,
                    authorization, previousCounter, signer, cancellationToken).ConfigureAwait(false);
            }
            else if (retained is not null && retained.Databases.SequenceEqual(states)) { current = retained; }
            else
            {
                long ordinal = retained is null ? 1 : retained.Ordinal + 1;
                DateTimeOffset now = clock.GetUtcNow();
                DateTimeOffset expires = activeGrant is null ? new[] { bundle.Admission.ExpiresAtUtc,
                    bundle.Capsule.ExpiresAtUtc, authorization.ExpiresAtUtc, now.AddMinutes(15) }.Min() :
                    new[] { activeGrant.ExpiresAtUtc, authorization.ExpiresAtUtc, now.AddMinutes(15) }.Min();
                var unsigned = new SourceBackedLocalRepairContinuation("1.0", claim.ClaimId,
                    claim.AdmissionSha256, claim.PreimageSha256, claim.SourceCaptureSha256, claim.FuturePlanSha256,
                    claim.TargetGeneration, authorization.AuthorizationId, SourceBackedLocalRepairContinuationStore.AuthorizationHash(authorization),
                    ordinal, retained is null ? null : SourceBackedLocalRepairContinuationStore.ComputeSha256(retained),
                    states.ToArray(), now, expires, signer.KeyId, null)
                {
                    AuthorizationArtifact = Snapshot(authorization),
                    RenewalCounter = activeGrant?.Counter,
                    RenewalGrantSha256 = activeGrant is null ? null : SourceBackedLocalRepairRenewalPolicy.ComputeSha256(activeGrant.SignedGrant),
                };
                SourceBackedLocalRepairContinuation signed = unsigned with
                {
                    AttestationSignature = Convert.ToBase64String(signer.Sign(SourceBackedLocalRepairContinuationStore.Payload(unsigned))),
                };
                try
                {
                    current = await continuations.AppendAsync(signed, authorization, states, now, cancellationToken, activeGrant).ConfigureAwait(false);
                }
                catch (Exception) when (!cancellationToken.IsCancellationRequested)
                {
                    // Interrupted publication or competing create: only independently authenticated
                    // retained content with this exact actual prefix can recover the same ordinal.
                    current = await continuations.ReadAsync(claim.ClaimId, claim.AdmissionSha256, ordinal,
                        authorization, clock.GetUtcNow(), cancellationToken, activeGrant).ConfigureAwait(false);
                    if (!current.Databases.SequenceEqual(states) || current.PreviousContinuationSha256 != signed.PreviousContinuationSha256)
                    { throw Invalid(); }
                }
            }
            // Second complete exact-23 scan brackets immutable publication/readback. These
            // transactions still hold all original table and allocation locks; maintenance
            // independently excludes global catalog changes that database locks cannot freeze.
            var second = new List<SourceBackedLocalRepairState>();
            for (int index = 0; index < leases.Count; index++)
            {
                var (connection, transaction) = leases[index];
                DatabaseSchemaPlan database = schema.Databases[index];
                SourceBackedLocalRepairDatabasePreimage prior = bundle.Capsule.Databases[index];
                SourceBackedLocalRepairDatabasePreimage actual = await SourceBackedLocalRepairPreimage
                    .InspectAsync(connection, transaction, database, cancellationToken).ConfigureAwait(false);
                SourceRepairRelationPreimage marker = actual.Relations.Single(item =>
                    item.Schema == "legacy_migration_internal" && item.Table == "delta_source_backed_repair");
                await SourceBackedLocalRepairPreimage.RequireMarkerCatalogAsync(connection, transaction,
                    marker.Rows, cancellationToken).ConfigureAwait(false);
                string metadata = claim.InitialMetadata[index].FingerprintSha256;
                if (marker.Rows == 0)
                {
                    SourceBackedLocalRepairPreimage.RequireMatches(prior, actual);
                    second.Add(new(database.Database, SourceBackedLocalRepairPhase.Prior, metadata, null, null, null));
                }
                else
                {
                    SourceBackedLocalRepairContinuation predecessor = await ReadPredecessorAsync(index + 1).ConfigureAwait(false);
                    second.Add(await InspectAppliedAsync(connection, transaction, database, plans.Persistent,
                        bundle.Admission, prior, actual, predecessor, metadata, epochs, cancellationToken).ConfigureAwait(false));
                }
            }
            if (!states.SequenceEqual(second)) { throw Invalid(); }
            // No proof escapes if identity, maintenance or authorization expired during retention.
            after = await observeTarget(cancellationToken).ConfigureAwait(false);
            if (after != before) { throw Invalid(); }
            await maintenanceLease.RequireStillQuiescentAsync(after, cancellationToken).ConfigureAwait(false);
            _ = await VerifyAuthorityAsync().ConfigureAwait(false);
            if (renewing)
            {
                _ = await createdGrant!.RequireFreshAsync(bundle.Admission, bundle.Capsule, plans, proof, schema,
                    authorization, after, cancellationToken).ConfigureAwait(false);
                result = new(null, createdGrant);
            }
            else { result = new(new(ProofToken, claim.AdmissionSha256, Snapshot(current!), after, clock.GetUtcNow(), activeGrant), null); }
        }
        catch (Exception exception) { failure = exception; }
        finally
        {
            var failures = new List<Exception>();
            foreach (var (connection, transaction) in leases.AsEnumerable().Reverse())
            {
                try { await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false); }
                catch (Exception exception) { failures.Add(exception); }
                try { await transaction.DisposeAsync().ConfigureAwait(false); }
                catch (Exception exception) { failures.Add(exception); }
                try { await connection.DisposeAsync().ConfigureAwait(false); }
                catch (Exception exception) { failures.Add(exception); }
            }
            if (failures.Count != 0)
            {
                if (failure is not null) { failures.Insert(0, failure); }
                failure = new AggregateException("LOCAL mixed observation cleanup failed.", failures);
            }
        }
        if (failure is not null) { ExceptionDispatchInfo.Capture(failure).Throw(); }
        return result ?? throw Invalid();
    }

    private static async Task<SourceBackedLocalRepairState> InspectAppliedAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, DatabaseSchemaPlan schema, DeltaSynchronizationPlan plan,
        SourceBackedLocalRepairAdmission admission, SourceBackedLocalRepairDatabasePreimage prior,
        SourceBackedLocalRepairDatabasePreimage actual, SourceBackedLocalRepairContinuation predecessor,
        string metadata, IReadOnlyList<SourceBackedLocalRepairAuthorizationEpoch> epochs, CancellationToken cancellationToken)
    {
        string planHash = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
        string reconciliationHash = await ReconcileAsync(connection, transaction, schema, plan, prior,
            actual, cancellationToken).ConfigureAwait(false);
        string checkpointHash;
        DateTimeOffset committedAtUtc;
        await using (var checkpoint = new NpgsqlCommand("""
            SELECT encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex'),committed_at_utc
            FROM legacy_migration_internal.delta_journal j
            WHERE plan_sha256=$1 AND plan_id=$2 AND source_cutoff_utc=$3
              AND target_observation_sha256=$4 AND operations_sha256=$5 AND reconciliation_sha256=$6;
            """, connection, transaction))
        {
            _ = checkpoint.Parameters.AddWithValue(planHash);
            _ = checkpoint.Parameters.AddWithValue(plan.PlanId);
            _ = checkpoint.Parameters.AddWithValue(plan.SourceCutoffUtc);
            _ = checkpoint.Parameters.AddWithValue(plan.TargetObservationSha256);
            _ = checkpoint.Parameters.AddWithValue(DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(
                plan.Databases.Single(item => item.Database == schema.Database)));
            _ = checkpoint.Parameters.AddWithValue(reconciliationHash);
            await using NpgsqlDataReader reader = await checkpoint.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw Invalid(); }
            checkpointHash = reader.GetString(0);
            committedAtUtc = reader.GetFieldValue<DateTimeOffset>(1);
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw Invalid(); }
        }
        await using (var fence = new NpgsqlCommand("""
            SELECT count(*) FROM legacy_migration_internal.delta_fence
            WHERE database_name=$1 AND schema_plan_sha256=$2 AND target_schema_sha256=$3
              AND target_generation=$4 AND target_observation_sha256=$5;
            """, connection, transaction))
        {
            _ = fence.Parameters.AddWithValue(schema.Database);
            _ = fence.Parameters.AddWithValue(plan.SchemaPlanSha256);
            _ = fence.Parameters.AddWithValue(prior.ObservedPhysicalSchemaSha256);
            _ = fence.Parameters.AddWithValue(plan.TargetGeneration);
            _ = fence.Parameters.AddWithValue(plan.TargetObservationSha256);
            if (Convert.ToInt64(await fence.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture) != 1 ||
                prior.FenceAuxiliarySha256 is null || prior.FenceAuxiliarySha256 != actual.FenceAuxiliarySha256) { throw Invalid(); }
        }
        string markerHash;
        await using (var marker = new NpgsqlCommand("""
            SELECT to_jsonb(m)::text,encode(sha256(convert_to(to_jsonb(m)::text,'UTF8')),'hex')
            FROM legacy_migration_internal.delta_source_backed_repair m;
            """, connection, transaction))
        await using (NpgsqlDataReader reader = await marker.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw Invalid(); }
            using JsonDocument row = JsonDocument.Parse(reader.GetString(0));
            JsonElement root = row.RootElement;
            string actualAuthorization = root.GetProperty("authorization_sha256").GetString() ?? throw Invalid();
            SourceBackedLocalRepairAuthorizationEpoch[] authorizing = [.. epochs.Where(epoch =>
                SourceBackedLocalRepairContinuationStore.AuthorizationHash(epoch.Authorization) == actualAuthorization &&
                epoch.BasisOrdinal <= predecessor.Ordinal && committedAtUtc >= epoch.IssuedAtUtc && committedAtUtc < epoch.ExpiresAtUtc &&
                committedAtUtc >= epoch.Authorization.IssuedAtUtc && committedAtUtc < epoch.Authorization.ExpiresAtUtc)];
            if (authorizing.Length != 1 || committedAtUtc < predecessor.IssuedAtUtc) { throw Invalid(); }
            var expected = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["database_name"] = schema.Database,
                ["admission_sha256"] = SourceBackedLocalRepairAdmissionPolicy.ComputeSha256(admission),
                ["claim_id"] = admission.ClaimId.ToString(),
                ["preimage_sha256"] = admission.PreimageSha256,
                ["source_capture_sha256"] = admission.SourceCaptureSha256,
                ["future_plan_sha256"] = planHash,
                ["continuation_sha256"] = SourceBackedLocalRepairContinuationStore.ComputeSha256(predecessor),
                ["authorization_sha256"] = actualAuthorization,
                ["prior_internal_sha256"] = metadata,
                ["checkpoint_sha256"] = checkpointHash,
                ["reconciliation_sha256"] = reconciliationHash,
            };
            if (root.EnumerateObject().Count() != 12 || root.GetProperty("continuation_ordinal").GetInt64() != predecessor.Ordinal ||
                expected.Any(item => root.GetProperty(item.Key).GetString() != item.Value)) { throw Invalid(); }
            markerHash = reader.GetString(1);
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw Invalid(); }
        }
        SourceRepairRelationPreimage oldJournal = prior.Relations.Single(item =>
            item.Schema == "legacy_migration_internal" && item.Table == "delta_journal");
        await using (var journal = new NpgsqlCommand("""
            SELECT count(*),encode(sha256(convert_to(coalesce(string_agg(h,'' ORDER BY h COLLATE "C"),''),'UTF8')),'hex')
            FROM (SELECT encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex') h
              FROM legacy_migration_internal.delta_journal j WHERE plan_sha256<>$1) preserved;
            """, connection, transaction))
        {
            _ = journal.Parameters.AddWithValue(planHash);
            await using NpgsqlDataReader reader = await journal.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.GetInt64(0) != oldJournal.Rows ||
                reader.GetString(1) != oldJournal.RowMultisetSha256) { throw Invalid(); }
        }
        DatabaseSchemaPlan target = new QuotationDeltaExecutionMapping(schema).TargetSchema;
        var mapped = target.Tables.Select(item => (item.TargetSchema, item.TargetTable)).ToHashSet();
        var identities = new HashSet<(string Schema, string Name)>();
        foreach (TableCopyPlan table in target.Tables)
            foreach (IdentityCopyPlan identity in table.Identities)
            {
                await using var sequence = new NpgsqlCommand("""
                SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE c.oid=pg_get_serial_sequence($1,$2)::regclass AND c.relkind='S';
                """, connection, transaction);
                _ = sequence.Parameters.AddWithValue(PostgreSqlDeltaCanonicalTarget.Qualified(table.TargetSchema, table.TargetTable));
                _ = sequence.Parameters.AddWithValue(identity.Column);
                await using NpgsqlDataReader reader = await sequence.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw Invalid(); }
                (string Schema, string Name) name = (reader.GetString(0), reader.GetString(1));
                SourceRepairSequencePreimage physical = actual.Sequences.Single(item => item.Schema == name.Schema && item.Name == name.Name);
                long expectedNext = plan.SourceCaptureManifest!.Databases.Single(item => item.Database == schema.Database)
                    .SourceReconciliation.SequenceNextValues[$"{table.TargetSchema}.{table.TargetTable}.{identity.Column}"];
                // Canonical alignment uses transactional ALTER SEQUENCE RESTART WITH next, so the
                // exact physical result is next/is_called=false, not merely an equivalent nextval.
                if (physical.LastValue != expectedNext || physical.IsCalled || !identities.Add(name)) { throw Invalid(); }
            }
        var normalizedRelations = new List<SourceRepairRelationPreimage>();
        foreach (SourceRepairRelationPreimage relation in actual.Relations)
        {
            SourceRepairRelationPreimage original = prior.Relations.Single(item => item.Schema == relation.Schema && item.Table == relation.Table);
            bool allowedRows = mapped.Contains((relation.Schema, relation.Table)) ||
                relation.Schema == "legacy_migration_internal" && relation.Table is "delta_fence" or "delta_journal" or "delta_source_backed_repair";
            normalizedRelations.Add(allowedRows ? relation with { Rows = original.Rows, RowMultisetSha256 = original.RowMultisetSha256 } : relation);
        }
        var normalizedSequences = new List<SourceRepairSequencePreimage>();
        foreach (SourceRepairSequencePreimage sequence in actual.Sequences)
        {
            SourceRepairSequencePreimage original = prior.Sequences.Single(item => item.Schema == sequence.Schema && item.Name == sequence.Name);
            normalizedSequences.Add(identities.Contains((sequence.Schema, sequence.Name)) ?
                sequence with { LastValue = original.LastValue, IsCalled = original.IsCalled } : sequence);
        }
        SourceBackedLocalRepairPreimage.RequireMatches(prior, actual with
        {
            Relations = normalizedRelations,
            Sequences = normalizedSequences,
            TargetExtensionStateSha256 = prior.TargetExtensionStateSha256,
        });
        return new(schema.Database, SourceBackedLocalRepairPhase.Applied, metadata, markerHash, checkpointHash, reconciliationHash);
    }

    private sealed record CoreResult(Observation? Observation, SourceBackedLocalRepairRenewalStore.ActiveGrant? Grant);

    private static async Task<string> ReconcileAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        DatabaseSchemaPlan schema, DeltaSynchronizationPlan plan, SourceBackedLocalRepairDatabasePreimage prior,
        SourceBackedLocalRepairDatabasePreimage actual, CancellationToken cancellationToken)
    {
        DatabaseSchemaPlan target = new QuotationDeltaExecutionMapping(schema).TargetSchema;
        DatabaseReconciliationEvidence expected = plan.SourceCaptureManifest!.Databases.Single(item => item.Database == schema.Database).SourceReconciliation;
        if (expected.SourceSchemaSha256 != schema.SourceSchemaSha256 || expected.TargetSchemaSha256 != schema.TargetSchemaSha256 ||
            !expected.Tables.Select(item => item.Table).Order(StringComparer.Ordinal).SequenceEqual(
                target.Tables.Select(item => $"{item.TargetSchema}.{item.TargetTable}").Order(StringComparer.Ordinal), StringComparer.Ordinal)) { throw Invalid(); }
        ReconciliationDiagnostics.CompareSchema(schema.Database, prior.ObservedPhysicalSchemaSha256, actual.ObservedPhysicalSchemaSha256);
        await using var inspection = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
        var tables = new List<TableReconciliationEvidence>();
        foreach (TableCopyPlan table in target.Tables)
        {
            TableReconciliationEvidence observed = await inspection.InspectTableAsync(table, cancellationToken).ConfigureAwait(false);
            ReconciliationDiagnostics.CompareTable(schema.Database,
                expected.Tables.Single(item => item.Table == $"{table.TargetSchema}.{table.TargetTable}"), observed);
            tables.Add(observed);
        }
        IReadOnlyDictionary<string, long> sequences = await inspection.InspectSequenceNextValuesAsync(target, cancellationToken).ConfigureAwait(false);
        ReconciliationDiagnostics.CompareSequences(target, expected.SequenceNextValues, sequences);
        string? extensionHash = null;
        if (ApprovedConsumerColumnOverlayManifest.HasState(target))
        {
            ApprovedTargetExtensionState extensions = await ApprovedTargetExtensionStateInspector.InspectAsync(connection,
                transaction, target, cancellationToken, ApprovedConsumerColumnOverlayManifest.InsertKeys(target, plan), afterApply: true).ConfigureAwait(false);
            extensionHash = ApprovedTargetExtensionStateInspector.ComputeSha256(target, extensions);
            ApprovedTargetExtensionState preserved = extensions with
            {
                Overlay = extensions.Overlay is null ? null : extensions.Overlay with { All = extensions.Overlay.Existing, InsertedCount = 0 },
            };
            if (prior.TargetExtensionStateSha256 is null ||
                ApprovedTargetExtensionStateInspector.ComputeSha256(target, preserved) != prior.TargetExtensionStateSha256) { throw Invalid(); }
        }
        else if (prior.TargetExtensionStateSha256 is not null) { throw Invalid(); }
        return DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(new(schema.Database,
            schema.SourceSchemaSha256, actual.ObservedPhysicalSchemaSha256, tables)
        {
            SequenceNextValues = sequences,
            TargetExtensionStateSha256 = extensionHash,
        });
    }

    private static T Snapshot<T>(T value) => JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value)) ?? throw Invalid();
    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    private static DeltaExecutionException Invalid() => new("delta_source_repair_mixed_state_invalid",
        "Actual exact-23 source repair state, original preservation, retained progress, identity and fresh authority must all agree.");
}
