using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Internal fresh source repair admission. Historical rollover and replay are excluded.</summary>
internal sealed class SourceBackedLocalRepairExecutionPermit
{
    private readonly SourceBackedLocalRepairAdmissionStore _admissions;
    private readonly SourceBackedLocalRepairContinuationStore _continuations;
    private readonly SourceBackedLocalRepairAdmissionBundle _bundle;
    private readonly PairedCapturedDeltaPlans _plans;
    private readonly Exact23DeltaReconciliationResult _proof;
    private readonly FreshSchemaPlan _schema;
    private readonly Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> _observe;
    private readonly ISourceBackedLocalRepairMaintenanceLease _maintenance;
    private readonly TimeProvider _clock;
    private readonly SourceBackedLocalRepairRenewalStore.ActiveGrant? _activeGrant;

    private SourceBackedLocalRepairExecutionPermit(SourceBackedLocalRepairAdmissionStore admissions,
        SourceBackedLocalRepairContinuationStore continuations, SourceBackedLocalRepairAdmissionBundle bundle,
        PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        PairedLocalTransitionAuthorization authorization, SourceBackedLocalRepairContinuation continuation,
        Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observe,
        ISourceBackedLocalRepairMaintenanceLease maintenance, TimeProvider clock,
        SourceBackedLocalRepairRenewalStore.ActiveGrant? activeGrant)
    {
        _admissions = admissions; _continuations = continuations; _bundle = bundle;
        _plans = plans; _proof = proof; _schema = schema; Authorization = authorization;
        Continuation = continuation; _observe = observe; _maintenance = maintenance; _clock = clock;
        _activeGrant = activeGrant;
    }

    internal SourceBackedLocalRepairAdmission Admission => _bundle.Admission;
    internal SourceBackedLocalRepairContinuation Continuation { get; }
    internal PairedLocalTransitionAuthorization Authorization { get; }
    internal string ActiveAuthorizationSha256 => SourceBackedLocalRepairContinuationStore.AuthorizationHash(Authorization);
    internal DateTimeOffset NowUtc => _clock.GetUtcNow();

    internal static async Task<SourceBackedLocalRepairExecutionPermit> AdmitAsync(
        SourceBackedLocalRepairAdmissionStore admissions, SourceBackedLocalRepairContinuationStore continuations,
        SourceBackedLocalRepairAdmissionBundle bundle, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization,
        long continuationOrdinal, Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observe,
        ISourceBackedLocalRepairMaintenanceLease maintenance, TimeProvider clock, CancellationToken cancellationToken)
    {
        return continuationOrdinal != 1
            ? throw Invalid()
            : await AdmitCoreAsync(admissions, continuations, bundle, plans, proof, schema, authorization,
            continuationOrdinal, null, observe, maintenance, clock, cancellationToken).ConfigureAwait(false);
    }

    internal static Task<SourceBackedLocalRepairExecutionPermit> AdmitAsync(
        SourceBackedLocalRepairAdmissionStore admissions, SourceBackedLocalRepairContinuationStore continuations,
        SourceBackedLocalRepairAdmissionBundle bundle, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization,
        SourceBackedLocalRepairMixedStateReader.Observation observation,
        Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observe,
        ISourceBackedLocalRepairMaintenanceLease maintenance, TimeProvider clock, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(observation);
        return AdmitCoreAsync(admissions, continuations, bundle, plans, proof, schema, authorization,
            observation.Continuation.Ordinal, observation, observe, maintenance, clock, cancellationToken);
    }

    private static async Task<SourceBackedLocalRepairExecutionPermit> AdmitCoreAsync(
        SourceBackedLocalRepairAdmissionStore admissions, SourceBackedLocalRepairContinuationStore continuations,
        SourceBackedLocalRepairAdmissionBundle bundle, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization,
        long continuationOrdinal, SourceBackedLocalRepairMixedStateReader.Observation? observation,
        Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observe,
        ISourceBackedLocalRepairMaintenanceLease maintenance, TimeProvider clock, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(admissions); ArgumentNullException.ThrowIfNull(continuations);
        ArgumentNullException.ThrowIfNull(observe); ArgumentNullException.ThrowIfNull(maintenance);
        ArgumentNullException.ThrowIfNull(clock);
        if (continuationOrdinal is < 1 or > 23 || (continuationOrdinal != 1 && observation is null)) { throw Invalid(); }
        bundle = Snapshot(bundle); plans = Snapshot(plans); proof = Snapshot(proof);
        schema = Snapshot(schema); authorization = Snapshot(authorization);
        SourceBackedLocalRepairRenewalStore.ActiveGrant? activeGrant = observation?.ActiveGrant;
        SourceBackedLocalRepairClaim claim = activeGrant is null
            ? await admissions.VerifyRetainedAsync(bundle.Admission, bundle.Capsule, plans, proof, schema,
                authorization, cancellationToken).ConfigureAwait(false)
            : await admissions.VerifyRetainedAsync(bundle.Admission, bundle.Capsule, plans, proof, schema,
                authorization, activeGrant, cancellationToken).ConfigureAwait(false);
        bundle = bundle with { VerifiedClaim = claim };
        SourceBackedLocalRepairContinuation continuation = await continuations.ReadAsync(claim.ClaimId,
            claim.AdmissionSha256, continuationOrdinal, authorization, clock.GetUtcNow(), cancellationToken, activeGrant).ConfigureAwait(false);
        if (observation is not null)
        {
            DateTimeOffset now = clock.GetUtcNow();
            if (observation.IsTerminal || observation.AdmissionSha256 != claim.AdmissionSha256 ||
                observation.Identity != bundle.Admission.TargetIdentity || observation.VerifiedAtUtc.Offset != TimeSpan.Zero ||
                now < observation.VerifiedAtUtc || now - observation.VerifiedAtUtc > TimeSpan.FromMinutes(1) ||
                SourceBackedLocalRepairContinuationStore.ComputeSha256(observation.Continuation) !=
                SourceBackedLocalRepairContinuationStore.ComputeSha256(continuation)) { throw Invalid(); }
        }
        var permit = new SourceBackedLocalRepairExecutionPermit(admissions, continuations, bundle, plans,
            proof, schema, authorization, Snapshot(continuation), observe, maintenance, clock, activeGrant);
        await permit.RequireFreshAsync(cancellationToken).ConfigureAwait(false);
        return permit;
    }

    internal SourceBackedLocalRepairDatabasePreimage Require(DeltaSynchronizationPlan plan, DatabaseSchemaPlan schema)
    {
        int ordinal = checked((int)Continuation.Ordinal - 1);
        if (ordinal >= DatabaseInventory.ActiveDatabases.Count || schema.Database != DatabaseInventory.ActiveDatabases[ordinal] ||
            DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan) != Admission.PersistentPlanSha256 ||
            !_schema.Databases.Any(item => item.Database == schema.Database &&
                (JsonSerializer.Serialize(item) == JsonSerializer.Serialize(schema) ||
                JsonSerializer.Serialize(new QuotationDeltaExecutionMapping(item).TargetSchema) == JsonSerializer.Serialize(schema))) ||
            Continuation.Databases[ordinal].Phase != SourceBackedLocalRepairPhase.Prior ||
            Continuation.Databases[ordinal].PriorMetadataSha256 != Admission.InitialMetadata[ordinal].FingerprintSha256 ||
            NowUtc < Admission.IssuedAtUtc || NowUtc >= Admission.ClaimExpiresAtUtc ||
            (_activeGrant is null && (NowUtc >= Admission.ExpiresAtUtc || NowUtc >= Continuation.ExpiresAtUtc)) ||
            (_activeGrant is not null && (NowUtc < _activeGrant.SignedGrant.IssuedAtUtc || NowUtc >= _activeGrant.ExpiresAtUtc)) ||
            NowUtc >= Authorization.ExpiresAtUtc)
        { throw Invalid(); }
        // Each permit admits exactly the next fresh database. Applied replay needs independent
        // marker/checkpoint and complete preserved-internal evidence; it is deliberately unavailable.
        return _bundle.Capsule.Databases[ordinal];
    }

    internal bool RequirePlanBinding(CanonicalDeltaTargetBinding binding)
    {
        return binding.PlanSha256 != Admission.PersistentPlanSha256 || binding.Database !=
            DatabaseInventory.ActiveDatabases[checked((int)Continuation.Ordinal - 1)]
            ? throw Invalid()
            : true;
    }

    internal async Task RequireFreshAsync(CancellationToken cancellationToken)
    {
        SourceBackedLocalRepairClaim claim = _activeGrant is null
            ? await _admissions.VerifyRetainedAsync(Admission, _bundle.Capsule, _plans, _proof, _schema,
                Authorization, cancellationToken).ConfigureAwait(false)
            : await _admissions.VerifyRetainedAsync(Admission, _bundle.Capsule, _plans, _proof, _schema,
                Authorization, _activeGrant, cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairContinuation retained = await _continuations.ReadAsync(claim.ClaimId,
            claim.AdmissionSha256, Continuation.Ordinal, Authorization, NowUtc, cancellationToken, _activeGrant).ConfigureAwait(false);
        if (SourceBackedLocalRepairContinuationStore.ComputeSha256(retained) !=
            SourceBackedLocalRepairContinuationStore.ComputeSha256(Continuation)) { throw Invalid(); }
        HistoricalCurrentLocalObservation actual = await _observe(cancellationToken).ConfigureAwait(false);
        if (actual != Admission.TargetIdentity) { throw Invalid(); }
        await _maintenance.RequireStillQuiescentAsync(actual, cancellationToken).ConfigureAwait(false);
        _ = Require(_plans.Persistent, _schema.Databases[checked((int)Continuation.Ordinal - 1)]);
    }

    private static T Snapshot<T>(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value)) ?? throw Invalid();
    }

    internal static DeltaExecutionException Invalid()
    {
        return new("delta_source_repair_execution_invalid", "Fresh retained source repair admission, ordinal, identity and maintenance must match; replay requires separate authenticated evidence.");
    }
}
