namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Opaque, LOCAL-only admission for a signed same-capture transition. Holding this
/// object does not itself authorize a write: the target must recheck identity,
/// physical schema, metadata, and row preimages in its serializable transaction.
/// </summary>
public sealed class PairedLocalTransitionExecutionPermit
{
    private readonly PairedCapturedDeltaPlans _plans;
    private readonly Exact23DeltaReconciliationResult _proof;
    private readonly PairedLocalTransitionAuthorization _authorization;
    private readonly FreshSchemaPlan _schema;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly DeltaTargetAuthority _authority;
    private readonly string _targetObservationSha256;

    private PairedLocalTransitionExecutionPermit(PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, PairedLocalTransitionAuthorization authorization,
        FreshSchemaPlan schema, IReceiptAttestationTrustStore trust,
        DeltaTargetAuthority authority, string targetObservationSha256)
    {
        _plans = plans;
        _proof = proof;
        _authorization = authorization;
        _schema = schema;
        _trust = trust;
        _authority = authority;
        _targetObservationSha256 = targetObservationSha256;
    }

    public static PairedLocalTransitionExecutionPermit Admit(PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, PairedLocalTransitionAuthorization authorization,
        FreshSchemaPlan schema, IReceiptAttestationTrustStore trust,
        DeltaTargetAuthority observedAuthority, string observedTargetObservationSha256,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(plans);
        ArgumentNullException.ThrowIfNull(schema);
        string transition = plans.Persistent.QuotationTransitionSchemaSha256 ?? string.Empty;
        PairedLocalTransitionAuthorizationPolicy.Verify(authorization, plans, proof, schema,
            trust, observedAuthority, observedTargetObservationSha256, transition, nowUtc);
        return new(plans, proof, authorization, schema, trust, observedAuthority,
            observedTargetObservationSha256);
    }

    public void Require(DeltaSynchronizationPlan plan, DatabaseSchemaPlan schema,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(schema);
        if (plan.SchemaVersion != "1.4" || plan.PairedTransitionPlanOnly != true ||
            !DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(plan.TargetAuthority) ||
            plan.TargetAuthority != _authority ||
            !DeltaSynchronizationPlanProducer.FixedHashEquals(
                DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan),
                DeltaSynchronizationPlanCanonicalizer.ComputeSha256(_plans.Persistent)) ||
            plan.SchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(_schema) ||
            !_schema.Databases.Any(database => database.Database == schema.Database &&
                database.TargetSchemaSha256 == schema.TargetSchemaSha256))
        {
            throw Invalid();
        }
        PairedLocalTransitionAuthorizationPolicy.Verify(_authorization, _plans, _proof,
            _schema, _trust, _authority, _targetObservationSha256,
            _plans.Persistent.QuotationTransitionSchemaSha256 ?? string.Empty, nowUtc);
    }

    private static DeltaExecutionException Invalid()
    {
        return new DeltaExecutionException("delta_paired_local_transition_authorization_invalid",
            "The signed LOCAL transition admission does not match this plan and schema.");
    }
}
