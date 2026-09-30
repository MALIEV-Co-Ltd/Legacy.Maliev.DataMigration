namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Consumes the published continuity bundle without reconstructing its signed
/// review. Claim creation is not a continuation, fence update, or execution permit.
/// </summary>
public static class HistoricalLocalContinuityClaimIssuer
{
    /// <summary>
    /// Validates the published authorization and exact signed review, rescans the
    /// current target and old metadata, then reserves one immutable claim. Old
    /// bundles without the review are rejected; no evidence is reconstructed.
    /// </summary>
    public static async Task<ImmutableRolloverClaim> CreateAsync(
        ImmutableRolloverClaimStore store,
        HistoricalLocalContinuityIssuance issuance,
        DeltaSynchronizationPlan historicalPlan,
        Exact23DeltaReconciliationResult historicalReceipt,
        FreshSchemaPlan historicalSchema,
        PairedCapturedDeltaPlans futurePlans,
        Exact23DeltaReconciliationResult disposableProof,
        FreshSchemaPlan futureSchema,
        Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observeTarget,
        IDeltaReconciliationInspector currentTarget,
        Func<CancellationToken, Task<IReadOnlyList<HistoricalLocalMetadataBinding>>> observePriorMetadata,
        IReceiptAttestationTrustStore trust,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(clock);
        if (issuance is not
            {
                CurrentTargetReview: { } review, Attestation: { } attestation,
                FutureAuthorization: { } authorization
            } ||
            !DeltaSynchronizationPlanProducer.FixedHashEquals(
                attestation.CurrentReviewSha256,
                HistoricalLocalContinuityAttestationCanonicalizer.ComputeReviewSha256(review)) ||
            attestation.FutureAuthorizationId != authorization.AuthorizationId ||
            !trust.TryGetPublicKeyFingerprintSha256(attestation.AttestationKeyId, out string continuityKey) ||
            !trust.TryGetPublicKeyFingerprintSha256(authorization.AttestationKeyId, out string authorizationKey) ||
            DeltaSynchronizationPlanProducer.FixedHashEquals(continuityKey, authorizationKey) ||
            futurePlans.Persistent.TargetAuthority is not { } authority)
        {
            throw new DeltaExecutionException("delta_historical_local_issuance_invalid",
                "The published signed continuity bundle must retain its exact current-target review.");
        }
        PairedLocalTransitionAuthorizationPolicy.Verify(authorization, futurePlans,
            disposableProof, futureSchema, trust, authority,
            futurePlans.Persistent.TargetObservationSha256,
            futurePlans.Persistent.QuotationTransitionSchemaSha256 ?? string.Empty,
            clock.GetUtcNow());
        HistoricalCurrentLocalObservation expected = await observeTarget(cancellationToken)
            .ConfigureAwait(false);
        return await store.CreateFromFreshEvidenceAsync(attestation, historicalPlan,
            historicalReceipt, historicalSchema, review, observeTarget, currentTarget,
            observePriorMetadata, expected,
            DeltaSynchronizationPlanCanonicalizer.ComputeSha256(futurePlans.Persistent),
            authorization.AuthorizationId, trust, clock, cancellationToken).ConfigureAwait(false);
    }
}
