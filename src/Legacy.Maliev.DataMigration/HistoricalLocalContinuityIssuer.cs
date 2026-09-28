namespace Legacy.Maliev.DataMigration;

/// <summary>
/// A create-only candidate for owner-controlled publication. Neither member is
/// accepted by an executor as a cross-container permit.
/// </summary>
public sealed record HistoricalLocalContinuityIssuance(
    PairedLocalTransitionAuthorization FutureAuthorization,
    HistoricalLocalContinuityAttestation Attestation)
{
    public static bool AuthorizesExecution => false;
}

public static class HistoricalLocalContinuityIssuer
{
    /// <summary>
    /// Issues evidence from fresh read-only target and metadata observations.
    /// In particular, this does not call paired-transition preflight: the old
    /// generation fence cannot be adopted before continuity is established.
    /// </summary>
    public static async Task<HistoricalLocalContinuityIssuance> IssueAsync(
        DeltaSynchronizationPlan historicalPlan,
        Exact23DeltaReconciliationResult historicalReceipt,
        FreshSchemaPlan historicalSchema,
        PairedCapturedDeltaPlans futurePlans,
        Exact23DeltaReconciliationResult disposableProof,
        FreshSchemaPlan futureSchema,
        IReceiptAttestationTrustStore trust,
        Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observeCurrentTarget,
        IDeltaReconciliationInspector currentTarget,
        Func<CancellationToken, Task<IReadOnlyList<HistoricalLocalMetadataBinding>>> observePriorMetadata,
        DateTimeOffset expiresAtUtc,
        P256MigrationEvidenceSigner authorizationSigner,
        P256MigrationEvidenceSigner continuitySigner,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(futurePlans);
        ArgumentNullException.ThrowIfNull(observeCurrentTarget);
        ArgumentNullException.ThrowIfNull(observePriorMetadata);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(continuitySigner);
        IReadOnlyList<HistoricalLocalMetadataBinding> before =
            await observePriorMetadata(cancellationToken).ConfigureAwait(false);
        HistoricalCurrentLocalObservation? reviewedObservation = null;
        HistoricalPairedLocalCurrentTargetReview review =
            await HistoricalPairedLocalCurrentTargetReviewer.CompareAsync(historicalPlan,
                historicalReceipt, historicalSchema, trust, async token =>
                {
                    reviewedObservation = await observeCurrentTarget(token).ConfigureAwait(false);
                    return reviewedObservation;
                },
                currentTarget, clock, cancellationToken).ConfigureAwait(false);
        HistoricalCurrentLocalObservation observation =
            await observeCurrentTarget(cancellationToken).ConfigureAwait(false);
        IReadOnlyList<HistoricalLocalMetadataBinding> after =
            await observePriorMetadata(cancellationToken).ConfigureAwait(false);
        DeltaSynchronizationPlan future = futurePlans.Persistent;
        DeltaTargetAuthority authority = future.TargetAuthority ?? throw Invalid();
        if (before is null || after is null || !before.SequenceEqual(after) ||
            reviewedObservation != observation ||
            future.TargetGeneration != observation.DockerGeneration ||
            authority.SystemIdentifierSha256 != observation.SystemIdentifierSha256 ||
            authority.AuthorityId !=
                "aspire://legacy-postgres-main-local/persistent-" + observation.ContainerId[..12] ||
            future.TargetGeneration == historicalPlan.TargetGeneration ||
            continuitySigner.PublicKeyFingerprintSha256 == authorizationSigner.PublicKeyFingerprintSha256 ||
            !trust.TryGetPublicKeyFingerprintSha256(continuitySigner.KeyId, out string trustedKey) ||
            trustedKey != continuitySigner.PublicKeyFingerprintSha256)
        {
            throw Invalid();
        }
        DateTimeOffset issuedAtUtc = clock.GetUtcNow();
        PairedLocalTransitionAuthorization authorization =
            PairedLocalTransitionAuthorizationPolicy.Produce(futurePlans, disposableProof,
                futureSchema, trust, authority, future.TargetObservationSha256,
                future.QuotationTransitionSchemaSha256 ?? string.Empty,
                issuedAtUtc, expiresAtUtc, authorizationSigner);
        string futurePlanHash = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(future);
        var unsigned = new HistoricalLocalContinuityAttestation("1.0", Guid.NewGuid(),
            DeltaSynchronizationPlanCanonicalizer.ComputeSha256(historicalPlan),
            Exact23DeltaReconciliationCoordinator.ComputeSha256(historicalReceipt),
            SchemaPlanCanonicalizer.ComputeSha256(historicalSchema), historicalPlan.SourceCutoffUtc,
            historicalPlan.TargetGeneration, observation.DockerGeneration,
            HistoricalLocalContinuityAttestationCanonicalizer.ComputeObservationSha256(observation),
            HistoricalLocalContinuityAttestationCanonicalizer.ComputeReviewSha256(review), true,
            after, futurePlanHash, authorization.AuthorizationId, issuedAtUtc,
            expiresAtUtc, continuitySigner.KeyId, null);
        HistoricalLocalContinuityAttestation signed = unsigned with
        {
            AttestationSignature = Convert.ToBase64String(continuitySigner.Sign(
                HistoricalLocalContinuityAttestationCanonicalizer.CreatePayload(unsigned))),
        };
        DateTimeOffset verifiedAtUtc = clock.GetUtcNow();
        PairedLocalTransitionAuthorizationPolicy.Verify(authorization, futurePlans,
            disposableProof, futureSchema, trust, authority, future.TargetObservationSha256,
            future.QuotationTransitionSchemaSha256 ?? string.Empty, verifiedAtUtc);
        _ = HistoricalLocalContinuityAttestationVerifier.Verify(signed, historicalPlan,
            historicalReceipt, historicalSchema, review, observation, after, futurePlanHash,
            authorization.AuthorizationId, trust, verifiedAtUtc);
        return new(authorization, signed);
    }

    private static DeltaExecutionException Invalid()
    {
        return new("delta_historical_local_continuity_invalid",
            "The prospective signed LOCAL continuity evidence is incomplete or untrusted.");
    }
}
