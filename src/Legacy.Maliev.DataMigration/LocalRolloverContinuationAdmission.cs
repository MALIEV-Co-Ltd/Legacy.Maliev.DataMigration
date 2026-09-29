using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Internal per-database admission; no CLI or live rollover entry point uses it.</summary>
internal sealed record LocalRolloverContinuationAdmission(
    HistoricalLocalMixedContinuation Continuation,
    PairedLocalTransitionAuthorization Authorization,
    PairedLocalTransitionExecutionPermit PairedPermit,
    LocalRolloverAdoptionPermit RolloverPermit);

internal static class LocalRolloverContinuationIssuer
{
    internal static async Task<LocalRolloverContinuationAdmission> IssueAsync(
        AuthenticatedHistoricalLocalRolloverReader reader,
        ImmutableRolloverClaimStore store,
        Guid claimId, HistoricalLocalContinuityAttestation attestation,
        DeltaSynchronizationPlan historicalPlan,
        Exact23DeltaReconciliationResult historicalReceipt,
        FreshSchemaPlan historicalSchema, PairedCapturedDeltaPlans futurePlans,
        Exact23DeltaReconciliationResult disposableProof, FreshSchemaPlan futureSchema,
        IReceiptAttestationTrustStore trust,
        P256MigrationEvidenceSigner authorizationSigner,
        P256MigrationEvidenceSigner continuationSigner,
        TimeProvider clock, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clock);
        AuthenticatedHistoricalLocalRolloverSnapshot before = await reader.ReadAsync(
            claimId, attestation, historicalPlan, historicalReceipt, historicalSchema,
            futurePlans, disposableProof, futureSchema, trust, cancellationToken)
            .ConfigureAwait(false);
        if (futurePlans.Persistent.TargetAuthority is not { } authority ||
            authority.AuthorityId !=
                "aspire://legacy-postgres-main-local/persistent-" +
                before.TargetIdentity.ContainerId[..12] ||
            authority.SystemIdentifierSha256 !=
                before.TargetIdentity.SystemIdentifierSha256)
        {
            throw Invalid();
        }
        DateTimeOffset issuedAtUtc = clock.GetUtcNow();
        PairedLocalTransitionAuthorization authorization =
            PairedLocalTransitionAuthorizationPolicy.Produce(futurePlans, disposableProof,
                futureSchema, trust, authority,
                futurePlans.Persistent.TargetObservationSha256,
                futurePlans.Persistent.QuotationTransitionSchemaSha256 ?? string.Empty,
                issuedAtUtc, issuedAtUtc.AddMinutes(15), authorizationSigner);
        HistoricalLocalMixedContinuation continuation =
            HistoricalLocalMixedContinuationIssuer.Issue(before.ContinuationClaim,
                before.Databases, authorization, continuationSigner, trust,
                clock.GetUtcNow());
        _ = await store.ReserveSignedOrdinalAsync(before.Claim, continuation,
            authorization, before.Databases, trust, clock.GetUtcNow(),
            cancellationToken).ConfigureAwait(false);
        AuthenticatedHistoricalLocalRolloverSnapshot after = await reader.ReadAsync(
            claimId, attestation, historicalPlan, historicalReceipt, historicalSchema,
            futurePlans, disposableProof, futureSchema, trust, cancellationToken)
            .ConfigureAwait(false);
        if (after.TargetIdentity != before.TargetIdentity ||
            !JsonSerializer.SerializeToUtf8Bytes(after.Claim).AsSpan()
                .SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(before.Claim)) ||
            after.ContinuationClaim.NextContinuationOrdinal !=
                before.ContinuationClaim.NextContinuationOrdinal + 1 ||
            !after.Databases.SequenceEqual(before.Databases))
        {
            throw Invalid();
        }
        DateTimeOffset admittedAtUtc = clock.GetUtcNow();
        PairedLocalTransitionAuthorizationPolicy.Verify(authorization, futurePlans,
            disposableProof, futureSchema, trust, authority,
            futurePlans.Persistent.TargetObservationSha256,
            futurePlans.Persistent.QuotationTransitionSchemaSha256 ?? string.Empty,
            admittedAtUtc);
        _ = HistoricalLocalMixedContinuationVerifier.Verify(continuation,
            before.ContinuationClaim, after.Databases, authorization, trust,
            admittedAtUtc);
        PairedLocalTransitionExecutionPermit pairedPermit =
            PairedLocalTransitionExecutionPermit.Admit(futurePlans,
                disposableProof, authorization, futureSchema, trust, authority,
                futurePlans.Persistent.TargetObservationSha256, clock);
        var rolloverPermit = new LocalRolloverAdoptionPermit(after.Claim,
            continuation, authorization, clock, reader.ObserveTargetAsync);
        return new(continuation, authorization, pairedPermit, rolloverPermit);
    }

    private static DeltaExecutionException Invalid()
    {
        return new("delta_rollover_continuation_admission_invalid",
            "Fresh exact-23 LOCAL claim evidence changed during continuation admission.");
    }
}
