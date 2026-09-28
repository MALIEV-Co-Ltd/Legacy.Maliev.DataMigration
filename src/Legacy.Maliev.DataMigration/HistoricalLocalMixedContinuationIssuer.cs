namespace Legacy.Maliev.DataMigration;

/// <summary>Signs one fresh, PII-free exact-23 mixed-state observation.</summary>
internal static class HistoricalLocalMixedContinuationIssuer
{
    internal static HistoricalLocalMixedContinuation Issue(
        HistoricalLocalRolloverClaimSnapshot claim,
        IReadOnlyList<HistoricalLocalRolloverDatabaseState> observedDatabases,
        PairedLocalTransitionAuthorization authorization,
        P256MigrationEvidenceSigner signer, IReceiptAttestationTrustStore trust,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(signer);
        if (nowUtc.Offset != TimeSpan.Zero ||
            !trust.TryGetPublicKeyFingerprintSha256(signer.KeyId, out string trusted) ||
            trusted != signer.PublicKeyFingerprintSha256 ||
            nowUtc < authorization.IssuedAtUtc || nowUtc >= authorization.ExpiresAtUtc)
        {
            throw Invalid();
        }
        DateTimeOffset expires = nowUtc.AddMinutes(15) < authorization.ExpiresAtUtc
            ? nowUtc.AddMinutes(15) : authorization.ExpiresAtUtc;
        var unsigned = new HistoricalLocalMixedContinuation("1.0", claim.ClaimId,
            claim.InitialAttestationSha256, claim.FuturePlanSha256,
            claim.TargetGeneration, authorization.AuthorizationId,
            claim.NextContinuationOrdinal, [.. observedDatabases], nowUtc,
            expires, signer.KeyId, null);
        HistoricalLocalMixedContinuation signed = unsigned with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(
                HistoricalLocalMixedContinuationCanonicalizer.CreatePayload(unsigned))),
        };
        _ = HistoricalLocalMixedContinuationVerifier.Verify(signed, claim,
            observedDatabases, authorization, trust, nowUtc);
        return signed;
    }

    private static DeltaExecutionException Invalid()
    {
        return new("delta_historical_local_mixed_continuation_invalid",
            "Fresh signed LOCAL continuation evidence is required.");
    }
}
