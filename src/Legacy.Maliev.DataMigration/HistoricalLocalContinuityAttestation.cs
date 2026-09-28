using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>
/// A prospective signed claim about an old reconciled LOCAL state and a fresh
/// read-only comparison. It is not an execution permit or a fence-adoption token.
/// </summary>
public sealed record HistoricalLocalContinuityAttestation(
    string SchemaVersion,
    Guid AttestationId,
    string HistoricalPlanSha256,
    string HistoricalReceiptSha256,
    string HistoricalSchemaSha256,
    DateTimeOffset HistoricalSourceCutoffUtc,
    string PriorDockerGeneration,
    string CurrentDockerGeneration,
    string CurrentObservationSha256,
    string CurrentReviewSha256,
    bool FormerContainerAbsentObserved,
    IReadOnlyList<HistoricalLocalMetadataBinding> PriorMetadata,
    string FuturePlanSha256,
    Guid FutureAuthorizationId,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string AttestationKeyId,
    string? AttestationSignature)
{
    public static bool AuthorizesExecution => false;
}

public sealed record HistoricalLocalMetadataBinding(string Database,
    PairedLocalTransitionMetadataState State, string FingerprintSha256);

public sealed record HistoricalLocalContinuityReview(Guid AttestationId, string AttestationSha256,
    DateTimeOffset HistoricalSourceCutoffUtc, DateTimeOffset ExpiresAtUtc, int MetadataBindingsVerified)
{
    public static bool AuthorizesExecution => false;
}

public static class HistoricalLocalContinuityAttestationCanonicalizer
{
    private static ReadOnlySpan<byte> Domain => "legacy-maliev-historical-local-continuity-v1\0"u8;

    public static byte[] CreatePayload(HistoricalLocalContinuityAttestation attestation)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(attestation with { AttestationSignature = null });
        return [.. Domain, .. json];
    }

    public static string ComputeSha256(HistoricalLocalContinuityAttestation attestation)
    {
        return Convert.ToHexString(SHA256.HashData(CreatePayload(attestation))).ToLowerInvariant();
    }

    public static string ComputeReviewSha256(HistoricalPairedLocalCurrentTargetReview review)
    {
        ArgumentNullException.ThrowIfNull(review);
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(review);
        return Convert.ToHexString(SHA256.HashData(
            [.. "legacy-maliev-historical-local-current-review-v1\0"u8, .. json])).ToLowerInvariant();
    }

    public static string ComputeObservationSha256(HistoricalCurrentLocalObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(observation);
        return Convert.ToHexString(SHA256.HashData(
            [.. "legacy-maliev-historical-local-observation-v1\0"u8, .. json])).ToLowerInvariant();
    }
}

public static class HistoricalLocalContinuityAttestationVerifier
{
    /// <summary>
    /// Rebuilds the current-target review from fresh read-only observations before
    /// checking the signed claim. This never grants a transition permit or writes
    /// a generation fence. A changed row digest prevents any review from being
    /// returned, even when the signed historical receipt is authentic.
    /// </summary>
    public static async Task<HistoricalLocalContinuityReview> VerifyFreshAsync(
        HistoricalLocalContinuityAttestation? attestation,
        DeltaSynchronizationPlan historicalPlan,
        Exact23DeltaReconciliationResult historicalReceipt,
        FreshSchemaPlan historicalSchema,
        HistoricalPairedLocalCurrentTargetReview signedReview,
        Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observeCurrentTarget,
        IDeltaReconciliationInspector currentTarget,
        Func<CancellationToken, Task<IReadOnlyList<HistoricalLocalMetadataBinding>>> observePriorMetadata,
        string expectedFuturePlanSha256,
        Guid expectedFutureAuthorizationId,
        IReceiptAttestationTrustStore trust,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(observeCurrentTarget);
        ArgumentNullException.ThrowIfNull(currentTarget);
        ArgumentNullException.ThrowIfNull(observePriorMetadata);
        ArgumentNullException.ThrowIfNull(clock);
        IReadOnlyList<HistoricalLocalMetadataBinding> before =
            await observePriorMetadata(cancellationToken).ConfigureAwait(false);
        HistoricalPairedLocalCurrentTargetReview freshReview =
            await HistoricalPairedLocalCurrentTargetReviewer.CompareAsync(historicalPlan,
                historicalReceipt, historicalSchema, trust, observeCurrentTarget,
                currentTarget, clock, cancellationToken).ConfigureAwait(false);
        if (signedReview is null ||
            signedReview.HistoricalPlanSha256 != freshReview.HistoricalPlanSha256 ||
            signedReview.HistoricalReceiptSha256 != freshReview.HistoricalReceiptSha256 ||
            signedReview.HistoricalSourceCutoffUtc != freshReview.HistoricalSourceCutoffUtc ||
            signedReview.CurrentDockerGeneration != freshReview.CurrentDockerGeneration ||
            signedReview.DatabasesCompared != freshReview.DatabasesCompared ||
            signedReview.ComparedAtUtc > freshReview.ComparedAtUtc)
        {
            throw Invalid();
        }
        IReadOnlyList<HistoricalLocalMetadataBinding> after =
            await observePriorMetadata(cancellationToken).ConfigureAwait(false);
        if (before is null || after is null || !before.SequenceEqual(after))
        {
            throw Invalid();
        }
        HistoricalCurrentLocalObservation observation =
            await observeCurrentTarget(cancellationToken).ConfigureAwait(false);
        return Verify(attestation, historicalPlan, historicalReceipt, historicalSchema,
            signedReview, observation, after, expectedFuturePlanSha256,
            expectedFutureAuthorizationId, trust, clock.GetUtcNow());
    }

    public static HistoricalLocalContinuityReview Verify(
        HistoricalLocalContinuityAttestation? attestation,
        DeltaSynchronizationPlan historicalPlan,
        Exact23DeltaReconciliationResult historicalReceipt,
        FreshSchemaPlan historicalSchema,
        HistoricalPairedLocalCurrentTargetReview currentReview,
        HistoricalCurrentLocalObservation currentObservation,
        IReadOnlyList<HistoricalLocalMetadataBinding> observedPriorMetadata,
        string expectedFuturePlanSha256,
        Guid expectedFutureAuthorizationId,
        IReceiptAttestationTrustStore trust,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(trust);
        HistoricalPairedLocalEvidenceReview historical = HistoricalPairedLocalEvidenceReviewer.Verify(
            historicalPlan, historicalReceipt, trust, nowUtc);
        return attestation is null || historicalSchema.SchemaVersion != "2.0" ||
            historicalSchema.Databases is null ||
            !historicalSchema.Databases.Select(database => database.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            nowUtc.Offset != TimeSpan.Zero || attestation.SchemaVersion != "1.0" ||
            attestation.AttestationId == Guid.Empty || expectedFutureAuthorizationId == Guid.Empty ||
            !Fixed(historicalPlan.SchemaPlanSha256, SchemaPlanCanonicalizer.ComputeSha256(historicalSchema)) ||
            !Fixed(attestation.HistoricalPlanSha256, historical.PlanSha256) ||
            !Fixed(attestation.HistoricalReceiptSha256, historical.ReconciliationSha256) ||
            !Fixed(attestation.HistoricalSchemaSha256, historicalPlan.SchemaPlanSha256) ||
            attestation.HistoricalSourceCutoffUtc != historical.SourceCutoffUtc ||
            attestation.PriorDockerGeneration != historicalPlan.TargetGeneration ||
            attestation.CurrentDockerGeneration != currentObservation.DockerGeneration ||
            attestation.CurrentDockerGeneration == attestation.PriorDockerGeneration ||
            !Fixed(attestation.CurrentObservationSha256,
                HistoricalLocalContinuityAttestationCanonicalizer.ComputeObservationSha256(currentObservation)) ||
            !Fixed(attestation.CurrentReviewSha256,
                HistoricalLocalContinuityAttestationCanonicalizer.ComputeReviewSha256(currentReview)) ||
            !Fixed(currentReview.HistoricalPlanSha256, historical.PlanSha256) ||
            !Fixed(currentReview.HistoricalReceiptSha256, historical.ReconciliationSha256) ||
            currentReview.HistoricalSourceCutoffUtc != historical.SourceCutoffUtc ||
            currentReview.CurrentDockerGeneration != currentObservation.DockerGeneration ||
            currentReview.DatabasesCompared != DatabaseInventory.ActiveDatabases.Count ||
            !attestation.FormerContainerAbsentObserved ||
            !ValidObservation(historicalPlan, currentObservation) ||
            !ValidMetadata(attestation.PriorMetadata, observedPriorMetadata) ||
            !Fixed(attestation.FuturePlanSha256, expectedFuturePlanSha256) ||
            attestation.FutureAuthorizationId != expectedFutureAuthorizationId ||
            attestation.IssuedAtUtc.Offset != TimeSpan.Zero ||
            attestation.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            attestation.IssuedAtUtc < currentReview.ComparedAtUtc ||
            attestation.IssuedAtUtc > nowUtc || nowUtc >= attestation.ExpiresAtUtc ||
            attestation.ExpiresAtUtc - attestation.IssuedAtUtc > TimeSpan.FromMinutes(15) ||
            string.IsNullOrWhiteSpace(attestation.AttestationKeyId) ||
            string.IsNullOrWhiteSpace(attestation.AttestationSignature) ||
            !DistinctTrustedSigner(attestation, historicalPlan, historicalReceipt, trust) ||
            !VerifySignature(attestation, trust)
            ? throw Invalid()
            : new(attestation.AttestationId,
                HistoricalLocalContinuityAttestationCanonicalizer.ComputeSha256(attestation),
                historical.SourceCutoffUtc, attestation.ExpiresAtUtc, DatabaseInventory.ActiveDatabases.Count);
    }

    private static bool ValidObservation(DeltaSynchronizationPlan plan,
        HistoricalCurrentLocalObservation observation)
    {
        string[] current = observation.DockerGeneration?.Split(':') ?? [];
        string[] prior = plan.TargetGeneration.Split(':');
        return current.Length == 5 && prior.Length == 5 && current[0] == "docker" &&
            current[1] == observation.ContainerId && current[1].Length == 64 &&
            current[1].All(char.IsAsciiHexDigit) && current[1] != prior[1] &&
            current.Skip(2).All(value => long.TryParse(value,
                System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture,
                out long milliseconds) && milliseconds > 0) &&
            current[4] == prior[4] && observation.VolumeName == "legacy-maliev-exact23-postgres-data" &&
            observation.VolumeCreatedAtUtc.Offset == TimeSpan.Zero &&
            observation.VolumeCreatedAtUtc.ToUnixTimeMilliseconds().ToString(
                System.Globalization.CultureInfo.InvariantCulture) == current[4] &&
            !string.IsNullOrWhiteSpace(observation.VolumeMountpoint) &&
            !string.IsNullOrWhiteSpace(observation.VolumeDestination) &&
            (observation.PgData == observation.VolumeDestination ||
                observation.PgData.StartsWith(observation.VolumeDestination.TrimEnd('/') + "/",
                    StringComparison.Ordinal)) &&
            Fixed(observation.SystemIdentifierSha256, plan.TargetAuthority?.SystemIdentifierSha256);
    }

    private static bool ValidMetadata(IReadOnlyList<HistoricalLocalMetadataBinding>? signed,
        IReadOnlyList<HistoricalLocalMetadataBinding>? observed)
    {
        return signed is not null && observed is not null &&
            signed.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases,
                StringComparer.Ordinal) &&
            observed.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases,
                StringComparer.Ordinal) &&
            signed.Zip(observed).All(pair => pair.First == pair.Second &&
                pair.First.State == PairedLocalTransitionMetadataState.SettledPrior &&
                Fixed(pair.First.FingerprintSha256, pair.Second.FingerprintSha256));
    }

    private static bool DistinctTrustedSigner(HistoricalLocalContinuityAttestation attestation,
        DeltaSynchronizationPlan plan, Exact23DeltaReconciliationResult receipt,
        IReceiptAttestationTrustStore trust)
    {
        return trust.TryGetPublicKeyFingerprintSha256(attestation.AttestationKeyId, out string continuity) &&
            trust.TryGetPublicKeyFingerprintSha256(plan.AttestationKeyId, out string planKey) &&
            trust.TryGetPublicKeyFingerprintSha256(receipt.AttestationKeyId, out string receiptKey) &&
            !Fixed(continuity, planKey) && !Fixed(continuity, receiptKey) &&
            !Fixed(continuity, plan.ExecutionAuthorizationKeyFingerprintSha256) &&
            !Fixed(continuity, plan.BackupKeyFingerprintSha256);
    }

    private static bool VerifySignature(HistoricalLocalContinuityAttestation attestation,
        IReceiptAttestationTrustStore trust)
    {
        try
        {
            return trust.Verify(attestation.AttestationKeyId,
                HistoricalLocalContinuityAttestationCanonicalizer.CreatePayload(attestation),
                Convert.FromBase64String(attestation.AttestationSignature!));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool Fixed(string? left, string? right)
    {
        return left is { Length: 64 } && right is { Length: 64 } &&
            left.All(char.IsAsciiHexDigit) && right.All(char.IsAsciiHexDigit) &&
            CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(left.ToLowerInvariant()),
                Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    private static DeltaExecutionException Invalid()
    {
        return new("delta_historical_local_continuity_invalid",
            "The prospective signed LOCAL continuity evidence is incomplete or untrusted.");
    }
}
