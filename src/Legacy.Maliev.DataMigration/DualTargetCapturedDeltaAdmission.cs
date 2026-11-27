using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record DualTargetCapturedDeltaReview(string Kind, Guid ReviewId, string BundleSha256,
    DualTargetCapturedDeltaPurpose Purpose, string PlanSha256, string DisposableProofSha256,
    string RuntimeObservationSha256, IReadOnlyDictionary<string, string> NativeBeforeSha256,
    string AcceptedMainCommitSha, DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc, string AttestationKeyId, string? AttestationSignature);

// This validates evidence only. The fixed Console issuer must observe live source, tools,
// generation and protected-main custody before issuing or consuming this review.
internal static class DualTargetCapturedDeltaAdmission
{
    private const string ReviewKind = "legacy-maliev-dual-target-captured-review-v1";
    internal static byte[] Payload(DualTargetCapturedDeltaReview review)
    {
        return [.. Encoding.UTF8.GetBytes(ReviewKind + "\0"), .. JsonSerializer.SerializeToUtf8Bytes(review with { AttestationSignature = null })];
    }

    internal static string ProofHash(Exact23DeltaReconciliationResult proof)
    {
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(proof))).ToLowerInvariant();
    }

    internal static void RequireProof(DualTargetCapturedDeltaBundle bundle, DualTargetCapturedDeltaPurpose purpose,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        DualTargetCapturedDeltaContract.Verify(bundle, schema, trust, now);
        DualTargetCapturedDeltaPurpose proofPurpose = ProofPurpose(purpose);
        DualTargetCapturedDeltaPlan member = bundle.Plans.Single(x => x.Purpose == proofPurpose);
        DeltaSynchronizationPlan plan = member.Plan;
        if (proof.AttestationKeyId != member.EvidenceKeyId ||
            !Exact23DeltaReconciliationCoordinator.VerifyForSchema(proof, plan, schema, trust) || proof.ReconciledAtUtc > now ||
            proof.ReconciledAtUtc < plan.CreatedAtUtc || now - proof.ReconciledAtUtc > TimeSpan.FromHours(12) ||
            proof.Checkpoints.Count != DatabaseInventory.ActiveDatabases.Count ||
            proof.Checkpoints.Any(x => x.TargetObservationSha256 != plan.TargetObservationSha256))
        { throw DualTargetCapturedDeltaContract.Invalid(); }
    }

    internal static DualTargetCapturedDeltaReview Issue(DualTargetCapturedDeltaBundle bundle, DualTargetCapturedDeltaPurpose purpose,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, IReceiptAttestationTrustStore trust,
        string observedRuntimeSha256, IReadOnlyDictionary<string, string> nativeBeforeSha256,
        string acceptedMainCommitSha, P256MigrationEvidenceSigner signer,
        DateTimeOffset now, DateTimeOffset expires)
    {
        RequireProof(bundle, purpose, proof, schema, trust, now);
        RequireNativeInventory(nativeBeforeSha256, purpose);
        if (!HashShape(observedRuntimeSha256) || acceptedMainCommitSha != bundle.SourceCommitSha ||
            now.Offset != TimeSpan.Zero || expires.Offset != TimeSpan.Zero || expires <= now || expires - now > TimeSpan.FromMinutes(15))
        { throw DualTargetCapturedDeltaContract.Invalid(); }
        DeltaSynchronizationPlan plan = bundle.Plans.Single(x => x.Purpose == purpose).Plan;
        DualTargetCapturedTargetObservation bound = bundle.Plans.Single(x => x.Purpose == purpose).Observation;
        if (bound.RuntimeSha256 != observedRuntimeSha256 || !bound.NativeBeforeSha256.OrderBy(x => x.Key, StringComparer.Ordinal).SequenceEqual(
            nativeBeforeSha256.OrderBy(x => x.Key, StringComparer.Ordinal))) { throw DualTargetCapturedDeltaContract.Invalid(); }
        if (signer.KeyId == plan.AttestationKeyId || signer.PublicKeyFingerprintSha256 == plan.ExecutionAuthorizationKeyFingerprintSha256 ||
            signer.PublicKeyFingerprintSha256 == plan.BackupKeyFingerprintSha256) { throw DualTargetCapturedDeltaContract.Invalid(); }
        var review = new DualTargetCapturedDeltaReview(ReviewKind, Guid.NewGuid(), DualTargetCapturedDeltaContract.Hash(bundle), purpose,
            DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan), ProofHash(proof), observedRuntimeSha256,
            nativeBeforeSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal), acceptedMainCommitSha,
            now, expires, signer.KeyId, null);
        return review with { AttestationSignature = Convert.ToBase64String(signer.Sign(Payload(review))) };
    }

    internal static void Require(DualTargetCapturedDeltaReview review, DualTargetCapturedDeltaBundle bundle,
        DualTargetCapturedDeltaPurpose purpose, Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        IReceiptAttestationTrustStore trust, string expectedReviewKeyFingerprintSha256, string actualRuntimeSha256,
        string actualAcceptedMainCommitSha, DateTimeOffset now)
    {
        RequireProof(bundle, purpose, proof, schema, trust, now);
        RequireNativeInventory(review.NativeBeforeSha256, purpose);
        DeltaSynchronizationPlan plan = bundle.Plans.Single(x => x.Purpose == purpose).Plan;
        if (review.Kind != ReviewKind || review.ReviewId == Guid.Empty || review.BundleSha256 != DualTargetCapturedDeltaContract.Hash(bundle) ||
            review.Purpose != purpose || review.PlanSha256 != DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan) ||
            review.DisposableProofSha256 != ProofHash(proof) || review.RuntimeObservationSha256 != actualRuntimeSha256 ||
            !HashShape(actualRuntimeSha256) || review.AcceptedMainCommitSha != actualAcceptedMainCommitSha ||
            actualAcceptedMainCommitSha != bundle.SourceCommitSha || review.IssuedAtUtc > now || now >= review.ExpiresAtUtc ||
            review.ExpiresAtUtc - review.IssuedAtUtc > TimeSpan.FromMinutes(15) ||
            !trust.TryGetPublicKeyFingerprintSha256(review.AttestationKeyId, out string fingerprint) ||
            !DeltaSynchronizationPlanProducer.FixedHashEquals(fingerprint, expectedReviewKeyFingerprintSha256) ||
            string.IsNullOrEmpty(review.AttestationSignature)) { throw DualTargetCapturedDeltaContract.Invalid(); }
        try
        {
            if (!trust.Verify(review.AttestationKeyId, Payload(review), Convert.FromBase64String(review.AttestationSignature)))
            { throw DualTargetCapturedDeltaContract.Invalid(); }
        }
        catch (FormatException) { throw DualTargetCapturedDeltaContract.Invalid(); }
    }
    internal static DualTargetCapturedDeltaPurpose ProofPurpose(DualTargetCapturedDeltaPurpose purpose)
    {
        return purpose switch
        {
            DualTargetCapturedDeltaPurpose.Production => DualTargetCapturedDeltaPurpose.ProductionProof,
            DualTargetCapturedDeltaPurpose.PersistentLocal => DualTargetCapturedDeltaPurpose.LocalProof,
            DualTargetCapturedDeltaPurpose.ProductionProof => throw DualTargetCapturedDeltaContract.Invalid(),
            DualTargetCapturedDeltaPurpose.LocalProof => throw DualTargetCapturedDeltaContract.Invalid(),
            _ => throw DualTargetCapturedDeltaContract.Invalid()
        };
    }

    private static bool HashShape(string value)
    {
        return value.Length == 64 && value.All(char.IsAsciiHexDigit);
    }

    private static void RequireNativeInventory(IReadOnlyDictionary<string, string> hashes, DualTargetCapturedDeltaPurpose purpose)
    {
        string kind = purpose == DualTargetCapturedDeltaPurpose.Production ? DeltaTargetAuthorityKind.ProductionCloudNativePg : DeltaTargetAuthorityKind.LocalAspire;
        if (!ReviewedProductionRepairInventory.MatchesKeys(kind, hashes.Keys) ||
            hashes.Values.Any(x => !HashShape(x))) { throw DualTargetCapturedDeltaContract.Invalid(); }
    }
}
