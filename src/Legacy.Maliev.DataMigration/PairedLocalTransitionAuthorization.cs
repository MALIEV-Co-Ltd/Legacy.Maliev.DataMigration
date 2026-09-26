using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Signed review artifact for a proven schema-1.4 persistent-local transition.
/// It is not accepted by the current execution authorization or metadata paths.
/// </summary>
public sealed record PairedLocalTransitionAuthorization(
    string SchemaVersion,
    Guid AuthorizationId,
    Guid PersistentPlanId,
    string PersistentPlanSha256,
    string DisposablePlanSha256,
    string DisposableReconciliationSha256,
    string SchemaPlanSha256,
    string QuotationTransitionSchemaSha256,
    DeltaTargetAuthority TargetAuthority,
    string TargetObservationSha256,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string AttestationKeyId,
    string? AttestationSignature);

public static class PairedLocalTransitionAuthorizationCanonicalizer
{
    private static ReadOnlySpan<byte> Domain =>
        "legacy-maliev-paired-local-transition-authorization-v1\0"u8;

    public static byte[] CreatePayload(PairedLocalTransitionAuthorization authorization)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(authorization with { AttestationSignature = null });
        return [.. Domain, .. json];
    }
}

/// <summary>
/// Binds fresh disposable proof and a current local physical observation to one
/// zero-delete paired plan. This does not implement an apply command or grant DML.
/// </summary>
public static class PairedLocalTransitionAuthorizationPolicy
{
    public static PairedLocalTransitionAuthorization Produce(
        PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult disposableResult,
        FreshSchemaPlan schema,
        IReceiptAttestationTrustStore trust,
        DeltaTargetAuthority observedLocalAuthority,
        string observedLocalTargetObservationSha256,
        string observedQuotationSchemaSha256,
        DateTimeOffset issuedAtUtc,
        DateTimeOffset expiresAtUtc,
        P256MigrationEvidenceSigner signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        ValidateEvidence(plans, disposableResult, schema, trust, observedLocalAuthority,
            observedLocalTargetObservationSha256,
            observedQuotationSchemaSha256, issuedAtUtc);
        DeltaSynchronizationPlan local = plans.Persistent;
        if (issuedAtUtc.Offset != TimeSpan.Zero || expiresAtUtc.Offset != TimeSpan.Zero ||
            expiresAtUtc <= issuedAtUtc || expiresAtUtc - issuedAtUtc > TimeSpan.FromMinutes(15) ||
            !DeltaSynchronizationPlanProducer.FixedHashEquals(
                signer.PublicKeyFingerprintSha256, local.ExecutionAuthorizationKeyFingerprintSha256) ||
            !trust.TryGetPublicKeyFingerprintSha256(signer.KeyId,
                out string trustedSignerFingerprint) ||
            !Fixed(trustedSignerFingerprint, signer.PublicKeyFingerprintSha256))
        {
            throw Invalid();
        }
        var unsigned = new PairedLocalTransitionAuthorization("1.0", Guid.NewGuid(), local.PlanId,
            DeltaSynchronizationPlanCanonicalizer.ComputeSha256(local),
            DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plans.Disposable),
            Exact23DeltaReconciliationCoordinator.ComputeSha256(disposableResult),
            local.SchemaPlanSha256, local.QuotationTransitionSchemaSha256!,
            observedLocalAuthority, local.TargetObservationSha256,
            issuedAtUtc, expiresAtUtc, signer.KeyId, null);
        return unsigned with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(
                PairedLocalTransitionAuthorizationCanonicalizer.CreatePayload(unsigned))),
        };
    }

    public static void Verify(
        PairedLocalTransitionAuthorization authorization,
        PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult disposableResult,
        FreshSchemaPlan schema,
        IReceiptAttestationTrustStore trust,
        DeltaTargetAuthority observedLocalAuthority,
        string observedLocalTargetObservationSha256,
        string observedQuotationSchemaSha256,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ValidateEvidence(plans, disposableResult, schema, trust, observedLocalAuthority,
            observedLocalTargetObservationSha256,
            observedQuotationSchemaSha256, nowUtc);
        DeltaSynchronizationPlan local = plans.Persistent;
        bool valid = authorization.SchemaVersion == "1.0" &&
            authorization.AuthorizationId != Guid.Empty &&
            authorization.PersistentPlanId == local.PlanId &&
            Fixed(authorization.PersistentPlanSha256,
                DeltaSynchronizationPlanCanonicalizer.ComputeSha256(local)) &&
            Fixed(authorization.DisposablePlanSha256,
                DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plans.Disposable)) &&
            Fixed(authorization.DisposableReconciliationSha256,
                Exact23DeltaReconciliationCoordinator.ComputeSha256(disposableResult)) &&
            Fixed(authorization.SchemaPlanSha256, local.SchemaPlanSha256) &&
            Fixed(authorization.QuotationTransitionSchemaSha256,
                local.QuotationTransitionSchemaSha256) &&
            authorization.TargetAuthority == observedLocalAuthority &&
            authorization.TargetAuthority == local.TargetAuthority &&
            Fixed(authorization.TargetObservationSha256, local.TargetObservationSha256) &&
            authorization.IssuedAtUtc.Offset == TimeSpan.Zero &&
            authorization.ExpiresAtUtc.Offset == TimeSpan.Zero &&
            authorization.IssuedAtUtc >= disposableResult.ReconciledAtUtc &&
            authorization.IssuedAtUtc >= local.CreatedAtUtc &&
            authorization.IssuedAtUtc <= nowUtc && nowUtc < authorization.ExpiresAtUtc &&
            authorization.ExpiresAtUtc - authorization.IssuedAtUtc <= TimeSpan.FromMinutes(15) &&
            !string.IsNullOrWhiteSpace(authorization.AttestationKeyId) &&
            !string.IsNullOrWhiteSpace(authorization.AttestationSignature) &&
            trust.TryGetPublicKeyFingerprintSha256(authorization.AttestationKeyId,
                out string signerFingerprint) &&
            Fixed(signerFingerprint, local.ExecutionAuthorizationKeyFingerprintSha256) &&
            VerifySignature(authorization, trust);
        if (!valid)
        {
            throw Invalid();
        }
    }

    private static void ValidateEvidence(
        PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult disposableResult,
        FreshSchemaPlan schema,
        IReceiptAttestationTrustStore trust,
        DeltaTargetAuthority observedLocalAuthority,
        string observedLocalTargetObservationSha256,
        string observedQuotationSchemaSha256,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(plans);
        ArgumentNullException.ThrowIfNull(disposableResult);
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(observedLocalAuthority);
        DeltaSynchronizationPlan local = plans.Persistent;
        if (local.SchemaVersion != "1.4" || local.PairedTransitionPlanOnly != true ||
            !DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(local.TargetAuthority) ||
            local.TargetAuthority != observedLocalAuthority ||
            !Fixed(local.TargetObservationSha256, observedLocalTargetObservationSha256) ||
            !Fixed(local.QuotationTransitionSchemaSha256 ?? string.Empty,
                observedQuotationSchemaSha256) ||
            !trust.TryGetPublicKeyFingerprintSha256(plans.Disposable.AttestationKeyId,
                out string disposablePlanFingerprint) ||
            !trust.TryGetPublicKeyFingerprintSha256(disposableResult.AttestationKeyId,
                out string disposableEvidenceFingerprint) ||
            Fixed(local.ExecutionAuthorizationKeyFingerprintSha256, disposablePlanFingerprint) ||
            Fixed(local.ExecutionAuthorizationKeyFingerprintSha256, disposableEvidenceFingerprint) ||
            nowUtc.Offset != TimeSpan.Zero)
        {
            throw Invalid();
        }
        try
        {
            ZeroDeleteCapturedDeltaProofValidator.Verify(plans.Disposable, disposableResult,
                local, schema, trust, nowUtc);
        }
        catch (Exception exception) when (exception is DeltaExecutionException or DeltaPlanException)
        {
            throw Invalid();
        }
    }

    private static bool VerifySignature(PairedLocalTransitionAuthorization authorization,
        IReceiptAttestationTrustStore trust)
    {
        try
        {
            return trust.Verify(authorization.AttestationKeyId,
                PairedLocalTransitionAuthorizationCanonicalizer.CreatePayload(authorization),
                Convert.FromBase64String(authorization.AttestationSignature!));
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
            CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(left.ToLowerInvariant()),
                Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    private static DeltaExecutionException Invalid()
    {
        return new DeltaExecutionException("delta_paired_local_transition_authorization_invalid",
            "A fresh, signed, target-bound zero-delete paired transition proof is required.");
    }
}
