using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Signed, PII-free evidence of the reviewed additive transition on a disposable target.</summary>
public sealed record QuotationTargetBootstrapProof(
    string SchemaVersion, Guid ProofId, string SourceCommitSha, string SourceSchemaSha256,
    string TargetSchemaSha256, string TransitionSchemaSha256, DeltaTargetAuthority TargetAuthority,
    string ReviewedMissingTables, string AuthorizationEnvelopeSha256, string Disposition,
    DateTimeOffset CompletedAtUtc, string AttestationKeyId, string? AttestationSignature);

/// <summary>Signs only a completed disposable bootstrap, never a persistent or production DDL result.</summary>
public static class QuotationTargetBootstrapProofProducer
{
    /// <summary>Creates a signed transition receipt after the disposable post-commit check.</summary>
    public static QuotationTargetBootstrapProof Produce(DatabaseSchemaPlan schema, string sourceCommitSha,
        DeltaTargetAuthority authority, string authorizationEnvelopeSha256, string disposition,
        DateTimeOffset completedAtUtc, P256MigrationEvidenceSigner signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        QuotationTargetBootstrapAuthorizationProducer.Validate(schema, sourceCommitSha, authority);
        if (!authority.AuthorityId.StartsWith("aspire://legacy-postgres-main-local/disposable-", StringComparison.Ordinal) ||
            disposition is not ("created" or "already-current") || completedAtUtc.Offset != TimeSpan.Zero ||
            authorizationEnvelopeSha256.Length != 64 || !authorizationEnvelopeSha256.All(char.IsAsciiHexDigit))
        {
            throw Invalid();
        }
        var unsigned = new QuotationTargetBootstrapProof("1.0", Guid.NewGuid(), sourceCommitSha,
            schema.SourceSchemaSha256, schema.TargetSchemaSha256,
            PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(schema, true), authority,
            QuotationTargetBootstrapAuthorizationProducer.ReviewedMissingSet,
            authorizationEnvelopeSha256.ToLowerInvariant(), disposition, completedAtUtc, signer.KeyId, null);
        return unsigned with { AttestationSignature = Convert.ToBase64String(signer.Sign(Payload(unsigned))) };
    }

    /// <summary>Hashes the complete signed envelope for a distinct persistent authorization.</summary>
    public static string ComputeSha256(QuotationTargetBootstrapProof proof)
    {
        ArgumentNullException.ThrowIfNull(proof);
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(proof)))
            .ToLowerInvariant();
    }

    internal static byte[] Payload(QuotationTargetBootstrapProof proof)
    {
        byte[] domain = "legacy-maliev-quotation-bootstrap-disposable-proof-v1.0\0"u8.ToArray();
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(proof with { AttestationSignature = null });
        byte[] payload = new byte[domain.Length + json.Length];
        domain.CopyTo(payload, 0);
        json.CopyTo(payload, domain.Length);
        return payload;
    }

    private static MigrationExecutionException Invalid() => new("quotation_target_bootstrap_proof_request_invalid",
        "A completed, reviewed disposable Quotation bootstrap is required.");
}

/// <summary>Admits a fresh disposable proof only for a different persistent local PostgreSQL identity.</summary>
public static class QuotationTargetBootstrapProofVerifier
{
    /// <summary>Rejects tampering, stale results, changed schemas, and same-target promotion.</summary>
    public static bool Verify(QuotationTargetBootstrapProof proof, DatabaseSchemaPlan schema,
        string sourceCommitSha, DeltaTargetAuthority persistentAuthority,
        IReceiptAttestationTrustStore trust, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(trust);
        try
        {
            QuotationTargetBootstrapAuthorizationProducer.Validate(schema, sourceCommitSha, persistentAuthority);
            return persistentAuthority.AuthorityId.StartsWith(
                    "aspire://legacy-postgres-main-local/persistent-", StringComparison.Ordinal) &&
                proof.SchemaVersion == "1.0" && proof.ProofId != Guid.Empty &&
                proof.SourceCommitSha == sourceCommitSha &&
                proof.SourceSchemaSha256 == schema.SourceSchemaSha256 &&
                proof.TargetSchemaSha256 == schema.TargetSchemaSha256 &&
                proof.TransitionSchemaSha256 == PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(schema, true) &&
                DeltaSynchronizationPlanProducer.ValidAuthority(proof.TargetAuthority,
                    "local-aspire", "legacy-postgres-main-local") &&
                proof.TargetAuthority.AuthorityId.StartsWith(
                    "aspire://legacy-postgres-main-local/disposable-", StringComparison.Ordinal) &&
                proof.TargetAuthority.SystemIdentifierSha256 != persistentAuthority.SystemIdentifierSha256 &&
                proof.TargetAuthority.AuthorityId != persistentAuthority.AuthorityId &&
                proof.ReviewedMissingTables == QuotationTargetBootstrapAuthorizationProducer.ReviewedMissingSet &&
                proof.AuthorizationEnvelopeSha256.Length == 64 &&
                proof.AuthorizationEnvelopeSha256.All(char.IsAsciiHexDigit) &&
                (proof.Disposition is "created" or "already-current") &&
                proof.CompletedAtUtc.Offset == TimeSpan.Zero &&
                proof.CompletedAtUtc <= nowUtc && nowUtc - proof.CompletedAtUtc <= TimeSpan.FromHours(12) &&
                !string.IsNullOrWhiteSpace(proof.AttestationSignature) &&
                trust.TryGetPublicKeyFingerprintSha256(proof.AttestationKeyId, out _) &&
                trust.Verify(proof.AttestationKeyId, QuotationTargetBootstrapProofProducer.Payload(proof),
                    Convert.FromBase64String(proof.AttestationSignature));
        }
        catch (Exception failure) when (failure is MigrationExecutionException or FormatException or ArgumentException or NullReferenceException)
        {
            return false;
        }
    }
}
