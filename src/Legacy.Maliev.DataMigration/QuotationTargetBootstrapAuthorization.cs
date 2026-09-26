using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Short-lived, local-target-specific authorization for the two reviewed Quotation tables.</summary>
public sealed record QuotationTargetBootstrapAuthorization(
    string SchemaVersion, Guid AuthorizationId, string SourceCommitSha, string SourceSchemaSha256,
    string TargetSchemaSha256, string TransitionSchemaSha256,
    DeltaTargetAuthority TargetAuthority, string ReviewedMissingTables, DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc, string AttestationKeyId, string? AttestationSignature);

/// <summary>Signs a Quotation-only DDL permission independent from row-delta permissions.</summary>
public static class QuotationTargetBootstrapAuthorizationProducer
{
    /// <summary>The only authorized additive set.</summary>
    public const string ReviewedMissingSet =
        "legacy_compatibility.GoogleAnalyticsOutbox;public.QuotationAcceptedOutcome";

    /// <summary>Creates a fifteen-minute-or-shorter exact-plan, exact-target authorization.</summary>
    public static QuotationTargetBootstrapAuthorization Produce(DatabaseSchemaPlan schema, string sourceCommitSha,
        DeltaTargetAuthority authority, DateTimeOffset issuedAtUtc, DateTimeOffset expiresAtUtc,
        P256MigrationEvidenceSigner signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        Validate(schema, sourceCommitSha, authority);
        if (issuedAtUtc.Offset != TimeSpan.Zero || expiresAtUtc.Offset != TimeSpan.Zero ||
            expiresAtUtc <= issuedAtUtc || expiresAtUtc - issuedAtUtc > TimeSpan.FromMinutes(15))
        {
            throw Invalid();
        }
        var unsigned = new QuotationTargetBootstrapAuthorization("1.0", Guid.NewGuid(), sourceCommitSha,
            schema.SourceSchemaSha256, schema.TargetSchemaSha256,
            PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(schema, true),
            authority, ReviewedMissingSet, issuedAtUtc, expiresAtUtc,
            signer.KeyId, null);
        return unsigned with { AttestationSignature = Convert.ToBase64String(signer.Sign(Payload(unsigned))) };
    }

    /// <summary>Rejects an unreviewed plan, source commit, or non-local target identity.</summary>
    public static void Validate(DatabaseSchemaPlan schema, string sourceCommitSha, DeltaTargetAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentNullException.ThrowIfNull(authority);
        if (sourceCommitSha.Length != 40 || !sourceCommitSha.All(char.IsAsciiHexDigit) ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(authority, "local-aspire", "legacy-postgres-main-local"))
        {
            throw Invalid();
        }
        _ = PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(schema, true);
    }

    internal static byte[] Payload(QuotationTargetBootstrapAuthorization authorization)
    {
        byte[] domain = "legacy-maliev-quotation-target-bootstrap-authorization-v1.0\0"u8.ToArray();
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(authorization with { AttestationSignature = null });
        byte[] payload = new byte[domain.Length + json.Length];
        domain.CopyTo(payload, 0);
        json.CopyTo(payload, domain.Length);
        return payload;
    }

    private static MigrationExecutionException Invalid()
    {
        return new("quotation_target_bootstrap_authorization_request_invalid",
        "The Quotation target bootstrap authorization request is invalid.");
    }
}

/// <summary>Verifies the exact local authority, schema, source commit, freshness, and signature.</summary>
public static class QuotationTargetBootstrapAuthorizationVerifier
{
    /// <summary>Returns false on any missing, stale, changed, or untrusted binding.</summary>
    public static bool Verify(QuotationTargetBootstrapAuthorization authorization, DatabaseSchemaPlan schema,
        string sourceCommitSha, DeltaTargetAuthority authority, IReceiptAttestationTrustStore trust,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(trust);
        try
        {
            QuotationTargetBootstrapAuthorizationProducer.Validate(schema, sourceCommitSha, authority);
            return authorization.SchemaVersion == "1.0" && authorization.AuthorizationId != Guid.Empty &&
                authorization.SourceCommitSha == sourceCommitSha &&
                authorization.SourceSchemaSha256 == schema.SourceSchemaSha256 &&
                authorization.TargetSchemaSha256 == schema.TargetSchemaSha256 &&
                authorization.TransitionSchemaSha256 ==
                    PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(schema, true) &&
                authorization.TargetAuthority == authority &&
                authorization.ReviewedMissingTables == QuotationTargetBootstrapAuthorizationProducer.ReviewedMissingSet &&
                authorization.IssuedAtUtc.Offset == TimeSpan.Zero &&
                authorization.ExpiresAtUtc.Offset == TimeSpan.Zero && authorization.IssuedAtUtc <= nowUtc &&
                nowUtc < authorization.ExpiresAtUtc &&
                authorization.ExpiresAtUtc - authorization.IssuedAtUtc <= TimeSpan.FromMinutes(15) &&
                !string.IsNullOrWhiteSpace(authorization.AttestationSignature) &&
                trust.TryGetPublicKeyFingerprintSha256(authorization.AttestationKeyId, out _) && trust.Verify(authorization.AttestationKeyId,
                QuotationTargetBootstrapAuthorizationProducer.Payload(authorization),
                Convert.FromBase64String(authorization.AttestationSignature));
        }
        catch (Exception failure) when (failure is MigrationExecutionException or FormatException or ArgumentException)
        {
            return false;
        }
    }
}
