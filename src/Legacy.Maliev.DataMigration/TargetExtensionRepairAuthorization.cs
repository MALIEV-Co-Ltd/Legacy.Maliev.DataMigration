using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Short-lived, target-specific permission for one reviewed create-only extension set.</summary>
public sealed record TargetExtensionRepairAuthorization(
    string SchemaVersion,
    Guid AuthorizationId,
    string Database,
    string SourceCommitSha,
    string TargetSchemaSha256,
    DeltaTargetAuthority TargetAuthority,
    string ReviewedMissingTables,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string AttestationKeyId,
    string? AttestationSignature);

/// <summary>Signs a distinct DDL authorization, never a row-delta or bootstrap authorization.</summary>
public static class TargetExtensionRepairAuthorizationProducer
{
    /// <summary>Creates a fifteen-minute-or-shorter authorization for the exact approved set.</summary>
    public static TargetExtensionRepairAuthorization Produce(
        DatabaseSchemaPlan schema, string sourceCommitSha, DeltaTargetAuthority authority,
        string reviewedMissingTables, DateTimeOffset issuedAtUtc, DateTimeOffset expiresAtUtc,
        P256MigrationEvidenceSigner signer)
    {
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(signer);
        string expectedSet = ExpectedMissingSet(schema);
        if (sourceCommitSha.Length != 40 || !sourceCommitSha.All(char.IsAsciiHexDigit) ||
            !string.Equals(reviewedMissingTables, expectedSet, StringComparison.Ordinal) ||
            !string.Equals(schema.TargetSchemaSha256, PostgreSqlSchemaFingerprint.ComputeExpected(schema),
                StringComparison.Ordinal) ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(authority, "local-aspire", "legacy-postgres-main-local") ||
            issuedAtUtc.Offset != TimeSpan.Zero || expiresAtUtc.Offset != TimeSpan.Zero ||
            expiresAtUtc <= issuedAtUtc || expiresAtUtc - issuedAtUtc > TimeSpan.FromMinutes(15))
        {
            throw Invalid();
        }
        var unsigned = new TargetExtensionRepairAuthorization("1.0", Guid.NewGuid(), schema.Database,
            sourceCommitSha, schema.TargetSchemaSha256, authority, reviewedMissingTables,
            issuedAtUtc, expiresAtUtc, signer.KeyId, null);
        return unsigned with { AttestationSignature = Convert.ToBase64String(signer.Sign(Payload(unsigned))) };
    }

    /// <summary>Returns the canonical ordinal-sorted approved extension set for one database.</summary>
    public static string ExpectedMissingSet(DatabaseSchemaPlan schema)
    {
        return string.Join(';',
        ApprovedTargetExtensionManifest.TablesFor(schema)
            .Select(table => $"{table.TargetSchema}.{table.TargetTable}")
            .Order(StringComparer.Ordinal));
    }

    internal static byte[] Payload(TargetExtensionRepairAuthorization authorization)
    {
        byte[] domain = "legacy-maliev-target-extension-repair-authorization-v1.0\0"u8.ToArray();
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(authorization with { AttestationSignature = null });
        byte[] payload = new byte[domain.Length + json.Length];
        domain.CopyTo(payload, 0);
        json.CopyTo(payload, domain.Length);
        return payload;
    }

    private static MigrationExecutionException Invalid()
    {
        return new(
        "target_extension_repair_authorization_request_invalid", "The DDL authorization request is invalid.");
    }
}

/// <summary>Verifies freshness and every source, schema, target, and missing-set binding.</summary>
public static class TargetExtensionRepairAuthorizationVerifier
{
    /// <summary>Returns false for any stale, changed, or untrusted DDL authorization.</summary>
    public static bool Verify(
        TargetExtensionRepairAuthorization authorization, DatabaseSchemaPlan schema,
        string sourceCommitSha, DeltaTargetAuthority authority, string reviewedMissingTables,
        IReceiptAttestationTrustStore trust, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(trust);
        if (authorization.SchemaVersion != "1.0" || authorization.AuthorizationId == Guid.Empty ||
            authorization.Database != schema.Database || authorization.SourceCommitSha != sourceCommitSha ||
            authorization.TargetSchemaSha256 != schema.TargetSchemaSha256 ||
            authorization.TargetSchemaSha256 != PostgreSqlSchemaFingerprint.ComputeExpected(schema) ||
            authorization.TargetAuthority != authority ||
            authorization.ReviewedMissingTables != reviewedMissingTables ||
            reviewedMissingTables != TargetExtensionRepairAuthorizationProducer.ExpectedMissingSet(schema) ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(authority, "local-aspire", "legacy-postgres-main-local") ||
            authorization.IssuedAtUtc.Offset != TimeSpan.Zero || authorization.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            authorization.IssuedAtUtc > nowUtc || nowUtc >= authorization.ExpiresAtUtc ||
            authorization.ExpiresAtUtc - authorization.IssuedAtUtc > TimeSpan.FromMinutes(15) ||
            string.IsNullOrWhiteSpace(authorization.AttestationSignature) ||
            !trust.TryGetPublicKeyFingerprintSha256(authorization.AttestationKeyId, out _))
        {
            return false;
        }
        try
        {
            byte[] signature = Convert.FromBase64String(authorization.AttestationSignature);
            return trust.Verify(authorization.AttestationKeyId,
                TargetExtensionRepairAuthorizationProducer.Payload(authorization), signature);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
