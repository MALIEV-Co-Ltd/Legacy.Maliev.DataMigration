using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

/// <summary>Describes the exact empty canonical database resource that may receive one reviewed schema.</summary>
public sealed record CanonicalDatabaseBootstrapRequest(
    DatabaseSchemaPlan Schema,
    string DatabaseResourceName,
    string DatabaseResourceUid,
    string DatabaseResourceGeneration,
    DeltaTargetAuthority TargetAuthority);

/// <summary>Authorizes one create-only schema initialization against an already provisioned canonical database.</summary>
public sealed record CanonicalDatabaseBootstrapAuthorization(
    string SchemaVersion,
    Guid AuthorizationId,
    string Database,
    string TargetSchemaSha256,
    string DatabaseResourceName,
    string DatabaseResourceUid,
    string DatabaseResourceGeneration,
    DeltaTargetAuthority TargetAuthority,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string AttestationKeyId,
    string? AttestationSignature);

/// <summary>Reports a fail-closed canonical database bootstrap validation failure.</summary>
public sealed class CanonicalDatabaseBootstrapException(string code, string message) : Exception(message)
{
    /// <summary>Gets the stable non-sensitive failure code.</summary>
    public string Code { get; } = code;
}

/// <summary>Creates deterministic bytes for a canonical database bootstrap authorization signature.</summary>
public static class CanonicalDatabaseBootstrapAuthorizationCanonicalizer
{
    private static ReadOnlySpan<byte> Domain => "legacy-maliev-canonical-database-bootstrap-authorization-v1.0\0"u8;

    /// <summary>Returns the domain-separated unsigned authorization payload.</summary>
    public static byte[] CreatePayload(CanonicalDatabaseBootstrapAuthorization authorization)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(authorization with { AttestationSignature = null });
        byte[] payload = new byte[Domain.Length + json.Length];
        Domain.CopyTo(payload);
        json.CopyTo(payload.AsSpan(Domain.Length));
        return payload;
    }
}

/// <summary>Produces a short-lived authorization for one exact canonical database resource.</summary>
public static partial class CanonicalDatabaseBootstrapAuthorizationProducer
{
    /// <summary>Signs a bootstrap authorization that is valid for no more than fifteen minutes.</summary>
    public static CanonicalDatabaseBootstrapAuthorization Produce(
        DatabaseSchemaPlan schema,
        string databaseResourceName,
        string databaseResourceUid,
        string databaseResourceGeneration,
        DeltaTargetAuthority targetAuthority,
        DateTimeOffset issuedAtUtc,
        DateTimeOffset expiresAtUtc,
        P256MigrationEvidenceSigner signer)
    {
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentNullException.ThrowIfNull(targetAuthority);
        ArgumentNullException.ThrowIfNull(signer);
        string expectedSchema = PostgreSqlSchemaFingerprint.ComputeExpected(schema);
        if (!DatabaseInventory.ActiveDatabases.Contains(schema.Database, StringComparer.Ordinal) ||
            !Fixed(schema.TargetSchemaSha256, expectedSchema) ||
            !KubernetesName().IsMatch(databaseResourceName) ||
            !SafeIdentity().IsMatch(databaseResourceUid) ||
            !PositiveGeneration().IsMatch(databaseResourceGeneration) ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(
                targetAuthority, "maliev-legacy", "legacy-postgres-main") ||
            issuedAtUtc.Offset != TimeSpan.Zero || expiresAtUtc.Offset != TimeSpan.Zero ||
            expiresAtUtc <= issuedAtUtc || expiresAtUtc - issuedAtUtc > TimeSpan.FromMinutes(15))
        {
            throw InvalidRequest();
        }

        var unsigned = new CanonicalDatabaseBootstrapAuthorization(
            "1.0",
            Guid.NewGuid(),
            schema.Database,
            expectedSchema,
            databaseResourceName,
            databaseResourceUid,
            databaseResourceGeneration,
            targetAuthority,
            issuedAtUtc,
            expiresAtUtc,
            signer.KeyId,
            null);
        return unsigned with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(
                CanonicalDatabaseBootstrapAuthorizationCanonicalizer.CreatePayload(unsigned))),
        };
    }

    internal static bool Fixed(string left, string right)
    {
        return left.Length == 64 && right.Length == 64 &&
            left.All(char.IsAsciiHexDigit) && right.All(char.IsAsciiHexDigit) &&
            CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(left.ToLowerInvariant()),
                Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    private static CanonicalDatabaseBootstrapException InvalidRequest()
    {
        return new(
        "canonical_database_bootstrap_authorization_request_invalid",
        "Canonical database bootstrap authorization requires an exact active database, schema, resource, target, and short UTC lifetime.");
    }

    [GeneratedRegex("^[a-z0-9](?:[-a-z0-9.]{0,61}[a-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex KubernetesName();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeIdentity();

    [GeneratedRegex("^[1-9][0-9]*$", RegexOptions.CultureInvariant)]
    private static partial Regex PositiveGeneration();
}

/// <summary>Validates a signed bootstrap authorization against a freshly observed database resource.</summary>
public sealed class SignedCanonicalDatabaseBootstrapAuthorizationGate(
    CanonicalDatabaseBootstrapAuthorization authorization,
    IReceiptAttestationTrustStore trust,
    TimeProvider timeProvider)
{
    /// <summary>Fails closed unless every schema, resource, target, time, trust, and signature binding matches.</summary>
    public Task ValidateAsync(CanonicalDatabaseBootstrapRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        DateTimeOffset nowUtc = timeProvider.GetUtcNow();
        string expectedSchema = PostgreSqlSchemaFingerprint.ComputeExpected(request.Schema);
        bool valid = authorization.SchemaVersion == "1.0" && authorization.AuthorizationId != Guid.Empty &&
            string.Equals(authorization.Database, request.Schema.Database, StringComparison.Ordinal) &&
            DatabaseInventory.ActiveDatabases.Contains(authorization.Database, StringComparer.Ordinal) &&
            CanonicalDatabaseBootstrapAuthorizationProducer.Fixed(
                authorization.TargetSchemaSha256, expectedSchema) &&
            CanonicalDatabaseBootstrapAuthorizationProducer.Fixed(
                request.Schema.TargetSchemaSha256, expectedSchema) &&
            string.Equals(authorization.DatabaseResourceName, request.DatabaseResourceName, StringComparison.Ordinal) &&
            string.Equals(authorization.DatabaseResourceUid, request.DatabaseResourceUid, StringComparison.Ordinal) &&
            string.Equals(authorization.DatabaseResourceGeneration, request.DatabaseResourceGeneration, StringComparison.Ordinal) &&
            authorization.TargetAuthority == request.TargetAuthority &&
            DeltaSynchronizationPlanProducer.ValidAuthority(
                authorization.TargetAuthority, "maliev-legacy", "legacy-postgres-main") &&
            authorization.IssuedAtUtc.Offset == TimeSpan.Zero && authorization.ExpiresAtUtc.Offset == TimeSpan.Zero &&
            authorization.IssuedAtUtc <= nowUtc && nowUtc < authorization.ExpiresAtUtc &&
            authorization.ExpiresAtUtc - authorization.IssuedAtUtc <= TimeSpan.FromMinutes(15) &&
            !string.IsNullOrWhiteSpace(authorization.AttestationKeyId) &&
            !string.IsNullOrWhiteSpace(authorization.AttestationSignature) &&
            trust.TryGetPublicKeyFingerprintSha256(authorization.AttestationKeyId, out _) &&
            VerifySignature();
        return valid
            ? Task.CompletedTask
            : Task.FromException(InvalidAuthorization());
    }

    private bool VerifySignature()
    {
        try
        {
            return trust.Verify(
                authorization.AttestationKeyId,
                CanonicalDatabaseBootstrapAuthorizationCanonicalizer.CreatePayload(authorization),
                Convert.FromBase64String(authorization.AttestationSignature!));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static CanonicalDatabaseBootstrapException InvalidAuthorization()
    {
        return new(
        "canonical_database_bootstrap_authorization_invalid",
        "The canonical database bootstrap authorization is absent, stale, untrusted, or mismatched.");
    }
}
