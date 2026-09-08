using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

public sealed record DeltaExecutionAuthorization(
    string SchemaVersion,
    Guid AuthorizationId,
    Guid PlanId,
    string PlanSha256,
    string TargetNamespace,
    string TargetCluster,
    string TargetGeneration,
    string TargetObservationSha256,
    IReadOnlyList<string> Databases,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string AttestationKeyId,
    string? AttestationSignature)
{
    public DeltaTargetAuthority? TargetAuthority { get; init; }
}

public static class DeltaExecutionAuthorizationCanonicalizer
{
    private static ReadOnlySpan<byte> Domain => "legacy-maliev-exact23-delta-execution-authorization-v1.1\0"u8;

    public static byte[] CreatePayload(DeltaExecutionAuthorization authorization)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(authorization with { AttestationSignature = null });
        byte[] payload = new byte[Domain.Length + json.Length];
        Domain.CopyTo(payload);
        json.CopyTo(payload.AsSpan(Domain.Length));
        return payload;
    }
}

public static class DeltaExecutionAuthorizationProducer
{
    public static DeltaExecutionAuthorization Produce(
        DeltaSynchronizationPlan plan,
        DateTimeOffset issuedAtUtc,
        DateTimeOffset expiresAtUtc,
        P256MigrationEvidenceSigner signer)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(signer);
        if (plan.SchemaVersion != "1.1" ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(
                plan.TargetAuthority, plan.TargetNamespace, plan.TargetCluster) ||
            issuedAtUtc.Offset != TimeSpan.Zero || expiresAtUtc.Offset != TimeSpan.Zero ||
            expiresAtUtc <= issuedAtUtc || expiresAtUtc - issuedAtUtc > TimeSpan.FromMinutes(15) ||
            !DeltaSynchronizationPlanProducer.FixedHashEquals(
                signer.PublicKeyFingerprintSha256, plan.ExecutionAuthorizationKeyFingerprintSha256))
        {
            throw new DeltaExecutionException("delta_execution_authorization_request_invalid",
                "Execution authorization requires the reviewed role and a UTC lifetime no longer than fifteen minutes.");
        }
        var unsigned = new DeltaExecutionAuthorization(
            "1.1", Guid.NewGuid(), plan.PlanId, DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan),
            plan.TargetNamespace, plan.TargetCluster, plan.TargetGeneration, plan.TargetObservationSha256,
            [.. plan.Databases.Select(item => item.Database)], issuedAtUtc, expiresAtUtc, signer.KeyId, null)
        {
            TargetAuthority = plan.TargetAuthority,
        };
        return unsigned with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(
                DeltaExecutionAuthorizationCanonicalizer.CreatePayload(unsigned))),
        };
    }
}

public sealed class SignedDeltaExecutionAuthorizationGate(
    DeltaExecutionAuthorization authorization,
    IReceiptAttestationTrustStore trust,
    TimeProvider timeProvider,
    DeltaTargetAuthority expectedAuthority) : IDeltaExecutionAuthorizationGate
{
    public Task ValidateAsync(DeltaSynchronizationPlan plan, string database, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        DateTimeOffset nowUtc = timeProvider.GetUtcNow();
        bool valid = authorization.SchemaVersion == "1.1" && plan.SchemaVersion == "1.1" &&
            authorization.AuthorizationId != Guid.Empty && authorization.PlanId == plan.PlanId &&
            Fixed(authorization.PlanSha256, DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan)) &&
            authorization.TargetAuthority == plan.TargetAuthority &&
            authorization.TargetAuthority == expectedAuthority &&
            DeltaSynchronizationPlanProducer.ValidAuthority(
                authorization.TargetAuthority, authorization.TargetNamespace, authorization.TargetCluster) &&
            string.Equals(authorization.TargetNamespace, plan.TargetNamespace, StringComparison.Ordinal) &&
            string.Equals(authorization.TargetCluster, plan.TargetCluster, StringComparison.Ordinal) &&
            string.Equals(authorization.TargetGeneration, plan.TargetGeneration, StringComparison.Ordinal) &&
            Fixed(authorization.TargetObservationSha256, plan.TargetObservationSha256) &&
            authorization.Databases.SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) &&
            authorization.Databases.Contains(database, StringComparer.Ordinal) &&
            authorization.IssuedAtUtc.Offset == TimeSpan.Zero && authorization.ExpiresAtUtc.Offset == TimeSpan.Zero &&
            authorization.IssuedAtUtc <= nowUtc && nowUtc < authorization.ExpiresAtUtc &&
            authorization.ExpiresAtUtc - authorization.IssuedAtUtc <= TimeSpan.FromMinutes(15) &&
            !string.IsNullOrWhiteSpace(authorization.AttestationKeyId) &&
            !string.IsNullOrWhiteSpace(authorization.AttestationSignature) &&
            trust.TryGetPublicKeyFingerprintSha256(authorization.AttestationKeyId, out string fingerprint) &&
            Fixed(fingerprint, plan.ExecutionAuthorizationKeyFingerprintSha256) &&
            VerifySignature();
        return valid
            ? Task.CompletedTask
            : Task.FromException(new DeltaExecutionException("delta_execution_authorization_invalid",
                "The short-lived signed execution authorization is absent, stale, untrusted, or mismatched."));
    }

    private bool VerifySignature()
    {
        try
        {
            return trust.Verify(authorization.AttestationKeyId,
                DeltaExecutionAuthorizationCanonicalizer.CreatePayload(authorization),
                Convert.FromBase64String(authorization.AttestationSignature!));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool Fixed(string left, string right)
    {
        return left.Length == 64 && right.Length == 64 && left.All(char.IsAsciiHexDigit) && right.All(char.IsAsciiHexDigit) &&
            CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(left.ToLowerInvariant()),
                Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }
}
