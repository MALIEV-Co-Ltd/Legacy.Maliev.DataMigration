using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

public sealed record CleanupAuthorizationReceipt(
    string SchemaVersion,
    Guid RunId,
    string ExecutionReceiptSha256,
    string SnapshotManifestDigestSha256,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string Mode,
    CloudNativePgTargetObservation TargetObservation,
    string AttestationKeyId,
    string? AttestationSignature)
{
    public bool OwnerApproved { get; init; }
}

public sealed record ReviewedCleanupAuthorizationRequest(
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    CloudNativePgTargetObservation TargetObservation,
    bool AllowCleanupAuthorization);

public static class CleanupAuthorizationAttestation
{
    private static readonly byte[] Domain = Encoding.UTF8.GetBytes("Legacy.Maliev.DataMigration.CleanupAuthorization.v1\0");

    public static byte[] CreatePayload(CleanupAuthorizationReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(receipt with { AttestationSignature = null });
        byte[] payload = new byte[Domain.Length + json.Length];
        Domain.CopyTo(payload, 0);
        json.CopyTo(payload, Domain.Length);
        return payload;
    }
}

public static class CleanupContract
{
    public static string ExecutionDigest(MigrationExecutionReceipt execution)
    {
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(execution))).ToLowerInvariant();
    }

    public static void ValidateSnapshot(
        LocalSnapshotManifest snapshot,
        MigrationExecutionReceipt execution,
        ReadOnlySpan<byte> rootKey)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        string expectedId = execution.RunId.ToString("D");
        string semantic = SnapshotManifestAuthentication.ComputeSemanticDigest(snapshot.SnapshotId, snapshot.Databases);
        string mac = SnapshotManifestAuthentication.ComputeMac(snapshot with { ManifestMacSha256 = string.Empty }, rootKey);
        if (snapshot.SchemaVersion != 2 || snapshot.Format != "MLVSNP02" ||
            snapshot.Encryption != "AES-256-GCM-chunked-v2" || snapshot.SnapshotId != expectedId ||
            !FixedHash(snapshot.ManifestDigestSha256, semantic) || !FixedHash(snapshot.ManifestMacSha256, mac) ||
            snapshot.Databases.Count != DatabaseInventory.ActiveDatabases.Count ||
            !snapshot.Databases.Select(item => item.Database).Order(StringComparer.Ordinal)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            snapshot.Databases.Any(item => execution.Databases.All(migrated =>
                migrated.Database != item.Database || migrated.ShadowName != item.ShadowDatabase)))
        {
            throw new MigrationExecutionException("cleanup_snapshot_invalid", "Cleanup requires the authenticated exact-24 snapshot exported from this execution.");
        }
    }

    public static bool FixedHash(string left, string right)
    {
        return left.Length == 64 && right.Length == 64 && CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(left.ToLowerInvariant()), Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }
}

public static class ReviewedCleanupAuthorizationProducer
{
    public static CleanupAuthorizationReceipt Produce(
        ReviewedCleanupAuthorizationRequest request,
        MigrationExecutionResult execution,
        LocalSnapshotManifest snapshot,
        ReadOnlySpan<byte> snapshotRootKey,
        IReceiptAttestationTrustStore executionTrust,
        IMigrationEvidenceSigner authorizationSigner,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentNullException.ThrowIfNull(executionTrust);
        ArgumentNullException.ThrowIfNull(authorizationSigner);
        if (!request.AllowCleanupAuthorization)
        {
            throw new OperatorAttestationException("cleanup_authorization_owner_review_required", "Explicit owner review is required before cleanup authorization can be signed.");
        }
        if (request.IssuedAtUtc.Offset != TimeSpan.Zero || request.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            request.IssuedAtUtc > nowUtc || request.ExpiresAtUtc <= nowUtc || request.ExpiresAtUtc <= request.IssuedAtUtc ||
            request.ExpiresAtUtc - request.IssuedAtUtc > TimeSpan.FromHours(1))
        {
            throw new OperatorAttestationException("cleanup_authorization_time_window_invalid", "Cleanup authorization must be current UTC and no longer than one hour.");
        }
        MigrationExecutionReceipt receipt = execution.Receipt;
        if (execution.Status is not (MigrationExecutionStatus.Completed or MigrationExecutionStatus.AlreadyCompleted) ||
            receipt.Databases.Count != DatabaseInventory.ActiveDatabases.Count ||
            !Verify(receipt.AttestationKeyId, receipt.AttestationSignature,
                MigrationEvidenceAttestation.CreatePayload(receipt), executionTrust))
        {
            throw new OperatorAttestationException("cleanup_authorization_execution_invalid", "A trusted successful exact-24 execution is required.");
        }
        if (request.IssuedAtUtc < receipt.CompletedAtUtc)
        {
            throw new OperatorAttestationException("cleanup_authorization_time_window_invalid", "Cleanup authorization must be issued after the signed execution completed.");
        }
        if (!executionTrust.TryGetPublicKeyFingerprintSha256(receipt.AttestationKeyId, out string executionFingerprint) ||
            string.Equals(executionFingerprint, authorizationSigner.PublicKeyFingerprintSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new OperatorAttestationException("cleanup_authorization_key_role_reuse", "Cleanup authorization and execution require distinct signing keys.");
        }
        CleanupContract.ValidateSnapshot(snapshot, receipt, snapshotRootKey);
        if (!request.TargetObservation.IsHealthy || request.TargetObservation.Namespace != "maliev-legacy" ||
            request.TargetObservation.Cluster != "legacy-postgres-main")
        {
            throw new OperatorAttestationException("cleanup_authorization_target_invalid", "Cleanup authorization requires the healthy exact CloudNativePG target.");
        }
        var unsigned = new CleanupAuthorizationReceipt(
            "1.0", receipt.RunId, CleanupContract.ExecutionDigest(receipt), snapshot.ManifestDigestSha256,
            request.IssuedAtUtc, request.ExpiresAtUtc, "cleanup-run-owned-shadows", request.TargetObservation,
            authorizationSigner.KeyId, null)
        {
            OwnerApproved = true,
        };
        byte[] payload = CleanupAuthorizationAttestation.CreatePayload(unsigned);
        return unsigned with { AttestationSignature = Convert.ToBase64String(authorizationSigner.Sign(payload)) };
    }

    private static bool Verify(string? keyId, string? signature, byte[] payload, IReceiptAttestationTrustStore trust)
    {
        try
        {
            return !string.IsNullOrWhiteSpace(keyId) && !string.IsNullOrWhiteSpace(signature) &&
                trust.Verify(keyId, payload, Convert.FromBase64String(signature));
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

public interface ICleanupTargetVerifier
{
    Task VerifyAsync(CleanupAuthorizationReceipt authorization, CancellationToken cancellationToken);
}

public sealed class CleanupTargetVerifier(
    ICloudNativePgTargetObserver observer,
    string targetNamespace,
    string targetCluster) : ICleanupTargetVerifier
{
    public async Task VerifyAsync(CleanupAuthorizationReceipt authorization, CancellationToken cancellationToken)
    {
        CloudNativePgTargetObservation observed = await observer.ObserveAsync(
            targetNamespace, targetCluster, cancellationToken).ConfigureAwait(false);
        if (observed != authorization.TargetObservation)
        {
            throw new RuntimeAttestationException("cleanup_target_drift", "The exact CloudNativePG target drifted after cleanup authorization.");
        }
    }
}
