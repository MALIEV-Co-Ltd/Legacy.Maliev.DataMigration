using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration;

public sealed record VerifiedBackupStateArtifact(
    string Database,
    string LocalPath,
    string GcsObject,
    long GcsGeneration,
    long GcsByteLength,
    string GcsSha256);

public static class BackupReceiptProducer
{
    public static async Task<BackupReceipt> ProduceAsync(
        IReadOnlyCollection<VerifiedBackupStateArtifact> backupState,
        string keyId,
        ECDsa signingKey,
        DateTimeOffset capturedAtUtc,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(backupState);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentNullException.ThrowIfNull(signingKey);
        EnsureP256(signingKey);

        string[] observed = [.. backupState.Select(item => item.Database)];
        if (observed.Length != DatabaseInventory.ActiveDatabases.Count ||
            observed.Distinct(StringComparer.Ordinal).Count() != observed.Length ||
            !observed.OrderBy(item => item, StringComparer.Ordinal)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            throw new BackupReceiptProductionException(
                "backup_state_database_coverage_invalid",
                "Backup state must cover exactly the approved database inventory.");
        }

        var artifacts = new List<BackupArtifact>(backupState.Count);
        foreach (VerifiedBackupStateArtifact state in backupState.OrderBy(item => item.Database, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (state.GcsGeneration <= 0 || state.GcsByteLength < 0 || !IsSha256(state.GcsSha256))
            {
                throw new BackupReceiptProductionException("backup_state_cloud_metadata_invalid", "Approved cloud metadata is incomplete.");
            }

            var file = new FileInfo(state.LocalPath);
            if (!file.Exists || file.Length != state.GcsByteLength)
            {
                throw new BackupReceiptProductionException("backup_state_local_size_mismatch", "A local backup does not match approved cloud metadata.");
            }

            string localSha256 = await ComputeSha256Async(state.LocalPath, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(localSha256),
                Encoding.ASCII.GetBytes(state.GcsSha256.ToLowerInvariant())))
            {
                throw new BackupReceiptProductionException("backup_state_local_hash_mismatch", "A local backup does not match approved cloud metadata.");
            }

            artifacts.Add(new BackupArtifact(
                state.Database,
                "Full",
                file.Name,
                file.Length,
                localSha256,
                localSha256)
            {
                GcsObject = state.GcsObject,
                GcsGeneration = state.GcsGeneration,
                GcsSha256 = state.GcsSha256.ToLowerInvariant(),
            });
        }

        string manifest = ComputeManifestSha256(artifacts);
        var unsigned = new BackupReceipt(
            "1.0",
            capturedAtUtc.ToUniversalTime(),
            DatabaseInventory.InventorySha256,
            manifest,
            artifacts,
            keyId,
            null);
        if (!ReceiptAttestation.TryCreatePayload(unsigned, out byte[] payload))
        {
            throw new BackupReceiptProductionException("backup_receipt_canonicalization_failed", "The receipt could not be canonicalized.");
        }

        string signature = Convert.ToBase64String(signingKey.SignData(payload, HashAlgorithmName.SHA256));
        return unsigned with { AttestationSignature = signature };
    }

    internal static string ComputeManifestSha256(IEnumerable<BackupArtifact> artifacts)
    {
        string canonical = string.Join('\n', artifacts
            .OrderBy(artifact => artifact.Database, StringComparer.Ordinal)
            .Select(artifact => string.Join('|', artifact.Database, artifact.BackupType, artifact.FileName,
                artifact.ByteLength, artifact.Sha256!.ToLowerInvariant(), artifact.ObservedSha256!.ToLowerInvariant())));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        byte[] hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static bool IsSha256(string value)
    {
        return value.Length == 64 && value.All(char.IsAsciiHexDigit);
    }

    private static void EnsureP256(ECDsa key)
    {
        ECParameters parameters = key.ExportParameters(false);
        if (key.KeySize != 256 || !string.Equals(parameters.Curve.Oid.Value, "1.2.840.10045.3.1.7", StringComparison.Ordinal))
        {
            throw new BackupReceiptProductionException("backup_receipt_signing_key_curve_invalid", "The signing key must be ECDSA P-256.");
        }
    }
}

public sealed class BackupReceiptProductionException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
