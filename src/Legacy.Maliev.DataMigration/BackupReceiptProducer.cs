using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration;

public static partial class Exact25FullBackupProducer
{
    private sealed record VerifiedBackupStateArtifact(
        string Database,
        string LocalPath,
        string GcsObject,
        long GcsGeneration,
        long GcsByteLength,
        string GcsSha256)
    {
        public DateTimeOffset? CompletedAtUtc { get; init; }
    }

    private static async Task<BackupReceipt> ProduceReceiptAsync(
        IReadOnlyCollection<VerifiedBackupStateArtifact> backupState,
        string keyId,
        ECDsa signingKey,
        DateTimeOffset sourceObservedAtUtc,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(backupState);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentNullException.ThrowIfNull(signingKey);
        EnsureP256(signingKey);
        if (sourceObservedAtUtc == default || sourceObservedAtUtc.Offset != TimeSpan.Zero)
        {
            throw ReceiptError("backup_state_capture_time_invalid", "The authoritative source observation time is invalid.");
        }

        string[] observed = [.. backupState.Select(item => item.Database)];
        if (observed.Length != DatabaseInventory.ActiveDatabases.Count ||
            observed.Distinct(StringComparer.Ordinal).Count() != observed.Length ||
            !observed.OrderBy(item => item, StringComparer.Ordinal)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            throw ReceiptError(
                "backup_state_database_coverage_invalid",
                "Backup state must cover exactly the approved database inventory.");
        }

        var artifacts = new List<BackupArtifact>(backupState.Count);
        foreach (VerifiedBackupStateArtifact state in backupState.OrderBy(item => item.Database, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (state.GcsGeneration <= 0 || state.GcsByteLength < 0 || !IsSha256(state.GcsSha256))
            {
                throw ReceiptError("backup_state_cloud_metadata_invalid", "Approved cloud metadata is incomplete.");
            }
            if (state.CompletedAtUtc is null || state.CompletedAtUtc.Value.Offset != TimeSpan.Zero ||
                state.CompletedAtUtc.Value < sourceObservedAtUtc)
            {
                throw ReceiptError("backup_state_capture_time_invalid", "The backup completion evidence is invalid.");
            }

            var file = new FileInfo(state.LocalPath);
            string localDirectory = file.DirectoryName
                ?? throw ReceiptError("backup_state_local_path_invalid", "A local backup path is invalid.");
            try
            {
                SecureLocalFile.EnsureOwnerOnlyDirectory(localDirectory);
                SecureLocalFile.EnsurePathWithin(localDirectory, state.LocalPath);
            }
            catch (Exact25FullBackupException exception)
            {
                throw ReceiptError("backup_state_local_path_invalid", exception.Message);
            }
            if (!SecureLocalFile.IsOwnerOnlyFile(file) || file.Length != state.GcsByteLength)
            {
                throw ReceiptError("backup_state_local_size_mismatch", "A local backup does not match approved cloud metadata.");
            }

            await using FileStream localRead = SecureLocalFile.OpenRead(state.LocalPath);
            string localSha256 = await SecureLocalFile.ComputeSha256Async(localRead, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(localSha256),
                Encoding.ASCII.GetBytes(state.GcsSha256.ToLowerInvariant())))
            {
                throw ReceiptError("backup_state_local_hash_mismatch", "A local backup does not match approved cloud metadata.");
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
                CompletedAtUtc = state.CompletedAtUtc,
            });
        }

        DateTimeOffset capturedAtUtc = backupState.Max(state => state.CompletedAtUtc!.Value);

        string manifest = ComputeManifestSha256(artifacts);
        var unsigned = new BackupReceipt(
            "1.1",
            capturedAtUtc.ToUniversalTime(),
            DatabaseInventory.InventorySha256,
            manifest,
            artifacts,
            keyId,
            null)
        {
            SourceObservedAtUtc = sourceObservedAtUtc,
        };
        if (!ReceiptAttestation.TryCreatePayload(unsigned, out byte[] payload))
        {
            throw ReceiptError("backup_receipt_canonicalization_failed", "The receipt could not be canonicalized.");
        }

        string signature = Convert.ToBase64String(signingKey.SignData(payload, HashAlgorithmName.SHA256));
        return unsigned with { AttestationSignature = signature };
    }

    private static string ComputeManifestSha256(IEnumerable<BackupArtifact> artifacts)
    {
        string canonical = string.Join('\n', artifacts
            .OrderBy(artifact => artifact.Database, StringComparer.Ordinal)
            .Select(artifact => string.Join('|', artifact.Database, artifact.BackupType, artifact.FileName,
                artifact.ByteLength, artifact.Sha256!.ToLowerInvariant(), artifact.ObservedSha256!.ToLowerInvariant())));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
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
            throw ReceiptError("backup_receipt_signing_key_curve_invalid", "The signing key must be ECDSA P-256.");
        }
    }

    private static Exact25FullBackupException ReceiptError(string code, string message)
    {
        return new(code, message);
    }
}
