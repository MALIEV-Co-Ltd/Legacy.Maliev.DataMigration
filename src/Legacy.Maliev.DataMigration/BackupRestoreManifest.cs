using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration;

public sealed record BackupRestoreManifest(
    string SchemaVersion,
    string ReceiptManifestSha256,
    DateTimeOffset SourceObservedAtUtc,
    IReadOnlyList<BackupRestoreArtifact> Artifacts);

public sealed record BackupRestoreArtifact(
    string Database,
    string LocalPath,
    long ByteLength,
    string Sha256);

public static class BackupRestoreManifestVerifier
{
    public static async Task<BackupRestoreManifest> CreateAsync(
        BackupReceipt receipt,
        IReceiptAttestationTrustStore trust,
        string recoveryDirectory,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(trust);
        string root = Path.GetFullPath(recoveryDirectory);
        SecureLocalFile.EnsureOwnerOnlyDirectory(root);
        if (!ReceiptAttestation.TryCreatePayload(receipt, out byte[] payload) ||
            string.IsNullOrWhiteSpace(receipt.AttestationKeyId) ||
            string.IsNullOrWhiteSpace(receipt.AttestationSignature) ||
            !TryDecode(receipt.AttestationSignature, out byte[] signature) ||
            !trust.Verify(receipt.AttestationKeyId, payload, signature) ||
            receipt.Artifacts is null || receipt.SourceObservedAtUtc is null ||
            !receipt.Artifacts.Select(item => item?.Database).Order(StringComparer.Ordinal)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            throw new Exact25FullBackupException("restore_receipt_invalid", "The signed exact-25 backup receipt is invalid.");
        }

        var artifacts = new List<BackupRestoreArtifact>(25);
        foreach (BackupArtifact artifact in receipt.Artifacts.Select(item => item!))
        {
            if (!string.Equals(artifact.FileName, Path.GetFileName(artifact.FileName), StringComparison.Ordinal))
            {
                throw new Exact25FullBackupException("restore_artifact_path_invalid", "A signed backup filename is unsafe.");
            }
            string localPath = Path.Combine(root, artifact.FileName!);
            SecureLocalFile.EnsurePathWithin(root, localPath);
            var file = new FileInfo(localPath);
            if (!SecureLocalFile.IsOwnerOnlyFile(file) || file.Length != artifact.ByteLength)
            {
                throw new Exact25FullBackupException("restore_artifact_invalid", "A retained backup does not match its signed receipt.");
            }
            await using FileStream stream = SecureLocalFile.OpenRead(localPath);
            string sha256 = await SecureLocalFile.ComputeSha256Async(stream, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(sha256), Encoding.ASCII.GetBytes(artifact.Sha256!.ToLowerInvariant())))
            {
                throw new Exact25FullBackupException("restore_artifact_invalid", "A retained backup does not match its signed receipt.");
            }
            artifacts.Add(new(artifact.Database!, localPath, file.Length, sha256));
        }
        return new("1.0", receipt.ManifestSha256!, receipt.SourceObservedAtUtc.Value, artifacts);
    }

    private static bool TryDecode(string value, out byte[] bytes)
    {
        try { bytes = Convert.FromBase64String(value); return true; }
        catch (FormatException) { bytes = []; return false; }
    }
}
