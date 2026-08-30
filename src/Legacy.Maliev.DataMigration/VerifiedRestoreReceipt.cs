using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public enum RestoreCleanupDisposition
{
    Pending = 0,
    Removed = 1,
}

public sealed record VerifiedRestoreResourceEvidence(
    string SqlServerImage,
    string SqlServerImageId,
    string ContainerId,
    string ContainerName,
    string RunBinding,
    string VolumeName,
    string VolumeId,
    string MountPath,
    bool MountReadOnly,
    string StagingImage);

public sealed record VerifiedRestoreArtifactEvidence(
    string Database,
    long RetainedByteLength,
    string RetainedSha256,
    long StagedByteLength,
    string StagedSha256,
    bool VerifyOnlyWithChecksum,
    bool SnapshotIsolationEnabled,
    bool ReadOnly);

public sealed record VerifiedRestoreReceipt(
    string SchemaVersion,
    DateTimeOffset RestoredAtUtc,
    string DatabaseInventorySha256,
    string BackupManifestSha256,
    VerifiedRestoreResourceEvidence Resources,
    IReadOnlyList<VerifiedRestoreArtifactEvidence> Artifacts,
    RestoreCleanupDisposition CleanupDisposition,
    DateTimeOffset? CleanedAtUtc,
    string AttestationKeyId,
    string? AttestationSignature);

public static partial class RestoreImagePolicy
{
    public static string ValidateSqlServer2022(string image)
    {
        return SqlServer2022().IsMatch(image ?? string.Empty)
            ? image!
            : throw new ArgumentException(
                "The restore image must be the approved digest-pinned Microsoft SQL Server 2022 image.",
                nameof(image));
    }

    public static string ValidateStagingHelper(string image)
    {
        return StagingHelper().IsMatch(image ?? string.Empty)
            ? image!
            : throw new ArgumentException(
                "The restore staging helper must be the approved digest-pinned Alpine 3.20 image.",
                nameof(image));
    }

    [GeneratedRegex("^mcr\\.microsoft\\.com/mssql/server:2022-[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex SqlServer2022();

    [GeneratedRegex("^(?:(?:docker\\.io/)?library/)?alpine:3\\.20(?:\\.[0-9]+)?@sha256:[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex StagingHelper();
}

public static class VerifiedRestoreReceiptAttestation
{
    private const string DomainSeparator = "Legacy.Maliev.DataMigration.VerifiedRestoreReceipt.v1";
    private static readonly byte[] SigningKeyProof = Encoding.UTF8.GetBytes(
        "Legacy.Maliev.DataMigration.VerifiedRestoreReceipt.SigningKeyProof.v1");

    public static bool SigningKeyMatchesTrust(string keyId, ECDsa key, IReceiptAttestationTrustStore trust)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(trust);
        if (string.IsNullOrWhiteSpace(keyId))
        {
            return false;
        }
        try
        {
            ValidateSigningKey(key);
            byte[] signature = key.SignData(SigningKeyProof, HashAlgorithmName.SHA256);
            return trust.Verify(keyId, SigningKeyProof, signature);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    public static VerifiedRestoreReceipt Sign(VerifiedRestoreReceipt receipt, ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(key);
        ValidateSigningKey(key);

        VerifiedRestoreReceipt unsigned = receipt with { AttestationSignature = null };
        return !TryCreatePayload(unsigned, out byte[] payload)
            ? throw new Exact25FullBackupException("verified_restore_receipt_invalid", "The verified restore receipt is incomplete.")
            : (unsigned with { AttestationSignature = Convert.ToBase64String(key.SignData(payload, HashAlgorithmName.SHA256)) });
    }

    public static bool Verify(VerifiedRestoreReceipt receipt, IReceiptAttestationTrustStore trust)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(trust);
        if (!TryCreatePayload(receipt, out byte[] payload) || string.IsNullOrWhiteSpace(receipt.AttestationSignature))
        {
            return false;
        }
        try
        {
            return trust.Verify(receipt.AttestationKeyId, payload, Convert.FromBase64String(receipt.AttestationSignature));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static bool TryCreatePayload(VerifiedRestoreReceipt receipt, out byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        payload = [];
        if (receipt.Resources is null || receipt.Artifacts is null || receipt.Artifacts.Any(item => item is null) ||
            !Enum.IsDefined(receipt.CleanupDisposition))
        {
            return false;
        }
        VerifiedRestoreResourceEvidence resources = receipt.Resources;
        string[] databases = [.. receipt.Artifacts.Select(item => item.Database).Order(StringComparer.Ordinal)];
        if (!string.Equals(receipt.SchemaVersion, "1.0", StringComparison.Ordinal) ||
            receipt.RestoredAtUtc == default || receipt.RestoredAtUtc.Offset != TimeSpan.Zero ||
            !Hash(receipt.DatabaseInventorySha256) || !Hash(receipt.BackupManifestSha256) ||
            !string.Equals(receipt.DatabaseInventorySha256, DatabaseInventory.InventorySha256, StringComparison.OrdinalIgnoreCase) ||
            databases.Length != DatabaseInventory.ActiveDatabases.Count ||
            !databases.SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            receipt.Artifacts.Select(item => item.Database).Distinct(StringComparer.Ordinal).Count() != databases.Length ||
            string.IsNullOrWhiteSpace(receipt.AttestationKeyId) ||
            !ValidResources(resources) || receipt.Artifacts.Any(item => !ValidArtifact(item)) ||
            (receipt.CleanupDisposition == RestoreCleanupDisposition.Pending && receipt.CleanedAtUtc is not null) ||
            (receipt.CleanupDisposition == RestoreCleanupDisposition.Removed &&
             (receipt.CleanedAtUtc is null || receipt.CleanedAtUtc.Value.Offset != TimeSpan.Zero || receipt.CleanedAtUtc < receipt.RestoredAtUtc)))
        {
            return false;
        }

        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, new UTF8Encoding(false), leaveOpen: true))
        {
            Write(writer, DomainSeparator);
            Write(writer, receipt.SchemaVersion);
            Write(writer, receipt.RestoredAtUtc.ToString("O", CultureInfo.InvariantCulture));
            Write(writer, receipt.DatabaseInventorySha256.ToLowerInvariant());
            Write(writer, receipt.BackupManifestSha256.ToLowerInvariant());
            Write(writer, resources.SqlServerImage);
            Write(writer, resources.SqlServerImageId);
            Write(writer, resources.ContainerId);
            Write(writer, resources.ContainerName);
            Write(writer, resources.RunBinding);
            Write(writer, resources.VolumeName);
            Write(writer, resources.VolumeId);
            Write(writer, resources.MountPath);
            writer.Write(resources.MountReadOnly);
            Write(writer, resources.StagingImage);
            writer.Write(receipt.Artifacts.Count);
            foreach (VerifiedRestoreArtifactEvidence artifact in receipt.Artifacts.OrderBy(item => item.Database, StringComparer.Ordinal))
            {
                Write(writer, artifact.Database);
                writer.Write(artifact.RetainedByteLength);
                Write(writer, artifact.RetainedSha256.ToLowerInvariant());
                writer.Write(artifact.StagedByteLength);
                Write(writer, artifact.StagedSha256.ToLowerInvariant());
                writer.Write(artifact.VerifyOnlyWithChecksum);
                writer.Write(artifact.SnapshotIsolationEnabled);
                writer.Write(artifact.ReadOnly);
            }
            writer.Write((int)receipt.CleanupDisposition);
            Write(writer, receipt.CleanedAtUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty);
            Write(writer, receipt.AttestationKeyId);
        }
        payload = stream.ToArray();
        return true;
    }

    private static bool ValidResources(VerifiedRestoreResourceEvidence value)
    {
        try
        {
            _ = RestoreImagePolicy.ValidateSqlServer2022(value.SqlServerImage);
            _ = RestoreImagePolicy.ValidateStagingHelper(value.StagingImage);
        }
        catch (ArgumentException)
        {
            return false;
        }
        return HashWithOptionalPrefix(value.SqlServerImageId) && HashWithOptionalPrefix(value.ContainerId) &&
            !string.IsNullOrWhiteSpace(value.ContainerName) && !string.IsNullOrWhiteSpace(value.RunBinding) &&
            !string.IsNullOrWhiteSpace(value.VolumeName) && !string.IsNullOrWhiteSpace(value.VolumeId) &&
            value.MountPath.Length > 0 && value.MountPath[0] == '/' && value.MountReadOnly;
    }

    private static bool ValidArtifact(VerifiedRestoreArtifactEvidence value)
    {
        return DatabaseInventory.ActiveDatabases.Contains(value.Database, StringComparer.Ordinal) &&
            value.RetainedByteLength > 0 && value.RetainedByteLength == value.StagedByteLength &&
            Hash(value.RetainedSha256) && Hash(value.StagedSha256) &&
            CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(value.RetainedSha256.ToLowerInvariant()),
                Encoding.ASCII.GetBytes(value.StagedSha256.ToLowerInvariant())) &&
            value.VerifyOnlyWithChecksum && value.SnapshotIsolationEnabled && value.ReadOnly;
    }

    private static bool Hash(string value)
    {
        return value.Length == 64 && value.All(char.IsAsciiHexDigit);
    }

    private static bool HashWithOptionalPrefix(string value)
    {
        string hash = value.StartsWith("sha256:", StringComparison.Ordinal) ? value[7..] : value;
        return Hash(hash);
    }

    private static void ValidateSigningKey(ECDsa key)
    {
        ECParameters parameters = key.ExportParameters(false);
        if (key.KeySize != 256 || !string.Equals(parameters.Curve.Oid.Value, "1.2.840.10045.3.1.7", StringComparison.Ordinal))
        {
            throw new ArgumentException("The verified restore receipt signing key must be ECDSA P-256.", nameof(key));
        }
    }

    private static void Write(BinaryWriter writer, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }
}
