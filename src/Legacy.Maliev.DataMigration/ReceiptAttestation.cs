using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration;

public interface IReceiptAttestationTrustStore
{
    bool ContainsKey(string keyId);

    bool Verify(string keyId, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature);
}

public sealed class ReceiptAttestationTrustStore : IReceiptAttestationTrustStore
{
    private readonly Dictionary<string, byte[]> _trustedKeys;

    public ReceiptAttestationTrustStore(IEnumerable<TrustedAttestationKey> trustedKeys)
    {
        ArgumentNullException.ThrowIfNull(trustedKeys);

        Dictionary<string, byte[]> keys = new(StringComparer.Ordinal);
        foreach (TrustedAttestationKey trustedKey in trustedKeys)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(trustedKey.KeyId);
            ArgumentNullException.ThrowIfNull(trustedKey.SubjectPublicKeyInfo);

            using ECDsa verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(trustedKey.SubjectPublicKeyInfo, out int bytesRead);
            if (bytesRead != trustedKey.SubjectPublicKeyInfo.Length ||
                !keys.TryAdd(trustedKey.KeyId, trustedKey.SubjectPublicKeyInfo.ToArray()))
            {
                throw new ArgumentException("Trusted attestation keys must be valid and have unique identifiers.", nameof(trustedKeys));
            }
        }

        _trustedKeys = keys;
    }

    public bool ContainsKey(string keyId)
    {
        return _trustedKeys.ContainsKey(keyId);
    }

    public bool Verify(string keyId, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature)
    {
        if (!_trustedKeys.TryGetValue(keyId, out byte[]? publicKey))
        {
            return false;
        }

        using ECDsa verifier = ECDsa.Create();
        verifier.ImportSubjectPublicKeyInfo(publicKey, out int bytesRead);
        return bytesRead == publicKey.Length &&
            verifier.VerifyData(payload, signature, HashAlgorithmName.SHA256);
    }
}

public static class ReceiptAttestation
{
    private const string DomainSeparator = "Legacy.Maliev.DataMigration.BackupReceipt.v1";

    public static bool TryCreatePayload(BackupReceipt receipt, out byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        payload = [];

        if (receipt.SchemaVersion is null ||
            receipt.DatabaseInventorySha256 is null ||
            receipt.ManifestSha256 is null ||
            receipt.AttestationKeyId is null ||
            receipt.Artifacts is null ||
            receipt.Artifacts.Any(artifact => artifact is null ||
                artifact.Database is null ||
                artifact.BackupType is null ||
                artifact.FileName is null ||
                artifact.Sha256 is null ||
                artifact.ObservedSha256 is null))
        {
            return false;
        }

        using MemoryStream stream = new();
        using (BinaryWriter writer = new(stream, new UTF8Encoding(false), leaveOpen: true))
        {
            WriteString(writer, DomainSeparator);
            WriteString(writer, receipt.SchemaVersion);
            WriteString(writer, receipt.CapturedAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            WriteString(writer, receipt.DatabaseInventorySha256);
            WriteString(writer, receipt.ManifestSha256);
            WriteString(writer, receipt.AttestationKeyId);

            BackupArtifact[] artifacts = receipt.Artifacts
                .Select(artifact => artifact!)
                .OrderBy(artifact => artifact.Database, StringComparer.Ordinal)
                .ToArray();
            writer.Write(artifacts.Length);
            foreach (BackupArtifact artifact in artifacts)
            {
                WriteString(writer, artifact.Database!);
                WriteString(writer, artifact.BackupType!);
                WriteString(writer, artifact.FileName!);
                writer.Write(artifact.ByteLength);
                WriteString(writer, artifact.Sha256!);
                WriteString(writer, artifact.ObservedSha256!);
            }
        }

        payload = stream.ToArray();
        return true;
    }

    private static void WriteString(BinaryWriter writer, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }
}
