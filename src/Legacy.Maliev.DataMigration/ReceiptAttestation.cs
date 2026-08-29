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
    private const string P256CurveOid = "1.2.840.10045.3.1.7";
    private readonly Dictionary<string, byte[]> _trustedKeys;

    public ReceiptAttestationTrustStore(IEnumerable<TrustedAttestationKey> trustedKeys)
    {
        ArgumentNullException.ThrowIfNull(trustedKeys);

        Dictionary<string, byte[]> keys = new(StringComparer.Ordinal);
        foreach (TrustedAttestationKey trustedKey in trustedKeys)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(trustedKey.KeyId);
            ArgumentNullException.ThrowIfNull(trustedKey.SubjectPublicKeyInfo);

            byte[] subjectPublicKeyInfo = trustedKey.SubjectPublicKeyInfo.ToArray();
            ValidateP256SubjectPublicKeyInfo(subjectPublicKeyInfo);
            if (!keys.TryAdd(trustedKey.KeyId, subjectPublicKeyInfo))
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
        try
        {
            verifier.ImportSubjectPublicKeyInfo(publicKey, out int bytesRead);
            return bytesRead == publicKey.Length &&
                IsP256(verifier) &&
                verifier.VerifyData(payload, signature, HashAlgorithmName.SHA256);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static void ValidateP256SubjectPublicKeyInfo(byte[] subjectPublicKeyInfo)
    {
        using ECDsa verifier = ECDsa.Create();
        try
        {
            verifier.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out int bytesRead);
            if (bytesRead != subjectPublicKeyInfo.Length)
            {
                throw CreateTrustedKeyException("trusted_attestation_key_encoding_invalid");
            }
        }
        catch (CryptographicException)
        {
            throw CreateTrustedKeyException("trusted_attestation_key_algorithm_invalid");
        }

        if (!IsP256(verifier))
        {
            throw CreateTrustedKeyException("trusted_attestation_key_curve_invalid");
        }
    }

    private static bool IsP256(ECDsa verifier)
    {
        ECCurve curve = verifier.ExportParameters(false).Curve;
        return verifier.KeySize == 256 &&
            string.Equals(curve.Oid.Value, P256CurveOid, StringComparison.Ordinal);
    }

    private static ArgumentException CreateTrustedKeyException(string code)
    {
        var exception = new ArgumentException("Trusted attestation key is not an ECDSA P-256 public key.");
        exception.Data["code"] = code;
        return exception;
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
                WriteString(writer, artifact.GcsObject ?? string.Empty);
                writer.Write(artifact.GcsGeneration ?? 0);
                WriteString(writer, artifact.GcsSha256 ?? string.Empty);
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
