using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration;

public sealed class P256MigrationEvidenceSigner : IMigrationEvidenceSigner, IDisposable
{
    private readonly ECDsa _key = ECDsa.Create();

    public P256MigrationEvidenceSigner(string keyId, ReadOnlySpan<char> privateKeyPem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        KeyId = keyId;
        try
        {
            _key.ImportFromPem(privateKeyPem);
            ECParameters parameters = _key.ExportParameters(false);
            if (_key.KeySize != 256 || !string.Equals(parameters.Curve.Oid.Value, "1.2.840.10045.3.1.7", StringComparison.Ordinal))
            {
                throw new ArgumentException("The migration evidence key must be ECDSA P-256.", nameof(privateKeyPem));
            }
        }
        catch (CryptographicException exception)
        {
            throw new ArgumentException("The migration evidence key is invalid.", nameof(privateKeyPem), exception);
        }
    }

    public string KeyId { get; }

    public byte[] Sign(ReadOnlySpan<byte> payload)
    {
        return _key.SignData(payload, HashAlgorithmName.SHA256);
    }

    public void Dispose()
    {
        _key.Dispose();
    }
}
