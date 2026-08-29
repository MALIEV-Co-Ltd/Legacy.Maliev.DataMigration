using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class P256MigrationEvidenceSignerTests
{
    [Fact]
    public void Sign_UsesExternallySuppliedP256Key()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("evidence-key", key.ExportECPrivateKeyPem());
        byte[] payload = "evidence"u8.ToArray();

        byte[] signature = signer.Sign(payload);

        Assert.True(key.VerifyData(payload, signature, HashAlgorithmName.SHA256));
    }
}
