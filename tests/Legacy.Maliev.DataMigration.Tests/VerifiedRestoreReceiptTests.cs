using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class VerifiedRestoreReceiptTests
{
    private const string Digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Theory]
    [InlineData("mcr.microsoft.com/mssql/server:2019-CU30-ubuntu-20.04@sha256:" + Digest)]
    [InlineData("example.invalid/mssql/server:2022-CU20-ubuntu-22.04@sha256:" + Digest)]
    [InlineData("mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04")]
    public void SqlServerImagePolicy_RejectsAnythingExceptDigestPinnedMicrosoftSql2022(string image)
    {
        _ = Assert.Throws<ArgumentException>(() => RestoreImagePolicy.ValidateSqlServer2022(image));
    }

    [Fact]
    public void SqlServerImagePolicy_AcceptsDigestPinnedMicrosoftSql2022()
    {
        Assert.Equal(
            "mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04@sha256:" + Digest,
            RestoreImagePolicy.ValidateSqlServer2022(
                "mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04@sha256:" + Digest));
    }

    [Theory]
    [InlineData("busybox:1.36@sha256:" + Digest)]
    [InlineData("example.invalid/alpine:3.20@sha256:" + Digest)]
    [InlineData("alpine:latest@sha256:" + Digest)]
    public void StagingImagePolicy_RejectsUnapprovedHelper(string image)
    {
        _ = Assert.Throws<ArgumentException>(() => RestoreImagePolicy.ValidateStagingHelper(image));
    }

    [Fact]
    public void SignedReceipt_BindsExactInventoryRuntimeCustodyAndCleanup()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        VerifiedRestoreReceipt unsigned = Receipt() with
        {
            AttestationKeyId = "restore-provenance-key",
            AttestationSignature = null,
        };

        VerifiedRestoreReceipt signed = VerifiedRestoreReceiptAttestation.Sign(unsigned, key);

        Assert.True(VerifiedRestoreReceiptAttestation.TryCreatePayload(signed, out byte[] payload));
        Assert.True(key.VerifyData(payload, Convert.FromBase64String(signed.AttestationSignature!), HashAlgorithmName.SHA256));
        Assert.Equal(DatabaseInventory.ActiveDatabases.Order(StringComparer.Ordinal),
            signed.Artifacts.Select(item => item.Database).Order(StringComparer.Ordinal));

        VerifiedRestoreReceipt tampered = signed with
        {
            Resources = signed.Resources with { ContainerId = "sha256:" + new string('b', 64) },
        };
        Assert.True(VerifiedRestoreReceiptAttestation.TryCreatePayload(tampered, out byte[] tamperedPayload));
        Assert.False(key.VerifyData(tamperedPayload, Convert.FromBase64String(signed.AttestationSignature!), HashAlgorithmName.SHA256));
    }

    [Fact]
    public void ReceiptCanonicalizer_FailsClosedForUnknownDispositionAndNullRuntimeEvidence()
    {
        Assert.False(VerifiedRestoreReceiptAttestation.TryCreatePayload(
            Receipt() with { CleanupDisposition = (RestoreCleanupDisposition)42 }, out _));
        Assert.False(VerifiedRestoreReceiptAttestation.TryCreatePayload(
            Receipt() with { Resources = null! }, out _));
        Assert.False(VerifiedRestoreReceiptAttestation.TryCreatePayload(
            Receipt() with { Artifacts = null! }, out _));
    }

    [Fact]
    public void ProvenanceSigner_MustMatchTheConfiguredTrustedKeyBeforeRuntimeMutation()
    {
        using ECDsa trustedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trust = new ReceiptAttestationTrustStore([
            new TrustedAttestationKey("restore-provenance-key", trustedKey.ExportSubjectPublicKeyInfo()),
        ]);

        Assert.True(VerifiedRestoreReceiptAttestation.SigningKeyMatchesTrust(
            "restore-provenance-key", trustedKey, trust));
        Assert.False(VerifiedRestoreReceiptAttestation.SigningKeyMatchesTrust(
            "restore-provenance-key", otherKey, trust));
        Assert.False(VerifiedRestoreReceiptAttestation.SigningKeyMatchesTrust(
            "unknown-key", trustedKey, trust));
    }

    private static VerifiedRestoreReceipt Receipt()
    {
        string sqlImage = "mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04@sha256:" + Digest;
        string stagingImage = "alpine:3.20@sha256:" + new string('b', 64);
        var resources = new VerifiedRestoreResourceEvidence(
            sqlImage,
            "sha256:" + Digest,
            "sha256:" + new string('c', 64),
            "legacy-sql-run-1",
            "run-1",
            "legacy-volume-run-1",
            "legacy-volume-run-1",
            "/var/opt/mssql/recovery",
            MountReadOnly: true,
            stagingImage);
        VerifiedRestoreArtifactEvidence[] artifacts = [.. DatabaseInventory.ActiveDatabases.Select(database =>
            new VerifiedRestoreArtifactEvidence(database, 42, Digest, 42, Digest,
                VerifyOnlyWithChecksum: true, SnapshotIsolationEnabled: true, ReadOnly: true))];
        return new VerifiedRestoreReceipt(
            "1.0",
            DateTimeOffset.Parse("2026-08-30T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture),
            DatabaseInventory.InventorySha256,
            new string('d', 64),
            resources,
            artifacts,
            RestoreCleanupDisposition.Removed,
            DateTimeOffset.Parse("2026-08-30T00:10:00Z", System.Globalization.CultureInfo.InvariantCulture),
            "restore-provenance-key",
            null);
    }
}
