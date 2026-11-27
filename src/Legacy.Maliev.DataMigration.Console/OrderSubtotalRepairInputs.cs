using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record OrderSubtotalArtifact(string Path, string Sha256);
internal sealed record OrderSubtotalRepairConfiguration(string Kind, string RunBindingPath,
    OrderSubtotalArtifact IntentClaim, OrderSubtotalArtifact SourceCredential, OrderSubtotalArtifact TargetPins,
    OrderSubtotalArtifact OperatorConnection, OrderSubtotalArtifact OrdinaryConnection,
    CurrentAppOwnedRepairSigningPins SigningPins, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    OrderSubtotalArtifact ReviewPrivateKey, OrderSubtotalArtifact AuthorizationPrivateKey, OrderSubtotalArtifact EvidencePrivateKey,
    string ProofParent, OrderSubtotalArtifact ToolPins);

internal sealed partial class OrderSubtotalRepairInputs : IDisposable
{
    internal WindowsLocalRunAuthority Authority { get; }
    internal CurrentAppOwnedRepairCustody Files { get; }
    internal OrderSubtotalRepairConfiguration Configuration { get; }
    internal OrderSubtotalRepairIntent Intent { get; }
    internal CurrentAuthArchiveClaim IntentClaim { get; }
    internal IReceiptAttestationTrustStore Trust { get; }
    private OrderSubtotalRepairInputs(WindowsLocalRunAuthority authority, CurrentAppOwnedRepairCustody files,
        OrderSubtotalRepairConfiguration configuration, OrderSubtotalRepairIntent intent, CurrentAuthArchiveClaim claim, IReceiptAttestationTrustStore trust)
    { Authority = authority; Files = files; Configuration = configuration; Intent = intent; IntentClaim = claim; Trust = trust; }

    internal static OrderSubtotalRepairInputs Open(string configurationPath)
    {
        if (!Path.IsPathFullyQualified(configurationPath) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(configurationPath))) { throw Invalid(); }
        byte[] bytes;
        using (var held = SecureLocalFile.OpenReadShared(configurationPath))
        {
            if (!SecureLocalFile.HandleResolvesToApprovedPath(held, configurationPath) || held.Length is < 1 or > 65536) { throw Invalid(); }
            bytes = new byte[checked((int)held.Length)]; held.ReadExactly(bytes);
        }
        var config = MigrationConsole.DecodeAuthRepair<OrderSubtotalRepairConfiguration>(bytes);
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(ReadLoose(config.RunBindingPath, 65536));
        WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(Path.GetDirectoryName(configurationPath)!, binding);
        var files = new CurrentAppOwnedRepairCustody(authority);
        try
        {
            if (config.Kind != "current-order-subtotal-fixed-configuration-v1" || !files.Read(configurationPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes) ||
                Path.GetDirectoryName(config.RunBindingPath) != authority.Binding.ArtifactRootCanonicalPath ||
                !Path.IsPathFullyQualified(config.ProofParent) || !Directory.Exists(config.ProofParent)) { throw Invalid(); }
            var trust = new ReceiptAttestationTrustStore(config.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
                files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
            var archivePins = ArchivePins(config.SigningPins); CurrentAuthLocalSessionArchivePolicy.RequirePins(archivePins, trust);
            byte[] intentBytes = Read(files, config.IntentClaim);
            var claim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(intentBytes);
            var intent = CurrentAuthLocalSessionArchivePolicy.Verify<OrderSubtotalRepairIntent>(claim, OrderSubtotalRepairProtocol.IntentDomain,
                archivePins.ReviewKeyId, archivePins.ReviewFingerprint, trust);
            return intent.Kind != OrderSubtotalRepairProtocol.IntentKind || intent.RunBindingSha256 != authority.Binding.ComputeSha256()
                ? throw Invalid()
                : new(authority, files, config, intent, claim, trust);
        }
        catch { files.Dispose(); authority.Dispose(); throw; }
    }
    private static byte[] ReadLoose(string path, int maximum)
    {
        if (!Path.IsPathFullyQualified(path) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path))) { throw Invalid(); }
        using var held = SecureLocalFile.OpenReadShared(path);
        if (!SecureLocalFile.HandleResolvesToApprovedPath(held, path) || held.Length is < 1 || held.Length > maximum) { throw Invalid(); }
        byte[] bytes = new byte[checked((int)held.Length)]; held.ReadExactly(bytes); return bytes;
    }
    internal static CurrentAuthArchivePins ArchivePins(CurrentAppOwnedRepairSigningPins pins)
    {
        return new(pins.ReviewKeyId, pins.ReviewFingerprint,
        pins.AuthorizationKeyId, pins.AuthorizationFingerprint, pins.ReceiptKeyId, pins.ReceiptFingerprint);
    }

    internal byte[] Read(OrderSubtotalArtifact artifact, int maximum = 65536)
    {
        return Read(Files, artifact, maximum);
    }

    private static byte[] Read(CurrentAppOwnedRepairCustody files, OrderSubtotalArtifact artifact, int maximum = 65536)
    { byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: maximum); return OrderSubtotalRepairProtocol.Hash(bytes) == artifact.Sha256 ? bytes : throw Invalid(); }
    internal string Secret(OrderSubtotalArtifact artifact)
    { byte[] bytes = Read(artifact); try { return new UTF8Encoding(false, true).GetString(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); } }
    internal P256MigrationEvidenceSigner Signer(OrderSubtotalArtifact artifact, string id, string fingerprint)
    {
        var signer = new P256MigrationEvidenceSigner(id, Secret(artifact));
        if (signer.PublicKeyFingerprintSha256 == fingerprint) { return signer; }
        signer.Dispose(); throw Invalid();
    }
    internal async Task<OrderSubtotalArtifact> PublishAsync<T>(string suffix, T value, Guid operation, CancellationToken ct)
    {
        string path = Path.Combine(Authority.Binding.ArtifactRootCanonicalPath, $"{operation:D}-Order-subtotal-{suffix}.json");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value); await Files.WriteNewAsync(path, bytes, ct);
        return !Files.Read(path, sharedReader: true, maximumBytes: 32 * 1024 * 1024).AsSpan().SequenceEqual(bytes)
            ? throw Invalid()
            : new(path, OrderSubtotalRepairProtocol.Hash(bytes));
    }
    public void Dispose() { Files.Dispose(); Authority.Dispose(); }
    private static MigrationExecutionException Invalid()
    {
        return OrderSubtotalRepairProtocol.Invalid();
    }
}
