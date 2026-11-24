using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CompanyStorageArtifact(string Path, string Sha256);
internal sealed record CompanyStorageRepairConfiguration(string Kind, string RunBindingPath,
    CompanyStorageArtifact IntentClaim, CompanyStorageArtifact SourceCredential, CompanyStorageArtifact TargetPins,
    CompanyStorageArtifact OperatorConnection, CompanyStorageArtifact OrdinaryConnection,
    CurrentAppOwnedRepairSigningPins SigningPins, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    CompanyStorageArtifact ReviewPrivateKey, CompanyStorageArtifact AuthorizationPrivateKey, CompanyStorageArtifact EvidencePrivateKey,
    string ProofParent, CompanyStorageArtifact TestsImage);

internal sealed partial class CompanyStorageRepairInputs : IDisposable
{
    internal WindowsLocalRunAuthority Authority { get; }
    internal CurrentAppOwnedRepairCustody Files { get; }
    internal CompanyStorageRepairConfiguration Configuration { get; }
    internal CompanyStorageRepairIntent Intent { get; }
    internal CurrentAuthArchiveClaim IntentClaim { get; }
    internal IReceiptAttestationTrustStore Trust { get; }
    private CompanyStorageRepairInputs(WindowsLocalRunAuthority authority, CurrentAppOwnedRepairCustody files,
        CompanyStorageRepairConfiguration configuration, CompanyStorageRepairIntent intent, CurrentAuthArchiveClaim claim, IReceiptAttestationTrustStore trust)
    { Authority = authority; Files = files; Configuration = configuration; Intent = intent; IntentClaim = claim; Trust = trust; }

    internal static CompanyStorageRepairInputs Open(string configurationPath)
    {
        return OpenCore(configurationPath, owned: false);
    }

    internal static CompanyStorageRepairInputs OpenOwned(string configurationPath, CompanyStorageOwnedSession session)
    {
        if (System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly || !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(session.Lease.Target)) { throw Invalid(); }
        var input = OpenCore(configurationPath, owned: true);
        if (input.Intent.Target == session.Lease.Target) { return input; }
        input.Dispose(); throw Invalid();
    }
    private static CompanyStorageRepairInputs OpenCore(string configurationPath, bool owned)
    {
        if (!Path.IsPathFullyQualified(configurationPath) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(configurationPath))) { throw Invalid(); }
        byte[] bytes;
        using (var held = SecureLocalFile.OpenReadShared(configurationPath))
        {
            if (!SecureLocalFile.HandleResolvesToApprovedPath(held, configurationPath) || held.Length is < 1 or > 65536) { throw Invalid(); }
            bytes = new byte[checked((int)held.Length)]; held.ReadExactly(bytes);
        }
        var config = MigrationConsole.DecodeAuthRepair<CompanyStorageRepairConfiguration>(bytes);
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(ReadLoose(config.RunBindingPath, 65536));
        WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(Path.GetDirectoryName(configurationPath)!, binding);
        var files = new CurrentAppOwnedRepairCustody(authority);
        try
        {
            if (config.Kind != (owned ? "current-company-storage-owned-fault-configuration-v1" : "current-company-storage-fixed-configuration-v1") || !files.Read(configurationPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes) ||
                Path.GetDirectoryName(config.RunBindingPath) != authority.Binding.ArtifactRootCanonicalPath ||
                !Path.IsPathFullyQualified(config.ProofParent) || !Directory.Exists(config.ProofParent)) { throw Invalid(); }
            var trust = new ReceiptAttestationTrustStore(config.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
                files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
            var archivePins = ArchivePins(config.SigningPins); CurrentAuthLocalSessionArchivePolicy.RequirePins(archivePins, trust);
            byte[] intentBytes = Read(files, config.IntentClaim);
            var claim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(intentBytes);
            var intent = CurrentAuthLocalSessionArchivePolicy.Verify<CompanyStorageRepairIntent>(claim, CompanyStorageRepairProtocol.IntentDomain,
                archivePins.ReviewKeyId, archivePins.ReviewFingerprint, trust);
            return intent.Kind != (owned ? CompanyStorageRepairProtocol.OwnedIntentKind : CompanyStorageRepairProtocol.IntentKind) || intent.RunBindingSha256 != authority.Binding.ComputeSha256()
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

    internal byte[] Read(CompanyStorageArtifact artifact, int maximum = 65536)
    {
        return Read(Files, artifact, maximum);
    }

    private static byte[] Read(CurrentAppOwnedRepairCustody files, CompanyStorageArtifact artifact, int maximum = 65536)
    { byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: maximum); return CompanyStorageRepairProtocol.Hash(bytes) == artifact.Sha256 ? bytes : throw Invalid(); }
    internal string Secret(CompanyStorageArtifact artifact)
    { byte[] bytes = Read(artifact); try { return new UTF8Encoding(false, true).GetString(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); } }
    internal P256MigrationEvidenceSigner Signer(CompanyStorageArtifact artifact, string id, string fingerprint)
    {
        var signer = new P256MigrationEvidenceSigner(id, Secret(artifact));
        if (signer.PublicKeyFingerprintSha256 == fingerprint) { return signer; }
        signer.Dispose(); throw Invalid();
    }
    internal async Task<CompanyStorageArtifact> PublishAsync<T>(string suffix, T value, Guid operation, CancellationToken ct)
    {
        string path = Path.Combine(Authority.Binding.ArtifactRootCanonicalPath, $"{operation:D}-Company-storage-{suffix}.json");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value); await Files.WriteNewAsync(path, bytes, ct);
        return !Files.Read(path, sharedReader: true, maximumBytes: 32 * 1024 * 1024).AsSpan().SequenceEqual(bytes)
            ? throw Invalid()
            : new(path, CompanyStorageRepairProtocol.Hash(bytes));
    }
    public void Dispose() { Files.Dispose(); Authority.Dispose(); }
    private static MigrationExecutionException Invalid()
    {
        return CompanyStorageRepairProtocol.Invalid();
    }
}
