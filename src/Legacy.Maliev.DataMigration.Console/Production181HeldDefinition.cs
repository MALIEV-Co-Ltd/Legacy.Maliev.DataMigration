using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record Production181PrerequisitePaths(string Catalog, string Definition, string PublicKey, string KeyId,
    string Fingerprint, string BindingPath, string BindingSha256, CustomerDefinitionArtifact SemanticEnvelope);

// The completed definition root is separate from the active native host root. No permit is returned.
internal sealed class Production181HeldDefinition : IDisposable
{
    private readonly WindowsLocalRunAuthority _authority;
    private readonly CurrentAppOwnedRepairCustody _files;
    internal CustomerDefinitionProof Proof { get; }
    internal string CatalogSha256 { get; }
    internal string DefinitionSha256 { get; }

    private Production181HeldDefinition(WindowsLocalRunAuthority authority, CurrentAppOwnedRepairCustody files,
        CustomerDefinitionProof proof, string catalog, string definition)
    { _authority = authority; _files = files; Proof = proof; CatalogSha256 = catalog; DefinitionSha256 = definition; }

    internal static Production181HeldDefinition Open(CurrentAppOwnedRepairCustody active, string manifest,
        CustomerDefinitionSubject intended, IReceiptAttestationTrustStore trust, string keyId, string fingerprint)
    {
        var paths = MigrationConsole.DecodeCustomerSequence<Production181PrerequisitePaths>(active.Read(manifest, sharedReader: true, maximumBytes: 65536));
        return Open(paths, intended, trust, keyId, fingerprint);
    }

    internal static Production181HeldDefinition Open(Production181PrerequisitePaths paths, CustomerDefinitionSubject? intended = null,
        IReceiptAttestationTrustStore? suppliedTrust = null, string? keyId = null, string? fingerprint = null)
    {
        using var bindingStream = SecureLocalFile.OpenReadShared(paths.BindingPath);
        if (bindingStream.Length is < 1 or > 65536) { throw Invalid(); }
        var binding = JsonSerializer.Deserialize<LocalExecutionBinding>(bindingStream) ?? throw Invalid();
        if (binding.ComputeSha256() != paths.BindingSha256 || !SecureLocalFile.HandleResolvesToApprovedPath(bindingStream, paths.BindingPath)) { throw Invalid(); }
        string? active = Environment.GetEnvironmentVariable("MALIEV_PRODUCTION181_NATIVE_LEDGER");
        if (active is not null && StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(active), binding.ArtifactRootCanonicalPath)) { throw Invalid(); }
        var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        var files = new CurrentAppOwnedRepairCustody(authority);
        try
        {
            byte[] publicKey = files.Read(paths.PublicKey, sharedReader: true, maximumBytes: 4096);
            var heldTrust = new ReceiptAttestationTrustStore([new(paths.KeyId, publicKey)]);
            if (!heldTrust.TryGetPublicKeyFingerprintSha256(paths.KeyId, out string measured) || measured != paths.Fingerprint ||
                (keyId is not null && keyId != paths.KeyId) || (fingerprint is not null && fingerprint != measured)) { throw Invalid(); }
            byte[] bytes = files.Read(paths.Definition, sharedReader: true, maximumBytes: 8_000_000);
            var proof = MigrationConsole.DecodeCustomerSequence<CustomerDefinitionProof>(bytes);
            Production181CustomerDefinitionReader.Require(files, proof, intended ?? proof.Subject, suppliedTrust ?? heldTrust, paths.KeyId, measured, DateTimeOffset.UtcNow);
            byte[] envelopeBytes = files.Read(paths.SemanticEnvelope.Path, sharedReader: true, maximumBytes: 8_000_000);
            if (CurrentCustomerSequenceRepairPermit.Hash(envelopeBytes) != paths.SemanticEnvelope.Sha256) { throw Invalid(); }
            var envelope = MigrationConsole.DecodeCustomerSequence<Production181SemanticEnvelope>(envelopeBytes);
            if (envelope.Phase != "definition" || envelope.Component.Sha256 != CurrentCustomerSequenceRepairPermit.Hash(bytes)) { throw Invalid(); }
            _ = Production181SemanticEnvelopeReader.Require(files, envelope, intended ?? proof.Subject, suppliedTrust ?? heldTrust, paths.KeyId, measured, DateTimeOffset.UtcNow);
            string catalog = CurrentCustomerSequenceRepairPermit.Hash(files.Read(paths.Catalog, sharedReader: true, maximumBytes: 8_000_000));
            if (catalog != proof.Subject.Source.CatalogReportSha256) { throw Invalid(); }
            files.Require(); return new(authority, files, proof, catalog, CurrentCustomerSequenceRepairPermit.Hash(bytes));
        }
        catch { files.Dispose(); authority.Dispose(); throw; }
    }
    internal void Require() { _files.Require(); }
    public void Dispose() { _files.Dispose(); _authority.Dispose(); }
    private static MigrationExecutionException Invalid()
    {
        return CurrentCustomerSequenceRepairPermit.Invalid();
    }
}
