using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record IsoComponentInputs(string BindingPath, string DefinitionBindingPath, string DefinitionPath, string DefinitionSubjectPath,
    string DefinitionPublicKeyPath, string DefinitionKeyId, string DefinitionFingerprint,
    string AcceptedSourcePath, string AcceptedOwnersPath, string SourceCatalogPath);
internal sealed record IsoCasePublicKey(string KeyId, string PublicKeyBase64);
internal sealed record IsoActualCaseEntry(string Kind, Guid RunId, string CaseId, string ContainerId,
    DateTimeOffset BeganAtUtc, string TestAssemblyPath, string TestAssemblySha256,
    int ProcessId, DateTimeOffset ProcessStartTimeUtc, string ExecutablePath, string ExecutableSha256);
internal sealed record IsoActualCaseExit(string Kind, Guid RunId, string CaseId, DateTimeOffset ObservedAtUtc,
    bool Returned, string? ExceptionType, string? RejectionCode);
internal sealed record IsoActualReceiptSlot(string Name, string PayloadBase64, bool Acknowledged, DateTimeOffset ObservedAtUtc);

internal sealed class IsoExecutedProofRecorder : IDisposable
{
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly WindowsLocalRunAuthority _authority;
    private readonly string _prefix;
    private int _slot;
    internal LocalExecutionBinding Binding { get; }
    internal IsoDefinitionSubject Intended { get; }
    internal FreshSchemaPlan Source { get; }
    internal IReadOnlyList<CurrentOwnerIsoSourceObservation> Owners { get; }
    internal string DefinitionSha256 { get; }
    internal string SourceCatalogSha256 { get; }
    internal Guid RunId { get; }
    internal string CaseId { get; }

    private IsoExecutedProofRecorder(WindowsLocalRunAuthority authority, CurrentAppOwnedRepairCustody files,
        LocalExecutionBinding binding, IsoDefinitionSubject intended, FreshSchemaPlan source,
        IReadOnlyList<CurrentOwnerIsoSourceObservation> owners, string definitionSha, string catalogSha, Guid run, string caseId)
    {
        _authority = authority; _files = files; Binding = binding; Intended = intended; Source = source;
        Owners = owners; DefinitionSha256 = definitionSha; SourceCatalogSha256 = catalogSha; RunId = run; CaseId = caseId;
        _prefix = Path.Combine(binding.ArtifactRootCanonicalPath, "iso-component-" + run.ToString("N"));
    }
    internal static IsoExecutedProofRecorder Open(Guid run, string caseId)
    {
        string path = Environment.GetEnvironmentVariable("MALIEV_ISO_COMPONENT_INPUTS") ?? throw Invalid();
        using var input = SecureLocalFile.OpenReadShared(path);
        if (input.Length is < 1 or > 65536) { throw Invalid(); }
        byte[] bytes = new byte[(int)input.Length]; input.ReadExactly(bytes);
        var settings = MigrationConsole.DecodeOwnerIso<IsoComponentInputs>(bytes);
        using var bindingFile = SecureLocalFile.OpenReadShared(settings.BindingPath);
        byte[] bindingBytes = new byte[checked((int)bindingFile.Length)]; bindingFile.ReadExactly(bindingBytes);
        var binding = MigrationConsole.DecodeOwnerIso<LocalExecutionBinding>(bindingBytes);
        var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        CurrentAppOwnedRepairCustody? files = null;
        try
        {
            files = new(authority);
            if (!files.Read(path, sharedReader: true).AsSpan().SequenceEqual(bytes) ||
                !files.Read(settings.BindingPath, sharedReader: true).AsSpan().SequenceEqual(bindingBytes)) { throw Invalid(); }
            using var definitionBindingFile = SecureLocalFile.OpenReadShared(settings.DefinitionBindingPath);
            if (definitionBindingFile.Length is < 1 or > 65536) { throw Invalid(); }
            byte[] definitionBindingBytes = new byte[(int)definitionBindingFile.Length]; definitionBindingFile.ReadExactly(definitionBindingBytes);
            var definitionBinding = MigrationConsole.DecodeOwnerIso<LocalExecutionBinding>(definitionBindingBytes);
            if (StringComparer.OrdinalIgnoreCase.Equals(definitionBinding.ArtifactRootCanonicalPath, binding.ArtifactRootCanonicalPath)) { throw Invalid(); }
            using var definitionAuthority = WindowsLocalRunAuthority.AcquireResume(definitionBinding.ArtifactRootCanonicalPath, definitionBinding);
            using var definitionFiles = new CurrentAppOwnedRepairCustody(definitionAuthority);
            if (!definitionFiles.Read(settings.DefinitionBindingPath, maximumBytes: 65536, sharedReader: true).AsSpan().SequenceEqual(definitionBindingBytes)) { throw Invalid(); }
            T Read<T>(string artifact)
            {
                return MigrationConsole.DecodeOwnerIso<T>(definitionFiles.Read(artifact, maximumBytes: 8_000_000, sharedReader: true));
            }

            byte[] publicKey = definitionFiles.Read(settings.DefinitionPublicKeyPath, maximumBytes: 65536, sharedReader: true);
            var trust = new ReceiptAttestationTrustStore([new(settings.DefinitionKeyId, publicKey)]);
            var proof = Read<IsoDefinitionProof>(settings.DefinitionPath); var intended = Read<IsoDefinitionSubject>(settings.DefinitionSubjectPath);
            // Full genuine reader gate before any fixture resource is created, not a signature-only shortcut.
            IsoDefinitionPrecursor.Require(definitionFiles, proof, intended, trust, settings.DefinitionKeyId, settings.DefinitionFingerprint, DateTimeOffset.UtcNow);
            var source = Read<FreshSchemaPlan>(settings.AcceptedSourcePath); var owners = Read<CurrentOwnerIsoSourceObservation[]>(settings.AcceptedOwnersPath);
            string sourceSha = CurrentAppOwnedRepairPermit.Hash(definitionFiles.Read(settings.AcceptedSourcePath, maximumBytes: 8_000_000, sharedReader: true));
            string ownerSha = CurrentAppOwnedRepairPermit.Hash(definitionFiles.Read(settings.AcceptedOwnersPath, maximumBytes: 8_000_000, sharedReader: true));
            byte[] catalog = definitionFiles.Read(settings.SourceCatalogPath, maximumBytes: 8_000_000, sharedReader: true);
            if (sourceSha != intended.RawSourceFileSha256 || SchemaPlanCanonicalizer.ComputeSha256(source) != intended.SourceSchemaPlanSha256 || ownerSha != intended.OwnerSourcesSha256 ||
                CurrentAppOwnedRepairPermit.Hash(catalog) != intended.SourceCatalogSha256 || source.SourceCommitSha != intended.SourceCommitSha)
            { throw Invalid(); }
            _ = CurrentOwnerIsoRepairSourceObservation.ReadCatalog(catalog, source, intended.SourceCatalogSha256, source.SourceCommitSha, DateTimeOffset.UtcNow);
            return new(authority, files, binding, intended, source, owners,
                CurrentAppOwnedRepairPermit.Hash(definitionFiles.Read(settings.DefinitionPath, maximumBytes: 8_000_000, sharedReader: true)), intended.SourceCatalogSha256, run, caseId);
        }
        catch { files?.Dispose(); authority.Dispose(); throw; }
    }
    internal Task RecordAsync(string phase, object actual, CancellationToken ct)
    {
        return phase.Length == 0 || phase.Any(x => !char.IsAsciiLetterOrDigit(x) && x != '-')
            ? throw Invalid()
            : _files.WriteNewAsync(_prefix + "-" + phase + ".json", JsonSerializer.SerializeToUtf8Bytes(actual, actual.GetType()), ct);
    }
    internal Task NativeAsync(string phase, CurrentOwnerIsoNativeObservation actual, CancellationToken ct)
    {
        return RecordAsync(phase, IsoCapturedNative.Capture(actual), ct);
    }

    internal Task FleetAsync(string phase, IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> actual, CancellationToken ct)
    {
        return _files.WriteBaselineNewAsync(_prefix + "-" + phase + ".json", actual.ToArray(), ct);
    }

    internal Task SlotAsync(string name, byte[] payload, bool acknowledged, CancellationToken ct)
    {
        return RecordAsync("slot-" + _slot++,
            new IsoActualReceiptSlot(name, Convert.ToBase64String(payload), acknowledged, DateTimeOffset.UtcNow), ct);
    }

    internal byte[] ReadHeld(string phase)
    {
        return _files.Read(_prefix + "-" + phase + ".json", maximumBytes: 32_000_000, sharedReader: true);
    }

    internal string[] OperationSlots()
    {
        _files.Require(); return Directory.EnumerateFileSystemEntries(Binding.ArtifactRootCanonicalPath)
        .Select(Path.GetFileName).Where(x => x is not null && x.StartsWith(RunId.ToString("D") + "-", StringComparison.Ordinal)).Select(x => x!).Order(StringComparer.Ordinal).ToArray();
    }
    internal Task RetainOperationAsync(string name, byte[] payload, CancellationToken ct)
    {
        return Path.GetFileName(name) != name || !name.StartsWith(RunId.ToString("D") + "-", StringComparison.Ordinal) ||
            !name.EndsWith(".json", StringComparison.Ordinal)
            ? throw Invalid()
            : _files.WriteNewAsync(Path.Combine(Binding.ArtifactRootCanonicalPath, name), payload, ct);
    }
    internal byte[] ReadOperation(string name)
    {
        return _files.Read(Path.Combine(Binding.ArtifactRootCanonicalPath, name), maximumBytes: 1_000_000, sharedReader: true);
    }

    internal void Capacity(bool admission) { CurrentOwnerIsoCapacity.Require(admission); _files.Require(); }
    public void Dispose() { _files.Dispose(); _authority.Dispose(); }
    private static MigrationExecutionException Invalid()
    {
        return CurrentOwnerIsoRepairPermit.Invalid();
    }
}
