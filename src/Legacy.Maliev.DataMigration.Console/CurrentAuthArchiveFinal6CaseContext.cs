using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveFinal6CaseInput(string Kind, CurrentAuthArchiveGenuineHostConfiguration Request,
    CurrentAuthArchiveProofArtifact OriginalSourceCapture, CurrentAuthArchiveProofArtifact Audience,
    CurrentAuthArchiveProofArtifact Definition, CurrentAuthArchiveFinal6DefinitionOwnerCopies DefinitionOwnerCopies,
    CurrentAuthArchiveProofArtifact SourceCredential, CurrentAuthArchiveProofArtifact CaseBinding);

// Constructed only after authentic new-domain case/definition readback and an independent actual SQL capture6.
// A deserialized packet or profile number is never a live source admission.
internal sealed class CurrentAuthArchiveFinal6CaseContext
{
    private readonly CurrentAuthArchiveRecoverySourceEvidence _original;
    private readonly CurrentAuthArchiveFinal6SourceCapture.Captured _current;
    private readonly CurrentAuthArchiveComponentBootstrapSeed _seed;
    private readonly string _seedSha256;
    private readonly string? _restoreSourceConnection;
    private readonly CurrentAuthArchivePins _pins;
    private readonly IReceiptAttestationTrustStore _trust;
    internal CurrentAuthArchiveProofCaseV2 Case { get; }
    internal CurrentAuthArchiveFreshDefinition NativeDefinition { get; }
    internal CurrentAuthArchiveFinal6SourceEvidence Original => new(CurrentAuthArchiveFinal6Source.Kind, _original);
    internal CurrentAuthArchiveGenuineHostConfiguration Request => Input.Request;
    internal Guid OperationId => _seed.OperationId;
    internal CurrentAuthArchiveFinal6SourceEvidence CurrentEvidence => _current.Evidence;
    internal CurrentAuthArchiveFinal6CaseInput Input { get; }
    internal CurrentAuthArchiveClaim AudienceClaim { get; }
    internal CurrentAuthArchiveClaim CaseClaim { get; }
    private CurrentAuthArchiveFinal6CaseContext(CurrentAuthArchiveFinal6CaseInput input, CurrentAuthArchiveRecoverySourceEvidence original,
        CurrentAuthArchiveFinal6SourceCapture.Captured current, CurrentAuthArchiveClaim audience, CurrentAuthArchiveClaim caseClaim,
        CurrentAuthArchiveComponentBootstrapSeed seed, CurrentAuthArchiveProofCaseV2 selected, CurrentAuthArchiveFreshDefinition definition,
        string? restoreSourceConnection, CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust)
    {
        Input = input; _original = original; _current = current; AudienceClaim = audience; CaseClaim = caseClaim; _seed = seed;
        _seedSha256 = CurrentAuthLocalSessionArchivePolicy.Hash(seed); Case = selected; NativeDefinition = definition;
        _restoreSourceConnection = restoreSourceConnection; _pins = pins; _trust = trust;
    }

    internal static async Task<CurrentAuthArchiveFinal6CaseContext> OpenAsync(string path, CurrentAuthArchiveProofCaseV2 expected, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); var identity = CurrentAuthArchiveGeneratedCasesV2.Identity(expected);
        if (System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly) { throw Invalid(); }
        byte[] original = CurrentAuthArchiveHelperHost.Read(path, 65536);
        var packet = Decode<CurrentAuthArchiveFinal6CaseInput>(original);
        CurrentAuthArchiveGenuineHost.RequireInput(packet.Request);
        if (packet.Kind != "current-auth-archive-final6-case-input-v1" || packet.Request.Phase != identity.Phase || packet.Request.CaseId != identity.CaseId ||
            packet.Request.Inputs.Scope is not null || Path.GetDirectoryName(path) != Path.GetDirectoryName(packet.Request.Inputs.ParentBinding.Path)) { throw Invalid(); }
        byte[] bindingBytes = CurrentAuthArchiveHelperHost.Read(packet.Request.Inputs.ParentBinding.Path, 65536);
        var binding = Decode<LocalExecutionBinding>(bindingBytes);
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        if (!files.Read(path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(original)) { throw Invalid(); }
        if (!Read(packet.Request.Inputs.ParentBinding, 65536).AsSpan().SequenceEqual(bindingBytes)) { throw Invalid(); }
        var pins = Decode<CurrentAuthArchivePins>(Read(packet.Request.Inputs.SigningPins, 65536));
        var trust = new ReceiptAttestationTrustStore(packet.Request.Inputs.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
            files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
        CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        var seed = Decode<CurrentAuthArchiveComponentBootstrapSeed>(Read(packet.Request.Inputs.ParentSeed, 65536));
        var source = Decode<CurrentAuthArchiveFinal6SourceEvidence>(Read(packet.OriginalSourceCapture, 32 * 1024 * 1024));
        var audience = Decode<CurrentAuthArchiveClaim>(Read(packet.Audience, 65536));
        var caseClaim = Decode<CurrentAuthArchiveClaim>(Read(packet.CaseBinding, 65536));
        _ = CurrentAuthArchiveFinal6CasePolicy.Require(caseClaim, audience, seed, source, packet.Definition.Sha256,
            identity.Phase, identity.CaseId, pins, trust, DateTimeOffset.UtcNow);
        if (seed.ParentRunBindingSha256 != binding.ComputeSha256() || packet.Request.Inputs.ParentSeed.Sha256 != CurrentAuthLocalSessionArchivePolicy.Hash(seed)) { throw Invalid(); }
        var signing = new CurrentAuthRepairSigningPins(pins.ReviewKeyId, pins.ReviewFingerprint, pins.AuthorizationKeyId,
            pins.AuthorizationFingerprint, pins.EvidenceKeyId, pins.EvidenceFingerprint);
        var definition = await CurrentAuthArchiveFinal6DefinitionReader.RequireCopiedAsync(files, packet.DefinitionOwnerCopies, packet.Definition,
            source, audience, signing, trust, DateTimeOffset.UtcNow, ct);
        if (seed.DefinitionPrecursorSha256 != definition.Definition.Sha256 || seed.PrecursorSubjectSha256 != definition.SubjectSha256 ||
            packet.Request.Inputs.PrecursorBinding != definition.RunBinding || packet.Request.Inputs.PrecursorScope != definition.CompletedScope ||
            packet.Request.Inputs.PrecursorSource != definition.Source || packet.Request.Inputs.DefinitionPrecursor != definition.Definition) { throw Invalid(); }
        byte[] credential = Read(packet.SourceCredential, 65536);
        CurrentAuthArchiveFinal6SourceCapture.Captured current; string connection;
        try
        {
            connection = new UTF8Encoding(false, true).GetString(credential);
            current = await CurrentAuthArchiveFinal6SourceCapture.Captured.CaptureAsync(connection, audience, pins, trust, ct);
        }
        finally { CryptographicOperations.ZeroMemory(credential); }
        var value = new CurrentAuthArchiveFinal6CaseContext(packet, source.Capture, current, audience, caseClaim, seed, expected,
            definition, identity.Phase == "recovery" ? connection : null, pins, trust);
        await value.RequireAsync(source.Capture.Plan, seed, pins, trust, ct); return value;

        byte[] Read(CurrentAuthArchiveProofArtifact artifact, int maximum)
        {
            byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: maximum);
            return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) == artifact.Sha256 ? bytes : throw Invalid();
        }
    }

    internal async Task RequireAsync(FreshSchemaPlan original, CurrentAuthArchiveComponentBootstrapSeed seed,
        CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (SchemaPlanCanonicalizer.ComputeSha256(original) != _original.FullPlanSha256 || CurrentAuthLocalSessionArchivePolicy.Hash(seed) != _seedSha256 ||
            CurrentAuthLocalSessionArchivePolicy.Hash(pins) != CurrentAuthLocalSessionArchivePolicy.Hash(_pins)) { throw Invalid(); }
        await _current.RequireAsync(ct);
        if (_seedSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(seed) || seed != _seed ||
            CurrentAuthLocalSessionArchivePolicy.Hash(pins) != CurrentAuthLocalSessionArchivePolicy.Hash(_pins) ||
            SchemaPlanCanonicalizer.ComputeSha256(original) != _original.FullPlanSha256 || _current.Evidence.Capture.DefinitionSha256 != _original.DefinitionSha256 ||
            _current.Evidence.Capture.SourceIdentitySha256 != _original.SourceIdentitySha256) { throw Invalid(); }
        var identity = CurrentAuthArchiveGeneratedCasesV2.Identity(Case);
        _ = CurrentAuthArchiveFinal6CasePolicy.Require(CaseClaim, AudienceClaim, seed, Original, Input.Definition.Sha256,
            identity.Phase, identity.CaseId, pins, trust, DateTimeOffset.UtcNow);
    }

    internal async Task<CurrentAuthArchiveFinal6SourceCapture.Captured> CaptureRestoreSourceAsync(CurrentAuthArchiveScope originalScope, CancellationToken ct)
    {
        if (Case is not (CurrentAuthArchiveProofCaseV2.FirstRestore or CurrentAuthArchiveProofCaseV2.SecondRestore) || _restoreSourceConnection is null) { throw Invalid(); }
        await RequireAsync(_original.Plan, _seed, _pins, _trust, ct);
        CurrentAuthArchiveComponentBootstrap.RequireClaims(originalScope, _trust, _pins, DateTimeOffset.UtcNow);
        return originalScope.ComponentSubject?.Seed != _seed
            ? throw Invalid()
            : await CurrentAuthArchiveFinal6SourceCapture.Captured.CaptureAsync(_restoreSourceConnection, AudienceClaim, _pins, _trust, ct);
    }
    internal void RequireEnvironmentScope(CurrentAuthArchiveScope scope, FreshSchemaPlan source)
    {
        CurrentAuthArchiveComponentBootstrap.RequireClaims(scope, _trust, _pins, DateTimeOffset.UtcNow);
        if (scope.ProofAdmission != CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap || scope.ComponentSubject?.Seed != _seed ||
            SchemaPlanCanonicalizer.ComputeSha256(source) != _original.FullPlanSha256 ||
            scope.LocalObservationPolicy.SourceSchemaPlanSha256 != _original.FullPlanSha256 || scope.ProductionObservationPolicy.SourceSchemaPlanSha256 != _original.FullPlanSha256)
        { throw Invalid(); }
    }
    internal async Task RequireFixtureAsync(FreshSchemaPlan source, Guid operation, bool comparison, IEnumerable<string> databases, CancellationToken ct)
    {
        if (operation != _seed.OperationId || !ReviewedProductionRepairInventory.MatchesKeys(
            CurrentAuthLocalSessionArchivePolicy.InventoryProfile(comparison), databases)) { throw Invalid(); }
        await RequireAsync(source, _seed, _pins, _trust, ct);
    }
    internal Task RequireFactoryAsync(CancellationToken ct)
    {
        return RequireAsync(_original.Plan, _seed, _pins, _trust, ct);
    }

    private static T Decode<T>(byte[] bytes)
    {
        return MigrationConsole.DecodeAuthRepair<T>(bytes);
    }

    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveFinal6Source.Invalid();
    }
}

internal sealed partial class CurrentAuthLocalSessionArchiveEnvironment
{
    private CurrentAuthArchiveFinal6CaseContext? _final6Case;
    internal void AttachFinal6Case(CurrentAuthArchiveFinal6CaseContext context)
    {
        if (_final6Case is not null || _persistentV2Baselines is not null || _reserved || _failed ||
            _scope.ProofAdmission != CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        context.RequireEnvironmentScope(_scope, _source); _final6Case = context;
    }
}
