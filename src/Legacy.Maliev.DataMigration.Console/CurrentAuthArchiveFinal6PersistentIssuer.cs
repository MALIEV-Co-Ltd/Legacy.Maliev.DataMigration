using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveFinal6PersistentConfiguration(string Kind, CurrentAuthArchiveProofArtifact ProofBinding,
    CurrentAuthArchiveFinal6ProofResult Proof, CurrentAuthArchiveProofArtifact Audience, CurrentAuthArchiveFinal6IntendedObservationInput Intended,
    CurrentAuthArchiveProofArtifact SourceCredential, CurrentAuthArchiveProofArtifact SigningPins, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    string ReviewPath, string AuthorizationPath, string EvidencePrivateKeyPath, string? ReviewPrivateKeyPath = null, string? AuthorizationPrivateKeyPath = null);

internal sealed class CurrentAuthArchiveFinal6PersistentIssuer : IDisposable
{
    private readonly CurrentAuthArchiveFinal6PersistentAttestation _binding;
    private readonly CurrentAppOwnedRepairCustody _proofFiles, _localFiles, _comparisonFiles;
    private readonly WindowsLocalRunAuthority _localAuthority, _comparisonAuthority;
    private readonly CurrentAuthLocalSessionArchiveEnvironment _environment;
    private readonly CurrentAuthArchiveAcceptedConsoleBundle _code;
    private readonly string _writer;
    private Guid _id;
    private int _minted;
    private bool _disposed;
    private CurrentAuthArchiveFinal6PersistentIssuer(CurrentAuthArchiveFinal6PersistentAttestation binding, CurrentAppOwnedRepairCustody proof,
        WindowsLocalRunAuthority localAuthority, WindowsLocalRunAuthority comparisonAuthority, CurrentAppOwnedRepairCustody local,
        CurrentAppOwnedRepairCustody comparison, CurrentAuthLocalSessionArchiveEnvironment environment,
        CurrentAuthArchiveAcceptedConsoleBundle code, string writer)
    {
        _binding = binding; _proofFiles = proof; _localAuthority = localAuthority; _comparisonAuthority = comparisonAuthority;
        _localFiles = local; _comparisonFiles = comparison; _environment = environment; _code = code; _writer = writer;
    }

    internal static async Task<CurrentAuthArchiveFinal6PersistentIssuer> OpenAsync(CurrentAuthArchiveFinal6PersistentConfiguration config,
        CurrentAppOwnedRepairCustody proofFiles, CancellationToken ct)
    {
        CurrentAuthArchiveClaim review, authorization; CurrentAuthArchivePins pins; ReceiptAttestationTrustStore trust;
        var localBinding = Binding(config.Intended.LocalBinding); var comparisonBinding = Binding(config.Intended.ComparisonBinding);
        using (var authority = WindowsLocalRunAuthority.AcquireResume(localBinding.ArtifactRootCanonicalPath, localBinding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            pins = Read<CurrentAuthArchivePins>(files, config.SigningPins); trust = Trust(files, config, pins);
            review = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(files.Read(config.ReviewPath, sharedReader: true, maximumBytes: 1024 * 1024));
            authorization = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(files.Read(config.AuthorizationPath, sharedReader: true, maximumBytes: 65536));
        }
        var intent = CurrentAuthArchiveFinal6PersistentPolicy.Claims(review, authorization, pins, trust, DateTimeOffset.UtcNow);
        if (intent.ProofSha256 != config.Proof.Proof.Sha256 || intent.FinalReadbackSha256 != config.Proof.FinalIntendedReadback.Sha256 ||
            intent.AudienceSha256 != config.Audience.Sha256) { throw Invalid(); }
        // Genuine proof and authentic current delete authorization precede source/target contact.
        await CurrentAuthArchiveFinal6ProofAssembly.RequirePublishedAsync(proofFiles, config.Proof, config.Audience, pins, trust, ct);
        var observed = await ObserveAsync(config, proofFiles, pins, trust, ct);
        RequireCurrent(intent, observed);
        var heldCode = await CurrentAuthArchiveAcceptedConsoleBundle.HoldAsync(typeof(MigrationConsole).Assembly.Location, ct);
        WindowsLocalRunAuthority? local = null, comparison = null;
        CurrentAppOwnedRepairCustody? localFiles = null, comparisonFiles = null;
        CurrentAuthLocalSessionArchiveEnvironment? environment = null;
        try
        {
            local = WindowsLocalRunAuthority.AcquireResume(localBinding.ArtifactRootCanonicalPath, localBinding);
            comparison = WindowsLocalRunAuthority.AcquireResume(comparisonBinding.ArtifactRootCanonicalPath, comparisonBinding);
            localFiles = new(local); comparisonFiles = new(comparison);
            var source = Read<CurrentAuthArchiveFinal6SourceEvidence>(localFiles, new(intent.SourceCapture.Path, intent.SourceCapture.Sha256), 32 * 1024 * 1024);
            CurrentAuthArchiveFinal6Source.Require(source, observed.Source.Evidence.Capture.Plan.SourceCommitSha, intent.SourceIdentitySha256, intent.SourceDefinitionSha256, DateTimeOffset.UtcNow);
            if (source.Capture.FullPlanSha256 != intent.Scope.LocalObservationPolicy.SourceSchemaPlanSha256) { throw Invalid(); }
            var audienceClaim = Read<CurrentAuthArchiveClaim>(proofFiles, config.Audience);
            var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Audience>(audienceClaim, CurrentAuthArchiveFinal6AudiencePolicy.Domain,
                pins.ReviewKeyId, pins.ReviewFingerprint, trust);
            _ = await CurrentAuthArchiveFinal6ProofAssembly.RequireIntendedAsync(localFiles, new(intent.CurrentIntendedObservation.Path, intent.CurrentIntendedObservation.Sha256),
                source, audience, DateTimeOffset.UtcNow, ct);
            var devices = Read<CurrentAuthArchiveDeviceProof>(localFiles, new(intent.DeviceProof.Path, intent.DeviceProof.Sha256));
            string writer = Text(localFiles, config.Intended.LocalOperator);
            environment = new(localFiles, comparisonFiles, local, comparison, intent.Scope, source.Capture.Plan,
                Read<CurrentAppOwnedRepairTargetPins>(localFiles, config.Intended.LocalTarget), Read<CurrentAppOwnedRepairTargetPins>(comparisonFiles, config.Intended.ComparisonTarget),
                writer, Text(comparisonFiles, config.Intended.ComparisonOperator), Text(localFiles, config.Intended.LocalOrdinary),
                Text(comparisonFiles, config.Intended.ComparisonOrdinary), devices, trust, pins, CurrentAuthLocalSessionArchivePolicy.Hash(authorization));
            environment.AttachFinal6PersistentBaselines(CurrentAuthArchiveFinal6PersistentBaselines.Create(review, authorization, pins, trust, observed.Targets));
            await environment.RequireAcceptedSourceOwnerCustodyAndTargetsAsync(intent.Scope, ct);
            return new(new(intent, review, authorization, pins, source.Capture.Plan, trust, environment), proofFiles, local, comparison,
                localFiles, comparisonFiles, environment, heldCode, new Npgsql.NpgsqlConnectionStringBuilder(writer) { Database = "Auth" }.ConnectionString);
        }
        catch (Exception primary)
        {
            var failures = new List<Exception> { primary };
            void Close(IDisposable? value) { try { value?.Dispose(); } catch (Exception failure) { failures.Add(failure); } }
            Close(environment); Close(comparisonFiles); Close(localFiles); Close(comparison); Close(local); Close(heldCode);
            if (failures.Count > 1) { throw new AggregateException("Persistent V2 admission and custody cleanup failed.", failures); }
            throw;
        }
    }
    internal async Task<CurrentAuthArchiveFinal6PersistentAttestation> MintFinal6PersistentAsync(Guid id, CancellationToken ct)
    {
        if (id == Guid.Empty || Interlocked.CompareExchange(ref _minted, 1, 0) != 0) { throw Invalid(); }
        _id = id; return await RequireFinal6PersistentAsync(id, ct);
    }
    internal Task<CurrentAuthArchiveFinal6PersistentAttestation> RequireFinal6PersistentAsync(Guid id, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (_disposed || id == Guid.Empty || id != _id || Volatile.Read(ref _minted) != 1) { throw Invalid(); }
        _code.Require(); _proofFiles.Require(); _localFiles.Require(); _comparisonFiles.Require();
        _localAuthority.ValidateHeld(); _comparisonAuthority.ValidateHeld();
        _ = CurrentAuthArchiveFinal6PersistentPolicy.Claims(_binding.Review, _binding.Authorization, _binding.Pins, _binding.Trust, DateTimeOffset.UtcNow);
        return Task.FromResult(_binding);
    }
    internal async Task<string> GetFinal6PersistentWriterAsync(Guid id, CancellationToken ct)
    { _ = await RequireFinal6PersistentAsync(id, ct); return _writer; }
    internal P256MigrationEvidenceSigner EvidenceSigner(string path)
    {
        byte[] bytes = _localFiles.Read(path, sharedReader: true, maximumBytes: 65536);
        try
        {
            var signer = new P256MigrationEvidenceSigner(_binding.Pins.EvidenceKeyId, Encoding.UTF8.GetString(bytes));
            if (signer.PublicKeyFingerprintSha256 == _binding.Pins.EvidenceFingerprint) { return signer; }
            signer.Dispose(); throw Invalid();
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal void RequireTerminal(CurrentAuthArchiveReceipt receipt)
    {
        _environment.RequireTerminal(receipt);
    }

    public void Dispose()
    {
        if (_disposed) { return; }
        _disposed = true;
        var failures = new List<Exception>();
        void Close(IDisposable value) { try { value.Dispose(); } catch (Exception failure) { failures.Add(failure); } }
        Close(_environment); Close(_comparisonFiles); Close(_localFiles); Close(_comparisonAuthority); Close(_localAuthority); Close(_code);
        if (failures.Count != 0) { throw new AggregateException("Persistent V2 custody cleanup failed; recovery files and journals were retained.", failures); }
    }
    internal sealed record Observation(CurrentAuthArchiveFinal6SourceCapture.Captured Source, CurrentAuthArchiveFinal6IntendedObservationRuntime Targets,
        CurrentAuthArchiveFinal6FinalReadback Final, CurrentAuthArchivePins Pins, ReceiptAttestationTrustStore Trust);
    internal static async Task<Observation> ObserveAsync(CurrentAuthArchiveFinal6PersistentConfiguration config, CurrentAppOwnedRepairCustody proofFiles,
        CurrentAuthArchivePins pins, ReceiptAttestationTrustStore trust, CancellationToken ct)
    {
        var audienceClaim = Read<CurrentAuthArchiveClaim>(proofFiles, config.Audience);
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Audience>(audienceClaim, CurrentAuthArchiveFinal6AudiencePolicy.Domain,
            pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        var finalClaim = Read<CurrentAuthArchiveClaim>(proofFiles, config.Proof.FinalIntendedReadback);
        var final = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6FinalReadback>(finalClaim, CurrentAuthArchiveFinal6ProofAssembly.IntendedDomain,
            pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        byte[] credential;
        var binding = Binding(config.Intended.LocalBinding);
        using (var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority)) { credential = Bytes(files, config.SourceCredential, 65536); }
        CurrentAuthArchiveFinal6SourceCapture.Captured source;
        try { source = await CurrentAuthArchiveFinal6SourceCapture.Captured.CaptureAsync(Encoding.UTF8.GetString(credential), audienceClaim, pins, trust, ct); }
        finally { CryptographicOperations.ZeroMemory(credential); }
        var targets = await CurrentAuthArchiveFinal6IntendedObservationRuntime.ObserveAsync(config.Intended, source, audienceClaim, trust, pins, ct);
        var finalSource = Read<CurrentAuthArchiveFinal6SourceEvidence>(proofFiles, final.CurrentSourceCapture, 32 * 1024 * 1024);
        var previous = await CurrentAuthArchiveFinal6ProofAssembly.RequireIntendedAsync(proofFiles, final.CurrentIntendedObservation, finalSource, audience, final.ObservedAtUtc, ct);
        foreach (bool comparison in new[] { false, true })
        {
            var retained = comparison ? previous.Comparison : previous.Local; var actual = comparison ? targets.Comparison : targets.Local;
            var baseline = await CurrentAuthArchiveStreamedBaselineV2.ReadAsync(proofFiles, retained.Databases, ct);
            var native = Read<CurrentAuthArchiveNativeCommitmentV2>(proofFiles, new(retained.Native.Path, retained.Native.Sha256), 32 * 1024 * 1024); native.Require();
            if (baseline.Length != actual.Databases.Count || baseline.Any(item => actual.Databases.Single(other => other.Database == item.Database).Sha256 != item.Sha256) ||
                native.NativeSha256 != CurrentAuthArchiveRecoveryV2Preservation.NativeSha(actual.Auth.Native)) { throw Invalid(); }
        }
        return DateTimeOffset.UtcNow >= final.ExpiresAtUtc ? throw Invalid() : new(source, targets, final, pins, trust);
    }
    internal static void RequireCurrent(CurrentAuthArchiveFinal6PersistentIntent intent, Observation observed)
    {
        CurrentAuthArchiveFinal6PersistentPolicy.RequireIntent(intent, DateTimeOffset.UtcNow);
        var current = observed.Targets.Evidence;
        if (intent.SourceIdentitySha256 != observed.Source.Evidence.Capture.SourceIdentitySha256 || intent.SourceDefinitionSha256 != observed.Source.Evidence.Capture.DefinitionSha256 ||
            CurrentAuthArchiveFinal6IntendedObservationRuntime.Identity(intent.Scope.LocalObservationPolicy) != current.LocalIdentitySha256 ||
            CurrentAuthArchiveFinal6IntendedObservationRuntime.Identity(intent.Scope.ProductionObservationPolicy) != current.ComparisonIdentitySha256 ||
            intent.Scope.DeleteSetSha256 != current.LocalAuthRowsSha256 || intent.Scope.DeleteCount != current.LocalAuthRows ||
            intent.Scope.ExpiresAtUtc > observed.Final.ExpiresAtUtc) { throw Invalid(); }
        CurrentAuthArchiveFinal6PersistentPolicy.RequireFleets(intent, observed.Targets.Local, observed.Targets.Comparison);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(observed.Targets.Local, intent.Scope.LocalObservationPolicy, DateTimeOffset.UtcNow);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(observed.Targets.Comparison, intent.Scope.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
        if (CurrentAuthLocalSessionArchivePolicy.RequireComparison(observed.Targets.Local.Auth, observed.Targets.Comparison.Auth) != intent.Scope.ApplicationComparisonSha256)
        { throw Invalid(); }
    }
    internal static LocalExecutionBinding Binding(CurrentAuthArchiveProofArtifact reference)
    {
        byte[] bytes = CurrentAuthArchiveHelperHost.Read(reference.Path, 65536);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != reference.Sha256) { throw Invalid(); }
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(bytes);
        return Path.GetDirectoryName(reference.Path) != binding.ArtifactRootCanonicalPath ? throw Invalid() : binding;
    }
    internal static ReceiptAttestationTrustStore Trust(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveFinal6PersistentConfiguration config, CurrentAuthArchivePins pins)
    {
        var trust = new ReceiptAttestationTrustStore(config.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
            files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
        CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust); return trust;
    }
    internal static T Read<T>(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofArtifact reference, int maximum = 1024 * 1024)
    {
        return MigrationConsole.DecodeAuthRepair<T>(Bytes(files, reference, maximum));
    }

    private static byte[] Bytes(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofArtifact reference, int maximum)
    { byte[] bytes = files.Read(reference.Path, sharedReader: true, maximumBytes: maximum); return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) == reference.Sha256 ? bytes : throw Invalid(); }
    private static string Text(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofArtifact reference)
    {
        return Encoding.UTF8.GetString(Bytes(files, reference, 65536)).Trim();
    }

    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveFinal6PersistentPolicy.Invalid();
    }
}
