using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchivePersistentV2Configuration(string Kind, CurrentAuthArchiveProofArtifact ProofBinding,
    CurrentAuthArchiveProofAssemblyResultV2 Proof, CurrentAuthArchiveProofArtifact Audience, CurrentAuthArchiveIntendedObservationInputV2 Intended,
    CurrentAuthArchiveProofArtifact SourceCredential, CurrentAuthArchiveProofArtifact SigningPins, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    string ReviewPath, string AuthorizationPath, string EvidencePrivateKeyPath, string? ReviewPrivateKeyPath = null, string? AuthorizationPrivateKeyPath = null);

internal sealed class CurrentAuthArchivePersistentV2Issuer : IDisposable
{
    private readonly CurrentAuthArchivePersistentAttestationV2 _binding;
    private readonly CurrentAppOwnedRepairCustody _proofFiles, _localFiles, _comparisonFiles;
    private readonly WindowsLocalRunAuthority _localAuthority, _comparisonAuthority;
    private readonly CurrentAuthLocalSessionArchiveEnvironment _environment;
    private readonly CurrentAuthArchiveAcceptedConsoleBundle _code;
    private readonly string _writer;
    private Guid _id;
    private int _minted;
    private bool _disposed;
    private CurrentAuthArchivePersistentV2Issuer(CurrentAuthArchivePersistentAttestationV2 binding, CurrentAppOwnedRepairCustody proof,
        WindowsLocalRunAuthority localAuthority, WindowsLocalRunAuthority comparisonAuthority, CurrentAppOwnedRepairCustody local,
        CurrentAppOwnedRepairCustody comparison, CurrentAuthLocalSessionArchiveEnvironment environment,
        CurrentAuthArchiveAcceptedConsoleBundle code, string writer)
    {
        _binding = binding; _proofFiles = proof; _localAuthority = localAuthority; _comparisonAuthority = comparisonAuthority;
        _localFiles = local; _comparisonFiles = comparison; _environment = environment; _code = code; _writer = writer;
    }

    internal static async Task<CurrentAuthArchivePersistentV2Issuer> OpenAsync(CurrentAuthArchivePersistentV2Configuration config,
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
        var intent = CurrentAuthArchivePersistentV2Policy.Claims(review, authorization, pins, trust, DateTimeOffset.UtcNow);
        if (intent.ProofSha256 != config.Proof.Proof.Sha256 || intent.FinalReadbackSha256 != config.Proof.FinalIntendedReadback.Sha256 ||
            intent.AudienceSha256 != config.Audience.Sha256) { throw Invalid(); }
        // Genuine proof and authentic current delete authorization precede source/target contact.
        await CurrentAuthArchiveProofAssemblyV2.RequirePublishedAsync(proofFiles, config.Proof, config.Audience, pins, trust, ct);
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
            var source = Read<CurrentAuthArchiveRecoverySourceEvidence>(localFiles, new(intent.SourceCapture.Path, intent.SourceCapture.Sha256), 32 * 1024 * 1024);
            CurrentAuthArchiveRecoveryV2.RequireSource(source, observed.Source.Evidence.Plan.SourceCommitSha, intent.SourceIdentitySha256, intent.SourceDefinitionSha256, DateTimeOffset.UtcNow);
            if (source.FullPlanSha256 != intent.Scope.LocalObservationPolicy.SourceSchemaPlanSha256) { throw Invalid(); }
            var audienceClaim = Read<CurrentAuthArchiveClaim>(proofFiles, config.Audience);
            var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveProofAudienceV2>(audienceClaim, CurrentAuthArchiveRecoveryV2.AudienceDomain,
                pins.ReviewKeyId, pins.ReviewFingerprint, trust);
            _ = await CurrentAuthArchiveProofAssemblyV2.RequireIntendedAsync(localFiles, new(intent.CurrentIntendedObservation.Path, intent.CurrentIntendedObservation.Sha256),
                source, audience, DateTimeOffset.UtcNow, ct);
            var devices = Read<CurrentAuthArchiveDeviceProof>(localFiles, new(intent.DeviceProof.Path, intent.DeviceProof.Sha256));
            string writer = Text(localFiles, config.Intended.LocalOperator);
            environment = new(localFiles, comparisonFiles, local, comparison, intent.Scope, source.Plan,
                Read<CurrentAppOwnedRepairTargetPins>(localFiles, config.Intended.LocalTarget), Read<CurrentAppOwnedRepairTargetPins>(comparisonFiles, config.Intended.ComparisonTarget),
                writer, Text(comparisonFiles, config.Intended.ComparisonOperator), Text(localFiles, config.Intended.LocalOrdinary),
                Text(comparisonFiles, config.Intended.ComparisonOrdinary), devices, trust, pins, CurrentAuthLocalSessionArchivePolicy.Hash(authorization));
            environment.AttachPersistentV2Baselines(CurrentAuthArchivePersistentV2Baselines.Create(review, authorization, pins, trust, observed.Targets));
            await environment.RequireAcceptedSourceOwnerCustodyAndTargetsAsync(intent.Scope, ct);
            return new(new(intent, review, authorization, pins, source.Plan, trust, environment), proofFiles, local, comparison,
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
    internal async Task<CurrentAuthArchivePersistentAttestationV2> MintPersistentV2Async(Guid id, CancellationToken ct)
    {
        if (id == Guid.Empty || Interlocked.CompareExchange(ref _minted, 1, 0) != 0) { throw Invalid(); }
        _id = id; return await RequirePersistentV2Async(id, ct);
    }
    internal Task<CurrentAuthArchivePersistentAttestationV2> RequirePersistentV2Async(Guid id, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (_disposed || id == Guid.Empty || id != _id || Volatile.Read(ref _minted) != 1) { throw Invalid(); }
        _code.Require(); _proofFiles.Require(); _localFiles.Require(); _comparisonFiles.Require();
        _localAuthority.ValidateHeld(); _comparisonAuthority.ValidateHeld();
        _ = CurrentAuthArchivePersistentV2Policy.Claims(_binding.Review, _binding.Authorization, _binding.Pins, _binding.Trust, DateTimeOffset.UtcNow);
        return Task.FromResult(_binding);
    }
    internal async Task<string> GetPersistentV2WriterAsync(Guid id, CancellationToken ct)
    { _ = await RequirePersistentV2Async(id, ct); return _writer; }
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
    internal sealed record Observation(CurrentReviewedCapture Source, CurrentAuthArchiveIntendedObservationRuntimeV2 Targets,
        CurrentAuthArchiveFinalIntendedReadbackV2 Final, CurrentAuthArchivePins Pins, ReceiptAttestationTrustStore Trust);
    internal static async Task<Observation> ObserveAsync(CurrentAuthArchivePersistentV2Configuration config, CurrentAppOwnedRepairCustody proofFiles,
        CurrentAuthArchivePins pins, ReceiptAttestationTrustStore trust, CancellationToken ct)
    {
        var audienceClaim = Read<CurrentAuthArchiveClaim>(proofFiles, config.Audience);
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveProofAudienceV2>(audienceClaim, CurrentAuthArchiveRecoveryV2.AudienceDomain,
            pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        var finalClaim = Read<CurrentAuthArchiveClaim>(proofFiles, config.Proof.FinalIntendedReadback);
        var final = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinalIntendedReadbackV2>(finalClaim, CurrentAuthArchiveProofAssemblyV2.IntendedDomain,
            pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        byte[] credential;
        var binding = Binding(config.Intended.LocalBinding);
        using (var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority)) { credential = Bytes(files, config.SourceCredential, 65536); }
        CurrentReviewedCapture source;
        try { source = await CurrentReviewedCapture.CaptureAsync(Encoding.UTF8.GetString(credential), audience, ct); }
        finally { CryptographicOperations.ZeroMemory(credential); }
        var targets = await CurrentAuthArchiveIntendedObservationRuntimeV2.ObserveAsync(config.Intended, source, audienceClaim, trust, pins, ct);
        var finalSource = Read<CurrentAuthArchiveRecoverySourceEvidence>(proofFiles, final.CurrentSourceCapture, 32 * 1024 * 1024);
        var previous = await CurrentAuthArchiveProofAssemblyV2.RequireIntendedAsync(proofFiles, final.CurrentIntendedObservation, finalSource, audience, final.ObservedAtUtc, ct);
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
    internal static void RequireCurrent(CurrentAuthArchivePersistentIntentV2 intent, Observation observed)
    {
        CurrentAuthArchivePersistentV2Policy.RequireIntent(intent, DateTimeOffset.UtcNow);
        var current = observed.Targets.Evidence;
        if (intent.SourceIdentitySha256 != observed.Source.Evidence.SourceIdentitySha256 || intent.SourceDefinitionSha256 != observed.Source.Evidence.DefinitionSha256 ||
            CurrentAuthArchiveIntendedObservationRuntimeV2.Identity(intent.Scope.LocalObservationPolicy) != current.LocalIdentitySha256 ||
            CurrentAuthArchiveIntendedObservationRuntimeV2.Identity(intent.Scope.ProductionObservationPolicy) != current.ComparisonIdentitySha256 ||
            intent.Scope.DeleteSetSha256 != current.LocalAuthRowsSha256 || intent.Scope.DeleteCount != current.LocalAuthRows ||
            intent.Scope.ExpiresAtUtc > observed.Final.ExpiresAtUtc) { throw Invalid(); }
        CurrentAuthArchivePersistentV2Policy.RequireFleets(intent, observed.Targets.Local, observed.Targets.Comparison);
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
    internal static ReceiptAttestationTrustStore Trust(CurrentAppOwnedRepairCustody files, CurrentAuthArchivePersistentV2Configuration config, CurrentAuthArchivePins pins)
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
        return CurrentAuthArchivePersistentV2Policy.Invalid();
    }
}
