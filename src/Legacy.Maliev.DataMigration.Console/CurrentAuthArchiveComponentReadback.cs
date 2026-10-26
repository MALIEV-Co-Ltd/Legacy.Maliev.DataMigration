using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

// PrecursorScope is a NEW derived artifact setting AuthHelperProofSha256 to the actual helper report hash.
// Preserve the immutable original scope. Change no subject operand: the genuine helper's signed Subject excludes proof digests.
internal sealed record CurrentAuthArchiveComponentReadbackInput(
    CurrentAuthArchiveProofArtifact ParentBinding, CurrentAuthArchiveProofArtifact ParentSeed,
    CurrentAuthArchiveProofArtifact Scope, CurrentAuthArchiveProofArtifact Source,
    CurrentAuthArchiveProofArtifact SigningPins, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    CurrentAuthArchiveProofArtifact TestImage, CurrentAuthArchiveProofArtifact ConsoleImage, CurrentAuthArchiveProofArtifact CoreImage,
    CurrentAuthArchiveProofArtifact PrecursorBinding, CurrentAuthArchiveProofArtifact PrecursorScope,
    CurrentAuthArchiveProofArtifact PrecursorSource, CurrentAuthArchiveProofArtifact PrecursorSigningPins,
    IReadOnlyList<DeltaTrustedKeyReference> PrecursorTrustedKeys, CurrentAuthArchiveProofArtifact DefinitionPrecursor);

// Holds authenticated inputs only. No paired target, policy or physical-device observation is supplied by this reader.
internal sealed class CurrentAuthArchiveComponentReadback : IDisposable
{
    private readonly CurrentAuthArchiveComponentReadbackInput _input;
    private readonly WindowsLocalRunAuthority _parent, _precursor;
    private readonly CurrentAppOwnedRepairCustody _parentFiles, _precursorFiles;
    private readonly List<(FileStream Stream, string Path, string Identity, string Hash)> _images = [];
    private readonly CurrentAuthArchiveScope _scope;
    private readonly CurrentAuthArchiveComponentBootstrapSeed _seed;
    private readonly CurrentAuthArchivePins _pins;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly FreshSchemaPlan _source;
    private readonly CurrentAuthRepairScope _precursorScope;
    private readonly CurrentAuthRepairSigningPins _precursorPins;
    private readonly IReceiptAttestationTrustStore _precursorTrust;
    private bool _disposed;

    internal string AcceptedSourceCommitSha => _seed.AcceptedSourceCommitSha;
    internal string SourceSchemaPlanSha256 => _seed.SourceSchemaPlanSha256;
    internal string ParentRunBindingSha256 => _parent.Binding.ComputeSha256();
    internal string TestAssemblySha256 => _seed.TestAssemblySha256;
    internal string ConsoleAssemblySha256 => _seed.ConsoleAssemblySha256;
    internal string CoreAssemblySha256 => _seed.CoreAssemblySha256;

    internal async Task<CurrentAuthArchiveComponentBootstrapSeed> ReadSeedAsync(CancellationToken ct)
    {
        await RequireAsync(ct).ConfigureAwait(false); return _seed;
    }

    private CurrentAuthArchiveComponentReadback(CurrentAuthArchiveComponentReadbackInput input,
        WindowsLocalRunAuthority parent, CurrentAppOwnedRepairCustody parentFiles,
        WindowsLocalRunAuthority precursor, CurrentAppOwnedRepairCustody precursorFiles)
    {
        _input = input; _parent = parent; _parentFiles = parentFiles; _precursor = precursor; _precursorFiles = precursorFiles;
        _scope = Decode<CurrentAuthArchiveScope>(Read(parentFiles, input.Scope));
        _seed = Decode<CurrentAuthArchiveComponentBootstrapSeed>(Read(parentFiles, input.ParentSeed));
        _pins = Decode<CurrentAuthArchivePins>(Read(parentFiles, input.SigningPins));
        _trust = Trust(parentFiles, input.TrustedKeys);
        RequireAuthenticatedClaims(_scope, _seed, _pins, _trust, DateTimeOffset.UtcNow);
        _source = Decode<FreshSchemaPlan>(Read(parentFiles, input.Source));
        _precursorScope = Decode<CurrentAuthRepairScope>(Read(precursorFiles, input.PrecursorScope));
        _precursorPins = Decode<CurrentAuthRepairSigningPins>(Read(precursorFiles, input.PrecursorSigningPins));
        _precursorTrust = Trust(precursorFiles, input.PrecursorTrustedKeys);
        RequirePinnedKeys(input.PrecursorTrustedKeys, _precursorTrust,
            [_precursorPins.ReviewKeyId, _precursorPins.AuthorizationKeyId, _precursorPins.ReceiptKeyId],
            [_precursorPins.ReviewFingerprint, _precursorPins.AuthorizationFingerprint, _precursorPins.ReceiptFingerprint]);
    }

    internal static async Task<CurrentAuthArchiveComponentReadback> OpenAsync(CurrentAuthArchiveComponentReadbackInput input, CancellationToken ct)
    {
        RequireInput(input);
        CurrentAuthArchiveCapacity.Require(admission: true);
        WindowsLocalRunAuthority? parent = null, precursor = null;
        CurrentAppOwnedRepairCustody? parentFiles = null, precursorFiles = null;
        CurrentAuthArchiveComponentReadback? result = null;
        try
        {
            (parent, parentFiles) = Resume(input.ParentBinding);
            (precursor, precursorFiles) = Resume(input.PrecursorBinding);
            if (parent.Binding.ComputeSha256() == precursor.Binding.ComputeSha256() ||
                string.Equals(parent.Binding.ArtifactRootCanonicalPath, precursor.Binding.ArtifactRootCanonicalPath, StringComparison.OrdinalIgnoreCase)) { throw Invalid(); }
            result = new(input, parent, parentFiles, precursor, precursorFiles);
            result.HoldImage(input.ConsoleImage, typeof(MigrationConsole).Assembly);
            result.HoldImage(input.CoreImage, typeof(CurrentAuthLocalSessionArchivePermit).Assembly);
            Assembly[] tests = AppDomain.CurrentDomain.GetAssemblies().Where(x => x.GetName().Name == "Legacy.Maliev.DataMigration.Tests").ToArray();
            if (tests.Length != 1) { throw Invalid(); }
            result.HoldImage(input.TestImage, tests[0]);
            await result.RequireAsync(ct).ConfigureAwait(false);
            return result;
        }
        catch
        {
            if (result is not null) { result.Dispose(); }
            else { DisposeRoots(parent, parentFiles, precursor, precursorFiles); }
            throw;
        }
    }

    internal async Task RequireAsync(CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        CurrentAuthArchiveCapacity.Require(admission: false);
        _parentFiles.Require(); _precursorFiles.Require();
        RequireAuthenticatedClaims(_scope, _seed, _pins, _trust, DateTimeOffset.UtcNow);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        TimeSpan remaining = _scope.ExpiresAtUtc - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero) { throw Invalid(); }
        deadline.CancelAfter(remaining); ct = deadline.Token;
        foreach (var image in _images)
        {
            if (SecureLocalFile.GetHandleIdentity(image.Stream) != image.Identity ||
                !SecureLocalFile.HandleResolvesToApprovedPath(image.Stream, image.Path) || HashImage(image.Stream) != image.Hash) { throw Invalid(); }
        }
        if (_images.Count != 3 || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != _seed.AcceptedSourceCommitSha ||
            _parent.Binding.ComputeSha256() != _seed.ParentRunBindingSha256) { throw Invalid(); }
        ProductionSchemaCatalogInspector.ValidatePlan(_source, DateTimeOffset.UtcNow);
        if (_source.SourceCommitSha != _seed.AcceptedSourceCommitSha || SchemaPlanCanonicalizer.ComputeSha256(_source) != _seed.SourceSchemaPlanSha256 ||
            !ApprovedConsumerOverlaySelection.IsApproved(_source) || _source.Databases.Sum(x => x.Tables.Count) != 100 ||
            !_source.Databases.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases.Order(StringComparer.Ordinal)) ||
            _source.Databases.Any(x => x.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(x.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3)) ||
            _source.Databases.Single(x => x.Database == "Quotation").SourceDispositionProfile != ApprovedSourceDispositionManifest.QuotationOutboxesV1 ||
            _source.CapturedAtUtc.Offset != TimeSpan.Zero || _source.CapturedAtUtc > _scope.CapturedAtUtc ||
            DateTimeOffset.UtcNow - _source.CapturedAtUtc > TimeSpan.FromMinutes(5)) { throw Invalid(); }
        var precursorSource = Decode<FreshSchemaPlan>(Read(_precursorFiles, _input.PrecursorSource));
        RequirePrecursorBinding(_precursorScope, _seed, _precursor.Binding.ComputeSha256(), SchemaPlanCanonicalizer.ComputeSha256(precursorSource), _input.DefinitionPrecursor.Sha256);
        await CurrentAuthOwnerSourceReader.RequireAsync(ObserveOwnerAsync, ct).ConfigureAwait(false);
        await CurrentAuthRepairProofReader.RequireAsync(_precursorFiles, new(_input.DefinitionPrecursor.Path, _input.DefinitionPrecursor.Sha256),
            _seed.DefinitionPrecursorSha256, "helper", _precursorScope, _precursorTrust, _precursorPins, precursorSource, ct).ConfigureAwait(false);
        var report = Decode<CurrentAuthClosedProof>(Read(_precursorFiles, _input.DefinitionPrecursor));
        if (report.Cases.Any(x => x.Invocation.TestAssemblySha256 != _seed.TestAssemblySha256) ||
            report.ConsoleAssemblySha256 != _seed.ConsoleAssemblySha256 || report.CoreAssemblySha256 != _seed.CoreAssemblySha256) { throw Invalid(); }
        await CurrentAuthOwnerSourceReader.RequireAsync(ObserveOwnerAsync, ct).ConfigureAwait(false);
        // Reclose accepted-main/bundle and source/lease freshness after the independent precursor readback.
        if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != _seed.AcceptedSourceCommitSha) { throw Invalid(); }
        RequireAuthenticatedClaims(_scope, _seed, _pins, _trust, DateTimeOffset.UtcNow);
        if (DateTimeOffset.UtcNow - _source.CapturedAtUtc > TimeSpan.FromMinutes(5)) { throw Invalid(); }
        _parentFiles.Require(); _precursorFiles.Require();
        ct.ThrowIfCancellationRequested();
    }

    internal static void RequireAuthenticatedClaims(CurrentAuthArchiveScope scope, CurrentAuthArchiveComponentBootstrapSeed heldSeed,
        CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        CurrentAuthArchiveComponentBootstrap.RequireClaims(scope, trust, pins, now);
        if (scope.ComponentSubject!.Seed != heldSeed) { throw Invalid(); }
    }

    private async Task ObserveOwnerAsync(CurrentAuthGitResource resource)
    {
        // Cleanup frames must still be retained when the calling operation has expired or cancelled.
        using var retention = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        string path = Path.Combine(_parent.Binding.ArtifactRootCanonicalPath, $"archive-component-readback-owner-{Guid.NewGuid():N}.json");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(resource);
        await _parentFiles.WriteNewAsync(path, bytes, retention.Token).ConfigureAwait(false);
        if (!_parentFiles.Read(path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw Invalid(); }
    }

    internal static void RequirePrecursorBinding(CurrentAuthRepairScope precursor, CurrentAuthArchiveComponentBootstrapSeed seed,
        string actualBinding, string actualSourcePlan, string heldProofHash)
    {
        if (precursor.ProofAdmission != CurrentAuthProofAdmission.DisposableNativeBootstrap || precursor.RunBindingSha256 != actualBinding ||
            precursor.SourceCommitSha != seed.AcceptedSourceCommitSha || precursor.SourceSchemaPlanSha256 != seed.SourceSchemaPlanSha256 ||
            actualSourcePlan != seed.SourceSchemaPlanSha256 || precursor.AuthOwnerCommitSha != seed.AuthOwnerCommitSha ||
            precursor.AuthOwnerSourcePinsSha256 != seed.OwnerPinsSha256 || precursor.AuthClosureSha256 != seed.ClosureSha256 ||
            CurrentAuthRepairProofReader.Subject(precursor) != seed.PrecursorSubjectSha256 ||
            precursor.AuthHelperProofSha256 != heldProofHash || heldProofHash != seed.DefinitionPrecursorSha256) { throw Invalid(); }
    }

    internal static void RequireArtifactBytes(byte[] bytes, string expectedHash)
    {
        if (bytes.Length is < 1 or > 32 * 1024 * 1024 || !HashShape(expectedHash) ||
            CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != expectedHash) { throw Invalid(); }
    }

    internal static void RequireInput(CurrentAuthArchiveComponentReadbackInput input)
    {
        if (input is null || input.TrustedKeys is null || input.PrecursorTrustedKeys is null) { throw Invalid(); }
        CurrentAuthArchiveProofArtifact[] artifacts = [input.ParentBinding, input.ParentSeed, input.Scope, input.Source, input.SigningPins,
            input.TestImage, input.ConsoleImage, input.CoreImage, input.PrecursorBinding, input.PrecursorScope, input.PrecursorSource,
            input.PrecursorSigningPins, input.DefinitionPrecursor];
        if (artifacts.Any(x => x is null || !Canonical(x.Path) || !HashShape(x.Sha256)) ||
            artifacts.Select(x => x.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != artifacts.Length ||
            new[] { input.TrustedKeys, input.PrecursorTrustedKeys }.Any(keys => keys.Count != 3 ||
                keys.Any(x => x is null || string.IsNullOrWhiteSpace(x.KeyId) || !Canonical(x.SubjectPublicKeyInfoPath)) ||
                keys.Select(x => x.KeyId).Distinct(StringComparer.Ordinal).Count() != 3 ||
                keys.Select(x => x.SubjectPublicKeyInfoPath).Distinct(StringComparer.OrdinalIgnoreCase).Count() != 3)) { throw Invalid(); }
    }

    private static (WindowsLocalRunAuthority, CurrentAppOwnedRepairCustody) Resume(CurrentAuthArchiveProofArtifact artifact)
    {
        using var initial = SecureLocalFile.OpenReadShared(artifact.Path);
        if (initial.Length is < 1 or > 65536) { throw Invalid(); }
        string identity = SecureLocalFile.GetHandleIdentity(initial);
        byte[] bytes = new byte[checked((int)initial.Length)]; initial.ReadExactly(bytes);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != artifact.Sha256) { throw Invalid(); }
        var binding = Decode<LocalExecutionBinding>(bytes);
        if (!string.Equals(artifact.Path, Path.Combine(binding.ArtifactRootCanonicalPath, Path.GetFileName(artifact.Path)), StringComparison.OrdinalIgnoreCase)) { throw Invalid(); }
        var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        var files = new CurrentAppOwnedRepairCustody(authority);
        try
        {
            if (!Read(files, artifact).AsSpan().SequenceEqual(bytes) || SecureLocalFile.GetHandleIdentity(initial) != identity) { throw Invalid(); }
            return (authority, files);
        }
        catch { try { files.Dispose(); } finally { authority.Dispose(); } throw; }
    }

    private void HoldImage(CurrentAuthArchiveProofArtifact artifact, Assembly assembly)
    {
        string path = Path.GetFullPath(assembly.Location);
        var stream = SecureLocalFile.OpenReadShared(path);
        try
        {
            string hash = HashImage(stream);
            if (!SecureLocalFile.HandleResolvesToApprovedPath(stream, path) ||
                HashImage(_parentFiles.BorrowReadStream(artifact.Path, 128 * 1024 * 1024)) != artifact.Sha256 || hash != artifact.Sha256 ||
                hash != (assembly == typeof(MigrationConsole).Assembly ? _seed.ConsoleAssemblySha256 :
                    assembly == typeof(CurrentAuthLocalSessionArchivePermit).Assembly ? _seed.CoreAssemblySha256 : _seed.TestAssemblySha256)) { throw Invalid(); }
            _images.Add((stream, path, SecureLocalFile.GetHandleIdentity(stream), hash));
        }
        catch { stream.Dispose(); throw; }
    }

    private static ReceiptAttestationTrustStore Trust(CurrentAppOwnedRepairCustody files, IReadOnlyList<DeltaTrustedKeyReference> keys)
    {
        return new(keys.Select(x => new TrustedAttestationKey(x.KeyId, files.Read(x.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))).ToArray());
    }
    private static void RequirePinnedKeys(IReadOnlyList<DeltaTrustedKeyReference> keys, IReceiptAttestationTrustStore trust,
        string[] ids, string[] fingerprints)
    {
        if (ids.Any(string.IsNullOrWhiteSpace) || ids.Distinct(StringComparer.Ordinal).Count() != 3 ||
            fingerprints.Any(x => !HashShape(x)) || fingerprints.Distinct(StringComparer.Ordinal).Count() != 3 ||
            !keys.Select(x => x.KeyId).Order(StringComparer.Ordinal).SequenceEqual(ids.Order(StringComparer.Ordinal))) { throw Invalid(); }
        for (int i = 0; i < ids.Length; i++)
        { if (!trust.TryGetPublicKeyFingerprintSha256(ids[i], out string actual) || actual != fingerprints[i]) { throw Invalid(); } }
    }
    private static byte[] Read(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofArtifact artifact)
    {
        byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: 32 * 1024 * 1024);
        RequireArtifactBytes(bytes, artifact.Sha256); return bytes;
    }
    private static T Decode<T>(byte[] bytes) { return MigrationConsole.DecodeAuthRepair<T>(bytes); }
    private static string HashImage(FileStream stream)
    {
        if (stream.Length is < 1 or > 128 * 1024 * 1024) { throw Invalid(); }
        stream.Position = 0; string hash = Convert.ToHexStringLower(SHA256.HashData(stream)); stream.Position = 0; return hash;
    }
    private static bool HashShape(string? value) { return value is not null && CurrentAuthRepairPermit.HashShape(value); }
    private static bool Canonical(string? path) { return !string.IsNullOrWhiteSpace(path) && Path.IsPathFullyQualified(path) && string.Equals(path, Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase); }
    private static MigrationExecutionException Invalid() { return CurrentAuthLocalSessionArchivePolicy.Invalid(); }
    public void Dispose()
    {
        if (_disposed) { return; }
        _disposed = true;
        try { DisposeImages(0); }
        finally { DisposeRoots(_parent, _parentFiles, _precursor, _precursorFiles); }
    }
    private void DisposeImages(int index)
    {
        if (index >= _images.Count) { return; }
        try { _images[index].Stream.Dispose(); } finally { DisposeImages(index + 1); }
    }
    private static void DisposeRoots(WindowsLocalRunAuthority? parent, CurrentAppOwnedRepairCustody? parentFiles,
        WindowsLocalRunAuthority? precursor, CurrentAppOwnedRepairCustody? precursorFiles)
    {
        try { precursorFiles?.Dispose(); }
        finally
        {
            try { precursor?.Dispose(); }
            finally
            {
                try { parentFiles?.Dispose(); } finally { parent?.Dispose(); }
            }
        }
    }
}
