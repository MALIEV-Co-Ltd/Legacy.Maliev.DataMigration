using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// This handle is never serialized. Only this fixed factory can construct it; no
// endpoint, Docker identity, image, SQL callback or pre-existing target is accepted.
internal sealed partial class CurrentAuthArchiveGenuineOwnedPair : IAsyncDisposable
{
    private readonly CurrentAuthArchiveComponentReadback _inputs;
    private readonly CurrentAuthTypedHostProducer.HeldTestBundle _bundle;
    private readonly CurrentAuthArchiveComponentBootstrapSeed _seed;
    private readonly CancellationTokenSource _lease;
    private CurrentAuthArchiveFixtureTarget? _first, _second;
    private CurrentAuthArchiveFixtureInstalledPolicy? _firstPolicy, _secondPolicy;
    private WindowsLocalRunAuthority? _firstAuthority, _secondAuthority;
    private CurrentAppOwnedRepairCustody? _firstFiles, _secondFiles;
    private CurrentAuthLocalSessionArchiveEnvironment? _environment;
    private bool _disposed;
    private CurrentAuthArchiveScope? _scope;
    private CurrentAuthArchiveComponentBootstrapSubject? _subject;

    private CurrentAuthArchiveGenuineOwnedPair(CurrentAuthArchiveComponentReadback inputs, CurrentAuthTypedHostProducer.HeldTestBundle bundle,
        CurrentAuthArchiveComponentBootstrapSeed seed, CancellationToken ct)
    {
        _inputs = inputs; _bundle = bundle; _seed = seed;
        TimeSpan remaining = seed.ExpiresAtUtc - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero) { throw Invalid(); }
        _lease = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _lease.CancelAfter(remaining);
    }

    internal CurrentAuthArchiveScope Scope => !_disposed && _scope is not null ? _scope : throw Invalid();
    internal CurrentAuthArchiveComponentBootstrapSubject Subject => !_disposed && _subject is not null ? _subject : throw Invalid();

    internal static Task<CurrentAuthArchiveGenuineOwnedPair> CreateAsync(
        CurrentAuthArchiveGenuineHostConfiguration request, CancellationToken ct)
    {
        return CreateHelperCoreAsync(request, CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback, ct);
    }

    internal static Task<CurrentAuthArchiveGenuineOwnedPair> CreateRecoveryHelperAsync(CurrentAuthArchiveGenuineHostConfiguration request,
        CurrentAuthArchiveGenuineRecoveryHelperCase helperCase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback
            ? throw Invalid()
            : CreateHelperCoreAsync(request, helperCase, ct);
    }

    private static async Task<CurrentAuthArchiveGenuineOwnedPair> CreateHelperCoreAsync(
        CurrentAuthArchiveGenuineHostConfiguration request,
        CurrentAuthArchiveGenuineRecoveryHelperCase helperCase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        CurrentAuthArchiveGenuineHost.RequireInput(request);
        if (request.Phase != "helper" || request.CaseId != CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(helperCase)) { throw Invalid(); }
        // Called only from the held qualified Tests bundle. All signatures, owner,
        // precursor, source age and input file identities precede target creation.
        var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(
            Path.GetDirectoryName(request.Inputs.TestImage.Path) ?? throw Invalid(), ct);
        CurrentAuthArchiveComponentReadback? inputs = null;
        CurrentAuthArchiveGenuineOwnedPair? pair = null;
        try
        {
            bundle.Require();
            inputs = helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback ?
                await CurrentAuthArchiveComponentReadback.OpenInitialAsync(request.Inputs, ct) :
                await CurrentAuthArchiveComponentReadback.OpenGenuineHelperInitialAsync(request.Inputs, helperCase, ct);
            var seed = await inputs.ReadSeedAsync(ct);
            pair = new(inputs, bundle, seed, ct);
            await pair.CreateOwnedAsync(request, pair._lease.Token);
            await pair.RequireAsync(ct);
            return pair;
        }
        catch (Exception primary)
        {
            if (pair is null)
            {
                try { inputs?.Dispose(); }
                catch (Exception cleanup) { primary.Data["owned_pair_input_cleanup_failure"] = cleanup.GetType().Name; }
                try { bundle.Dispose(); }
                catch (Exception cleanup) { primary.Data["owned_pair_bundle_cleanup_failure"] = cleanup.GetType().Name; }
            }
            else
            {
                try { await pair.DisposeAsync(); }
                catch (Exception cleanup) { primary.Data["owned_pair_cleanup_failure"] = cleanup.GetType().Name; }
            }
            throw;
        }
    }

    private async Task CreateOwnedAsync(CurrentAuthArchiveGenuineHostConfiguration request, CancellationToken ct)
    {
        await _inputs.RequireAsync(ct);
        _first = await CurrentAuthArchiveFixtureTarget.CreateAsync(request.FirstFixtureParent, _inputs.ParentFiles,
            _inputs.SourceArtifact, _seed.AcceptedSourceCommitSha, _seed.OperationId, comparison: false, ct);
        await _inputs.RequireAsync(ct);
        _second = await CurrentAuthArchiveFixtureTarget.CreateAsync(request.SecondFixtureParent, _inputs.ParentFiles,
            _inputs.SourceArtifact, _seed.AcceptedSourceCommitSha, _seed.OperationId, comparison: true, ct);
        var firstSeed = await CurrentAuthArchiveFixtureSeed.SeedAndCaptureAsync(_first, _inputs.ParentFiles,
            _inputs.SourceArtifact, _seed.AcceptedSourceCommitSha, ct);
        var secondSeed = await CurrentAuthArchiveFixtureSeed.SeedAndCaptureAsync(_second, _inputs.ParentFiles,
            _inputs.SourceArtifact, _seed.AcceptedSourceCommitSha, ct);
        _firstPolicy = await CurrentAuthArchiveFixturePolicy.InstallAndObserveAsync(_first, firstSeed,
            _inputs.ParentFiles, _inputs.SourceArtifact, _seed.AcceptedSourceCommitSha, ct);
        _secondPolicy = await CurrentAuthArchiveFixturePolicy.InstallAndObserveAsync(_second, secondSeed,
            _inputs.ParentFiles, _inputs.SourceArtifact, _seed.AcceptedSourceCommitSha, ct);
        var first = await CurrentAuthArchiveInitialNativeProducer.CaptureTargetAsync(_first, _firstPolicy, ct);
        var second = await CurrentAuthArchiveInitialNativeProducer.CaptureTargetAsync(_second, _secondPolicy, ct);
        _firstAuthority = WindowsLocalRunAuthority.AcquireResume(_first.Root, _first.Binding);
        _secondAuthority = WindowsLocalRunAuthority.AcquireResume(_second.Root, _second.Binding);
        _firstFiles = new(_firstAuthority); _secondFiles = new(_secondAuthority);
        var firstPolicy = CurrentAuthArchiveInitialNativeProducer.ObservationPolicy(_seed, _first, _firstPolicy, first.Pins, first.Docker.Target);
        var secondPolicy = CurrentAuthArchiveInitialNativeProducer.ObservationPolicy(_seed, _second, _secondPolicy, second.Pins, second.Docker.Target);
        var paths = new CurrentAuthArchivePaths(Path.Combine(_first.Root, "genuine-first.ciphertext"),
            Path.Combine(_second.Root, "genuine-second.ciphertext"), Path.Combine(_first.Root, "genuine-first-recovery.pem"),
            Path.Combine(_second.Root, "genuine-second-recovery.pem"));
        DateTimeOffset began = DateTimeOffset.UtcNow;
        var deviceRequest = new CurrentAuthArchiveDevicePreflightRequest("Legacy.Maliev.CurrentAuth.ArchiveDevicePreflight.v1",
            _seed.OperationId, _seed.AcceptedSourceCommitSha, firstPolicy.RunBindingSha256, secondPolicy.RunBindingSha256,
            firstPolicy.TargetObservationSha256, secondPolicy.TargetObservationSha256, paths, _first.Root, _second.Root, began, began.AddMinutes(1));
        var devices = await CurrentAuthLocalSessionArchiveDeviceProcess.ObservePreflightAsync(deviceRequest, _firstFiles, _secondFiles, ct);
        _dualDeviceProof = devices;
        var firstFleet = CurrentAuthArchiveInitialNativeProducer.Fleet(_firstPolicy.Baseline, firstPolicy);
        var secondFleet = CurrentAuthArchiveInitialNativeProducer.Fleet(_secondPolicy.Baseline, secondPolicy);
        byte[] rows = CurrentAuthLocalSessionArchivePolicy.EncodeRows(firstFleet.Auth.Sessions);
        CurrentAuthArchiveComponentBootstrapSubject subject;
        try
        {
            subject = new("current-auth-actual-paired-archive-component-subject-v1", _seed,
                CurrentAuthLocalSessionArchiveEnvironment.ObservedTarget(first.Docker, first.Pins, _firstAuthority, firstPolicy, firstFleet),
                CurrentAuthLocalSessionArchiveEnvironment.ObservedTarget(second.Docker, second.Pins, _secondAuthority, secondPolicy, secondFleet),
                CurrentAuthLocalSessionArchivePolicy.Hash(devices), CurrentAuthLocalSessionArchivePolicy.HashBytes(rows), firstFleet.Auth.Sessions.Count,
                CurrentAuthLocalSessionArchivePolicy.RequireComparison(firstFleet.Auth, secondFleet.Auth), CurrentAuthLocalSessionArchivePolicy.Hash(paths));
        }
        finally { CryptographicOperations.ZeroMemory(rows); }
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset expires = new[] { _seed.ExpiresAtUtc, _firstPolicy.Maintenance.ExpiresAtUtc.AddSeconds(-1),
            _secondPolicy.Maintenance.ExpiresAtUtc.AddSeconds(-1), now.AddMinutes(4) }.Min();
        _scope = new(_seed.OperationId, firstPolicy, secondPolicy, subject.DeleteSetSha256, subject.DeleteCount,
            subject.ApplicationComparisonSha256, paths, subject.RecoveryDeviceProofSha256,
            string.Empty, string.Empty, string.Empty, string.Empty, now, expires,
            CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap, subject);
        CurrentAuthArchiveComponentBootstrap.RequireClaims(_scope, _inputs.TrustStore, _inputs.Pins, now);
        string scopePath = Path.Combine(_inputs.ParentAuthority.Binding.ArtifactRootCanonicalPath, $"genuine-owned-pair-{_seed.OperationId:N}-scope.json");
        byte[] scopeBytes = JsonSerializer.SerializeToUtf8Bytes(_scope);
        await _inputs.ParentFiles.WriteNewAsync(scopePath, scopeBytes, ct);
        if (!_inputs.ParentFiles.Read(scopePath, sharedReader: true, maximumBytes: 1024 * 1024).AsSpan().SequenceEqual(scopeBytes)) { throw Invalid(); }
        await _inputs.AttachObservedScopeAsync(new(scopePath, CurrentAuthLocalSessionArchivePolicy.HashBytes(scopeBytes)), ct);
        _environment = new(_firstFiles, _secondFiles, _firstAuthority, _secondAuthority, _scope, _inputs.Source, first.Pins, second.Pins,
            Encoding.UTF8.GetString(_firstFiles.Read(_firstPolicy.OperatorConnectionPath, maximumBytes: 65536)),
            Encoding.UTF8.GetString(_secondFiles.Read(_secondPolicy.OperatorConnectionPath, maximumBytes: 65536)),
            Encoding.UTF8.GetString(_firstFiles.Read(_firstPolicy.OrdinaryConnectionPath, maximumBytes: 65536)),
            Encoding.UTF8.GetString(_secondFiles.Read(_secondPolicy.OrdinaryConnectionPath, maximumBytes: 65536)),
            devices, _inputs.TrustStore, _inputs.Pins, CurrentAuthLocalSessionArchivePolicy.Hash(_seed));
        _subject = await _environment.ObserveComponentSubjectAsync(_inputs, ct);
    }

    internal async Task RequireAsync(CancellationToken ct)
    {
        if (_disposed || _environment is null || _first is null || _second is null || _firstAuthority is null || _secondAuthority is null || _scope is null ||
            _subject is null || DateTimeOffset.UtcNow >= _scope.ExpiresAtUtc) { throw Invalid(); }
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct, _lease.Token, _first.Token, _second.Token);
        _bundle.Require();
        await _inputs.RequireAsync(lease.Token);
        await _first.RequireHealthyHeldAsync(_firstAuthority, lease.Token);
        await _second.RequireHealthyHeldAsync(_secondAuthority, lease.Token);
        // The existing environment re-observes actual Docker, system identifiers,
        // maintenance/HBA and all 26/49 database snapshots; this is no cached marker.
        var observed = await _environment.ObserveComponentSubjectAsync(_inputs, lease.Token);
        if (CurrentAuthLocalSessionArchivePolicy.Hash(observed) != CurrentAuthLocalSessionArchivePolicy.Hash(_subject)) { throw Invalid(); }
        _bundle.Require();
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true; _lease.Cancel();
        Exception? failure = null;
        void Release(IDisposable? resource)
        {
            try { resource?.Dispose(); } catch (Exception cleanup) { failure ??= cleanup; }
        }
        try { if (_commitProxy is not null) { await _commitProxy.DisposeAsync(); } } catch (Exception cleanup) { failure ??= cleanup; }
        Release(_recoveryHelpersStorage); Release(_environment);
        Release(_secondFiles); Release(_firstFiles); Release(_secondAuthority); Release(_firstAuthority);
        Release(_secondPolicy); Release(_firstPolicy);
        try { if (_second is not null) { await _second.DisposeAsync(); } } catch (Exception cleanup) { failure ??= cleanup; }
        try { if (_first is not null) { await _first.DisposeAsync(); } } catch (Exception cleanup) { failure ??= cleanup; }
        Release(_inputs); Release(_bundle); Release(_lease);
        if (failure is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw(); }
    }

    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveGenuineHost.Invalid("owned_pair_binding");
    }
}
