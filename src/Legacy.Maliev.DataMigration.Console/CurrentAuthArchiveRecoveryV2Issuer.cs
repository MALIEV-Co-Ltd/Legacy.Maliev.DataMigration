using System.Reflection;

namespace Legacy.Maliev.DataMigration.Console;

// Fixed owned-disposable execution issuer; the existing helper issuer and persistent permit gate remain separate.
internal sealed partial class CurrentAuthArchiveRecoveryV2Issuer : IAsyncDisposable
{
    private const string LeaseType = "Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveGenuineOwnedPair";
    private readonly CurrentAuthTypedHostProducer.HeldTestBundle _bundle;
    private readonly CurrentAuthArchiveInitialProducer.FixedNativeBundle? _loader;
    private readonly ICurrentAuthArchiveRecoveryV2Lease _lease;
    private readonly Lock _gate = new();
    private Guid _id;
    private bool _minted, _reserved, _failed, _closed, _disposed;
    private CurrentAuthArchiveRecoveryV2Issuer(CurrentAuthTypedHostProducer.HeldTestBundle bundle,
        CurrentAuthArchiveInitialProducer.FixedNativeBundle? loader, ICurrentAuthArchiveRecoveryV2Lease lease)
    { _bundle = bundle; _loader = loader; _lease = lease; }

    internal static async Task<CurrentAuthArchiveRecoveryV2Issuer> CreateAsync(CurrentAuthArchiveRecoveryV2Input input,
        CurrentAuthArchiveRecoveryV2Case expectedCase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); CurrentAuthArchiveRecoveryV2InputContract.Require(input, expectedCase);
        var request = input.Request;
        // Strict original Console acceptance remains mandatory before qualified code or native fixtures execute.
        _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
        var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(Path.GetDirectoryName(request.Inputs.TestImage.Path) ?? throw Invalid(), ct);
        CurrentAuthArchiveInitialProducer.FixedNativeBundle? loader = null;
        ICurrentAuthArchiveRecoveryV2Lease? lease = null;
        try
        {
            bundle.Require();
            Assembly[] loaded = AppDomain.CurrentDomain.GetAssemblies().Where(value => value.GetName().Name == "Legacy.Maliev.DataMigration.Tests").ToArray();
            if (loaded.Length > 1) { throw Invalid(); }
            Assembly tests;
            if (loaded.Length == 0) { loader = new(request.Inputs.TestImage.Path); tests = loader.LoadFromAssemblyPath(request.Inputs.TestImage.Path); }
            else
            {
                tests = loaded[0];
                if (!StringComparer.OrdinalIgnoreCase.Equals(tests.Location, request.Inputs.TestImage.Path)) { throw Invalid(); }
                using var image = SecureLocalFile.OpenReadShared(tests.Location);
                if (!SecureLocalFile.HandleResolvesToApprovedPath(image, request.Inputs.TestImage.Path) ||
                    Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(image)) != request.Inputs.TestImage.Sha256) { throw Invalid(); }
            }
            Type type = tests.GetType(LeaseType, throwOnError: true)!;
            if (!type.IsSealed || type.GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length != 0) { throw Invalid(); }
            MethodInfo factory = type.GetMethod("OpenRecoveryV2LeaseAsync", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.DeclaredOnly,
                binder: null, types: [typeof(CurrentAuthArchiveRecoveryV2Input), typeof(CurrentAuthArchiveRecoveryV2Case), typeof(CancellationToken)], modifiers: null) ?? throw Invalid();
            if (factory.ReturnType != typeof(Task<ICurrentAuthArchiveRecoveryV2Lease>)) { throw Invalid(); }
            bundle.Require();
            lease = await (factory.Invoke(null, [input, expectedCase, ct]) as Task<ICurrentAuthArchiveRecoveryV2Lease> ?? throw Invalid());
            if (lease.GetType() != type) { throw Invalid(); }
            var issuer = new CurrentAuthArchiveRecoveryV2Issuer(bundle, loader, lease);
            _ = await issuer.ObserveAsync(baseline: true, ct);

            return issuer;
        }
        catch (Exception primary)
        {
            try { if (lease is not null) { await lease.DisposeAsync(); } } catch (Exception cleanup) { primary.Data["execution_pair_cleanup_failure"] = cleanup.GetType().Name; }
            try { loader?.Dispose(); } catch (Exception cleanup) { primary.Data["execution_loader_cleanup_failure"] = cleanup.GetType().Name; }
            try { loader?.Unload(); } catch (Exception cleanup) { primary.Data["execution_loader_unload_failure"] = cleanup.GetType().Name; }
            try { bundle.Dispose(); } catch (Exception cleanup) { primary.Data["execution_bundle_cleanup_failure"] = cleanup.GetType().Name; }
            throw;
        }
    }

    private async Task<CurrentAuthArchiveGenuineExecutionAttestation> ObserveAsync(bool baseline, CancellationToken ct)
    {
        lock (_gate) { if (_disposed || _closed || _failed) { throw Invalid(); } }
        _bundle.Require(); var result = await _lease.AttestExecutionAsync(baseline, ct); _bundle.Require();
        lock (_gate) { if (_disposed || _closed || _failed) { throw Invalid(); } }
        return result;
    }
    internal async Task<CurrentAuthArchiveGenuineExecutionAttestation> MintExecutionAsync(Guid id, CancellationToken ct)
    {
        lock (_gate)
        {
            if (_disposed || _closed || _failed || _minted || id == Guid.Empty) { throw Invalid(); }
            _minted = true; _id = id;
        }
        return await RequireExecutionAsync(id, true, ct);
    }
    internal async Task<CurrentAuthArchiveGenuineExecutionAttestation> RequireExecutionAsync(Guid id, bool baseline, CancellationToken ct)
    {
        Check(id, baseline);
        try { var result = await ObserveAsync(baseline, ct); Check(id, baseline); return result; }
        catch { lock (_gate) { _failed = true; } throw; }
    }
    internal async Task ReserveExecutionAsync(Guid id, CancellationToken ct)
    {
        lock (_gate)
        {
            if (_disposed || _closed || _failed || !_minted || _reserved || id != _id) { throw Invalid(); }
            _reserved = true;
        }
        _ = await RequireExecutionAsync(id, false, ct);
    }
    internal async Task<string> ReadExecutionConnectionAsync(Guid id, CancellationToken ct)
    {
        _ = await RequireExecutionAsync(id, false, ct);
        string result = await _lease.ReadExecutionConnectionAsync(ct);
        _ = await RequireExecutionAsync(id, false, ct); return result;
    }
    internal async Task<P256MigrationEvidenceSigner> CreateExecutionSignerAsync(Guid id, CancellationToken ct)
    {
        _ = await RequireExecutionAsync(id, false, ct);
        var result = await _lease.CreateExecutionSignerAsync(ct);
        try { _ = await RequireExecutionAsync(id, false, ct); return result; }
        catch { result.Dispose(); throw; }
    }
    internal async Task<CurrentAuthArchiveGenuineDualArtifacts> CompleteRecoveryAsync(Guid id, CurrentAuthArchiveGenuineExecutionFacts facts, CancellationToken ct)
    {
        _ = await RequireExecutionAsync(id, false, ct);
        try
        {
            var result = await _lease.CompleteRecoveryAsync(facts, ct);
            lock (_gate) { if (_disposed || _failed || _closed || id != _id) { throw Invalid(); } _closed = true; }
            _bundle.Require(); return result;
        }
        catch { lock (_gate) { _failed = true; } throw; }
    }
    private void Check(Guid id, bool baseline)
    {
        lock (_gate)
        { if (_disposed || _closed || _failed || !_minted || id != _id || baseline == _reserved) { throw Invalid(); } }
    }
    public async ValueTask DisposeAsync()
    {
        lock (_gate) { if (_disposed) { return; } _disposed = true; }
        Exception? failure = null;
        try { await _lease.DisposeAsync(); } catch (Exception cleanup) { failure = cleanup; }
        try { _loader?.Dispose(); } catch (Exception cleanup) { failure ??= cleanup; }
        try { _loader?.Unload(); } catch (Exception cleanup) { failure ??= cleanup; }
        try { _bundle.Dispose(); } catch (Exception cleanup) { failure ??= cleanup; }
        if (failure is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw(); }
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveGenuineExecutionCases.Invalid();
    }
}
