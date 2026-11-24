using System.Reflection;

namespace Legacy.Maliev.DataMigration.Console;

// No route activates this issuer. It owns its exact fixed-factory pair until
// explicit disposal, independently of every serialized configuration object.
internal sealed partial class CurrentAuthArchiveGenuineIssuer : IAsyncDisposable
{
    private const string LeaseType = "Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveGenuineOwnedPair";
    private readonly CurrentAuthTypedHostProducer.HeldTestBundle _bundle;
    private readonly CurrentAuthArchiveInitialProducer.FixedNativeBundle? _loader;
    private readonly ICurrentAuthArchiveGenuineOwnedLease _lease;
    private bool _disposed;
    private readonly Lock _capabilityGate = new();
    private Guid _capabilityId;
    private bool _minted, _reserved, _failed;

    private CurrentAuthArchiveGenuineIssuer(CurrentAuthTypedHostProducer.HeldTestBundle bundle,
        CurrentAuthArchiveInitialProducer.FixedNativeBundle? loader, ICurrentAuthArchiveGenuineOwnedLease lease)
    { _bundle = bundle; _loader = loader; _lease = lease; }

    internal static Task<CurrentAuthArchiveGenuineIssuer> CreateAsync(CurrentAuthArchiveGenuineHostConfiguration request, CancellationToken ct)
    {
        return CreateHelperCoreAsync(request, CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback, ct);
    }

    internal static Task<CurrentAuthArchiveGenuineIssuer> CreateRecoveryHelperAsync(CurrentAuthArchiveGenuineHostConfiguration request,
        CurrentAuthArchiveGenuineRecoveryHelperCase helperCase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback
            ? throw Invalid()
            : CreateHelperCoreAsync(request, helperCase, ct);
    }

    private static async Task<CurrentAuthArchiveGenuineIssuer> CreateHelperCoreAsync(CurrentAuthArchiveGenuineHostConfiguration request,
        CurrentAuthArchiveGenuineRecoveryHelperCase helperCase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); CurrentAuthArchiveGenuineHost.RequireInput(request);
        if (request.Phase != "helper" || request.CaseId != CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(helperCase)) { throw Invalid(); }
        var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(Path.GetDirectoryName(request.Inputs.TestImage.Path) ?? throw Invalid(), ct);
        CurrentAuthArchiveInitialProducer.FixedNativeBundle? loader = null;
        ICurrentAuthArchiveGenuineOwnedLease? lease = null;
        try
        {
            bundle.Require();
            Assembly[] loaded = AppDomain.CurrentDomain.GetAssemblies().Where(x => x.GetName().Name == "Legacy.Maliev.DataMigration.Tests").ToArray();
            if (loaded.Length > 1) { throw Invalid(); }
            Assembly tests;
            if (loaded.Length == 0)
            {
                loader = new(request.Inputs.TestImage.Path);
                tests = loader.LoadFromAssemblyPath(request.Inputs.TestImage.Path);
            }
            else
            {
                tests = loaded[0];
                if (!StringComparer.OrdinalIgnoreCase.Equals(tests.Location, request.Inputs.TestImage.Path)) { throw Invalid(); }
                using var image = SecureLocalFile.OpenReadShared(tests.Location);
                if (!SecureLocalFile.HandleResolvesToApprovedPath(image, request.Inputs.TestImage.Path) ||
                    Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(image)) != request.Inputs.TestImage.Sha256) { throw Invalid(); }
            }
            Type type = tests.GetType(LeaseType, throwOnError: true)!;
            if (!type.IsSealed || type.GetConstructors(BindingFlags.Instance | BindingFlags.Public).Length != 0) { throw Invalid(); }
            MethodInfo method = helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback ?
                type.GetMethod("OpenLeaseAsync", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.DeclaredOnly,
                    binder: null, types: [typeof(CurrentAuthArchiveGenuineHostConfiguration), typeof(CancellationToken)], modifiers: null) ?? throw Invalid() :
                type.GetMethod("OpenRecoveryHelperLeaseAsync", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.DeclaredOnly,
                    binder: null, types: [typeof(CurrentAuthArchiveGenuineHostConfiguration), typeof(CurrentAuthArchiveGenuineRecoveryHelperCase), typeof(CancellationToken)], modifiers: null) ?? throw Invalid();
            if (method.ReturnType != typeof(Task<ICurrentAuthArchiveGenuineOwnedLease>)) { throw Invalid(); }
            var pending = method.Invoke(null, helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback ? [request, ct] : [request, helperCase, ct]) as Task<ICurrentAuthArchiveGenuineOwnedLease> ?? throw Invalid();
            lease = await pending.ConfigureAwait(false);
            if (lease.GetType() != type) { throw Invalid(); }
            var issuer = new CurrentAuthArchiveGenuineIssuer(bundle, loader, lease);
            _ = await issuer.AttestOwnedLeaseAsync(true, ct);
            bundle.Require(); return issuer;
        }
        catch (Exception primary)
        {
            try { if (lease is not null) { await lease.DisposeAsync(); } }
            catch (Exception cleanup) { primary.Data["issuer_pair_cleanup_failure"] = cleanup.GetType().Name; }
            try { loader?.Dispose(); }
            catch (Exception cleanup) { primary.Data["issuer_loader_cleanup_failure"] = cleanup.GetType().Name; }
            try { loader?.Unload(); }
            catch (Exception cleanup) { primary.Data["issuer_loader_unload_failure"] = cleanup.GetType().Name; }
            try { bundle.Dispose(); }
            catch (Exception cleanup) { primary.Data["issuer_bundle_cleanup_failure"] = cleanup.GetType().Name; }
            throw;
        }
    }

    // Only the three fixed mint/require/reserve methods expose this observation.
    private async Task<CurrentAuthArchiveGenuineAttestation> AttestOwnedLeaseAsync(bool requireBaseline, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this); _bundle.Require();
        var facts = await _lease.AttestAsync(requireBaseline, ct);
        ObjectDisposedException.ThrowIf(_disposed, this); _bundle.Require(); return facts;
    }

    internal async Task<CurrentAuthArchiveGenuineAttestation> MintOwnedCapabilityAsync(Guid capabilityId, CancellationToken ct)
    {
        lock (_capabilityGate)
        {
            if (_disposed || _failed || _minted || capabilityId == Guid.Empty) { throw Invalid(); }
            _minted = true; _capabilityId = capabilityId;
        }
        return await RequireOwnedCapabilityAsync(capabilityId, requireBaseline: true, ct);
    }

    internal async Task<CurrentAuthArchiveGenuineAttestation> RequireOwnedCapabilityAsync(Guid capabilityId, bool requireBaseline, CancellationToken ct)
    {
        lock (_capabilityGate)
        {
            if (_disposed || _failed || !_minted || capabilityId != _capabilityId || requireBaseline == _reserved) { throw Invalid(); }
        }
        try
        {
            var facts = await AttestOwnedLeaseAsync(requireBaseline, ct);
            lock (_capabilityGate)
            {
                if (_disposed || _failed || capabilityId != _capabilityId || requireBaseline == _reserved) { throw Invalid(); }
            }
            return facts;
        }
        catch { lock (_capabilityGate) { _failed = true; } throw; }
    }

    internal async Task ReserveOwnedCapabilityAsync(Guid capabilityId, CancellationToken ct)
    {
        lock (_capabilityGate)
        {
            if (_disposed || _failed || !_minted || _reserved || capabilityId != _capabilityId) { throw Invalid(); }
            _reserved = true;
        }
        _ = await RequireOwnedCapabilityAsync(capabilityId, requireBaseline: false, ct);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true;
        Exception? failure = null;
        try { await _lease.DisposeAsync(); } catch (Exception cleanup) { failure = cleanup; }
        try { _loader?.Dispose(); } catch (Exception cleanup) { failure ??= cleanup; }
        try { _loader?.Unload(); } catch (Exception cleanup) { failure ??= cleanup; }
        try { _bundle.Dispose(); } catch (Exception cleanup) { failure ??= cleanup; }
        if (failure is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw(); }
    }

    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveGenuineHost.Invalid("issuer_binding");
    }
}
