using System.Reflection;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed class CurrentAuthArchiveDefinitionAnchorSession : IAsyncDisposable
{
    private readonly CurrentAuthArchiveInitialProducer.FixedNativeBundle _loader;
    private readonly CurrentAuthTypedHostProducer.HeldTestBundle _bundle;
    private readonly ICurrentAuthArchiveDefinitionAnchorLease _lease;
    private int _closed;
    internal CurrentAuthRepairScope Intent => _lease.Intent;
    internal LocalExecutionBinding Binding => _lease.Binding;
    internal string SourcePath => _lease.SourcePath;
    private CurrentAuthArchiveDefinitionAnchorSession(CurrentAuthArchiveInitialProducer.FixedNativeBundle loader,
        CurrentAuthTypedHostProducer.HeldTestBundle bundle, ICurrentAuthArchiveDefinitionAnchorLease lease)
    { _loader = loader; _bundle = bundle; _lease = lease; }

    internal static async Task<CurrentAuthArchiveDefinitionAnchorSession> OpenAsync(CurrentAuthArchiveDefinitionAnchorOwner owner,
        CurrentReviewedCapture capture, CurrentAuthArchiveProofArtifact testsImage, CancellationToken ct)
    {
        owner.RequireForFixture(); await capture.RequireAsync(ct);
        string root = Path.GetDirectoryName(testsImage.Path)!;
        if (Path.GetFileName(testsImage.Path) != "Legacy.Maliev.DataMigration.Tests.dll" || !Path.IsPathFullyQualified(testsImage.Path)) { throw Invalid(); }
        CurrentAuthArchiveDefinitionCodeCopy.RequireBoundedInventory(root, ct);
        var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(root, ct);
        CurrentAuthArchiveInitialProducer.FixedNativeBundle? loader = null;
        ICurrentAuthArchiveDefinitionAnchorLease? lease = null;
        try
        {
            using var image = SecureLocalFile.OpenReadShared(testsImage.Path);
            if (!SecureLocalFile.HandleResolvesToApprovedPath(image, testsImage.Path) ||
                Convert.ToHexStringLower(await SHA256.HashDataAsync(image, ct)) != testsImage.Sha256) { throw Invalid(); }
            loader = new(testsImage.Path); bundle.Require();
            Assembly tests = loader.LoadFromAssemblyPath(testsImage.Path);
            Type exact = tests.GetType("Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveDefinitionAnchor", throwOnError: true)!;
            if (!exact.IsSealed || exact.Assembly != tests || exact.FullName != "Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveDefinitionAnchor") { throw Invalid(); }
            MethodInfo factory = exact.GetMethod("CreateAsync", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.DeclaredOnly,
                binder: null, types: [typeof(CurrentAuthArchiveDefinitionAnchorOwner), typeof(CurrentReviewedCapture), typeof(CancellationToken)], modifiers: null) ?? throw Invalid();
            if (factory.ReturnType != typeof(Task<ICurrentAuthArchiveDefinitionAnchorLease>)) { throw Invalid(); }
            // Independent accepted code/bundle authentication precedes the first factory invocation.
            await capture.RequireAsync(ct); owner.RequireForFixture(); bundle.Require();
            lease = await (factory.Invoke(null, [owner, capture, ct]) as Task<ICurrentAuthArchiveDefinitionAnchorLease> ?? throw Invalid());
            if (lease.GetType() != exact || lease.Binding != owner.Binding || lease.Intent.RunBindingSha256 != owner.Binding.ComputeSha256()) { throw Invalid(); }
            await lease.RequireAsync(ct); bundle.Require();
            var session = new CurrentAuthArchiveDefinitionAnchorSession(loader, bundle, lease);
            loader = null; lease = null; return session;
        }
        catch (Exception primary)
        {
            var failures = new List<Exception> { primary };
            try { if (lease is not null) { await lease.DisposeAsync(); } } catch (Exception cleanup) { failures.Add(cleanup); }
            try { loader?.Unload(); } catch (Exception cleanup) { failures.Add(cleanup); }
            try { loader?.Dispose(); } catch (Exception cleanup) { failures.Add(cleanup); }
            try { bundle.Dispose(); } catch (Exception cleanup) { failures.Add(cleanup); }
            if (failures.Count > 1) { throw new AggregateException("The definition anchor failed and its exact cleanup also failed.", failures); }
            throw;
        }
    }

    internal async Task RequireAsync(CancellationToken ct) { _bundle.Require(); await _lease.RequireAsync(ct); }
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) { return; }
        var failures = new List<Exception>();
        try { await _lease.DisposeAsync(); } catch (Exception cleanup) { failures.Add(cleanup); }
        try { _loader.Unload(); } catch (Exception cleanup) { failures.Add(cleanup); }
        try { _loader.Dispose(); } catch (Exception cleanup) { failures.Add(cleanup); }
        try { _bundle.Dispose(); } catch (Exception cleanup) { failures.Add(cleanup); }
        if (failures.Count > 1) { throw new AggregateException("The exact definition anchor cleanup failed.", failures); }
        if (failures.Count == 1) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failures[0]).Throw(); }
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveRecoveryV2.Invalid();
    }
}
