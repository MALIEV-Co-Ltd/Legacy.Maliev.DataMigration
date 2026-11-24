using System.Reflection;

namespace Legacy.Maliev.DataMigration.Console;

// Only this private construction path obtains an owned lease. JSON cannot adopt an endpoint.
internal sealed class SourceOrderOwnerIsoOwnedSession : IAsyncDisposable
{
    private readonly CurrentAuthTypedHostProducer.HeldTestBundle _bundle;
    private readonly CurrentAuthArchiveInitialProducer.FixedNativeBundle _loader;
    internal ISourceOrderOwnerIsoOwnedProofLease Lease { get; }
    private bool _disposed;
    private SourceOrderOwnerIsoOwnedSession(CurrentAuthTypedHostProducer.HeldTestBundle bundle,
        CurrentAuthArchiveInitialProducer.FixedNativeBundle loader, ISourceOrderOwnerIsoOwnedProofLease lease)
    { _bundle = bundle; _loader = loader; Lease = lease; }
    internal static async Task<SourceOrderOwnerIsoOwnedSession> CreateAsync(SourceOrderOwnerIsoInputs template, ConsumerColumnBootstrapSourceCapture source, string parent, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != source.Plan.SourceCommitSha)
        { throw Invalid(); }
        var image = template.Configuration.TestsImage;
        if (Path.GetFileName(image.Path) != "Legacy.Maliev.DataMigration.Tests.dll") { throw Invalid(); }
        var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(Path.GetDirectoryName(image.Path)!, ct);
        CurrentAuthArchiveInitialProducer.FixedNativeBundle? loader = null; ISourceOrderOwnerIsoOwnedProofLease? lease = null;
        try
        {
            if (CurrentAuthTypedHostProducer.ImageHash(image.Path) != image.Sha256) { throw Invalid(); }
            loader = new(image.Path); var tests = loader.LoadFromAssemblyPath(image.Path);
            Type exact = tests.GetType("Legacy.Maliev.DataMigration.Tests.SourceOrderOwnerIsoOwnedProofLease", true)!;
            var factory = exact.GetMethod("CreateAsync", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.DeclaredOnly,
                null, [typeof(string), typeof(FreshSchemaPlan), typeof(bool), typeof(CancellationToken)], null) ?? throw Invalid();
            if (!exact.IsSealed || exact.GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length != 0 || factory.ReturnType != typeof(Task<ISourceOrderOwnerIsoOwnedProofLease>))
            { throw Invalid(); }
            lease = await (factory.Invoke(null, [parent, source.Plan, template.Intent.CompanyAlreadyApplied, ct]) as Task<ISourceOrderOwnerIsoOwnedProofLease> ?? throw Invalid());
            if (lease.GetType() != exact || lease.SourceFullSha256 != source.FullPlanSha256 || lease.CompanyAlreadyApplied != template.Intent.CompanyAlreadyApplied || !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(lease.Target)) { throw Invalid(); }
            await lease.RequireAsync(ct); bundle.Require(); return new(bundle, loader, lease);
        }
        catch (Exception primary)
        {
            Exception? cleanup = null;
            try { if (lease is not null) { await lease.DisposeAsync(); await lease.RequireAbsentAsync(CancellationToken.None); } }
            catch (Exception failure) { cleanup = failure; }
            finally { loader?.Dispose(); bundle.Dispose(); }
            if (cleanup is not null) { throw new AggregateException(primary, cleanup); }
            throw;
        }
    }
    internal async Task RequireAsync(CancellationToken ct)
    { ObjectDisposedException.ThrowIf(_disposed, this); _bundle.Require(); await Lease.RequireAsync(ct); }
    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true;
        try
        {
            await Lease.DisposeAsync(); using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await Lease.RequireAbsentAsync(cleanup.Token);
        }
        finally { _loader.Dispose(); _bundle.Dispose(); }
    }
    private static MigrationExecutionException Invalid()
    {
        return SourceOrderOwnerIsoProtocol.Invalid();
    }
}
