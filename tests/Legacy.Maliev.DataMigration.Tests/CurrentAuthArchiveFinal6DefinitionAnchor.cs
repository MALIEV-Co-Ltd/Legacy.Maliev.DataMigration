using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// The definition target is a real BEFORE-C owned disposable. The intended archive targets remain separate AFTER-C observations.
internal sealed class CurrentAuthArchiveFinal6DefinitionAnchor : ICurrentAuthArchiveDefinitionAnchorLease
{
    private readonly CurrentAuthNamedClosedFixture _fixture;
    private readonly CurrentAuthArchiveDefinitionAnchorOwner _owner;
    private readonly CurrentAuthArchiveFinal6SourceCapture.Captured _capture;
    private readonly byte[] _intent;
    private readonly byte[] _source;
    private int _disposed;
    public CurrentAuthRepairScope Intent => MigrationConsole.DecodeAuthRepair<CurrentAuthRepairScope>(_intent);
    public LocalExecutionBinding Binding => _fixture.Binding;
    public string SourcePath => Path.Combine(_fixture.Root, "archive-definition-source.json");

    private CurrentAuthArchiveFinal6DefinitionAnchor(CurrentAuthNamedClosedFixture fixture, CurrentAuthArchiveDefinitionAnchorOwner owner,
        CurrentAuthArchiveFinal6SourceCapture.Captured capture, CurrentAuthRepairScope intent, byte[] source)
    { _fixture = fixture; _owner = owner; _capture = capture; _intent = JsonSerializer.SerializeToUtf8Bytes(intent); _source = source; }

    internal static async Task<ICurrentAuthArchiveDefinitionAnchorLease> CreateAsync(CurrentAuthArchiveDefinitionAnchorOwner owner,
        CurrentAuthArchiveFinal6SourceCapture.Captured capture, CancellationToken ct)
    {
        owner.RequireForFixture(); await capture.RequireAsync(ct);
        var source = MigrationConsole.DecodeAuthRepair<FreshSchemaPlan>(JsonSerializer.SerializeToUtf8Bytes(capture.Evidence.Capture.Plan));
        CurrentAuthNamedClosedFixture? fixture = null;
        try
        {
            fixture = await CurrentAuthNamedClosedFixture.CreateDefinitionAnchorAsync(owner, ct);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, fixture.Token);
            using var authority = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            byte[] sourceBytes = JsonSerializer.SerializeToUtf8Bytes(source);
            string sourcePath = Path.Combine(fixture.Root, "archive-definition-source.json");
            await files.WriteNewAsync(sourcePath, sourceBytes, deadline.Token);
            var state = await CurrentAuthClosedTemplate.PrepareFinal6Async(files, fixture.Binding, fixture.Operation, fixture.ContainerId,
                capture, fixture.AdminConnection, deadline.Token);
            await CurrentAuthClosedTemplate.InstallPolicyAsync(files, fixture.Binding, state, fixture.AdminConnection, "success", deadline.Token);
            var native = await CurrentAuthClosedTemplate.CaptureAsync(files, fixture.Binding, state, source, unsafePolicyFixture: false, deadline.Token);
            var intent = new CurrentAuthRepairScope(fixture.Operation, CurrentAuthRepairOperation.SixteenSameTypeTextCollations,
                source.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(source), ApprovedCurrentAuthSchema.AuthServiceCommit,
                CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256, ApprovedCurrentAuthSchema.PhysicalSha256(false),
                ApprovedCurrentAuthSchema.PhysicalSha256(true), string.Empty, string.Empty, CurrentAuthRepairPermit.MaintenanceValidator,
                native.Target, "local-aspire", "legacy-postgres-main-local", state.TargetGeneration,
                CurrentAppOwnedSnapshotSerialization.Sha256(native.TargetPins), fixture.Binding.ComputeSha256(), native.BeforeDatabaseSha256,
                native.FleetSha256, string.Empty, string.Empty, string.Empty, native.Maintenance, CurrentAuthProofAdmission.DisposableNativeBootstrap);
            CurrentAuthRepairPermit.RequireProofAdmission(intent);
            await files.WriteNewAsync(Path.Combine(fixture.Root, "archive-definition-intent.json"), JsonSerializer.SerializeToUtf8Bytes(intent), deadline.Token);
            await capture.RequireAsync(deadline.Token);
            var result = new CurrentAuthArchiveFinal6DefinitionAnchor(fixture, owner, capture, intent, sourceBytes);
            fixture = null; return result;
        }
        catch (Exception primary)
        {
            try { if (fixture is not null) { await fixture.DisposeAsync(); } }
            catch (Exception cleanup) { throw new AggregateException("The definition anchor preparation failed and its exact cleanup also failed.", primary, cleanup); }
            throw;
        }
    }

    public async Task RequireAsync(CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        _fixture.Token.ThrowIfCancellationRequested(); _owner.RequireForFixture(); await _capture.RequireAsync(ct);
        using var authority = WindowsLocalRunAuthority.AcquireResume(_fixture.Root, _fixture.Binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        if (!files.Read(SourcePath, sharedReader: true, maximumBytes: 32 * 1024 * 1024).AsSpan().SequenceEqual(_source) ||
            !files.Read(Path.Combine(_fixture.Root, "archive-definition-intent.json"), sharedReader: true, maximumBytes: 1024 * 1024).AsSpan().SequenceEqual(_intent))
        { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) { return; }
        await _fixture.DisposeAsync();
        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await _owner.RequireAbsentAfterOwnerAsync(cleanup.Token);
    }
}
