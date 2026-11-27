using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal enum CompanyStorageFaultCase { PreparedPublication = 1, LostCommitAcknowledgement = 2, TerminalPublication = 3, ReplayReservation = 4, FreshReconciliation = 5 }

internal sealed partial class CompanyStorageFaultControl : IAsyncDisposable
{
    private readonly CompanyStorageOwnedSession _session;
    private readonly CompanyStorageFaultCase _case;
    private readonly CompanyCommitProxy? _proxy;
    private FileStream? _denial;
    private Guid? _operation;
    private bool _disposed;
    internal int PublicationDenials { get; private set; }
    internal int PublicationHResult { get; private set; }
    internal int DroppedCommits => _proxy?.DroppedCommits ?? 0;
    internal int? ProxyPort => _proxy?.Port;
    internal ConsumerColumnBootstrapProxyCleanup? ProxyCleanup => _proxy?.Cleanup;
    private CompanyStorageFaultControl(CompanyStorageOwnedSession session, CompanyStorageFaultCase @case)
    {
        _session = session; _case = @case;
        if (@case == CompanyStorageFaultCase.LostCommitAcknowledgement) { _proxy = new(new NpgsqlConnectionStringBuilder(session.Lease.ConnectionString).Port, session.Lease.Maintenance.ExpiresAtUtc); }
    }
    internal static async Task<CompanyStorageFaultControl> CreateAsync(CompanyStorageOwnedSession session, CompanyStorageFaultCase @case, CompanyStorageOwnedConfiguration owned, CancellationToken ct)
    {
        await session.RequireAsync(ct);
        if (!Enum.IsDefined(@case) || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(session.Lease.Target)) { throw Invalid(); }
        var control = new CompanyStorageFaultControl(session, @case);
        try
        {
            if (control._proxy is not null)
            {
                using var authority = WindowsLocalRunAuthority.AcquireResume(owned.Binding.ArtifactRootCanonicalPath, owned.Binding);
                using var files = new CurrentAppOwnedRepairCustody(authority); using var process = System.Diagnostics.Process.GetCurrentProcess();
                await files.WriteNewAsync(Path.Combine(owned.Binding.ArtifactRootCanonicalPath, "company-owned-proxy-created.json"), System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
                {
                    Kind = "fixed-company-owned-proxy-created-v1",
                    owned.IntentId,
                    Case = @case,
                    ProcessId = process.Id,
                    ProcessStartedAtUtc = process.StartTime.ToUniversalTime(),
                    Executable = Environment.ProcessPath,
                    ExecutableSha256 = CurrentAuthTypedHostProducer.ImageHash(Environment.ProcessPath!),
                    Host = "127.0.0.1",
                    control._proxy.Port,
                    BackendPort = new NpgsqlConnectionStringBuilder(session.Lease.ConnectionString).Port,
                    control._proxy.ExpiresAtUtc,
                    session.Lease.ContainerId,
                    session.Lease.Volume,
                    PersistentData = false,
                    CreatedAtUtc = DateTimeOffset.UtcNow,
                }), ct);
            }
            return control;
        }
        catch (Exception primary)
        { try { await control.DisposeAsync(); } catch (Exception cleanup) { throw new AggregateException(primary, cleanup); } throw; }
    }
    internal bool IsOwnedBy(CompanyStorageOwnedSession session)
    {
        return !_disposed && ReferenceEquals(_session, session);
    }

    internal string Route(string direct)
    {
        var endpoint = new NpgsqlConnectionStringBuilder(direct); var actual = new NpgsqlConnectionStringBuilder(_session.Lease.ConnectionString);
        return _disposed || endpoint.Host != "127.0.0.1" || endpoint.Port != actual.Port || endpoint.Username != actual.Username || endpoint.Pooling || endpoint.SslMode != SslMode.Disable
            ? throw Invalid()
            : _proxy is null ? direct : new NpgsqlConnectionStringBuilder(direct) { Port = _proxy.Port }.ConnectionString;
    }
    internal async Task BindAsync(CompanyStorageRepairInputs input, Guid operation, CancellationToken ct)
    {
        if (_disposed || _operation is not null || input.Intent.Target != _session.Lease.Target || operation == Guid.Empty) { throw Invalid(); }
        await _session.RequireAsync(ct); _operation = operation;
        if (_case is CompanyStorageFaultCase.PreparedPublication or CompanyStorageFaultCase.TerminalPublication or CompanyStorageFaultCase.ReplayReservation)
        {
            string slot = _case == CompanyStorageFaultCase.TerminalPublication ? "committed-readback" : "prepared";
            string path = Path.Combine(input.Authority.Binding.ArtifactRootCanonicalPath, $"{operation:D}-Company-storage-{slot}.json");
            await input.Files.WriteNewAsync(path, [], ct); _denial = SecureLocalFile.OpenRead(path);
        }
        using var process = System.Diagnostics.Process.GetCurrentProcess();
        _ = await input.PublishAsync("owned-fault-control", new
        {
            Kind = "fixed-company-owned-fault-control-v1",
            Case = _case,
            OperationId = operation,
            ProcessId = process.Id,
            ProcessStartedAtUtc = process.StartTime.ToUniversalTime(),
            Executable = Environment.ProcessPath,
            _session.Lease.ContainerId,
            _session.Lease.Volume,
            ProxyPort,
            BackendPort = new NpgsqlConnectionStringBuilder(_session.Lease.ConnectionString).Port,
            _session.Lease.Maintenance.ExpiresAtUtc,
            PersistentData = false,
        }, operation, ct);
    }
    internal void PublicationFailed(string slot, Guid operation, IOException failure)
    {
        string expected = _case == CompanyStorageFaultCase.TerminalPublication ? "committed-readback" : "prepared";
        if (_disposed || _denial is null || operation != _operation || slot != expected || PublicationDenials != 0) { throw Invalid(); }
        PublicationDenials++; PublicationHResult = failure.HResult;
    }
    internal void Prepared(Guid operation)
    {
        if (_disposed || _operation != operation) { throw Invalid(); }
        if (_case == CompanyStorageFaultCase.LostCommitAcknowledgement) { (_proxy ?? throw Invalid()).Arm(); }
    }
    internal void ReleaseDenial() { _denial?.Dispose(); _denial = null; }
    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true; ReleaseDenial();
        if (_proxy is not null) { await _proxy.DisposeAsync(); }
    }
    private static MigrationExecutionException Invalid()
    {
        return CompanyStorageRepairProtocol.Invalid();
    }
}
