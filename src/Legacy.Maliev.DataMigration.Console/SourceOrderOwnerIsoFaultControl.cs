using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal enum SourceOrderOwnerIsoFaultCase
{ PreparedPublication = 1, LostCommitAcknowledgement = 2, TerminalPublication = 3, PartialSecondDatabase = 4, FinalFleet = 5 }

internal sealed partial class SourceOrderOwnerIsoFaultControl : IAsyncDisposable
{
    private readonly SourceOrderOwnerIsoOwnedSession _session;
    private readonly SourceOrderOwnerIsoFaultCase _case;
    private readonly IsoCommitProxy? _proxy;
    private FileStream? _denial;
    private Guid? _operation;
    private bool _disposed;
    internal int PublicationDenials { get; private set; }
    internal int PublicationHResult { get; private set; }
    internal int DroppedCommits => _proxy?.DroppedCommits ?? 0;
    internal ConsumerColumnBootstrapProxyCleanup? ProxyCleanup => _proxy?.Cleanup;
    internal ConsumerColumnBootstrapUploadFaultWitness? UploadBefore { get; private set; }
    internal ConsumerColumnBootstrapUploadFaultWitness? UploadAfter { get; private set; }
    private SourceOrderOwnerIsoFaultControl(SourceOrderOwnerIsoOwnedSession session, SourceOrderOwnerIsoFaultCase @case)
    {
        _session = session; _case = @case;
        if (@case == SourceOrderOwnerIsoFaultCase.LostCommitAcknowledgement)
        { _proxy = new(new NpgsqlConnectionStringBuilder(session.Lease.ConnectionString).Port, session.Lease.Maintenance.ExpiresAtUtc); }
    }
    internal static async Task<SourceOrderOwnerIsoFaultControl> CreateAsync(SourceOrderOwnerIsoOwnedSession session,
        SourceOrderOwnerIsoFaultCase @case, SourceOrderOwnerIsoOwnedConfiguration owned, CancellationToken ct)
    {
        await session.RequireAsync(ct);
        if (!Enum.IsDefined(@case) || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(session.Lease.Target)) { throw Invalid(); }
        var control = new SourceOrderOwnerIsoFaultControl(session, @case);
        try
        {
            if (control._proxy is not null)
            {
                using var authority = WindowsLocalRunAuthority.AcquireResume(owned.Binding.ArtifactRootCanonicalPath, owned.Binding);
                using var files = new CurrentAppOwnedRepairCustody(authority); using var process = System.Diagnostics.Process.GetCurrentProcess();
                await files.WriteNewAsync(Path.Combine(owned.Binding.ArtifactRootCanonicalPath, "source-order-iso-owned-proxy-created.json"), System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
                {
                    Kind = "source-order-owner-iso-owned-proxy-created-v1",
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
    internal bool IsOwnedBy(SourceOrderOwnerIsoOwnedSession session)
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
    internal async Task BindAsync(SourceOrderOwnerIsoInputs input, SourceOrderOwnerIsoScope scope, CancellationToken ct)
    {
        if (_disposed || _operation is not null || input.Intent.Target != _session.Lease.Target || scope.OperationId == Guid.Empty ||
            !scope.PendingDatabases.SequenceEqual(SourceOrderOwnerIsoProtocol.Databases, StringComparer.Ordinal)) { throw Invalid(); }
        await _session.RequireAsync(ct); _operation = scope.OperationId;
        if (_case is SourceOrderOwnerIsoFaultCase.PreparedPublication or SourceOrderOwnerIsoFaultCase.TerminalPublication or SourceOrderOwnerIsoFaultCase.PartialSecondDatabase)
        {
            string database = _case == SourceOrderOwnerIsoFaultCase.PartialSecondDatabase ? "Material" : "Country";
            string slot = _case == SourceOrderOwnerIsoFaultCase.TerminalPublication ? "committed-readback" : "prepared";
            string path = Path.Combine(input.Authority.Binding.ArtifactRootCanonicalPath, $"{scope.OperationId:D}-SourceOrderIso-{database}-{slot}.json");
            await input.Files.WriteNewAsync(path, [], ct); _denial = SecureLocalFile.OpenRead(path);
        }
        using var process = System.Diagnostics.Process.GetCurrentProcess();
        _ = await input.PublishAsync("owned-fault-control", new
        {
            Kind = "source-order-iso-owned-fault-control-v1",
            Case = _case,
            scope.OperationId,
            ProcessId = process.Id,
            ProcessStartedAtUtc = process.StartTime.ToUniversalTime(),
            Executable = Environment.ProcessPath,
            _session.Lease.ContainerId,
            _session.Lease.Volume,
            ProxyPort = _proxy?.Port,
            BackendPort = new NpgsqlConnectionStringBuilder(_session.Lease.ConnectionString).Port,
            _session.Lease.Maintenance.ExpiresAtUtc,
            PersistentData = false,
        }, scope.OperationId, ct);
    }
    internal void PublicationFailed(string database, string slot, IOException failure)
    {
        string expectedDb = _case == SourceOrderOwnerIsoFaultCase.PartialSecondDatabase ? "Material" : "Country";
        string expectedSlot = _case == SourceOrderOwnerIsoFaultCase.TerminalPublication ? "committed-readback" : "prepared";
        if (_disposed || _denial is null || database != expectedDb || slot != expectedSlot || PublicationDenials != 0) { throw Invalid(); }
        PublicationDenials++; PublicationHResult = failure.HResult;
    }
    internal void Prepared(Guid operation, string database)
    {
        if (_disposed || _operation != operation) { throw Invalid(); }
        if (_case == SourceOrderOwnerIsoFaultCase.LostCommitAcknowledgement && database == "Country") { (_proxy ?? throw Invalid()).Arm(); }
    }
    internal async Task BeforeFinalFleetAsync(SourceOrderOwnerIsoInputs input, CancellationToken ct)
    {
        if (_case != SourceOrderOwnerIsoFaultCase.FinalFleet) { return; }
        if (_disposed || _operation is null || input.Intent.Target != _session.Lease.Target) { throw Invalid(); }
        await _session.RequireAsync(ct);
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_session.Lease.ConnectionString) { Database = "Upload" }.ConnectionString);
        await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct);
        await CompanyStorageRuntime.RequirePolicyAsync(connection, tx, _session.Lease.Maintenance, _session.Lease.Target, ct);
        UploadBefore = await ConsumerColumnBootstrapUploadFaultPreservation.CaptureAsync(connection, tx, ct);
        await using var command = new NpgsqlCommand(ConsumerColumnBootstrapUploadFaultPreservation.MutationSql, connection, tx);
        int affected = await command.ExecuteNonQueryAsync(ct);
        UploadAfter = await ConsumerColumnBootstrapUploadFaultPreservation.CaptureAsync(connection, tx, ct);
        ConsumerColumnBootstrapUploadFaultPreservation.Require(UploadBefore, UploadAfter, affected); await tx.CommitAsync(ct);
        _ = await input.PublishAsync("owned-final-fleet-effect", new { AffectedRows = affected, Before = UploadBefore, After = UploadAfter }, _operation.Value, ct);
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
        return SourceOrderOwnerIsoProtocol.Invalid();
    }
}
