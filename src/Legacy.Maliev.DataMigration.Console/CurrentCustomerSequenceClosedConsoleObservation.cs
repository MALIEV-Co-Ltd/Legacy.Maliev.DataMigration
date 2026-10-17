using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

// Every authorization/source/policy/fleet/reservation operation delegates to the
// actual closed environment. This sealed observer is reachable only in enum3.
internal sealed class CurrentCustomerSequenceClosedConsoleObservation : ICurrentCustomerSequenceRepairEnvironment,
    ICurrentCustomerSequenceCandidateProofObserver, ICurrentCustomerSequenceClosedCommitObserver, IAsyncDisposable
{
    private readonly CurrentCustomerSequenceRepairConsoleEnvironment _actual;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly CurrentCustomerSequenceRepairScope _scope;
    private readonly string _root, _connection;
    private ClosedCommitProxy? _proxy;
    private readonly bool _applying;
    private int _ordinal;
    private bool _fleetFaultUsed;
    internal string WriterConnectionString { get; private set; }
    internal CurrentCustomerSequenceClosedConsoleObservation(CurrentCustomerSequenceRepairConsoleEnvironment actual,
        CurrentAppOwnedRepairCustody files, CurrentCustomerSequenceRepairScope scope, string root, string connection, bool applying)
    {
        CurrentCustomerSequenceClosedBootstrap.RequireBinding(scope.ClosedConsoleSeed ?? throw CurrentCustomerSequenceRepairPermit.Invalid(), scope);
        var endpoint = new NpgsqlConnectionStringBuilder(connection);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 || endpoint.Username != scope.Maintenance.Role ||
            endpoint.Pooling || endpoint.SslMode != SslMode.Disable || string.IsNullOrWhiteSpace(endpoint.Password) || !string.IsNullOrEmpty(endpoint.Options))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        _actual = actual; _files = files; _scope = scope; _root = root; _connection = connection;
        WriterConnectionString = connection; _applying = applying;
    }
    internal async Task CreateWriterAfterActualAdmissionAsync(CurrentCustomerSequenceRepairPermit permit, CancellationToken ct)
    {
        if (!_applying || permit.Scope.OperationSha256 != _scope.OperationSha256 || !ReferenceEquals(permit.Environment, this))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        await permit.RequireAsync(ct).ConfigureAwait(false);
        if (_scope.ClosedConsoleSeed!.CaseId == "lost-commit-ack")
        {
            if (_proxy is not null) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            var endpoint = new NpgsqlConnectionStringBuilder(_connection);
            _proxy = new ClosedCommitProxy(endpoint.Port, _scope.ClosedConsoleSeed.ExpiresAtUtc, RecordAsync);
            endpoint.Port = _proxy.Port; WriterConnectionString = endpoint.ConnectionString;
            await RecordInitialAsync(ct).ConfigureAwait(false);
        }
    }
    public Task RequireSourceAsync(string sha, CancellationToken ct)
    {
        return _actual.RequireSourceAsync(sha, ct);
    }

    public Task<CurrentCustomerSequenceSource> ObserveCurrentCatalogAsync(string sha, CancellationToken ct)
    {
        return _actual.ObserveCurrentCatalogAsync(sha, ct);
    }

    public Task<CurrentCustomerSequenceOwner> ObserveOwnerAsync(CancellationToken ct)
    {
        return _actual.ObserveOwnerAsync(ct);
    }

    public Task<CurrentCustomerSequenceObservation> ObserveNativeBeforeAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
    {
        return _actual.ObserveNativeBeforeAsync(scope, ct);
    }

    public Task RequireSource23PhysicalBaselineAsync(FreshSchemaPlan source, CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
    {
        return _actual.RequireSource23PhysicalBaselineAsync(source, scope, ct);
    }

    public Task RequireResourceAndCustodyAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
    {
        return _actual.RequireResourceAndCustodyAsync(scope, ct);
    }

    public Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
    {
        return _actual.InspectFleetAsync(scope, ct);
    }

    public Task RequireFreshOperationAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
    {
        return _actual.RequireFreshOperationAsync(scope, ct);
    }

    public Task ReserveFreshOperationAsync(CurrentCustomerSequenceRepairScope scope, string authorization, CancellationToken ct)
    {
        return _actual.ReserveFreshOperationAsync(scope, authorization, ct);
    }

    public async Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken ct)
    {
        await _actual.RetainNewEvidenceAsync(name, payload, ct).ConfigureAwait(false);
        if (name == _scope.OperationId.ToString("D") + "-Customer-committed-readback.json")
        {
            var receipt = JsonSerializer.Deserialize<CurrentCustomerSequenceRepairReceipt>(payload) ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
            if (receipt.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            await MutateFleetAfterTerminalAcknowledgedAsync(ct).ConfigureAwait(false);
        }
    }
    internal Task RecordInitialAsync(CancellationToken ct)
    {
        return _proxy is null ? Task.CompletedTask :
        RecordAsync("proxy-started", new
        {
            _proxy.Port,
            BackendPort = new NpgsqlConnectionStringBuilder(_connection).Port,
            _scope.OperationId,
            LoopbackOnly = true,
            _scope.ClosedConsoleSeed!.ExpiresAtUtc,
            BeganAtUtc = DateTimeOffset.UtcNow
        }, ct);
    }

    public async Task RetainActualCandidateAsync(CurrentCustomerSequenceObservation before, CurrentCustomerSequenceObservation candidate, CancellationToken ct)
    {
        ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, candidate, "legacy_local");
        await RecordAsync("locked-before", before, ct).ConfigureAwait(false);
        await RecordAsync("candidate", candidate, ct).ConfigureAwait(false);
    }
    internal async Task MutateFleetAfterTerminalAcknowledgedAsync(CancellationToken ct)
    {
        if (_scope.ClosedConsoleSeed!.CaseId == "final-fleet" && !_fleetFaultUsed)
        {
            _fleetFaultUsed = true;
            // Exact dedicated owned-fixture sentinel only; no public/source table is modified.
            var endpoint = new NpgsqlConnectionStringBuilder(_connection) { Database = "postgres", Pooling = false, Timeout = 5, CommandTimeout = 5 };
            await using var connection = new NpgsqlConnection(endpoint.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(ct).ConfigureAwait(false);
            await using var command = new NpgsqlCommand("UPDATE private.customer_closed_sentinel SET evidence='changed-during-candidate' WHERE id=1 AND evidence='unchanged';", connection, tx);
            if (await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false) != 1) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            await tx.CommitAsync(ct).ConfigureAwait(false);
            await RecordAsync("fleet-fault-committed", new { Database = "postgres", Relation = "private.customer_closed_sentinel", Count = 1, ObservedAtUtc = DateTimeOffset.UtcNow }, ct).ConfigureAwait(false);
        }
    }
    public async Task ArmImmediatelyBeforeCommitAsync(CancellationToken ct)
    {
        if (_scope.ClosedConsoleSeed!.CaseId != "lost-commit-ack") { return; }
        if (_proxy is null) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        await RecordAsync("proxy-armed", new { _proxy.Port, _scope.OperationId, ObservedAtUtc = DateTimeOffset.UtcNow }, ct).ConfigureAwait(false);
        _proxy.Arm();
    }
    private Task RecordAsync(string phase, object value, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false); _files.Require();
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        return bytes.Length > 8 * 1024 * 1024
            ? throw CurrentCustomerSequenceRepairPermit.Invalid()
            : _files.WriteNewAsync(Path.Combine(_root, $"customer-closed-{_scope.OperationId:N}-{Interlocked.Increment(ref _ordinal):D5}-{phase}.json"), bytes, ct);
    }
    public async ValueTask DisposeAsync()
    { if (_proxy is not null) { await _proxy.DisposeAsync().ConfigureAwait(false); } }

    private sealed class ClosedCommitProxy : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _life;
        private readonly Func<string, object, CancellationToken, Task> _record;
        private readonly Task _worker;
        private int _armed, _dropped;
        internal int Port { get; }
        internal ClosedCommitProxy(int backendPort, DateTimeOffset expires, Func<string, object, CancellationToken, Task> record)
        {
            TimeSpan remaining = expires - DateTimeOffset.UtcNow;
            if (backendPort is < 1 or > 65535 || remaining <= TimeSpan.Zero || remaining > TimeSpan.FromMinutes(8)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            _record = record; _life = new(remaining);
            try { _listener.Start(1); Port = ((IPEndPoint)_listener.LocalEndpoint).Port; _worker = RunAsync(backendPort); }
            catch { _listener.Stop(); _life.Dispose(); throw; }
        }
        internal void Arm() { if (Interlocked.CompareExchange(ref _armed, 1, 0) != 0 || Volatile.Read(ref _dropped) != 0) { throw CurrentCustomerSequenceRepairPermit.Invalid(); } }
        private async Task RunAsync(int backendPort)
        {
            try
            {
                while (!_life.IsCancellationRequested)
                {
                    using var client = await _listener.AcceptTcpClientAsync(_life.Token).ConfigureAwait(false);
                    using var server = new TcpClient(); await server.ConnectAsync(IPAddress.Loopback, backendPort, _life.Token).ConfigureAwait(false);
                    using var session = CancellationTokenSource.CreateLinkedTokenSource(_life.Token);
                    Task front = client.GetStream().CopyToAsync(server.GetStream(), session.Token);
                    Task back = RelayAsync(server.GetStream(), client.GetStream(), session.Token);
                    try { _ = await Task.WhenAny(front, back).ConfigureAwait(false); }
                    finally
                    {
                        await session.CancelAsync().ConfigureAwait(false); client.Close(); server.Close();
                        try { await Task.WhenAll(front, back).ConfigureAwait(false); }
                        catch (Exception failure) when (failure is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
                    }
                }
            }
            catch (Exception failure) when (_life.IsCancellationRequested && failure is OperationCanceledException or SocketException or ObjectDisposedException) { }
        }
        private async Task RelayAsync(NetworkStream server, NetworkStream client, CancellationToken ct)
        {
            byte[] header = new byte[5];
            while (true)
            {
                if (await server.ReadAsync(header.AsMemory(0, 1), ct).ConfigureAwait(false) == 0) { return; }
                await server.ReadExactlyAsync(header.AsMemory(1, 4), ct).ConfigureAwait(false);
                int length = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(1));
                if (length is < 4 or > 16 * 1024 * 1024) { throw new InvalidDataException("Invalid owned PostgreSQL frame."); }
                byte[] payload = new byte[length - 4]; await server.ReadExactlyAsync(payload, ct).ConfigureAwait(false);
                if (header[0] == (byte)'C' && payload.AsSpan().SequenceEqual("COMMIT\0"u8) && Interlocked.CompareExchange(ref _armed, 0, 1) == 1)
                {
                    int count = Interlocked.Increment(ref _dropped);
                    await _record("actual-commit-ack-dropped", new
                    {
                        Count = count,
                        ObservedAtUtc = DateTimeOffset.UtcNow,
                        PayloadSha256 = CurrentCustomerSequenceRepairPermit.Hash(payload)
                    }, ct).ConfigureAwait(false);
                    return;
                }
                await client.WriteAsync(header, ct).ConfigureAwait(false); await client.WriteAsync(payload, ct).ConfigureAwait(false);
            }
        }
        public async ValueTask DisposeAsync()
        {
            await _life.CancelAsync().ConfigureAwait(false); _listener.Stop();
            try { await _worker.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false); }
            finally { _life.Dispose(); }
            if (!_worker.IsCompleted || IPGlobalPropertiesHasPort(Port)) { throw new IOException("Owned Customer proxy cleanup not proven."); }
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await _record("proxy-disposed", new { Port, WorkerCompleted = true, ListenerAbsent = true, DroppedCommits = Volatile.Read(ref _dropped), CompletedAtUtc = DateTimeOffset.UtcNow }, deadline.Token).ConfigureAwait(false);
        }
        private static bool IPGlobalPropertiesHasPort(int port)
        {
            return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(x => x.Port == port);
        }
    }
}
