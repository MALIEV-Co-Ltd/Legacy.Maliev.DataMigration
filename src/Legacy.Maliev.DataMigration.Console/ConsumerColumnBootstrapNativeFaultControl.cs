using System.Net;
using System.Net.Sockets;
using System.Buffers.Binary;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal enum ConsumerColumnBootstrapNativeFaultCase
{
    PreparedPublication = 1, LostCommitAcknowledgement = 2, TerminalPublication = 3, PartialThenForwardRecovery = 4, FinalFleet = 5,
}
internal sealed record ConsumerColumnBootstrapProxySessionCleanup(int ClientLocalPort, int ClientRemotePort, int BackendLocalPort, int BackendRemotePort,
    bool ClientHandleClosed, bool BackendHandleClosed, bool RelaysStarted, bool RelaysJoined);
internal sealed record ConsumerColumnBootstrapProxyConnection(int LocalPort, int RemotePort, string State);
internal sealed record ConsumerColumnBootstrapProxyCleanup(int Port, bool WorkerJoined, IReadOnlyList<ConsumerColumnBootstrapProxySessionCleanup> Sessions,
    IReadOnlyList<ConsumerColumnBootstrapProxyConnection> RemainingOwnedConnections, DateTimeOffset ObservedAtUtc);

/// <summary>Fixed controls attached only to the actual newly created disposable fixture.</summary>
internal sealed class ConsumerColumnBootstrapNativeFaultControl : IAsyncDisposable
{
    private readonly ConsumerColumnBootstrapProofFixture _fixture;
    private readonly Dictionary<(Guid Operation, string Database, ConsumerColumnBootstrapNativePhase Phase), ConsumerColumnBootstrapPreservationObservation> _native = [];
    private readonly HashSet<string> _committed = new(StringComparer.Ordinal);
    private FileStream? _denial;
    private OwnedCommitProxy? _proxy;
    private Guid? _forward;
    private bool _disposed;
    internal ConsumerColumnBootstrapNativeFaultCase Case { get; }
    internal int PublicationDenials { get; private set; }
    internal int ReservationDenials { get; private set; }
    internal int LastPublicationHResult { get; private set; }
    internal int LastReservationHResult { get; private set; }
    internal int DroppedCommits => _proxy?.DroppedCommits ?? 0;
    internal bool FinalFleetMutationExecuted { get; private set; }
    internal int FinalFleetAffectedRows { get; private set; }
    internal ConsumerColumnBootstrapUploadFaultWitness? UploadBefore { get; private set; }
    internal ConsumerColumnBootstrapUploadFaultWitness? UploadAfter { get; private set; }
    internal int? ProxyPort => _proxy?.Port;
    internal ConsumerColumnBootstrapProxyCleanup? ProxyCleanup => _proxy?.Cleanup;

    private ConsumerColumnBootstrapNativeFaultControl(ConsumerColumnBootstrapProofFixture fixture, ConsumerColumnBootstrapNativeFaultCase @case)
    { _fixture = fixture; Case = @case; }

    internal static async Task<ConsumerColumnBootstrapNativeFaultControl> CreateAsync(ConsumerColumnBootstrapProofFixture fixture,
        ConsumerColumnBootstrapNativeFaultCase @case, CurrentAppOwnedRepairCustody files, string executionRoot, CancellationToken ct)
    {
        if (!Enum.IsDefined(@case) || System.Reflection.Assembly.GetEntryAssembly() != typeof(ConsumerColumnBootstrapNativeFaultControl).Assembly)
        { throw Invalid(); }
        fixture.Require(fixture.OperationId, fixture.ExecutionBindingSha256, fixture.ContainerId, fixture.VolumeName, fixture.Cohort.ImageReference);
        files.Require();
        var control = new ConsumerColumnBootstrapNativeFaultControl(fixture, @case);
        try
        {
            if (@case == ConsumerColumnBootstrapNativeFaultCase.LostCommitAcknowledgement)
            {
                control._proxy = new OwnedCommitProxy(fixture.BackendPort);
                using var process = System.Diagnostics.Process.GetCurrentProcess();
                await files.WriteNewAsync(Path.Combine(executionRoot, $"consumer-bootstrap-{fixture.OperationId:N}-fault-proxy-created.json"),
                    System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
                    {
                        Kind = "owned-consumer-bootstrap-fault-proxy-v1",
                        fixture.OperationId,
                        ProcessId = process.Id,
                        ProcessStartedAtUtc = process.StartTime.ToUniversalTime(),
                        Executable = Environment.ProcessPath,
                        Host = "127.0.0.1",
                        control._proxy.Port,
                        fixture.BackendPort,
                        CreatedAtUtc = DateTimeOffset.UtcNow,
                        fixture.ExpiresAtUtc,
                        fixture.ContainerId,
                        fixture.VolumeName,
                        PersistentData = false
                    }), ct).ConfigureAwait(false);
            }
            else if (@case != ConsumerColumnBootstrapNativeFaultCase.FinalFleet)
            {
                string database = @case == ConsumerColumnBootstrapNativeFaultCase.PartialThenForwardRecovery ? "Quotation" : "CustomerIdentity";
                string phase = @case == ConsumerColumnBootstrapNativeFaultCase.TerminalPublication ? "committed-readback" : "prepared";
                string path = Path.Combine(executionRoot, $"consumer-bootstrap-{fixture.OperationId:N}-{database}-{phase}.json");
                await files.WriteNewAsync(path, [], ct).ConfigureAwait(false);
                control._denial = SecureLocalFile.OpenRead(path); // Actual exclusive OS handle; marker remains as fault evidence.
            }
            fixture.AttachFault(control); return control;
        }
        catch (Exception primary)
        {
            try { await control.DisposeAsync().ConfigureAwait(false); }
            catch (Exception cleanup) { throw new AggregateException("Fault control creation and cleanup failed.", primary, cleanup); }
            throw;
        }
    }

    internal bool IsOwnedBy(ConsumerColumnBootstrapProofFixture fixture)
    {
        return ReferenceEquals(fixture, _fixture) && !_disposed;
    }

    internal bool AcceptsOperation(Guid operation)
    {
        return !_disposed && _forward == operation;
    }

    internal bool AcceptsRecovery(ConsumerColumnBootstrapOperationalScope scope)
    {
        return AcceptsOperation(scope.OperationId) &&
            scope.Mode == ConsumerColumnBootstrapOperationalMode.OwnedForwardRecoveryCharacterization && scope.PendingDatabases.Count == 1 &&
            scope.PendingDatabases[0] == "Quotation" && scope.PreviouslyCompletedDatabaseSha256.Count == 1 && scope.PreviouslyCompletedDatabaseSha256.ContainsKey("CustomerIdentity");
    }

    internal void AuthorizeForward(Guid operation)
    {
        if (_disposed || Case != ConsumerColumnBootstrapNativeFaultCase.PartialThenForwardRecovery || _forward is not null || operation == Guid.Empty ||
            operation == _fixture.OperationId || _committed.Count != 1 || !_committed.Contains("CustomerIdentity") || PublicationDenials != 1) { throw Invalid(); }
        _forward = operation; ReleasePublicationDenial();
    }

    internal string Route(string direct)
    {
        var endpoint = new NpgsqlConnectionStringBuilder(direct);
        return _disposed || endpoint.Host != "127.0.0.1" || endpoint.Port != _fixture.BackendPort
            ? throw Invalid()
            : _proxy is null ? direct : new NpgsqlConnectionStringBuilder(direct) { Port = _proxy.Port, SslMode = SslMode.Disable }.ConnectionString;
    }
    internal int RequireDataPort(int port)
    {
        return _disposed || port != (_proxy?.Port ?? _fixture.BackendPort) ? throw Invalid() : _fixture.BackendPort;
    }
    internal void PublicationDenied(Guid operation, int hResult)
    { if (operation != _fixture.OperationId || _denial is null) { throw Invalid(); } PublicationDenials++; LastPublicationHResult = hResult; }
    internal void ReservationDenied(Guid operation, string path, int hResult)
    {
        if (_disposed || operation != _fixture.OperationId || Path.GetFileName(path) != $"consumer-bootstrap-{operation:N}-execution-reservation.json") { throw Invalid(); }
        ReservationDenials++; LastReservationHResult = hResult;
    }
    internal void RecordNative(ConsumerColumnBootstrapOperationalScope scope, ConsumerColumnBootstrapNativePhase phase, ConsumerColumnBootstrapPreservationObservation observation)
    {
        if (_disposed || (scope.OperationId != _fixture.OperationId && !AcceptsRecovery(scope)) ||
            !_native.TryAdd((scope.OperationId, observation.LogicalDatabase, phase), observation)) { throw Invalid(); }
    }
    internal ConsumerColumnBootstrapPreservationObservation Observation(Guid operation, string database, ConsumerColumnBootstrapNativePhase phase)
    {
        return _native.TryGetValue((operation, database, phase), out var result) ? result : throw Invalid();
    }

    internal object[] RetainedNativeFacts()
    {
        return _native.OrderBy(pair => pair.Key.Operation).ThenBy(pair => pair.Key.Database, StringComparer.Ordinal).ThenBy(pair => pair.Key.Phase)
            .Select(pair => (object)new { pair.Key.Operation, Witness = ConsumerColumnBootstrapNativeWitness.Capture(pair.Key.Phase, pair.Value) }).ToArray();
    }

    internal void ReceiptRetained(ConsumerColumnBootstrapOperationalScope scope, ConsumerColumnBootstrapOperationalReceipt receipt)
    {
        if (_disposed) { throw Invalid(); }
        if (scope.OperationId == _fixture.OperationId && receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback) { _ = _committed.Add(receipt.Database); }
        if (Case == ConsumerColumnBootstrapNativeFaultCase.LostCommitAcknowledgement && receipt.Database == "CustomerIdentity" &&
            receipt.Classification == CurrentAppOwnedCommitClassification.Prepared) { (_proxy ?? throw Invalid()).Arm(); }
    }
    internal async Task BeforeFleetAsync(ConsumerColumnBootstrapOperationalScope scope, CancellationToken ct)
    {
        if (_disposed) { throw Invalid(); }
        if (Case != ConsumerColumnBootstrapNativeFaultCase.FinalFleet || FinalFleetMutationExecuted || scope.OperationId != _fixture.OperationId || _committed.Count != 2) { return; }
        // Change exactly one owned synthetic probe row. All journals and sequences are unchanged.
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_fixture.OperatorDirectConnection) { Database = "Upload", Pooling = false }.ConnectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct).ConfigureAwait(false);
        await using (var locked = new NpgsqlCommand("LOCK TABLE legacy_migration_internal.\"BootstrapFleetProbe\" IN ACCESS EXCLUSIVE MODE;", connection, transaction))
        { _ = await locked.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
        UploadBefore = await ConsumerColumnBootstrapUploadFaultPreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
        if (UploadBefore.Snapshot.Sha256 != scope.BeforeDatabaseSha256["Upload"]) { throw Invalid(); }
        await using (var command = new NpgsqlCommand(ConsumerColumnBootstrapUploadFaultPreservation.MutationSql, connection, transaction))
        { FinalFleetAffectedRows = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
        UploadAfter = await ConsumerColumnBootstrapUploadFaultPreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
        ConsumerColumnBootstrapUploadFaultPreservation.Require(UploadBefore, UploadAfter, FinalFleetAffectedRows);
        await transaction.CommitAsync(ct).ConfigureAwait(false); FinalFleetMutationExecuted = true;
    }
    internal void ReleasePublicationDenial() { _denial?.Dispose(); _denial = null; }
    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true; ReleasePublicationDenial();
        if (_proxy is not null) { await _proxy.DisposeAsync().ConfigureAwait(false); }
    }
    private static MigrationExecutionException Invalid()
    {
        return ConsumerColumnBootstrapOperationalContract.Invalid();
    }

    private sealed class OwnedCommitProxy : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _lifetime = new(TimeSpan.FromMinutes(8));
        private readonly Task _worker;
        private readonly List<OwnedSession> _sessions = [];
        private int _armed, _dropped;
        internal ConsumerColumnBootstrapProxyCleanup? Cleanup { get; private set; }
        private sealed class OwnedSession(System.Runtime.InteropServices.SafeHandle client, System.Runtime.InteropServices.SafeHandle backend)
        {
            internal System.Runtime.InteropServices.SafeHandle Client { get; } = client;
            internal System.Runtime.InteropServices.SafeHandle Backend { get; set; } = backend;
            internal int ClientLocal, ClientRemote, BackendLocal, BackendRemote;
            internal bool RelaysStarted, RelaysJoined;
        }
        internal int Port { get; }
        internal int DroppedCommits => Volatile.Read(ref _dropped);
        internal OwnedCommitProxy(int backendPort)
        {
            try { _listener.Start(1); Port = ((IPEndPoint)_listener.LocalEndpoint).Port; _worker = RunAsync(backendPort); }
            catch { _listener.Stop(); _lifetime.Dispose(); throw; }
        }
        internal void Arm() { _ = Interlocked.Exchange(ref _armed, 1); }
        private async Task RunAsync(int backendPort)
        {
            try
            {
                while (!_lifetime.IsCancellationRequested)
                {
                    using var client = await _listener.AcceptTcpClientAsync(_lifetime.Token).ConfigureAwait(false);
                    using var server = new TcpClient();
                    var owned = new OwnedSession(client.Client.SafeHandle, server.Client.SafeHandle)
                    { ClientLocal = ((IPEndPoint)client.Client.LocalEndPoint!).Port, ClientRemote = ((IPEndPoint)client.Client.RemoteEndPoint!).Port };
                    _sessions.Add(owned);
                    try
                    {
                        await server.ConnectAsync(IPAddress.Loopback, backendPort, _lifetime.Token).ConfigureAwait(false);
                        owned.Backend = server.Client.SafeHandle;
                        owned.BackendLocal = ((IPEndPoint)server.Client.LocalEndPoint!).Port; owned.BackendRemote = backendPort;
                        using var session = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
                        Task frontend = client.GetStream().CopyToAsync(server.GetStream(), session.Token);
                        Task backend = RelayAsync(server.GetStream(), client.GetStream(), session.Token); owned.RelaysStarted = true;
                        try { _ = await Task.WhenAny(frontend, backend).ConfigureAwait(false); }
                        finally
                        {
                            await session.CancelAsync().ConfigureAwait(false); client.Close(); server.Close();
                            try { await Task.WhenAll(frontend, backend).ConfigureAwait(false); }
                            catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
                            finally { owned.RelaysJoined = frontend.IsCompleted && backend.IsCompleted; }
                        }
                    }
                    finally
                    {
                        client.Dispose(); server.Dispose();
                    }
                }
            }
            catch (Exception e) when (_lifetime.IsCancellationRequested && e is OperationCanceledException or SocketException or ObjectDisposedException) { }
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
                { _ = Interlocked.Increment(ref _dropped); return; }
                await client.WriteAsync(header, ct).ConfigureAwait(false); await client.WriteAsync(payload, ct).ConfigureAwait(false);
            }
        }
        public async ValueTask DisposeAsync()
        {
            await _lifetime.CancelAsync().ConfigureAwait(false); _listener.Stop();
            try { await _worker.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false); }
            finally { _lifetime.Dispose(); }
            if (!_worker.IsCompleted || System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(endpoint => endpoint.Port == Port)) { throw Invalid(); }
            var sessions = _sessions.Select(session => new ConsumerColumnBootstrapProxySessionCleanup(session.ClientLocal, session.ClientRemote,
                session.BackendLocal, session.BackendRemote, session.Client.IsClosed, session.Backend.IsClosed, session.RelaysStarted, session.RelaysJoined)).ToArray();
            if (sessions.Length == 0 || sessions.Any(session => !session.ClientHandleClosed || !session.BackendHandleClosed || (session.RelaysStarted && !session.RelaysJoined))) { throw Invalid(); }
            ConsumerColumnBootstrapProxyConnection[] remaining = ObserveOwnedConnections();
            DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(2);
            while (remaining.Any(connection => connection.State is not ("TimeWait" or "Closed")) && DateTimeOffset.UtcNow < deadline)
            { await Task.Delay(50).ConfigureAwait(false); remaining = ObserveOwnedConnections(); }
            Cleanup = new(Port, _worker.IsCompleted, sessions, remaining, DateTimeOffset.UtcNow);
            if (remaining.Any(connection => connection.State is not ("TimeWait" or "Closed"))) { throw Invalid(); }

            ConsumerColumnBootstrapProxyConnection[] ObserveOwnedConnections()
            {
                return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()
                .Where(connection => IPAddress.IsLoopback(connection.LocalEndPoint.Address) && IPAddress.IsLoopback(connection.RemoteEndPoint.Address) && _sessions.Any(session => Pair(connection.LocalEndPoint.Port, connection.RemoteEndPoint.Port, session.ClientLocal, session.ClientRemote) ||
                    Pair(connection.LocalEndPoint.Port, connection.RemoteEndPoint.Port, session.BackendLocal, session.BackendRemote)))
                .Select(connection => new ConsumerColumnBootstrapProxyConnection(connection.LocalEndPoint.Port, connection.RemoteEndPoint.Port, connection.State.ToString())).ToArray();
            }

            static bool Pair(int local, int remote, int first, int second)
            {
                return first > 0 && second > 0 && ((local == first && remote == second) || (local == second && remote == first));
            }
        }
    }
}

internal sealed partial class ConsumerColumnBootstrapProofFixture
{
    internal ConsumerColumnBootstrapNativeFaultControl? FaultControl { get; private set; }
    internal int BackendPort => _port ?? throw ConsumerColumnBootstrapOperationalContract.Invalid();
    internal string OperatorDirectConnection { get; private set; } = string.Empty;
    internal void AttachFault(ConsumerColumnBootstrapNativeFaultControl control)
    { if (FaultControl is not null || !control.IsOwnedBy(this)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); } FaultControl = control; }
    internal void BindFaultOperator(string connection)
    {
        var endpoint = new NpgsqlConnectionStringBuilder(connection);
        if (FaultControl is null || endpoint.Host != "127.0.0.1" || endpoint.Port != BackendPort || string.IsNullOrEmpty(endpoint.Password))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        OperatorDirectConnection = connection;
    }
    internal int RequireDataPort(int port)
    {
        return FaultControl?.RequireDataPort(port) ?? (port == BackendPort ? BackendPort : throw ConsumerColumnBootstrapOperationalContract.Invalid());
    }

    internal bool AcceptsRecovery(ConsumerColumnBootstrapOperationalScope scope)
    {
        return FaultControl?.AcceptsRecovery(scope) == true;
    }

    internal ConsumerColumnBootstrapCleanupEvidence ReadFaultCleanup()
    {
        return _disposed && FaultControl is not null && _cleanup is not null
            ? ConsumerColumnBootstrapOperationalContract.Copy(_cleanup) : throw ConsumerColumnBootstrapOperationalContract.Invalid();
    }
}
