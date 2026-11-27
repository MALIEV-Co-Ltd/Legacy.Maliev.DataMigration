using System.Net;
using System.Net.Sockets;
using System.Buffers.Binary;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record OrderSubtotalProxySession(int ClientLocal, int ClientRemote, int BackendLocal, int BackendRemote,
    bool ClientHandleClosed, bool BackendHandleClosed, bool RelaysStarted, bool RelaysJoined);
internal sealed record OrderSubtotalProxyConnection(int LocalPort, int RemotePort, string State);
internal sealed record OrderSubtotalProxyCleanup(int Port, bool WorkerJoined, IReadOnlyList<OrderSubtotalProxySession> Sessions,
    IReadOnlyList<OrderSubtotalProxyConnection> Remaining, DateTimeOffset ObservedAtUtc);

internal sealed partial class OrderSubtotalRuntime
{
    private sealed class OrderCommitProxy : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _lifetime;
        private readonly Task _worker;
        private readonly List<OwnedSession> _sessions = [];
        private int _armed, _dropped;
        private int _backendPid;
        private bool _disposed;
        internal OrderSubtotalProxyCleanup? Cleanup { get; private set; }
        private sealed class OwnedSession(System.Runtime.InteropServices.SafeHandle client, System.Runtime.InteropServices.SafeHandle backend)
        {
            internal System.Runtime.InteropServices.SafeHandle Client { get; } = client;
            internal System.Runtime.InteropServices.SafeHandle Backend { get; set; } = backend;
            internal int ClientLocal, ClientRemote, BackendLocal, BackendRemote;
            internal bool RelaysStarted, RelaysJoined;
        }
        internal int Port { get; }
        internal DateTimeOffset ExpiresAtUtc { get; }
        internal int DroppedCommits => Volatile.Read(ref _dropped);
        internal OrderCommitProxy(int backendPort, DateTimeOffset expiresAtUtc)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (expiresAtUtc <= now || expiresAtUtc > now.AddMinutes(8)) { throw Invalid(); }
            ExpiresAtUtc = expiresAtUtc; _lifetime = new(expiresAtUtc - now);
            try { _listener.Start(1); Port = ((IPEndPoint)_listener.LocalEndpoint).Port; _worker = RunAsync(backendPort); }
            catch { _listener.Stop(); _lifetime.Dispose(); throw; }
        }
        internal async Task ArmAsync(Npgsql.NpgsqlConnection writer, Npgsql.NpgsqlTransaction transaction, CancellationToken ct)
        {
            var endpoint = new Npgsql.NpgsqlConnectionStringBuilder(writer.ConnectionString);
            await using var query = new Npgsql.NpgsqlCommand("SELECT pg_backend_pid();", writer, transaction);
            if (_disposed || endpoint.Host != "127.0.0.1" || endpoint.Port != Port || endpoint.Pooling ||
                await query.ExecuteScalarAsync(ct).ConfigureAwait(false) is not int pid || pid != Volatile.Read(ref _backendPid) ||
                Interlocked.CompareExchange(ref _armed, 1, 0) != 0) { throw Invalid(); }
        }
        private async Task RunAsync(int backendPort)
        {
            try
            {
                if (!_lifetime.IsCancellationRequested)
                {
                    using var client = await _listener.AcceptTcpClientAsync(_lifetime.Token).ConfigureAwait(false);
                    _listener.Stop();
                    _listener.Stop(); // Exactly one writer session; no reaccept/retry can consume the fault twice.
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
                    return;
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
                if (header[0] == (byte)'K')
                {
                    if (payload.Length != 8 || Interlocked.CompareExchange(ref _backendPid, BinaryPrimitives.ReadInt32BigEndian(payload.AsSpan(0, 4)), 0) != 0) { throw Invalid(); }
                    // Only the backend PID is retained. The cancel secret remains transient and is cleared below.
                }
                if (header[0] == (byte)'C' && payload.AsSpan().SequenceEqual("COMMIT\0"u8) && Interlocked.CompareExchange(ref _armed, 0, 1) == 1)
                { System.Security.Cryptography.CryptographicOperations.ZeroMemory(payload); _ = Interlocked.Increment(ref _dropped); return; }
                try { await client.WriteAsync(header, ct).ConfigureAwait(false); await client.WriteAsync(payload, ct).ConfigureAwait(false); }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(payload); }
            }
        }
        public async ValueTask DisposeAsync()
        {
            if (_disposed) { return; }
            _disposed = true;
            await _lifetime.CancelAsync().ConfigureAwait(false); _listener.Stop();
            try { await _worker.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false); }
            finally { _lifetime.Dispose(); }
            if (!_worker.IsCompleted || System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(endpoint => endpoint.Port == Port)) { throw Invalid(); }
            var sessions = _sessions.Select(session => new OrderSubtotalProxySession(session.ClientLocal, session.ClientRemote,
                session.BackendLocal, session.BackendRemote, session.Client.IsClosed, session.Backend.IsClosed, session.RelaysStarted, session.RelaysJoined)).ToArray();
            if (sessions.Any(session => !session.ClientHandleClosed || !session.BackendHandleClosed || (session.RelaysStarted && !session.RelaysJoined))) { throw Invalid(); }
            OrderSubtotalProxyConnection[] remaining = ObserveOwnedConnections();
            DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(2);
            while (remaining.Any(connection => connection.State is not ("TimeWait" or "Closed")) && DateTimeOffset.UtcNow < deadline)
            { await Task.Delay(50).ConfigureAwait(false); remaining = ObserveOwnedConnections(); }
            Cleanup = new(Port, _worker.IsCompleted, sessions, remaining, DateTimeOffset.UtcNow);
            if (remaining.Any(connection => connection.State is not ("TimeWait" or "Closed"))) { throw Invalid(); }

            OrderSubtotalProxyConnection[] ObserveOwnedConnections()
            {
                return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()
                .Where(connection => IPAddress.IsLoopback(connection.LocalEndPoint.Address) && IPAddress.IsLoopback(connection.RemoteEndPoint.Address) && _sessions.Any(session => Pair(connection.LocalEndPoint.Port, connection.RemoteEndPoint.Port, session.ClientLocal, session.ClientRemote) ||
                    Pair(connection.LocalEndPoint.Port, connection.RemoteEndPoint.Port, session.BackendLocal, session.BackendRemote)))
                .Select(connection => new OrderSubtotalProxyConnection(connection.LocalEndPoint.Port, connection.RemoteEndPoint.Port, connection.State.ToString())).ToArray();
            }

            static bool Pair(int local, int remote, int first, int second)
            {
                return first > 0 && second > 0 && ((local == first && remote == second) || (local == second && remote == first));
            }
        }
    }
}
