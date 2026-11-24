using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CurrentAuthLocalSessionArchiveEnvironment
{
    private OwnedCommitProxy? _ownedCommitProxy;

    internal async Task<OwnedCommitProxy> OpenOwnedCommitProxyAsync(CurrentAuthArchiveGenuineExecutionIssuer.CommitProxyFactory factory, CancellationToken ct)
    {
        if (_ownedCommitProxy is not null || _genuineDenial is not null || _reserved || _failed || _scope.ComponentSubject?.Seed.CaseId != "commit-ack-lost")
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        await RequireAcceptedSourceOwnerCustodyAndTargetsAsync(_scope, ct);
        factory.RequireOwner(this, _scope, _authorization);
        var proxy = await OwnedCommitProxy.CreateOwnedAsync(this, factory, ct);
        _ownedCommitProxy = proxy; return proxy;
    }

    // Only this fixed object, created from its owning Env's private direct endpoint, can be a writer transport.
    internal sealed class OwnedCommitProxy : IAsyncDisposable
    {
        private readonly CurrentAuthLocalSessionArchiveEnvironment _owner;
        private readonly CurrentAuthArchiveGenuineExecutionIssuer.CommitProxyFactory _factory;
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _lifetime;
        private readonly DateTimeOffset _created, _expires, _processStart;
        private readonly int _pid, _upstream;
        private readonly string _image, _imageSha;
        private readonly Task _worker;
        private TcpClient? _client, _server;
        private int _accepted, _backend, _armed, _dropped;
        private long _armedTicks, _droppedTicks;
        private bool _closed, _settled, _listenerAbsent, _clientsAbsent;
        private DateTimeOffset? _closedAt;
        internal int Port { get; }

        private OwnedCommitProxy(CurrentAuthLocalSessionArchiveEnvironment owner,
            CurrentAuthArchiveGenuineExecutionIssuer.CommitProxyFactory factory, CancellationToken ct)
        {
            _owner = owner; _factory = factory; _created = DateTimeOffset.UtcNow; _expires = owner._scope.ExpiresAtUtc;
            factory.RequireOwner(owner, owner._scope, owner._authorization);
            var direct = RequireEndpoint(owner._localConnection, owner._scope.LocalObservationPolicy);
            if (direct.SslMode != SslMode.Disable || direct.Pooling || _expires <= _created || _expires - _created > TimeSpan.FromMinutes(8))
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            _upstream = direct.Port;
            using var process = Process.GetCurrentProcess(); _pid = process.Id; _processStart = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
            _image = process.MainModule?.FileName ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid(); _imageSha = CurrentAuthTypedHostProducer.ImageHash(_image);
            _lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct); _lifetime.CancelAfter(_expires - _created);
            _listener.Start(1); Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            if (Port == _upstream) { _listener.Stop(); _lifetime.Dispose(); throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            _worker = RunAsync();
        }

        internal static async Task<OwnedCommitProxy> CreateOwnedAsync(CurrentAuthLocalSessionArchiveEnvironment owner,
            CurrentAuthArchiveGenuineExecutionIssuer.CommitProxyFactory factory, CancellationToken ct)
        {
            factory.ReserveProxy(owner, owner._scope, owner._authorization); owner._localFiles.Require();
            var proxy = new OwnedCommitProxy(owner, factory, ct);
            try { await proxy.RecordAsync("created", ct); return proxy; }
            catch (Exception primary)
            { try { await proxy.DisposeAsync(); } catch (Exception cleanup) { primary.Data["commit_proxy_cleanup_failure"] = cleanup.GetType().Name; } throw; }
        }

        internal CurrentAuthArchiveGenuineCommitProxyInfo Observe()
        {
            _owner._localAuthority.ValidateHeld(); _owner._productionAuthority.ValidateHeld(); _owner._localFiles.Require();
            using var process = Process.GetCurrentProcess();
            if (process.Id != _pid || new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero) != _processStart ||
                CurrentAuthTypedHostProducer.ImageHash(_image) != _imageSha) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            if (!_closed) { _factory.RequireOwner(_owner, _owner._scope, _owner._authorization); }
            return new(_owner._scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(_owner._scope), _owner._authorization,
                _owner._scope.LocalObservationPolicy.Maintenance.Role, _upstream, Port, _pid, _processStart, _imageSha, _created, _expires,
                Volatile.Read(ref _accepted), Volatile.Read(ref _backend), Volatile.Read(ref _armed) != 0, Volatile.Read(ref _dropped),
                _armedTicks == 0 ? null : new DateTimeOffset(_armedTicks, TimeSpan.Zero),
                _droppedTicks == 0 ? null : new DateTimeOffset(_droppedTicks, TimeSpan.Zero), _closed, _settled, _listenerAbsent, _clientsAbsent, _closedAt, _owner);
        }

        internal void Arm(int backendPid)
        {
            var value = Observe();
            if (_closed || DateTimeOffset.UtcNow >= _expires || value.AcceptedSessions != 1 || backendPid <= 0 || backendPid != value.BackendPid ||
                value.DroppedCommits != 0 || Interlocked.CompareExchange(ref _armed, 1, 0) != 0) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            _ = Interlocked.Exchange(ref _armedTicks, DateTimeOffset.UtcNow.UtcTicks);
        }
        internal CurrentAuthArchiveGenuineCommitProxyInfo RequirePostFailure()
        {
            _factory.RequireOwner(_owner, _owner._scope, _owner._authorization);
            var info = Observe(); CurrentAuthArchiveGenuineCommitFacts.RequireSettled(info, _owner._scope, _owner._authorization); return info;
        }

        private async Task RunAsync()
        {
            try
            {
                using var client = await _listener.AcceptTcpClientAsync(_lifetime.Token); _client = client;
                _listener.Stop();
                if (Interlocked.Increment(ref _accepted) != 1) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                using var server = new TcpClient(); _server = server; await server.ConnectAsync(IPAddress.Loopback, _upstream, _lifetime.Token);
                using var session = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
                Task frontend = FrontendAsync(client.GetStream(), server.GetStream(), session.Token);
                Task backend = BackendAsync(server.GetStream(), client.GetStream(), session.Token);
                try { _ = await Task.WhenAny(frontend, backend); }
                finally
                {
                    await session.CancelAsync(); client.Close(); server.Close();
                    try { await Task.WhenAll(frontend, backend); }
                    catch (Exception failure) when (failure is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
                }
            }
            catch (Exception failure) when (_lifetime.IsCancellationRequested && failure is OperationCanceledException or SocketException or ObjectDisposedException) { }
            finally { _client?.Close(); _server?.Close(); _listener.Stop(); }
        }

        private static async Task FrontendAsync(NetworkStream source, NetworkStream destination, CancellationToken ct)
        {
            byte[] length = new byte[4]; await source.ReadExactlyAsync(length, ct);
            int size = BinaryPrimitives.ReadInt32BigEndian(length);
            if (size is < 8 or > 65536) { throw new InvalidDataException("owned_commit_startup_frame_invalid"); }
            byte[] startup = new byte[size - 4];
            try
            {
                await source.ReadExactlyAsync(startup, ct);
                if (BinaryPrimitives.ReadInt32BigEndian(startup) != 196608) { throw new InvalidDataException("owned_commit_startup_protocol_invalid"); }
                await destination.WriteAsync(length, ct); await destination.WriteAsync(startup, ct);
            }
            finally { CryptographicOperations.ZeroMemory(startup); }
            await RelayAsync(source, destination, null, ct);
        }
        private Task BackendAsync(NetworkStream source, NetworkStream destination, CancellationToken ct)
        {
            return RelayAsync(source, destination, this, ct);
        }

        private static async Task RelayAsync(NetworkStream source, NetworkStream destination, OwnedCommitProxy? backendOwner, CancellationToken ct)
        {
            byte[] header = new byte[5];
            while (true)
            {
                if (await source.ReadAsync(header.AsMemory(0, 1), ct) == 0) { return; }
                await source.ReadExactlyAsync(header.AsMemory(1, 4), ct); int length = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(1));
                if (length is < 4 or > 16 * 1024 * 1024) { throw new InvalidDataException("owned_commit_frame_invalid"); }
                byte[] payload = new byte[length - 4];
                try
                {
                    await source.ReadExactlyAsync(payload, ct);
                    if (backendOwner is not null && header[0] == (byte)'K')
                    {
                        if (payload.Length != 8 || Interlocked.CompareExchange(ref backendOwner._backend, BinaryPrimitives.ReadInt32BigEndian(payload), 0) != 0 ||
                            Volatile.Read(ref backendOwner._backend) <= 0) { throw new InvalidDataException("owned_commit_backend_invalid"); }
                    }
                    if (backendOwner is not null && CurrentAuthArchiveGenuineCommitFacts.IsCommitCompletion(header[0], payload) &&
                        Interlocked.CompareExchange(ref backendOwner._armed, 0, 1) == 1)
                    { _ = Interlocked.Increment(ref backendOwner._dropped); _ = Interlocked.Exchange(ref backendOwner._droppedTicks, DateTimeOffset.UtcNow.UtcTicks); return; }
                    await destination.WriteAsync(header, ct); await destination.WriteAsync(payload, ct);
                }
                finally { CryptographicOperations.ZeroMemory(payload); }
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (_closed) { return; }
            _closed = true;
            Exception? primary = null;
            try
            {
                await _lifetime.CancelAsync(); _client?.Close(); _server?.Close(); _listener.Stop();
                await _worker.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None); _settled = _worker.IsCompleted;
                _listenerAbsent = !IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(endpoint => endpoint.Port == Port);
                _clientsAbsent = !IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections().Any(connection =>
                    (connection.LocalEndPoint.Port == Port || connection.RemoteEndPoint.Port == Port) && connection.State is not (TcpState.TimeWait or TcpState.Closed or TcpState.DeleteTcb));
                _closedAt = DateTimeOffset.UtcNow;
                if (!_settled || !_listenerAbsent || !_clientsAbsent) { throw new IOException("owned_commit_proxy_not_settled"); }
                _ = Observe();
            }
            catch (Exception failure) { primary = failure; throw; }
            finally
            {
                try { await RecordAsync("disposed", CancellationToken.None); }
                catch (Exception cleanup) when (primary is not null) { primary.Data["commit_proxy_retention_failure"] = cleanup.GetType().Name; }
                finally { _lifetime.Dispose(); }
            }
        }
        private Task RecordAsync(string phase, CancellationToken ct)
        {
            return _owner._localFiles.WriteNewAsync(
            Path.Combine(_owner._localAuthority.Binding.ArtifactRootCanonicalPath, $"genuine-commit-proxy-{_owner._scope.OperationId:N}-{phase}.json"),
            JsonSerializer.SerializeToUtf8Bytes(Observe()), ct);
        }
    }
}
