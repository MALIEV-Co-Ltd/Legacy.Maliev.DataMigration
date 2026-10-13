using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

// Fixed admitted enum3 lost-COMMIT fixture resource. No supplied executable, callback,
// proxy port, upstream address, SSL negotiation, command or persistent target.
internal sealed class CurrentAuthClosedCommitProxy : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _lifetime;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly string _root;
    private readonly Task _worker;
    private readonly Guid _operation;
    private readonly int _processId;
    private readonly DateTimeOffset _processStart, _began, _expires;
    private readonly string _image, _imageSha;
    private int _armed, _dropped;
    private long _armedTicks, _droppedTicks;
    private bool _disposed;
    internal string ConnectionString { get; }
    internal int Port { get; }
    internal Guid Operation => _operation;
    internal int DroppedCount => Volatile.Read(ref _dropped);

    private CurrentAuthClosedCommitProxy(CurrentAuthRepairScope scope, string operatorConnection,
        CurrentAppOwnedRepairCustody files, string root)
    {
        if (scope.ProofAdmission != CurrentAuthProofAdmission.DisposableClosedConsoleBootstrap || scope.ClosedBootstrapSubject?.CaseId != "lost-commit-ack" ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target)) { throw CurrentAuthRepairPermit.Invalid(); }
        var actual = new NpgsqlConnectionStringBuilder(operatorConnection);
        if (actual.Host != "127.0.0.1" || actual.Port is < 1 or > 65535 || actual.Username != scope.Maintenance.Role ||
            actual.Pooling || actual.SslMode != SslMode.Disable || string.IsNullOrEmpty(actual.Password) || !string.IsNullOrEmpty(actual.Options))
        { throw CurrentAuthRepairPermit.Invalid(); }
        _files = files; _root = root; _operation = scope.OperationId; _began = DateTimeOffset.UtcNow; _expires = scope.Maintenance.ExpiresAtUtc;
        if (_expires <= _began || _expires - _began > TimeSpan.FromMinutes(8)) { throw CurrentAuthRepairPermit.Invalid(); }
        using var process = Process.GetCurrentProcess(); _processId = process.Id;
        _processStart = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
        _image = process.MainModule?.FileName ?? throw CurrentAuthRepairPermit.Invalid(); _imageSha = CurrentAuthTypedHostProducer.ImageHash(_image);
        _lifetime = new CancellationTokenSource(_expires - _began);
        _listener.Start(1); Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        ConnectionString = new NpgsqlConnectionStringBuilder(actual.ConnectionString) { Port = Port }.ConnectionString;
        _worker = RunAsync(actual.Port);
    }

    internal static async Task<CurrentAuthClosedCommitProxy> CreateAsync(CurrentAuthRepairPermit permit, string operatorConnection,
        CurrentAppOwnedRepairCustody files, string root, CancellationToken ct)
    {
        await permit.RequireAsync(ct).ConfigureAwait(false); files.Require();
        var proxy = new CurrentAuthClosedCommitProxy(permit.Scope, operatorConnection, files, root);
        try
        {
            await proxy.RecordAsync("created", new { proxy._operation, port = proxy.Port,
                upstreamPort = new NpgsqlConnectionStringBuilder(operatorConnection).Port, proxy._processId, processStartTimeUtc = proxy._processStart,
                executable = proxy._image, executableSha256 = proxy._imageSha, beganAtUtc = proxy._began, expiresAtUtc = proxy._expires,
                loopbackAddress = ((IPEndPoint)proxy._listener.LocalEndpoint).Address.ToString(), upstreamAddress = "127.0.0.1" }, ct).ConfigureAwait(false);
            return proxy;
        }
        catch { await proxy.DisposeAsync().ConfigureAwait(false); throw; }
    }

    internal void Arm()
    {
        if (_disposed || Volatile.Read(ref _dropped) != 0 || Interlocked.CompareExchange(ref _armed, 1, 0) != 0) { throw CurrentAuthRepairPermit.Invalid(); }
        _ = Interlocked.Exchange(ref _armedTicks, DateTimeOffset.UtcNow.UtcTicks);
    }

    private async Task RunAsync(int upstreamPort)
    {
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                using TcpClient client = await _listener.AcceptTcpClientAsync(_lifetime.Token).ConfigureAwait(false);
                using var server = new TcpClient(); await server.ConnectAsync(IPAddress.Loopback, upstreamPort, _lifetime.Token).ConfigureAwait(false);
                using var session = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
                Task frontend = client.GetStream().CopyToAsync(server.GetStream(), 64 * 1024, session.Token);
                Task backend = RelayAsync(server.GetStream(), client.GetStream(), session.Token);
                try { _ = await Task.WhenAny(frontend, backend).ConfigureAwait(false); }
                finally
                {
                    await session.CancelAsync().ConfigureAwait(false); client.Close(); server.Close();
                    try { await Task.WhenAll(frontend, backend).ConfigureAwait(false); }
                    catch (Exception failure) when (failure is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
                }
            }
        }
        catch (Exception failure) when (_lifetime.IsCancellationRequested && failure is OperationCanceledException or SocketException or ObjectDisposedException) { }
    }

    private async Task RelayAsync(NetworkStream server, NetworkStream client, CancellationToken ct)
    {
        byte[] header = new byte[5];
        while (true)
        {
            int read = await server.ReadAsync(header.AsMemory(0, 1), ct).ConfigureAwait(false); if (read == 0) { return; }
            await server.ReadExactlyAsync(header.AsMemory(1, 4), ct).ConfigureAwait(false);
            int length = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(1));
            if (length is < 4 or > 16 * 1024 * 1024) { throw new InvalidDataException("owned_auth_closed_postgres_frame_limit"); }
            byte[] payload = new byte[length - 4]; await server.ReadExactlyAsync(payload, ct).ConfigureAwait(false);
            if (header[0] == (byte)'C' && payload.AsSpan().SequenceEqual("COMMIT\0"u8) && Interlocked.CompareExchange(ref _armed, 0, 1) == 1)
            { _ = Interlocked.Increment(ref _dropped); _ = Interlocked.Exchange(ref _droppedTicks, DateTimeOffset.UtcNow.UtcTicks); return; }
            await client.WriteAsync(header, ct).ConfigureAwait(false); await client.WriteAsync(payload, ct).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; } _disposed = true; bool settled = false, verified = false;
        try
        {
            await _lifetime.CancelAsync().ConfigureAwait(false); _listener.Stop();
            await _worker.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false); settled = _worker.IsCompleted;
            if (!settled || System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(x => x.Port == Port))
            { throw new IOException("owned_auth_closed_proxy_cleanup_failed"); }
            using var process = Process.GetCurrentProcess();
            if (process.Id != _processId || new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero) != _processStart ||
                CurrentAuthTypedHostProducer.ImageHash(_image) != _imageSha) { throw CurrentAuthRepairPermit.Invalid(); }
            verified = true;
        }
        finally
        {
            try
            {
                await RecordAsync("disposed", new { _operation, port = Port, _processId, processStartTimeUtc = _processStart,
                    executableSha256 = _imageSha, workerCompleted = settled, readersSettled = settled, cleanupFailed = !settled || !verified,
                    armedAtUtc = Ticks(_armedTicks), droppedAtUtc = Ticks(_droppedTicks), droppedCommits = DroppedCount,
                    completedAtUtc = DateTimeOffset.UtcNow }, CancellationToken.None).ConfigureAwait(false);
            }
            finally { _lifetime.Dispose(); }
        }
    }

    private static DateTimeOffset? Ticks(long ticks) => ticks == 0 ? null : new(ticks, TimeSpan.Zero);
    private Task RecordAsync<T>(string phase, T value, CancellationToken ct) => _files.WriteNewAsync(
        Path.Combine(_root, $"auth-closed-proxy-{_operation:N}-{phase}.json"), JsonSerializer.SerializeToUtf8Bytes(value), ct);
}
