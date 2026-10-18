using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

// Fixed admitted enum4 lost-COMMIT fixture resource. No supplied executable, callback,
// proxy port, upstream address, SSL negotiation, command or persistent target.
internal sealed class CurrentOwnerIsoNamedClosedCommitProxy : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _lifetime;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly string _root;
    private readonly Task _worker;
    private readonly int _processId;
    private readonly DateTimeOffset _processStart, _began, _expires;
    private readonly string _image, _imageSha;
    private int _armed, _dropped;
    private long _armedTicks, _droppedTicks;
    private bool _disposed;
    internal string ConnectionString { get; }
    internal int Port { get; }
    internal Guid Operation { get; }
    internal int DroppedCount => Volatile.Read(ref _dropped);

    private CurrentOwnerIsoNamedClosedCommitProxy(CurrentOwnerIsoRepairScope scope, string operatorConnection,
        CurrentAppOwnedRepairCustody files, string root)
    {
        if (scope.ProofAdmission != CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap || scope.BootstrapSubject?.CaseId != "lost-commit-ack" ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        var actual = new NpgsqlConnectionStringBuilder(operatorConnection);
        if (actual.Host != "127.0.0.1" || actual.Port is < 1 or > 65535 || actual.Username != scope.Maintenance.Role ||
            actual.Pooling || actual.SslMode != SslMode.Disable || string.IsNullOrEmpty(actual.Password) || !string.IsNullOrEmpty(actual.Options))
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        _files = files; _root = root; Operation = scope.OperationId; _began = DateTimeOffset.UtcNow; _expires = scope.Maintenance.ExpiresAtUtc;
        if (_expires <= _began || _expires - _began > TimeSpan.FromMinutes(8)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        using var process = Process.GetCurrentProcess(); _processId = process.Id;
        _processStart = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
        _image = process.MainModule?.FileName ?? throw CurrentOwnerIsoRepairPermit.Invalid(); _imageSha = ImageHash(_image);
        _lifetime = new CancellationTokenSource(_expires - _began);
        _listener.Start(1); Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        ConnectionString = new NpgsqlConnectionStringBuilder(actual.ConnectionString) { Port = Port }.ConnectionString;
        _worker = RunAsync(actual.Port);
    }

    internal static async Task<CurrentOwnerIsoNamedClosedCommitProxy> CreateAsync(CurrentOwnerIsoRepairPermit permit, string operatorConnection,
        CurrentAppOwnedRepairCustody files, string root, CancellationToken ct)
    {
        await permit.RequireAsync(ct).ConfigureAwait(false); files.Require();
        await files.WriteNewAsync(Path.Combine(root, $"iso-closed-proxy-{permit.Scope.OperationId:N}-attempt.json"), JsonSerializer.SerializeToUtf8Bytes(new { permit.Scope.OperationId, beganAtUtc = DateTimeOffset.UtcNow, expiresAtUtc = permit.Scope.Maintenance.ExpiresAtUtc, loopback = "127.0.0.1", upstreamPort = new NpgsqlConnectionStringBuilder(operatorConnection).Port }), ct).ConfigureAwait(false);
        var proxy = new CurrentOwnerIsoNamedClosedCommitProxy(permit.Scope, operatorConnection, files, root);
        try
        {
            await proxy.RecordAsync("created", new
            {
                proxy.Operation,
                port = proxy.Port,
                upstreamPort = new NpgsqlConnectionStringBuilder(operatorConnection).Port,
                proxy._processId,
                processStartTimeUtc = proxy._processStart,
                executable = proxy._image,
                executableSha256 = proxy._imageSha,
                beganAtUtc = proxy._began,
                expiresAtUtc = proxy._expires,
                loopbackAddress = ((IPEndPoint)proxy._listener.LocalEndpoint).Address.ToString(),
                upstreamAddress = "127.0.0.1"
            }, ct).ConfigureAwait(false);
            return proxy;
        }
        catch { await proxy.DisposeAsync().ConfigureAwait(false); throw; }
    }

    internal void Arm()
    {
        if (_disposed || Volatile.Read(ref _dropped) != 0 || Interlocked.CompareExchange(ref _armed, 1, 0) != 0) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
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
        if (_disposed) { return; }
        _disposed = true; bool settled = false, verified = false;
        try
        {
            await _lifetime.CancelAsync().ConfigureAwait(false); _listener.Stop();
            await _worker.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false); settled = _worker.IsCompleted;
            if (!settled || System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(x => x.Port == Port))
            { throw new IOException("owned_auth_closed_proxy_cleanup_failed"); }
            using var process = Process.GetCurrentProcess();
            if (process.Id != _processId || new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero) != _processStart ||
                ImageHash(_image) != _imageSha) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            verified = true;
        }
        finally
        {
            try
            {
                await RecordAsync("disposed", new
                {
                    Operation,
                    port = Port,
                    _processId,
                    processStartTimeUtc = _processStart,
                    executableSha256 = _imageSha,
                    workerCompleted = settled,
                    readersSettled = settled,
                    cleanupFailed = !settled || !verified,
                    armedAtUtc = Ticks(_armedTicks),
                    droppedAtUtc = Ticks(_droppedTicks),
                    droppedCommits = DroppedCount,
                    completedAtUtc = DateTimeOffset.UtcNow
                }, CancellationToken.None).ConfigureAwait(false);
            }
            finally { _lifetime.Dispose(); }
        }
    }

    private static DateTimeOffset? Ticks(long ticks)
    {
        return ticks == 0 ? null : new(ticks, TimeSpan.Zero);
    }

    private Task RecordAsync<T>(string phase, T value, CancellationToken ct)
    {
        return _files.WriteNewAsync(
            Path.Combine(_root, $"iso-closed-proxy-{Operation:N}-{phase}.json"), JsonSerializer.SerializeToUtf8Bytes(value), ct);
    }

    private static string ImageHash(string path) { using var held = SecureLocalFile.OpenReadShared(path); return Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(held)); }
}
