using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration.Console;

// Disposable native proof only. Drops exactly the real PostgreSQL CommandComplete COMMIT
// acknowledgment; it does not forge an outcome or submit a replacement COMMIT.
internal sealed class IsoCommitAcknowledgementProxy : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _life = new(TimeSpan.FromMinutes(8));
    private readonly IsoExecutedProofRecorder _proof;
    private readonly Task _worker;
    private int _armed, _dropped;
    private readonly TaskCompletionSource _drop = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal int Port { get; }
    internal Task Dropped => _drop.Task;
    internal int DroppedCommits => Volatile.Read(ref _dropped);

    private IsoCommitAcknowledgementProxy(string host, int port, IsoExecutedProofRecorder proof)
    {
        _proof = proof; _listener.Start(1); Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _worker = RunAsync(host, port);
    }
    internal static async Task<IsoCommitAcknowledgementProxy> StartAsync(string host, int port,
        IsoExecutedProofRecorder proof, CancellationToken ct)
    {
        if (host != "127.0.0.1" || port is < 1 or > 65535) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        proof.Capacity(admission: false);
        using var process = Process.GetCurrentProcess(); string executable = process.MainModule?.FileName ?? throw CurrentOwnerIsoRepairPermit.Invalid();
        using var file = SecureLocalFile.OpenReadShared(executable);
        string executableSha = Convert.ToHexStringLower(SHA256.HashData(file));
        // Immutable attempt precedes listener creation. Observed binds the actual allocated port.
        await proof.RecordAsync("proxy-attempt", new
        {
            proof.RunId,
            proof.CaseId,
            processId = process.Id,
            processStartTimeUtc = new DateTimeOffset(process.StartTime.ToUniversalTime()),
            executable,
            executableSha,
            beganAtUtc = DateTimeOffset.UtcNow,
            expiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(8),
            targetPort = port
        }, ct).ConfigureAwait(false);
        var proxy = new IsoCommitAcknowledgementProxy(host, port, proof);
        try
        {
            await proof.RecordAsync("proxy-observed", new
            {
                proof.RunId,
                proof.CaseId,
                address = "127.0.0.1",
                port = proxy.Port,
                targetPort = port,
                observedAtUtc = DateTimeOffset.UtcNow
            }, ct).ConfigureAwait(false);
            return proxy;
        }
        catch { await proxy.DisposeAsync().ConfigureAwait(false); throw; }
    }
    internal void Arm()
    {
        if (DroppedCommits != 0 || Interlocked.CompareExchange(ref _armed, 1, 0) != 0) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
    }
    private async Task RunAsync(string host, int port)
    {
        try
        {
            while (!_life.IsCancellationRequested)
            {
                using TcpClient client = await _listener.AcceptTcpClientAsync(_life.Token).ConfigureAwait(false);
                using var server = new TcpClient(); await server.ConnectAsync(host, port, _life.Token).ConfigureAwait(false);
                using var session = CancellationTokenSource.CreateLinkedTokenSource(_life.Token);
                Task request = client.GetStream().CopyToAsync(server.GetStream(), session.Token);
                Task response = RelayAsync(server.GetStream(), client.GetStream(), session.Token);
                _ = await Task.WhenAny(request, response).ConfigureAwait(false);
                session.Cancel(); client.Close(); server.Close();
                try { await Task.WhenAll(request, response).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); }
                catch (Exception failure) when (failure is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
                if (DroppedCommits == 1) { _ = _drop.TrySetResult(); }
            }
        }
        catch (Exception failure) when (_life.IsCancellationRequested && failure is OperationCanceledException or ObjectDisposedException or SocketException) { }
    }
    private async Task RelayAsync(Stream from, Stream to, CancellationToken ct)
    {
        byte[] header = new byte[5];
        while (true)
        {
            await from.ReadExactlyAsync(header, ct).ConfigureAwait(false);
            int length = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(1));
            if (length is < 4 or > 16 * 1024 * 1024) { throw new IOException("Invalid PostgreSQL response frame."); }
            byte[] payload = new byte[length - 4]; await from.ReadExactlyAsync(payload, ct).ConfigureAwait(false);
            if (header[0] == (byte)'C' && payload.AsSpan().SequenceEqual("COMMIT\0"u8) && Interlocked.CompareExchange(ref _armed, 0, 1) == 1)
            {
                if (Interlocked.Increment(ref _dropped) != 1) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                await _proof.RecordAsync("proxy-dropped", new
                {
                    _proof.RunId,
                    _proof.CaseId,
                    port = Port,
                    actualTag = Encoding.ASCII.GetString(payload),
                    observedAtUtc = DateTimeOffset.UtcNow
                }, ct).ConfigureAwait(false);
                return;
            }
            await to.WriteAsync(header, ct).ConfigureAwait(false); await to.WriteAsync(payload, ct).ConfigureAwait(false);
        }
    }
    public async ValueTask DisposeAsync()
    {
        Exception? error = null; _life.Cancel(); _listener.Stop();
        try { await _worker.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false); }
        catch (Exception failure) { error = failure; }
        int[] ports = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()
            .Where(x => IPAddress.IsLoopback(x.Address)).Select(x => x.Port).Order().ToArray();
        bool absent = !ports.Contains(Port); _life.Dispose();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await _proof.RecordAsync("proxy-disposed", new
        {
            _proof.RunId,
            _proof.CaseId,
            port = Port,
            workerExited = _worker.IsCompleted,
            listenerAbsent = absent,
            listenerPorts = ports,
            cleanupFailed = error is not null || !absent,
            droppedCommits = DroppedCommits,
            completedAtUtc = DateTimeOffset.UtcNow
        }, deadline.Token).ConfigureAwait(false);
        if (error is not null || !absent) { throw new MigrationExecutionException("iso_proxy_cleanup_failed", "Exact owned proxy did not exit cleanly."); }
    }
}
