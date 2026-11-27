using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record DualTargetCapturedRelayChild(string Kind, string Nonce, string AcceptedMain,
    string TunnelPath, string TunnelSha256, string GatePath, string StopPath, DateTimeOffset ExpiresAtUtc);
internal sealed record DualTargetCapturedRelayGate(string Nonce, int ProcessId, DateTimeOffset StartTimeUtc);

// A fixed Console child owns only a temporary relay. It receives no SQL credentials or capture/signing material.
internal sealed class DualTargetCapturedDeltaRelay : IAsyncDisposable
{
    private readonly CurrentAuthTypedHostJob _job;
    private readonly Process _process;
    private readonly CancellationTokenSource _stop;
    private readonly Task _monitor, _stdout, _stderr;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly DualTargetCapturedRelayChild _child;
    private readonly int _port;
    private bool _disposed;
    private DualTargetCapturedDeltaRelay(CurrentAuthTypedHostJob job, Process process, CancellationTokenSource stop,
        Task monitor, Task stdout, Task stderr, CurrentAppOwnedRepairCustody files, DualTargetCapturedRelayChild child, int port)
    { _job = job; _process = process; _stop = stop; _monitor = monitor; _stdout = stdout; _stderr = stderr; _files = files; _child = child; _port = port; }

    internal static async Task<DualTargetCapturedDeltaRelay> OpenAsync(CurrentAppOwnedRepairCustody files, string root,
        string tunnelPath, string acceptedMain, DateTimeOffset expires, CancellationToken ct)
    {
        CurrentAuthArchiveCapacity.Require(admission: true);
        if (!OperatingSystem.IsWindows() || expires <= DateTimeOffset.UtcNow || expires - DateTimeOffset.UtcNow > TimeSpan.FromMinutes(15)) { throw Invalid(); }
        byte[] config = files.Read(tunnelPath, sharedReader: true, maximumBytes: 65536);
        var tunnel = MigrationConsole.DecodeV3<CnpgExecTunnelConfiguration>(config); CnpgExecTunnel.Validate(tunnel);
        string nonce = Guid.NewGuid().ToString("N"), prefix = Path.Combine(root, "dual-relay-" + nonce);
        var child = new DualTargetCapturedRelayChild("dual-target-captured-relay-v1", nonce, acceptedMain, tunnelPath, Hash(config),
            prefix + "-gate.json", prefix + "-stop.json", expires);
        string childPath = prefix + "-input.json";
        await files.WriteNewAsync(childPath, JsonSerializer.SerializeToUtf8Bytes(child), ct).ConfigureAwait(false);
        string host = Environment.ProcessPath ?? throw Invalid();
        string[] images = [host, @"C:\Program Files\Git\cmd\git.exe", @"C:\Program Files\Git\mingw64\bin\git.exe",
            @"C:\Program Files\GitHub CLI\gh.exe", DualTargetCapturedToolLease.Kubectl, DualTargetCapturedToolLease.CredentialPlugin,
            Path.Combine(Environment.SystemDirectory, "cmd.exe"), DualTargetCapturedToolLease.CloudPython];
        var job = new CurrentAuthTypedHostJob(images.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(), nonce);
        var start = new ProcessStartInfo(host) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        if (Path.GetFileName(host).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase)) { start.ArgumentList.Add(typeof(MigrationConsole).Assembly.Location); }
        start.ArgumentList.Add("run-dual-target-captured-relay"); start.ArgumentList.Add("--config"); start.ArgumentList.Add(childPath);
        start.Environment["PATH"] = string.Join(Path.PathSeparator, @"C:\Program Files\Git\cmd", @"C:\Program Files\GitHub CLI",
            Path.GetDirectoryName(DualTargetCapturedToolLease.CredentialPlugin), Path.GetDirectoryName(host), Environment.SystemDirectory);
        foreach (string variable in new[] { "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTHONINSPECT",
            "DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS", "DOTNET_SHARED_STORE", "CORECLR_PROFILER", "CORECLR_PROFILER_PATH",
            "CORECLR_ENABLE_PROFILING", "COR_PROFILER", "COR_PROFILER_PATH", "COR_ENABLE_PROFILING", "CLOUDSDK_PYTHON_ARGS" })
        { _ = start.Environment.Remove(variable); }
        start.Environment["CLOUDSDK_PYTHON"] = DualTargetCapturedToolLease.CloudPython;
        start.Environment["CLOUDSDK_PYTHON_SITEPACKAGES"] = "0";
        start.Environment["CLOUDSDK_ROOT_DIR"] = @"C:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk";
        Process? process = null; CancellationTokenSource? stop = null; DateTimeOffset? ownedStart = null;
        try
        {
            process = Process.Start(start) ?? throw Invalid(); _ = process.SafeHandle;
            ownedStart = new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
            job.AssignWaitingChild(process);
            await files.WriteNewAsync(child.GatePath, JsonSerializer.SerializeToUtf8Bytes(new DualTargetCapturedRelayGate(nonce,
                process.Id, new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero))), ct).ConfigureAwait(false);
            stop = CancellationTokenSource.CreateLinkedTokenSource(ct); stop.CancelAfter(expires - DateTimeOffset.UtcNow);
            Task<string?> ready = process.StandardOutput.ReadLineAsync(stop.Token).AsTask();
            while (!ready.IsCompleted)
            {
                _ = job.Observe(admission: false);
                _ = await Task.WhenAny(ready, Task.Delay(TimeSpan.FromMilliseconds(100), stop.Token)).ConfigureAwait(false);
            }
            if (await ready.ConfigureAwait(false) != "cnpg_exec_tunnel_ready") { throw Invalid(); }
            Task stdout = process.StandardOutput.ReadToEndAsync(stop.Token);
            Task stderr = process.StandardError.ReadToEndAsync(stop.Token);
            Task monitor = MonitorAsync(job, process, stop);
            return new(job, process, stop, monitor, stdout, stderr, files, child, tunnel.ListenPort);
        }
        catch (Exception primary)
        {
            stop?.Cancel();
            try
            {
                if (HasClients(tunnel.ListenPort)) { throw Invalid(); }
                await job.CompleteCleanupAsync().ConfigureAwait(false);
            }
            catch (Exception cleanup) { primary.Data["DualRelayStartupCleanup"] = cleanup; }
            try
            {
                if (process is not null && !process.HasExited && job.Empty)
                {
                    if (ownedStart is null || new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero) != ownedStart ||
                        !StringComparer.OrdinalIgnoreCase.Equals(process.MainModule?.FileName, host)) { throw Invalid(); }
                    process.Kill(); await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false);
                }
                await files.WriteNewAsync(prefix + "-startup-resources.json", JsonSerializer.SerializeToUtf8Bytes(new
                {
                    child.Nonce,
                    child.ExpiresAtUtc,
                    Port = tunnel.ListenPort,
                    ProcessId = process?.Id,
                    StartTimeUtc = ownedStart,
                    ExecutablePath = host,
                    CleanupVerified = job.Empty && (process is null || process.HasExited),
                    RemainingLease = !job.Empty || process is { HasExited: false }
                }), CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception cleanup) { primary.Data["DualRelayStartupLedger"] = cleanup; }
            stop?.Dispose(); process?.Dispose(); job.Dispose(); throw;
        }
    }

    internal void RequireLive()
    {
        if (_disposed || _process.HasExited || _stop.IsCancellationRequested || _monitor.IsFaulted || DateTimeOffset.UtcNow >= _child.ExpiresAtUtc)
        { throw Invalid(); }
        _ = _job.Observe(admission: false); _files.Require();
    }
    internal CancellationToken OperationToken => _stop.Token;
    private static async Task MonitorAsync(CurrentAuthTypedHostJob job, Process process, CancellationTokenSource stop)
    {
        try
        {
            while (!stop.IsCancellationRequested && !process.HasExited)
            { _ = job.Observe(admission: false); await Task.Delay(TimeSpan.FromMilliseconds(250), stop.Token).ConfigureAwait(false); }
        }
        catch { stop.Cancel(); throw; }
    }
    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true;
        Exception? failure = null;
        try
        {
            // Dedicated fresh port: any established client must close before this owner stops the relay.
            if (HasClients(_port)) { throw Invalid(); }
            await _files.WriteNewAsync(_child.StopPath, JsonSerializer.SerializeToUtf8Bytes(new { _child.Nonce }), CancellationToken.None).ConfigureAwait(false);
            await _process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(90), CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception problem) { failure = problem; }
        finally
        {
            _stop.Cancel();
            try
            {
                if (!HasClients(_port)) { await _job.CompleteCleanupAsync().ConfigureAwait(false); }
                try { await Task.WhenAll(_monitor, _stdout, _stderr).ConfigureAwait(false); }
                catch (OperationCanceledException) { }
                var (Capacity, Processes) = _job.Observe(admission: false);
                await _files.WriteNewAsync(Path.Combine(Path.GetDirectoryName(_child.StopPath)!, "dual-relay-" + _child.Nonce + "-resources.json"),
                    JsonSerializer.SerializeToUtf8Bytes(new
                    {
                        _child.ExpiresAtUtc,
                        Port = _port,
                        Processes,
                        CleanupVerified = _job.Empty && !HasClients(_port),
                        RemainingLease = !_job.Empty,
                        HadFailure = failure is not null
                    }), CancellationToken.None).ConfigureAwait(false);
                if (failure is null && (!_job.Empty || IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(x => x.Port == _port && x.Address.Equals(IPAddress.Loopback))))
                { failure = Invalid(); }
            }
            catch (Exception cleanup) { if (failure is null) { failure = cleanup; } else { failure.Data["DualRelayCleanup"] = cleanup; } }
            _stop.Dispose(); _process.Dispose(); _job.Dispose();
        }
        if (failure is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw(); }
    }

    internal static async Task<int> RunChildAsync(string path, CancellationToken ct)
    {
        byte[] input;
        using (FileStream held = SecureLocalFile.OpenRead(path))
        {
            if (held.Length > 65536) { throw Invalid(); }
            using var copy = new MemoryStream(); await held.CopyToAsync(copy, ct).ConfigureAwait(false); input = copy.ToArray();
        }
        var child = MigrationConsole.DecodeV3<DualTargetCapturedRelayChild>(input);
        if (child.Kind != "dual-target-captured-relay-v1" || !Guid.TryParseExact(child.Nonce, "N", out _) ||
            child.ExpiresAtUtc <= DateTimeOffset.UtcNow || child.ExpiresAtUtc - DateTimeOffset.UtcNow > TimeSpan.FromMinutes(15)) { throw Invalid(); }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(child.ExpiresAtUtc - DateTimeOffset.UtcNow);
        while (!File.Exists(child.GatePath)) { await Task.Delay(TimeSpan.FromMilliseconds(100), timeout.Token).ConfigureAwait(false); }
        CurrentAuthTypedHostJob.RequireWaitingChildMembership(child.Nonce);
        using Process self = Process.GetCurrentProcess();
        using (FileStream gateFile = SecureLocalFile.OpenRead(child.GatePath))
        {
            var gate = await JsonSerializer.DeserializeAsync<DualTargetCapturedRelayGate>(gateFile, cancellationToken: timeout.Token).ConfigureAwait(false) ?? throw Invalid();
            if (gate.Nonce != child.Nonce || gate.ProcessId != self.Id || gate.StartTimeUtc != new DateTimeOffset(self.StartTime.ToUniversalTime(), TimeSpan.Zero)) { throw Invalid(); }
        }
        if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(timeout.Token).ConfigureAwait(false) != child.AcceptedMain) { throw Invalid(); }
        using DualTargetCapturedToolLease tools = DualTargetCapturedToolLease.AcquireInAssignedChild(child.Nonce);
        using FileStream config = SecureLocalFile.OpenReadShared(child.TunnelPath);
        if (!MatchesTunnelHash(child.TunnelSha256, SHA256.HashData(config))) { throw Invalid(); }
        Task relay = CnpgExecTunnel.RunOwnedAsync(child.TunnelPath, System.Console.Out, System.Console.Error, tools, timeout.Token);
        Exception? primary = null;
        try
        {
            while (!relay.IsCompleted && !File.Exists(child.StopPath)) { await Task.Delay(TimeSpan.FromMilliseconds(100), timeout.Token).ConfigureAwait(false); }
        }
        catch (Exception failure) { primary = failure; }
        finally
        {
            timeout.Cancel();
            try { await relay.ConfigureAwait(false); }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
            catch (Exception cleanup)
            {
                if (primary is not null) { primary.Data["DualRelayChildCleanup"] = cleanup; }
                else { primary = cleanup; }
            }
        }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
        return 0;
    }
    internal static bool MatchesTunnelHash(string? expected, ReadOnlySpan<byte> actualDigest)
    {
        return expected is { Length: 64 } && actualDigest.Length == 32 && expected.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f')) &&
                string.Equals(Convert.ToHexString(actualDigest), expected, StringComparison.OrdinalIgnoreCase);
    }

    private static string Hash(byte[] bytes)
    {
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static bool HasClients(int port)
    {
        return IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections().Any(x =>
            x.LocalEndPoint.Address.Equals(IPAddress.Loopback) && x.LocalEndPoint.Port == port && x.State == TcpState.Established);
    }

    private static MigrationConsoleException Invalid()
    {
        return new("dual_target_owned_relay_invalid", "The fixed run-owned relay lifecycle is not admitted.");
    }
}
