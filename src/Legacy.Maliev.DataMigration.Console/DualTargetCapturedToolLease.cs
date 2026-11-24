using System.Diagnostics;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Console;

// Fixed paths, retained image handles and a parent-assigned kernel job. No configured executable or argument callback.
internal sealed class DualTargetCapturedToolLease : IDisposable
{
    internal const string Kubectl = @"C:\ProgramData\chocolatey\lib\kubernetes-cli\tools\kubernetes\client\bin\kubectl.exe";
    internal const string Docker = @"C:\Program Files\Docker\Docker\resources\bin\docker.exe";
    internal const string CredentialPlugin = @"C:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk\bin\gke-gcloud-auth-plugin.exe";
    internal const string CloudPython = @"C:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk\platform\bundledpython\python.exe";
    internal const string CloudCommand = @"C:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd";
    private static readonly string[] FixedImages = [Kubectl, Docker, CredentialPlugin, CloudPython, CloudCommand];
    private readonly List<(string Path, FileStream File, string Identity)> _images = [];
    private readonly List<CurrentAuthTypedProcessFrame> _frames = [];
    private FileStream? _kubeConfig;
    private string? _kubeConfigPath;
    private string? _kubeConfigIdentity;
    private bool _assignedChild;
    private bool _disposed;
    private DualTargetCapturedToolLease()
    {
        try
        {
            foreach (string path in FixedImages)
            {
                FileSystemInfo? ancestor = new FileInfo(path);
                while (ancestor is not null)
                {
                    if ((ancestor.Attributes & FileAttributes.ReparsePoint) != 0) { throw Invalid(); }
                    ancestor = ancestor is FileInfo file ? file.Directory : (ancestor as DirectoryInfo)?.Parent;
                }
                FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                try
                {
                    if (!SecureLocalFile.HandleResolvesToApprovedPath(stream, path)) { throw Invalid(); }
                    _images.Add((path, stream, SecureLocalFile.GetHandleIdentity(stream)));
                }
                catch { stream.Dispose(); throw; }
            }
        }
        catch { Dispose(); throw; }
    }
    internal static DualTargetCapturedToolLease AcquireInAssignedChild(string nonce)
    {
        CurrentAuthTypedHostJob.RequireWaitingChildMembership(nonce);
        var lease = new DualTargetCapturedToolLease { _assignedChild = true };
        try
        {
            string? python = Environment.GetEnvironmentVariable("CLOUDSDK_PYTHON");
            if ((!string.IsNullOrEmpty(python) && !StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(python), CloudPython)) ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CLOUDSDK_PYTHON_ARGS"))) { throw Invalid(); }
            string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".kube", "config");
            string? configured = Environment.GetEnvironmentVariable("KUBECONFIG");
            if (!string.IsNullOrEmpty(configured) && !StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(configured), path)) { throw Invalid(); }
            lease._kubeConfig = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (!SecureLocalFile.HandleResolvesToApprovedPath(lease._kubeConfig, path)) { throw Invalid(); }
            lease._kubeConfigPath = path; lease._kubeConfigIdentity = SecureLocalFile.GetHandleIdentity(lease._kubeConfig);
            return lease;
        }
        catch { lease.Dispose(); throw; }
    }
    internal static DualTargetCapturedToolLease AcquireForFixedObserver()
    {
        return !OperatingSystem.IsWindows() ? throw Invalid() : new();
    }
    internal string KubectlPath { get { Require(); return !_assignedChild ? throw Invalid() : Kubectl; } }
    internal string DockerPath { get { Require(); return Docker; } }
    internal void Require()
    {
        if (_disposed || !OperatingSystem.IsWindows()) { throw Invalid(); }
        foreach (var image in _images)
        {
            if (!SecureLocalFile.HandleResolvesToApprovedPath(image.File, image.Path) ||
                SecureLocalFile.GetHandleIdentity(image.File) != image.Identity) { throw Invalid(); }
        }
        if (_kubeConfig is not null && (!SecureLocalFile.HandleResolvesToApprovedPath(_kubeConfig, _kubeConfigPath!) ||
            SecureLocalFile.GetHandleIdentity(_kubeConfig) != _kubeConfigIdentity)) { throw Invalid(); }
    }
    internal IReadOnlyDictionary<string, string> ImageHashes()
    {
        Require();
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var image in _images)
        {
            image.File.Position = 0; result.Add(image.Path, Convert.ToHexString(SHA256.HashData(image.File)).ToLowerInvariant());
        }
        return result;
    }
    internal IReadOnlyList<CurrentAuthTypedProcessFrame> Frames => Array.AsReadOnly(_frames.ToArray());
    internal async Task RequireCredentialProtocolAsync(CancellationToken ct)
    {
        string command = await ConfigFieldAsync("{.users[0].user.exec.command}", ct).ConfigureAwait(false);
        if (command is not (CredentialPlugin or "gke-gcloud-auth-plugin" or "gke-gcloud-auth-plugin.exe") ||
            !string.IsNullOrWhiteSpace(await ConfigFieldAsync("{.users[0].user.exec.args}", ct).ConfigureAwait(false)) ||
            !string.IsNullOrWhiteSpace(await ConfigFieldAsync("{.users[0].user.exec.env}", ct).ConfigureAwait(false)) ||
            !string.IsNullOrWhiteSpace(await ConfigFieldAsync("{.clusters[0].cluster.proxy-url}", ct).ConfigureAwait(false)) ||
            (await ConfigFieldAsync("{.clusters[0].cluster.insecure-skip-tls-verify}", ct).ConfigureAwait(false)).Trim() == "true")
        { throw Invalid(); }
    }
    private async Task<string> ConfigFieldAsync(string field, CancellationToken ct)
    {
        var start = new ProcessStartInfo(KubectlPath) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in new[] { "config", "view", "--minify", "-o", "jsonpath=" + field }) { start.ArgumentList.Add(arg); }
        using Process process = Process.Start(start) ?? throw Invalid();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(30));
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
        Task<string> stderr = process.StandardError.ReadToEndAsync(timeout.Token);
        DateTimeOffset began = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
        Exception? primary = null;
        string? result = null;
        var cleanupFailures = new List<Exception>();
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            string value = await stdout.ConfigureAwait(false); _ = await stderr.ConfigureAwait(false);
            if (process.ExitCode != 0 || value.Length > 4096) { throw Invalid(); }
            result = value.Trim();
        }
        catch (Exception failure) { primary = failure; }
        finally
        {
            try
            {
                if (!process.HasExited)
                {
                    if (new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero) != began ||
                        !StringComparer.OrdinalIgnoreCase.Equals(process.MainModule?.FileName, Kubectl)) { cleanupFailures.Add(Invalid()); }
                    else { process.Kill(); }
                }
            }
            catch (Exception cleanup) { cleanupFailures.Add(cleanup); }
            try { await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false); }
            catch (Exception cleanup) { cleanupFailures.Add(cleanup); }
            Task drains = Task.WhenAll(stdout, stderr);
            try { await drains.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false); }
            catch (Exception cleanup)
            {
                if (drains.Exception is { } failures) { cleanupFailures.AddRange(failures.InnerExceptions); }
                else { cleanupFailures.Add(cleanup); }
            }
        }
        if (cleanupFailures.Count != 0)
        {
            if (primary is not null) { cleanupFailures.Insert(0, primary); }
            throw new AggregateException("Dual kubectl operation or verified cleanup failed.", cleanupFailures);
        }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
        return result ?? throw Invalid();
    }
    internal async Task<string> RunDockerAsync(IReadOnlyList<string> arguments, CancellationToken ct)
    {
        Require(); CurrentAuthArchiveCapacity.Require(admission: false);
        bool allowed = arguments.Count == 4 && arguments[0] == "inspect" && arguments[1] == "--type" &&
            arguments[2] is "container" or "volume";
        allowed |= arguments.Count == 5 && arguments[0] == "ps" && arguments[1] == "-aq" && arguments[2] == "--no-trunc" &&
            arguments[3] == "--filter" && arguments[4].StartsWith("volume=", StringComparison.Ordinal);
        allowed |= arguments.Count == 5 && arguments[0] == "exec" && arguments[2] == "df" && arguments[3] == "-Pk" && arguments[4].StartsWith('/');
        if (!allowed || arguments.Any(x => x.Any(char.IsControl))) { throw Invalid(); }
        var start = new ProcessStartInfo(DockerPath) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in arguments) { start.ArgumentList.Add(argument); }
        using Process process = Process.Start(start) ?? throw Invalid();
        _ = process.SafeHandle;
        DateTimeOffset began = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
        string image = process.MainModule?.FileName ?? throw Invalid();
        if (!StringComparer.OrdinalIgnoreCase.Equals(image, Docker)) { throw Invalid(); }
        string hash = ImageHashes()[Docker];
        _frames.Add(new(process.Id, began, image, hash, false, process.WorkingSet64));
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(60));
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
        Task<string> stderr = process.StandardError.ReadToEndAsync(timeout.Token);
        Exception? primary = null;
        string? completedResult = null;
        var cleanupFailures = new List<Exception>();
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            string result = await stdout.ConfigureAwait(false); _ = await stderr.ConfigureAwait(false);
            if (process.ExitCode != 0 || result.Length > 2 * 1024 * 1024) { throw Invalid(); }
            completedResult = result;
        }
        catch (Exception failure) { primary = failure; }
        finally
        {
            try
            {
                if (!process.HasExited)
                {
                    if (new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero) != began ||
                        !StringComparer.OrdinalIgnoreCase.Equals(process.MainModule?.FileName, Docker)) { cleanupFailures.Add(Invalid()); }
                    else { process.Kill(); }
                }
            }
            catch (Exception cleanup) { cleanupFailures.Add(cleanup); }
            try { await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false); }
            catch (Exception cleanup) { cleanupFailures.Add(cleanup); }
            Task drains = Task.WhenAll(stdout, stderr);
            try { await drains.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false); }
            catch (Exception cleanup)
            {
                if (drains.Exception is { } failures) { cleanupFailures.AddRange(failures.InnerExceptions); }
                else { cleanupFailures.Add(cleanup); }
            }
            if (cleanupFailures.Count == 0) { _frames.Add(new(process.Id, began, image, hash, true, 0)); }
        }
        if (cleanupFailures.Count != 0)
        {
            if (primary is not null) { cleanupFailures.Insert(0, primary); }
            throw new AggregateException("Dual Docker operation or verified cleanup failed.", cleanupFailures);
        }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
        return completedResult ?? throw Invalid();
    }
    public void Dispose()
    {
        if (_disposed) { return; }
        _disposed = true;
        foreach (var image in _images) { image.File.Dispose(); }
        _kubeConfig?.Dispose();
    }
    private static MigrationConsoleException Invalid()
    {
        return new("dual_target_tool_lease_invalid", "The fixed native tool images are not held by the assigned child.");
    }
}
