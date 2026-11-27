using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record DualTargetNativeProofToolPins(string Kind, string AcceptedMain, string Version,
    IReadOnlyDictionary<string, string> Files, DateTimeOffset ExpiresAtUtc);

// Only fixed installed PG18 executables and their complete held bin inventory can run.
internal sealed class DualTargetNativeProofTools : IDisposable
{
    internal const string DirectoryPath = @"C:\Program Files\PostgreSQL\18\bin";
    private const long MaximumDumpBytes = 512L * 1024 * 1024;
    private static readonly string[] ToolNames = ["pg_dump.exe", "pg_restore.exe"];
    private readonly List<FileStream> _files = [];
    private readonly DualTargetNativeProofToolPins _pins;
    private readonly List<CurrentAuthTypedProcessFrame> _processes = [];
    private bool _disposed;
    private DualTargetNativeProofTools(DualTargetNativeProofToolPins pins) { _pins = pins; }
    internal IReadOnlyList<CurrentAuthTypedProcessFrame> Processes => _processes.AsReadOnly();

    internal static DualTargetNativeProofTools Acquire(CurrentAppOwnedRepairCustody custody, string pinPath, string acceptedMain)
    {
        if (!OperatingSystem.IsWindows()) { throw DualTargetNativeProofPreimage.Invalid(); }
        var pins = MigrationConsole.DecodeV3<DualTargetNativeProofToolPins>(custody.Read(pinPath, maximumBytes: 1024 * 1024));
        string[] actual = Directory.GetFiles(DirectoryPath, "*", SearchOption.TopDirectoryOnly);
        RequirePins(pins, acceptedMain, actual.Select(x => Path.GetFileName(x)).ToArray(), DateTimeOffset.UtcNow);
        var lease = new DualTargetNativeProofTools(pins);
        try
        {
            foreach (string path in actual.Order(StringComparer.Ordinal))
            {
                var info = new FileInfo(path);
                if (info.LinkTarget is not null || (info.Attributes & FileAttributes.ReparsePoint) != 0) { throw DualTargetNativeProofPreimage.Invalid(); }
                for (DirectoryInfo? folder = new(Path.GetDirectoryName(path)!); folder is not null; folder = folder.Parent)
                { if (folder.LinkTarget is not null || (folder.Attributes & FileAttributes.ReparsePoint) != 0) { throw DualTargetNativeProofPreimage.Invalid(); } }
                FileStream file = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                lease._files.Add(file);
                if (!DualTargetNativeProofPreimage.IsHash(pins.Files[Path.GetFileName(path)]) ||
                    Convert.ToHexStringLower(SHA256.HashData(file)) != pins.Files[Path.GetFileName(path)]) { throw DualTargetNativeProofPreimage.Invalid(); }
            }
            foreach (string name in ToolNames)
            { if (FileVersionInfo.GetVersionInfo(Path.Combine(DirectoryPath, name)).FileVersion != pins.Version) { throw DualTargetNativeProofPreimage.Invalid(); } }
            return lease;
        }
        catch { lease.Dispose(); throw; }
    }

    internal static void RequirePins(DualTargetNativeProofToolPins pins, string acceptedMain, IReadOnlyList<string> actualNames, DateTimeOffset now)
    {
        if (pins.Kind != "dual-target-native-proof-pg18-tools-v1" || pins.AcceptedMain != acceptedMain ||
            pins.ExpiresAtUtc.Offset != TimeSpan.Zero || pins.ExpiresAtUtc <= now || pins.ExpiresAtUtc - now > TimeSpan.FromHours(12) ||
            !pins.Version.StartsWith("18.", StringComparison.Ordinal) || pins.Files.Values.Any(x => !DualTargetNativeProofPreimage.IsHash(x)) ||
            ToolNames.Any(x => !pins.Files.ContainsKey(x)) || pins.Files.Keys.Any(x => string.IsNullOrWhiteSpace(x) || Path.GetFileName(x) != x) ||
            !actualNames.Order(StringComparer.Ordinal).SequenceEqual(pins.Files.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal))
        { throw DualTargetNativeProofPreimage.Invalid(); }
    }

    internal async Task RequireVersionsAsync(CancellationToken ct)
    {
        foreach (string name in ToolNames)
        {
            using var output = new MemoryStream();
            await RunAsync(name, ["--version"], null, null, output, maximumOutput: 4096, ct).ConfigureAwait(false);
            if (!Encoding.UTF8.GetString(output.ToArray()).Trim().EndsWith("(PostgreSQL) " + _pins.Version, StringComparison.Ordinal))
            { throw DualTargetNativeProofPreimage.Invalid(); }
        }
    }

    internal async Task DumpAsync(string connection, string database, string snapshot, Stream destination, bool definition, CancellationToken ct)
    {
        var args = new List<string>
        {
            "--dbname",
            database,
            "--encoding=UTF8",
            "--no-password",
            "--quote-all-identifiers",
            "--create",
            "--lock-wait-timeout=5s",
            "--snapshot=" + snapshot,
            definition ? "--format=plain" : "--format=custom"
        };
        if (definition) { args.Add("--schema-only"); args.Add("--restrict-key=LegacyMalievOwnedLogicalCloneV1"); }
        await RunAsync("pg_dump.exe", args, connection, null, destination, MaximumDumpBytes, ct).ConfigureAwait(false);
    }

    internal Task RestoreAsync(DualTargetNativeProofClone clone, Stream generatedArchive, CancellationToken ct)
    {
        return RunAsync("pg_restore.exe", ["--dbname", "clone_control", "--create", "--exit-on-error", "--no-password", "--jobs=1", "--use-set-session-authorization"],
            clone.AdminConnection, generatedArchive, Stream.Null, 1024 * 1024, ct);
    }

    private async Task RunAsync(string name, List<string> arguments, string? connection, Stream? input, Stream output, long maximumOutput, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (DateTimeOffset.UtcNow >= _pins.ExpiresAtUtc || name is not ("pg_dump.exe" or "pg_restore.exe")) { throw DualTargetNativeProofPreimage.Invalid(); }
        CurrentAuthArchiveCapacity.Require(admission: true);
        string executable = Path.Combine(DirectoryPath, name);
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = input is not null,
            WorkingDirectory = DirectoryPath
        };
        foreach (string key in start.Environment.Keys.Where(x => x.StartsWith("PG", StringComparison.OrdinalIgnoreCase)).ToArray()) { _ = start.Environment.Remove(key); }
        start.Environment["PATH"] = DirectoryPath + Path.PathSeparator + Environment.SystemDirectory;
        start.Environment["PGPASSFILE"] = "NUL"; start.Environment["PGGSSENCMODE"] = "disable"; start.Environment["PGSSLCERTMODE"] = "disable";
        start.Environment["PGCONNECT_TIMEOUT"] = "5";
        start.Environment["OPENSSL_CONF"] = "NUL";
        start.Environment["OPENSSL_MODULES"] = DirectoryPath;
        _ = start.Environment.Remove("OPENSSL_ENGINES");
        if (connection is not null)
        {
            var settings = new NpgsqlConnectionStringBuilder(connection);
            if (settings.Host != "127.0.0.1" || settings.Port is < 1 or > 65535 || settings.Username is null || settings.Password is null ||
                !string.IsNullOrEmpty(settings.Options) || settings.SslMode != SslMode.Disable || settings.Multiplexing) { throw DualTargetNativeProofPreimage.Invalid(); }
            start.Environment["PGHOST"] = settings.Host; start.Environment["PGPORT"] = settings.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
            start.Environment["PGUSER"] = settings.Username; start.Environment["PGPASSWORD"] = settings.Password; start.Environment["PGSSLMODE"] = "disable";
            start.Environment["PGOPTIONS"] = input is null ? "-c default_transaction_read_only=on" : "-c statement_timeout=60000";
        }
        foreach (string argument in arguments) { start.ArgumentList.Add(argument); }
        using var job = new CurrentAuthTypedHostJob([executable], Guid.NewGuid().ToString("N"));
        using var process = new Process { StartInfo = start };
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromMinutes(3));
        if (!process.Start()) { throw DualTargetNativeProofPreimage.Invalid(); }
        _ = process.SafeHandle;
        DateTimeOffset began = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
        Exception? primary = null;
        var cleanupFailures = new List<Exception>();
        Task? stdout = null, stderr = null, stdin = null;
        try
        {
            bool versionOnly = connection is null && input is null && arguments.Count == 1 && arguments[0] == "--version";
            try
            {
                if (!process.HasExited)
                {
                    string? actualImage = process.MainModule?.FileName;
                    if (actualImage is null)
                    { if (!versionOnly || !process.HasExited) { throw DualTargetNativeProofPreimage.Invalid(); } }
                    else if (!StringComparer.OrdinalIgnoreCase.Equals(actualImage, executable)) { throw DualTargetNativeProofPreimage.Invalid(); }
                    if (!process.HasExited) { job.AssignWaitingChild(process); }
                    else if (!versionOnly) { throw DualTargetNativeProofPreimage.Invalid(); }
                }
                else if (!versionOnly) { throw DualTargetNativeProofPreimage.Invalid(); }
            }
            catch (Exception race) when (versionOnly && process.HasExited && (race is InvalidOperationException or System.ComponentModel.Win32Exception))
            { /* A credential-free, held fixed --version image may exit before assignment. */ }
            stdout = CopyBoundedAsync(process.StandardOutput.BaseStream, output, maximumOutput, timeout.Token);
            stderr = CopyBoundedAsync(process.StandardError.BaseStream, Stream.Null, 1024 * 1024, timeout.Token);
            stdin = input is null ? Task.CompletedTask : SupplyAsync(input, process.StandardInput.BaseStream, timeout.Token);
            Task exit = process.WaitForExitAsync(timeout.Token);
            Task all = Task.WhenAll(stdout, stderr, stdin, exit);
            while (!all.IsCompleted)
            {
                _ = job.Observe(admission: false);
                _ = await Task.WhenAny(all, Task.Delay(100, timeout.Token)).ConfigureAwait(false);
                timeout.Token.ThrowIfCancellationRequested();
                if (stdout.IsFaulted || stderr.IsFaulted || stdin.IsFaulted) { await Task.WhenAll(stdout, stderr, stdin).ConfigureAwait(false); }
            }
            await all.ConfigureAwait(false);
            if (process.ExitCode != 0) { throw DualTargetNativeProofPreimage.Invalid(); }
        }
        catch (Exception failure) { primary = failure; }
        finally
        {
            try
            {
                if (!process.HasExited && (new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero) != began ||
                    !StringComparer.OrdinalIgnoreCase.Equals(process.MainModule?.FileName, executable))) { cleanupFailures.Add(DualTargetNativeProofPreimage.Invalid()); }
                else if (!process.HasExited) { process.Kill(); }
            }
            catch (Exception cleanup) { cleanupFailures.Add(cleanup); }
            try { await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false); }
            catch (Exception cleanup) { cleanupFailures.Add(cleanup); }
            try { await job.CompleteCleanupAsync().ConfigureAwait(false); }
            catch (Exception cleanup) { cleanupFailures.Add(cleanup); }
            try { if (!job.Empty) { cleanupFailures.Add(DualTargetNativeProofPreimage.Invalid()); } }
            catch (Exception cleanup) { cleanupFailures.Add(cleanup); }
            Task drains = Task.WhenAll(stdout ?? Task.CompletedTask, stderr ?? Task.CompletedTask, stdin ?? Task.CompletedTask);
            try { await drains.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false); }
            catch (Exception cleanup)
            {
                if (drains.Exception is { } failures) { cleanupFailures.AddRange(failures.InnerExceptions); }
                else { cleanupFailures.Add(cleanup); }
            }
            if (cleanupFailures.Count == 0) { _processes.Add(new(process.Id, began, executable, _pins.Files[name], true, 0)); }
        }
        if (cleanupFailures.Count != 0)
        {
            if (primary is not null) { cleanupFailures.Insert(0, primary); }
            throw new AggregateException("Dual proof PG operation or verified cleanup failed.", cleanupFailures);
        }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
    }

    private static async Task SupplyAsync(Stream source, Stream input, CancellationToken ct)
    {
        Exception? primary = null, cleanup = null;
        try { await source.CopyToAsync(input, 65536, ct).ConfigureAwait(false); }
        catch (Exception failure) { primary = failure; }
        finally
        {
            try { await input.DisposeAsync().ConfigureAwait(false); }
            catch (Exception failure) { cleanup = failure; }
        }
        if (cleanup is not null) { throw new AggregateException("Dual proof PG input or cleanup failed.", primary is null ? [cleanup] : [primary, cleanup]); }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
    }
    private static async Task CopyBoundedAsync(Stream source, Stream target, long maximumOutput, CancellationToken ct)
    {
        byte[] buffer = new byte[65536]; long total = 0;
        while (true)
        {
            int count = await source.ReadAsync(buffer, ct).ConfigureAwait(false); if (count == 0) { break; }
            total = checked(total + count); if (total > maximumOutput) { throw DualTargetNativeProofPreimage.Invalid(); }
            await target.WriteAsync(buffer.AsMemory(0, count), ct).ConfigureAwait(false);
        }
    }
    public void Dispose() { if (_disposed) { return; } _disposed = true; foreach (FileStream file in _files) { file.Dispose(); } }
}
