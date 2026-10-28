using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveDeviceRequest(CurrentAuthArchiveScope Scope, string FirstRoot, string SecondRoot);
internal sealed record CurrentAuthArchiveDeviceResource(Guid RunId, string Executable, string ExecutableSha256,
    int? ProcessId, long? StartUtcTicks, DateTimeOffset ExpiresAtUtc, bool Exited, bool ReadersSettled, bool CleanupFailed);

/// <summary>Fixed accepted-bundle child isolates potentially blocking read-only Windows driver calls.</summary>
internal static class CurrentAuthLocalSessionArchiveDeviceProcess
{
    internal const string Command = "observe-current-auth-archive-recovery-devices";
    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(20), Cleanup = TimeSpan.FromSeconds(5);
    private const int Limit = 65536;

    internal static async Task<CurrentAuthArchiveDeviceProof> ObserveAsync(CurrentAuthArchiveScope scope,
        string firstRoot, string secondRoot, CurrentAppOwnedRepairCustody firstFiles,
        CurrentAppOwnedRepairCustody secondFiles, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        CurrentAuthArchiveCapacity.Require(admission: false);
        firstFiles.Require(); secondFiles.Require();
        var request = new CurrentAuthArchiveDeviceRequest(scope, firstRoot, secondRoot);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(request);
        if (bytes.Length > Limit) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        string path = Path.Combine(firstRoot, $"device-request-auth-archive-{Guid.NewGuid():N}.json");
        await firstFiles.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
        if (!firstFiles.Read(path, sharedReader: true, maximumBytes: Limit).AsSpan().SequenceEqual(bytes))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        // This fixed child belongs to the already accepted running bundle. Parent
        // checks acceptance independently; the child performs no network/authority checks.
        string text = await RunAsync(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes), FrameAsync, ct).ConfigureAwait(false);
        firstFiles.Require(); secondFiles.Require();
        if (!firstFiles.Read(path, sharedReader: true, maximumBytes: Limit).AsSpan().SequenceEqual(bytes))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        byte[] output = new UTF8Encoding(false, true).GetBytes(text);
        if (output.Length > Limit) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        CurrentAuthArchiveDeviceProof proof = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveDeviceProof>(output);
        if (!JsonSerializer.SerializeToUtf8Bytes(proof).AsSpan().SequenceEqual(output)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        CurrentAuthLocalSessionArchiveRecoveryDevices.RequireSubject(proof, scope, firstRoot, secondRoot);
        return proof;

        async Task FrameAsync(CurrentAuthArchiveDeviceResource resource)
        {
            using var bound = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            byte[] frame = JsonSerializer.SerializeToUtf8Bytes(new { scope.OperationId, Resource = resource });
            string framePath = Path.Combine(firstRoot, $"resource-auth-archive-device-{Guid.NewGuid():N}.json");
            await firstFiles.WriteNewAsync(framePath, frame, bound.Token).ConfigureAwait(false);
            if (!firstFiles.Read(framePath, maximumBytes: Limit).AsSpan().SequenceEqual(frame))
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
    }

    internal static ProcessStartInfo StartInfo(string configPath, string configSha256)
    {
        if (!Path.IsPathFullyQualified(configPath) || !CurrentAuthRepairPermit.HashShape(configSha256))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        string executable = Path.Combine(AppContext.BaseDirectory, "Legacy.Maliev.DataMigration.Console.exe");
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = new UTF8Encoding(false, true),
            StandardErrorEncoding = new UTF8Encoding(false, true),
            WorkingDirectory = AppContext.BaseDirectory,
        };
        start.Environment.Clear();
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        start.Environment["SystemRoot"] = windows; start.Environment["WINDIR"] = windows;
        start.ArgumentList.Add(Command); start.ArgumentList.Add(Path.GetFullPath(configPath)); start.ArgumentList.Add(configSha256);
        return start;
    }

    private static async Task<string> RunAsync(string configPath, string configSha256,
        Func<CurrentAuthArchiveDeviceResource, Task> observe, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        ProcessStartInfo start = StartInfo(configPath, configSha256);
        // Every running bundle file is owner/link/handle checked and held read-only
        // through final child exit. No replacing a DLL between acceptance and launch.
        var bundle = new List<FileStream>();
        try
        {
            string[] names = Directory.GetFiles(AppContext.BaseDirectory, "*", SearchOption.AllDirectories);
            if (names.Length is < 1 or > 1024) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            foreach (string name in names)
            {
                FileStream held = SecureLocalFile.OpenReadShared(name);
                if (!SecureLocalFile.HandleResolvesToApprovedPath(held, name)) { held.Dispose(); throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                bundle.Add(held);
            }
            using var image = SecureLocalFile.OpenReadShared(start.FileName);
            string imageSha = Convert.ToHexStringLower(await SHA256.HashDataAsync(image, ct).ConfigureAwait(false));
            string imageIdentity = SecureLocalFile.GetHandleIdentity(image);
            using var process = new Process { StartInfo = start };
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(Lifetime);
            using var readers = new CancellationTokenSource();
            CurrentAuthArchiveDeviceResource resource = new(Guid.NewGuid(), start.FileName, imageSha, null, null,
                DateTimeOffset.UtcNow.Add(Lifetime + Cleanup + Cleanup + TimeSpan.FromSeconds(20)), false, false, false);
            Task<string>? stdout = null, stderr = null; bool started = false;
            try
            {
                ct.ThrowIfCancellationRequested();
                if (!SecureLocalFile.HandleResolvesToApprovedPath(image, start.FileName) || SecureLocalFile.GetHandleIdentity(image) != imageIdentity || !process.Start())
                { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                started = true; _ = process.SafeHandle;
                resource = resource with { ProcessId = process.Id };
                resource = resource with { StartUtcTicks = process.StartTime.ToUniversalTime().Ticks };
                if (!string.Equals(process.MainModule?.FileName, start.FileName, StringComparison.OrdinalIgnoreCase))
                { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                // Readers start before the durable start frame, so output cannot block
                // the child while evidence custody is being acknowledged.
                process.StandardInput.Close();
                stdout = ReadAsync(process.StandardOutput, readers.Token); stderr = ReadAsync(process.StandardError, readers.Token);
                await observe(resource).ConfigureAwait(false); deadline.Token.ThrowIfCancellationRequested();
                Task exited = process.WaitForExitAsync(deadline.Token);
                var pending = new List<Task> { exited, stdout, stderr };
                while (pending.Count != 0)
                {
                    Task finished = await Task.WhenAny(pending).WaitAsync(deadline.Token).ConfigureAwait(false);
                    _ = pending.Remove(finished); await finished.ConfigureAwait(false);
                }
                string result = await stdout.ConfigureAwait(false);
                return process.ExitCode != 0 || result.Length == 0 || (await stderr.ConfigureAwait(false)).Length != 0 ||
                    SecureLocalFile.GetHandleIdentity(image) != imageIdentity
                    ? throw CurrentAuthLocalSessionArchivePolicy.Invalid()
                    : result;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            finally { await CompleteCleanupAsync().ConfigureAwait(false); }

            async Task CompleteCleanupAsync()
            {
                Exception? failure = null;
                if (started)
                {
                    try
                    {
                        process.Refresh();
                        if ((resource.ProcessId is { } pid && process.Id != pid) ||
                            (resource.StartUtcTicks is { } ticks && process.StartTime.ToUniversalTime().Ticks != ticks))
                        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                        if (!process.HasExited) { try { process.Kill(); } catch (InvalidOperationException) when (process.HasExited) { } }
                        await process.WaitForExitAsync(CancellationToken.None).WaitAsync(Cleanup, CancellationToken.None).ConfigureAwait(false);
                        if (!process.HasExited) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                        resource = resource with { Exited = true };
                    }
                    catch (Exception problem) when (problem is InvalidOperationException or System.ComponentModel.Win32Exception or TimeoutException or MigrationExecutionException)
                    { failure = problem; }
                }
                await readers.CancelAsync().ConfigureAwait(false);
                if (started)
                {
                    try { process.StandardInput.Dispose(); } catch (IOException problem) { failure ??= problem; }
                    try { process.StandardOutput.Dispose(); } catch (IOException problem) { failure ??= problem; }
                    try { process.StandardError.Dispose(); } catch (IOException problem) { failure ??= problem; }
                }
                try { await SettleAsync(stdout, stderr).WaitAsync(Cleanup, CancellationToken.None).ConfigureAwait(false); resource = resource with { ReadersSettled = true }; }
                catch (TimeoutException problem) { failure ??= problem; }
                resource = resource with { CleanupFailed = failure is not null };
                // Final evidence failure prevents success after exact process cleanup.
                await observe(resource).ConfigureAwait(false);
                if (failure is not null) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            }
        }
        finally { foreach (FileStream held in bundle) { held.Dispose(); } }
    }
    internal static Task<string> ReadOutputForTestAsync(StreamReader reader, CancellationToken ct)
    {
        return ReadAsync(reader, ct);
    }

    private static async Task<string> ReadAsync(StreamReader reader, CancellationToken ct)
    {
        var text = new StringBuilder(4096); char[] buffer = new char[4096];
        while (true)
        {
            int count = await reader.ReadAsync(buffer.AsMemory(), ct).ConfigureAwait(false);
            if (count == 0) { return text.ToString(); }
            if (count > Limit - text.Length) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            _ = text.Append(buffer, 0, count);
        }
    }
    private static async Task SettleAsync(Task<string>? stdout, Task<string>? stderr)
    {
        foreach (Task<string>? task in new[] { stdout, stderr })
        {
            if (task is null) { continue; }
            try { _ = await task.ConfigureAwait(false); }
            catch (Exception failure) when (failure is OperationCanceledException or IOException or ObjectDisposedException or InvalidOperationException or MigrationExecutionException or DecoderFallbackException) { }
        }
    }
}

public static partial class MigrationConsole
{
    internal static (string Path, string Sha256) RequireArchiveDeviceInvocation(IReadOnlyList<string> arguments)
    {
        return arguments.Count != 3 || arguments[0] != CurrentAuthLocalSessionArchiveDeviceProcess.Command ||
            !Path.IsPathFullyQualified(arguments[1]) || !CurrentAuthRepairPermit.HashShape(arguments[2])
            ? throw new CommandLineException("current_auth_archive_device_arguments_invalid", "A fixed protected device request path and digest are required.")
            : ((string Path, string Sha256))(Path.GetFullPath(arguments[1]), arguments[2]);
    }
    // New fixed dispatcher candidate only. Root must integrate it; there is no
    // generic executable, device write, network operation or injected callback.
    private static async Task<int> RunCurrentAuthArchiveDeviceObserverAsync(string configPath, string configSha256,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            if (!OperatingSystem.IsWindows() || !CurrentAuthRepairPermit.HashShape(configSha256)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            using FileStream held = SecureLocalFile.OpenReadShared(configPath);
            if (!SecureLocalFile.HandleResolvesToApprovedPath(held, configPath) || held.Length is < 1 or > 65536) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            string identity = SecureLocalFile.GetHandleIdentity(held); byte[] bytes = new byte[checked((int)held.Length)];
            await held.ReadExactlyAsync(bytes, ct).ConfigureAwait(false);
            CurrentAuthArchiveDeviceRequest request = DecodeAuthRepair<CurrentAuthArchiveDeviceRequest>(bytes);
            CurrentAuthLocalSessionArchivePolicy.RequireScope(request.Scope, DateTimeOffset.UtcNow);
            CurrentAuthLocalSessionArchiveEnvironment.RequireObservationPolicies(request.Scope, DateTimeOffset.UtcNow);
            if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != configSha256 ||
                !JsonSerializer.SerializeToUtf8Bytes(request).AsSpan().SequenceEqual(bytes) ||
                CompiledDeviceSource(typeof(MigrationConsole).Assembly) != request.Scope.LocalObservationPolicy.SourceCommitSha ||
                CompiledDeviceSource(typeof(DeltaExecutionCoordinator).Assembly) != request.Scope.LocalObservationPolicy.SourceCommitSha)
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            CurrentAuthArchiveDeviceProof proof = CurrentAuthLocalSessionArchiveRecoveryDevices.ObserveInChild(request.Scope, request.FirstRoot, request.SecondRoot, ct);
            if (SecureLocalFile.GetHandleIdentity(held) != identity || !SecureLocalFile.HandleResolvesToApprovedPath(held, configPath)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            await output.WriteAsync(JsonSerializer.Serialize(proof)).ConfigureAwait(false); return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or IOException or UnauthorizedAccessException or JsonException or ArgumentException or InvalidOperationException)
        { await error.WriteAsync("current_auth_archive_device_observer_failed").ConfigureAwait(false); return 1; }
    }
    private static string CompiledDeviceSource(Assembly assembly)
    {
        return SourceBackedLocalRepairSourceAcceptance.RequireCompiledSourceRevision(
        assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "");
    }
}
