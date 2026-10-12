using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAppOwnedDockerResource(Guid RunId, string Executable, string ExecutableSha256,
    int? ProcessId, long? StartUtcTicks, DateTimeOffset ExpiresAtUtc, bool Exited, bool ReadersSettled, bool CleanupFailed);

/// <summary>Bounded read-only Docker CLI observations; retained exact child ownership on every exit path.</summary>
internal static class CurrentAppOwnedRepairDockerProcess
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan Cleanup = TimeSpan.FromSeconds(5);
    private const int OutputLimit = 2_000_000;

    internal static Task<string> RunDockerAsync(IReadOnlyList<string> arguments, CancellationToken ct,
        Func<CurrentAppOwnedDockerResource, Task>? observe = null)
    {
        if (!OperatingSystem.IsWindows()) { throw Failure("platform"); }
        string executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Docker", "Docker", "resources", "bin", "docker.exe");
        return RunOwnedAsync(executable, ["--context", "default", .. arguments], Lifetime, OutputLimit, ct, observe);
    }

    // Test seam only: production fixes the executable, arguments prefix, lifetime and bounds above.
    // No environment implementation or execution permission is accepted from serialized configuration.
    internal static Task<string> RunChildForTestAsync(string executable, IReadOnlyList<string> arguments,
        TimeSpan lifetime, int maximumCharacters, CancellationToken ct, Action<CurrentAppOwnedDockerResource> observe) =>
        RunOwnedAsync(executable, arguments, lifetime, maximumCharacters, ct, resource =>
        {
            observe(resource);
            return Task.CompletedTask;
        });

    internal static Task<string> RunChildWithAsyncObserverForTestAsync(string executable, IReadOnlyList<string> arguments,
        TimeSpan lifetime, int maximumCharacters, CancellationToken ct, Func<CurrentAppOwnedDockerResource, Task> observe) =>
        RunOwnedAsync(executable, arguments, lifetime, maximumCharacters, ct, observe);

    private static async Task<string> RunOwnedAsync(string executable, IReadOnlyList<string> arguments,
        TimeSpan lifetime, int maximumCharacters, CancellationToken ct, Func<CurrentAppOwnedDockerResource, Task>? observe)
    {
        ct.ThrowIfCancellationRequested();
        if (!Path.IsPathFullyQualified(executable) || lifetime <= TimeSpan.Zero || lifetime > Lifetime ||
            maximumCharacters is < 1 or > OutputLimit || arguments.Any(x => x is null || x.Contains('\0')))
        { throw Failure("input"); }
        executable = Path.GetFullPath(executable);
        // Hold the executable against writes/deletion while its identity is captured and launched.
        using var image = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read);
        string imageSha = Convert.ToHexStringLower(SHA256.HashData(image));
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        // Do not inherit tokens, credential overrides, debug switches or caller script variables.
        // Docker's built-in default context uses the same Windows user profile; no shell is used.
        start.Environment.Clear();
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        start.Environment["SystemRoot"] = windows;
        start.Environment["WINDIR"] = windows;
        start.Environment["USERPROFILE"] = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        start.Environment["TEMP"] = Path.GetTempPath();
        start.Environment["TMP"] = Path.GetTempPath();
        foreach (string argument in arguments) { start.ArgumentList.Add(argument); }
        using var process = new Process { StartInfo = start };
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(lifetime);
        using var readers = new CancellationTokenSource();
        CurrentAppOwnedDockerResource resource = new(Guid.NewGuid(), executable, imageSha, null, null,
            DateTimeOffset.UtcNow.Add(lifetime + Cleanup + Cleanup), false, false, false);
        Task<string>? stdout = null;
        Task<string>? stderr = null;
        bool started = false;
        try
        {
            ct.ThrowIfCancellationRequested();
            if (!process.Start()) { throw Failure("start"); }
            started = true;
            // Opening/retaining the kernel process handle protects cleanup against PID reuse.
            _ = process.SafeHandle;
            resource = resource with { ProcessId = process.Id };
            resource = resource with { StartUtcTicks = process.StartTime.ToUniversalTime().Ticks };
            if (observe is not null) { await observe(resource).ConfigureAwait(false); }
            process.StandardInput.Close();
            stdout = ReadBoundedAsync(process.StandardOutput, maximumCharacters, readers.Token);
            stderr = ReadBoundedAsync(process.StandardError, maximumCharacters, readers.Token);
            Task exited = process.WaitForExitAsync(timeout.Token);
            // Continue observing both readers even if one stream reaches EOF before child exit.
            var pending = new List<Task> { exited, stdout, stderr };
            while (pending.Count != 0)
            {
                Task finished = await Task.WhenAny(pending).WaitAsync(timeout.Token).ConfigureAwait(false);
                _ = pending.Remove(finished);
                await finished.ConfigureAwait(false);
            }
            string content = await stdout.ConfigureAwait(false);
            if (process.ExitCode != 0 || content.Length == 0) { throw Failure("child"); }
            return content;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { throw Failure("timeout"); }
        finally
        {
            Exception? cleanupFailure = null;
            if (started)
            {
                try
                {
                    process.Refresh();
                    if ((resource.ProcessId is { } pid && process.Id != pid) ||
                        (resource.StartUtcTicks is { } ticks && process.StartTime.ToUniversalTime().Ticks != ticks))
                    { throw Failure("identity"); }
                    if (!process.HasExited)
                    {
                        // Uses the retained exact process handle. Never kill descendants or enumerate a tree.
                        try { process.Kill(); }
                        catch (InvalidOperationException) when (process.HasExited) { }
                    }
                    await process.WaitForExitAsync().WaitAsync(Cleanup).ConfigureAwait(false);
                    if (!process.HasExited) { throw Failure("exit"); }
                    resource = resource with { Exited = true };
                }
                catch (Exception failure) when (failure is InvalidOperationException or System.ComponentModel.Win32Exception or
                    TimeoutException or MigrationConsoleException)
                { cleanupFailure = failure; }
            }
            await readers.CancelAsync().ConfigureAwait(false);
            // Close the parent's pipe ends even if another process inherited a writer. No tree termination.
            if (started)
            {
                try { process.StandardOutput.Dispose(); }
                catch (IOException failure) { cleanupFailure ??= failure; }
                try { process.StandardError.Dispose(); }
                catch (IOException failure) { cleanupFailure ??= failure; }
                try { process.StandardInput.Dispose(); }
                catch (IOException failure) { cleanupFailure ??= failure; }
            }
            try
            {
                await SettleAsync(stdout, stderr).WaitAsync(Cleanup).ConfigureAwait(false);
                resource = resource with { ReadersSettled = true };
            }
            catch (TimeoutException failure) { cleanupFailure ??= failure; }
            resource = resource with { CleanupFailed = cleanupFailure is not null };
            // Test evidence is PII-free: no arguments, output, environment values or credentials.
            if (observe is not null) { await observe(resource).ConfigureAwait(false); }
            if (cleanupFailure is not null) { throw Failure("cleanup"); }
        }
    }

    private static async Task<string> ReadBoundedAsync(StreamReader stream, int maximum, CancellationToken ct)
    {
        var text = new StringBuilder(Math.Min(maximum, 4096));
        char[] buffer = new char[4096];
        while (true)
        {
            int count = await stream.ReadAsync(buffer.AsMemory(), ct).ConfigureAwait(false);
            if (count == 0) { return text.ToString(); }
            if (count > maximum - text.Length) { throw Failure("output"); }
            _ = text.Append(buffer, 0, count);
        }
    }

    private static async Task SettleAsync(Task<string>? stdout, Task<string>? stderr)
    {
        foreach (Task<string>? task in new[] { stdout, stderr })
        {
            if (task is null) { continue; }
            try { _ = await task.ConfigureAwait(false); }
            catch (Exception failure) when (failure is OperationCanceledException or IOException or ObjectDisposedException or
                InvalidOperationException or MigrationConsoleException) { }
        }
    }

    private static MigrationConsoleException Failure(string category) =>
        new("current_app_owned_docker_" + category + "_failed", "The bounded repair target observer failed without exposing child output.");
}
