using System.Diagnostics;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveHelperLauncherFactAttribute : FactAttribute
{
    public CurrentAuthArchiveHelperLauncherFactAttribute()
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("MALIEV_AUTH_ARCHIVE_HELPER_HOST_CONFIG")) ||
            string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("MALIEV_AUTH_ARCHIVE_HELPER_CONSOLE_IMAGE")))
        { Skip = "Requires fresh protected three-root helper host configuration, accepted images, signed input and actual native resources."; }
    }
}

[Collection(CurrentAuthNativeProofGroup.Name)]
public sealed class CurrentAuthArchiveProofSdkLauncherNativeTests
{
    [Theory]
    [InlineData("untrusted.dll")]
    [InlineData("Legacy.Maliev.DataMigration.Console.exe")]
    public async Task Driver_rejects_another_entry_image_before_bundle_access_or_process_start(string name)
    {
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => HoldConsoleBundleAsync(Path.Combine(Path.GetTempPath(), name), CancellationToken.None));
    }

    [CurrentAuthArchiveHelperLauncherFact]
    public async Task Actual_helper_launcher_observes_real_provider_sdk_exit_and_trx_after_cleanup()
    {
        string path = Environment.GetEnvironmentVariable("MALIEV_AUTH_ARCHIVE_HELPER_HOST_CONFIG") ??
            throw new InvalidOperationException("archive_helper_host_configuration_required");
        string console = Environment.GetEnvironmentVariable("MALIEV_AUTH_ARCHIVE_HELPER_CONSOLE_IMAGE") ??
            throw new InvalidOperationException("archive_helper_frozen_console_required");
        var config = CurrentAuthArchiveHelperHost.Decode<CurrentAuthArchiveHelperHostConfiguration>(CurrentAuthArchiveHelperHost.Read(path, 65536));
        CurrentAuthArchiveHelperHost.RequireConfiguration(config, path);
        var request = CurrentAuthArchiveHelperHost.Request(config);
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        using var bundle = await HoldConsoleBundleAsync(console, timeout.Token);
        using var dotnet = new FileStream(CurrentAuthArchiveHelperHost.Tool("dotnet"), FileMode.Open, FileAccess.Read, FileShare.Read);
        Assert.True(SecureLocalFile.HandleResolvesToApprovedPath(dotnet, CurrentAuthArchiveHelperHost.Tool("dotnet")));
        Assert.Equal(request.Inputs.ConsoleImage.Sha256, CurrentAuthTypedHostProducer.ImageHash(console));
        ProcessStartInfo start = CurrentAuthArchiveHelperHost.Start(Path.GetDirectoryName(path)!);
        start.ArgumentList.Add(console); start.ArgumentList.Add(CurrentAuthArchiveHelperHost.ParentCommand);
        start.ArgumentList.Add("--config"); start.ArgumentList.Add(path);
        using var process = new Process { StartInfo = start };
        Assert.True(process.Start());
        _ = process.SafeHandle;
        DateTimeOffset began = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
        string ledger = Path.Combine(Path.GetDirectoryName(path)!, "archive-helper-native-driver-" + Guid.NewGuid().ToString("N"));
        process.StandardInput.Close();
        Task stdout = CurrentAuthTypedHostProducer.DrainAsync(process.StandardOutput, timeout.Token);
        Task stderr = CurrentAuthTypedHostProducer.DrainAsync(process.StandardError, timeout.Token);
        try
        {
            await CurrentAuthArchiveHelperHost.WriteAsync(ledger + "-started.json", JsonSerializer.SerializeToUtf8Bytes(new
            {
                Purpose = "archive-helper-native-driver",
                ProcessId = process.Id,
                ProcessStartTimeUtc = began,
                Executable = start.FileName,
                ConsoleImage = console,
                ExpiresAtUtc = began.AddMinutes(10),
            }), timeout.Token);
            await process.WaitForExitAsync(timeout.Token); await Task.WhenAll(stdout, stderr);
            bundle.Require();
            Assert.Equal(0, process.ExitCode);
        }
        finally
        {
            if (!process.HasExited)
            {
                Assert.Equal(began, new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero));
                Assert.Equal(CurrentAuthArchiveHelperHost.Tool("dotnet"), process.MainModule?.FileName, StringComparer.OrdinalIgnoreCase);
                process.Kill(); await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None);
            }
            using var settle = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try { await Task.WhenAll(stdout, stderr).WaitAsync(settle.Token); }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested && stdout.IsCompleted && stderr.IsCompleted) { }
            await CurrentAuthArchiveHelperHost.WriteAsync(ledger + "-completed.json", JsonSerializer.SerializeToUtf8Bytes(new
            { ProcessId = process.Id, ProcessStartTimeUtc = began, Exited = process.HasExited, CompletedAtUtc = DateTimeOffset.UtcNow }), settle.Token);
        }
    }

    private static async Task<HeldConsoleBundle> HoldConsoleBundleAsync(string image, CancellationToken ct)
    {
        const string accepted = @"B:\maliev-legacy\Legacy.Maliev.DataMigration\src\Legacy.Maliev.DataMigration.Console\bin\Release\net10.0";
        if (!Path.IsPathFullyQualified(image) || Path.GetFileName(image) != "Legacy.Maliev.DataMigration.Console.dll")
        { throw new InvalidOperationException("archive_helper_console_image_unaccepted"); }
        string running = Path.GetDirectoryName(image)!;
        var held = new HeldConsoleBundle();
        try
        {
            foreach (string path in Directory.GetFiles(accepted, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
            {
                ct.ThrowIfCancellationRequested();
                held.Add(path, requireOwner: false);
                held.Add(Path.Combine(running, Path.GetRelativePath(accepted, path)), requireOwner: true);
            }
            // Compare against the fixed independent canonical bundle while all code/dependency bytes are held.
            await SourceBackedLocalRepairSourceAcceptance.RequireBundleForPathsAsync(accepted, running, ct);
            held.Require(); return held;
        }
        catch { held.Dispose(); throw; }
    }

    private sealed class HeldConsoleBundle : IDisposable
    {
        private readonly List<(FileStream Stream, string Path)> _files = [];
        internal void Add(string path, bool requireOwner)
        {
            FileStream stream = requireOwner ? SecureLocalFile.OpenReadShared(path) : new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                if (!SecureLocalFile.HandleResolvesToApprovedPath(stream, path)) { throw new InvalidOperationException("archive_helper_console_bundle_unprotected"); }
                _files.Add((stream, path));
            }
            catch { stream.Dispose(); throw; }
        }
        internal void Require()
        {
            foreach (var file in _files)
            {
                if (!SecureLocalFile.HandleResolvesToApprovedPath(file.Stream, file.Path)) { throw new InvalidOperationException("archive_helper_console_bundle_changed"); }
            }
        }
        public void Dispose() { foreach (var file in _files) { file.Stream.Dispose(); } }
    }
}
