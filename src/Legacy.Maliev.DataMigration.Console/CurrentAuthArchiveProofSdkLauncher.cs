using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveHelperHostConfiguration(string Kind, CurrentAuthArchiveProofArtifact ControlBinding,
    CurrentAuthArchiveProofArtifact CaseInput, CurrentAuthArchiveGenuineRecoveryHelperCase ExpectedCase);
internal sealed record CurrentAuthArchiveHelperRun(string Kind, string Nonce, CurrentAuthArchiveHelperHostConfiguration Configuration,
    Guid OperationId, string ConsoleImage, string InputRoot, string SourceCommitSha, DateTimeOffset BeganAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record CurrentAuthArchiveHelperGate(string Nonce, int ProcessId, DateTimeOffset ProcessStartTimeUtc, string ControlBindingSha256);
internal sealed record CurrentAuthArchiveHelperProviderResult(CurrentAuthArchiveGenuineProviderCaseResult Case,
    string SourceCommitSha, string InputSha256);

internal static class CurrentAuthArchiveHelperHost
{
    private static readonly string[] ToolNames = ["dotnet", "git", "gh", "docker"];
    internal const string ParentCommand = "produce-current-auth-archive-helper-host";
    internal const string ChildCommand = "run-current-auth-archive-helper-sdk";
    internal const string ProviderCommand = "execute-current-auth-archive-helper-provider";
    internal const string RunVariable = "MALIEV_AUTH_ARCHIVE_HELPER_RUN";
    internal const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";

    internal static string Tool(string name)
    {
        return name switch
        {
            "dotnet" => CurrentAuthTypedHostProducer.Dotnet,
            "git" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "cmd", "git.exe"),
            "gh" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "GitHub CLI", "gh.exe"),
            "docker" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Docker", "Docker", "resources", "bin", "docker.exe"),
            _ => throw Invalid(),
        };
    }

    internal static ProcessStartInfo Start(string controlRoot)
    {
        ProcessStartInfo start = CurrentAuthTypedHostProducer.FixedStart(controlRoot);
        // Bare fixed-gate Git/GH lookups must never search the writable evidence root first.
        start.WorkingDirectory = Environment.SystemDirectory;
        start.RedirectStandardInput = true; start.RedirectStandardOutput = true; start.RedirectStandardError = true;
        // Fixed installed directories only; neither caller PATH nor tokens are inherited.
        start.Environment["PATH"] = string.Join(';', ToolNames.Select(x => Path.GetDirectoryName(Tool(x)))
            .Append(Environment.SystemDirectory));
        foreach (var item in new[] { ("USERPROFILE", Environment.SpecialFolder.UserProfile),
            ("APPDATA", Environment.SpecialFolder.ApplicationData), ("LOCALAPPDATA", Environment.SpecialFolder.LocalApplicationData) })
        {
            string value = Environment.GetFolderPath(item.Item2);
            if (!Path.IsPathFullyQualified(value)) { throw Invalid(); }
            start.Environment[item.Item1] = value;
        }
        start.Environment["GIT_TERMINAL_PROMPT"] = "0"; start.Environment["GH_PROMPT_DISABLED"] = "1";
        start.Environment["GIT_OPTIONAL_LOCKS"] = "0";
        start.Environment["GIT_CONFIG_NOSYSTEM"] = "1"; start.Environment["GIT_CONFIG_GLOBAL"] = "NUL";
        start.Environment["GIT_CONFIG_COUNT"] = "2";
        start.Environment["GIT_CONFIG_KEY_0"] = "core.fsmonitor"; start.Environment["GIT_CONFIG_VALUE_0"] = "false";
        start.Environment["GIT_CONFIG_KEY_1"] = "core.untrackedCache"; start.Environment["GIT_CONFIG_VALUE_1"] = "false";
        start.Environment["LEGACY_DEPLOY_ENABLED"] = "false";
        return start;
    }

    internal static void RequireConfiguration(CurrentAuthArchiveHelperHostConfiguration config, string path)
    {
        if (config is null || config.Kind != "current-auth-archive-helper-host-v1" ||
            config.ControlBinding is null || config.CaseInput is null || !Path.IsPathFullyQualified(path) ||
            !Path.IsPathFullyQualified(config.ControlBinding.Path) || !Path.IsPathFullyQualified(config.CaseInput.Path) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(path), Path.GetDirectoryName(config.ControlBinding.Path)) ||
            StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(path), Path.GetDirectoryName(config.CaseInput.Path))) { throw Invalid(); }
        _ = CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(config.ExpectedCase);
    }

    internal static CurrentAuthArchiveGenuineHostConfiguration Request(CurrentAuthArchiveHelperHostConfiguration config)
    {
        byte[] bytes = Read(config.CaseInput.Path, 65536);
        if (Hash(bytes) != config.CaseInput.Sha256) { throw Invalid(); }
        using var packet = JsonDocument.Parse(bytes);
        string kind = config.ExpectedCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback
            ? "current-auth-archive-genuine-dual-helper-input-v1" : "current-auth-archive-genuine-recovery-helper-input-v1";
        if (packet.RootElement.GetProperty("Kind").GetString() != kind) { throw Invalid(); }
        var request = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveGenuineHostConfiguration>(JsonSerializer.SerializeToUtf8Bytes(packet.RootElement.GetProperty("Request")));
        CurrentAuthArchiveGenuineHost.RequireInput(request);
        return request.Phase != "helper" || request.CaseId != CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(config.ExpectedCase) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(config.CaseInput.Path), Path.GetDirectoryName(request.Inputs.ParentBinding.Path)) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(config.CaseInput.Path), Path.GetDirectoryName(request.Inputs.TestImage.Path))
            ? throw Invalid()
            : request;
    }

    internal static byte[] Read(string path, int maximum)
    {
        if (!Path.IsPathFullyQualified(path)) { throw Invalid(); }
        using var held = SecureLocalFile.OpenReadShared(path);
        if (held.Length < 1 || held.Length > maximum || !SecureLocalFile.HandleResolvesToApprovedPath(held, path)) { throw Invalid(); }
        byte[] bytes = new byte[checked((int)held.Length)]; held.ReadExactly(bytes); return bytes;
    }
    internal static T Decode<T>(byte[] bytes)
    {
        return MigrationConsole.DecodeAuthRepair<T>(bytes);
    }

    internal static string Hash(byte[] bytes)
    {
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }

    internal static string Prefix(string runPath)
    {
        return Path.Combine(Path.GetDirectoryName(runPath)!, Path.GetFileNameWithoutExtension(runPath));
    }

    internal static async Task WriteAsync(string path, byte[] bytes, CancellationToken ct)
    {
        SecureLocalFile.EnsureOwnerOnlyDirectory(Path.GetDirectoryName(path)!);
        await using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
        {
            if (!SecureLocalFile.HandleResolvesToApprovedPath(stream, path) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path))) { throw Invalid(); }
            await stream.WriteAsync(bytes, ct); await stream.FlushAsync(ct); stream.Flush(true);
        }
        if (!Read(path, Math.Max(bytes.Length, 1)).AsSpan().SequenceEqual(bytes)) { throw Invalid(); }
    }
    internal static void RequireRun(CurrentAuthArchiveHelperRun run, string path)
    {
        RequireConfiguration(run.Configuration, path);
        if (run.Kind != "current-auth-archive-helper-run-v1" || !Guid.TryParseExact(run.Nonce, "N", out _) ||
            run.OperationId == Guid.Empty || run.BeganAtUtc.Offset != TimeSpan.Zero || run.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            run.BeganAtUtc > DateTimeOffset.UtcNow || run.ExpiresAtUtc <= DateTimeOffset.UtcNow || run.ExpiresAtUtc - run.BeganAtUtc != TimeSpan.FromMinutes(8) ||
            Path.GetFileName(path) != "archive-helper-" + run.Nonce + ".json" ||
            !Path.IsPathFullyQualified(run.ConsoleImage) || Path.GetFileName(run.ConsoleImage) != "Legacy.Maliev.DataMigration.Console.dll" ||
            !StringComparer.OrdinalIgnoreCase.Equals(run.InputRoot, Path.GetDirectoryName(run.Configuration.CaseInput.Path)) ||
            StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(run.ConsoleImage), run.InputRoot) ||
            StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(run.ConsoleImage), Path.GetDirectoryName(path))) { throw Invalid(); }
    }
    internal static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveGenuineHost.Invalid("helper_host");
    }

    internal static void RequireTrx(byte[] bytes, string methodName, string? expectedAssemblyPath = null)
    {
        using var stream = new MemoryStream(bytes);
        using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        XDocument document = XDocument.Load(reader); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        XElement result = document.Descendants(ns + "UnitTestResult").Single();
        XElement test = document.Descendants(ns + "UnitTest").Single(); XElement method = test.Element(ns + "TestMethod") ?? throw Invalid();
        XElement counters = document.Descendants(ns + "Counters").Single();
        string fullName = "Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveGuardedExecutionTests." + methodName;
        if ((string?)result.Attribute("outcome") != "Passed" || ((string?)result.Attribute("testName") != methodName && (string?)result.Attribute("testName") != fullName) ||
            (string?)method.Attribute("name") != methodName || (string?)method.Attribute("className") != "Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveGuardedExecutionTests" ||
            (string?)result.Attribute("testId") != (string?)test.Attribute("id") || !Guid.TryParse((string?)result.Attribute("executionId"), out _) ||
            (string?)counters.Attribute("total") != "1" || (string?)counters.Attribute("passed") != "1" || (string?)counters.Attribute("executed") != "1") { throw Invalid(); }
        if (expectedAssemblyPath is not null && (!SamePath((string?)method.Attribute("codeBase"), expectedAssemblyPath) ||
            !SamePath((string?)test.Attribute("storage"), expectedAssemblyPath))) { throw Invalid(); }

        static bool SamePath(string? value, string expected)
        {
            if (string.IsNullOrWhiteSpace(value)) { return false; }
            string path = Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) && uri.IsFile ? uri.LocalPath : value;
            return Path.IsPathFullyQualified(path) && StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(path), Path.GetFullPath(expected));
        }
    }
}

public static partial class MigrationConsole
{
    private static async Task<int> RunCurrentAuthArchiveHelperHostAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
            byte[] initial = CurrentAuthArchiveHelperHost.Read(configPath, 65536);
            var config = CurrentAuthArchiveHelperHost.Decode<CurrentAuthArchiveHelperHostConfiguration>(initial);
            CurrentAuthArchiveHelperHost.RequireConfiguration(config, configPath);
            byte[] bindingBytes = CurrentAuthArchiveHelperHost.Read(config.ControlBinding.Path, 65536);
            if (CurrentAuthArchiveHelperHost.Hash(bindingBytes) != config.ControlBinding.Sha256) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            var binding = CurrentAuthArchiveHelperHost.Decode<LocalExecutionBinding>(bindingBytes);
            using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            if (!files.Read(configPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(initial)) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            using var heldCaseInput = SecureLocalFile.OpenReadShared(config.CaseInput.Path);
            if (!SecureLocalFile.HandleResolvesToApprovedPath(heldCaseInput, config.CaseInput.Path) || heldCaseInput.Length is < 1 or > 65536 ||
                Convert.ToHexStringLower(await SHA256.HashDataAsync(heldCaseInput, ct)) != config.CaseInput.Sha256) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            var request = CurrentAuthArchiveHelperHost.Request(config);
            byte[] seedBytes = CurrentAuthArchiveHelperHost.Read(request.Inputs.ParentSeed.Path, 65536);
            if (CurrentAuthArchiveHelperHost.Hash(seedBytes) != request.Inputs.ParentSeed.Sha256) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            var seed = CurrentAuthArchiveHelperHost.Decode<CurrentAuthArchiveComponentBootstrapSeed>(seedBytes);
            string inputRoot = Path.GetDirectoryName(config.CaseInput.Path)!;
            using var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(inputRoot, ct);
            DateTimeOffset began = DateTimeOffset.UtcNow; string nonce = Guid.NewGuid().ToString("N");
            var run = new CurrentAuthArchiveHelperRun("current-auth-archive-helper-run-v1", nonce, config, seed.OperationId,
                typeof(MigrationConsole).Assembly.Location, inputRoot, accepted, began, began.AddMinutes(8));
            string runPath = Path.Combine(binding.ArtifactRootCanonicalPath, "archive-helper-" + nonce + ".json");
            CurrentAuthArchiveHelperHost.RequireRun(run, runPath);
            await files.WriteNewAsync(runPath, JsonSerializer.SerializeToUtf8Bytes(run), ct);
            _ = files.Read(runPath, sharedReader: true, maximumBytes: 65536);
            string[] images = [CurrentAuthArchiveHelperHost.Tool("dotnet"), Path.Combine(inputRoot, "testhost.exe"),
                CurrentAuthArchiveHelperHost.Tool("git"), CurrentAuthArchiveHelperHost.Tool("gh"), CurrentAuthArchiveHelperHost.Tool("docker")];
            var heldImages = new List<FileStream>();
            try
            {
                foreach (string image in images)
                {
                    var held = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read);
                    heldImages.Add(held);
                    if (!SecureLocalFile.HandleResolvesToApprovedPath(held, image)) { throw CurrentAuthArchiveHelperHost.Invalid(); }
                }
                using var job = new CurrentAuthTypedHostJob(images, nonce);
                _ = job.Observe(admission: true);
                await RunJobAsync(job, run, runPath, request, files, bundle, ct);
            }
            finally { foreach (FileStream held in heldImages) { held.Dispose(); } }
            await output.WriteLineAsync("archive_helper_host_observed_no_phase_proof"); return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or InvalidOperationException or OperationCanceledException or AggregateException or System.ComponentModel.Win32Exception)
        { await error.WriteLineAsync("archive_helper_host_failed_no_phase_proof"); return 1; }
    }

    private static async Task RunJobAsync(CurrentAuthTypedHostJob job, CurrentAuthArchiveHelperRun run, string runPath,
        CurrentAuthArchiveGenuineHostConfiguration request, CurrentAppOwnedRepairCustody files,
        CurrentAuthTypedHostProducer.HeldTestBundle bundle, CancellationToken ct)
    {
        var resources = new CurrentAuthArchiveHelperResources(run, request);
        await resources.ObserveBeforeAsync(files, runPath, ct);
        ProcessStartInfo start = CurrentAuthArchiveHelperHost.Start(Path.GetDirectoryName(runPath)!);
        start.ArgumentList.Add(run.ConsoleImage); start.ArgumentList.Add(CurrentAuthArchiveHelperHost.ChildCommand);
        start.ArgumentList.Add("--config"); start.ArgumentList.Add(runPath);
        using var process = new Process { StartInfo = start };
        using var expiry = CancellationTokenSource.CreateLinkedTokenSource(ct); expiry.CancelAfter(run.ExpiresAtUtc - DateTimeOffset.UtcNow);
        using var readers = new CancellationTokenSource();
        bool started = false, settled = false; DateTimeOffset processStart = default;
        Task stdout = Task.CompletedTask, stderr = Task.CompletedTask; Exception? primary = null;
        try
        {
            if (!process.Start()) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            started = true; processStart = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero); process.StandardInput.Close();
            job.AssignWaitingChild(process);
            stdout = CurrentAuthTypedHostProducer.DrainAsync(process.StandardOutput, readers.Token);
            stderr = CurrentAuthTypedHostProducer.DrainAsync(process.StandardError, readers.Token);
            byte[] bindingBytes = files.Read(run.Configuration.ControlBinding.Path, sharedReader: true, maximumBytes: 65536);
            var binding = CurrentAuthArchiveHelperHost.Decode<LocalExecutionBinding>(bindingBytes);
            await files.WriteNewAsync(CurrentAuthArchiveHelperHost.Prefix(runPath) + "-gate.json", JsonSerializer.SerializeToUtf8Bytes(
                new CurrentAuthArchiveHelperGate(run.Nonce, process.Id, processStart, binding.ComputeSha256())), expiry.Token);
            while (!process.HasExited || !job.Empty)
            {
                expiry.Token.ThrowIfCancellationRequested(); files.Require(); bundle.Require();
                var (Capacity, Processes) = job.Observe(admission: false);
                await files.WriteNewAsync(CurrentAuthArchiveHelperHost.Prefix(runPath) + "-processes-" + Guid.NewGuid().ToString("N") + ".json",
                    JsonSerializer.SerializeToUtf8Bytes(new { Capacity, Processes }), expiry.Token);
                if (stdout.IsFaulted) { await stdout; }
                if (stderr.IsFaulted) { await stderr; }
                await Task.Delay(250, expiry.Token);
            }
            await process.WaitForExitAsync(expiry.Token); await Task.WhenAll(stdout, stderr); settled = true;
            if (process.ExitCode != 0 || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(expiry.Token) != run.SourceCommitSha) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            byte[] trx = files.Read(Path.Combine(Path.GetDirectoryName(runPath)!, run.Nonce + ".trx"), sharedReader: true, maximumBytes: 8 * 1024 * 1024);
            CurrentAuthArchiveHelperHost.RequireTrx(trx, CurrentAuthArchiveGenuineCases.Require("helper", request.CaseId).MethodName, request.Inputs.TestImage.Path);
        }
        catch (Exception failure) { primary = failure; }
        Exception? cleanupFailure = null;
        using (var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(90)))
        {
            try
            {
                if (!job.Empty) { await job.CompleteCleanupAsync(); }
                if (started && !process.HasExited)
                {
                    if (new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero) != processStart ||
                        !StringComparer.OrdinalIgnoreCase.Equals(process.MainModule?.FileName, CurrentAuthArchiveHelperHost.Tool("dotnet"))) { throw CurrentAuthArchiveHelperHost.Invalid(); }
                    process.Kill(); await process.WaitForExitAsync(cleanup.Token);
                }
                readers.Cancel(); await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(5), cleanup.Token); settled = true;
                if (!job.Empty) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            }
            catch (OperationCanceledException) when (readers.IsCancellationRequested && stdout.IsCompleted && stderr.IsCompleted) { settled = true; }
            catch (Exception failure) { cleanupFailure = failure; }
            try
            {
                if (!job.Empty || (started && !process.HasExited)) { throw CurrentAuthArchiveHelperHost.Invalid(); }
                await resources.CleanupAndObserveAsync(files, runPath, requireCompletedPair: primary is null, cleanup.Token);
            }
            catch (Exception failure) { cleanupFailure ??= failure; }
            await files.WriteNewAsync(CurrentAuthArchiveHelperHost.Prefix(runPath) + "-host-exit.json", JsonSerializer.SerializeToUtf8Bytes(new
            {
                Kind = "current-auth-archive-helper-host-exit-v1",
                run.OperationId,
                run.SourceCommitSha,
                run.BeganAtUtc,
                run.ExpiresAtUtc,
                ProcessId = started ? process.Id : 0,
                ProcessStartTimeUtc = processStart,
                ExitedAtUtc = started && process.HasExited ? new DateTimeOffset(process.ExitTime.ToUniversalTime(), TimeSpan.Zero) : (DateTimeOffset?)null,
                ExitCode = started && process.HasExited ? process.ExitCode : (int?)null,
                Exited = started && process.HasExited,
                ReadersSettled = settled,
                CleanupFailed = cleanupFailure is not null,
                FailureType = primary?.GetType().Name,
                CleanupFailureType = cleanupFailure?.GetType().Name,
                PhaseProofComplete = false,
            }), cleanup.Token);
        }
        if (cleanupFailure is not null) { throw new AggregateException("The exact archive host cleanup failed.", primary is null ? [cleanupFailure] : [primary, cleanupFailure]); }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
    }
}

internal sealed class CurrentAuthArchiveHelperResources(CurrentAuthArchiveHelperRun run, CurrentAuthArchiveGenuineHostConfiguration request)
{
    private static readonly bool[] PairMembers = [false, true];
    private string[] _beforeIds = [], _beforeVolumes = [];
    private readonly List<int> _ports = [];
    private static string Name(Guid operation, bool comparison)
    {
        return "legacy-delta-proof-" + operation.ToString("N") + (comparison ? "-comparison" : "");
    }

    private string Root(bool comparison)
    {
        return Path.Combine(comparison ? request.SecondFixtureParent : request.FirstFixtureParent,
            "auth-archive-target-" + run.OperationId.ToString("N") + (comparison ? "-comparison" : ""));
    }

    private static Task<string> Docker(IReadOnlyList<string> args, CancellationToken ct)
    {
        return CurrentAppOwnedRepairDockerProcess.RunDockerAsync(args, ct);
    }

    private static string[] Lines(string text)
    {
        return text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    internal async Task ObserveBeforeAsync(CurrentAppOwnedRepairCustody files, string runPath, CancellationToken ct)
    {
        _beforeIds = Lines(await Docker(["ps", "--all", "--no-trunc", "--format", "{{.ID}}|{{.Names}}"], ct));
        _beforeVolumes = Lines(await Docker(["volume", "ls", "--format", "{{.Name}}"], ct));
        foreach (bool comparison in PairMembers)
        {
            string name = Name(run.OperationId, comparison);
            if (Directory.Exists(Root(comparison)) || _beforeVolumes.Contains(name, StringComparer.Ordinal) ||
                _beforeIds.Any(x => x.Split('|')[^1] == name)) { throw CurrentAuthArchiveHelperHost.Invalid(); }
        }
        await files.WriteNewAsync(CurrentAuthArchiveHelperHost.Prefix(runPath) + "-before-absence.json",
            JsonSerializer.SerializeToUtf8Bytes(new { run.OperationId, ObservedAtUtc = DateTimeOffset.UtcNow, Containers = _beforeIds, Volumes = _beforeVolumes }), ct);
    }

    internal async Task CleanupAndObserveAsync(CurrentAppOwnedRepairCustody files, string runPath, bool requireCompletedPair, CancellationToken ct)
    {
        var failures = new List<Exception>();
        foreach (bool comparison in PairMembers)
        {
            try { await CleanupOneAsync(comparison, requireCompletedPair, ct); } catch (Exception failure) { failures.Add(failure); }
        }
        string[] containers = Lines(await Docker(["ps", "--all", "--no-trunc", "--format", "{{.ID}}|{{.Names}}"], ct));
        string[] volumes = Lines(await Docker(["volume", "ls", "--format", "{{.Name}}"], ct));
        int[] listeners = [.. IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(x => x.Port).Distinct()];
        if (PairMembers.Any(second => containers.Any(x => x.Split('|')[^1] == Name(run.OperationId, second)) ||
            volumes.Contains(Name(run.OperationId, second), StringComparer.Ordinal)) || _ports.Any(listeners.Contains))
        { failures.Add(CurrentAuthArchiveHelperHost.Invalid()); }
        await files.WriteNewAsync(CurrentAuthArchiveHelperHost.Prefix(runPath) + "-resource-cleanup.json", JsonSerializer.SerializeToUtf8Bytes(new
        {
            run.OperationId,
            ObservedAtUtc = DateTimeOffset.UtcNow,
            run.ExpiresAtUtc,
            Containers = containers,
            Volumes = volumes,
            OwnedPorts = _ports,
            Listeners = listeners,
            CleanupFailed = failures.Count != 0,
            PreservedUncertainResources = failures.Count != 0,
            PhaseProofComplete = false,
        }), ct);
        if (failures.Count != 0) { throw new AggregateException("Uncertain archive resources were preserved.", failures); }
    }

    private async Task CleanupOneAsync(bool comparison, bool requireCompletedPair, CancellationToken ct)
    {
        string name = Name(run.OperationId, comparison), root = Root(comparison);
        string[] existingContainers = Lines(await Docker(["ps", "--all", "--no-trunc", "--filter", "name=^/" + name + "$", "--format", "{{.ID}}"], ct));
        bool volumeExists = Lines(await Docker(["volume", "ls", "--format", "{{.Name}}"], ct)).Contains(name, StringComparer.Ordinal);
        if (existingContainers.Length == 0 && !volumeExists)
        {
            if (requireCompletedPair) { RequireCompletedCleanup(root, name); }
            RequireNoUncertainCredentials(root);
            return;
        }
        if (existingContainers.Length > 1 || !Directory.Exists(root)) { throw CurrentAuthArchiveHelperHost.Invalid(); }
        var binding = CurrentAuthArchiveHelperHost.Decode<LocalExecutionBinding>(CurrentAuthArchiveHelperHost.Read(Path.Combine(root, "fixture-binding.json"), 65536));
        using var authority = WindowsLocalRunAuthority.AcquireResume(root, binding);
        using var custody = new CurrentAppOwnedRepairCustody(authority);
        string[] attempts = Directory.GetFiles(root, "*-attempt.json");
        if (attempts.Length != 1) { throw CurrentAuthArchiveHelperHost.Invalid(); }
        using var attempt = JsonDocument.Parse(custody.Read(attempts[0], maximumBytes: 65536));
        if (attempt.RootElement.GetProperty("operation").GetGuid() != run.OperationId || attempt.RootElement.GetProperty("name").GetString() != name ||
            attempt.RootElement.GetProperty("persistent").GetBoolean() || attempt.RootElement.GetProperty("acceptedCommit").GetString() != run.SourceCommitSha)
        { throw CurrentAuthArchiveHelperHost.Invalid(); }
        string? volumeCreated = null;
        if (volumeExists)
        {
            string[] frames = Directory.GetFiles(root, "*-volume.json");
            if (frames.Length == 0) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            using var recorded = JsonDocument.Parse(custody.Read(frames.Order(StringComparer.Ordinal).First(), maximumBytes: 65536));
            volumeCreated = recorded.RootElement.GetProperty("CreatedAt").GetString();
            using var actual = JsonDocument.Parse(await Docker(["volume", "inspect", name], ct)); JsonElement volume = actual.RootElement[0];
            RequireLabels(volume.GetProperty("Labels"), binding);
            if (volume.GetProperty("Name").GetString() != name || volume.GetProperty("Driver").GetString() != "local" ||
                volume.GetProperty("Scope").GetString() != "local" || volume.GetProperty("CreatedAt").GetString() != recorded.RootElement.GetProperty("CreatedAt").GetString() ||
                (volume.GetProperty("Options").ValueKind != JsonValueKind.Null && volume.GetProperty("Options").EnumerateObject().Any())) { throw CurrentAuthArchiveHelperHost.Invalid(); }
        }
        if (existingContainers.Length == 1)
        {
            string id = existingContainers[0];
            if (_beforeIds.Any(x => x.StartsWith(id + "|", StringComparison.Ordinal))) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            string[] frames = Directory.GetFiles(root, "*-target.json");
            if (frames.Length == 0) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            using var recorded = JsonDocument.Parse(custody.Read(frames.Order(StringComparer.Ordinal).Last(), maximumBytes: 2 * 1024 * 1024));
            using var actual = JsonDocument.Parse(await Docker(["inspect", "--type", "container", id], ct)); JsonElement container = actual.RootElement[0];
            JsonElement config = container.GetProperty("Config"), host = container.GetProperty("HostConfig"); RequireLabels(config.GetProperty("Labels"), binding);
            JsonElement[] mounts = [.. container.GetProperty("Mounts").EnumerateArray()];
            DateTimeOffset created = container.GetProperty("Created").GetDateTimeOffset();
            if (container.GetProperty("Id").GetString() != id || recorded.RootElement.GetProperty("Id").GetString() != id ||
                container.GetProperty("Name").GetString() != "/" + name || container.GetProperty("Image").GetString() != recorded.RootElement.GetProperty("Image").GetString() ||
                config.GetProperty("Image").GetString() != CurrentAuthArchiveHelperHost.Image || created < run.BeganAtUtc || created > run.ExpiresAtUtc ||
                container.GetProperty("Created").GetString() != recorded.RootElement.GetProperty("Created").GetString() ||
                host.GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 || host.GetProperty("MemorySwap").GetInt64() != 512L * 1024 * 1024 ||
                host.GetProperty("NanoCpus").GetInt64() != 750_000_000 || mounts.Length != 1 || mounts[0].GetProperty("Type").GetString() != "volume" ||
                mounts[0].GetProperty("Name").GetString() != name || mounts[0].GetProperty("Destination").GetString() != "/var/lib/postgresql" || !mounts[0].GetProperty("RW").GetBoolean())
            { throw CurrentAuthArchiveHelperHost.Invalid(); }
            var ports = container.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp").EnumerateArray().ToArray();
            if (ports.Length != 1 || ports[0].GetProperty("HostIp").GetString() != "127.0.0.1" || !int.TryParse(ports[0].GetProperty("HostPort").GetString(), out int port))
            { throw CurrentAuthArchiveHelperHost.Invalid(); }
            _ports.Add(port);
            if (IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections().Any(x => x.State == TcpState.Established && (x.LocalEndPoint.Port == port || x.RemoteEndPoint.Port == port)))
            { throw CurrentAuthArchiveHelperHost.Invalid(); }
            string[] consumers = Lines(await Docker(["ps", "--all", "--no-trunc", "--filter", "volume=" + name, "--format", "{{.ID}}"], ct));
            if (!consumers.SequenceEqual([id], StringComparer.Ordinal)) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            authority.ValidateHeld(); _ = await Docker(["stop", "--time", "5", id], ct); _ = await Docker(["rm", id], ct);
        }
        if (volumeExists)
        {
            if (Lines(await Docker(["ps", "--all", "--no-trunc", "--filter", "volume=" + name, "--format", "{{.ID}}"], ct)).Length != 0) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            using var recheck = JsonDocument.Parse(await Docker(["volume", "inspect", name], ct));
            JsonElement actualVolume = recheck.RootElement[0]; RequireLabels(actualVolume.GetProperty("Labels"), binding);
            if (actualVolume.GetProperty("Name").GetString() != name || actualVolume.GetProperty("CreatedAt").GetString() != volumeCreated ||
                actualVolume.GetProperty("Driver").GetString() != "local" || actualVolume.GetProperty("Scope").GetString() != "local" ||
                (actualVolume.GetProperty("Options").ValueKind != JsonValueKind.Null && actualVolume.GetProperty("Options").EnumerateObject().Any()))
            { throw CurrentAuthArchiveHelperHost.Invalid(); }
            authority.ValidateHeld(); _ = await Docker(["volume", "rm", name], ct);
        }
        // A killed owner may leave credentials whose original file identity is unavailable here.
        // Preserve those files and fail cleanup rather than deleting by name or claiming absence.
        RequireNoUncertainCredentials(root);
    }

    private static void RequireNoUncertainCredentials(string root)
    {
        if (File.Exists(Path.Combine(root, "archive-policy-operator.txt")) || File.Exists(Path.Combine(root, "archive-policy-ordinary.txt")))
        { throw CurrentAuthArchiveHelperHost.Invalid(); }
    }

    private void RequireCompletedCleanup(string root, string name)
    {
        var binding = CurrentAuthArchiveHelperHost.Decode<LocalExecutionBinding>(CurrentAuthArchiveHelperHost.Read(Path.Combine(root, "fixture-binding.json"), 65536));
        using var authority = WindowsLocalRunAuthority.AcquireResume(root, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        using var disposed = JsonDocument.Parse(files.Read(Directory.GetFiles(root, "*-disposed.json").Single(), maximumBytes: 65536));
        using var absent = JsonDocument.Parse(files.Read(Directory.GetFiles(root, "*-absent.json").Single(), maximumBytes: 65536));
        if (disposed.RootElement.GetProperty("Operation").GetGuid() != run.OperationId || disposed.RootElement.GetProperty("volume").GetString() != name ||
            disposed.RootElement.GetProperty("cleanupFailed").GetBoolean() || !disposed.RootElement.GetProperty("verifiedAbsence").GetBoolean() ||
            !disposed.RootElement.GetProperty("removed").GetBoolean() || !disposed.RootElement.GetProperty("sdkDisposed").GetBoolean() ||
            absent.RootElement.GetProperty("Operation").GetGuid() != run.OperationId || absent.RootElement.GetProperty("volume").GetString() != name ||
            File.Exists(Path.Combine(root, "archive-policy-operator.txt")) || File.Exists(Path.Combine(root, "archive-policy-ordinary.txt")))
        { throw CurrentAuthArchiveHelperHost.Invalid(); }
        _ports.Add(absent.RootElement.GetProperty("observedPort").GetInt32());
    }

    private void RequireLabels(JsonElement labels, LocalExecutionBinding binding)
    {
        RequireResourceLabels(labels, run.OperationId, binding.ComputeSha256());
    }

    internal static void RequireResourceLabels(JsonElement labels, Guid operation, string bindingSha256)
    {
        if (labels.EnumerateObject().Count() != 3 || labels.GetProperty("codex.repair.purpose").GetString() != "current-auth-local-session-archive-proof" ||
            labels.GetProperty("codex.repair.operation").GetString() != operation.ToString("D") ||
            labels.GetProperty("codex.repair.run-binding").GetString() != bindingSha256) { throw CurrentAuthArchiveHelperHost.Invalid(); }
    }
}
