using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CustomerNamedClosedHostConfiguration(string Root, string TestAssemblyPath, string TestAssemblySha256,
    string ConsoleAssemblySha256, string CoreAssemblySha256, string PrerequisitesPath, string PrerequisitesSha256, string Group);
internal sealed record CustomerNamedClosedWaitingChildConfiguration(CustomerNamedClosedHostConfiguration Configuration, string Nonce,
    string GatePath, string SettingsPath, DateTimeOffset ExpiresAtUtc);
internal sealed record CustomerNamedClosedHostGate(string Nonce, int ProcessId, DateTimeOffset ProcessStartTimeUtc);
internal sealed record CustomerNamedClosedHostExit(string Kind, int ProcessId, DateTimeOffset ProcessStartTimeUtc, string Executable, string ExecutableSha256, string TestAssemblySha256, DateTimeOffset ExitedAtUtc, int ExitCode, IReadOnlyList<Guid> RunIds, bool ProcessExitObserved, string JobNonce, DateTimeOffset MembershipObservedAtUtc, bool NativeMembershipObserved, bool EmptyJobObservedAfterExit);
internal sealed record CustomerNamedClosedHostResult(CustomerDefinitionArtifact HostExit, CustomerDefinitionArtifact Trx,
    CustomerDefinitionArtifact Stdout, CustomerDefinitionArtifact Stderr, DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc);

// Host composition only. Caller supplies the genuine held artifact custody, never execution permission.
// The two-argument child entry must be routed explicitly; it has no persistent database command.
internal static class CustomerNamedClosedHostLauncher
{
    private static readonly string Dotnet = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");
    internal static string Filter(string group)
    {
        return group == "closed-console"
    ? "FullyQualifiedName=Legacy.Maliev.DataMigration.Tests.CurrentCustomerClosedConsoleExecutionTests.Genuine_named_closed_customer_console"
    : throw Invalid();
    }

    internal static TimeSpan Lease(string group)
    {
        return group == "closed-console" ? TimeSpan.FromMinutes(80) : throw Invalid();
    }

    internal static string ChildCommand => "customer-sequence-named-closed-host-child";
    internal static async Task<CustomerNamedClosedHostResult> RunAsync(CurrentAppOwnedRepairCustody files, CustomerNamedClosedHostConfiguration configuration,
            CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: true);
        RequireConfiguration(configuration);
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(configuration.Root));
        SecureLocalFile.EnsureOwnerOnlyDirectory(root);
        RequirePrerequisites(); RequireDefinitionPrecursor();
        using var bundle = HoldBundle(configuration);
        using var installedDotnet = HoldInstalledImage(Dotnet);
        string nonce = Guid.NewGuid().ToString("N"); DateTimeOffset began = DateTimeOffset.UtcNow, expiry = began + Lease(configuration.Group);
        string prefix = Path.Combine(root, "customer-host-" + nonce), configPath = prefix + "-child.json", gatePath = prefix + "-gate.json", settingsPath = prefix + ".runsettings";
        string stdoutPath = prefix + "-stdout.txt", stderrPath = prefix + "-stderr.txt", hostExitPath = prefix + "-exit.json";
        var dockerBaseline = await CustomerNamedClosedHostDockerCleanup.ObserveBeforeAsync(ct).ConfigureAwait(false);
        await files.WriteNewAsync(prefix + "-docker-before.json", JsonSerializer.SerializeToUtf8Bytes(dockerBaseline), ct).ConfigureAwait(false);
        await files.WriteNewAsync(settingsPath, "<RunSettings><RunConfiguration><MaxCpuCount>1</MaxCpuCount></RunConfiguration></RunSettings>"u8.ToArray(), ct).ConfigureAwait(false);
        var childConfiguration = new CustomerNamedClosedWaitingChildConfiguration(configuration, nonce, gatePath, settingsPath, expiry);
        await files.WriteNewAsync(configPath, JsonSerializer.SerializeToUtf8Bytes(childConfiguration), ct).ConfigureAwait(false);
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct); lifetime.CancelAfter(Lease(configuration.Group));
        using var job = new CurrentCustomerSequenceBootstrapHostJob([Dotnet], nonce);
        _ = job.Observe(admission: true);
        var start = FixedStart(root);
        start.ArgumentList.Add(typeof(MigrationConsole).Assembly.Location); start.ArgumentList.Add(ChildCommand); start.ArgumentList.Add(configPath);
        start.RedirectStandardOutput = true; start.RedirectStandardError = true;
        using var child = new Process { StartInfo = start };
        bool launched = false; DateTimeOffset childStart = default; Task? stdout = null, stderr = null; ExceptionDispatchInfo? primaryFailure = null;
        CustomerNamedClosedHostResult? successfulResult = null; CustomerNamedClosedHostObservation? observer = null;
        var cleanupFailures = new List<Exception>(); bool? allMemberExitObserved = null, waitingChildExited = null;
        var runs = new HashSet<Guid>(); int testhostPid = 0; int frame = 0;
        try
        {
            await files.WriteNewAsync(prefix + "-attempt.json", JsonSerializer.SerializeToUtf8Bytes(new
            {
                nonce,
                began,
                expiry,
                group = configuration.Group,
                persistent = false,
                executable = Dotnet,
                consoleAssemblySha256 = configuration.ConsoleAssemblySha256,
                testAssemblySha256 = configuration.TestAssemblySha256
            }), lifetime.Token).ConfigureAwait(false);
            if (!child.Start()) { throw Invalid(); }
            launched = true; childStart = new(child.StartTime.ToUniversalTime(), TimeSpan.Zero);
            stdout = DrainAsync(child.StandardOutput, stdoutPath, lifetime.Token); stderr = DrainAsync(child.StandardError, stderrPath, lifetime.Token);
            job.AssignWaitingChild(child);
            await files.WriteNewAsync(gatePath, JsonSerializer.SerializeToUtf8Bytes(new CustomerNamedClosedHostGate(nonce, child.Id,
                new(child.StartTime.ToUniversalTime(), TimeSpan.Zero))), lifetime.Token).ConfigureAwait(false);
            while (!child.HasExited)
            {
                lifetime.Token.ThrowIfCancellationRequested(); bundle.Require();
                if (stdout.IsFaulted) { await stdout.ConfigureAwait(false); }
                if (stderr.IsFaulted) { await stderr.ConfigureAwait(false); }
                var (Capacity, Processes) = job.Observe(admission: false);
                await files.WriteNewAsync(prefix + "-members-" + frame++.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".json",
                    JsonSerializer.SerializeToUtf8Bytes(new { nonce, Capacity, Processes }), lifetime.Token).ConfigureAwait(false);
                ObserveEntries(); await Task.Delay(200, lifetime.Token).ConfigureAwait(false);
            }
            ObserveEntries(); await child.WaitForExitAsync(lifetime.Token).ConfigureAwait(false);
            await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(10), lifetime.Token).ConfigureAwait(false);
            var final = job.Observe(admission: false); RequirePrerequisites();
            if (child.ExitCode != 0 || !job.Empty || final.Processes.Any(x => !x.Exited) || observer is null ||
                runs.Count != 8) { throw Invalid(); }
            var actualExit = await observer.RetainActualSuccessfulExitAsync(files, hostExitPath, runs.Order().ToArray(), lifetime.Token).ConfigureAwait(false);
            string trxPath = Path.Combine(root, "customer-closed-eight.trx");
            successfulResult = new(actualExit, Artifact(trxPath), Artifact(stdoutPath), Artifact(stderrPath), began, DateTimeOffset.UtcNow);
        }
        catch (Exception error) { primaryFailure = ExceptionDispatchInfo.Capture(error); }
        finally
        {
            try { lifetime.Cancel(); } catch (Exception error) { cleanupFailures.Add(error); }
            if (launched)
            {
                try { await job.CompleteCleanupAsync().WaitAsync(TimeSpan.FromSeconds(20), CancellationToken.None).ConfigureAwait(false); }
                catch (Exception error) { cleanupFailures.Add(error); }
                try
                {
                    if (!child.HasExited)
                    {
                        bool owned = new DateTimeOffset(child.StartTime.ToUniversalTime(), TimeSpan.Zero) == childStart &&
                            StringComparer.OrdinalIgnoreCase.Equals(child.MainModule?.FileName, Dotnet) && SecureLocalFile.HandleResolvesToApprovedPath(installedDotnet, Dotnet);
                        if (!owned) { cleanupFailures.Add(Invalid()); }
                        else
                        {
                            try { await child.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(1), CancellationToken.None).ConfigureAwait(false); }
                            catch (TimeoutException)
                            {
                                if (!child.HasExited)
                                {
                                    bool stillOwned = new DateTimeOffset(child.StartTime.ToUniversalTime(), TimeSpan.Zero) == childStart &&
                                        StringComparer.OrdinalIgnoreCase.Equals(child.MainModule?.FileName, Dotnet) && SecureLocalFile.HandleResolvesToApprovedPath(installedDotnet, Dotnet);
                                    if (stillOwned) { child.Kill(); } else { cleanupFailures.Add(Invalid()); }
                                }
                            }
                            await child.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false);
                        }
                    }
                }
                catch (Exception error) { cleanupFailures.Add(error); }
            }
            try { if (stdout is not null && stderr is not null) { await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false); } }
            catch (Exception error) { if (primaryFailure is null || stdout is not { IsCompleted: true } || stderr is not { IsCompleted: true }) { cleanupFailures.Add(error); } }
            try { observer?.Dispose(); } catch (Exception error) { cleanupFailures.Add(error); }
            try { allMemberExitObserved = job.Empty; } catch (Exception error) { cleanupFailures.Add(error); }
            try { waitingChildExited = !launched || child.HasExited; } catch (Exception error) { cleanupFailures.Add(error); }
            if (launched)
            {
                if (allMemberExitObserved == true && waitingChildExited == true)
                {
                    try { await CustomerNamedClosedHostDockerCleanup.RequireCleanupAfterExitAsync(files, root, nonce, dockerBaseline).ConfigureAwait(false); }
                    catch (Exception error) { cleanupFailures.Add(error); }
                }
                else { cleanupFailures.Add(Invalid()); }
            }
            try
            {
                await files.WriteNewAsync(prefix + "-cleanup.json", JsonSerializer.SerializeToUtf8Bytes(new
                {
                    nonce,
                    completedAtUtc = DateTimeOffset.UtcNow,
                    launched,
                    allMemberExitObserved,
                    waitingChildExited,
                    streamsSettled = (stdout is null && stderr is null) || (stdout is { IsCompleted: true } && stderr is { IsCompleted: true }),
                    cleanupFailure = cleanupFailures.Count != 0,
                    cleanupFailureCodes = cleanupFailures.Select(x => (x as MigrationExecutionException)?.Code ?? x.GetType().Name).ToArray(),
                    failureCode = (primaryFailure?.SourceException as MigrationExecutionException)?.Code
                }), CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception error) { cleanupFailures.Add(error); }
        }
        if (primaryFailure is not null)
        {
            if (cleanupFailures.Count != 0) { primaryFailure.SourceException.Data["CustomerGuardedHostCleanupFailures"] = new AggregateException(cleanupFailures); }
            primaryFailure.Throw();
        }
        return cleanupFailures.Count != 0
            ? throw new MigrationExecutionException("customer_guarded_host_cleanup_failed", "Exact owned process cleanup, settled streams or cleanup evidence retention failed.")
            : successfulResult is not null ? successfulResult with { CompletedAtUtc = DateTimeOffset.UtcNow } : throw Invalid();
        void ObserveEntries()
        {
            foreach (string path in Directory.EnumerateFiles(root, "*-host-entry.json", SearchOption.TopDirectoryOnly))
            {
                byte[] bytes; try { using var stream = SecureLocalFile.OpenReadShared(path); if (stream.Length is < 1 or > 65536) { throw Invalid(); } bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes); }
                catch (IOException) { continue; }
                using var json = JsonDocument.Parse(bytes); JsonElement entry = json.RootElement;
                if (entry.GetProperty("jobNonce").GetString() != nonce) { continue; }
                if (!entry.GetProperty("nativeJobMembershipObserved").GetBoolean() || entry.GetProperty("testAssemblySha256").GetString() != configuration.TestAssemblySha256) { throw Invalid(); }
                int pid = entry.GetProperty("processId").GetInt32();
                if (observer is null) { observer = new(pid, nonce, configuration.TestAssemblyPath); testhostPid = pid; }
                else if (pid != testhostPid) { throw Invalid(); }
                _ = runs.Add(entry.GetProperty("run").GetGuid());
            }
        }
        CustomerDefinitionArtifact Artifact(string path)
        { byte[] bytes = files.Read(path, sharedReader: true, maximumBytes: 8_000_000); return new(path, Convert.ToHexStringLower(SHA256.HashData(bytes))); }
        void RequirePrerequisites()
        { using var prerequisites = SecureLocalFile.OpenReadShared(configuration.PrerequisitesPath); if (Digest(prerequisites, 8_000_000) != configuration.PrerequisitesSha256) { throw Invalid(); } }
        void RequireDefinitionPrecursor()
        {
            var input = CustomerClosedCompletedReadback.Decode<CustomerClosedLaneInput>(files.Read(configuration.PrerequisitesPath, sharedReader: true, maximumBytes: 65536));
            if (input.TestAssemblyPath != configuration.TestAssemblyPath || input.TestAssemblySha256 != configuration.TestAssemblySha256 ||
                input.ConsoleAssemblySha256 != configuration.ConsoleAssemblySha256 || input.CoreAssemblySha256 != configuration.CoreAssemblySha256)
            { throw Invalid(); }
            _ = CustomerClosedCompletedReadback.Require(input, DateTimeOffset.UtcNow);
            var inputBinding = CustomerClosedCompletedReadback.ReadProtected<LocalExecutionBinding>(input.InputBindingPath, 65536);
            if (inputBinding.ComputeSha256() != input.InputBindingSha256 || StringComparer.OrdinalIgnoreCase.Equals(inputBinding.ArtifactRootCanonicalPath, root)) { throw Invalid(); }
            using var inputAuthority = WindowsLocalRunAuthority.AcquireResume(inputBinding.ArtifactRootCanonicalPath, inputBinding);
            using var inputFiles = new CurrentAppOwnedRepairCustody(inputAuthority);
            CustomerClosedCompletedReadback.RequireExactBinding(inputFiles, input.InputBindingPath, inputBinding);
            var source = CustomerClosedCompletedReadback.Decode<FreshSchemaPlan>(inputFiles.Read(input.SourceSchemaPath, sharedReader: true, maximumBytes: 32 * 1024 * 1024));
            if (SchemaPlanCanonicalizer.ComputeSha256(source) != input.SourceSchemaSha256) { throw Invalid(); }
            inputFiles.Require();
        }
    }
    internal static async Task<int> RunWaitingChildAsync(string configurationPath, CancellationToken ct)
    {
        using var configurationStream = SecureLocalFile.OpenRead(configurationPath);
        if (configurationStream.Length is < 1 or > 65536) { throw Invalid(); }
        byte[] bytes = new byte[(int)configurationStream.Length]; configurationStream.ReadExactly(bytes);
        var child = MigrationConsole.DecodeCustomerSequence<CustomerNamedClosedWaitingChildConfiguration>(bytes);
        RequireConfiguration(child.Configuration);
        if (!Guid.TryParseExact(child.Nonce, "N", out _) || child.ExpiresAtUtc <= DateTimeOffset.UtcNow || child.ExpiresAtUtc - DateTimeOffset.UtcNow > Lease(child.Configuration.Group)) { throw Invalid(); }
        string expectedPrefix = Path.Combine(Path.TrimEndingDirectorySeparator(Path.GetFullPath(child.Configuration.Root)), "customer-host-" + child.Nonce);
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(configurationPath), expectedPrefix + "-child.json") ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(child.GatePath), expectedPrefix + "-gate.json") ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(child.SettingsPath), expectedPrefix + ".runsettings")) { throw Invalid(); }
        using var self = Process.GetCurrentProcess();
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct); wait.CancelAfter(TimeSpan.FromSeconds(30));
        CustomerNamedClosedHostGate gate;
        while (true)
        {
            wait.Token.ThrowIfCancellationRequested();
            try
            {
                using var gateStream = SecureLocalFile.OpenRead(child.GatePath);
                if (gateStream.Length is < 1 or > 65536) { throw Invalid(); }
                gate = JsonSerializer.Deserialize<CustomerNamedClosedHostGate>(gateStream) ?? throw Invalid(); break;
            }
            catch (IOException) { await Task.Delay(50, wait.Token).ConfigureAwait(false); }
        }
        if (gate.Nonce != child.Nonce || gate.ProcessId != self.Id || gate.ProcessStartTimeUtc != new DateTimeOffset(self.StartTime.ToUniversalTime(), TimeSpan.Zero)) { throw Invalid(); }
        CustomerNamedClosedHostObservation.RequireCurrentMembership(child.Nonce);
        using var bundle = HoldBundle(child.Configuration);
        using var settings = SecureLocalFile.OpenReadShared(child.SettingsPath);
        if (Digest(settings, 65536) != Convert.ToHexStringLower(SHA256.HashData("<RunSettings><RunConfiguration><MaxCpuCount>1</MaxCpuCount></RunConfiguration></RunSettings>"u8))) { throw Invalid(); }
        var start = FixedStart(child.Configuration.Root);
        start.Environment["MALIEV_CUSTOMER_GUARDED_JOB_NONCE"] = child.Nonce;
        start.Environment["MALIEV_CUSTOMER_CLOSED_PARENT_ROOT"] = child.Configuration.Root;
        start.Environment["MALIEV_CUSTOMER_CLOSED_LANE_INPUT"] = child.Configuration.PrerequisitesPath;
        start.ArgumentList.Add("vstest"); start.ArgumentList.Add(child.Configuration.TestAssemblyPath);
        start.ArgumentList.Add("--TestCaseFilter:" + Filter(child.Configuration.Group));
        start.ArgumentList.Add("--Settings:" + child.SettingsPath); start.ArgumentList.Add("--ResultsDirectory:" + child.Configuration.Root);
        start.ArgumentList.Add("--Logger:trx;LogFileName=" + "customer-closed-eight.trx");
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct); lifetime.CancelAfter(child.ExpiresAtUtc - DateTimeOffset.UtcNow);
        using var process = new Process { StartInfo = start }; if (!process.Start()) { throw Invalid(); }
        // The outer named-job owner is responsible for exact-handle failure cleanup. No child tree kill.
        await process.WaitForExitAsync(lifetime.Token).ConfigureAwait(false); bundle.Require(); return process.ExitCode;
    }
    private static ProcessStartInfo FixedStart(string root)
    {
        var start = new ProcessStartInfo(Dotnet) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = root }; start.Environment.Clear();
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows); start.Environment["SystemRoot"] = windows; start.Environment["WINDIR"] = windows;
        start.Environment["PATH"] = Path.GetDirectoryName(Dotnet) + ";" + Environment.SystemDirectory; start.Environment["TEMP"] = root; start.Environment["TMP"] = root;
        start.Environment["DOTNET_CLI_HOME"] = root; start.Environment["DOTNET_NOLOGO"] = "1"; start.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        start.Environment["DOTNET_GCHeapHardLimit"] = "0x20000000"; start.Environment["MSBUILDDISABLENODEREUSE"] = "1"; start.Environment["TESTCONTAINERS_RYUK_DISABLED"] = "true";
        return start;
    }
    private static async Task DrainAsync(StreamReader reader, string path, CancellationToken ct)
    {
        await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough);
        if (!SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path)) || !SecureLocalFile.HandleResolvesToApprovedPath(output, path)) { throw Invalid(); }
        using var writer = new StreamWriter(output, new UTF8Encoding(false), 4096, leaveOpen: true); char[] buffer = new char[4096]; int total = 0;
        while (true) { int count = await reader.ReadAsync(buffer, ct).ConfigureAwait(false); if (count == 0) { break; } total = checked(total + Encoding.UTF8.GetByteCount(buffer, 0, count)); if (total > 8_000_000) { throw Invalid(); } await writer.WriteAsync(buffer.AsMemory(0, count), ct).ConfigureAwait(false); }
        await writer.FlushAsync(ct).ConfigureAwait(false); await output.FlushAsync(ct).ConfigureAwait(false); output.Flush(true);
    }
    internal static void RequireConfiguration(CustomerNamedClosedHostConfiguration configuration)
    {
        _ = Filter(configuration.Group);
        if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(configuration.Root) || !Path.IsPathFullyQualified(configuration.TestAssemblyPath) ||
            !Path.IsPathFullyQualified(configuration.PrerequisitesPath) || Path.GetFileName(configuration.TestAssemblyPath) != "Legacy.Maliev.DataMigration.Tests.dll" ||
            !CurrentCustomerSequenceRepairPermit.HashShape(configuration.TestAssemblySha256) || !CurrentCustomerSequenceRepairPermit.HashShape(configuration.ConsoleAssemblySha256) ||
            !CurrentCustomerSequenceRepairPermit.HashShape(configuration.CoreAssemblySha256) || !CurrentCustomerSequenceRepairPermit.HashShape(configuration.PrerequisitesSha256)) { throw Invalid(); }
    }
    private sealed class HeldBundle(List<(FileStream Stream, string Path)> values) : IDisposable
    {
        internal void Require() { foreach (var value in values) { if (!SecureLocalFile.HandleResolvesToApprovedPath(value.Stream, value.Path)) { throw Invalid(); } } }
        public void Dispose() { foreach (var value in values) { value.Stream.Dispose(); } }
    }
    private static HeldBundle HoldBundle(CustomerNamedClosedHostConfiguration configuration)
    {
        var held = new List<(FileStream Stream, string Path)>();
        try
        {
            string directory = Path.GetDirectoryName(configuration.TestAssemblyPath) ?? throw Invalid();
            string[] paths = Directory.GetFiles(directory, "*", SearchOption.AllDirectories);
            if (paths.Length is < 1 or > 4000) { throw Invalid(); }
            foreach (string path in paths)
            {
                if (Path.GetFileName(path) == WindowsLocalRunAuthority.RunLockRelativeName) { continue; }
                var stream = SecureLocalFile.OpenReadShared(path); held.Add((stream, path)); _ = Digest(stream, 128 * 1024 * 1024);
            }
            foreach ((string path, string expected) in new[] {(configuration.TestAssemblyPath,configuration.TestAssemblySha256),
                (typeof(MigrationConsole).Assembly.Location,configuration.ConsoleAssemblySha256),(typeof(CurrentCustomerSequenceRepairPermit).Assembly.Location,configuration.CoreAssemblySha256),
                (Path.Combine(directory,"Legacy.Maliev.DataMigration.Console.dll"),configuration.ConsoleAssemblySha256),
                (Path.Combine(directory,"Legacy.Maliev.DataMigration.dll"),configuration.CoreAssemblySha256)})
            { var stream = SecureLocalFile.OpenReadShared(path); held.Add((stream, path)); if (Digest(stream, 128 * 1024 * 1024) != expected) { throw Invalid(); } }
            var result = new HeldBundle(held); result.Require(); return result;
        }
        catch { foreach (var item in held) { item.Stream.Dispose(); } throw; }
    }
    private static string Digest(FileStream stream, int maximum)
    { if (stream.Length is < 1 || stream.Length > maximum) { throw Invalid(); } stream.Position = 0; return Convert.ToHexStringLower(SHA256.HashData(stream)); }
    private static FileStream HoldInstalledImage(string path)
    {
        FileSystemInfo? ancestor = new FileInfo(path);
        while (ancestor is not null)
        { if ((ancestor.Attributes & FileAttributes.ReparsePoint) != 0) { throw Invalid(); } ancestor = ancestor is FileInfo file ? file.Directory : (ancestor as DirectoryInfo)?.Parent; }
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        try { if (!SecureLocalFile.HandleResolvesToApprovedPath(stream, path)) { throw Invalid(); } _ = Digest(stream, 128 * 1024 * 1024); return stream; }
        catch { stream.Dispose(); throw; }
    }
    private static MigrationExecutionException Invalid()
    {
        return new("customer_guarded_host_invalid", "Fixed actual Customer component host configuration and evidence required.");
    }
}
