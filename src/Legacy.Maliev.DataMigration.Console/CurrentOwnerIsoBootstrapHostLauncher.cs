using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record OwnerIsoGuardedHostConfiguration(string Root, string TestAssemblyPath, string TestAssemblySha256,
    string ConsoleAssemblySha256, string CoreAssemblySha256, string InputsPath, string InputsSha256, string CaseRoot, string Group);
internal sealed record OwnerIsoGuardedWaitingChildConfiguration(OwnerIsoGuardedHostConfiguration Configuration, string Nonce,
    string GatePath, string SettingsPath, DateTimeOffset ExpiresAtUtc);
internal sealed record OwnerIsoGuardedHostGate(string Nonce, int ProcessId, DateTimeOffset ProcessStartTimeUtc);
internal sealed record OwnerIsoGuardedHostResult(IsoDefinitionArtifact HostExit, IsoDefinitionArtifact Trx,
    IsoDefinitionArtifact Stdout, IsoDefinitionArtifact Stderr, DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc);

// Host composition only. Caller supplies the genuine held artifact custody, never execution permission.
// The two-argument child entry must be routed explicitly; it has no persistent database command.
internal static class OwnerIsoGuardedBootstrapHostLauncher
{
    private static readonly string Dotnet = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");
    internal static string Filter(string group)
    {
        string[] names = group switch
        {
            "native-component" => ["Complete_26_database_fleet_is_preserved_after_Country_and_Material_commit", "Prepared_receipt_publication_failure_rolls_back_without_commit", "Dropped_commit_ack_stops_without_Material_apply", "Terminal_publication_uncertainty_stops_without_Material_apply", "Wrong_owner_rejected_before_DDL", "Full_fleet_drift_after_Country_stops_Material"],
            "maintenance-component" => ["Unsafe_unprobed_host_rule_rejected", "Local_trust_rejected", "Ordinary_client_rejected_in_all_26_databases", "Exact_installed_policy_accepts_only_maintenance_client"],
            _ => throw Invalid()
        };
        return string.Join('|', names.Select(x => "FullyQualifiedName=Legacy.Maliev.DataMigration.Tests.CurrentOwnerIsoGuardedNativeExecutionTests." + x));
    }
    internal static TimeSpan Lease(string group)
    {
        return group switch
        { "native-component" => TimeSpan.FromMinutes(55), "maintenance-component" => TimeSpan.FromMinutes(38), _ => throw Invalid() };
    }

    internal static string ChildCommand => "owner-iso-bootstrap-host-child";

    internal static async Task<OwnerIsoGuardedHostResult> RunAsync(CurrentAppOwnedRepairCustody files, OwnerIsoGuardedHostConfiguration configuration,
        IsoDefinitionSubject intendedDefinition, IReceiptAttestationTrustStore definitionTrust, string definitionKeyId, string definitionFingerprint, CancellationToken ct)
    {
        CurrentOwnerIsoCapacity.Require(admission: true);
        RequireConfiguration(configuration);
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(configuration.Root));
        SecureLocalFile.EnsureOwnerOnlyDirectory(root);
        RequirePrerequisites(); RequireDefinitionPrecursor();
        using var bundle = HoldBundle(configuration);
        using var installedDotnet = HoldInstalledImage(Dotnet);
        string nonce = Guid.NewGuid().ToString("N"); DateTimeOffset began = DateTimeOffset.UtcNow, expiry = began + Lease(configuration.Group);
        string prefix = Path.Combine(root, "iso-host-" + nonce), configPath = prefix + "-child.json", gatePath = prefix + "-gate.json", settingsPath = prefix + ".runsettings";
        string stdoutPath = prefix + "-stdout.txt", stderrPath = prefix + "-stderr.txt", hostExitPath = prefix + "-exit.json";
        var dockerBaseline = await OwnerIsoGuardedBootstrapHostDockerCleanup.ObserveBeforeAsync(ct).ConfigureAwait(false);
        await files.WriteNewAsync(prefix + "-docker-before.json", JsonSerializer.SerializeToUtf8Bytes(dockerBaseline), ct).ConfigureAwait(false);
        await files.WriteNewAsync(settingsPath, "<RunSettings><RunConfiguration><MaxCpuCount>1</MaxCpuCount></RunConfiguration></RunSettings>"u8.ToArray(), ct).ConfigureAwait(false);
        var childConfiguration = new OwnerIsoGuardedWaitingChildConfiguration(configuration, nonce, gatePath, settingsPath, expiry);
        await files.WriteNewAsync(configPath, JsonSerializer.SerializeToUtf8Bytes(childConfiguration), ct).ConfigureAwait(false);
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct); lifetime.CancelAfter(Lease(configuration.Group));
        using var job = new CurrentOwnerIsoBootstrapHostJob([Dotnet], nonce);
        _ = job.Observe(admission: true);
        var start = FixedStart(root);
        start.ArgumentList.Add(typeof(MigrationConsole).Assembly.Location); start.ArgumentList.Add(ChildCommand); start.ArgumentList.Add(configPath);
        start.RedirectStandardOutput = true; start.RedirectStandardError = true;
        using var child = new Process { StartInfo = start };
        bool launched = false; DateTimeOffset childStart = default; Task? stdout = null, stderr = null; ExceptionDispatchInfo? primaryFailure = null;
        OwnerIsoGuardedHostResult? successfulResult = null; OwnerIsoGuardedBootstrapHostObservation? observer = null;
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
            await files.WriteNewAsync(gatePath, JsonSerializer.SerializeToUtf8Bytes(new OwnerIsoGuardedHostGate(nonce, child.Id,
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
                runs.Count != (configuration.Group == "native-component" ? 6 : 4)) { throw Invalid(); }
            var actualExit = await observer.RetainActualSuccessfulExitAsync(files, hostExitPath, runs.Order().ToArray(), lifetime.Token).ConfigureAwait(false);
            string trxPath = Path.Combine(root, configuration.Group == "native-component" ? "iso-native.trx" : "iso-maintenance.trx");
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
                    try { await OwnerIsoGuardedBootstrapHostDockerCleanup.RequireCleanupAfterExitAsync(files, root, configuration.CaseRoot, nonce, dockerBaseline).ConfigureAwait(false); }
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
            if (cleanupFailures.Count != 0) { primaryFailure.SourceException.Data["OwnerIsoGuardedHostCleanupFailures"] = new AggregateException(cleanupFailures); }
            primaryFailure.Throw();
        }
        return cleanupFailures.Count != 0
            ? throw new MigrationExecutionException("iso_guarded_host_cleanup_failed", "Exact owned process cleanup, settled streams or cleanup evidence retention failed.")
            : successfulResult is not null ? successfulResult with { CompletedAtUtc = DateTimeOffset.UtcNow } : throw Invalid();
        void ObserveEntries()
        {
            foreach (string path in Directory.EnumerateFiles(configuration.CaseRoot, "iso-component-*-host-entry.json", SearchOption.TopDirectoryOnly))
            {
                byte[] bytes;
                try { using var stream = SecureLocalFile.OpenReadShared(path); if (stream.Length is < 1 or > 65536) { throw Invalid(); } bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes); }
                catch (IOException) { continue; }
                var entry = MigrationConsole.DecodeOwnerIso<IsoActualHostEntry>(bytes);
                if (entry.JobNonce != nonce) { continue; }
                if (!entry.NativeJobMembershipObserved || entry.TestAssemblySha256 != configuration.TestAssemblySha256 || entry.RunId == Guid.Empty) { throw Invalid(); }
                if (observer is null) { observer = new(entry.ProcessId, nonce, configuration.TestAssemblyPath); testhostPid = entry.ProcessId; }
                else if (entry.ProcessId != testhostPid) { throw Invalid(); }
                _ = runs.Add(entry.RunId);
            }
        }
        IsoDefinitionArtifact Artifact(string path)
        { byte[] bytes = files.Read(path, sharedReader: true, maximumBytes: 8_000_000); return new(path, Convert.ToHexStringLower(SHA256.HashData(bytes))); }
        void RequirePrerequisites()
        { using var prerequisites = SecureLocalFile.OpenReadShared(configuration.InputsPath); if (Digest(prerequisites, 8_000_000) != configuration.InputsSha256) { throw Invalid(); } }
        void RequireDefinitionPrecursor()
        {
            using var input = SecureLocalFile.OpenReadShared(configuration.InputsPath);
            if (input.Length is < 1 or > 65536) { throw Invalid(); }
            byte[] bytes = new byte[(int)input.Length]; input.ReadExactly(bytes);
            var settings = MigrationConsole.DecodeOwnerIso<IsoComponentInputs>(bytes);
            using var caseBinding = SecureLocalFile.OpenReadShared(settings.BindingPath);
            if (caseBinding.Length is < 1 or > 65536) { throw Invalid(); }
            byte[] caseBytes = new byte[(int)caseBinding.Length]; caseBinding.ReadExactly(caseBytes);
            var active = MigrationConsole.DecodeOwnerIso<LocalExecutionBinding>(caseBytes);
            if (!StringComparer.OrdinalIgnoreCase.Equals(active.ArtifactRootCanonicalPath, configuration.CaseRoot) ||
                StringComparer.OrdinalIgnoreCase.Equals(active.ArtifactRootCanonicalPath, configuration.Root) ||
                settings.DefinitionKeyId != definitionKeyId || settings.DefinitionFingerprint != definitionFingerprint) { throw Invalid(); }
            using var definitionBinding = SecureLocalFile.OpenReadShared(settings.DefinitionBindingPath);
            if (definitionBinding.Length is < 1 or > 65536) { throw Invalid(); }
            byte[] defBytes = new byte[(int)definitionBinding.Length]; definitionBinding.ReadExactly(defBytes);
            var def = MigrationConsole.DecodeOwnerIso<LocalExecutionBinding>(defBytes);
            if (StringComparer.OrdinalIgnoreCase.Equals(def.ArtifactRootCanonicalPath, configuration.Root) ||
                StringComparer.OrdinalIgnoreCase.Equals(def.ArtifactRootCanonicalPath, configuration.CaseRoot)) { throw Invalid(); }
            // Release this authority/mutex before the child, which independently repeats this full gate.
            using var authority = WindowsLocalRunAuthority.AcquireResume(def.ArtifactRootCanonicalPath, def);
            using var definitionFiles = new CurrentAppOwnedRepairCustody(authority);
            byte[] publicKey = definitionFiles.Read(settings.DefinitionPublicKeyPath, sharedReader: true, maximumBytes: 4096);
            var heldTrust = new ReceiptAttestationTrustStore([new(definitionKeyId, publicKey)]);
            if (!heldTrust.TryGetPublicKeyFingerprintSha256(definitionKeyId, out string heldFingerprint) || heldFingerprint != definitionFingerprint ||
                !definitionTrust.TryGetPublicKeyFingerprintSha256(definitionKeyId, out string suppliedFingerprint) || suppliedFingerprint != heldFingerprint) { throw Invalid(); }
            var proof = MigrationConsole.DecodeOwnerIso<IsoDefinitionProof>(definitionFiles.Read(settings.DefinitionPath, sharedReader: true, maximumBytes: 8_000_000));
            IsoDefinitionPrecursor.Require(definitionFiles, proof, intendedDefinition, heldTrust, definitionKeyId, definitionFingerprint, DateTimeOffset.UtcNow);
            if (intendedDefinition.ConsoleAssemblySha256 != configuration.ConsoleAssemblySha256 || intendedDefinition.CoreAssemblySha256 != configuration.CoreAssemblySha256 ||
                intendedDefinition.TestAssemblySha256 != configuration.TestAssemblySha256) { throw Invalid(); }
            if (proof.Cases.Any(x => x.TestAssembly.Sha256 != configuration.TestAssemblySha256)) { throw Invalid(); }
            var source = MigrationConsole.DecodeOwnerIso<FreshSchemaPlan>(definitionFiles.Read(settings.AcceptedSourcePath, sharedReader: true, maximumBytes: 8_000_000));
            byte[] catalog = definitionFiles.Read(settings.SourceCatalogPath, sharedReader: true, maximumBytes: 8_000_000);
            _ = CurrentOwnerIsoRepairSourceObservation.ReadCatalog(catalog, source, intendedDefinition.SourceCatalogSha256, intendedDefinition.SourceCommitSha, DateTimeOffset.UtcNow);
        }
    }
    internal static async Task<int> RunWaitingChildAsync(string configurationPath, CancellationToken ct)
    {
        using var configurationStream = SecureLocalFile.OpenRead(configurationPath);
        if (configurationStream.Length is < 1 or > 65536) { throw Invalid(); }
        byte[] bytes = new byte[(int)configurationStream.Length]; configurationStream.ReadExactly(bytes);
        var child = MigrationConsole.DecodeOwnerIso<OwnerIsoGuardedWaitingChildConfiguration>(bytes);
        RequireConfiguration(child.Configuration);
        if (!Guid.TryParseExact(child.Nonce, "N", out _) || child.ExpiresAtUtc <= DateTimeOffset.UtcNow || child.ExpiresAtUtc - DateTimeOffset.UtcNow > Lease(child.Configuration.Group)) { throw Invalid(); }
        string expectedPrefix = Path.Combine(Path.TrimEndingDirectorySeparator(Path.GetFullPath(child.Configuration.Root)), "iso-host-" + child.Nonce);
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(configurationPath), expectedPrefix + "-child.json") ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(child.GatePath), expectedPrefix + "-gate.json") ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(child.SettingsPath), expectedPrefix + ".runsettings")) { throw Invalid(); }
        using var self = Process.GetCurrentProcess();
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct); wait.CancelAfter(TimeSpan.FromSeconds(30));
        OwnerIsoGuardedHostGate gate;
        while (true)
        {
            wait.Token.ThrowIfCancellationRequested();
            try
            {
                using var gateStream = SecureLocalFile.OpenRead(child.GatePath);
                if (gateStream.Length is < 1 or > 65536) { throw Invalid(); }
                gate = JsonSerializer.Deserialize<OwnerIsoGuardedHostGate>(gateStream) ?? throw Invalid(); break;
            }
            catch (IOException) { await Task.Delay(50, wait.Token).ConfigureAwait(false); }
        }
        if (gate.Nonce != child.Nonce || gate.ProcessId != self.Id || gate.ProcessStartTimeUtc != new DateTimeOffset(self.StartTime.ToUniversalTime(), TimeSpan.Zero)) { throw Invalid(); }
        OwnerIsoGuardedBootstrapHostObservation.RequireCurrentMembership(child.Nonce);
        using var bundle = HoldBundle(child.Configuration);
        using var settings = SecureLocalFile.OpenReadShared(child.SettingsPath);
        if (Digest(settings, 65536) != Convert.ToHexStringLower(SHA256.HashData("<RunSettings><RunConfiguration><MaxCpuCount>1</MaxCpuCount></RunConfiguration></RunSettings>"u8))) { throw Invalid(); }
        var start = FixedStart(child.Configuration.Root);
        start.Environment["MALIEV_ISO_COMPONENT_JOB_NONCE"] = child.Nonce;
        start.Environment["MALIEV_ISO_COMPONENT_INPUTS"] = child.Configuration.InputsPath;
        start.ArgumentList.Add("vstest"); start.ArgumentList.Add(child.Configuration.TestAssemblyPath);
        start.ArgumentList.Add("--TestCaseFilter:" + Filter(child.Configuration.Group));
        start.ArgumentList.Add("--Settings:" + child.SettingsPath); start.ArgumentList.Add("--ResultsDirectory:" + child.Configuration.Root);
        start.ArgumentList.Add("--Logger:trx;LogFileName=" + (child.Configuration.Group == "native-component" ? "iso-native.trx" : "iso-maintenance.trx"));
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
    internal static void RequireConfiguration(OwnerIsoGuardedHostConfiguration configuration)
    {
        _ = Filter(configuration.Group);
        if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(configuration.Root) || !Path.IsPathFullyQualified(configuration.TestAssemblyPath) ||
            !Path.IsPathFullyQualified(configuration.InputsPath) || !Path.IsPathFullyQualified(configuration.CaseRoot) ||
            StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(configuration.Root), Path.GetFullPath(configuration.CaseRoot)) || Path.GetFileName(configuration.TestAssemblyPath) != "Legacy.Maliev.DataMigration.Tests.dll" ||
            !CurrentAppOwnedRepairPermit.HashShape(configuration.TestAssemblySha256) || !CurrentAppOwnedRepairPermit.HashShape(configuration.ConsoleAssemblySha256) ||
            !CurrentAppOwnedRepairPermit.HashShape(configuration.CoreAssemblySha256) || !CurrentAppOwnedRepairPermit.HashShape(configuration.InputsSha256)) { throw Invalid(); }
    }
    private sealed class HeldBundle(List<(FileStream Stream, string Path)> values) : IDisposable
    {
        internal void Require() { foreach (var value in values) { if (!SecureLocalFile.HandleResolvesToApprovedPath(value.Stream, value.Path)) { throw Invalid(); } } }
        public void Dispose() { foreach (var value in values) { value.Stream.Dispose(); } }
    }
    private static HeldBundle HoldBundle(OwnerIsoGuardedHostConfiguration configuration)
    {
        var held = new List<(FileStream Stream, string Path)>();
        try
        {
            string directory = Path.GetDirectoryName(configuration.TestAssemblyPath) ?? throw Invalid();
            string[] paths = Directory.GetFiles(directory, "*", SearchOption.AllDirectories);
            if (paths.Length is < 1 or > 4000) { throw Invalid(); }
            foreach (string path in paths)
            { var stream = SecureLocalFile.OpenReadShared(path); held.Add((stream, path)); _ = Digest(stream, 128 * 1024 * 1024); }
            foreach ((string path, string expected) in new[] {(configuration.TestAssemblyPath,configuration.TestAssemblySha256),
                (typeof(MigrationConsole).Assembly.Location,configuration.ConsoleAssemblySha256),(typeof(CurrentOwnerIsoRepairPermit).Assembly.Location,configuration.CoreAssemblySha256),
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
        return new("iso_guarded_host_invalid", "Fixed actual ISO component host configuration and evidence required.");
    }
}
