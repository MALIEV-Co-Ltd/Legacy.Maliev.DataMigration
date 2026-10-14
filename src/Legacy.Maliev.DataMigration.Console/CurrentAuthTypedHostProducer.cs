using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthTypedHostConfiguration(string RunBindingPath, string IntendedScopePath,
    string SigningPinsPath, string ReviewPrivateKeyPath, string ReviewPublicKeyPath, string TestAssemblyPath, string TestAssemblySha256,
    string ConsoleAssemblySha256, string CoreAssemblySha256, string Group, string OutputPath,
    string SourceSchemaPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys, CurrentAuthProofArtifact? DefinitionPrecursor = null, string? ClosedLaneInputPath = null);
internal sealed record CurrentAuthTypedTestHostConfiguration(string Root, string BindingSha256, string Group,
    string TestAssemblyPath, string TestAssemblySha256, string ConsoleAssemblySha256, string CoreAssemblySha256,
    string GatePath, string GateNonce, DateTimeOffset ExpiresAtUtc, string? ComponentSeedPath = null, string? ComponentSeedPublicKeyPath = null, string? ClosedLaneInputPath = null);
internal sealed record CurrentAuthTypedHostGate(string Nonce, string BindingSha256, int ProcessId, DateTimeOffset ProcessStartTimeUtc);

internal static class CurrentAuthTypedHostProducer
{
    private static readonly byte[] Newline = [10];
    internal static ReadOnlyMemory<byte> NewlineBytes => Newline;
    internal static readonly string Dotnet = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");
    internal static string Filter(string group)
    {
        return group switch
        {
            "definition" => "FullyQualifiedName~CurrentAuthNativePreservationTests.Fixed_transition_preserves_populated_rows_private_state_and_independent_history_through_rollback_commit_readback|FullyQualifiedName~CurrentAuthNativePreservationTests.Unsupported_preimage_fails_before_candidate",
            "provider" => "FullyQualifiedName~CurrentAuthGuardedNativeExecutionTests.Genuine_auth_provider_preserves_fleet_and_receipts_or_stops",
            "closed" => "FullyQualifiedName~CurrentAuthClosedConsoleExecutionTests.Genuine_named_closed_auth_console_preserves_or_stops",
            _ => throw CurrentAuthRepairPermit.Invalid()
        };
    }

    internal static ProcessStartInfo FixedStart(string root)
    {
        if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(root)) { throw CurrentAuthRepairPermit.Invalid(); }
        var start = new ProcessStartInfo(Dotnet) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = root };
        start.Environment.Clear();
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        start.Environment["SystemRoot"] = windows; start.Environment["WINDIR"] = windows;
        start.Environment["PATH"] = Path.GetDirectoryName(Dotnet) + ";" + Environment.SystemDirectory;
        start.Environment["TEMP"] = root; start.Environment["TMP"] = root;
        start.Environment["DOTNET_CLI_HOME"] = root; start.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        start.Environment["DOTNET_NOLOGO"] = "1"; start.Environment["DOTNET_GCHeapHardLimit"] = "0x20000000";
        start.Environment["MALIEV_AUTH_TYPED_PROOF_ROOT"] = root;
        start.Environment["MALIEV_AUTH_NATIVE_LEDGER"] = root;
        start.Environment["TESTCONTAINERS_RYUK_DISABLED"] = "true";
        return start;
    }
    internal static string ImageHash(string path)
    {
        FileSystemInfo? entry = new FileInfo(path);
        while (entry is not null)
        {
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0) { throw CurrentAuthRepairPermit.Invalid(); }
            entry = entry is FileInfo file ? file.Directory : (entry as DirectoryInfo)?.Parent;
        }
        using var image = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return !SecureLocalFile.HandleResolvesToApprovedPath(image, path) || image.Length is < 1 or > 128 * 1024 * 1024
            ? throw CurrentAuthRepairPermit.Invalid()
            : Convert.ToHexStringLower(SHA256.HashData(image));
    }
    internal sealed class HeldTestBundle(List<(FileStream Stream, string Path)> files) : IDisposable
    {
        internal void Require()
        { foreach (var file in files) { if (!SecureLocalFile.HandleResolvesToApprovedPath(file.Stream, file.Path)) { throw CurrentAuthRepairPermit.Invalid(); } } }
        public void Dispose() { foreach (var file in files) { file.Stream.Dispose(); } }
    }
    internal static async Task<HeldTestBundle> HoldFixedTestBundleAsync(string root, CancellationToken ct)
    {
        const string accepted = @"B:\maliev-legacy\Legacy.Maliev.DataMigration\tests\Legacy.Maliev.DataMigration.Tests\bin\Release\net10.0";
        string[] expected = Directory.GetFiles(accepted, "*", SearchOption.AllDirectories).Select(x => Path.GetRelativePath(accepted, x)).Order(StringComparer.Ordinal).ToArray();
        if (expected.Length is < 1 or > 4000) { throw CurrentAuthRepairPermit.Invalid(); }
        string[] actualRuntime = Directory.GetFiles(root, "*", SearchOption.AllDirectories)
            .Where(x => x.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || x.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                x.EndsWith(".deps.json", StringComparison.OrdinalIgnoreCase) || x.EndsWith(".runtimeconfig.json", StringComparison.OrdinalIgnoreCase))
            .Select(x => Path.GetRelativePath(root, x)).Order(StringComparer.Ordinal).ToArray();
        string[] expectedRuntime = expected.Where(x => x.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || x.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            x.EndsWith(".deps.json", StringComparison.OrdinalIgnoreCase) || x.EndsWith(".runtimeconfig.json", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (!actualRuntime.SequenceEqual(expectedRuntime, StringComparer.Ordinal)) { throw CurrentAuthRepairPermit.Invalid(); }
        var held = new List<(FileStream Stream, string Path)>();
        try
        {
            foreach (string relative in expected)
            {
                ct.ThrowIfCancellationRequested();
                string path = Path.GetFullPath(Path.Combine(root, relative));
                if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) { throw CurrentAuthRepairPermit.Invalid(); }
                var stream = SecureLocalFile.OpenReadShared(path); held.Add((stream, path));
                using var original = new FileStream(Path.Combine(accepted, relative), FileMode.Open, FileAccess.Read, FileShare.Read);
                byte[] originalHash = await SHA256.HashDataAsync(original, ct).ConfigureAwait(false);
                byte[] heldHash = await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false);
                if (stream.Length is < 1 or > 128 * 1024 * 1024 || original.Length != stream.Length ||
                    !CryptographicOperations.FixedTimeEquals(originalHash, heldHash)) { throw CurrentAuthRepairPermit.Invalid(); }
            }
            var bundle = new HeldTestBundle(held); bundle.Require(); return bundle;
        }
        catch { foreach (var file in held) { file.Stream.Dispose(); } throw; }
    }
    internal static async Task DrainAsync(StreamReader reader, CancellationToken ct)
    {
        char[] buffer = new char[4096]; int total = 0;
        while (true)
        {
            int read = await reader.ReadAsync(buffer.AsMemory(), ct).ConfigureAwait(false);
            if (read == 0) { return; }
            total = checked(total + read); if (total > 8 * 1024 * 1024) { throw CurrentAuthRepairPermit.Invalid(); }
        }
    }
    internal static async Task<CurrentAuthProofArtifact> RequireIndependentAbsenceAsync(CurrentAppOwnedRepairCustody files, string root, string group,
        Func<CurrentAppOwnedDockerResource, Task> observe, CancellationToken ct)
    {
        if (group == "closed") { return await CurrentAuthNamedClosedProofProducer.RequireIndependentAbsenceAsync(files, root, observe, ct).ConfigureAwait(false); }
        string[] expected = CurrentAuthRepairProofReader.Cases(group == "definition" ? "helper" : "native", CurrentAuthProofAdmission.DisposableNativeBootstrap, component: true);
        var cases = new HashSet<string>(StringComparer.Ordinal);
        string containers = await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(
            ["--host", "npipe:////./pipe/docker_engine", "ps", "--all", "--no-trunc", "--format", "table {{.ID}} {{.Names}}"], ct, observe).ConfigureAwait(false);
        string volumes = await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(
            ["--host", "npipe:////./pipe/docker_engine", "volume", "ls", "--format", "table {{.Name}}"], ct, observe).ConfigureAwait(false);
        int[] listeners = [.. IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(x => x.Port)];
        foreach (string directory in Directory.EnumerateDirectories(root, "auth-executed-*", SearchOption.TopDirectoryOnly))
        {
            if (!Guid.TryParseExact(Path.GetFileName(directory)["auth-executed-".Length..], "N", out Guid run)) { throw CurrentAuthRepairPermit.Invalid(); }
            LocalExecutionBinding caseBinding = CurrentAuthTypedProofArtifactImport.ReadChildBinding(directory, run);
            using WindowsLocalRunAuthority caseAuthority = WindowsLocalRunAuthority.AcquireResume(directory, caseBinding);
            using var caseFiles = new CurrentAppOwnedRepairCustody(caseAuthority);
            var events = Directory.GetFiles(directory, "*-event.json").Select(path =>
                JsonSerializer.Deserialize<HostEvent>(caseFiles.Read(path, sharedReader: true, maximumBytes: 65536)) ?? throw CurrentAuthRepairPermit.Invalid()).ToArray();
            string id = events.Select(x => x.CaseId).Distinct(StringComparer.Ordinal).Single();
            if (!expected.Contains(id, StringComparer.Ordinal)) { continue; }
            if (!cases.Add(id)) { throw CurrentAuthRepairPermit.Invalid(); }
            JsonDocument Artifact(string phase)
            {
                CurrentAuthProofArtifact value = events.Single(x => x.Phase == phase).Artifact;
                byte[] bytes = caseFiles.Read(value.Path, sharedReader: true, maximumBytes: 4 * 1024 * 1024);
                return Convert.ToHexStringLower(SHA256.HashData(bytes)) != value.Sha256
                    ? throw CurrentAuthRepairPermit.Invalid()
                    : JsonDocument.Parse(bytes);
            }
            using var container = Artifact("container"); using var disposed = Artifact("disposed");
            string actualId = container.RootElement.GetProperty("Id").GetString()!;
            string name = container.RootElement.GetProperty("Name").GetString()!.TrimStart('/');
            string? volume = disposed.RootElement.TryGetProperty("volume", out JsonElement v) ? v.GetString() : null;
            int port = int.Parse(container.RootElement.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp")[0].GetProperty("HostPort").GetString()!, System.Globalization.CultureInfo.InvariantCulture);
            if (containers.Split('\n').Any(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries).Any(x => x == actualId || x == name)) ||
                (volume is not null && volumes.Split('\n').Any(x => x.Trim() == volume)) || listeners.Contains(port) ||
                disposed.RootElement.GetProperty("cleanupFailed").GetBoolean() || !disposed.RootElement.GetProperty("disposed").GetBoolean())
            { throw CurrentAuthRepairPermit.Invalid(); }
        }
        if (!cases.SetEquals(expected)) { throw CurrentAuthRepairPermit.Invalid(); }
        string path = Path.Combine(root, "auth-host-" + group + "-independent-absence.json");
        byte[] inventory = JsonSerializer.SerializeToUtf8Bytes(new
        {
            observedAtUtc = DateTimeOffset.UtcNow,
            group,
            cases = cases.Order(StringComparer.Ordinal).ToArray(),
            containerInventory = containers,
            volumeInventory = volumes,
            listeningPorts = listeners
        });
        await files.WriteNewAsync(path, inventory, ct).ConfigureAwait(false);
        return new(path, Convert.ToHexStringLower(SHA256.HashData(inventory)));
    }
    private sealed record HostEvent(Guid RunId, string CaseId, string Phase, DateTimeOffset ObservedAtUtc, CurrentAuthProofArtifact Artifact);
}

public static partial class MigrationConsole
{
    private static async Task<int> RunCurrentAuthTypedHostProducerAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            CurrentAuthRepairCapacity.Require(admission: true);
            string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
            var config = await ReadProtectedJsonAsync<CurrentAuthTypedHostConfiguration>(configPath, "auth_host_config_unprotected", ct).ConfigureAwait(false);
            var binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(config.RunBindingPath, "auth_host_binding_unprotected", ct).ConfigureAwait(false);
            using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            T Read<T>(string path)
            {
                return DecodeAuthRepair<T>(files.Read(path, sharedReader: true, maximumBytes: 1024 * 1024));
            }

            if (JsonSerializer.Serialize(Read<CurrentAuthTypedHostConfiguration>(configPath)) != JsonSerializer.Serialize(config)) { throw CurrentAuthRepairPermit.Invalid(); }
            var scope = Read<CurrentAuthRepairScope>(config.IntendedScopePath); var pins = Read<CurrentAuthRepairSigningPins>(config.SigningPinsPath);
            if (scope.SourceCommitSha != accepted || scope.ProofAdmission != CurrentAuthProofAdmission.DisposableNativeBootstrap ||
                scope.AuthOwnerCommitSha != ApprovedCurrentAuthSchema.AuthServiceCommit || scope.AuthOwnerSourcePinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 ||
                scope.AuthClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 || (config.Group != "closed" && scope.RunBindingSha256 != binding.ComputeSha256())) { throw CurrentAuthRepairPermit.Invalid(); }
            string root = binding.ArtifactRootCanonicalPath; string assembly = Path.GetFullPath(config.TestAssemblyPath);
            if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(assembly), root) ||
                Path.GetFileName(assembly) != "Legacy.Maliev.DataMigration.Tests.dll" || CurrentAuthTypedHostProducer.ImageHash(assembly) != config.TestAssemblySha256 ||
                CurrentAuthTypedHostProducer.ImageHash(typeof(MigrationConsole).Assembly.Location) != config.ConsoleAssemblySha256 ||
                CurrentAuthTypedHostProducer.ImageHash(typeof(CurrentAuthRepairPermit).Assembly.Location) != config.CoreAssemblySha256)
            { throw CurrentAuthRepairPermit.Invalid(); }
            using var testBundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(root, ct).ConfigureAwait(false);
            foreach ((string path, string hash) in new[]
            {
                (assembly, config.TestAssemblySha256),
                (Path.Combine(Path.GetDirectoryName(assembly)!, "Legacy.Maliev.DataMigration.Console.dll"), config.ConsoleAssemblySha256),
                (Path.Combine(Path.GetDirectoryName(assembly)!, "Legacy.Maliev.DataMigration.dll"), config.CoreAssemblySha256)
            })
            { if (Convert.ToHexStringLower(SHA256.HashData(files.Read(path, sharedReader: true, maximumBytes: 64 * 1024 * 1024))) != hash) { throw CurrentAuthRepairPermit.Invalid(); } }
            byte[] publicKey = files.Read(config.ReviewPublicKeyPath, sharedReader: true, maximumBytes: 65536);
            if (Convert.ToHexStringLower(SHA256.HashData(publicKey)) != pins.ReviewFingerprint) { throw CurrentAuthRepairPermit.Invalid(); }
            var trust = new ReceiptAttestationTrustStore([new TrustedAttestationKey(pins.ReviewKeyId, publicKey)]);
            using var signer = new P256MigrationEvidenceSigner(pins.ReviewKeyId, Encoding.UTF8.GetString(files.Read(config.ReviewPrivateKeyPath, sharedReader: true, maximumBytes: 65536)));
            int ordinal = 0;
            async Task ObserveOwner(CurrentAuthGitResource frame)
            {
                await files.WriteNewAsync(Path.Combine(root,
                $"auth-host-{config.Group}-owner-{ordinal++:D6}.json"), JsonSerializer.SerializeToUtf8Bytes(frame), CancellationToken.None).ConfigureAwait(false);
            }

            async Task ObserveDocker(CurrentAppOwnedDockerResource frame)
            {
                await files.WriteNewAsync(Path.Combine(root,
                            $"auth-host-{config.Group}-docker-{ordinal++:D6}.json"), JsonSerializer.SerializeToUtf8Bytes(frame), CancellationToken.None).ConfigureAwait(false);
            }

            await CurrentAuthOwnerSourceReader.RequireAsync(ObserveOwner, ct).ConfigureAwait(false);
            DateTimeOffset began = DateTimeOffset.UtcNow, expires = began.AddHours(2);
            string? seedPath = null;
            if (config.Group == "provider")
            {
                var source = Read<FreshSchemaPlan>(config.SourceSchemaPath);
                if (source.SourceCommitSha != accepted || SchemaPlanCanonicalizer.ComputeSha256(source) != scope.SourceSchemaPlanSha256 ||
                    config.DefinitionPrecursor is null || scope.AuthHelperProofSha256 != config.DefinitionPrecursor.Sha256 || config.TrustedKeys.Count != 3)
                { throw CurrentAuthRepairPermit.Invalid(); }
                var precursorTrust = new ReceiptAttestationTrustStore(config.TrustedKeys.Select(key =>
                    new TrustedAttestationKey(key.KeyId, files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))).ToArray());
                await CurrentAuthRepairProofReader.RequireAsync(files, new(config.DefinitionPrecursor.Path, config.DefinitionPrecursor.Sha256), config.DefinitionPrecursor.Sha256, "helper",
                    scope, precursorTrust, pins, source, ct).ConfigureAwait(false);
                var seed = new CurrentAuthComponentBootstrapSeed("current-auth-genuine-definition-component-seed-v1", accepted,
                    scope.SourceSchemaPlanSha256, ApprovedCurrentAuthSchema.AuthServiceCommit, CurrentAuthRepairPermit.OwnerPinsSha256,
                    ApprovedCurrentAuthSchema.ClosureSha256, config.DefinitionPrecursor.Sha256, config.TestAssemblySha256,
                    config.ConsoleAssemblySha256, config.CoreAssemblySha256, binding.ComputeSha256(), began, expires, pins.ReviewKeyId, null);
                seed = seed with { Signature = Convert.ToBase64String(signer.Sign(CurrentAuthComponentBootstrap.SeedPayload(seed))) };
                CurrentAuthComponentBootstrap.RequireSeed(seed, trust, pins.ReviewKeyId, pins.ReviewFingerprint, began);
                seedPath = Path.Combine(root, "auth-host-provider-component-seed.json");
                await files.WriteNewAsync(seedPath, JsonSerializer.SerializeToUtf8Bytes(seed), ct).ConfigureAwait(false);
            }
            if (config.Group == "closed")
            {
                if (config.ClosedLaneInputPath is null) { throw CurrentAuthRepairPermit.Invalid(); }
                var lane = Read<CurrentAuthClosedLaneConfiguration>(config.ClosedLaneInputPath);
                if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(config.ClosedLaneInputPath), root) ||
                    lane.ParentRunBindingSha256 != binding.ComputeSha256() || lane.ParentRunBindingPath != config.RunBindingPath ||
                    lane.TestAssemblyPath != assembly || lane.TestAssemblySha256 != config.TestAssemblySha256 ||
                    lane.ConsoleAssemblySha256 != config.ConsoleAssemblySha256 || lane.CoreAssemblySha256 != config.CoreAssemblySha256)
                { throw CurrentAuthRepairPermit.Invalid(); }
                var source = Read<FreshSchemaPlan>(lane.SourceSchemaPath);
                if (source.SourceCommitSha != accepted || SchemaPlanCanonicalizer.ComputeSha256(source) != scope.SourceSchemaPlanSha256)
                { throw CurrentAuthRepairPermit.Invalid(); }
                if (StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(lane.IntendedEvidence.RunBindingPath), root))
                { throw CurrentAuthRepairPermit.Invalid(); }
                var intent = await CurrentAuthNamedClosedIntent.ReadHeldAsync(lane.IntendedEvidence, source, ct).ConfigureAwait(false);
                if (intent.TestAssemblySha256 != config.TestAssemblySha256 || intent.ConsoleAssemblySha256 != config.ConsoleAssemblySha256 ||
                    intent.CoreAssemblySha256 != config.CoreAssemblySha256) { throw CurrentAuthRepairPermit.Invalid(); }
                await CurrentAuthClosedBootstrapReadback.RequireCompletedForHostAsync(lane.CompletedComponents, source,
                    config.TestAssemblySha256, config.ConsoleAssemblySha256, config.CoreAssemblySha256, ct).ConfigureAwait(false);
            }
            string gatePath = Path.Combine(root, "auth-host-" + config.Group + "-gate.json");
            string childPath = Path.Combine(root, "auth-host-" + config.Group + "-child.json");
            string nonce = Guid.NewGuid().ToString("N");
            var child = new CurrentAuthTypedTestHostConfiguration(root, binding.ComputeSha256(), config.Group, assembly,
                config.TestAssemblySha256, config.ConsoleAssemblySha256, config.CoreAssemblySha256, gatePath, nonce, expires, seedPath,
                seedPath is null ? null : config.ReviewPublicKeyPath, config.ClosedLaneInputPath);
            await files.WriteNewAsync(childPath, JsonSerializer.SerializeToUtf8Bytes(child), ct).ConfigureAwait(false);
            using var executableImage = new FileStream(CurrentAuthTypedHostProducer.Dotnet, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (!SecureLocalFile.HandleResolvesToApprovedPath(executableImage, CurrentAuthTypedHostProducer.Dotnet)) { throw CurrentAuthRepairPermit.Invalid(); }
            string executableHash = Convert.ToHexStringLower(SHA256.HashData(executableImage));
            using var job = new CurrentAuthTypedHostJob([CurrentAuthTypedHostProducer.Dotnet, Path.Combine(Path.GetDirectoryName(assembly)!, "testhost.exe")], nonce);
            var capacities = new List<CurrentAuthTypedHostCapacity> { job.Observe(admission: true).Capacity };
            ProcessStartInfo start = CurrentAuthTypedHostProducer.FixedStart(root);
            start.RedirectStandardOutput = true; start.RedirectStandardError = true; start.RedirectStandardInput = true;
            start.ArgumentList.Add(typeof(MigrationConsole).Assembly.Location); start.ArgumentList.Add("run-current-auth-typed-testhost");
            start.ArgumentList.Add("--config"); start.ArgumentList.Add(childPath);
            using var process = new Process { StartInfo = start };
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromHours(2));
            using var readers = new CancellationTokenSource();
            using var budgetStop = new CancellationTokenSource();
            string budgetJournalPath = Path.Combine(root, "auth-host-" + config.Group + "-budget-journal.jsonl");
            using var budgetJournal = new FileStream(budgetJournalPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            if (!SecureLocalFile.HandleResolvesToApprovedPath(budgetJournal, budgetJournalPath)) { throw CurrentAuthRepairPermit.Invalid(); }
            Task stdout = Task.CompletedTask, stderr = Task.CompletedTask; bool started = false, settled = false, cleanupFailed = false;
            Task budget = Task.CompletedTask;
            DateTimeOffset processStart = default, exited = default;
            CurrentAuthProofArtifact? finalAbsence = null;
            try
            {
                if (!process.Start()) { throw CurrentAuthRepairPermit.Invalid(); }
                started = true; _ = process.SafeHandle;
                processStart = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero); process.StandardInput.Close();
                job.AssignWaitingChild(process);
                stdout = CurrentAuthTypedHostProducer.DrainAsync(process.StandardOutput, readers.Token);
                stderr = CurrentAuthTypedHostProducer.DrainAsync(process.StandardError, readers.Token);
                budget = ObserveContinuousBudgetAsync();
                await files.WriteNewAsync(gatePath, JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthTypedHostGate(nonce,
                    binding.ComputeSha256(), process.Id, processStart)), deadline.Token).ConfigureAwait(false);
                while (!process.HasExited || !job.Empty)
                {
                    deadline.Token.ThrowIfCancellationRequested(); files.Require();
                    if (budget.IsFaulted) { await budget.ConfigureAwait(false); }
                    if (stdout.IsFaulted) { await stdout.ConfigureAwait(false); }
                    if (stderr.IsFaulted) { await stderr.ConfigureAwait(false); }
                    await Task.Delay(TimeSpan.FromMilliseconds(500), deadline.Token).ConfigureAwait(false);
                }
                await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false); exited = DateTimeOffset.UtcNow;
                await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(5), deadline.Token).ConfigureAwait(false); settled = true;
                if (process.ExitCode != 0) { throw CurrentAuthRepairPermit.Invalid(); }
                finalAbsence = await CurrentAuthTypedHostProducer.RequireIndependentAbsenceAsync(files, root, config.Group, ObserveDocker, deadline.Token).ConfigureAwait(false);
                await CurrentAuthOwnerSourceReader.RequireAsync(ObserveOwner, deadline.Token).ConfigureAwait(false);
                if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(deadline.Token).ConfigureAwait(false) != accepted) { throw CurrentAuthRepairPermit.Invalid(); }
                testBundle.Require();
            }
            finally { await CompleteCleanupAsync().ConfigureAwait(false); }
            async Task ObserveContinuousBudgetAsync()
            {
                try
                {
                    while (true)
                    {
                        var (Capacity, Processes) = job.Observe(admission: false); capacities.Add(Capacity);
                        byte[] frame = JsonSerializer.SerializeToUtf8Bytes(new { Capacity, Processes });
                        if (frame.Length > 65536 || budgetJournal.Position + frame.Length + 1 > 32 * 1024 * 1024) { throw CurrentAuthRepairPermit.Invalid(); }
                        await budgetJournal.WriteAsync(frame, budgetStop.Token).ConfigureAwait(false);
                        await budgetJournal.WriteAsync(CurrentAuthTypedHostProducer.NewlineBytes, budgetStop.Token).ConfigureAwait(false);
                        budgetJournal.Flush(flushToDisk: true);
                        await Task.Delay(TimeSpan.FromMilliseconds(500), budgetStop.Token).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException) when (budgetStop.IsCancellationRequested) { }
                catch { deadline.Cancel(); throw; }
            }
            async Task CompleteCleanupAsync()
            {
                Exception? failure = null;
                budgetStop.Cancel();
                try { await budget.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false); }
                catch (Exception problem) { failure = problem; cleanupFailed = true; }
                budgetJournal.Dispose();
                if (failure is null)
                {
                    try { _ = files.Read(budgetJournalPath, sharedReader: true, maximumBytes: 32 * 1024 * 1024); }
                    catch (Exception problem) { failure = problem; cleanupFailed = true; }
                }
                try
                {
                    if (started && !process.HasExited && !job.Empty) { await job.CompleteCleanupAsync().ConfigureAwait(false); }
                    // Assignment failure leaves only the fixed waiting child, whose gate was never opened.
                    if (started && !process.HasExited)
                    {
                        if (new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero) != processStart ||
                            !StringComparer.OrdinalIgnoreCase.Equals(process.MainModule?.FileName, CurrentAuthTypedHostProducer.Dotnet))
                        { throw CurrentAuthRepairPermit.Invalid(); }
                        process.Kill(); await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false);
                    }
                    if (!job.Empty) { await job.CompleteCleanupAsync().ConfigureAwait(false); }
                }
                catch (Exception problem) { failure = problem; cleanupFailed = true; }
                readers.Cancel();
                try
                {
                    if (started) { process.StandardOutput.Dispose(); process.StandardError.Dispose(); }
                    await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false); settled = true;
                }
                catch (OperationCanceledException) when (readers.IsCancellationRequested) { settled = stdout.IsCompleted && stderr.IsCompleted; }
                catch (Exception problem) { failure ??= problem; cleanupFailed = true; }
                await files.WriteNewAsync(Path.Combine(root, $"auth-host-{config.Group}-cleanup.json"), JsonSerializer.SerializeToUtf8Bytes(new
                {
                    observedAtUtc = DateTimeOffset.UtcNow,
                    started,
                    processId = started ? process.Id : 0,
                    processStart,
                    expiresAtUtc = expires,
                    exited = started && process.HasExited,
                    readersSettled = settled,
                    cleanupFailed,
                    containerCleanupOwnedByExternalDriver = true
                }), CancellationToken.None).ConfigureAwait(false);
                if (failure is not null || !settled || (started && !process.HasExited)) { throw CurrentAuthRepairPermit.Invalid(); }
            }
            string trxPath = Path.Combine(root, "auth-host-" + config.Group + ".trx");
            byte[] trx = files.Read(trxPath, sharedReader: true, maximumBytes: 8 * 1024 * 1024);
            string capacityPath = Path.Combine(root, "auth-host-" + config.Group + "-capacity.json"); byte[] capacity = JsonSerializer.SerializeToUtf8Bytes(capacities);
            await files.WriteNewAsync(capacityPath, capacity, ct).ConfigureAwait(false);
            var host = new CurrentAuthTypedHostExit("current-auth-typed-host-exit-v1", accepted, binding.ComputeSha256(), config.Group,
                assembly, config.TestAssemblySha256, config.ConsoleAssemblySha256, config.CoreAssemblySha256,
                CurrentAuthTypedHostProducer.Dotnet, executableHash, process.Id, processStart, began, exited, expires,
                process.ExitCode, process.HasExited, settled, cleanupFailed, new(trxPath, Convert.ToHexStringLower(SHA256.HashData(trx))),
                new(capacityPath, Convert.ToHexStringLower(SHA256.HashData(capacity))), pins.ReviewKeyId, null,
                new(budgetJournalPath, Convert.ToHexStringLower(SHA256.HashData(files.Read(budgetJournalPath, sharedReader: true, maximumBytes: 32 * 1024 * 1024)))), finalAbsence);
            CurrentAuthTypedProofAssembler.RequireCapacity(capacities.ToArray(), host);
            host = host with { Signature = Convert.ToBase64String(signer.Sign(CurrentAuthTypedProofAssembler.HostPayload(host))) };
            CurrentAuthTypedProofAssembler.RequireHost(host, binding, scope, pins, trust, DateTimeOffset.UtcNow);
            await files.WriteNewAsync(config.OutputPath, JsonSerializer.SerializeToUtf8Bytes(host), ct).ConfigureAwait(false);
            var retained = DecodeAuthRepair<CurrentAuthTypedHostExit>(files.Read(config.OutputPath, sharedReader: true));
            if (retained != host || !SecureLocalFile.HandleResolvesToApprovedPath(executableImage, CurrentAuthTypedHostProducer.Dotnet)) { throw CurrentAuthRepairPermit.Invalid(); }
            CurrentAuthTypedProofAssembler.RequireHost(retained, binding, scope, pins, trust, DateTimeOffset.UtcNow);
            await output.WriteLineAsync("current_auth_typed_host_observed_no_execution_authority").ConfigureAwait(false); return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or
            UnauthorizedAccessException or System.ComponentModel.Win32Exception or JsonException or InvalidOperationException or TimeoutException or OperationCanceledException)
        { await error.WriteLineAsync("current_auth_typed_host_failed_no_proof").ConfigureAwait(false); return 1; }
    }

    private static async Task<int> RunCurrentAuthTypedTestHostAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        _ = output; _ = error;
        var config = await ReadProtectedJsonAsync<CurrentAuthTypedTestHostConfiguration>(configPath, "auth_child_config_unprotected", ct).ConfigureAwait(false);
        if (!OperatingSystem.IsWindows() || config.ExpiresAtUtc <= DateTimeOffset.UtcNow || config.ExpiresAtUtc > DateTimeOffset.UtcNow.AddHours(2) ||
            !Path.GetFullPath(configPath).StartsWith(config.Root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFullPath(config.GatePath).StartsWith(config.Root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            CurrentAuthTypedHostProducer.ImageHash(config.TestAssemblyPath) != config.TestAssemblySha256 ||
            CurrentAuthTypedHostProducer.ImageHash(typeof(MigrationConsole).Assembly.Location) != config.ConsoleAssemblySha256 ||
            CurrentAuthTypedHostProducer.ImageHash(typeof(CurrentAuthRepairPermit).Assembly.Location) != config.CoreAssemblySha256)
        { throw CurrentAuthRepairPermit.Invalid(); }
        // This fixed route performs no Docker or database action before the parent's held assignment gate.
        using var gateTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct); gateTimeout.CancelAfter(TimeSpan.FromSeconds(30));
        while (!File.Exists(config.GatePath)) { await Task.Delay(TimeSpan.FromMilliseconds(100), gateTimeout.Token).ConfigureAwait(false); }
        var gate = await ReadProtectedJsonAsync<CurrentAuthTypedHostGate>(config.GatePath, "auth_child_gate_unprotected", gateTimeout.Token).ConfigureAwait(false);
        using Process self = Process.GetCurrentProcess();
        if (gate.Nonce != config.GateNonce || gate.BindingSha256 != config.BindingSha256 || gate.ProcessId != self.Id ||
            gate.ProcessStartTimeUtc != new DateTimeOffset(self.StartTime.ToUniversalTime(), TimeSpan.Zero)) { throw CurrentAuthRepairPermit.Invalid(); }
        CurrentAuthTypedHostJob.RequireWaitingChildMembership(config.GateNonce);
        ProcessStartInfo start = CurrentAuthTypedHostProducer.FixedStart(config.Root);
        if (config.Group == "provider")
        {
            if (config.ComponentSeedPath is null || config.ComponentSeedPublicKeyPath is null) { throw CurrentAuthRepairPermit.Invalid(); }
            start.Environment["MALIEV_AUTH_TYPED_COMPONENT_SEED"] = config.ComponentSeedPath;
            start.Environment["MALIEV_AUTH_TYPED_COMPONENT_SEED_KEY"] = config.ComponentSeedPublicKeyPath;
        }
        if (config.Group == "closed")
        {
            if (config.ClosedLaneInputPath is null || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(config.ClosedLaneInputPath), config.Root))
            { throw CurrentAuthRepairPermit.Invalid(); }
            start.Environment["MALIEV_AUTH_CLOSED_LANE_INPUT"] = config.ClosedLaneInputPath;
        }
        start.ArgumentList.Add("vstest"); start.ArgumentList.Add(config.TestAssemblyPath);
        start.ArgumentList.Add("/TestCaseFilter:" + CurrentAuthTypedHostProducer.Filter(config.Group));
        start.ArgumentList.Add("/Logger:trx;LogFileName=auth-host-" + config.Group + ".trx"); start.ArgumentList.Add("/ResultsDirectory:" + config.Root);
        using var process = new Process { StartInfo = start };
        if (!process.Start()) { throw CurrentAuthRepairPermit.Invalid(); }
        // Parent Windows-job observation owns this child and any VSTest children for termination/expiry.
        await process.WaitForExitAsync(ct).ConfigureAwait(false); return process.ExitCode;
    }
}
