using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveExecutionHostConfiguration(string Kind, CurrentAuthArchiveProofArtifact ControlBinding,
    CurrentAuthArchiveProofArtifact CaseInput, CurrentAuthArchiveGenuineExecutionCase ExpectedCase);
internal sealed record CurrentAuthArchiveExecutionRun(string Kind, string Nonce, CurrentAuthArchiveExecutionHostConfiguration Configuration,
    Guid OperationId, string ConsoleImage, string InputRoot, string SourceCommitSha, DateTimeOffset BeganAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record CurrentAuthArchiveExecutionGate(string Nonce, int ProcessId, DateTimeOffset ProcessStartTimeUtc, string ControlBindingSha256);
internal sealed record CurrentAuthArchiveExecutionProviderResult(CurrentAuthArchiveGenuineExecutionResult Case,
    string SourceCommitSha, string InputSha256);

internal static class CurrentAuthArchiveExecutionHost
{
    internal const string ParentCommand = "produce-current-auth-archive-execution-host";
    internal const string ChildCommand = "run-current-auth-archive-execution-sdk";
    internal const string ProviderCommand = "execute-current-auth-archive-execution-provider";
    internal const string RunVariable = "MALIEV_AUTH_ARCHIVE_EXECUTION_RUN";
    internal static string Tool(string name)
    {
        return CurrentAuthArchiveHelperHost.Tool(name);
    }

    internal static ProcessStartInfo Start(string root)
    {
        return CurrentAuthArchiveHelperHost.Start(root);
    }

    internal static byte[] Read(string path, int maximum)
    {
        return CurrentAuthArchiveHelperHost.Read(path, maximum);
    }

    internal static T Decode<T>(byte[] bytes)
    {
        return CurrentAuthArchiveHelperHost.Decode<T>(bytes);
    }

    internal static string Hash(byte[] bytes)
    {
        return CurrentAuthArchiveHelperHost.Hash(bytes);
    }

    internal static string Prefix(string path)
    {
        return CurrentAuthArchiveHelperHost.Prefix(path);
    }

    internal static Task WriteAsync(string path, byte[] bytes, CancellationToken ct)
    {
        return CurrentAuthArchiveHelperHost.WriteAsync(path, bytes, ct);
    }

    internal static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveGenuineExecutionCases.Invalid();
    }

    internal static void RequireTrx(byte[] bytes, string method, string assembly)
    {
        CurrentAuthArchiveHelperHost.RequireTrx(bytes, method, assembly);
    }

    internal static void RequireConfiguration(CurrentAuthArchiveExecutionHostConfiguration config, string path)
    {
        if (config is null || config.Kind != "current-auth-archive-execution-host-v1" || config.ControlBinding is null || config.CaseInput is null ||
            !Path.IsPathFullyQualified(path) || !Path.IsPathFullyQualified(config.ControlBinding.Path) || !Path.IsPathFullyQualified(config.CaseInput.Path) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(path), Path.GetDirectoryName(config.ControlBinding.Path)) ||
            StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(path), Path.GetDirectoryName(config.CaseInput.Path))) { throw Invalid(); }
        CurrentAuthArchiveGenuineExecutionCases.RequireImplemented(config.ExpectedCase);
    }

    internal static CurrentAuthArchiveGenuineHostConfiguration Request(CurrentAuthArchiveExecutionHostConfiguration config)
    {
        byte[] bytes = Read(config.CaseInput.Path, 65536);
        if (Hash(bytes) != config.CaseInput.Sha256) { throw Invalid(); }
        var packet = Decode<CurrentAuthArchiveGenuineExecutionInput>(bytes);
        CurrentAuthArchiveGenuineExecutionInputContract.Require(packet, config.ExpectedCase);
        var request = packet.Request;
        return !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(config.CaseInput.Path), Path.GetDirectoryName(request.Inputs.ParentBinding.Path)) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(config.CaseInput.Path), Path.GetDirectoryName(request.Inputs.TestImage.Path))
            ? throw Invalid()
            : request;
    }

    internal static string InputVariable(CurrentAuthArchiveGenuineExecutionCase value)
    {
        return value switch
        {
            CurrentAuthArchiveGenuineExecutionCase.NativeComplete => "MALIEV_AUTH_ARCHIVE_GENUINE_NATIVE_COMPLETE_INPUT",
            CurrentAuthArchiveGenuineExecutionCase.ExactReviewedDelete => "MALIEV_AUTH_ARCHIVE_GENUINE_EXACT_DELETE_INPUT",
            CurrentAuthArchiveGenuineExecutionCase.PreparedPublication => "MALIEV_AUTH_ARCHIVE_GENUINE_PREPARED_PUBLICATION_INPUT",
            CurrentAuthArchiveGenuineExecutionCase.TerminalPublication => "MALIEV_AUTH_ARCHIVE_GENUINE_TERMINAL_PUBLICATION_INPUT",
            CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.HostUnprobedSdk => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.LocalTrust => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift => "MALIEV_AUTH_ARCHIVE_GENUINE_CAS_DRIFT_INPUT",
            CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift => "MALIEV_AUTH_ARCHIVE_GENUINE_PRIVATE_JOURNAL_DRIFT_INPUT",
            CurrentAuthArchiveGenuineExecutionCase.SequenceDrift => "MALIEV_AUTH_ARCHIVE_GENUINE_SEQUENCE_DRIFT_INPUT",
            CurrentAuthArchiveGenuineExecutionCase.ProductionDrift => "MALIEV_AUTH_ARCHIVE_GENUINE_COMPARISON_DRIFT_INPUT",
            CurrentAuthArchiveGenuineExecutionCase.FirstOnlyDecryptInsertReadback => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.SecondOnlyDecryptInsertReadback => throw Invalid(),
            _ => throw Invalid(),
        };
    }

    internal static int ExpectedMethodCode(CurrentAuthArchiveGenuineExecutionCase value)
    {
        return value switch
        {
            CurrentAuthArchiveGenuineExecutionCase.NativeComplete or CurrentAuthArchiveGenuineExecutionCase.ExactReviewedDelete => 0,
            CurrentAuthArchiveGenuineExecutionCase.PreparedPublication or CurrentAuthArchiveGenuineExecutionCase.TerminalPublication => 1,
            CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.HostUnprobedSdk => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.LocalTrust => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift => 1,
            CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift => 1,
            CurrentAuthArchiveGenuineExecutionCase.SequenceDrift => 1,
            CurrentAuthArchiveGenuineExecutionCase.ProductionDrift => 1,
            CurrentAuthArchiveGenuineExecutionCase.FirstOnlyDecryptInsertReadback => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.SecondOnlyDecryptInsertReadback => throw Invalid(),
            _ => throw Invalid(),
        };
    }

    internal static void RequireRun(CurrentAuthArchiveExecutionRun run, string path)
    {
        RequireConfiguration(run.Configuration, path);
        if (run.Kind != "current-auth-archive-execution-run-v1" || !Guid.TryParseExact(run.Nonce, "N", out _) || run.OperationId == Guid.Empty ||
            run.BeganAtUtc.Offset != TimeSpan.Zero || run.ExpiresAtUtc.Offset != TimeSpan.Zero || run.BeganAtUtc > DateTimeOffset.UtcNow ||
            run.ExpiresAtUtc <= DateTimeOffset.UtcNow || run.ExpiresAtUtc - run.BeganAtUtc != TimeSpan.FromMinutes(8) ||
            Path.GetFileName(path) != "archive-execution-" + run.Nonce + ".json" || !Path.IsPathFullyQualified(run.ConsoleImage) ||
            Path.GetFileName(run.ConsoleImage) != "Legacy.Maliev.DataMigration.Console.dll" ||
            !StringComparer.OrdinalIgnoreCase.Equals(run.InputRoot, Path.GetDirectoryName(run.Configuration.CaseInput.Path)) ||
            StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(run.ConsoleImage), run.InputRoot) ||
            StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(run.ConsoleImage), Path.GetDirectoryName(path))) { throw Invalid(); }
    }
}
public static partial class MigrationConsole
{
    private static async Task<int> RunCurrentAuthArchiveExecutionHostAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
            byte[] initial = CurrentAuthArchiveExecutionHost.Read(configPath, 65536);
            var config = CurrentAuthArchiveExecutionHost.Decode<CurrentAuthArchiveExecutionHostConfiguration>(initial);
            CurrentAuthArchiveExecutionHost.RequireConfiguration(config, configPath);
            byte[] bindingBytes = CurrentAuthArchiveExecutionHost.Read(config.ControlBinding.Path, 65536);
            if (CurrentAuthArchiveExecutionHost.Hash(bindingBytes) != config.ControlBinding.Sha256) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            var binding = CurrentAuthArchiveExecutionHost.Decode<LocalExecutionBinding>(bindingBytes);
            using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            if (!files.Read(configPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(initial)) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            using var heldCaseInput = SecureLocalFile.OpenReadShared(config.CaseInput.Path);
            if (!SecureLocalFile.HandleResolvesToApprovedPath(heldCaseInput, config.CaseInput.Path) || heldCaseInput.Length is < 1 or > 65536 ||
                Convert.ToHexStringLower(await SHA256.HashDataAsync(heldCaseInput, ct)) != config.CaseInput.Sha256) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            var request = CurrentAuthArchiveExecutionHost.Request(config);
            byte[] seedBytes = CurrentAuthArchiveExecutionHost.Read(request.Inputs.ParentSeed.Path, 65536);
            if (CurrentAuthArchiveExecutionHost.Hash(seedBytes) != request.Inputs.ParentSeed.Sha256) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            var seed = CurrentAuthArchiveExecutionHost.Decode<CurrentAuthArchiveComponentBootstrapSeed>(seedBytes);
            string inputRoot = Path.GetDirectoryName(config.CaseInput.Path)!;
            using var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(inputRoot, ct);
            DateTimeOffset began = DateTimeOffset.UtcNow; string nonce = Guid.NewGuid().ToString("N");
            var run = new CurrentAuthArchiveExecutionRun("current-auth-archive-execution-run-v1", nonce, config, seed.OperationId,
                typeof(MigrationConsole).Assembly.Location, inputRoot, accepted, began, began.AddMinutes(8));
            string runPath = Path.Combine(binding.ArtifactRootCanonicalPath, "archive-execution-" + nonce + ".json");
            CurrentAuthArchiveExecutionHost.RequireRun(run, runPath);
            await files.WriteNewAsync(runPath, JsonSerializer.SerializeToUtf8Bytes(run), ct);
            _ = files.Read(runPath, sharedReader: true, maximumBytes: 65536);
            string[] images = [CurrentAuthArchiveExecutionHost.Tool("dotnet"), Path.Combine(inputRoot, "testhost.exe"),
                CurrentAuthArchiveExecutionHost.Tool("git"), CurrentAuthArchiveExecutionHost.Tool("gh"), CurrentAuthArchiveExecutionHost.Tool("docker")];
            var heldImages = new List<FileStream>();
            try
            {
                foreach (string image in images)
                {
                    var held = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read);
                    heldImages.Add(held);
                    if (!SecureLocalFile.HandleResolvesToApprovedPath(held, image)) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
                }
                using var job = new CurrentAuthTypedHostJob(images, nonce);
                _ = job.Observe(admission: true);
                await RunExecutionJobAsync(job, run, runPath, request, files, bundle, ct);
            }
            finally { foreach (FileStream held in heldImages) { held.Dispose(); } }
            await output.WriteLineAsync("archive_execution_host_observed_no_phase_proof"); return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or InvalidOperationException or OperationCanceledException or AggregateException or System.ComponentModel.Win32Exception)
        { await error.WriteLineAsync("archive_execution_host_failed_no_phase_proof"); return 1; }
    }

    private static async Task RunExecutionJobAsync(CurrentAuthTypedHostJob job, CurrentAuthArchiveExecutionRun run, string runPath,
        CurrentAuthArchiveGenuineHostConfiguration request, CurrentAppOwnedRepairCustody files,
        CurrentAuthTypedHostProducer.HeldTestBundle bundle, CancellationToken ct)
    {
        var resources = new CurrentAuthArchiveHelperResources(run.OperationId, run.BeganAtUtc, run.ExpiresAtUtc, run.SourceCommitSha,
            request.FirstFixtureParent, request.SecondFixtureParent);
        await resources.ObserveBeforeAsync(files, runPath, ct);
        ProcessStartInfo start = CurrentAuthArchiveExecutionHost.Start(Path.GetDirectoryName(runPath)!);
        start.ArgumentList.Add(run.ConsoleImage); start.ArgumentList.Add(CurrentAuthArchiveExecutionHost.ChildCommand);
        start.ArgumentList.Add("--config"); start.ArgumentList.Add(runPath);
        using var process = new Process { StartInfo = start };
        using var expiry = CancellationTokenSource.CreateLinkedTokenSource(ct); expiry.CancelAfter(run.ExpiresAtUtc - DateTimeOffset.UtcNow);
        using var readers = new CancellationTokenSource();
        bool started = false, settled = false; DateTimeOffset processStart = default;
        Task stdout = Task.CompletedTask, stderr = Task.CompletedTask; Exception? primary = null;
        try
        {
            if (!process.Start()) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            started = true; processStart = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero); process.StandardInput.Close();
            job.AssignWaitingChild(process);
            stdout = CurrentAuthTypedHostProducer.DrainAsync(process.StandardOutput, readers.Token);
            stderr = CurrentAuthTypedHostProducer.DrainAsync(process.StandardError, readers.Token);
            byte[] bindingBytes = files.Read(run.Configuration.ControlBinding.Path, sharedReader: true, maximumBytes: 65536);
            var binding = CurrentAuthArchiveExecutionHost.Decode<LocalExecutionBinding>(bindingBytes);
            await files.WriteNewAsync(CurrentAuthArchiveExecutionHost.Prefix(runPath) + "-gate.json", JsonSerializer.SerializeToUtf8Bytes(
                new CurrentAuthArchiveExecutionGate(run.Nonce, process.Id, processStart, binding.ComputeSha256())), expiry.Token);
            while (!process.HasExited || !job.Empty)
            {
                expiry.Token.ThrowIfCancellationRequested(); files.Require(); bundle.Require();
                var (Capacity, Processes) = job.Observe(admission: false);
                await files.WriteNewAsync(CurrentAuthArchiveExecutionHost.Prefix(runPath) + "-processes-" + Guid.NewGuid().ToString("N") + ".json",
                    JsonSerializer.SerializeToUtf8Bytes(new { Capacity, Processes }), expiry.Token);
                if (stdout.IsFaulted) { await stdout; }
                if (stderr.IsFaulted) { await stderr; }
                await Task.Delay(250, expiry.Token);
            }
            await process.WaitForExitAsync(expiry.Token); await Task.WhenAll(stdout, stderr); settled = true;
            if (process.ExitCode != 0 || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(expiry.Token) != run.SourceCommitSha) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            byte[] trx = files.Read(Path.Combine(Path.GetDirectoryName(runPath)!, run.Nonce + ".trx"), sharedReader: true, maximumBytes: 8 * 1024 * 1024);
            CurrentAuthArchiveExecutionHost.RequireTrx(trx, CurrentAuthArchiveGenuineCases.Require(request.Phase, request.CaseId).MethodName, request.Inputs.TestImage.Path);
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
                        !StringComparer.OrdinalIgnoreCase.Equals(process.MainModule?.FileName, CurrentAuthArchiveExecutionHost.Tool("dotnet"))) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
                    process.Kill(); await process.WaitForExitAsync(cleanup.Token);
                }
                readers.Cancel(); await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(5), cleanup.Token); settled = true;
                if (!job.Empty) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            }
            catch (OperationCanceledException) when (readers.IsCancellationRequested && stdout.IsCompleted && stderr.IsCompleted) { settled = true; }
            catch (Exception failure) { cleanupFailure = failure; }
            try
            {
                if (!job.Empty || (started && !process.HasExited)) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
                await resources.CleanupAndObserveAsync(files, runPath, requireCompletedPair: primary is null, cleanup.Token);
            }
            catch (Exception failure) { cleanupFailure ??= failure; }
            await files.WriteNewAsync(CurrentAuthArchiveExecutionHost.Prefix(runPath) + "-host-exit.json", JsonSerializer.SerializeToUtf8Bytes(new
            {
                Kind = "current-auth-archive-execution-host-exit-v1",
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

