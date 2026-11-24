using System.Diagnostics;
using System.Reflection;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static class CurrentAuthArchiveGenuineHelperSdkHarness
{
    internal static async Task<CurrentAuthArchiveGenuineProviderCaseResult> RunAsync(string inputPath,
        CurrentAuthArchiveGenuineRecoveryHelperCase expectedCase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        string runPath = Environment.GetEnvironmentVariable(CurrentAuthArchiveHelperHost.RunVariable) ?? throw CurrentAuthArchiveHelperHost.Invalid();
        var run = CurrentAuthArchiveHelperHost.Decode<CurrentAuthArchiveHelperRun>(CurrentAuthArchiveHelperHost.Read(runPath, 65536));
        CurrentAuthArchiveHelperHost.RequireRun(run, runPath);
        if (inputPath != run.Configuration.CaseInput.Path || expectedCase != run.Configuration.ExpectedCase ||
            Assembly.GetEntryAssembly()?.GetName().Name != "testhost" ||
            !StringComparer.OrdinalIgnoreCase.Equals(Assembly.GetEntryAssembly()?.Location, Path.Combine(run.InputRoot, "testhost.dll"))) { throw CurrentAuthArchiveHelperHost.Invalid(); }
        CurrentAuthTypedHostJob.RequireWaitingChildMembership(run.Nonce);
        var request = CurrentAuthArchiveHelperHost.Request(run.Configuration);
        using var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(run.InputRoot, ct);
        if (CurrentAuthTypedHostProducer.ImageHash(run.ConsoleImage) != request.Inputs.ConsoleImage.Sha256) { throw CurrentAuthArchiveHelperHost.Invalid(); }
        using var image = new FileStream(CurrentAuthArchiveHelperHost.Tool("dotnet"), FileMode.Open, FileAccess.Read, FileShare.Read);
        ProcessStartInfo start = CurrentAuthArchiveHelperHost.Start(Path.GetDirectoryName(runPath)!);
        start.ArgumentList.Add(run.ConsoleImage); start.ArgumentList.Add(CurrentAuthArchiveHelperHost.ProviderCommand);
        start.ArgumentList.Add("--config"); start.ArgumentList.Add(runPath);
        using var process = new Process { StartInfo = start };
        using var expiry = CancellationTokenSource.CreateLinkedTokenSource(ct); expiry.CancelAfter(run.ExpiresAtUtc - DateTimeOffset.UtcNow);
        bool started = false, settled = false; DateTimeOffset began = DateTimeOffset.UtcNow, processStart = default;
        Task stdout = Task.CompletedTask, stderr = Task.CompletedTask;
        Exception? primary = null;
        CurrentAuthArchiveGenuineProviderCaseResult? completed = null;
        try
        {
            if (!process.Start()) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            started = true; processStart = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero); process.StandardInput.Close();
            stdout = CurrentAuthTypedHostProducer.DrainAsync(process.StandardOutput, expiry.Token);
            stderr = CurrentAuthTypedHostProducer.DrainAsync(process.StandardError, expiry.Token);
            await process.WaitForExitAsync(expiry.Token); await Task.WhenAll(stdout, stderr); settled = true;
            bundle.Require();
            byte[] resultBytes = CurrentAuthArchiveHelperHost.Read(CurrentAuthArchiveHelperHost.Prefix(runPath) + "-provider-result.json", 65536);
            var result = CurrentAuthArchiveHelperHost.Decode<CurrentAuthArchiveHelperProviderResult>(resultBytes);
            if (result.SourceCommitSha != run.SourceCommitSha || result.InputSha256 != run.Configuration.CaseInput.Sha256 ||
                result.Case.Method.ReturnCode != process.ExitCode || result.Case.Method.ReturnCode !=
                    (expectedCase is CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption or CurrentAuthArchiveGenuineRecoveryHelperCase.CipherCorruption ? 1 : 0) ||
                result.Case.Method.StartedAtUtc < run.BeganAtUtc || result.Case.Method.ReturnedAtUtc < result.Case.Method.StartedAtUtc ||
                result.Case.Method.ReturnedAtUtc > new DateTimeOffset(process.ExitTime.ToUniversalTime(), TimeSpan.Zero)) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(result.Case.FinalCandidate.Path), run.InputRoot)) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            byte[] candidateBytes = CurrentAuthArchiveHelperHost.Read(result.Case.FinalCandidate.Path, 65536);
            if (CurrentAuthArchiveHelperHost.Hash(candidateBytes) != result.Case.FinalCandidate.Sha256) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            using var candidate = JsonDocument.Parse(candidateBytes);
            if (candidate.RootElement.GetProperty("OperationId").GetGuid() != run.OperationId ||
                candidate.RootElement.GetProperty("CaseId").GetString() != CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(expectedCase) ||
                !candidate.RootElement.GetProperty("CleanupVerified").GetBoolean() || candidate.RootElement.GetProperty("PhaseProofComplete").GetBoolean()) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            completed = result.Case;
        }
        catch (Exception failure) { primary = failure; }
        Exception? cleanupFailure = null;
        try
        {
            if (started && !process.HasExited)
            {
                if (new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero) != processStart ||
                    !StringComparer.OrdinalIgnoreCase.Equals(process.MainModule?.FileName, CurrentAuthArchiveHelperHost.Tool("dotnet"))) { throw CurrentAuthArchiveHelperHost.Invalid(); }
                process.Kill(); await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None);
            }
            if (started)
            {
                await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None); settled = stdout.IsCompletedSuccessfully && stderr.IsCompletedSuccessfully;
            }
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await CurrentAuthArchiveHelperHost.WriteAsync(CurrentAuthArchiveHelperHost.Prefix(runPath) + "-provider-process.json",
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    Kind = "current-auth-archive-helper-actual-provider-process-v1",
                    run.OperationId,
                    run.Configuration.ExpectedCase,
                    Command = CurrentAuthArchiveHelperHost.ProviderCommand,
                    Executable = CurrentAuthArchiveHelperHost.Tool("dotnet"),
                    run.ConsoleImage,
                    ConsoleImageSha256 = CurrentAuthTypedHostProducer.ImageHash(run.ConsoleImage),
                    ExecutableSha256 = CurrentAuthTypedHostProducer.ImageHash(CurrentAuthArchiveHelperHost.Tool("dotnet")),
                    ProcessId = started ? process.Id : 0,
                    ProcessStartTimeUtc = processStart,
                    StartedAtUtc = began,
                    ExitedAtUtc = started && process.HasExited ? new DateTimeOffset(process.ExitTime.ToUniversalTime(), TimeSpan.Zero) : (DateTimeOffset?)null,
                    ExitCode = started && process.HasExited ? process.ExitCode : (int?)null,
                    Exited = started && process.HasExited,
                    ReadersSettled = settled,
                    FailureType = primary?.GetType().Name,
                    PhaseProofComplete = false,
                }), cleanup.Token);
        }
        catch (Exception cleanup) { cleanupFailure = cleanup; }
        if (cleanupFailure is not null) { throw new AggregateException("The exact provider process cleanup failed.", primary is null ? [cleanupFailure] : [primary, cleanupFailure]); }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
        return completed ?? throw CurrentAuthArchiveHelperHost.Invalid();
    }
}

public static partial class MigrationConsole
{
    private static async Task<int> RunCurrentAuthArchiveHelperProviderAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        _ = output;
        try
        {
            var run = CurrentAuthArchiveHelperHost.Decode<CurrentAuthArchiveHelperRun>(CurrentAuthArchiveHelperHost.Read(configPath, 65536));
            CurrentAuthArchiveHelperHost.RequireRun(run, configPath);
            CurrentAuthTypedHostJob.RequireWaitingChildMembership(run.Nonce);
            if (typeof(MigrationConsole).Assembly.Location != run.ConsoleImage || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != run.SourceCommitSha)
            { throw CurrentAuthArchiveHelperHost.Invalid(); }
            var request = CurrentAuthArchiveHelperHost.Request(run.Configuration);
            using var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(run.InputRoot, ct);
            using var loader = new CurrentAuthArchiveInitialProducer.FixedNativeBundle(request.Inputs.TestImage.Path);
            CurrentAuthArchiveGenuineProviderCaseResult result;
            try
            {
                Assembly tests = loader.LoadFromAssemblyPath(request.Inputs.TestImage.Path);
                MethodInfo method = tests.GetType("Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveGenuineRecoveryHelpersRunner", throwOnError: true)!
                    .GetMethod("ExecuteAsync", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.DeclaredOnly, binder: null,
                        types: [typeof(string), typeof(CurrentAuthArchiveGenuineRecoveryHelperCase), typeof(CancellationToken)], modifiers: null)
                    ?? throw CurrentAuthArchiveHelperHost.Invalid();
                if (method.ReturnType != typeof(Task<CurrentAuthArchiveGenuineProviderCaseResult>)) { throw CurrentAuthArchiveHelperHost.Invalid(); }
                using var expiry = CancellationTokenSource.CreateLinkedTokenSource(ct); expiry.CancelAfter(run.ExpiresAtUtc - DateTimeOffset.UtcNow);
                bundle.Require();
                var pending = method.Invoke(null, [run.Configuration.CaseInput.Path, run.Configuration.ExpectedCase, expiry.Token]) as Task<CurrentAuthArchiveGenuineProviderCaseResult>
                    ?? throw CurrentAuthArchiveHelperHost.Invalid();
                result = await pending; bundle.Require();
            }
            finally { loader.Unload(); }
            if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != run.SourceCommitSha ||
                result.Method.StartedAtUtc < run.BeganAtUtc || result.Method.ReturnedAtUtc > DateTimeOffset.UtcNow ||
                result.Method.ReturnedAtUtc < result.Method.StartedAtUtc || result.Method.ReturnCode is not (0 or 1)) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            await CurrentAuthArchiveHelperHost.WriteAsync(CurrentAuthArchiveHelperHost.Prefix(configPath) + "-provider-result.json",
                JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthArchiveHelperProviderResult(result, run.SourceCommitSha, run.Configuration.CaseInput.Sha256)), ct);
            return result.Method.ReturnCode;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or InvalidOperationException or OperationCanceledException or TargetInvocationException or System.ComponentModel.Win32Exception)
        { await error.WriteLineAsync("archive_helper_provider_failed_before_completed_method_result"); return 1; }
    }

    private static async Task<int> RunCurrentAuthArchiveHelperSdkAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        _ = output;
        try
        {
            var run = CurrentAuthArchiveHelperHost.Decode<CurrentAuthArchiveHelperRun>(CurrentAuthArchiveHelperHost.Read(configPath, 65536));
            CurrentAuthArchiveHelperHost.RequireRun(run, configPath);
            if (typeof(MigrationConsole).Assembly.Location != run.ConsoleImage) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct); wait.CancelAfter(TimeSpan.FromSeconds(30));
            string gatePath = CurrentAuthArchiveHelperHost.Prefix(configPath) + "-gate.json";
            byte[]? gateBytes = null;
            while (gateBytes is null)
            {
                wait.Token.ThrowIfCancellationRequested();
                try { if (File.Exists(gatePath)) { gateBytes = CurrentAuthArchiveHelperHost.Read(gatePath, 65536); } }
                catch (IOException) { /* The parent publishes with exclusive sharing until its durable write closes. */ }
                if (gateBytes is null) { await Task.Delay(50, wait.Token); }
            }
            var gate = CurrentAuthArchiveHelperHost.Decode<CurrentAuthArchiveHelperGate>(gateBytes);
            using var self = Process.GetCurrentProcess();
            byte[] bindingBytes = CurrentAuthArchiveHelperHost.Read(run.Configuration.ControlBinding.Path, 65536);
            var binding = CurrentAuthArchiveHelperHost.Decode<LocalExecutionBinding>(bindingBytes);
            if (CurrentAuthArchiveHelperHost.Hash(bindingBytes) != run.Configuration.ControlBinding.Sha256 || gate.Nonce != run.Nonce ||
                gate.ControlBindingSha256 != binding.ComputeSha256() || gate.ProcessId != self.Id ||
                gate.ProcessStartTimeUtc != new DateTimeOffset(self.StartTime.ToUniversalTime(), TimeSpan.Zero)) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            CurrentAuthTypedHostJob.RequireWaitingChildMembership(run.Nonce);
            if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != run.SourceCommitSha) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            var request = CurrentAuthArchiveHelperHost.Request(run.Configuration);
            using var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(run.InputRoot, ct);
            ProcessStartInfo start = CurrentAuthArchiveHelperHost.Start(Path.GetDirectoryName(configPath)!);
            start.Environment[CurrentAuthArchiveHelperHost.RunVariable] = configPath;
            start.Environment[InputVariable(run.Configuration.ExpectedCase)] = run.Configuration.CaseInput.Path;
            start.ArgumentList.Add("vstest"); start.ArgumentList.Add(request.Inputs.TestImage.Path);
            start.ArgumentList.Add("/TestCaseFilter:" + CurrentAuthTypedHostProducer.ArchiveFilter("helper", request.CaseId));
            start.ArgumentList.Add("/Logger:trx;LogFileName=" + run.Nonce + ".trx");
            start.ArgumentList.Add("/ResultsDirectory:" + Path.GetDirectoryName(configPath));
            using var process = new Process { StartInfo = start };
            using var expiry = CancellationTokenSource.CreateLinkedTokenSource(ct); expiry.CancelAfter(run.ExpiresAtUtc - DateTimeOffset.UtcNow);
            if (!process.Start()) { throw CurrentAuthArchiveHelperHost.Invalid(); }
            process.StandardInput.Close();
            Task stdout = CurrentAuthTypedHostProducer.DrainAsync(process.StandardOutput, expiry.Token), stderr = CurrentAuthTypedHostProducer.DrainAsync(process.StandardError, expiry.Token);
            await process.WaitForExitAsync(expiry.Token); await Task.WhenAll(stdout, stderr); bundle.Require();
            await CurrentAuthArchiveHelperHost.WriteAsync(CurrentAuthArchiveHelperHost.Prefix(configPath) + "-vstest-process.json", JsonSerializer.SerializeToUtf8Bytes(new
            {
                Kind = "current-auth-archive-helper-actual-vstest-process-v1",
                ProcessId = process.Id,
                ProcessStartTimeUtc = new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero),
                ExitedAtUtc = new DateTimeOffset(process.ExitTime.ToUniversalTime(), TimeSpan.Zero),
                process.ExitCode,
                ReadersSettled = true,
            }), ct);
            return process.ExitCode;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or InvalidOperationException or OperationCanceledException or System.ComponentModel.Win32Exception)
        { await error.WriteLineAsync("archive_helper_sdk_failed_no_phase_proof"); return 1; }
    }

    private static string InputVariable(CurrentAuthArchiveGenuineRecoveryHelperCase value)
    {
        return value switch
        {
            CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback => "MALIEV_AUTH_ARCHIVE_GENUINE_DUAL_HELPER_INPUT",
            CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery => "MALIEV_AUTH_ARCHIVE_GENUINE_FIRST_ONLY_INPUT",
            CurrentAuthArchiveGenuineRecoveryHelperCase.SecondOnlyRecovery => "MALIEV_AUTH_ARCHIVE_GENUINE_SECOND_ONLY_INPUT",
            CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption => "MALIEV_AUTH_ARCHIVE_GENUINE_KEY_CORRUPTION_INPUT",
            CurrentAuthArchiveGenuineRecoveryHelperCase.CipherCorruption => "MALIEV_AUTH_ARCHIVE_GENUINE_CIPHER_CORRUPTION_INPUT",
            _ => throw CurrentAuthArchiveHelperHost.Invalid(),
        };
    }
}
