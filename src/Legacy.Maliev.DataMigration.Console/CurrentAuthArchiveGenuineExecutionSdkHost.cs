using System.Diagnostics;
using System.Reflection;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static class CurrentAuthArchiveGenuineExecutionSdkHarness
{
    internal static async Task<CurrentAuthArchiveGenuineExecutionResult> RunAsync(string inputPath,
        CurrentAuthArchiveGenuineExecutionCase expectedCase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        string runPath = Environment.GetEnvironmentVariable(CurrentAuthArchiveExecutionHost.RunVariable) ?? throw CurrentAuthArchiveExecutionHost.Invalid();
        var run = CurrentAuthArchiveExecutionHost.Decode<CurrentAuthArchiveExecutionRun>(CurrentAuthArchiveExecutionHost.Read(runPath, 65536));
        CurrentAuthArchiveExecutionHost.RequireRun(run, runPath);
        if (inputPath != run.Configuration.CaseInput.Path || expectedCase != run.Configuration.ExpectedCase ||
            Assembly.GetEntryAssembly()?.GetName().Name != "testhost" ||
            !StringComparer.OrdinalIgnoreCase.Equals(Assembly.GetEntryAssembly()?.Location, Path.Combine(run.InputRoot, "testhost.dll"))) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
        CurrentAuthTypedHostJob.RequireWaitingChildMembership(run.Nonce);
        using var harnessProcess = Process.GetCurrentProcess();
        var request = CurrentAuthArchiveExecutionHost.Request(run.Configuration);
        using var acceptedConsole = await CurrentAuthArchiveAcceptedConsoleBundle.HoldAsync(run.ConsoleImage, ct);
        using var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(run.InputRoot, ct);
        if (CurrentAuthTypedHostProducer.ImageHash(run.ConsoleImage) != request.Inputs.ConsoleImage.Sha256) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
        ProcessStartInfo start = CurrentAuthArchiveExecutionHost.Start(Path.GetDirectoryName(runPath)!);
        start.ArgumentList.Add(run.ConsoleImage); start.ArgumentList.Add(CurrentAuthArchiveExecutionHost.ProviderCommand);
        start.ArgumentList.Add("--config"); start.ArgumentList.Add(runPath);
        using var process = new Process { StartInfo = start };
        using var expiry = CancellationTokenSource.CreateLinkedTokenSource(ct); expiry.CancelAfter(run.ExpiresAtUtc - DateTimeOffset.UtcNow);
        bool started = false, settled = false; DateTimeOffset began = DateTimeOffset.UtcNow, processStart = default;
        Task stdout = Task.CompletedTask, stderr = Task.CompletedTask;
        Exception? primary = null;
        CurrentAuthArchiveGenuineExecutionResult? completed = null;
        try
        {
            acceptedConsole.Require();
            if (!process.Start()) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            started = true; processStart = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero); process.StandardInput.Close();
            stdout = CurrentAuthTypedHostProducer.DrainAsync(process.StandardOutput, expiry.Token);
            stderr = CurrentAuthTypedHostProducer.DrainAsync(process.StandardError, expiry.Token);
            await process.WaitForExitAsync(expiry.Token); await Task.WhenAll(stdout, stderr); settled = true;
            bundle.Require(); acceptedConsole.Require();
            byte[] resultBytes = CurrentAuthArchiveExecutionHost.Read(CurrentAuthArchiveExecutionHost.Prefix(runPath) + "-provider-result.json", 65536);
            var result = CurrentAuthArchiveExecutionHost.Decode<CurrentAuthArchiveExecutionProviderResult>(resultBytes);
            if (result.SourceCommitSha != run.SourceCommitSha || result.InputSha256 != run.Configuration.CaseInput.Sha256 ||
                result.Case.Method.ReturnCode != process.ExitCode || result.Case.Method.ReturnCode != CurrentAuthArchiveExecutionHost.ExpectedMethodCode(expectedCase) ||
                result.Case.Method.StartedAtUtc < run.BeganAtUtc || result.Case.Method.ReturnedAtUtc < result.Case.Method.StartedAtUtc ||
                result.Case.Method.ReturnedAtUtc > new DateTimeOffset(process.ExitTime.ToUniversalTime(), TimeSpan.Zero)) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(result.Case.FinalCandidate.Path), run.InputRoot)) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            byte[] candidateBytes = CurrentAuthArchiveExecutionHost.Read(result.Case.FinalCandidate.Path, 65536);
            if (CurrentAuthArchiveExecutionHost.Hash(candidateBytes) != result.Case.FinalCandidate.Sha256) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            using var candidate = JsonDocument.Parse(candidateBytes);
            if (candidate.RootElement.GetProperty("Kind").GetString() != "current-auth-genuine-execution-candidate-v1" ||
                candidate.RootElement.GetProperty("Phase").GetString() != CurrentAuthArchiveGenuineExecutionCases.Identity(expectedCase).Phase ||
                candidate.RootElement.GetProperty("ProviderProcessExitCode").ValueKind != JsonValueKind.Null ||
                candidate.RootElement.GetProperty("OperationId").GetGuid() != run.OperationId ||
                candidate.RootElement.GetProperty("CaseId").GetString() != CurrentAuthArchiveGenuineExecutionCases.Identity(expectedCase).CaseId ||
                !candidate.RootElement.GetProperty("CleanupVerified").GetBoolean() || candidate.RootElement.GetProperty("PhaseProofComplete").GetBoolean()) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            completed = result.Case;
        }
        catch (Exception failure) { primary = failure; }
        Exception? cleanupFailure = null;
        try
        {
            if (started && !process.HasExited)
            {
                if (new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero) != processStart ||
                    !StringComparer.OrdinalIgnoreCase.Equals(process.MainModule?.FileName, CurrentAuthArchiveExecutionHost.Tool("dotnet"))) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
                process.Kill(); await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None);
            }
            if (started)
            {
                await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None); settled = stdout.IsCompletedSuccessfully && stderr.IsCompletedSuccessfully;
            }
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await CurrentAuthArchiveExecutionHost.WriteAsync(CurrentAuthArchiveExecutionHost.Prefix(runPath) + "-provider-process.json",
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    Kind = "current-auth-archive-execution-actual-provider-process-v1",
                    run.OperationId,
                    run.Nonce,
                    run.SourceCommitSha,
                    CaseInputSha256 = run.Configuration.CaseInput.Sha256,
                    RunSha256 = CurrentAuthLocalSessionArchivePolicy.HashBytes(CurrentAuthArchiveHelperHost.Read(runPath, 65536)),
                    HarnessProcessId = Environment.ProcessId,
                    HarnessProcessStartTimeUtc = new DateTimeOffset(harnessProcess.StartTime.ToUniversalTime(), TimeSpan.Zero),
                    RequiredJobNonce = run.Nonce,
                    run.Configuration.ExpectedCase,
                    Command = CurrentAuthArchiveExecutionHost.ProviderCommand,
                    Executable = CurrentAuthArchiveExecutionHost.Tool("dotnet"),
                    run.ConsoleImage,
                    ConsoleImageSha256 = CurrentAuthTypedHostProducer.ImageHash(run.ConsoleImage),
                    ExecutableSha256 = CurrentAuthTypedHostProducer.ImageHash(CurrentAuthArchiveExecutionHost.Tool("dotnet")),
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
        return completed ?? throw CurrentAuthArchiveExecutionHost.Invalid();
    }
}

public static partial class MigrationConsole
{
    private static async Task<int> RunCurrentAuthArchiveExecutionProviderAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        _ = output;
        try
        {
            var run = CurrentAuthArchiveExecutionHost.Decode<CurrentAuthArchiveExecutionRun>(CurrentAuthArchiveExecutionHost.Read(configPath, 65536));
            CurrentAuthArchiveExecutionHost.RequireRun(run, configPath);
            CurrentAuthTypedHostJob.RequireWaitingChildMembership(run.Nonce);
            if (typeof(MigrationConsole).Assembly.Location != run.ConsoleImage || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != run.SourceCommitSha)
            { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            var request = CurrentAuthArchiveExecutionHost.Request(run.Configuration);
            using var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(run.InputRoot, ct);
            using var loader = new CurrentAuthArchiveInitialProducer.FixedNativeBundle(request.Inputs.TestImage.Path);
            CurrentAuthArchiveGenuineExecutionResult result;
            try
            {
                Assembly tests = loader.LoadFromAssemblyPath(request.Inputs.TestImage.Path);
                MethodInfo method = tests.GetType("Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveGenuineExecutionRunner", throwOnError: true)!
                    .GetMethod("ExecuteAsync", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.DeclaredOnly, binder: null,
                        types: [typeof(string), typeof(CurrentAuthArchiveGenuineExecutionCase), typeof(CancellationToken)], modifiers: null)
                    ?? throw CurrentAuthArchiveExecutionHost.Invalid();
                if (method.ReturnType != typeof(Task<CurrentAuthArchiveGenuineExecutionResult>)) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
                using var expiry = CancellationTokenSource.CreateLinkedTokenSource(ct); expiry.CancelAfter(run.ExpiresAtUtc - DateTimeOffset.UtcNow);
                bundle.Require();
                var pending = method.Invoke(null, [run.Configuration.CaseInput.Path, run.Configuration.ExpectedCase, expiry.Token]) as Task<CurrentAuthArchiveGenuineExecutionResult>
                    ?? throw CurrentAuthArchiveExecutionHost.Invalid();
                result = await pending; bundle.Require();
            }
            finally { loader.Unload(); }
            if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != run.SourceCommitSha ||
                result.Method.StartedAtUtc < run.BeganAtUtc || result.Method.ReturnedAtUtc > DateTimeOffset.UtcNow ||
                result.Method.ReturnedAtUtc < result.Method.StartedAtUtc ||
                result.Method.ReturnCode != CurrentAuthArchiveExecutionHost.ExpectedMethodCode(run.Configuration.ExpectedCase)) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            await CurrentAuthArchiveExecutionHost.WriteAsync(CurrentAuthArchiveExecutionHost.Prefix(configPath) + "-provider-result.json",
                JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthArchiveExecutionProviderResult(result, run.SourceCommitSha, run.Configuration.CaseInput.Sha256)), ct);
            return result.Method.ReturnCode;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or InvalidOperationException or OperationCanceledException or TargetInvocationException or System.ComponentModel.Win32Exception)
        { await error.WriteLineAsync("archive_execution_provider_failed_before_completed_method_result"); return 1; }
    }

    private static async Task<int> RunCurrentAuthArchiveExecutionSdkAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        _ = output;
        try
        {
            var run = CurrentAuthArchiveExecutionHost.Decode<CurrentAuthArchiveExecutionRun>(CurrentAuthArchiveExecutionHost.Read(configPath, 65536));
            CurrentAuthArchiveExecutionHost.RequireRun(run, configPath);
            if (typeof(MigrationConsole).Assembly.Location != run.ConsoleImage) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct); wait.CancelAfter(TimeSpan.FromSeconds(30));
            string gatePath = CurrentAuthArchiveExecutionHost.Prefix(configPath) + "-gate.json";
            byte[]? gateBytes = null;
            while (gateBytes is null)
            {
                wait.Token.ThrowIfCancellationRequested();
                try { if (File.Exists(gatePath)) { gateBytes = CurrentAuthArchiveExecutionHost.Read(gatePath, 65536); } }
                catch (IOException) { /* The parent publishes with exclusive sharing until its durable write closes. */ }
                if (gateBytes is null) { await Task.Delay(50, wait.Token); }
            }
            var gate = CurrentAuthArchiveExecutionHost.Decode<CurrentAuthArchiveExecutionGate>(gateBytes);
            using var self = Process.GetCurrentProcess();
            byte[] bindingBytes = CurrentAuthArchiveExecutionHost.Read(run.Configuration.ControlBinding.Path, 65536);
            var binding = CurrentAuthArchiveExecutionHost.Decode<LocalExecutionBinding>(bindingBytes);
            if (CurrentAuthArchiveExecutionHost.Hash(bindingBytes) != run.Configuration.ControlBinding.Sha256 || gate.Nonce != run.Nonce ||
                gate.ControlBindingSha256 != binding.ComputeSha256() || gate.ProcessId != self.Id ||
                gate.ProcessStartTimeUtc != new DateTimeOffset(self.StartTime.ToUniversalTime(), TimeSpan.Zero)) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            CurrentAuthTypedHostJob.RequireWaitingChildMembership(run.Nonce);
            if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != run.SourceCommitSha) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            var request = CurrentAuthArchiveExecutionHost.Request(run.Configuration);
            using var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(run.InputRoot, ct);
            ProcessStartInfo start = CurrentAuthArchiveExecutionHost.Start(Path.GetDirectoryName(configPath)!);
            start.Environment[CurrentAuthArchiveExecutionHost.RunVariable] = configPath;
            start.Environment[CurrentAuthArchiveExecutionHost.InputVariable(run.Configuration.ExpectedCase)] = run.Configuration.CaseInput.Path;
            start.ArgumentList.Add("vstest"); start.ArgumentList.Add(request.Inputs.TestImage.Path);
            start.ArgumentList.Add("/TestCaseFilter:" + CurrentAuthTypedHostProducer.ArchiveFilter(request.Phase, request.CaseId));
            start.ArgumentList.Add("/Logger:trx;LogFileName=" + run.Nonce + ".trx");
            start.ArgumentList.Add("/ResultsDirectory:" + Path.GetDirectoryName(configPath));
            using var process = new Process { StartInfo = start };
            using var expiry = CancellationTokenSource.CreateLinkedTokenSource(ct); expiry.CancelAfter(run.ExpiresAtUtc - DateTimeOffset.UtcNow);
            if (!process.Start()) { throw CurrentAuthArchiveExecutionHost.Invalid(); }
            process.StandardInput.Close();
            Task stdout = CurrentAuthTypedHostProducer.DrainAsync(process.StandardOutput, expiry.Token), stderr = CurrentAuthTypedHostProducer.DrainAsync(process.StandardError, expiry.Token);
            await process.WaitForExitAsync(expiry.Token); await Task.WhenAll(stdout, stderr); bundle.Require();
            await CurrentAuthArchiveExecutionHost.WriteAsync(CurrentAuthArchiveExecutionHost.Prefix(configPath) + "-vstest-process.json", JsonSerializer.SerializeToUtf8Bytes(new
            {
                Kind = "current-auth-archive-execution-actual-vstest-process-v1",
                run.OperationId,
                run.Nonce,
                run.SourceCommitSha,
                CaseInputSha256 = run.Configuration.CaseInput.Sha256,
                RunSha256 = CurrentAuthLocalSessionArchivePolicy.HashBytes(CurrentAuthArchiveHelperHost.Read(configPath, 65536)),
                SdkProcessId = self.Id,
                SdkProcessStartTimeUtc = new DateTimeOffset(self.StartTime.ToUniversalTime(), TimeSpan.Zero),
                RequiredJobNonce = run.Nonce,
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
        { await error.WriteLineAsync("archive_execution_sdk_failed_no_phase_proof"); return 1; }
    }

}
