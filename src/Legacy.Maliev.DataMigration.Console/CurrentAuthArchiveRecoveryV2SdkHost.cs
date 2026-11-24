using System.Diagnostics;
using System.Reflection;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static class CurrentAuthArchiveRecoveryV2SdkHarness
{
    internal static async Task<CurrentAuthArchiveRecoveryResultV2> RunAsync(string inputPath,
        CurrentAuthArchiveRecoveryV2Case expectedCase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        string runPath = Environment.GetEnvironmentVariable(CurrentAuthArchiveRecoveryV2Host.RunVariable) ?? throw CurrentAuthArchiveRecoveryV2Host.Invalid();
        var run = CurrentAuthArchiveRecoveryV2Host.Decode<CurrentAuthArchiveRecoveryV2Run>(CurrentAuthArchiveRecoveryV2Host.Read(runPath, 65536));
        CurrentAuthArchiveRecoveryV2Host.RequireRun(run, runPath);
        if (inputPath != run.Configuration.CaseInput.Path || expectedCase != run.Configuration.ExpectedCase ||
            Assembly.GetEntryAssembly()?.GetName().Name != "testhost" ||
            !StringComparer.OrdinalIgnoreCase.Equals(Assembly.GetEntryAssembly()?.Location, Path.Combine(run.InputRoot, "testhost.dll"))) { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
        CurrentAuthTypedHostJob.RequireWaitingChildMembership(run.Nonce);
        var request = CurrentAuthArchiveRecoveryV2Host.Request(run.Configuration);
        using var acceptedConsole = await CurrentAuthArchiveAcceptedConsoleBundle.HoldAsync(run.ConsoleImage, ct);
        using var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(run.InputRoot, ct);
        if (CurrentAuthTypedHostProducer.ImageHash(run.ConsoleImage) != request.Inputs.ConsoleImage.Sha256) { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
        ProcessStartInfo start = CurrentAuthArchiveRecoveryV2Host.Start(Path.GetDirectoryName(runPath)!);
        start.ArgumentList.Add(run.ConsoleImage); start.ArgumentList.Add(CurrentAuthArchiveRecoveryV2Host.ProviderCommand);
        start.ArgumentList.Add("--config"); start.ArgumentList.Add(runPath);
        using var process = new Process { StartInfo = start };
        using var expiry = CancellationTokenSource.CreateLinkedTokenSource(ct); expiry.CancelAfter(run.ExpiresAtUtc - DateTimeOffset.UtcNow);
        bool started = false, settled = false; DateTimeOffset began = DateTimeOffset.UtcNow, processStart = default;
        Task stdout = Task.CompletedTask, stderr = Task.CompletedTask;
        Exception? primary = null;
        CurrentAuthArchiveRecoveryResultV2? completed = null;
        try
        {
            acceptedConsole.Require();
            if (!process.Start()) { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
            started = true; processStart = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero); process.StandardInput.Close();
            stdout = CurrentAuthTypedHostProducer.DrainAsync(process.StandardOutput, expiry.Token);
            stderr = CurrentAuthTypedHostProducer.DrainAsync(process.StandardError, expiry.Token);
            await process.WaitForExitAsync(expiry.Token); await Task.WhenAll(stdout, stderr); settled = true;
            bundle.Require(); acceptedConsole.Require();
            byte[] resultBytes = CurrentAuthArchiveRecoveryV2Host.Read(CurrentAuthArchiveRecoveryV2Host.Prefix(runPath) + "-provider-result.json", 65536);
            var result = CurrentAuthArchiveRecoveryV2Host.Decode<CurrentAuthArchiveRecoveryV2ProviderResult>(resultBytes);
            if (result.SourceCommitSha != run.SourceCommitSha || result.InputSha256 != run.Configuration.CaseInput.Sha256 ||
                result.Case.Method.ReturnCode != process.ExitCode || result.Case.Method.ReturnCode != CurrentAuthArchiveRecoveryV2Host.ExpectedMethodCode(expectedCase) ||
                result.Case.Method.StartedAtUtc < run.BeganAtUtc || result.Case.Method.ReturnedAtUtc < result.Case.Method.StartedAtUtc ||
                result.Case.Method.ReturnedAtUtc > new DateTimeOffset(process.ExitTime.ToUniversalTime(), TimeSpan.Zero)) { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
            if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(result.Case.Candidate.Path), run.InputRoot)) { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
            byte[] candidateBytes = CurrentAuthArchiveRecoveryV2Host.Read(result.Case.Candidate.Path, 65536);
            if (CurrentAuthArchiveRecoveryV2Host.Hash(candidateBytes) != result.Case.Candidate.Sha256) { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
            using var candidate = JsonDocument.Parse(candidateBytes);
            if (candidate.RootElement.GetProperty("Kind").GetString() != "current-auth-genuine-recovery-candidate-v2" ||
                candidate.RootElement.GetProperty("Phase").GetString() != CurrentAuthArchiveRecoveryV2.Identity(expectedCase).Phase ||
                candidate.RootElement.GetProperty("ProviderProcessExitCode").ValueKind != JsonValueKind.Null ||
                candidate.RootElement.GetProperty("OperationId").GetGuid() != run.OperationId ||
                candidate.RootElement.GetProperty("CaseId").GetString() != CurrentAuthArchiveRecoveryV2.Identity(expectedCase).CaseId ||
                !candidate.RootElement.GetProperty("CleanupVerified").GetBoolean() || candidate.RootElement.GetProperty("PhaseProofComplete").GetBoolean()) { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
            completed = result.Case;
        }
        catch (Exception failure) { primary = failure; }
        Exception? cleanupFailure = null;
        try
        {
            if (started && !process.HasExited)
            {
                if (new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero) != processStart ||
                    !StringComparer.OrdinalIgnoreCase.Equals(process.MainModule?.FileName, CurrentAuthArchiveRecoveryV2Host.Tool("dotnet"))) { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
                process.Kill(); await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None);
            }
            if (started)
            {
                await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None); settled = stdout.IsCompletedSuccessfully && stderr.IsCompletedSuccessfully;
            }
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await CurrentAuthArchiveRecoveryV2Host.WriteAsync(CurrentAuthArchiveRecoveryV2Host.Prefix(runPath) + "-provider-process.json",
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    Kind = "current-auth-archive-recovery-actual-provider-process-v2",
                    run.OperationId,
                    run.Configuration.ExpectedCase,
                    Command = CurrentAuthArchiveRecoveryV2Host.ProviderCommand,
                    Executable = CurrentAuthArchiveRecoveryV2Host.Tool("dotnet"),
                    run.ConsoleImage,
                    ConsoleImageSha256 = CurrentAuthTypedHostProducer.ImageHash(run.ConsoleImage),
                    ExecutableSha256 = CurrentAuthTypedHostProducer.ImageHash(CurrentAuthArchiveRecoveryV2Host.Tool("dotnet")),
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
        return completed ?? throw CurrentAuthArchiveRecoveryV2Host.Invalid();
    }
}

public static partial class MigrationConsole
{
    private static async Task<int> RunCurrentAuthArchiveRecoveryV2ProviderAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        _ = output;
        try
        {
            var run = CurrentAuthArchiveRecoveryV2Host.Decode<CurrentAuthArchiveRecoveryV2Run>(CurrentAuthArchiveRecoveryV2Host.Read(configPath, 65536));
            CurrentAuthArchiveRecoveryV2Host.RequireRun(run, configPath);
            CurrentAuthTypedHostJob.RequireWaitingChildMembership(run.Nonce);
            if (typeof(MigrationConsole).Assembly.Location != run.ConsoleImage || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != run.SourceCommitSha)
            { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
            var request = CurrentAuthArchiveRecoveryV2Host.Request(run.Configuration);
            using var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(run.InputRoot, ct);
            using var loader = new CurrentAuthArchiveInitialProducer.FixedNativeBundle(request.Inputs.TestImage.Path);
            CurrentAuthArchiveRecoveryResultV2 result;
            try
            {
                Assembly tests = loader.LoadFromAssemblyPath(request.Inputs.TestImage.Path);
                MethodInfo method = tests.GetType("Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveRecoveryV2Runner", throwOnError: true)!
                    .GetMethod("ExecuteAsync", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.DeclaredOnly, binder: null,
                        types: [typeof(string), typeof(CurrentAuthArchiveRecoveryV2Case), typeof(CancellationToken)], modifiers: null)
                    ?? throw CurrentAuthArchiveRecoveryV2Host.Invalid();
                if (method.ReturnType != typeof(Task<CurrentAuthArchiveRecoveryResultV2>)) { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
                using var expiry = CancellationTokenSource.CreateLinkedTokenSource(ct); expiry.CancelAfter(run.ExpiresAtUtc - DateTimeOffset.UtcNow);
                bundle.Require();
                var pending = method.Invoke(null, [run.Configuration.CaseInput.Path, run.Configuration.ExpectedCase, expiry.Token]) as Task<CurrentAuthArchiveRecoveryResultV2>
                    ?? throw CurrentAuthArchiveRecoveryV2Host.Invalid();
                result = await pending; bundle.Require();
            }
            finally { loader.Unload(); }
            if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != run.SourceCommitSha ||
                result.Method.StartedAtUtc < run.BeganAtUtc || result.Method.ReturnedAtUtc > DateTimeOffset.UtcNow ||
                result.Method.ReturnedAtUtc < result.Method.StartedAtUtc ||
                result.Method.ReturnCode != CurrentAuthArchiveRecoveryV2Host.ExpectedMethodCode(run.Configuration.ExpectedCase)) { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
            await CurrentAuthArchiveRecoveryV2Host.WriteAsync(CurrentAuthArchiveRecoveryV2Host.Prefix(configPath) + "-provider-result.json",
                JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthArchiveRecoveryV2ProviderResult(result, run.SourceCommitSha, run.Configuration.CaseInput.Sha256)), ct);
            return result.Method.ReturnCode;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or InvalidOperationException or OperationCanceledException or TargetInvocationException or System.ComponentModel.Win32Exception)
        { await error.WriteLineAsync("archive_recovery_v2_provider_failed_before_completed_method_result"); return 1; }
    }

    private static async Task<int> RunCurrentAuthArchiveRecoveryV2SdkAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        _ = output;
        try
        {
            var run = CurrentAuthArchiveRecoveryV2Host.Decode<CurrentAuthArchiveRecoveryV2Run>(CurrentAuthArchiveRecoveryV2Host.Read(configPath, 65536));
            CurrentAuthArchiveRecoveryV2Host.RequireRun(run, configPath);
            if (typeof(MigrationConsole).Assembly.Location != run.ConsoleImage) { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct); wait.CancelAfter(TimeSpan.FromSeconds(30));
            string gatePath = CurrentAuthArchiveRecoveryV2Host.Prefix(configPath) + "-gate.json";
            byte[]? gateBytes = null;
            while (gateBytes is null)
            {
                wait.Token.ThrowIfCancellationRequested();
                try { if (File.Exists(gatePath)) { gateBytes = CurrentAuthArchiveRecoveryV2Host.Read(gatePath, 65536); } }
                catch (IOException) { /* The parent publishes with exclusive sharing until its durable write closes. */ }
                if (gateBytes is null) { await Task.Delay(50, wait.Token); }
            }
            var gate = CurrentAuthArchiveRecoveryV2Host.Decode<CurrentAuthArchiveRecoveryV2Gate>(gateBytes);
            using var self = Process.GetCurrentProcess();
            byte[] bindingBytes = CurrentAuthArchiveRecoveryV2Host.Read(run.Configuration.ControlBinding.Path, 65536);
            var binding = CurrentAuthArchiveRecoveryV2Host.Decode<LocalExecutionBinding>(bindingBytes);
            if (CurrentAuthArchiveRecoveryV2Host.Hash(bindingBytes) != run.Configuration.ControlBinding.Sha256 || gate.Nonce != run.Nonce ||
                gate.ControlBindingSha256 != binding.ComputeSha256() || gate.ProcessId != self.Id ||
                gate.ProcessStartTimeUtc != new DateTimeOffset(self.StartTime.ToUniversalTime(), TimeSpan.Zero)) { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
            CurrentAuthTypedHostJob.RequireWaitingChildMembership(run.Nonce);
            if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != run.SourceCommitSha) { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
            var request = CurrentAuthArchiveRecoveryV2Host.Request(run.Configuration);
            using var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(run.InputRoot, ct);
            ProcessStartInfo start = CurrentAuthArchiveRecoveryV2Host.Start(Path.GetDirectoryName(configPath)!);
            start.Environment[CurrentAuthArchiveRecoveryV2Host.RunVariable] = configPath;
            start.Environment[CurrentAuthArchiveRecoveryV2Host.InputVariable(run.Configuration.ExpectedCase)] = run.Configuration.CaseInput.Path;
            start.ArgumentList.Add("vstest"); start.ArgumentList.Add(request.Inputs.TestImage.Path);
            start.ArgumentList.Add("/TestCaseFilter:" + CurrentAuthArchiveRecoveryV2Host.Filter(run.Configuration.ExpectedCase));
            start.ArgumentList.Add("/Logger:trx;LogFileName=" + run.Nonce + ".trx");
            start.ArgumentList.Add("/ResultsDirectory:" + Path.GetDirectoryName(configPath));
            using var process = new Process { StartInfo = start };
            using var expiry = CancellationTokenSource.CreateLinkedTokenSource(ct); expiry.CancelAfter(run.ExpiresAtUtc - DateTimeOffset.UtcNow);
            if (!process.Start()) { throw CurrentAuthArchiveRecoveryV2Host.Invalid(); }
            process.StandardInput.Close();
            Task stdout = CurrentAuthTypedHostProducer.DrainAsync(process.StandardOutput, expiry.Token), stderr = CurrentAuthTypedHostProducer.DrainAsync(process.StandardError, expiry.Token);
            await process.WaitForExitAsync(expiry.Token); await Task.WhenAll(stdout, stderr); bundle.Require();
            await CurrentAuthArchiveRecoveryV2Host.WriteAsync(CurrentAuthArchiveRecoveryV2Host.Prefix(configPath) + "-vstest-process.json", JsonSerializer.SerializeToUtf8Bytes(new
            {
                Kind = "current-auth-archive-recovery-actual-vstest-process-v2",
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
        { await error.WriteLineAsync("archive_recovery_v2_sdk_failed_no_phase_proof"); return 1; }
    }

}
