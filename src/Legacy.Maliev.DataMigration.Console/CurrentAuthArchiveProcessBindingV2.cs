using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

// Data validation only. Successful validation does not mint process, target or execution authority.
internal static class CurrentAuthArchiveProcessBindingV2
{
    internal static void Require(JsonElement run, JsonElement provider, JsonElement vstest, JsonElement host, JsonElement cleanup,
        JsonElement result, JsonElement gate, Guid operation, string source, string input, string runHash, string controlBindingSha256,
        DateTimeOffset began, DateTimeOffset completed)
    {
        string nonce = run.GetProperty("Nonce").GetString() ?? throw Invalid();
        DateTimeOffset expires = run.GetProperty("ExpiresAtUtc").GetDateTimeOffset();
        if (!Guid.TryParseExact(nonce, "N", out _) || run.GetProperty("OperationId").GetGuid() != operation ||
            run.GetProperty("SourceCommitSha").GetString() != source || run.GetProperty("BeganAtUtc").GetDateTimeOffset() < began ||
            run.GetProperty("BeganAtUtc").GetDateTimeOffset() >= expires || completed > expires.AddMinutes(1) ||
            result.GetProperty("SourceCommitSha").GetString() != source || result.GetProperty("InputSha256").GetString() != input) { throw Invalid(); }
        foreach (var frame in new[] { provider, vstest, host, cleanup })
        {
            if (frame.GetProperty("OperationId").GetGuid() != operation || frame.GetProperty("SourceCommitSha").GetString() != source ||
                frame.GetProperty("RunSha256").GetString() != runHash) { throw Invalid(); }
        }
        foreach (var frame in new[] { provider, vstest })
        {
            if (frame.GetProperty("Nonce").GetString() != nonce || frame.GetProperty("RequiredJobNonce").GetString() != nonce ||
                frame.GetProperty("CaseInputSha256").GetString() != input) { throw Invalid(); }
        }
        if (host.GetProperty("Nonce").GetString() != nonce || host.GetProperty("ExitCode").GetInt32() != 0 ||
            host.GetProperty("CleanupFailed").GetBoolean() || cleanup.GetProperty("CleanupFailed").GetBoolean() ||
            cleanup.GetProperty("PreservedUncertainResources").GetBoolean() || cleanup.GetProperty("PhaseProofComplete").GetBoolean() ||
            cleanup.GetProperty("ExpiresAtUtc").GetDateTimeOffset() != expires ||
            cleanup.GetProperty("ObservedAtUtc").GetDateTimeOffset() < host.GetProperty("ExitedAtUtc").GetDateTimeOffset() ||
            cleanup.GetProperty("ObservedAtUtc").GetDateTimeOffset() > completed) { throw Invalid(); }
        int sdkId = host.GetProperty("ProcessId").GetInt32();
        DateTimeOffset sdkStart = host.GetProperty("ProcessStartTimeUtc").GetDateTimeOffset();
        if (gate.GetProperty("Nonce").GetString() != nonce || gate.GetProperty("ProcessId").GetInt32() != sdkId ||
            gate.GetProperty("ProcessStartTimeUtc").GetDateTimeOffset() != sdkStart ||
            gate.GetProperty("ControlBindingSha256").GetString() != controlBindingSha256 ||
            vstest.GetProperty("SdkProcessId").GetInt32() != sdkId || vstest.GetProperty("SdkProcessStartTimeUtc").GetDateTimeOffset() != sdkStart) { throw Invalid(); }
        DateTimeOffset vstestStart = vstest.GetProperty("ProcessStartTimeUtc").GetDateTimeOffset();
        DateTimeOffset vstestExit = vstest.GetProperty("ExitedAtUtc").GetDateTimeOffset();
        DateTimeOffset providerStart = provider.GetProperty("ProcessStartTimeUtc").GetDateTimeOffset();
        DateTimeOffset providerExit = provider.GetProperty("ExitedAtUtc").GetDateTimeOffset();
        DateTimeOffset harnessStart = provider.GetProperty("HarnessProcessStartTimeUtc").GetDateTimeOffset();
        int[] ids = [sdkId, vstest.GetProperty("ProcessId").GetInt32(), provider.GetProperty("HarnessProcessId").GetInt32(), provider.GetProperty("ProcessId").GetInt32()];
        if (ids.Any(id => id <= 0) || ids.Distinct().Count() != ids.Length || sdkStart < began ||
            vstestStart < sdkStart || harnessStart < vstestStart || providerStart < harnessStart || providerExit < providerStart ||
            providerExit > vstestExit || vstestExit > host.GetProperty("ExitedAtUtc").GetDateTimeOffset() ||
            host.GetProperty("ExitedAtUtc").GetDateTimeOffset() > completed ||
            provider.GetProperty("StartedAtUtc").GetDateTimeOffset() < vstestStart) { throw Invalid(); }
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveRecoveryV2.Invalid();
    }
}
