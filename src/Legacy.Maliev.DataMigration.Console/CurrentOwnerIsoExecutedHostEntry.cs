using System.Diagnostics;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record IsoActualHostEntry(Guid RunId, string CaseId, string JobNonce, bool NativeJobMembershipObserved,
    int ProcessId, DateTimeOffset ProcessStartTimeUtc, string ExecutablePath, string ExecutableSha256,
    string TestAssemblyPath, string TestAssemblySha256, DateTimeOffset ObservedAtUtc);
internal static class IsoExecutedHostEntry
{
    internal static IsoActualHostEntry Capture(Guid run, string caseId, string testAssembly)
    {
        string nonce = Environment.GetEnvironmentVariable("MALIEV_ISO_COMPONENT_JOB_NONCE") ?? throw CurrentOwnerIsoRepairPermit.Invalid();
        OwnerIsoGuardedBootstrapHostObservation.RequireCurrentMembership(nonce);
        using var process = Process.GetCurrentProcess(); string executable = Environment.ProcessPath ?? throw CurrentOwnerIsoRepairPermit.Invalid();
        using var image = SecureLocalFile.OpenReadShared(executable); using var test = SecureLocalFile.OpenReadShared(testAssembly);
        return new(run, caseId, nonce, true, process.Id, new DateTimeOffset(process.StartTime.ToUniversalTime()), executable,
            Convert.ToHexStringLower(SHA256.HashData(image)), testAssembly, Convert.ToHexStringLower(SHA256.HashData(test)), DateTimeOffset.UtcNow);
    }
}
