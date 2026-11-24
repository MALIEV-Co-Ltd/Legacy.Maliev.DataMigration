using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal static class CurrentAuthArchiveGenuineDualInputReader
{
    internal static async Task RunAsync(string path, CancellationToken ct)
    {
        _ = await CurrentAuthArchiveGenuineRecoveryHelpersRunner.ExecuteAsync(path, CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback, ct);
    }

    internal static async Task<CurrentAuthArchiveGenuineArtifact> PublishCompletedAsync(CurrentAuthArchiveGenuineHostConfiguration request,
        LocalExecutionBinding binding, CurrentAuthArchiveGenuineRecoveryHelperCase helperCase, CurrentAuthArchiveGenuineProviderMethodResult method, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        string root = Path.GetDirectoryName(request.Inputs.ParentBinding.Path)!;
        var result = method.Artifacts;
        string caseId = CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(helperCase);
        bool dual = helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback;
        string prefix = dual ? "genuine-dual" : "genuine-recovery";
        // The live operation retained only explicitly incomplete staging. Final
        // publication happens below after both exact cleanup records are verified.
        using var finalAuthority = WindowsLocalRunAuthority.AcquireResume(root, binding);
        using var finalFiles = new CurrentAppOwnedRepairCustody(finalAuthority);
        byte[] stage = finalFiles.Read(result.IncompletePreCleanupStage.Path, maximumBytes: 65536);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(stage) != result.IncompletePreCleanupStage.Sha256) { throw Invalid(); }
        using var parsed = JsonDocument.Parse(stage);
        if (parsed.RootElement.GetProperty("Kind").GetString() != (dual ? "current-auth-genuine-dual-helper-incomplete-precleanup-v1" : "current-auth-genuine-recovery-helper-incomplete-precleanup-v1") ||
            parsed.RootElement.GetProperty("CaseId").GetString() != caseId ||
            parsed.RootElement.GetProperty("CleanupVerified").GetBoolean() ||
            parsed.RootElement.GetProperty("PhaseProofComplete").GetBoolean() ||
            parsed.RootElement.GetProperty("BeganAtUtc").GetDateTimeOffset() != result.BeganAtUtc ||
            parsed.RootElement.GetProperty("EndedAtUtc").GetDateTimeOffset() != result.EndedAtUtc || result.EndedAtUtc < result.BeganAtUtc ||
            method.StartedAtUtc != result.BeganAtUtc || method.ReturnedAtUtc < result.EndedAtUtc || method.ReturnedAtUtc > DateTimeOffset.UtcNow ||
            method.ReturnCode is not (0 or 1)) { throw Invalid(); }
        Guid operation = parsed.RootElement.GetProperty("OperationId").GetGuid();
        var scopeRef = parsed.RootElement.GetProperty("Artifacts").GetProperty("scope");
        byte[] scopeBytes = finalFiles.Read(scopeRef.GetProperty("Path").GetString()!, maximumBytes: 1024 * 1024);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(scopeBytes) != scopeRef.GetProperty("Sha256").GetString()) { throw Invalid(); }
        var scope = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveScope>(scopeBytes);
        if (scope.OperationId != operation || scope.ComponentSubject is null || scope.ComponentSubject.Seed.CaseId != caseId) { throw Invalid(); }
        var localCleanup = await RetainCleanupAsync(request.FirstFixtureParent, comparison: false,
            scope.ComponentSubject.Local, parsed.RootElement.GetProperty("LocalPort").GetInt32());
        var comparisonCleanup = await RetainCleanupAsync(request.SecondFixtureParent, comparison: true,
            scope.ComponentSubject.Comparison, parsed.RootElement.GetProperty("ComparisonPort").GetInt32());
        byte[] methodBytes = JsonSerializer.SerializeToUtf8Bytes(method);
        string methodPath = Path.Combine(root, $"{prefix}-{operation:N}-provider-method.json");
        await finalFiles.WriteNewAsync(methodPath, methodBytes, ct);
        if (!finalFiles.Read(methodPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(methodBytes)) { throw Invalid(); }
        var methodArtifact = new CurrentAuthArchiveGenuineArtifact(methodPath, CurrentAuthLocalSessionArchivePolicy.HashBytes(methodBytes));
        byte[] candidate = JsonSerializer.SerializeToUtf8Bytes(new
        {
            Kind = dual ? "current-auth-genuine-dual-helper-candidate-v1" : "current-auth-genuine-recovery-helper-candidate-v1",
            CaseId = caseId,
            OperationId = operation,
            result.BeganAtUtc,
            result.EndedAtUtc,
            result.IncompletePreCleanupStage,
            ProviderMethod = methodArtifact,
            ProviderProcessExitCode = (int?)null,
            LocalCleanup = localCleanup,
            ComparisonCleanup = comparisonCleanup,
            PublishedAtUtc = DateTimeOffset.UtcNow,
            CleanupVerified = true,
            PhaseProofComplete = false,
        });
        string finalPath = Path.Combine(root, $"{prefix}-{operation:N}-candidate.json");
        await finalFiles.WriteNewAsync(finalPath, candidate, ct);
        return !finalFiles.Read(finalPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(candidate)
            ? throw Invalid()
            : new(finalPath, CurrentAuthLocalSessionArchivePolicy.HashBytes(candidate));

        async Task<CurrentAuthArchiveGenuineCleanupArtifacts> RetainCleanupAsync(string parent, bool comparison,
            CurrentAuthArchiveComponentTargetSubject target, int port)
        {
            string fixtureRoot = Path.Combine(parent, "auth-archive-target-" + operation.ToString("N") + (comparison ? "-comparison" : ""));
            byte[] bindingBytes = ReadProtected(Path.Combine(fixtureRoot, "fixture-binding.json"));
            var fixtureBinding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(bindingBytes);
            if (fixtureBinding.ComputeSha256() != target.RunBindingSha256) { throw Invalid(); }
            using var authority = WindowsLocalRunAuthority.AcquireResume(fixtureRoot, fixtureBinding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            string[] disposed = Directory.GetFiles(fixtureRoot, "*-disposed.json"), absent = Directory.GetFiles(fixtureRoot, "*-absent.json");
            if (disposed.Length != 1 || absent.Length != 1) { throw Invalid(); }
            byte[] disposal = files.Read(disposed[0], maximumBytes: 65536), absence = files.Read(absent[0], maximumBytes: 65536);
            RequireCleanupRecords(disposal, absence, operation, target, port);
            using var completed = JsonDocument.Parse(disposal);
            if (completed.RootElement.GetProperty("removedAtUtc").GetDateTimeOffset() < method.ReturnedAtUtc) { throw Invalid(); }
            string cleanupPrefix = Path.Combine(root, $"{prefix}-{operation:N}-{(comparison ? "comparison" : "local")}");
            await finalFiles.WriteNewAsync(cleanupPrefix + "-binding.json", bindingBytes, ct);
            await finalFiles.WriteNewAsync(cleanupPrefix + "-disposed.json", disposal, ct);
            await finalFiles.WriteNewAsync(cleanupPrefix + "-absent.json", absence, ct);
            if (!finalFiles.Read(cleanupPrefix + "-disposed.json", sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(disposal) ||
                !finalFiles.Read(cleanupPrefix + "-absent.json", sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(absence)) { throw Invalid(); }
            return !finalFiles.Read(cleanupPrefix + "-binding.json", sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bindingBytes)
                ? throw Invalid()
                : new(new(cleanupPrefix + "-binding.json", CurrentAuthLocalSessionArchivePolicy.HashBytes(bindingBytes)),
                new(cleanupPrefix + "-disposed.json", CurrentAuthLocalSessionArchivePolicy.HashBytes(disposal)),
                new(cleanupPrefix + "-absent.json", CurrentAuthLocalSessionArchivePolicy.HashBytes(absence)));
        }
    }

    internal static void RequireCleanupRecords(byte[] disposal, byte[] absence, Guid operation,
        CurrentAuthArchiveComponentTargetSubject target, int port)
    {
        using var disposed = JsonDocument.Parse(disposal); using var absent = JsonDocument.Parse(absence);
        JsonElement d = disposed.RootElement, a = absent.RootElement;
        if (port is < 1 or > 65535 || d.GetProperty("Operation").GetGuid() != operation || a.GetProperty("Operation").GetGuid() != operation ||
            d.GetProperty("_id").GetString() != target.ContainerId || a.GetProperty("_id").GetString() != target.ContainerId ||
            d.GetProperty("volume").GetString() != target.VolumeName || a.GetProperty("volume").GetString() != target.VolumeName ||
            d.GetProperty("cleanupFailed").GetBoolean() || !d.GetProperty("verifiedAbsence").GetBoolean() ||
            !d.GetProperty("removed").GetBoolean() || !d.GetProperty("sdkDisposed").GetBoolean() || a.GetProperty("observedPort").GetInt32() != port ||
            a.GetProperty("containerIds").EnumerateArray().Any(x => x.GetString() == target.ContainerId) ||
            a.GetProperty("containerNames").EnumerateArray().Any(x => x.GetString()?.TrimStart('/') == target.ContainerName.TrimStart('/')) ||
            a.GetProperty("volumeNames").EnumerateArray().Any(x => x.GetString() == target.VolumeName) ||
            a.GetProperty("listeningPorts").EnumerateArray().Any(x => x.GetInt32() == port) ||
            a.GetProperty("observedAtUtc").GetDateTimeOffset() < d.GetProperty("removedAtUtc").GetDateTimeOffset() ||
            d.GetProperty("completedAtUtc").GetDateTimeOffset() < a.GetProperty("observedAtUtc").GetDateTimeOffset()) { throw Invalid(); }
    }

    private static byte[] ReadProtected(string path)
    {
        if (!Path.IsPathFullyQualified(path)) { throw Invalid(); }
        using var held = SecureLocalFile.OpenReadShared(path);
        if (held.Length is < 1 or > 65536 || !SecureLocalFile.HandleResolvesToApprovedPath(held, path)) { throw Invalid(); }
        byte[] bytes = new byte[checked((int)held.Length)]; held.ReadExactly(bytes); return bytes;
    }

    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveGenuineHost.Invalid("dual_helper_retention");
    }
}
