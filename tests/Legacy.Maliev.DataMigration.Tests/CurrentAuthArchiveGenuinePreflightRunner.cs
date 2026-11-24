using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Qualified Tests entry from a clean accepted Console process only. This does not activate an SDK/database role.
internal static class CurrentAuthArchiveGenuinePreflightRunner
{
    internal static async Task<CurrentAuthArchiveGenuinePreflightResult> ExecuteAsync(string inputPath,
        CurrentAuthArchiveGenuinePreflightCase expected, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); _ = CurrentAuthArchiveGenuinePreflight.CaseId(expected);
        byte[] original = Read(inputPath);
        var packet = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveGenuinePreflightInput>(original);
        CurrentAuthArchiveGenuinePreflightInputContract.Require(packet, expected);
        var request = packet.Request; string root = Path.GetDirectoryName(request.Inputs.ParentBinding.Path)!;
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(inputPath), root)) { throw Invalid(); }
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(Read(request.Inputs.ParentBinding.Path));
        using (var authority = WindowsLocalRunAuthority.AcquireResume(root, binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        { if (!files.Read(inputPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(original)) { throw Invalid(); } }
        // This concrete factory authenticates the original seed/source/owner and image before any target exists.
        var pair = await CurrentAuthArchiveGenuineOwnedPair.CreatePreflightAsync(request, expected, ct);
        CurrentAuthArchiveGenuinePreflightMethodResult method; Exception? primary = null;
        try { method = await pair.RunPreflightAsync(ct); }
        catch (Exception failure) { primary = failure; throw; }
        finally
        {
            try { await pair.DisposeAsync(); }
            catch (Exception cleanup) when (primary is not null) { primary.Data["preflight_pair_cleanup_failure"] = cleanup.GetType().Name; }
        }
        return new(method, await PublishAsync(request, binding, expected, method, ct));
    }

    private static async Task<CurrentAuthArchiveGenuineArtifact> PublishAsync(CurrentAuthArchiveGenuineHostConfiguration request,
        LocalExecutionBinding binding, CurrentAuthArchiveGenuinePreflightCase expected,
        CurrentAuthArchiveGenuinePreflightMethodResult method, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        string caseId = CurrentAuthArchiveGenuinePreflight.CaseId(expected), root = Path.GetDirectoryName(request.Inputs.ParentBinding.Path)!;
        using var authority = WindowsLocalRunAuthority.AcquireResume(root, binding); using var files = new CurrentAppOwnedRepairCustody(authority);
        var stageRef = method.Artifacts.IncompletePreCleanupStage; byte[] stage = files.Read(stageRef.Path, maximumBytes: 65536);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(stage) != stageRef.Sha256) { throw Invalid(); }
        using var parsed = JsonDocument.Parse(stage); var value = parsed.RootElement;
        RequireMethod(value, expected, method, DateTimeOffset.UtcNow);
        Guid operation = value.GetProperty("OperationId").GetGuid(); var scopeRef = value.GetProperty("Artifacts").GetProperty("scope");
        byte[] scopeBytes = files.Read(scopeRef.GetProperty("Path").GetString()!, maximumBytes: 1024 * 1024);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(scopeBytes) != scopeRef.GetProperty("Sha256").GetString()) { throw Invalid(); }
        var scope = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveScope>(scopeBytes);
        if (scope.OperationId != operation || scope.ComponentSubject?.Seed.CaseId != caseId || scope.ProofAdmission != CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap) { throw Invalid(); }
        var local = await CleanupAsync(request.FirstFixtureParent, false, scope.ComponentSubject.Local, value.GetProperty("LocalPort").GetInt32());
        var comparison = await CleanupAsync(request.SecondFixtureParent, true, scope.ComponentSubject.Comparison, value.GetProperty("ComparisonPort").GetInt32());
        var methodRef = await WriteAsync("provider-method", JsonSerializer.SerializeToUtf8Bytes(method));
        return await WriteAsync("candidate", JsonSerializer.SerializeToUtf8Bytes(new
        {
            Kind = "current-auth-genuine-policy-preflight-candidate-v1",
            Phase = "native",
            CaseId = caseId,
            OperationId = operation,
            IncompletePreCleanupStage = stageRef,
            ProviderMethod = methodRef,
            LocalCleanup = local,
            ComparisonCleanup = comparison,
            PublishedAtUtc = DateTimeOffset.UtcNow,
            CleanupVerified = true,
            PhaseProofComplete = false,
            ProviderProcessExitCode = (int?)null,
        }));

        async Task<CurrentAuthArchiveGenuineArtifact> WriteAsync(string name, byte[] bytes)
        {
            string path = Path.Combine(root, $"genuine-preflight-{operation:N}-{name}.json"); await files.WriteNewAsync(path, bytes, ct);
            return !files.Read(path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)
                ? throw Invalid()
                : new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
        }
        async Task<CurrentAuthArchiveGenuineCleanupArtifacts> CleanupAsync(string parent, bool comparisonSide,
            CurrentAuthArchiveComponentTargetSubject target, int port)
        {
            string fixture = Path.Combine(parent, "auth-archive-target-" + operation.ToString("N") + (comparisonSide ? "-comparison" : ""));
            byte[] bindingBytes = Read(Path.Combine(fixture, "fixture-binding.json"));
            var targetBinding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(bindingBytes);
            if (targetBinding.ComputeSha256() != target.RunBindingSha256) { throw Invalid(); }
            using var targetAuthority = WindowsLocalRunAuthority.AcquireResume(fixture, targetBinding); using var targetFiles = new CurrentAppOwnedRepairCustody(targetAuthority);
            string[] disposed = Directory.GetFiles(fixture, "*-disposed.json"), absent = Directory.GetFiles(fixture, "*-absent.json");
            if (disposed.Length != 1 || absent.Length != 1) { throw Invalid(); }
            byte[] disposal = targetFiles.Read(disposed[0], maximumBytes: 65536), absence = targetFiles.Read(absent[0], maximumBytes: 65536);
            CurrentAuthArchiveGenuineDualInputReader.RequireCleanupRecords(disposal, absence, operation, target, port);
            using var record = JsonDocument.Parse(disposal);
            if (record.RootElement.GetProperty("removedAtUtc").GetDateTimeOffset() < method.ReturnedAtUtc) { throw Invalid(); }
            string prefix = comparisonSide ? "comparison" : "local";
            return new(await WriteAsync(prefix + "-binding", bindingBytes), await WriteAsync(prefix + "-disposed", disposal), await WriteAsync(prefix + "-absent", absence));
        }
    }
    internal static void RequireMethod(JsonElement stage, CurrentAuthArchiveGenuinePreflightCase expected,
        CurrentAuthArchiveGenuinePreflightMethodResult method, DateTimeOffset now)
    {
        if (stage.GetProperty("Kind").GetString() != "current-auth-genuine-preflight-incomplete-precleanup-v1" ||
            stage.GetProperty("Phase").GetString() != "native" || stage.GetProperty("CaseId").GetString() != CurrentAuthArchiveGenuinePreflight.CaseId(expected) ||
            stage.GetProperty("ActualBoundary").GetString() != "before-issuer-mint" || stage.GetProperty("CleanupVerified").GetBoolean() ||
            stage.GetProperty("PhaseProofComplete").GetBoolean() || stage.GetProperty("ProviderExitCode").ValueKind != JsonValueKind.Null ||
            method.ReturnCode != 1 || method.StartedAtUtc != method.Artifacts.BeganAtUtc || method.Artifacts.EndedAtUtc < method.StartedAtUtc ||
            method.ReturnedAtUtc < method.Artifacts.EndedAtUtc || method.ReturnedAtUtc > now || method.StartedAtUtc.Offset != TimeSpan.Zero || method.ReturnedAtUtc.Offset != TimeSpan.Zero ||
            stage.GetProperty("BeganAtUtc").GetDateTimeOffset() != method.StartedAtUtc || stage.GetProperty("EndedAtUtc").GetDateTimeOffset() != method.Artifacts.EndedAtUtc) { throw Invalid(); }
    }
    private static byte[] Read(string path)
    {
        if (!Path.IsPathFullyQualified(path) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path))) { throw Invalid(); }
        using var held = SecureLocalFile.OpenReadShared(path);
        if (held.Length is < 1 or > 65536 || !SecureLocalFile.HandleResolvesToApprovedPath(held, path)) { throw Invalid(); }
        byte[] bytes = new byte[checked((int)held.Length)]; held.ReadExactly(bytes); return bytes;
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveGenuinePreflight.Invalid();
    }
}
