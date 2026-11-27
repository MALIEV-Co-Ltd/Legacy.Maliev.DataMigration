using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Fixed qualified-ALC execution-provider entry; SDK callers receive no database role or execution permit.
internal static class CurrentAuthArchiveRecoveryV2Runner
{
    internal static async Task<CurrentAuthArchiveRecoveryResultV2> ExecuteAsync(string inputPath,
        CurrentAuthArchiveRecoveryV2Case expectedCase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); _ = CurrentAuthArchiveRecoveryV2.CaseId(expectedCase);
        byte[] original = Read(inputPath);
        var packet = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveRecoveryV2Input>(original);
        CurrentAuthArchiveRecoveryV2InputContract.Require(packet, expectedCase);
        var request = packet.Request;
        string root = Path.GetDirectoryName(request.Inputs.ParentBinding.Path)!;
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(inputPath), root)) { throw Invalid(); }
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(Read(request.Inputs.ParentBinding.Path));
        using (var authority = WindowsLocalRunAuthority.AcquireResume(root, binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        { if (!files.Read(inputPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(original)) { throw Invalid(); } }
        var issuer = await CurrentAuthArchiveRecoveryV2Issuer.CreateAsync(packet, expectedCase, ct);
        CurrentAuthArchiveGenuineExecutionMethodResult method;
        Exception? primary = null;
        try
        {
            var capability = await CurrentAuthLocalSessionArchivePermit.GenuineRecoveryV2Capability.AuthenticateAsync(issuer, ct);
            method = await capability.ExecuteAsync(ct);
        }
        catch (Exception failure) { primary = failure; throw; }
        finally
        {
            try { await issuer.DisposeAsync(); }
            catch (Exception cleanup) when (primary is not null) { primary.Data["execution_cleanup_failure"] = cleanup.GetType().Name; }
        }
        var candidate = await PublishCompletedAsync(request, binding, expectedCase, method, ct);
        return new(new(method.ReturnCode, method.StartedAtUtc, method.ReturnedAtUtc, method.Artifacts), candidate);
    }

    internal static async Task<CurrentAuthArchiveGenuineArtifact> PublishCompletedAsync(CurrentAuthArchiveGenuineHostConfiguration request,
        LocalExecutionBinding binding, CurrentAuthArchiveRecoveryV2Case expectedCase, CurrentAuthArchiveGenuineExecutionMethodResult method, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var (Phase, CaseId) = CurrentAuthArchiveRecoveryV2.Identity(expectedCase);
        string root = Path.GetDirectoryName(request.Inputs.ParentBinding.Path)!;
        using var authority = WindowsLocalRunAuthority.AcquireResume(root, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        var result = method.Artifacts;
        byte[] stage = files.Read(result.IncompletePreCleanupStage.Path, maximumBytes: 65536);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(stage) != result.IncompletePreCleanupStage.Sha256) { throw Invalid(); }
        using var parsed = JsonDocument.Parse(stage); var value = parsed.RootElement;
        RequireCompletedMethod(value, expectedCase, method);
        Guid operation = value.GetProperty("OperationId").GetGuid();
        var scopeRef = value.GetProperty("Artifacts").GetProperty("scope");
        byte[] scopeBytes = files.Read(scopeRef.GetProperty("Path").GetString()!, maximumBytes: 1024 * 1024);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(scopeBytes) != scopeRef.GetProperty("Sha256").GetString()) { throw Invalid(); }
        var scope = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveScope>(scopeBytes);
        if (scope.OperationId != operation || scope.ComponentSubject?.Seed.CaseId != CaseId) { throw Invalid(); }
        var local = await RetainCleanupAsync(request.FirstFixtureParent, false, scope.ComponentSubject.Local, value.GetProperty("LocalPort").GetInt32());
        var comparison = await RetainCleanupAsync(request.SecondFixtureParent, true, scope.ComponentSubject.Comparison, value.GetProperty("ComparisonPort").GetInt32());
        var methodArtifact = await WriteAsync("provider-method", JsonSerializer.SerializeToUtf8Bytes(method));
        return await WriteAsync("candidate", JsonSerializer.SerializeToUtf8Bytes(new
        {
            Kind = "current-auth-genuine-recovery-candidate-v2",
            Phase,
            CaseId,
            OperationId = operation,
            result.IncompletePreCleanupStage,
            ProviderMethod = methodArtifact,
            LocalCleanup = local,
            ComparisonCleanup = comparison,
            PublishedAtUtc = DateTimeOffset.UtcNow,
            CleanupVerified = true,
            PhaseProofComplete = false,
            ProviderProcessExitCode = (int?)null,
        }));

        async Task<CurrentAuthArchiveGenuineArtifact> WriteAsync(string name, byte[] bytes)
        {
            string path = Path.Combine(root, $"genuine-recovery-v2-{operation:N}-{name}.json");
            await files.WriteNewAsync(path, bytes, ct);
            return !files.Read(path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)
                ? throw Invalid()
                : new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
        }
        async Task<CurrentAuthArchiveGenuineCleanupArtifacts> RetainCleanupAsync(string parent, bool isComparison,
            CurrentAuthArchiveComponentTargetSubject target, int port)
        {
            string fixture = Path.Combine(parent, "auth-archive-target-" + operation.ToString("N") + (isComparison ? "-comparison" : ""));
            byte[] fixtureBindingBytes = Read(Path.Combine(fixture, "fixture-binding.json"));
            var fixtureBinding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(fixtureBindingBytes);
            if (fixtureBinding.ComputeSha256() != target.RunBindingSha256) { throw Invalid(); }
            using var fixtureAuthority = WindowsLocalRunAuthority.AcquireResume(fixture, fixtureBinding);
            using var fixtureFiles = new CurrentAppOwnedRepairCustody(fixtureAuthority);
            string[] disposed = Directory.GetFiles(fixture, "*-disposed.json"), absent = Directory.GetFiles(fixture, "*-absent.json");
            if (disposed.Length != 1 || absent.Length != 1) { throw Invalid(); }
            byte[] disposal = fixtureFiles.Read(disposed[0], maximumBytes: 65536), absence = fixtureFiles.Read(absent[0], maximumBytes: 65536);
            CurrentAuthArchiveGenuineDualInputReader.RequireCleanupRecords(disposal, absence, operation, target, port);
            using var record = JsonDocument.Parse(disposal);
            if (record.RootElement.GetProperty("removedAtUtc").GetDateTimeOffset() < method.ReturnedAtUtc) { throw Invalid(); }
            string name = isComparison ? "comparison" : "local";
            return new(await WriteAsync(name + "-binding", fixtureBindingBytes), await WriteAsync(name + "-disposed", disposal), await WriteAsync(name + "-absent", absence));
        }
    }

    internal static void RequireCompletedMethod(JsonElement stage, CurrentAuthArchiveRecoveryV2Case expectedCase,
        CurrentAuthArchiveGenuineExecutionMethodResult method)
    {
        _ = CurrentAuthArchiveRecoveryV2.CaseId(expectedCase);
        var (Phase, CaseId) = CurrentAuthArchiveRecoveryV2.Identity(expectedCase);
        if (stage.GetProperty("Kind").GetString() != "current-auth-genuine-recovery-incomplete-precleanup-v2" ||
            stage.GetProperty("Phase").GetString() != Phase || stage.GetProperty("CaseId").GetString() != CaseId ||
            stage.GetProperty("CleanupVerified").GetBoolean() || stage.GetProperty("PhaseProofComplete").GetBoolean() ||
            stage.GetProperty("ProviderExitCode").ValueKind != JsonValueKind.Null ||
            method.ReturnCode != 0 || !stage.GetProperty("RestoreCompleted").GetBoolean() ||
            method.StartedAtUtc != method.Artifacts.BeganAtUtc || method.Artifacts.EndedAtUtc < method.StartedAtUtc ||
            method.ReturnedAtUtc < method.Artifacts.EndedAtUtc || method.ReturnedAtUtc > DateTimeOffset.UtcNow ||
            method.StartedAtUtc.Offset != TimeSpan.Zero || method.ReturnedAtUtc.Offset != TimeSpan.Zero ||
            stage.GetProperty("BeganAtUtc").GetDateTimeOffset() != method.StartedAtUtc || stage.GetProperty("EndedAtUtc").GetDateTimeOffset() != method.Artifacts.EndedAtUtc)
        { throw Invalid(); }
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
        return CurrentAuthArchiveRecoveryV2.Invalid();
    }
}
