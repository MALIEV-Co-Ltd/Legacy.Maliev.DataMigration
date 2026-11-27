using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal static class CurrentAuthArchiveFinal6CasePublication
{
    internal static async Task<CurrentAuthArchiveFinal6CaseResult> FinishAsync(CurrentAuthArchiveFinal6CaseContext context,
        CurrentAuthArchiveActualMethodV2 method, CurrentAuthArchiveGenuineArtifact effect, CancellationToken ct)
    {
        await context.RequireFactoryAsync(ct);
        var identity = CurrentAuthArchiveGeneratedCasesV2.Identity(context.Case);
        if (method.ReturnCode != identity.ExpectedProviderExitCode || method.StartedAtUtc != method.Artifacts.BeganAtUtc ||
            method.Artifacts.EndedAtUtc > method.ReturnedAtUtc || method.ReturnedAtUtc > DateTimeOffset.UtcNow ||
            context.CurrentEvidence.Capture.CompletedAtUtc > method.StartedAtUtc) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        var request = context.Request;
        byte[] bindingBytes = CurrentAuthArchiveHelperHost.Read(request.Inputs.ParentBinding.Path, 65536);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bindingBytes) != request.Inputs.ParentBinding.Sha256) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(bindingBytes);
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        byte[] effectBytes = files.Read(effect.Path, sharedReader: true, maximumBytes: 65536);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(effectBytes) != effect.Sha256) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        using var candidate = JsonDocument.Parse(effectBytes);
        var value = candidate.RootElement;
        if (value.GetProperty("OperationId").GetGuid() != context.OperationId || value.GetProperty("CaseId").GetString() != identity.CaseId ||
            !value.GetProperty("CleanupVerified").GetBoolean() || value.GetProperty("PhaseProofComplete").GetBoolean() ||
            value.GetProperty("ProviderProcessExitCode").ValueKind != JsonValueKind.Null) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        var methodArtifact = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveGenuineArtifact>(JsonSerializer.SerializeToUtf8Bytes(value.GetProperty("ProviderMethod")));
        byte[] retainedMethod = files.Read(methodArtifact.Path, sharedReader: true, maximumBytes: 65536);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(retainedMethod) != methodArtifact.Sha256 ||
            CurrentAuthLocalSessionArchivePolicy.Hash(MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveActualMethodV2>(retainedMethod)) != CurrentAuthLocalSessionArchivePolicy.Hash(method))
        { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        byte[] source = JsonSerializer.SerializeToUtf8Bytes(context.CurrentEvidence);
        string path = Path.Combine(binding.ArtifactRootCanonicalPath, "final6-current-source-" + context.OperationId.ToString("N") + ".json");
        await files.WriteNewAsync(path, source, ct);
        return new("current-auth-archive-final6-executed-case-v1", context.Case, context.OperationId, method, effect,
            new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(source)), context.Input.OriginalSourceCapture,
            context.Input.Audience, context.Input.Definition, context.Input.CaseBinding);
    }
}
