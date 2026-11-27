using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveGeneratedCaseRunV2(string Kind, CurrentAuthArchiveGeneratedCaseV2 Generated,
    DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, int ActualHostReturnCode,
    CurrentAuthArchiveProofArtifact Run, CurrentAuthArchiveProofArtifact ProviderResult, CurrentAuthArchiveProofArtifact ProviderProcess,
    CurrentAuthArchiveProofArtifact VstestProcess, CurrentAuthArchiveProofArtifact Trx, CurrentAuthArchiveProofArtifact HostExit,
    CurrentAuthArchiveProofArtifact ResourceCleanup, bool PhaseProofComplete);

public static partial class MigrationConsole
{
    internal static async Task<CurrentAuthArchiveGeneratedCaseRunV2> RunCurrentAuthArchiveGeneratedCaseV2Async(
        CurrentAuthArchiveGeneratedCaseV2 generated, CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, CancellationToken ct)
    {
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
        var identity = CurrentAuthArchiveGeneratedCasesV2.Identity(generated.Case);
        var bindingClaim = DecodeAuthRepair<CurrentAuthArchiveClaim>(ReadGenerated(generated.BindingClaim, 65536));
        var binding = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveGeneratedBindingV2>(bindingClaim,
            CurrentAuthArchiveGeneratedCasesV2.BindingDomain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        var audienceClaim = DecodeAuthRepair<CurrentAuthArchiveClaim>(ReadGenerated(generated.Audience, 65536));
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveProofAudienceV2>(audienceClaim,
            CurrentAuthArchiveRecoveryV2.AudienceDomain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        var seed = DecodeAuthRepair<CurrentAuthArchiveComponentBootstrapSeed>(ReadGenerated(generated.Seed, 65536));
        var source = DecodeAuthRepair<CurrentAuthArchiveRecoverySourceEvidence>(ReadGenerated(generated.SourceCapture, 32 * 1024 * 1024));
        DateTimeOffset began = DateTimeOffset.UtcNow;
        CurrentAuthArchiveRecoveryV2.RequireSource(source, accepted, audience.SourceIdentitySha256, audience.SourceDefinitionSha256, began);
        CurrentAuthArchiveRecoveryV2.RequireAudience(audience, seed, pins, began);
        if (binding.Kind != "current-auth-archive-generated-case-binding-v2" || binding.AudienceSha256 != generated.Audience.Sha256 ||
            binding.Phase != identity.Phase || binding.CaseId != identity.CaseId || binding.OperationId != generated.OperationId ||
            binding.OperationId != seed.OperationId || binding.SeedSha256 != generated.Seed.Sha256 || seed.CaseId != identity.CaseId ||
            binding.SourceFullSha256 != source.FullPlanSha256 || seed.SourceSchemaPlanSha256 != source.FullPlanSha256 ||
            binding.SourceIdentitySha256 != source.SourceIdentitySha256 || binding.SourceDefinitionSha256 != source.DefinitionSha256 ||
            binding.DefinitionPrecursorSha256 != generated.Definition.Definition.Sha256 || seed.DefinitionPrecursorSha256 != binding.DefinitionPrecursorSha256 ||
            binding.InputSha256 != generated.Input.Sha256 || binding.HostConfigurationSha256 != generated.HostConfiguration.Sha256 ||
            binding.IntendedObservationSha256 != generated.IntendedObservation.Sha256 ||
            binding.PreDefinitionIntendedObservationSha256 != generated.PreDefinitionIntendedObservation.Sha256 ||
            binding.IssuedAtUtc.Offset != TimeSpan.Zero || binding.ExpiresAtUtc.Offset != TimeSpan.Zero || binding.IssuedAtUtc > began ||
            binding.ExpiresAtUtc <= began || binding.ExpiresAtUtc > seed.ExpiresAtUtc) { throw InvalidGenerated(); }
        _ = ReadGenerated(generated.Input, 65536);
        using var hostConfiguration = JsonDocument.Parse(ReadGenerated(generated.HostConfiguration, 65536));
        if (hostConfiguration.RootElement.GetProperty("CaseInput").GetProperty("Path").GetString() != generated.Input.Path ||
            hostConfiguration.RootElement.GetProperty("CaseInput").GetProperty("Sha256").GetString() != generated.Input.Sha256) { throw InvalidGenerated(); }
        var intended = DecodeAuthRepair<CurrentAuthArchiveIntendedRetainedEvidenceV2>(ReadGenerated(generated.IntendedObservation, 1024 * 1024));
        if (intended.Kind != "current-auth-archive-intended-after-c-observation-v2" || intended.SourceFullSha256 != source.FullPlanSha256 ||
            intended.LocalIdentitySha256 != audience.IntendedLocalIdentitySha256 || intended.ComparisonIdentitySha256 != audience.IntendedComparisonIdentitySha256 ||
            intended.LocalAuthRowsSha256 != audience.IntendedAuthRowsSha256 || intended.LocalAuthRows != audience.IntendedAuthRows ||
            intended.BeganAtUtc > intended.CompletedAtUtc || intended.CompletedAtUtc > binding.IssuedAtUtc || began - intended.CompletedAtUtc > TimeSpan.FromMinutes(2))
        { throw InvalidGenerated(); }
        // Atomic create-new reservation before invoking any provider prevents replay of this generated case.
        string controlRoot = Path.GetDirectoryName(generated.HostConfiguration.Path)!;
        byte[] controlBytes = CurrentAuthArchiveHelperHost.Read(Path.Combine(controlRoot, "fixture-binding.json"), 65536);
        var controlBinding = DecodeAuthRepair<LocalExecutionBinding>(controlBytes);
        if (hostConfiguration.RootElement.GetProperty("ControlBinding").GetProperty("Path").GetString() != Path.Combine(controlRoot, "fixture-binding.json") ||
            hostConfiguration.RootElement.GetProperty("ControlBinding").GetProperty("Sha256").GetString() != CurrentAuthLocalSessionArchivePolicy.HashBytes(controlBytes))
        { throw InvalidGenerated(); }
        using (var authority = WindowsLocalRunAuthority.AcquireResume(controlRoot, controlBinding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            await files.WriteNewAsync(Path.Combine(controlRoot, "generated-case-reservation.json"), JsonSerializer.SerializeToUtf8Bytes(new
            { generated.OperationId, BindingSha256 = generated.BindingClaim.Sha256, InputSha256 = generated.Input.Sha256, BeganAtUtc = began }), ct);
        }
        using var output = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
        using var error = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
        int actual = identity.Phase == "helper"
            ? await RunCurrentAuthArchiveHelperHostAsync(generated.HostConfiguration.Path, output, error, ct)
            : generated.Case is CurrentAuthArchiveProofCaseV2.HostUnprobed or CurrentAuthArchiveProofCaseV2.LocalTrust
            ? await RunCurrentAuthArchivePreflightHostAsync(generated.HostConfiguration.Path, output, error, ct)
            : identity.Phase == "recovery"
            ? await RunCurrentAuthArchiveRecoveryV2HostAsync(generated.HostConfiguration.Path, output, error, ct)
            : await RunCurrentAuthArchiveExecutionHostAsync(generated.HostConfiguration.Path, output, error, ct);
        DateTimeOffset completed = DateTimeOffset.UtcNow;
        using var resultAuthority = WindowsLocalRunAuthority.AcquireResume(controlRoot, controlBinding);
        using var resultFiles = new CurrentAppOwnedRepairCustody(resultAuthority);
        await resultFiles.WriteNewAsync(Path.Combine(controlRoot, "generated-case-actual-host-return.json"), JsonSerializer.SerializeToUtf8Bytes(new
        { generated.OperationId, BeganAtUtc = began, CompletedAtUtc = completed, ActualReturnCode = actual, PhaseProofComplete = false }), ct);
        if (actual != 0) { throw InvalidGenerated(); }
        string family = identity.Phase == "helper" ? "helper" : identity.Phase == "recovery" ? "recovery-v2" :
            generated.Case is CurrentAuthArchiveProofCaseV2.HostUnprobed or CurrentAuthArchiveProofCaseV2.LocalTrust ? "preflight" : "execution";
        string filePrefix = "archive-" + family + "-";
        string runPath = Directory.EnumerateFiles(controlRoot, filePrefix + "*.json", SearchOption.TopDirectoryOnly).Single(path =>
            Path.GetFileName(path).Length == filePrefix.Length + 32 + 5 && Guid.TryParseExact(Path.GetFileNameWithoutExtension(path)[filePrefix.Length..], "N", out _));
        string prefix = Path.Combine(controlRoot, Path.GetFileNameWithoutExtension(runPath));
        using var run = JsonDocument.Parse(resultFiles.Read(runPath, sharedReader: true, maximumBytes: 65536));
        string nonce = run.RootElement.GetProperty("Nonce").GetString()!;
        if (run.RootElement.GetProperty("OperationId").GetGuid() != generated.OperationId || run.RootElement.GetProperty("SourceCommitSha").GetString() != accepted ||
            run.RootElement.GetProperty("Configuration").GetProperty("CaseInput").GetProperty("Sha256").GetString() != generated.Input.Sha256) { throw InvalidGenerated(); }
        var result = new CurrentAuthArchiveGeneratedCaseRunV2("current-auth-archive-generated-actual-case-run-v2", generated, began, completed, actual,
            Artifact(runPath, 65536), Artifact(prefix + "-provider-result.json", 65536), Artifact(prefix + "-provider-process.json", 65536),
            Artifact(prefix + "-vstest-process.json", 65536), Artifact(Path.Combine(controlRoot, nonce + ".trx"), 8 * 1024 * 1024),
            Artifact(prefix + "-host-exit.json", 65536), Artifact(prefix + "-resource-cleanup.json", 2 * 1024 * 1024), false);
        RequireActualGeneratedProcesses(result, identity, ct);
        await resultFiles.WriteNewAsync(Path.Combine(controlRoot, "generated-case-actual-run.json"), JsonSerializer.SerializeToUtf8Bytes(result), ct);
        return result;
        CurrentAuthArchiveProofArtifact Artifact(string path, int maximum)
        {
            return new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(
            resultFiles.Read(path, sharedReader: true, maximumBytes: maximum)));
        }
    }

    internal static void RequireActualGeneratedProcesses(CurrentAuthArchiveGeneratedCaseRunV2 value, CurrentAuthArchiveGenuineCase identity, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var provider = JsonDocument.Parse(ReadGenerated(value.ProviderProcess, 65536));
        using var vstest = JsonDocument.Parse(ReadGenerated(value.VstestProcess, 65536));
        using var host = JsonDocument.Parse(ReadGenerated(value.HostExit, 65536));
        using var cleanup = JsonDocument.Parse(ReadGenerated(value.ResourceCleanup, 2 * 1024 * 1024));
        using var result = JsonDocument.Parse(ReadGenerated(value.ProviderResult, 65536));
        JsonElement method = result.RootElement.GetProperty("Case").GetProperty("Method");
        int actualMethodCode = method.GetProperty("ReturnCode").GetInt32();
        string dotnet = CurrentAuthArchiveHelperHost.Tool("dotnet");
        var seed = DecodeAuthRepair<CurrentAuthArchiveComponentBootstrapSeed>(ReadGenerated(value.Generated.Seed, 65536));
        if (value.Kind != "current-auth-archive-generated-actual-case-run-v2" || value.PhaseProofComplete || value.ActualHostReturnCode != 0 ||
            provider.RootElement.GetProperty("OperationId").GetGuid() != value.Generated.OperationId ||
            provider.RootElement.GetProperty("Executable").GetString() != dotnet ||
            provider.RootElement.GetProperty("ExecutableSha256").GetString() != CurrentAuthTypedHostProducer.ImageHash(dotnet) ||
            provider.RootElement.GetProperty("ConsoleImageSha256").GetString() != seed.ConsoleAssemblySha256 ||
            provider.RootElement.GetProperty("ConsoleImageSha256").GetString() != CurrentAuthTypedHostProducer.ImageHash(typeof(MigrationConsole).Assembly.Location) ||
            provider.RootElement.GetProperty("ProcessStartTimeUtc").GetDateTimeOffset() > method.GetProperty("StartedAtUtc").GetDateTimeOffset() ||
            actualMethodCode != identity.ExpectedProviderExitCode || provider.RootElement.GetProperty("ExitCode").GetInt32() != actualMethodCode ||
            !provider.RootElement.GetProperty("Exited").GetBoolean() || !provider.RootElement.GetProperty("ReadersSettled").GetBoolean() ||
            provider.RootElement.GetProperty("ProcessId").GetInt32() < 1 ||
            vstest.RootElement.GetProperty("ExitCode").GetInt32() != 0 || !vstest.RootElement.GetProperty("ReadersSettled").GetBoolean() ||
            !host.RootElement.GetProperty("Exited").GetBoolean() || !host.RootElement.GetProperty("ReadersSettled").GetBoolean() ||
            host.RootElement.GetProperty("CleanupFailed").GetBoolean() || cleanup.RootElement.GetProperty("CleanupFailed").GetBoolean() ||
            method.GetProperty("StartedAtUtc").GetDateTimeOffset() < value.BeganAtUtc ||
            method.GetProperty("ReturnedAtUtc").GetDateTimeOffset() > value.CompletedAtUtc ||
            method.GetProperty("ReturnedAtUtc").GetDateTimeOffset() > provider.RootElement.GetProperty("ExitedAtUtc").GetDateTimeOffset()) { throw InvalidGenerated(); }
        using var run = JsonDocument.Parse(ReadGenerated(value.Run, 65536));
        var controlRef = DecodeAuthRepair<CurrentAuthArchiveProofArtifact>(JsonSerializer.SerializeToUtf8Bytes(run.RootElement.GetProperty("Configuration").GetProperty("ControlBinding")));
        if (Path.GetDirectoryName(controlRef.Path) != Path.GetDirectoryName(value.Run.Path) || Path.GetFileName(controlRef.Path) != "fixture-binding.json") { throw InvalidGenerated(); }
        var control = DecodeAuthRepair<LocalExecutionBinding>(ReadGenerated(controlRef, 65536));
        using var gate = JsonDocument.Parse(CurrentAuthArchiveHelperHost.Read(Path.Combine(Path.GetDirectoryName(value.Run.Path)!,
            Path.GetFileNameWithoutExtension(value.Run.Path) + "-gate.json"), 65536));
        CurrentAuthArchiveProcessBindingV2.Require(run.RootElement, provider.RootElement, vstest.RootElement, host.RootElement, cleanup.RootElement,
            result.RootElement, gate.RootElement, value.Generated.OperationId, seed.AcceptedSourceCommitSha, value.Generated.Input.Sha256,
            value.Run.Sha256, control.ComputeSha256(), value.BeganAtUtc, value.CompletedAtUtc);
        string tests = run.RootElement.GetProperty("InputRoot").GetString()!;
        CurrentAuthArchiveHelperHost.RequireTrx(ReadGenerated(value.Trx, 8 * 1024 * 1024), identity.MethodName, Path.Combine(tests, "Legacy.Maliev.DataMigration.Tests.dll"));
    }
    private static byte[] ReadGenerated(CurrentAuthArchiveProofArtifact artifact, int maximum)
    {
        byte[] bytes = CurrentAuthArchiveHelperHost.Read(artifact.Path, maximum);
        return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) == artifact.Sha256 ? bytes : throw InvalidGenerated();
    }
}
