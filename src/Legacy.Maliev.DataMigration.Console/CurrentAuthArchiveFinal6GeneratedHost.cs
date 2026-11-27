using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    internal static async Task<CurrentAuthArchiveFinal6CaseRun> RunCurrentAuthArchiveFinal6GeneratedCaseAsync(
        CurrentAuthArchiveFinal6GeneratedCase generated, CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, CancellationToken ct)
    {
        var identity = CurrentAuthArchiveGeneratedCasesV2.Identity(generated.Case);
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
        var seed = DecodeAuthRepair<CurrentAuthArchiveComponentBootstrapSeed>(ReadFinal6Generated(generated.Seed, 65536));
        var source = DecodeAuthRepair<CurrentAuthArchiveFinal6SourceEvidence>(ReadFinal6Generated(generated.SourceCapture, 32 * 1024 * 1024));
        var audience = DecodeAuthRepair<CurrentAuthArchiveClaim>(ReadFinal6Generated(generated.Audience, 65536));
        var caseClaim = DecodeAuthRepair<CurrentAuthArchiveClaim>(ReadFinal6Generated(generated.CaseBinding, 65536));
        DateTimeOffset began = DateTimeOffset.UtcNow;
        _ = CurrentAuthArchiveFinal6CasePolicy.Require(caseClaim, audience, seed, source, generated.Definition.Sha256,
            identity.Phase, identity.CaseId, pins, trust, began);
        var binding = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6GenerationBinding>(
            DecodeAuthRepair<CurrentAuthArchiveClaim>(ReadFinal6Generated(generated.GenerationBinding, 65536)), CurrentAuthArchiveFinal6GenerationPolicy.Domain,
            pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        CurrentAuthArchiveFinal6GenerationPolicy.Require(binding, generated, seed, began);
        var config = DecodeAuthRepair<CurrentAuthArchiveFinal6HostConfiguration>(ReadFinal6Generated(generated.HostConfiguration, 65536));
        CurrentAuthArchiveFinal6Host.RequireConfiguration(config, generated.HostConfiguration.Path);
        if (accepted != seed.AcceptedSourceCommitSha || config.ExpectedCase != generated.Case || config.CaseInput != generated.Input ||
            CurrentAuthArchiveFinal6Host.Request(config).Inputs.ParentSeed != generated.Seed) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        string root = Path.GetDirectoryName(generated.HostConfiguration.Path)!;
        var control = DecodeAuthRepair<LocalExecutionBinding>(ReadFinal6Generated(config.ControlBinding, 65536));
        using (var authority = WindowsLocalRunAuthority.AcquireResume(root, control))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            await files.WriteNewAsync(Path.Combine(root, "generated-case-reservation.json"), JsonSerializer.SerializeToUtf8Bytes(new
            { generated.OperationId, GenerationSha256 = generated.GenerationBinding.Sha256, InputSha256 = generated.Input.Sha256, BeganAtUtc = began }), ct);
        }
        using var output = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
        using var error = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
        int actual = await RunCurrentAuthArchiveFinal6HostAsync(generated.HostConfiguration.Path, output, error, ct);
        DateTimeOffset completed = DateTimeOffset.UtcNow;
        using var resultAuthority = WindowsLocalRunAuthority.AcquireResume(root, control);
        using var results = new CurrentAppOwnedRepairCustody(resultAuthority);
        await results.WriteNewAsync(Path.Combine(root, "generated-case-actual-host-return.json"), JsonSerializer.SerializeToUtf8Bytes(new
        { generated.OperationId, BeganAtUtc = began, CompletedAtUtc = completed, ActualReturnCode = actual, PhaseProofComplete = false }), ct);
        if (actual != 0) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        const string prefix = "archive-final6-";
        string runPath = Directory.EnumerateFiles(root, prefix + "*.json", SearchOption.TopDirectoryOnly).Single(path =>
            Path.GetFileName(path).Length == prefix.Length + 32 + 5 && Guid.TryParseExact(Path.GetFileNameWithoutExtension(path)[prefix.Length..], "N", out _));
        var run = DecodeAuthRepair<CurrentAuthArchiveFinal6Run>(results.Read(runPath, sharedReader: true, maximumBytes: 65536));
        CurrentAuthArchiveFinal6Host.RequireRun(run, runPath);
        if (run.OperationId != generated.OperationId || run.Configuration != config || run.SourceCommitSha != accepted) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        string stem = Path.Combine(root, Path.GetFileNameWithoutExtension(runPath));
        var value = new CurrentAuthArchiveFinal6CaseRun("current-auth-archive-final6-actual-case-run-v1", generated, began, completed, actual,
            Artifact(runPath, 65536), Artifact(stem + "-provider-result.json", 65536), Artifact(stem + "-provider-process.json", 65536),
            Artifact(stem + "-vstest-process.json", 65536), Artifact(Path.Combine(root, run.Nonce + ".trx"), 8 * 1024 * 1024),
            Artifact(stem + "-host-exit.json", 65536), Artifact(stem + "-resource-cleanup.json", 2 * 1024 * 1024), false);
        RequireActualFinal6Processes(value, identity, ct);
        await results.WriteNewAsync(Path.Combine(root, "generated-case-actual-run.json"), JsonSerializer.SerializeToUtf8Bytes(value), ct);
        return value;
        CurrentAuthArchiveProofArtifact Artifact(string path, int maximum)
        {
            return new(path,
            CurrentAuthLocalSessionArchivePolicy.HashBytes(results.Read(path, sharedReader: true, maximumBytes: maximum)));
        }
    }
}
