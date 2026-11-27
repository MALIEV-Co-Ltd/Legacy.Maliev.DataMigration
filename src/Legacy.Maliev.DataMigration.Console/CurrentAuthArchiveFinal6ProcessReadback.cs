using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    internal static void RequireActualFinal6Processes(CurrentAuthArchiveFinal6CaseRun value, CurrentAuthArchiveGenuineCase identity, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var provider = JsonDocument.Parse(ReadFinal6Generated(value.ProviderProcess, 65536));
        using var vstest = JsonDocument.Parse(ReadFinal6Generated(value.VstestProcess, 65536));
        using var host = JsonDocument.Parse(ReadFinal6Generated(value.HostExit, 65536));
        using var cleanup = JsonDocument.Parse(ReadFinal6Generated(value.ResourceCleanup, 2 * 1024 * 1024));
        using var result = JsonDocument.Parse(ReadFinal6Generated(value.ProviderResult, 65536));
        JsonElement method = result.RootElement.GetProperty("Case").GetProperty("Method");
        int actualMethodCode = method.GetProperty("ReturnCode").GetInt32();
        string dotnet = CurrentAuthArchiveHelperHost.Tool("dotnet");
        var seed = DecodeAuthRepair<CurrentAuthArchiveComponentBootstrapSeed>(ReadFinal6Generated(value.Generated.Seed, 65536));
        if (value.Kind != "current-auth-archive-final6-actual-case-run-v1" || value.PhaseProofComplete || value.ActualHostReturnCode != 0 ||
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
            method.GetProperty("ReturnedAtUtc").GetDateTimeOffset() > provider.RootElement.GetProperty("ExitedAtUtc").GetDateTimeOffset()) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        using var run = JsonDocument.Parse(ReadFinal6Generated(value.RunMetadata, 65536));
        var metadata = DecodeAuthRepair<CurrentAuthArchiveFinal6Run>(ReadFinal6Generated(value.RunMetadata, 65536));
        if (metadata.Kind != "current-auth-archive-final6-run-v1" || metadata.Configuration.Kind != "current-auth-archive-final6-host-v1" ||
            metadata.Configuration.ExpectedCase != value.Generated.Case || metadata.Configuration.CaseInput != value.Generated.Input ||
            Path.GetFileName(value.RunMetadata.Path) != "archive-final6-" + metadata.Nonce + ".json" ||
            provider.RootElement.GetProperty("Command").GetString() != CurrentAuthArchiveFinal6Host.ProviderCommand)
        { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        var controlRef = DecodeAuthRepair<CurrentAuthArchiveProofArtifact>(JsonSerializer.SerializeToUtf8Bytes(run.RootElement.GetProperty("Configuration").GetProperty("ControlBinding")));
        if (Path.GetDirectoryName(controlRef.Path) != Path.GetDirectoryName(value.RunMetadata.Path) || Path.GetFileName(controlRef.Path) != "fixture-binding.json") { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        var control = DecodeAuthRepair<LocalExecutionBinding>(ReadFinal6Generated(controlRef, 65536));
        using var gate = JsonDocument.Parse(CurrentAuthArchiveHelperHost.Read(Path.Combine(Path.GetDirectoryName(value.RunMetadata.Path)!,
            Path.GetFileNameWithoutExtension(value.RunMetadata.Path) + "-gate.json"), 65536));
        CurrentAuthArchiveProcessBindingV2.Require(run.RootElement, provider.RootElement, vstest.RootElement, host.RootElement, cleanup.RootElement,
            result.RootElement, gate.RootElement, value.Generated.OperationId, seed.AcceptedSourceCommitSha, value.Generated.Input.Sha256,
            value.RunMetadata.Sha256, control.ComputeSha256(), value.BeganAtUtc, value.CompletedAtUtc);
        string tests = run.RootElement.GetProperty("InputRoot").GetString()!;
        CurrentAuthArchiveFinal6Trx.Require(ReadFinal6Generated(value.Trx, 8 * 1024 * 1024), identity.MethodName, Path.Combine(tests, "Legacy.Maliev.DataMigration.Tests.dll"));
    }
    private static byte[] ReadFinal6Generated(CurrentAuthArchiveProofArtifact artifact, int maximum)
    {
        byte[] bytes = CurrentAuthArchiveHelperHost.Read(artifact.Path, maximum);
        return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) == artifact.Sha256 ? bytes : throw CurrentAuthArchiveFinal6Source.Invalid();
    }
}
