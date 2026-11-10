using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

// Initial physical facts only: no completed scope, future proof hash or device claims.
internal sealed record CurrentAuthArchiveDevicePreflightRequest(string Domain, Guid OperationId, string SourceCommitSha,
    string LocalRunBindingSha256, string ProductionRunBindingSha256, string LocalTargetObservationSha256,
    string ProductionTargetObservationSha256, CurrentAuthArchivePaths Paths, string FirstRoot, string SecondRoot,
    DateTimeOffset CapturedAtUtc, DateTimeOffset ExpiresAtUtc);

internal static partial class CurrentAuthLocalSessionArchiveDeviceProcess
{
    internal const string PreflightCommand = "preflight-current-auth-archive-recovery-devices";

    internal static void RequirePreflight(CurrentAuthArchiveDevicePreflightRequest request, DateTimeOffset now)
    {
        if (request is null || request.Paths is null ||
            new[] { request.SourceCommitSha, request.LocalRunBindingSha256, request.ProductionRunBindingSha256,
                request.LocalTargetObservationSha256, request.ProductionTargetObservationSha256 }.Any(string.IsNullOrWhiteSpace) ||
            request.Domain != "Legacy.Maliev.CurrentAuth.ArchiveDevicePreflight.v1" || request.OperationId == Guid.Empty ||
            request.SourceCommitSha.Length != 40 || !request.SourceCommitSha.All(char.IsAsciiHexDigitLower) ||
            !CurrentAuthRepairPermit.HashShape(request.LocalRunBindingSha256) || !CurrentAuthRepairPermit.HashShape(request.ProductionRunBindingSha256) ||
            !CurrentAuthRepairPermit.HashShape(request.LocalTargetObservationSha256) || !CurrentAuthRepairPermit.HashShape(request.ProductionTargetObservationSha256) ||
            request.LocalRunBindingSha256 == request.ProductionRunBindingSha256 || request.LocalTargetObservationSha256 == request.ProductionTargetObservationSha256 ||
            request.CapturedAtUtc.Offset != TimeSpan.Zero || request.ExpiresAtUtc.Offset != TimeSpan.Zero || request.CapturedAtUtc > now ||
            request.ExpiresAtUtc <= now || request.ExpiresAtUtc <= request.CapturedAtUtc || request.ExpiresAtUtc - request.CapturedAtUtc > TimeSpan.FromMinutes(1) ||
            !Path.IsPathFullyQualified(request.FirstRoot) || !Path.IsPathFullyQualified(request.SecondRoot))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        string first = Path.TrimEndingDirectorySeparator(Path.GetFullPath(request.FirstRoot));
        string second = Path.TrimEndingDirectorySeparator(Path.GetFullPath(request.SecondRoot));
        if (first != request.FirstRoot || second != request.SecondRoot || StringComparer.OrdinalIgnoreCase.Equals(first, second))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        string[] paths = [request.Paths.FirstCiphertext, request.Paths.RecoveryPrivateKey, request.Paths.SecondCiphertext, request.Paths.SecondRecoveryPrivateKey];
        if (paths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != 4) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        for (int i = 0; i < paths.Length; i++)
        {
            if (!Path.IsPathFullyQualified(paths[i]) || Path.GetFullPath(paths[i]) != paths[i] ||
                !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(paths[i]), i < 2 ? first : second))
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
    }

    internal static async Task<CurrentAuthArchiveDeviceProof> ObservePreflightAsync(CurrentAuthArchiveDevicePreflightRequest request,
        CurrentAppOwnedRepairCustody firstFiles, CurrentAppOwnedRepairCustody secondFiles, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        RequirePreflight(request, DateTimeOffset.UtcNow);
        CurrentAuthArchiveCapacity.Require(admission: true);
        if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != request.SourceCommitSha)
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        firstFiles.RequireRunBinding(request.FirstRoot, request.LocalRunBindingSha256);
        secondFiles.RequireRunBinding(request.SecondRoot, request.ProductionRunBindingSha256);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(request);
        if (bytes.Length > Limit) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        string path = Path.Combine(request.FirstRoot, $"device-preflight-auth-archive-{Guid.NewGuid():N}.json");
        await firstFiles.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
        if (!firstFiles.Read(path, sharedReader: true, maximumBytes: Limit).AsSpan().SequenceEqual(bytes))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        string result = await RunAsync(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes), FrameAsync, ct, PreflightCommand).ConfigureAwait(false);
        firstFiles.RequireRunBinding(request.FirstRoot, request.LocalRunBindingSha256);
        secondFiles.RequireRunBinding(request.SecondRoot, request.ProductionRunBindingSha256);
        RequirePreflight(request, DateTimeOffset.UtcNow);
        if (!firstFiles.Read(path, sharedReader: true, maximumBytes: Limit).AsSpan().SequenceEqual(bytes))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        byte[] output = new UTF8Encoding(false, true).GetBytes(result);
        CurrentAuthArchiveDeviceProof proof = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveDeviceProof>(output);
        if (!JsonSerializer.SerializeToUtf8Bytes(proof).AsSpan().SequenceEqual(output)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        RequirePreflightProof(proof, request, DateTimeOffset.UtcNow);
        return proof;

        async Task FrameAsync(CurrentAuthArchiveDeviceResource resource)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            byte[] frame = JsonSerializer.SerializeToUtf8Bytes(new { request.OperationId, Resource = resource });
            string framePath = Path.Combine(request.FirstRoot, $"resource-auth-archive-device-preflight-{Guid.NewGuid():N}.json");
            await firstFiles.WriteNewAsync(framePath, frame, deadline.Token).ConfigureAwait(false);
            if (!firstFiles.Read(framePath, maximumBytes: Limit).AsSpan().SequenceEqual(frame))
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
    }

    internal static void RequirePreflightProof(CurrentAuthArchiveDeviceProof proof, CurrentAuthArchiveDevicePreflightRequest request, DateTimeOffset now)
    {
        RequirePreflight(request, now);
        if (proof.Domain != "Legacy.Maliev.CurrentAuth.ArchivePhysicalDevices.v1" || proof.OperationId != request.OperationId ||
            proof.SourceCommitSha != request.SourceCommitSha || proof.OwnerPinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 ||
            proof.LocalRunBindingSha256 != request.LocalRunBindingSha256 || proof.ProductionRunBindingSha256 != request.ProductionRunBindingSha256 ||
            proof.LocalTargetObservationSha256 != request.LocalTargetObservationSha256 || proof.ProductionTargetObservationSha256 != request.ProductionTargetObservationSha256 ||
            proof.Paths != request.Paths || proof.ObservedAtUtc.Offset != TimeSpan.Zero || proof.ObservedAtUtc < request.CapturedAtUtc || proof.ObservedAtUtc > now)
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        CurrentAuthLocalSessionArchiveRecoveryDevices.RequireIndependent(proof.First, proof.Second);
    }
}

public static partial class MigrationConsole
{
    internal static (string Path, string Sha256) RequireArchiveDevicePreflightInvocation(IReadOnlyList<string> arguments)
    {
        return arguments.Count != 3 || arguments[0] != CurrentAuthLocalSessionArchiveDeviceProcess.PreflightCommand ||
            !Path.IsPathFullyQualified(arguments[1]) || !CurrentAuthRepairPermit.HashShape(arguments[2])
            ? throw new CommandLineException("current_auth_archive_device_preflight_arguments_invalid", "A fixed protected preflight path and digest are required.")
            : ((string Path, string Sha256))(Path.GetFullPath(arguments[1]), arguments[2]);
    }

    private static async Task<int> RunCurrentAuthArchiveDevicePreflightAsync(string path, string sha256, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            if (!OperatingSystem.IsWindows()) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            using FileStream held = SecureLocalFile.OpenReadShared(path);
            if (!SecureLocalFile.HandleResolvesToApprovedPath(held, path) || held.Length is < 1 or > 65536)
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            string identity = SecureLocalFile.GetHandleIdentity(held);
            byte[] bytes = new byte[checked((int)held.Length)]; await held.ReadExactlyAsync(bytes, ct).ConfigureAwait(false);
            var request = DecodeAuthRepair<CurrentAuthArchiveDevicePreflightRequest>(bytes);
            CurrentAuthLocalSessionArchiveDeviceProcess.RequirePreflight(request, DateTimeOffset.UtcNow);
            if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != sha256 || !JsonSerializer.SerializeToUtf8Bytes(request).AsSpan().SequenceEqual(bytes) ||
                CompiledDeviceSource(typeof(MigrationConsole).Assembly) != request.SourceCommitSha ||
                CompiledDeviceSource(typeof(DeltaExecutionCoordinator).Assembly) != request.SourceCommitSha)
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            var proof = CurrentAuthLocalSessionArchiveRecoveryDevices.ObservePreflightInChild(request, ct);
            CurrentAuthLocalSessionArchiveDeviceProcess.RequirePreflightProof(proof, request, DateTimeOffset.UtcNow);
            if (SecureLocalFile.GetHandleIdentity(held) != identity || !SecureLocalFile.HandleResolvesToApprovedPath(held, path))
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            await output.WriteAsync(JsonSerializer.Serialize(proof)).ConfigureAwait(false); return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or IOException or UnauthorizedAccessException or JsonException or ArgumentException or InvalidOperationException)
        { await error.WriteAsync("current_auth_archive_device_preflight_failed").ConfigureAwait(false); return 1; }
    }
}
