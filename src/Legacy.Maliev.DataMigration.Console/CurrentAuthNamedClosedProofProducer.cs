using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthNamedClosedAssemblyConfiguration(string RunBindingPath, string IntendedScopePath,
    string SourceSchemaPath, string SigningPinsPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    string ReceiptPrivateKeyPath, CurrentAuthProofArtifact Host, CurrentAuthProofArtifact LaneInput,
    string Phase, string OutputPath);

internal static class CurrentAuthNamedClosedProofProducer
{
    internal static async Task<CurrentAuthProofArtifact> RequireIndependentAbsenceAsync(CurrentAppOwnedRepairCustody files,
        string root, Func<CurrentAppOwnedDockerResource, Task> observe, CancellationToken ct)
    {
        string containers = await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(
            ["--host", "npipe:////./pipe/docker_engine", "ps", "--all", "--no-trunc", "--format", "table {{.ID}} {{.Names}}"], ct, observe).ConfigureAwait(false);
        string volumes = await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(
            ["--host", "npipe:////./pipe/docker_engine", "volume", "ls", "--format", "table {{.Name}}"], ct, observe).ConfigureAwait(false);
        int[] ports = [.. IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(x => x.Port).Distinct().Order()];
        string[] containerIds = [.. containers.Split('\n', StringSplitOptions.RemoveEmptyEntries).Skip(1).Select(x => x.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0])];
        string[] containerNames = [.. containers.Split('\n', StringSplitOptions.RemoveEmptyEntries).Skip(1).SelectMany(x => x.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1))];
        string[] volumeNames = [.. volumes.Split('\n', StringSplitOptions.RemoveEmptyEntries).Skip(1).Select(x => x.Trim())];
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (string directory in Directory.EnumerateDirectories(root, "auth-closed-case-*", SearchOption.TopDirectoryOnly))
        {
            var binding = ReadBinding(Path.Combine(directory, "fixture-binding.json"));
            using var authority = WindowsLocalRunAuthority.AcquireResume(directory, binding); using var child = new CurrentAppOwnedRepairCustody(authority);
            using var returned = JsonDocument.Parse(child.Read(Path.Combine(directory, "closed-case-return.json"), sharedReader: true, maximumBytes: 65536));
            string id = returned.RootElement.GetProperty("caseId").GetString() ?? throw CurrentAuthRepairPermit.Invalid();
            Guid operation = returned.RootElement.GetProperty("Operation").GetGuid();
            if (!CurrentAuthNamedClosedProofReadback.Cases.Contains(id, StringComparer.Ordinal) || !ids.Add(id) || Path.GetFileName(directory) != "auth-closed-case-" + operation.ToString("N"))
            { throw CurrentAuthRepairPermit.Invalid(); }
            using var disposed = JsonDocument.Parse(child.Read(Directory.GetFiles(directory, "auth-closed-resource-*-disposed.json").Single(), sharedReader: true, maximumBytes: 65536));
            using var target = JsonDocument.Parse(child.Read(Directory.GetFiles(directory, "auth-closed-resource-*-target.json").Single(), sharedReader: true, maximumBytes: 2 * 1024 * 1024));
            string name = "legacy-delta-proof-" + operation.ToString("N"), container = target.RootElement.GetProperty("Id").GetString()!;
            int port = int.Parse(target.RootElement.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp")[0].GetProperty("HostPort").GetString()!, System.Globalization.CultureInfo.InvariantCulture);
            if (disposed.RootElement.GetProperty("cleanupFailed").GetBoolean() || !disposed.RootElement.GetProperty("verifiedAbsence").GetBoolean() ||
                containerIds.Contains(container, StringComparer.Ordinal) || containerNames.Any(x => x.TrimStart('/') == name) || volumeNames.Contains(name, StringComparer.Ordinal) || ports.Contains(port))
            { throw CurrentAuthRepairPermit.Invalid(); }
            child.Require();
        }
        if (!ids.SetEquals(CurrentAuthNamedClosedProofReadback.Cases)) { throw CurrentAuthRepairPermit.Invalid(); }
        byte[] value = JsonSerializer.SerializeToUtf8Bytes(new { observedAtUtc = DateTimeOffset.UtcNow, group = "closed", containerIds, containerNames, volumeNames, listeningPorts = ports });
        string path = Path.Combine(root, "auth-host-closed-independent-absence.json"); await files.WriteNewAsync(path, value, ct).ConfigureAwait(false);
        return new(path, CurrentAuthRepairPermit.Hash(value));
    }
    internal static LocalExecutionBinding ReadBinding(string path)
    {
        using var stream = SecureLocalFile.OpenReadShared(path); if (stream.Length is < 1 or > 65536) { throw CurrentAuthRepairPermit.Invalid(); }
        byte[] bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes); return MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(bytes);
    }
}

public static partial class MigrationConsole
{
    private static async Task<int> RunCurrentAuthNamedClosedAssemblerAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            CurrentAuthRepairCapacity.Require(admission: true); string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
            var config = await ReadProtectedJsonAsync<CurrentAuthNamedClosedAssemblyConfiguration>(configPath, "auth_closed_assembly_config_unprotected", ct).ConfigureAwait(false);
            var binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(config.RunBindingPath, "auth_closed_assembly_binding_unprotected", ct).ConfigureAwait(false);
            using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding); using var files = new CurrentAppOwnedRepairCustody(authority);
            T Read<T>(string path) => DecodeAuthRepair<T>(files.Read(path, sharedReader: true, maximumBytes: 32 * 1024 * 1024));
            if (JsonSerializer.Serialize(Read<CurrentAuthNamedClosedAssemblyConfiguration>(configPath)) != JsonSerializer.Serialize(config) || Read<LocalExecutionBinding>(config.RunBindingPath) != binding)
            { throw CurrentAuthRepairPermit.Invalid(); }
            var intended = Read<CurrentAuthRepairScope>(config.IntendedScopePath); var source = Read<FreshSchemaPlan>(config.SourceSchemaPath); var pins = Read<CurrentAuthRepairSigningPins>(config.SigningPinsPath);
            if (intended.SourceCommitSha != accepted || source.SourceCommitSha != accepted ||
                intended.ProofAdmission != CurrentAuthProofAdmission.DisposableNativeBootstrap || config.Phase is not ("native" or "recovery" or "maintenance") ||
                config.TrustedKeys.Count != 3 || config.TrustedKeys.Select(x => x.KeyId).Distinct(StringComparer.Ordinal).Count() != 3)
            { throw CurrentAuthRepairPermit.Invalid(); }
            if (config.OutputPath != Path.Combine(binding.ArtifactRootCanonicalPath, "auth-named-closed-" + config.Phase + ".json"))
            { throw CurrentAuthRepairPermit.Invalid(); }
            var trust = new ReceiptAttestationTrustStore(config.TrustedKeys.Select(x => new TrustedAttestationKey(x.KeyId,
                files.Read(x.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
            using var signer = new P256MigrationEvidenceSigner(pins.ReceiptKeyId, Encoding.UTF8.GetString(files.Read(config.ReceiptPrivateKeyPath, sharedReader: true, maximumBytes: 65536)));
            if (signer.PublicKeyFingerprintSha256 != pins.ReceiptFingerprint) { throw CurrentAuthRepairPermit.Invalid(); }
            var cases = new List<CurrentAuthNamedClosedCase>();
            foreach (string directory in Directory.EnumerateDirectories(binding.ArtifactRootCanonicalPath, "auth-closed-case-*", SearchOption.TopDirectoryOnly).Order(StringComparer.Ordinal))
            {
                ct.ThrowIfCancellationRequested(); CurrentAuthRepairCapacity.Require(admission: false);
                string bindingPath = Path.Combine(directory, "fixture-binding.json"); var childBinding = CurrentAuthNamedClosedProofProducer.ReadBinding(bindingPath);
                using var childAuthority = WindowsLocalRunAuthority.AcquireResume(directory, childBinding); using var held = new CurrentAppOwnedRepairCustody(childAuthority);
                using var returned = JsonDocument.Parse(held.Read(Path.Combine(directory, "closed-case-return.json"), sharedReader: true, maximumBytes: 65536));
                var artifacts = new List<CurrentAuthProofArtifact>();
                foreach (string path in Directory.GetFiles(directory, "*", SearchOption.TopDirectoryOnly).Where(x => Path.GetFileName(x) != WindowsLocalRunAuthority.RunLockRelativeName).Order(StringComparer.OrdinalIgnoreCase))
                {
                    FileStream stream = held.BorrowReadStream(path); string hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false));
                    artifacts.Add(new(path, hash)); held.Require();
                }
                cases.Add(new(returned.RootElement.GetProperty("caseId").GetString()!, returned.RootElement.GetProperty("Operation").GetGuid(), directory,
                    bindingPath, childBinding.ComputeSha256(), artifacts));
            }
            var lane = Read<CurrentAuthClosedLaneConfiguration>(config.LaneInput.Path);
            var intent = await CurrentAuthNamedClosedIntent.ReadHeldAsync(lane.IntendedEvidence, source, ct).ConfigureAwait(false);
            string hostScopeHash = CurrentAuthRepairPermit.Hash(files.Read(config.IntendedScopePath, sharedReader: true, maximumBytes: 1024 * 1024));
            var report = new CurrentAuthNamedClosedReport("current-auth-eight-named-console-proof-v1", config.Phase, CurrentAuthNamedClosedIntent.Subject(intent),
                accepted, config.Host, config.LaneInput, new(config.IntendedScopePath, hostScopeHash), DateTimeOffset.UtcNow, cases, signer.KeyId, null);
            await CurrentAuthNamedClosedProofReadback.RequireAsync(files, binding, report, intended, source, pins, trust, requireSignature: false, null, ct).ConfigureAwait(false);
            if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != accepted) { throw CurrentAuthRepairPermit.Invalid(); }
            report = report with { Signature = Convert.ToBase64String(signer.Sign(CurrentAuthNamedClosedProofReadback.Payload(report))) };
            await files.WriteNewAsync(config.OutputPath, JsonSerializer.SerializeToUtf8Bytes(report), ct).ConfigureAwait(false);
            var readback = Read<CurrentAuthNamedClosedReport>(config.OutputPath);
            await CurrentAuthNamedClosedProofReadback.RequireAsync(files, binding, readback, intended, source, pins, trust, requireSignature: true, null, ct).ConfigureAwait(false);
            await output.WriteLineAsync(JsonSerializer.Serialize(new { config.OutputPath, sha256 = CurrentAuthRepairPermit.Hash(files.Read(config.OutputPath, sharedReader: true, maximumBytes: 32 * 1024 * 1024)), persistentAuthority = false })).ConfigureAwait(false);
            return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or JsonException or CryptographicException or FormatException or InvalidOperationException or OperationCanceledException)
        { await error.WriteLineAsync("current_auth_named_closed_assembly_failed").ConfigureAwait(false); return 1; }
    }
}
