using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthTypedProofConfiguration(string RunBindingPath, string IntendedScopePath,
    string SourceSchemaPath, string SigningPinsPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    string ReceiptPrivateKeyPath, CurrentAuthProofArtifact ExecutedHostProof, string Phase, string OutputPath);

public static partial class MigrationConsole
{
    // Proposed fixed dispatcher route only. This produces disposable proof and never invokes an Auth provider or issuer.
    private static async Task<int> RunCurrentAuthTypedProofAssemblerAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            CurrentAuthRepairCapacity.Require(admission: true);
            string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
            CurrentAuthTypedProofConfiguration config = await ReadProtectedJsonAsync<CurrentAuthTypedProofConfiguration>(configPath,
                "current_auth_typed_proof_config_unprotected", ct).ConfigureAwait(false);
            LocalExecutionBinding binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(config.RunBindingPath,
                "current_auth_typed_proof_binding_unprotected", ct).ConfigureAwait(false);
            using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            int ownerFrame = 0;
            Task ObserveOwner(CurrentAuthGitResource frame)
            {
                return files.WriteNewAsync(Path.Combine(binding.ArtifactRootCanonicalPath,
                $"auth-assembly-owner-{frame.RunId:N}-{Interlocked.Increment(ref ownerFrame):D4}.json"),
                JsonSerializer.SerializeToUtf8Bytes(frame), CancellationToken.None);
            }

            await CurrentAuthOwnerSourceReader.RequireAsync(ObserveOwner, ct).ConfigureAwait(false);
            T Read<T>(string path)
            {
                return DecodeAuthRepair<T>(files.Read(path, sharedReader: true, maximumBytes: 32 * 1024 * 1024));
            }

            if (JsonSerializer.Serialize(Read<CurrentAuthTypedProofConfiguration>(configPath)) != JsonSerializer.Serialize(config) ||
                Read<LocalExecutionBinding>(config.RunBindingPath) != binding) { throw CurrentAuthRepairPermit.Invalid(); }
            CurrentAuthRepairScope scope = Read<CurrentAuthRepairScope>(config.IntendedScopePath);
            FreshSchemaPlan source = Read<FreshSchemaPlan>(config.SourceSchemaPath);
            if (scope.SourceCommitSha != accepted || source.SourceCommitSha != accepted ||
                scope.SourceSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(source) ||
                scope.AuthOwnerCommitSha != ApprovedCurrentAuthSchema.AuthServiceCommit ||
                scope.AuthOwnerSourcePinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 ||
                scope.AuthClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 ||
                scope.ProofAdmission != CurrentAuthProofAdmission.DisposableNativeBootstrap) { throw CurrentAuthRepairPermit.Invalid(); }
            CurrentAuthRepairSigningPins pins = Read<CurrentAuthRepairSigningPins>(config.SigningPinsPath);
            if (config.TrustedKeys.Count != 3 || config.TrustedKeys.Select(x => x.KeyId).Distinct(StringComparer.Ordinal).Count() != 3)
            { throw CurrentAuthRepairPermit.Invalid(); }
            var trust = new ReceiptAttestationTrustStore(config.TrustedKeys.Select(x =>
                new TrustedAttestationKey(x.KeyId, files.Read(x.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))).ToArray());
            using var signer = new P256MigrationEvidenceSigner(pins.ReceiptKeyId,
                Encoding.UTF8.GetString(files.Read(config.ReceiptPrivateKeyPath, sharedReader: true, maximumBytes: 65536)));
            CurrentAuthProofArtifact result = await CurrentAuthTypedProofAssembler.AssembleAsync(files, binding, config.ExecutedHostProof,
                config.Phase, scope, source, pins, trust, signer, config.OutputPath, ct).ConfigureAwait(false);
            CurrentAuthRepairCapacity.Require(admission: false);
            await CurrentAuthOwnerSourceReader.RequireAsync(ObserveOwner, ct).ConfigureAwait(false);
            if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != accepted)
            { throw CurrentAuthRepairPermit.Invalid(); }
            files.Require();
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                kind = "current-auth-disposable-proof-assembled-v1",
                result.Path,
                result.Sha256,
                executionAuthority = false,
                persistentAuthority = false
            })).ConfigureAwait(false);
            return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or
            UnauthorizedAccessException or System.Security.Cryptography.CryptographicException or JsonException or FormatException or InvalidOperationException)
        {
            await error.WriteLineAsync("current_auth_typed_proof_assembly_failed").ConfigureAwait(false); return 1;
        }
    }
}
