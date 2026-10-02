using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Google.Cloud.Storage.V1;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record SourceBackedLocalRepairAuthorityCommandConfiguration(string ArtifactRoot, string BindingOutputPath);

internal sealed record SourceBackedLocalRepairCommandConfiguration(string PairPath, string ProofPath,
    string SchemaPath, string? AuthorizationPath, string OperatorConnectionFile, string MaintenancePinsPath,
    string RunBindingPath, string SigningPinsPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    string EvidenceKeyId, string EvidencePrivateKeyFile, string TerminalSigningPinPath,
    string PersistentEvidenceKeyId, string PersistentEvidencePrivateKeyFile, string OutputPath, DateTimeOffset ExpiresAtUtc,
    string? AdmissionPath = null, long RetainedOrdinal = 0, string? CaptureDirectory = null,
    string? CaptureKeyFile = null, string? FreshAuthorizationPath = null,
    long PreviousGrantCounter = 0, long ActiveGrantCounter = 0,
    string? AuthorizationKeyId = null, string? AuthorizationPrivateKeyFile = null);

public static partial class MigrationConsole
{
    private static async Task<int> RunSourceBackedLocalRepairBoundaryAsync(string command, string configPath,
        TextWriter output, TextWriter error, CancellationToken cancellationToken)
    {
        try
        {
            // Actual fixed repository/protected-main/CI and frozen bytes, never a config
            // AllowExecution flag, caller string, fixture identity or historical receipt.
            string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(cancellationToken).ConfigureAwait(false);
            MigrationConsoleConfiguration root = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
                configPath, "delta_source_repair_config_unprotected", cancellationToken).ConfigureAwait(false);
            if (command == "prepare-source-backed-local-repair-authority")
            {
                SourceBackedLocalRepairAuthorityCommandConfiguration prepare = root.SourceBackedLocalRepairAuthority
                    ?? throw DeltaInvalid("delta_source_repair_authority_config_missing");
                string artifactRoot = Path.GetFullPath(prepare.ArtifactRoot);
                if (!string.Equals(Path.GetDirectoryName(Path.GetFullPath(prepare.BindingOutputPath)), artifactRoot,
                    StringComparison.OrdinalIgnoreCase)) { throw DeltaInvalid("delta_source_repair_binding_output_invalid"); }
                using WindowsLocalRunAuthority fresh = WindowsLocalRunAuthority.AcquireFresh(artifactRoot);
                await WriteNewJsonAsync(prepare.BindingOutputPath, fresh.Binding, cancellationToken).ConfigureAwait(false);
                await output.WriteLineAsync("prepare_source_backed_local_repair_authority_complete").ConfigureAwait(false);
                return 0;
            }
            SourceBackedLocalRepairCommandConfiguration request = root.SourceBackedLocalRepair
                ?? throw DeltaInvalid("delta_source_repair_config_missing");
            if (request.PreviousGrantCounter < 0 || request.ActiveGrantCounter < 0)
            { throw DeltaInvalid("delta_source_repair_renewal_invalid"); }
            PairedCapturedDeltaPlans plans = await ReadProtectedJsonAsync<PairedCapturedDeltaPlans>(request.PairPath,
                "delta_source_repair_pair_unprotected", cancellationToken).ConfigureAwait(false);
            Exact23DeltaReconciliationResult proof = await ReadProtectedJsonAsync<Exact23DeltaReconciliationResult>(request.ProofPath,
                "delta_source_repair_proof_unprotected", cancellationToken).ConfigureAwait(false);
            FreshSchemaPlan schema = await ReadProtectedJsonAsync<FreshSchemaPlan>(request.SchemaPath,
                "delta_source_repair_schema_unprotected", cancellationToken).ConfigureAwait(false);
            if (plans.Persistent.SourceCommitSha != accepted || schema.SourceCommitSha != accepted ||
                plans.Disposable.SourceCommitSha != accepted) { throw DeltaInvalid("delta_source_repair_source_unaccepted"); }
            SourceBackedLocalRepairMaintenancePins maintenancePins = await ReadProtectedJsonAsync<SourceBackedLocalRepairMaintenancePins>(
                request.MaintenancePinsPath, "delta_source_repair_maintenance_unprotected", cancellationToken).ConfigureAwait(false);
            if (maintenancePins.TargetIdentity.VolumeName != "legacy-maliev-exact23-postgres-data")
            { throw DeltaInvalid("delta_source_repair_volume_invalid"); }
            LocalExecutionBinding binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(request.RunBindingPath,
                "delta_source_repair_binding_unprotected", cancellationToken).ConfigureAwait(false);
            using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            string connection = await ReadProtectedTextAsync(request.OperatorConnectionFile,
                "delta_source_repair_operator_unprotected", cancellationToken).ConfigureAwait(false);
            Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observe = token =>
                ObserveSourceRepairTargetAsync(plans.Persistent, connection, token);
            var maintenance = new SourceBackedLocalRepairMaintenance(connection, maintenancePins, observe, TimeProvider.System, authority);
            SourceBackedLocalRepairSigningPins pins = await ReadProtectedJsonAsync<SourceBackedLocalRepairSigningPins>(
                request.SigningPinsPath, "delta_source_repair_signing_pins_unprotected", cancellationToken).ConfigureAwait(false);
            ReceiptAttestationTrustStore trust = await ReadTrustStoreAsync([.. request.TrustedKeys.Select(key =>
                new TrustedKeyReference(key.KeyId, key.SubjectPublicKeyInfoPath))], cancellationToken).ConfigureAwait(false);
            if (!trust.TryGetPublicKeyFingerprintSha256(request.EvidenceKeyId, out string fingerprint) || fingerprint != pins.EvidenceFingerprint)
            { throw DeltaInvalid("delta_source_repair_evidence_key_invalid"); }
            SourceBackedLocalRepairTerminalSigningPin terminalPin = await ReadProtectedJsonAsync<SourceBackedLocalRepairTerminalSigningPin>(
                request.TerminalSigningPinPath, "delta_source_repair_terminal_pin_unprotected", cancellationToken).ConfigureAwait(false);
            if (terminalPin.KeyId != request.PersistentEvidenceKeyId ||
                !trust.TryGetPublicKeyFingerprintSha256(request.PersistentEvidenceKeyId, out string persistentFingerprint) ||
                persistentFingerprint != terminalPin.PublicKeyFingerprintSha256)
            { throw DeltaInvalid("delta_source_repair_terminal_key_invalid"); }
            var sourceAcceptance = new ProtectedMainSourceRepairAcceptance();
            if (command == "authorize-source-backed-local-repair")
            {
                string keyId = Required(request.AuthorizationKeyId);
                if (!trust.TryGetPublicKeyFingerprintSha256(keyId, out string authorizationFingerprint) ||
                    authorizationFingerprint != pins.AuthorizationFingerprint)
                { throw DeltaInvalid("delta_source_repair_authorization_key_invalid"); }
                using var authorizationSigner = new P256MigrationEvidenceSigner(keyId,
                    await ReadProtectedTextAsync(Required(request.AuthorizationPrivateKeyFile),
                        "delta_source_repair_authorization_signer_unprotected", cancellationToken).ConfigureAwait(false));
                PairedLocalTransitionAuthorization signed = await SourceBackedLocalRepairRuntime.AuthorizeMaintainedAsync(
                    connection, plans, proof, schema, trust, observe, maintenance, sourceAcceptance,
                    TimeProvider.System, request.ExpiresAtUtc, authorizationSigner, cancellationToken).ConfigureAwait(false);
                await WriteNewJsonAsync(request.OutputPath, signed, cancellationToken).ConfigureAwait(false);
                await output.WriteLineAsync("authorize_source_backed_local_repair_complete").ConfigureAwait(false);
                return 0;
            }
            PairedLocalTransitionAuthorization authorization = await ReadProtectedJsonAsync<PairedLocalTransitionAuthorization>(
                Required(request.AuthorizationPath), "delta_source_repair_authorization_unprotected", cancellationToken).ConfigureAwait(false);
            using var signer = new P256MigrationEvidenceSigner(request.EvidenceKeyId,
                await ReadProtectedTextAsync(request.EvidencePrivateKeyFile, "delta_source_repair_signer_unprotected",
                    cancellationToken).ConfigureAwait(false));
            // Same reviewed create/get gateway and fixed locked bucket for reservations,
            // ordinal progress and terminal publication. No caller bucket override.
            var gateway = new GoogleCloudRolloverClaimGateway(await StorageClient.CreateAsync().ConfigureAwait(false),
                "maliev-legacy-rollover-claims");
            var claims = new SourceBackedLocalRepairClaimStore(gateway);
            var continuations = new SourceBackedLocalRepairContinuationStore(gateway, claims, trust,
                pins.AuthorizationFingerprint, pins.EvidenceFingerprint);
            var renewals = new SourceBackedLocalRepairRenewalStore(gateway, claims, continuations, trust,
                pins, terminalPin, observe, TimeProvider.System, sourceAcceptance);
            var admissions = new SourceBackedLocalRepairAdmissionStore(claims, trust, pins, observe,
                TimeProvider.System, renewals, sourceAcceptance);
            var runtime = ComposeSourceBackedLocalRepairRuntime(connection, maintenance, observe, admissions,
                continuations, trust, TimeProvider.System, gateway, sourceAcceptance, pins, terminalPin, renewals);
            object result;
            if (command == "stage-source-backed-local-repair")
            {
                await runtime.StageAsync(plans, proof, schema, authorization, cancellationToken).ConfigureAwait(false);
                result = new { StagedDatabases = 23, SourceCommitSha = accepted };
            }
            else if (command == "admit-source-backed-local-repair")
            {
                result = await runtime.AdmitAsync(plans, proof, schema, authorization, request.ExpiresAtUtc,
                    signer, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                SourceBackedLocalRepairAdmissionBundle bundle = await ReadProtectedJsonAsync<SourceBackedLocalRepairAdmissionBundle>(
                    Required(request.AdmissionPath), "delta_source_repair_admission_unprotected", cancellationToken).ConfigureAwait(false);
                SourceBackedLocalRepairRenewalStore.ActiveGrant? activeGrant = request.ActiveGrantCounter == 0 ||
                    command == "renew-source-backed-local-repair" ? null :
                    await runtime.ReadActiveGrantAsync(bundle, plans, proof, schema, request.ActiveGrantCounter,
                        cancellationToken).ConfigureAwait(false);
                if (command == "renew-source-backed-local-repair")
                {
                    PairedLocalTransitionAuthorization freshAuthorization = await ReadProtectedJsonAsync<PairedLocalTransitionAuthorization>(
                        Required(request.FreshAuthorizationPath), "delta_source_repair_authorization_unprotected",
                        cancellationToken).ConfigureAwait(false);
                    SourceBackedLocalRepairRenewalStore.ActiveGrant renewed = await runtime.RenewAsync(bundle,
                        plans, proof, schema, freshAuthorization, request.RetainedOrdinal, request.PreviousGrantCounter,
                        signer, cancellationToken).ConfigureAwait(false);
                    result = renewed.SignedGrant;
                }
                else if (command == "apply-source-backed-local-repair-next")
                {
                    await using FileStream keyFile = OwnerProtectedFilePolicy.OpenRead(Required(request.CaptureKeyFile),
                        "delta_source_repair_capture_key_unprotected");
                    if (keyFile.Length != 32) { throw DeltaInvalid("delta_capture_key_invalid"); }
                    byte[] key = new byte[32];
                    try
                    {
                        await keyFile.ReadExactlyAsync(key, cancellationToken).ConfigureAwait(false);
                        SourceBackedLocalRepairMixedStateReader.Observation observed = await runtime.ApplyNextAsync(bundle, plans, proof, schema, authorization,
                            request.RetainedOrdinal, Required(request.CaptureDirectory), key, signer, cancellationToken, activeGrant).ConfigureAwait(false);
                        result = ObservationEvidence(observed, activeGrant?.Counter ?? 0);
                    }
                    finally { CryptographicOperations.ZeroMemory(key); }
                }
                else if (command == "reconcile-source-backed-local-repair")
                {
                    using var persistentSigner = new P256MigrationEvidenceSigner(request.PersistentEvidenceKeyId,
                        await ReadProtectedTextAsync(request.PersistentEvidencePrivateKeyFile,
                            "delta_source_repair_persistent_signer_unprotected", cancellationToken).ConfigureAwait(false));
                    result = await runtime.ReconcileAndPublishAsync(bundle, plans, proof, schema, authorization,
                        signer, persistentSigner, cancellationToken, activeGrant).ConfigureAwait(false);
                }
                else { throw DeltaInvalid("delta_source_repair_command_invalid"); }
            }
            await WriteNewJsonAsync(request.OutputPath, result, cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync(command.Replace('-', '_') + "_complete").ConfigureAwait(false);
            return 0;
        }
        catch (Exception failure)
        {
            // Never print connection text, credential/provider stderr, signatures or raw rows.
            string code = ClassifyDeltaFailure(failure);
            if (code.Length > 100 || code.Any(value => value is not (>= 'a' and <= 'z') and not '_'))
            { code = "delta_source_repair_failed"; }
            await error.WriteLineAsync(code).ConfigureAwait(false);
            return failure is OperationCanceledException ? 130 : 70;
        }
    }

    internal static object ObservationEvidence(SourceBackedLocalRepairMixedStateReader.Observation observed, long activeGrantCounter)
    {
        // Serialize signed progress and actual observation metadata explicitly. The opaque
        // proof has internal properties and must never become a deserializable permit.
        return new
        {
            observed.AdmissionSha256,
            observed.Continuation,
            observed.Identity,
            observed.VerifiedAtUtc,
            observed.IsTerminal,
            ActiveGrantCounter = activeGrantCounter
        };
    }

    internal static SourceBackedLocalRepairRuntime ComposeSourceBackedLocalRepairRuntime(string connection,
        SourceBackedLocalRepairMaintenance maintenance,
        Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observe,
        SourceBackedLocalRepairAdmissionStore admissions, SourceBackedLocalRepairContinuationStore continuations,
        IReceiptAttestationTrustStore trust, TimeProvider clock, IRolloverClaimObjectGateway gateway,
        ISourceBackedLocalRepairSourceAcceptance sourceAcceptance, SourceBackedLocalRepairSigningPins pins,
        SourceBackedLocalRepairTerminalSigningPin terminalPin, SourceBackedLocalRepairRenewalStore renewals) =>
        new(connection, maintenance, observe, admissions, continuations, trust, clock, gateway,
            sourceAcceptance, pins, terminalPin, renewals);

    private static async Task<HistoricalCurrentLocalObservation> ObserveSourceRepairTargetAsync(
        DeltaSynchronizationPlan plan, string connectionString, CancellationToken cancellationToken)
    {
        await LocalDockerGenerationGuard.VerifyAsync(plan, connectionString, cancellationToken).ConfigureAwait(false);
        string id = LocalDockerGenerationGuard.RequireContainerId(plan);
        const string volume = "legacy-maliev-exact23-postgres-data";
        var settings = LocalPostgreSqlResourceAuthority.Connection(connectionString);
        string containerJson = await DefaultPairedLocalTemplateObserver.RunDockerAsync(
            ["inspect", "--type", "container", id], cancellationToken).ConfigureAwait(false);
        string volumeJson = await DefaultPairedLocalTemplateObserver.RunDockerAsync(
            ["inspect", "--type", "volume", volume], cancellationToken).ConfigureAwait(false);
        DockerLocalTargetObservation actual = DockerLocalTargetObservation.Parse(containerJson, volumeJson,
            id, volume, settings.Port, persistent: true);
        using JsonDocument metadata = JsonDocument.Parse(volumeJson);
        string mountpoint = metadata.RootElement[0].GetProperty("Mountpoint").GetString()
            ?? throw DeltaInvalid("delta_source_repair_volume_invalid");
        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand("SELECT system_identifier::text FROM pg_control_system();", connection);
        string identifier = (string)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false)
            ?? throw DeltaInvalid("delta_source_repair_identity_invalid"));
        return new(actual.ContainerId, LocalDockerGenerationGuard.ComposeGeneration(actual), actual.VolumeName,
            actual.VolumeCreatedAtUtc, mountpoint, actual.VolumeDestination, actual.PgData,
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identifier))).ToLowerInvariant());
    }
}
