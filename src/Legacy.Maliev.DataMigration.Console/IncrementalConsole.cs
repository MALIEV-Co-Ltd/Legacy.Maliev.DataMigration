using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    private static async Task<int> RunIncrementalBoundaryAsync(string command, string config, Func<string, string?> environment,
        TextWriter output, TextWriter error, IIncrementalConsoleRuntime runtime, CancellationToken token)
    {
        try { await RunIncrementalAsync(command, config, environment, output, runtime, token).ConfigureAwait(false); return 0; }
        catch (Exception failure)
        {
            // Never emit provider messages, inner exceptions, stack traces or exception.Data.
            string code = failure switch
            {
                MigrationConsoleException value => value.Code,
                MigrationExecutionException value => value.Code,
                RuntimeAttestationException value => value.Code,
                OperatorAttestationException value => value.Code,
                PostgreSqlMigrationBoundaryException value => value.Code,
                Exact25FullBackupException value => value.Code,
                OperationCanceledException => "operation_cancelled",
                IOException or UnauthorizedAccessException => "incremental_io_failed",
                JsonException or ArgumentException or FormatException or CryptographicException => "incremental_configuration_invalid",
                PlatformNotSupportedException => "incremental_windows_required",
                _ => "incremental_execution_failed",
            };
            if (code.Length > 100 || code.Any(value => value is not (>= 'a' and <= 'z') and not '_')) { code = "incremental_execution_failed"; }
            await error.WriteLineAsync(code).ConfigureAwait(false);
            if (failure is MigrationExecutionException { Reconciliation: { } diagnostic })
            {
                string? SafeName(string? value)
                {
                    return value is { Length: > 0 and <= 128 } && value.All(character => char.IsLetterOrDigit(character) || character is '_' or '.' or '-') ? value : null;
                }

                string? SafeValue(string? value)
                {
                    return value is not null && ((value.Length == 64 && value.All(Uri.IsHexDigit)) ||
                                    long.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out _)) ? value : null;
                }

                await error.WriteLineAsync(JsonSerializer.Serialize(new
                {
                    database = DatabaseInventory.ActiveDatabases.Contains(diagnostic.Database, StringComparer.Ordinal) ? diagnostic.Database : null,
                    table = SafeName(diagnostic.Table),
                    check = SafeName(diagnostic.Check),
                    field = SafeName(diagnostic.Field),
                    expected = SafeValue(diagnostic.Expected),
                    observed = SafeValue(diagnostic.Observed),
                })).ConfigureAwait(false);
            }
            return failure is OperationCanceledException ? 130 : failure is MigrationConsoleException or OperatorAttestationException or JsonException or ArgumentException or FormatException or CryptographicException ? 65 : 70;
        }
    }

    internal static Task<int> RunIncrementalForTestsAsync(IReadOnlyList<string> arguments, TextWriter output, TextWriter error,
        Func<string, string?> environment, IIncrementalConsoleRuntime runtime, CancellationToken token)
    {
        return RunCoreAsync(arguments, output, error, environment, new DefaultExact25BackupRuntimeFactory(),
                new DefaultAuthorizationRuntimeAttestationFactory(), new DefaultQuotationSnapshotRuntimeFactory(), token, runtime);
    }

    private static async Task RunIncrementalAsync(string commandName, string configPath,
        Func<string, string?> environment, TextWriter output, IIncrementalConsoleRuntime runtime, CancellationToken token)
    {
        if (!string.Equals(environment(DeployEnabledEnvironmentVariable), "false", StringComparison.OrdinalIgnoreCase))
        { throw Invalid("incremental_deploy_gate_invalid"); }
        MigrationConsoleConfiguration configuration = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(configPath,
            "incremental_config_unprotected", token).ConfigureAwait(false);
        IncrementalCommandConfiguration command = configuration.Incremental ?? throw Invalid("incremental_configuration_missing");
        bool initial = commandName is "execute-shadow" or "plan-incremental";
        bool executing = commandName is "execute-shadow" or "resume-shadow";
        if ((executing && !command.AllowExecution) || (commandName == "authorize-resume" && !command.AllowSigning))
        { throw Invalid("incremental_owner_approval_required"); }
        if (commandName is "resume-shadow" or "authorize-resume" && string.IsNullOrWhiteSpace(command.ContinuityPath))
        { throw Invalid("incremental_continuity_required"); }
        ValidateIncrementalPaths(command);
        if (commandName == "execute-shadow")
        {
            string admissionOutput = Required(command.AdmissionPath);
            ValidateIncrementalLocalPath(admissionOutput);
            if (PathsOverlap(admissionOutput, command.ArtifactRoot) || PathsOverlap(admissionOutput, command.OutputDirectory) || PathsOverlap(admissionOutput, command.OutputPath))
            { throw Invalid("incremental_admission_output_invalid"); }
            OwnerProtectedFilePolicy.ValidatePublicationParent(admissionOutput);
            if (File.Exists(admissionOutput) || Directory.Exists(admissionOutput) || File.Exists(command.OutputPath) || Directory.Exists(command.OutputPath))
            { throw Invalid("incremental_output_exists"); }
        }
        SigningRolesCommandConfiguration roles = configuration.SigningRoles ?? throw Invalid("signing_role_configuration_missing");
        _ = await ReadSigningRolesAsync(roles, token).ConfigureAwait(false);
        ReceiptAttestationTrustStore trust = await ReadTrustStoreAsync([roles.Backup, roles.Authorization, roles.Execution, roles.Provenance, roles.FinalEvidence], token).ConfigureAwait(false);
        var verification = new RecoveryAuthorityVerificationOptions(new(command.ExpectedSourceCommitSha, command.ExpectedRunnerDigestSha256),
            new(roles.Backup.KeyId, roles.Authorization.KeyId, roles.Execution.KeyId, roles.Provenance.KeyId, roles.FinalEvidence.KeyId), trust,
            TimeSpan.FromMinutes(command.MaximumObservationAgeMinutes));
        var verifier = new RecoveryAuthorityVerifier(verification);
        if (commandName == "finalize-local")
        {
            CompletedSnapshotDocument saved = await ReadProtectedJsonAsync<CompletedSnapshotDocument>(Required(command.CompletedSnapshotPath), "completed_snapshot_unprotected", token).ConfigureAwait(false);
            RecoveryJournalSnapshot completed = saved.ToSnapshot();
            byte[] completedKey = ReadIncrementalRootKey(command, environment);
            try
            {
                IncrementalMigrationResult result = await CompletedLocalMigrationFinalizer.FinalizeAsync(completed, verification,
                    command.ArtifactRoot, command.OutputDirectory, command.SnapshotId, completedKey, token).ConfigureAwait(false);
                await PublishIncrementalResultAsync(command, result, output, token).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(completedKey); }
            return;
        }

        InitialMigrationAdmission? admission = null;
        string backupJson, planJson, authorizationJson, restoreJson;
        if (initial)
        {
            backupJson = await ReadProtectedTextAsync(Required(command.ReceiptPath), "incremental_backup_unprotected", token).ConfigureAwait(false);
            planJson = await ReadProtectedTextAsync(Required(command.PlanPath), "incremental_plan_unprotected", token).ConfigureAwait(false);
            authorizationJson = await ReadProtectedTextAsync(Required(command.AuthorizationPath), "incremental_authorization_unprotected", token).ConfigureAwait(false);
            restoreJson = await ReadProtectedTextAsync(Required(command.VerifiedRestoreReceiptPath), "incremental_restore_unprotected", token).ConfigureAwait(false);
        }
        else
        {
            admission = InitialMigrationAdmission.Parse(await ReadProtectedTextAsync(Required(command.AdmissionPath), "incremental_admission_unprotected", token).ConfigureAwait(false));
            verifier.ValidateAdmission(admission, DateTimeOffset.UtcNow);
            if (!SamePath(command.ArtifactRoot, admission.Payload.LocalBinding.ArtifactRootCanonicalPath)) { throw Invalid("incremental_root_mismatch"); }
            backupJson = admission.Payload.OriginalBackupReceiptJson; planJson = admission.Payload.OriginalSchemaPlanJson;
            authorizationJson = admission.Payload.OriginalAuthorizationJson; restoreJson = admission.Payload.OriginalVerifiedRestoreReceiptJson;
        }
        BackupReceipt backup = ParseIncremental<BackupReceipt>(backupJson);
        FreshSchemaPlan plan = ParseIncremental<FreshSchemaPlan>(planJson);
        ExecutionAuthorizationReceipt authorization = ParseIncremental<ExecutionAuthorizationReceipt>(authorizationJson);
        VerifiedRestoreReceipt restore = ParseIncremental<VerifiedRestoreReceipt>(restoreJson);
        if (initial) { verifier.ValidateOriginalInputs(backupJson, planJson, authorizationJson, restoreJson, DateTimeOffset.UtcNow); }
        MigrationRunIdentity identity = MigrationRunIdentity.FromRequest(new(backup, plan, authorization));
        IncrementalReadOnlyRequest request = await ReadIncrementalRuntimeAsync(command, plan, restore, identity, authorization, verification, token).ConfigureAwait(false);
        IncrementalReadOnlyObservation observed = await runtime.ObserveAsync(request, token).ConfigureAwait(false);
        if (observed.Runner.RunnerDigestSha256 != command.ExpectedRunnerDigestSha256 ||
            !observed.Target.Target.IsHealthy || observed.Target.Target.Uid != authorization.TargetObservation!.Uid ||
            observed.Target.Target.Generation != authorization.TargetObservation.Generation || observed.Target.Target.SystemId != authorization.TargetObservation.SystemId)
        { throw Invalid("incremental_runtime_drift"); }
        if (commandName == "plan-incremental")
        {
            await WriteNewJsonAsync(command.OutputPath, new
            {
                status = "readonly_preflight_complete",
                identity,
                source = observed.Source,
                runner = observed.Runner,
                target = observed.Target,
                localCredentialAuthentication = "not_probed_readonly",
                initialAdmission = "requires_explicit_execution_held_binding"
            }, token).ConfigureAwait(false);
            await output.WriteLineAsync("readonly_preflight_complete").ConfigureAwait(false);
            return;
        }
        RecoveryJournalSnapshot? snapshot = null;
        SourceContinuityAttestation? continuity = null;
        if (!initial)
        {
            snapshot = await runtime.ReadSnapshotAsync(request, token).ConfigureAwait(false);
            if (snapshot.Admission.ExactJson != admission!.ExactJson) { throw Invalid("recovery_admission_mismatch"); }
            if (commandName == "plan-resume")
            {
                // Completed evidence is deliberately exportable without a new execution lease or signer.
                if (snapshot.Baseline.Status != "completed") { _ = verifier.GetPermittedOperations(admission, snapshot.Baseline, DateTimeOffset.UtcNow); }
                await WriteNewJsonAsync(command.OutputPath, CompletedSnapshotDocument.FromSnapshot(snapshot), token).ConfigureAwait(false);
                await output.WriteLineAsync("readonly_recovery_snapshot_complete").ConfigureAwait(false);
                return;
            }
            continuity = SourceContinuityAttestation.Parse(await ReadProtectedTextAsync(Required(command.ContinuityPath), "incremental_continuity_unprotected", token).ConfigureAwait(false));
            verifier.ValidateContinuity(admission, continuity, observed.Source, DateTimeOffset.UtcNow);
        }
        if (commandName == "authorize-resume")
        {
            using P256MigrationEvidenceSigner authorizer = await ReadIncrementalSignerAsync(environment, AuthorizationSigningKeyEnvironmentVariable, roles.Authorization, token).ConfigureAwait(false);
            using WindowsLocalRunAuthority held = WindowsLocalRunAuthority.AcquireResume(command.ArtifactRoot, admission!.Payload.LocalBinding);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            ResumeAuthorizationReceipt signed = verifier.PrepareResume(admission, continuity!, snapshot!.Baseline, observed.Source, held.Binding,
                observed.Runner, observed.Target, Guid.NewGuid(), now, command.ResumeExpiresAtUtc ?? throw Invalid("incremental_resume_expiry_required"), authorizer, now);
            await WriteExactRecoveryAsync(command.OutputPath, signed.ExactJson, token).ConfigureAwait(false);
            await output.WriteLineAsync("authorize_resume_complete").ConfigureAwait(false);
            return;
        }

        byte[] key = ReadIncrementalRootKey(command, environment);
        try
        {
            using P256MigrationEvidenceSigner signer = await ReadIncrementalSignerAsync(environment, ExecutionSigningKeyEnvironmentVariable, roles.Execution, token).ConfigureAwait(false);
            WindowsLocalRunAuthority? owned = null;
            try
            {
                if (initial)
                {
                    // Only explicit execution creates the permanent root/lock. Never adopt an abandoned setup.
                    owned = WindowsLocalRunAuthority.AcquireFresh(command.ArtifactRoot);
                    DateTimeOffset now = DateTimeOffset.UtcNow;
                    if (!ExecutionAuthorizationAttestation.TryCreatePayload(authorization, out byte[] approvalBytes) ||
                        !VerifiedRestoreReceiptAttestation.TryCreatePayload(restore, out byte[] restoreBytes)) { throw Invalid("incremental_original_evidence_invalid"); }
                    admission = verifier.PrepareAdmission(new(identity, DatabaseInventory.InventorySha256, backupJson, planJson, authorizationJson, restoreJson,
                        Digest(approvalBytes), Digest(restoreBytes), observed.Source, owned.Binding, now, RecoveryAuthorityVerifier.ValidationPolicyVersion,
                        verification.MaximumObservationAge!.Value, RecoveryAuthorityVerifier.ValidationStatement), signer, now);
                    // This copy is recovery input, not proof of a journal commit. Missing journal admission is explicit setup recovery.
                    await WriteExactRecoveryAsync(Required(command.AdmissionPath), admission.ExactJson, token).ConfigureAwait(false);
                }
                ResumeAuthorizationReceipt? resume = initial ? null : ResumeAuthorizationReceipt.Parse(await ReadProtectedTextAsync(
                    Required(command.ResumeAuthorizationPath), "incremental_resume_unprotected", token).ConfigureAwait(false));
                if (resume is not null)
                { verifier.ValidateResume(admission!, continuity!, resume, snapshot!.Baseline, observed.Source, admission!.Payload.LocalBinding, observed.Runner, observed.Target, DateTimeOffset.UtcNow); }
                IncrementalMigrationProgress progress = new(null, 0, 0, 0);
                await using AdmittedSequentialMigrationCoordinator coordinator = runtime.CreateExecution(new(admission!, verification, signer,
                    request.SourceConnectionString, request.Journal, request.ShadowAdministrativeConnectionString, request.Provisioning,
                    request.TargetObservation, request.LocalVerification, request.PgDumpPath, AppContext.BaseDirectory, command.SnapshotId, key, command.OutputDirectory),
                    value =>
                    {
                        progress = value;
                        // An unavailable diagnostic sink must not change commit/checkpoint outcomes.
                        try { output.WriteLine(JsonSerializer.Serialize(new { remoteCommitted = value.RemoteCommitted, downloaded = value.Downloaded, localVerified = value.LocalVerified })); }
                        catch (Exception) { /* The final awaited output still reports sink failure. */ }
                    });
                try
                {
                    Task<IncrementalMigrationResult> execution;
                    if (owned is not null) { execution = coordinator.ExecuteInitialAsync(owned, token); owned = null; }
                    else { execution = coordinator.ResumeAsync(continuity!, resume!, token); }
                    IncrementalMigrationResult result = await execution.ConfigureAwait(false);
                    await PublishIncrementalResultAsync(command, result, output, token).ConfigureAwait(false);
                }
                catch (Exception failure)
                {
                    try { await WriteProgressAsync(output, progress).ConfigureAwait(false); }
                    catch (Exception secondary) { failure.Data["console_progress_failure"] = secondary.GetType().Name; }
                    throw;
                }
            }
            finally { owned?.Dispose(); }
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static MigrationConsoleException Invalid(string code)
    {
        return new(code, "The protected incremental boundary is incomplete or mismatched; retained work was preserved.");
    }

    private static string Required(string? value)
    {
        return !string.IsNullOrWhiteSpace(value) ? value : throw Invalid("incremental_reference_required");
    }

    private static string Digest(byte[] value)
    {
        return Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
    }

    private static T ParseIncremental<T>(string json)
    {
        return OriginalMigrationDocumentReader.Read<T>(json);
    }

    private static async Task<P256MigrationEvidenceSigner> ReadIncrementalSignerAsync(Func<string, string?> environment, string variable, TrustedKeyReference role, CancellationToken token)
    {
        var signer = new P256MigrationEvidenceSigner(role.KeyId, await ReadProtectedTextAsync(Required(environment(variable)), "incremental_signing_key_unprotected", token).ConfigureAwait(false));
        try
        {
            SigningRoleTrust expected = await ReadSigningRoleAsync(role, token).ConfigureAwait(false);
            EnsureSignerMatchesRole(signer, expected, [], "incremental_signer_mismatch", "signing_role_key_reuse");
            return signer;
        }
        catch { signer.Dispose(); throw; }
    }

    private static byte[] ReadIncrementalRootKey(IncrementalCommandConfiguration command, Func<string, string?> environment)
    {
        string path = Required(environment(SnapshotKeyEnvironmentVariable));
        if (Within(path, command.ArtifactRoot) || Within(path, command.OutputDirectory)) { throw Invalid("incremental_key_inside_artifacts"); }
        using FileStream stream = OwnerProtectedFilePolicy.OpenRead(path, "snapshot_key_unprotected");
        try { return SnapshotRootKey.Load(stream); }
        catch (Exception failure) when (failure is InvalidOperationException or DecoderFallbackException)
        { throw Invalid("snapshot_key_invalid"); }
    }

    private static bool SamePath(string left, string right)
    {
        return string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)), Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)), StringComparison.OrdinalIgnoreCase);
    }

    private static bool Within(string child, string parent)
    {
        return SamePath(child, parent) || Path.GetFullPath(child).StartsWith(Path.TrimEndingDirectorySeparator(Path.GetFullPath(parent)) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static bool PathsOverlap(string left, string right)
    {
        return Within(left, right) || Within(right, left);
    }

    private static void ValidateIncrementalPaths(IncrementalCommandConfiguration command)
    {
        foreach (string path in new[] { command.ArtifactRoot, command.OutputDirectory, command.OutputPath })
        { ValidateIncrementalLocalPath(path); }
        if (PathsOverlap(command.OutputDirectory, command.ArtifactRoot) ||
            PathsOverlap(command.OutputPath, command.ArtifactRoot) || PathsOverlap(command.OutputPath, command.OutputDirectory) ||
            string.IsNullOrWhiteSpace(command.SnapshotId)) { throw Invalid("incremental_local_path_invalid"); }
        OwnerProtectedFilePolicy.ValidatePublicationParent(command.OutputPath);
    }

    private static void ValidateIncrementalLocalPath(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal) || Path.GetPathRoot(path) == path) { throw Invalid("incremental_local_path_invalid"); }
        // Stream and short-name notation must not disguise collisions with signed artifact paths.
        if (OperatingSystem.IsWindows() && (path.AsSpan(2).Contains(':') || path.Contains('~'))) { throw Invalid("incremental_local_path_invalid"); }
        for (DirectoryInfo? current = new(path); current is not null; current = current.Parent)
        { if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0) { throw Invalid("incremental_local_path_invalid"); } }
    }

    private static async Task PublishIncrementalResultAsync(IncrementalCommandConfiguration command, IncrementalMigrationResult result, TextWriter output, CancellationToken token)
    {
        var compatible = new MigrationExecutionResult(MigrationExecutionStatus.Completed, result.Receipt);
        if (File.Exists(command.OutputPath))
        {
            MigrationExecutionResult existing = await ReadProtectedJsonAsync<MigrationExecutionResult>(command.OutputPath, "incremental_result_unprotected", token).ConfigureAwait(false);
            if (JsonSerializer.Serialize(existing, JsonOptions) != JsonSerializer.Serialize(compatible, JsonOptions)) { throw Invalid("incremental_result_conflict"); }
        }
        else { await WriteNewJsonAsync(command.OutputPath, compatible, token).ConfigureAwait(false); }
        await WriteProgressAsync(output, result.Progress).ConfigureAwait(false);
        await output.WriteLineAsync("incremental_local_complete; remote_shadows_preserved; final_evidence_not_produced").ConfigureAwait(false);
    }

    private static Task WriteProgressAsync(TextWriter output, IncrementalMigrationProgress progress)
    {
        return output.WriteLineAsync(JsonSerializer.Serialize(
        new { remoteCommitted = progress.RemoteCommitted, downloaded = progress.Downloaded, localVerified = progress.LocalVerified }));
    }

    private static async Task WriteExactRecoveryAsync(string path, string text, CancellationToken token)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        await WriteNewContentAsync(path, stream => stream.WriteAsync(bytes, token).AsTask(), token).ConfigureAwait(false);
    }

    private static async Task<IncrementalReadOnlyRequest> ReadIncrementalRuntimeAsync(IncrementalCommandConfiguration command, FreshSchemaPlan plan,
        VerifiedRestoreReceipt restore, MigrationRunIdentity identity, ExecutionAuthorizationReceipt authorization, RecoveryAuthorityVerificationOptions verification, CancellationToken token)
    {
        IncrementalRuntimeConfiguration runtime = command.Runtime ?? throw Invalid("incremental_runtime_required");
        if (!Path.IsPathFullyQualified(runtime.PgDumpPath) || !File.Exists(runtime.PgDumpPath) ||
            !Path.IsPathFullyQualified(runtime.PgRestorePath) || !File.Exists(runtime.PgRestorePath) ||
            string.IsNullOrWhiteSpace(runtime.ExpectedControlRole) || string.IsNullOrWhiteSpace(runtime.ExpectedShadowAdminRole))
        { throw Invalid("incremental_runtime_required"); }
        string source = await ReadProtectedTextAsync(runtime.SourceConnectionFile, "incremental_connection_unprotected", token).ConfigureAwait(false);
        string control = await ReadProtectedTextAsync(runtime.ControlConnectionFile, "incremental_connection_unprotected", token).ConfigureAwait(false);
        string shadow = await ReadProtectedTextAsync(runtime.ShadowAdministrativeConnectionFile, "incremental_connection_unprotected", token).ConfigureAwait(false);
        string local = await ReadProtectedTextAsync(runtime.LocalAdministrativeConnectionFile, "incremental_connection_unprotected", token).ConfigureAwait(false);
        string restricted = await ReadProtectedTextAsync(runtime.LocalRestoreConnectionFile, "incremental_connection_unprotected", token).ConfigureAwait(false);
        CloudNativePgTargetObservation target = authorization.TargetObservation!;
        return new(source, new(control, ExpectedControlRole: runtime.ExpectedControlRole,
            CheckpointVerification: new(identity, plan, verification.TrustStore), RecoveryVerification: verification), shadow,
            new(runtime.KubernetesApiServer, runtime.KubernetesTokenFile, runtime.KubernetesCaFile),
            new(runtime.KubernetesApiServer, target.Namespace, target.Cluster, runtime.ExpectedShadowAdminRole, runtime.KubernetesTokenFile, runtime.KubernetesCaFile, TimeSpan.FromMinutes(5)),
            new(local, restricted, runtime.LocalContainerId, runtime.LocalImageId, runtime.LocalSystemIdentifier, runtime.PgRestorePath),
            runtime.PgDumpPath, restore, plan, identity, authorization, verification);
    }
}

internal sealed record IncrementalCommandConfiguration(
    string ArtifactRoot, string OutputDirectory, string SnapshotId, string OutputPath,
    string ExpectedSourceCommitSha, string ExpectedRunnerDigestSha256,
    string? ReceiptPath = null, string? PlanPath = null, string? AuthorizationPath = null,
    string? VerifiedRestoreReceiptPath = null, string? AdmissionPath = null, string? ContinuityPath = null,
    string? ResumeAuthorizationPath = null, string? CompletedSnapshotPath = null,
    IncrementalRuntimeConfiguration? Runtime = null, bool AllowExecution = false, bool AllowSigning = false,
    DateTimeOffset? ResumeExpiresAtUtc = null, double MaximumObservationAgeMinutes = 60);

internal sealed record IncrementalRuntimeConfiguration(string SourceConnectionFile, string ControlConnectionFile,
    string ShadowAdministrativeConnectionFile, string LocalAdministrativeConnectionFile, string LocalRestoreConnectionFile,
    string ExpectedControlRole, string ExpectedShadowAdminRole, string PgDumpPath, string PgRestorePath,
    string LocalContainerId, string LocalImageId, string LocalSystemIdentifier,
    Uri KubernetesApiServer, string KubernetesTokenFile, string KubernetesCaFile);

internal sealed record IncrementalReadOnlyRequest(string SourceConnectionString, PostgreSqlMigrationRunJournalOptions Journal,
    string ShadowAdministrativeConnectionString, CloudNativePgTargetObserverOptions TargetObservation,
    CloudNativePgShadowDatabaseProvisionerOptions Provisioning, LocalPostgreSqlArchiveVerificationOptions LocalVerification,
    string PgDumpPath, VerifiedRestoreReceipt Restore, FreshSchemaPlan Plan, MigrationRunIdentity Identity,
    ExecutionAuthorizationReceipt Authorization, RecoveryAuthorityVerificationOptions Verification);

internal sealed record IncrementalReadOnlyObservation(RestoredSourceObservation Source, FreshRunnerObservation Runner, FreshTargetObservation Target);

internal sealed record CompletedSnapshotDocument(string AdmissionJson, RecoveryJournalBaseline Baseline, DateTimeOffset ObservedAtUtc, DateTimeOffset? LeaseExpiresAtUtc)
{
    internal RecoveryJournalSnapshot ToSnapshot()
    {
        return new(InitialMigrationAdmission.Parse(AdmissionJson), Baseline, ObservedAtUtc, LeaseExpiresAtUtc);
    }

    internal static CompletedSnapshotDocument FromSnapshot(RecoveryJournalSnapshot snapshot)
    {
        return new(snapshot.Admission.ExactJson, snapshot.Baseline, snapshot.ObservedAtUtc, snapshot.LeaseExpiresAtUtc);
    }
}

internal interface IIncrementalConsoleRuntime
{
    Task<IncrementalReadOnlyObservation> ObserveAsync(IncrementalReadOnlyRequest request, CancellationToken token);
    Task<RecoveryJournalSnapshot> ReadSnapshotAsync(IncrementalReadOnlyRequest request, CancellationToken token);
    AdmittedSequentialMigrationCoordinator CreateExecution(AdmittedCoordinatorHostOptions options, Action<IncrementalMigrationProgress> progress);
}

internal sealed class DefaultIncrementalConsoleRuntime : IIncrementalConsoleRuntime
{
    public async Task<IncrementalReadOnlyObservation> ObserveAsync(IncrementalReadOnlyRequest request, CancellationToken token)
    {
        using CloudNativePgTargetObserver observer = CloudNativePgTargetObserver.CreateForHost(request.TargetObservation);
        var control = new RemotePostgreSqlHostBoundary(request.Journal.ConnectionString, request.Authorization.TargetObservation!, observer);
        var shadow = new RemotePostgreSqlHostBoundary(request.ShadowAdministrativeConnectionString, request.Authorization.TargetObservation!, observer);
        await control.VerifyEndpointAsync(new Npgsql.NpgsqlConnectionStringBuilder(request.Journal.ConnectionString).Database!, token).ConfigureAwait(false);
        await shadow.VerifyEndpointAsync(new Npgsql.NpgsqlConnectionStringBuilder(request.ShadowAdministrativeConnectionString).Database!, token).ConfigureAwait(false);
        _ = await PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(request.Journal.ConnectionString, request.ShadowAdministrativeConnectionString,
            request.Journal.ExpectedControlRole!, request.Provisioning.OwnerRole, token).ConfigureAwait(false);
        var local = new LocalPostgreSqlArchiveVerifier(request.LocalVerification, new(request.Identity, request.Plan, request.Verification.TrustStore));
        await local.PreflightAsync(token).ConfigureAwait(false);
        RestoredSourceObservation source = await new DockerSqlRestoredSourceObserver(request.Verification.TrustStore)
            .ObserveAsync(request.SourceConnectionString, request.Restore, request.Plan, token).ConfigureAwait(false);
        RunnerArtifactManifest manifest = await RunnerArtifactManifestMeasurer.MeasureAsync(AppContext.BaseDirectory, token).ConfigureAwait(false);
        CloudNativePgTargetObservation target = await observer.ObserveAsync(request.Provisioning.Namespace, request.Provisioning.Cluster, token).ConfigureAwait(false);
        return new(source, new(DateTimeOffset.UtcNow, manifest.ManifestSha256), new(DateTimeOffset.UtcNow, target));
    }

    public async Task<RecoveryJournalSnapshot> ReadSnapshotAsync(IncrementalReadOnlyRequest request, CancellationToken token)
    {
        using CloudNativePgTargetObserver observer = CloudNativePgTargetObserver.CreateForHost(request.TargetObservation);
        var journal = new PostgreSqlMigrationRunJournal(request.Journal with
        { HostBoundary = new RemotePostgreSqlHostBoundary(request.Journal.ConnectionString, request.Authorization.TargetObservation!, observer) });
        return await journal.ReadRecoverySnapshotAsync(request.Identity, token).ConfigureAwait(false);
    }

    public AdmittedSequentialMigrationCoordinator CreateExecution(AdmittedCoordinatorHostOptions options, Action<IncrementalMigrationProgress> progress)
    {
        return AdmittedSequentialMigrationCoordinator.CreateForHost(options, progress);
    }
}
