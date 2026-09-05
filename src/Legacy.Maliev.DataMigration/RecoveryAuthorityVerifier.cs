using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using static Legacy.Maliev.DataMigration.RecoveryContractEncoding;

namespace Legacy.Maliev.DataMigration;

/// <summary>Pure contract verification. No lease, nonce consumption, source history proof, or runtime observation is implied.</summary>
public sealed class RecoveryAuthorityVerifier
{
    public const string ValidationPolicyVersion = "fresh-admission-v1";
    public const string ValidationStatement = "Original backup, plan and execution authorization passed fresh gates; exact restored source is read-only and bound to the permanent local execution authority.";
    public const string ContinuityStatementVersion = "source-continuity-v1";
    public const string ContinuityStatement = "Throughout the complete admitted interval, data, schema, identity-sequence and restore state remained unchanged; no write-enabled transition, replacement, re-restore, detach-attach or redirection occurred.";
    public const string RunnerCompatibilityPolicyVersion = "runner-compatibility-v1";
    public const string RunnerCompatibilityStatement = "This one-run recovery may use only the explicitly measured replacement runner while retaining the immutable admitted run identity, checkpoints, source, target and local binding.";

    private readonly GuardedRunnerPolicy _runnerPolicy;
    private readonly GuardedRunnerPolicy? _recoveryRunnerPolicy;
    private readonly RecoveryAuthorityRoles _roles;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly ImmutableDictionary<string, string> _fingerprints;
    private readonly TimeSpan _observationAge;

    public RecoveryAuthorityVerifier(RecoveryAuthorityVerificationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.RunnerPolicy);
        ArgumentNullException.ThrowIfNull(options.Roles);
        ArgumentNullException.ThrowIfNull(options.TrustStore);
        _runnerPolicy = options.RunnerPolicy;
        _recoveryRunnerPolicy = options.RecoveryRunnerPolicy;
        _roles = options.Roles;
        _trust = options.TrustStore;
        _observationAge = options.MaximumObservationAge ?? GuardedRunnerPolicy.MaximumAuthorizationLifetime;
        if (_recoveryRunnerPolicy is not null)
        {
            Require(Hex(_recoveryRunnerPolicy.ExpectedSourceCommitSha, 40) && Hex(_recoveryRunnerPolicy.ExpectedRunnerDigestSha256, 64),
                "The explicitly approved recovery runner policy is malformed.");
        }
        Require(_observationAge > TimeSpan.Zero && _observationAge <= GuardedRunnerPolicy.MaximumAuthorizationLifetime,
            "Observation freshness must be positive and no longer than the existing authorization lifetime.");
        string[] ids = [_roles.BackupKeyId, _roles.AuthorizationKeyId, _roles.ExecutionKeyId, _roles.ProvenanceKeyId, _roles.FinalEvidenceKeyId];
        Require(ids.All(id => !string.IsNullOrWhiteSpace(id)) && ids.Distinct(StringComparer.Ordinal).Count() == ids.Length,
            "Backup, authorization, execution, provenance and final-evidence key IDs must remain distinct.");
        var keys = ImmutableDictionary.CreateBuilder<string, string>(StringComparer.Ordinal);
        foreach (string id in ids)
        {
            Require(_trust.ContainsKey(id) && _trust.TryGetPublicKeyFingerprintSha256(id, out _), "A configured authority key is not explicitly trusted.");
            _ = _trust.TryGetPublicKeyFingerprintSha256(id, out string fingerprint);
            Require(Hex(fingerprint, 64), "A configured authority key fingerprint is malformed.");
            keys.Add(id, fingerprint.ToLowerInvariant());
        }
        Require(keys.Values.Distinct(StringComparer.Ordinal).Count() == ids.Length, "Signing roles must use distinct key material, not aliases.");
        _fingerprints = keys.ToImmutable();
    }

    /// <summary>Revalidates the originals at admittedAt, not now. It does not extend the original authorization.</summary>
    public void ValidateAdmission(InitialMigrationAdmission admission, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(admission);
        ValidateTrust();
        admission.Verify(_trust, _roles.ExecutionKeyId);
        ValidateAdmissionPayload(admission.Payload, nowUtc);
    }

    /// <summary>4c2 must use this at the fresh post-lock server clock before first persistence, never historical validation alone.</summary>
    public void ValidateInitialAcquisition(InitialMigrationAdmission admission, RestoredSourceObservation source, LocalExecutionBinding localBinding, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(localBinding);
        ValidateAdmission(admission, nowUtc);
        // Check unchanged original gates again at the actual acquisition time without rewriting the signed document.
        ValidateAdmissionPayload(admission.Payload with { AdmittedAtUtc = nowUtc }, nowUtc);
        ValidateSource(source, admission.Payload, nowUtc);
        Require(localBinding == admission.Payload.LocalBinding && source.ComputeStableStateSha256() == admission.Payload.SourceObservation.ComputeStableStateSha256(),
            "Fresh acquisition no longer matches the admitted permanent local binding or source state.");
    }

    /// <summary>Call only with freshly observed source and a held Windows local authority; persist atomically with first lease.</summary>
    public InitialMigrationAdmission PrepareAdmission(InitialMigrationAdmissionPayload payload, IMigrationEvidenceSigner signer, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(payload);
        // Freeze before gates and before invoking a caller-supplied signer.
        payload = Parse<InitialMigrationAdmissionPayload>(Serialize(payload));
        ValidateSigner(signer, _roles.ExecutionKeyId);
        Require(payload.AdmittedAtUtc == nowUtc, "Initial admission must use the current acquisition clock, not a backdated approval.");
        ValidateAdmissionPayload(payload, nowUtc);
        InitialMigrationAdmission signed = InitialMigrationAdmission.Sign(payload, signer);
        ValidateAdmission(signed, nowUtc);
        return signed;
    }

    /// <summary>Pure pre-lock original-input validation. Does not observe runtime, sign, create local state or grant execution authority.</summary>
    public void ValidateOriginalInputs(string backupJson, string planJson, string authorizationJson, string restoreJson, DateTimeOffset nowUtc)
    {
        ValidateTrust();
        _ = ValidateOriginalDocuments(backupJson, planJson, authorizationJson, restoreJson, nowUtc);
    }

    private void ValidateAdmissionPayload(InitialMigrationAdmissionPayload value, DateTimeOffset nowUtc)
    {
        Require(Utc(nowUtc) && Utc(value.AdmittedAtUtc) && value.AdmittedAtUtc <= nowUtc &&
            value.ValidationPolicyVersion == ValidationPolicyVersion && value.ValidationStatement == ValidationStatement && value.MaximumObservationAge == _observationAge,
            "Admission time, validation policy, freshness limit or acceptance statement is invalid.");
        ValidateIdentity(value.Identity);
        Require(value.InventorySha256 == DatabaseInventory.InventorySha256, "Admission must bind the exact approved inventory.");
        (BackupReceipt backup, FreshSchemaPlan plan, ExecutionAuthorizationReceipt authorization, VerifiedRestoreReceipt restore) =
            ValidateOriginalDocuments(value.OriginalBackupReceiptJson, value.OriginalSchemaPlanJson, value.OriginalAuthorizationJson,
                value.OriginalVerifiedRestoreReceiptJson, value.AdmittedAtUtc);
        Require(value.Identity == MigrationRunIdentity.FromRequest(new(backup, plan, authorization)), "Admission identity does not match all original inputs.");
        Require(ExecutionAuthorizationAttestation.TryCreatePayload(authorization, out byte[] authorizationBytes) &&
            value.OriginalAuthorizationSha256 == Hash(authorizationBytes), "Original authorization digest is mismatched.");
        Require(restore.RestoredAtUtc <= value.SourceObservation.ObservedAtUtc, "The restore postdates the admitted source observation.");
        Require(VerifiedRestoreReceiptAttestation.TryCreatePayload(restore, out byte[] restoreBytes) && value.VerifiedRestoreSha256 == Hash(restoreBytes),
            "Verified restore payload digest is mismatched.");
        ValidateLocalBinding(value.LocalBinding);
        ValidateSource(value.SourceObservation, value, value.AdmittedAtUtc);
        VerifiedRestoreResourceEvidence resources = restore.Resources;
        LocalDockerResourceState docker = value.SourceObservation.State.Docker;
        Require(docker.ContainerId == resources.ContainerId && docker.ContainerName == resources.ContainerName && docker.Image.Id == resources.SqlServerImageId &&
            docker.RunBinding == resources.RunBinding && docker.Mounts.Any(mount => mount.Destination == resources.MountPath && !mount.ReadWrite &&
                mount.Name == resources.VolumeName && mount.Volume.Name == resources.VolumeId && mount.Volume.RunBinding == resources.RunBinding &&
                mount.Volume.VolumeBinding == resources.VolumeBinding && mount.Volume.Fingerprint == resources.VolumeFingerprint),
            "The admission observation differs from the signed restore resource binding.");
    }

    private (BackupReceipt, FreshSchemaPlan, ExecutionAuthorizationReceipt, VerifiedRestoreReceipt) ValidateOriginalDocuments(
        string backupJson, string planJson, string authorizationJson, string restoreJson, DateTimeOffset nowUtc)
    {
        Require(Utc(nowUtc), "Original-input validation requires a current UTC clock.");
        BackupReceipt backup = OriginalMigrationDocumentReader.Read<BackupReceipt>(backupJson);
        FreshSchemaPlan plan = OriginalMigrationDocumentReader.Read<FreshSchemaPlan>(planJson);
        ExecutionAuthorizationReceipt authorization = OriginalMigrationDocumentReader.Read<ExecutionAuthorizationReceipt>(authorizationJson);
        VerifiedRestoreReceipt restore = OriginalMigrationDocumentReader.Read<VerifiedRestoreReceipt>(restoreJson);
        Require(backup.AttestationKeyId == _roles.BackupKeyId && authorization.AttestationKeyId == _roles.AuthorizationKeyId && restore.AttestationKeyId == _roles.ProvenanceKeyId,
            "The retained original documents do not use their configured signing roles.");
        try { VerifiedBackupRestorer.ValidateReceipt(backup, _trust, nowUtc, GuardedRunnerPolicy.MaximumBackupReceiptAge); }
        catch (Exact25FullBackupException exception) { throw Invalid("Original backup freshness or attestation failed at admission time.", exception); }
        Require(Utc(plan.CapturedAtUtc) && SchemaPlanCanonicalizer.Validate(plan, _runnerPolicy, nowUtc, GuardedRunnerPolicy.MaximumSchemaPlanAge).Count == 0,
            "The original plan did not pass the unchanged fresh-plan gates at admission.");
        Require(authorization.SchemaVersion == "2.1" && Utc(authorization.IssuedAtUtc) && Utc(authorization.ExpiresAtUtc) &&
            ExecutionAuthorizationValidator.Validate(authorization, plan, backup, _runnerPolicy, nowUtc, _trust).Count == 0,
            "The original authorization did not pass the unchanged approval gates at admission.");
        Require(VerifiedRestoreReceiptAttestation.Verify(restore, _trust) && restore.CleanupDisposition == RestoreCleanupDisposition.Pending &&
            restore.BackupManifestSha256 == backup.ManifestSha256 && restore.DatabaseInventorySha256 == DatabaseInventory.InventorySha256 &&
            Utc(restore.RestoredAtUtc) && restore.RestoredAtUtc >= backup.CapturedAtUtc && restore.RestoredAtUtc <= nowUtc,
            "The original verified restore is not bound to the admitted backup and source.");
        Require(restore.Artifacts.All(item => backup.Artifacts!.Any(original => original!.Database == item.Database && original.ByteLength == item.RetainedByteLength &&
            string.Equals(original.Sha256, item.RetainedSha256, StringComparison.OrdinalIgnoreCase))), "Restore artifacts differ from the signed backup artifacts.");
        return (backup, plan, authorization, restore);
    }

    public void ValidateContinuity(InitialMigrationAdmission admission, SourceContinuityAttestation continuity, RestoredSourceObservation independentlyObservedSource, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(continuity);
        ArgumentNullException.ThrowIfNull(independentlyObservedSource);
        ValidateAdmission(admission, nowUtc);
        continuity.Verify(_trust, _roles.ProvenanceKeyId);
        SourceContinuityPayload value = continuity.Payload;
        InitialMigrationAdmissionPayload original = admission.Payload;
        ValidateWindow(value.IssuedAtUtc, value.ExpiresAtUtc, nowUtc);
        Require(value.Nonce != Guid.Empty && value.RunIdentitySha256 == ComputeIdentitySha256(original.Identity) && value.AdmissionSha256 == admission.ComputeSha256() &&
            value.VerifiedRestoreSha256 == original.VerifiedRestoreSha256 && value.InventorySha256 == original.InventorySha256 &&
            value.InitialObservationSha256 == original.SourceObservation.ComputeSha256(), "Continuity identity, nonce or original digests are mismatched.");
        Require(value.StatementVersion == ContinuityStatementVersion && value.Statement == ContinuityStatement &&
            value.ContinuousFromUtc == original.AdmittedAtUtc && Utc(value.ContinuousFromUtc) && Utc(value.ContinuousThroughUtc) &&
            value.ContinuousThroughUtc == value.CurrentObservation.ObservedAtUtc && value.ContinuousThroughUtc >= value.ContinuousFromUtc &&
            value.IssuedAtUtc >= value.ContinuousThroughUtc,
            "External provenance must explicitly assert the complete interval through the signed current observation.");
        ValidateSource(value.CurrentObservation, original, nowUtc);
        ValidateSource(independentlyObservedSource, original, nowUtc);
        Require(independentlyObservedSource.ObservedAtUtc >= original.AdmittedAtUtc &&
            value.CurrentObservationSha256 == value.CurrentObservation.ComputeSha256() && value.StableSourceStateSha256 == original.SourceObservation.ComputeStableStateSha256() &&
            value.StableSourceStateSha256 == value.CurrentObservation.ComputeStableStateSha256() && value.StableSourceStateSha256 == independentlyObservedSource.ComputeStableStateSha256(),
            "The timestamped signed observation or independently repeated stable source state is mismatched.");
    }

    public ImmutableArray<PermittedDatabaseRecovery> GetPermittedOperations(InitialMigrationAdmission admission, RecoveryJournalBaseline baseline, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ValidateAdmission(admission, nowUtc);
        _ = baseline.ComputeSha256();
        Require(baseline.Identity == admission.Payload.Identity && baseline.AdmissionSha256 == admission.ComputeSha256() && baseline.Status is "failed" or "in_progress" &&
            !string.IsNullOrWhiteSpace(baseline.LeaseOwner) && baseline.LeaseAttempt >= 1 && baseline.FencingToken is not null && baseline.FencingToken != Guid.Empty,
            "The journal baseline is unadmitted, completed or does not match the immutable run.");
        _ = Parse<JsonElement[]>(baseline.FailureHistoryJson);
        Require(baseline.Shadows.Select(item => item.Shadow.Name).Distinct(StringComparer.Ordinal).Count() == baseline.Shadows.Length &&
            baseline.Shadows.Select(item => item.Shadow.Database).Distinct(StringComparer.Ordinal).Count() == baseline.Shadows.Length &&
            baseline.Checkpoints.Select(item => item.Database).Distinct(StringComparer.Ordinal).Count() == baseline.Checkpoints.Length,
            "The recovery baseline contains duplicate checkpoint or shadow ownership.");
        foreach (RecoveryShadowState item in baseline.Shadows)
        {
            ShadowDatabase shadow = item.Shadow;
            Require(DatabaseInventory.ActiveDatabases.Contains(shadow.Database, StringComparer.Ordinal) && shadow.OwnerRunId == baseline.Identity.RunId.ToString("D") &&
                shadow.Name == GuardedShadowMigrationRunner.CreateShadowName(shadow.Database, baseline.Identity.RunId) && shadow.OwnerAttempt is > 0 &&
                shadow.OwnerAttempt <= baseline.LeaseAttempt && shadow.FencingToken != Guid.Empty && item.CleanupStatus is "pending" or "failed" && item.CleanupAttempts >= 0,
                "Recovery requires retained original owned shadows; deleted, relabeled or conflicting state cannot be adopted.");
        }
        var verifier = new DatabaseMigrationCheckpointVerifier(new(baseline.Identity, OriginalMigrationDocumentReader.Read<FreshSchemaPlan>(admission.Payload.OriginalSchemaPlanJson), _trust));
        foreach (RecoveryCheckpointState item in baseline.Checkpoints)
        {
            DatabaseMigrationCheckpoint checkpoint = Parse<DatabaseMigrationCheckpoint>(item.SignedCheckpointJson);
            Require(item.Database == checkpoint.Database.Database && checkpoint.AttestationKeyId == _roles.ExecutionKeyId && checkpoint.CommittedAtUtc <= nowUtc &&
                checkpoint.CommittedAtUtc >= admission.Payload.AdmittedAtUtc &&
                Encoding.UTF8.GetString(MigrationEvidenceAttestation.SerializeCheckpoint(checkpoint)) == item.SignedCheckpointJson,
                "Checkpoint index, exact canonical signed bytes, signing role or commit time is invalid.");
            RecoveryShadowState? registered = baseline.Shadows.SingleOrDefault(shadow => shadow.Shadow.Database == item.Database);
            Require(registered is not null, "A signed checkpoint must retain its original shadow ownership.");
            verifier.Validate(checkpoint, registered!.Shadow);
        }
        return DatabaseInventory.ActiveDatabases.Select(database => new PermittedDatabaseRecovery(database,
            baseline.Checkpoints.Any(item => item.Database == database) ? RecoveryDatabaseOperation.RevalidateCheckpointAndDeliver :
            baseline.Shadows.Any(item => item.Shadow.Database == database) ? RecoveryDatabaseOperation.ReconcileOwnedShadowAndReuseOnlyIfEmpty :
            RecoveryDatabaseOperation.CreateCopyAndDeliver)).ToImmutableArray();
    }

    /// <summary>Requires external continuity. Signing this document does not consume its nonce or acquire a lease.</summary>
    public ResumeAuthorizationReceipt PrepareResume(InitialMigrationAdmission admission, SourceContinuityAttestation continuity, RecoveryJournalBaseline baseline, RestoredSourceObservation source, LocalExecutionBinding localBinding, FreshRunnerObservation runner, FreshTargetObservation target, Guid nonce, DateTimeOffset issuedAtUtc, DateTimeOffset expiresAtUtc, IMigrationEvidenceSigner signer, DateTimeOffset nowUtc)
    {
        return PrepareResumeCore(admission, continuity, baseline, source, localBinding, runner, target, nonce, issuedAtUtc, expiresAtUtc, signer, nowUtc, compatibleRunner: false);
    }

    /// <summary>Signs an explicit old-to-new runner exception for this admitted run; ordinary resume never infers compatibility.</summary>
    public ResumeAuthorizationReceipt PrepareCompatibleResume(InitialMigrationAdmission admission, SourceContinuityAttestation continuity, RecoveryJournalBaseline baseline, RestoredSourceObservation source, LocalExecutionBinding localBinding, FreshRunnerObservation runner, FreshTargetObservation target, Guid nonce, DateTimeOffset issuedAtUtc, DateTimeOffset expiresAtUtc, IMigrationEvidenceSigner signer, DateTimeOffset nowUtc)
    {
        return PrepareResumeCore(admission, continuity, baseline, source, localBinding, runner, target, nonce, issuedAtUtc, expiresAtUtc, signer, nowUtc, compatibleRunner: true);
    }

    private ResumeAuthorizationReceipt PrepareResumeCore(InitialMigrationAdmission admission, SourceContinuityAttestation continuity, RecoveryJournalBaseline baseline, RestoredSourceObservation source, LocalExecutionBinding localBinding, FreshRunnerObservation runner, FreshTargetObservation target, Guid nonce, DateTimeOffset issuedAtUtc, DateTimeOffset expiresAtUtc, IMigrationEvidenceSigner signer, DateTimeOffset nowUtc, bool compatibleRunner)
    {
        ArgumentNullException.ThrowIfNull(continuity);
        ValidateSigner(signer, _roles.AuthorizationKeyId);
        RecoveryRunnerCompatibility? compatibility = compatibleRunner
            ? _recoveryRunnerPolicy is null
                ? throw Invalid("Explicit compatible resume requires a reviewed replacement runner policy.")
                : new(RunnerCompatibilityPolicyVersion, RunnerCompatibilityStatement, admission.Payload.Identity.RunnerDigestSha256,
                    _recoveryRunnerPolicy.ExpectedSourceCommitSha, _recoveryRunnerPolicy.ExpectedRunnerDigestSha256)
            : null;
        var payload = new ResumeAuthorizationPayload(admission.Payload.Identity, admission.ComputeSha256(), continuity.ComputeSha256(), baseline.ComputeSha256(),
            localBinding.ComputeSha256(), runner, target, GetPermittedOperations(admission, baseline, nowUtc), nonce, issuedAtUtc, expiresAtUtc);
        payload = payload with { RunnerCompatibility = compatibility };
        ValidateResumePayload(admission, continuity, payload, baseline, source, localBinding, runner, target, nowUtc);
        ResumeAuthorizationReceipt signed = ResumeAuthorizationReceipt.Sign(payload, signer);
        ValidateResume(admission, continuity, signed, baseline, source, localBinding, runner, target, nowUtc);
        return signed;
    }

    /// <summary>4c2 must call again after locking the real run row using fresh server time and that transaction's exact baseline.</summary>
    public void ValidateResume(InitialMigrationAdmission admission, SourceContinuityAttestation continuity, ResumeAuthorizationReceipt resume, RecoveryJournalBaseline lockedBaseline, RestoredSourceObservation source, LocalExecutionBinding localBinding, FreshRunnerObservation runner, FreshTargetObservation target, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(resume);
        ValidateTrust();
        resume.Verify(_trust, _roles.AuthorizationKeyId);
        ValidateResumePayload(admission, continuity, resume.Payload, lockedBaseline, source, localBinding, runner, target, nowUtc);
    }

    private void ValidateResumePayload(InitialMigrationAdmission admission, SourceContinuityAttestation continuity, ResumeAuthorizationPayload value, RecoveryJournalBaseline baseline,
        RestoredSourceObservation source, LocalExecutionBinding localBinding, FreshRunnerObservation runner, FreshTargetObservation target, DateTimeOffset nowUtc)
    {
        ValidateContinuity(admission, continuity, source, nowUtc);
        ValidateWindow(value.IssuedAtUtc, value.ExpiresAtUtc, nowUtc);
        InitialMigrationAdmissionPayload original = admission.Payload;
        Require(value.Identity == original.Identity && value.AdmissionSha256 == admission.ComputeSha256() && value.ContinuitySha256 == continuity.ComputeSha256() &&
            value.BaselineSha256 == baseline.ComputeSha256() && value.LocalBindingSha256 == original.LocalBinding.ComputeSha256() && localBinding == original.LocalBinding &&
            value.Nonce != Guid.Empty && value.Nonce != continuity.Payload.Nonce && value.IssuedAtUtc >= continuity.Payload.IssuedAtUtc && value.ExpiresAtUtc <= continuity.Payload.ExpiresAtUtc,
            "Fresh resume identity, approved baseline, local binding, nonce or continuity window is mismatched.");
        ValidateObservationTime(value.Runner.ObservedAtUtc, nowUtc);
        ValidateObservationTime(value.Target.ObservedAtUtc, nowUtc);
        ValidateObservationTime(runner.ObservedAtUtc, nowUtc);
        ValidateObservationTime(target.ObservedAtUtc, nowUtc);
        RecoveryRunnerCompatibility? compatibility = value.RunnerCompatibility;
        string expectedRunnerDigest;
        if (compatibility is null)
        {
            expectedRunnerDigest = original.Identity.RunnerDigestSha256;
        }
        else
        {
            Require(_recoveryRunnerPolicy is not null &&
                compatibility.PolicyVersion == RunnerCompatibilityPolicyVersion && compatibility.Statement == RunnerCompatibilityStatement &&
                compatibility.AdmittedRunnerDigestSha256 == original.Identity.RunnerDigestSha256 &&
                compatibility.ReplacementSourceCommitSha == _recoveryRunnerPolicy.ExpectedSourceCommitSha &&
                compatibility.ReplacementRunnerDigestSha256 == _recoveryRunnerPolicy.ExpectedRunnerDigestSha256 &&
                compatibility.ReplacementRunnerDigestSha256 != compatibility.AdmittedRunnerDigestSha256,
                "The signed compatible recovery runner exception is absent, malformed or mismatched.");
            expectedRunnerDigest = compatibility.ReplacementRunnerDigestSha256;
        }
        Require(value.Runner.ObservedAtUtc <= value.IssuedAtUtc && value.Target.ObservedAtUtc <= value.IssuedAtUtc &&
            value.Runner.ObservedAtUtc >= original.AdmittedAtUtc && value.Target.ObservedAtUtc >= original.AdmittedAtUtc &&
            runner.ObservedAtUtc >= original.AdmittedAtUtc && target.ObservedAtUtc >= original.AdmittedAtUtc &&
            value.Runner.RunnerDigestSha256 == expectedRunnerDigest && runner.RunnerDigestSha256 == value.Runner.RunnerDigestSha256,
            "Resume requires a newly measured unchanged runner and fresh target observation.");
        CloudNativePgTargetObservation originalTarget = OriginalMigrationDocumentReader.Read<ExecutionAuthorizationReceipt>(original.OriginalAuthorizationJson).TargetObservation!;
        CloudNativePgTargetObservation signedTarget = value.Target.Target;
        Require(signedTarget.IsHealthy && target.Target.SameRuntimeTarget(signedTarget) && signedTarget.SameRuntimeTarget(originalTarget),
            "The signed and independently observed target do not match the original healthy target identity.");
        ImmutableArray<PermittedDatabaseRecovery> expected = GetPermittedOperations(admission, baseline, nowUtc);
        Require(!value.PermittedOperations.IsDefault && value.PermittedOperations.SequenceEqual(expected),
            "The resume approval must permit exactly the baseline-derived recovery operations in inventory order.");
    }

    private void ValidateSource(RestoredSourceObservation source, InitialMigrationAdmissionPayload original, DateTimeOffset nowUtc)
    {
        ValidateObservationTime(source.ObservedAtUtc, nowUtc);
        RestoredSourceState state = source.State;
        Require(state.VerifiedRestoreSha256 == original.VerifiedRestoreSha256 && state.SchemaPlanSha256 == original.Identity.SchemaPlanSha256 && state.InventorySha256 == original.InventorySha256 &&
            state.Sql.CompleteMetadataVisibility && !state.Sql.Databases.IsDefaultOrEmpty && state.Sql.Databases.All(item => item is not null) &&
            state.Sql.Databases.Select(item => item.Name).Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) &&
            state.Sql.Databases.All(item => item.ReadOnly && item.SnapshotIsolationState == 1 && item.State == 0 && item.DatabaseGuid != Guid.Empty && item.DatabaseId > 4) &&
            state.Sql.Databases.Select(item => item.DatabaseId).Distinct().Count() == state.Sql.Databases.Length,
            "Source observation must retain the exact plan, restore, inventory, database identities and read-only state.");
        Require(!state.Docker.Mounts.IsDefault && !state.Docker.Ports.IsDefaultOrEmpty && !state.Docker.Networks.IsDefaultOrEmpty && !state.Sql.Files.IsDefaultOrEmpty && !state.Files.IsDefaultOrEmpty &&
            state.Sql.Files.All(item => item is not null) && state.Files.All(item => item is not null) &&
            state.Sql.Files.All(file => state.Files.Count(binding => binding.File == file) == 1) && state.Files.Length == state.Sql.Files.Length &&
            state.Sql.Databases.All(database => state.Sql.Files.Any(file => file.DatabaseId == database.DatabaseId && file.Type == 0)) &&
            state.Sql.Files.All(file => state.Sql.Databases.Any(database => database.DatabaseId == file.DatabaseId) && file.FileId > 0 && file.Type is 0 or 1) &&
            state.Sql.Files.Select(file => (file.DatabaseId, file.FileId)).Distinct().Count() == state.Sql.Files.Length &&
            state.Docker.Ports.Any(port => port.HostAddress == "127.0.0.1" && port.ContainerPort == state.Sql.LocalPort &&
                state.ConfiguredEndpoint == "tcp:127.0.0.1," + port.HostPort.ToString(System.Globalization.CultureInfo.InvariantCulture)) &&
            state.Docker.Networks.Any(network => network.Address == state.Sql.LocalAddress) && state.Sql.MachineName == state.Docker.Hostname && state.Sql.ServerName == state.Docker.Hostname && state.Sql.ProductMajorVersion == "16",
            "Source endpoint, Docker resource or complete database file binding is invalid.");
    }

    private void ValidateIdentity(MigrationRunIdentity identity)
    {
        Require(identity.RunId != Guid.Empty && Hex(identity.SourceCommitSha, 40) && Hex(identity.SchemaPlanSha256, 64) && Hex(identity.BackupManifestSha256, 64) &&
            Hex(identity.RunnerDigestSha256, 64) && !string.IsNullOrWhiteSpace(identity.TargetGeneration) && identity.SourceCommitSha == _runnerPolicy.ExpectedSourceCommitSha &&
            identity.RunnerDigestSha256 == _runnerPolicy.ExpectedRunnerDigestSha256, "The immutable run identity differs from the approved executable or is malformed.");
    }
    private static void ValidateLocalBinding(LocalExecutionBinding binding)
    {
        Require(binding.LocalExecutionBindingVersion == 1 && binding.LockProtocolVersion == 1 && binding.RunLockRelativeName == WindowsLocalRunAuthority.RunLockRelativeName &&
            new[] { binding.HostIdentity, binding.LocalVolumeIdentity, binding.ArtifactRootCanonicalPath, binding.ArtifactRootFilesystemObjectIdentity, binding.RunLockFilesystemObjectIdentity }
                .All(value => !string.IsNullOrWhiteSpace(value) && !value.Contains('\0', StringComparison.Ordinal)) &&
            binding.ArtifactRootCanonicalPath.Length > 3 && char.IsAsciiLetterUpper(binding.ArtifactRootCanonicalPath[0]) && binding.ArtifactRootCanonicalPath[1..3] == ":\\",
            "The permanent supported Windows local execution binding is missing or invalid.");
    }
    private void ValidateSigner(IMigrationEvidenceSigner signer, string role)
    {
        ArgumentNullException.ThrowIfNull(signer);
        ValidateTrust();
        Require(signer.KeyId == role && string.Equals(signer.PublicKeyFingerprintSha256, _fingerprints[role], StringComparison.OrdinalIgnoreCase),
            "The supplied signer does not match the configured authority role.");
    }
    private void ValidateTrust()
    {
        foreach ((string id, string fingerprint) in _fingerprints)
        {
            Require(_trust.ContainsKey(id) && _trust.TryGetPublicKeyFingerprintSha256(id, out string current) &&
                string.Equals(current, fingerprint, StringComparison.OrdinalIgnoreCase), "Configured authority trust changed after verification policy was established.");
        }
    }
    private void ValidateObservationTime(DateTimeOffset observed, DateTimeOffset now)
    {
        Require(Utc(now) && Utc(observed) && observed <= now && now - observed <= _observationAge,
        "A source, runner or target observation is future-dated or outside the admitted freshness policy.");
    }

    private static void ValidateWindow(DateTimeOffset issued, DateTimeOffset expires, DateTimeOffset now)
    {
        Require(Utc(now) && Utc(issued) && Utc(expires) && issued <= now && expires > now &&
            expires > issued && expires - issued <= GuardedRunnerPolicy.MaximumAuthorizationLifetime, "The fresh authority window is invalid or exceeds the existing one-hour approval lifetime.");
    }

    private static bool Utc(DateTimeOffset value)
    {
        return value != default && value.Offset == TimeSpan.Zero;
    }

    private static bool Hex(string? value, int length)
    {
        return value is not null && value.Length == length && value.All(char.IsAsciiHexDigit);
    }

    public static string ComputeIdentitySha256(MigrationRunIdentity identity)
    {
        return Digest("Legacy.Maliev.DataMigration.RunIdentity.v1", JsonSerializer.Serialize(identity, Options));
    }
}
