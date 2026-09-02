using System.Collections.Immutable;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

public sealed record InitialMigrationAdmissionPayload(
    MigrationRunIdentity Identity,
    string InventorySha256,
    string OriginalBackupReceiptJson,
    string OriginalSchemaPlanJson,
    string OriginalAuthorizationJson,
    string OriginalVerifiedRestoreReceiptJson,
    string OriginalAuthorizationSha256,
    string VerifiedRestoreSha256,
    RestoredSourceObservation SourceObservation,
    LocalExecutionBinding LocalBinding,
    DateTimeOffset AdmittedAtUtc,
    string ValidationPolicyVersion,
    TimeSpan MaximumObservationAge,
    string ValidationStatement);

public sealed record SourceContinuityPayload(
    Guid Nonce,
    string RunIdentitySha256,
    string AdmissionSha256,
    string VerifiedRestoreSha256,
    string InventorySha256,
    string InitialObservationSha256,
    RestoredSourceObservation CurrentObservation,
    string CurrentObservationSha256,
    string StableSourceStateSha256,
    DateTimeOffset ContinuousFromUtc,
    DateTimeOffset ContinuousThroughUtc,
    string StatementVersion,
    string Statement,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc);

public sealed record FreshRunnerObservation(DateTimeOffset ObservedAtUtc, string RunnerDigestSha256);
public sealed record FreshTargetObservation(DateTimeOffset ObservedAtUtc, CloudNativePgTargetObservation Target);

public sealed record RecoveryShadowState(ShadowDatabase Shadow, string CleanupStatus, int CleanupAttempts, string? LastErrorCode);
public sealed record RecoveryCheckpointState(string Database, string SignedCheckpointJson);

/// <summary>Semantic journal facts only; heartbeat and lease expiry are deliberately not part of the approval baseline.</summary>
public sealed record RecoveryJournalBaseline(
    MigrationRunIdentity Identity,
    string AdmissionSha256,
    string Status,
    string? LeaseOwner,
    int LeaseAttempt,
    Guid? FencingToken,
    string? TerminalReceiptSignedJson,
    string FailureHistoryJson,
    ImmutableArray<RecoveryShadowState> Shadows,
    ImmutableArray<RecoveryCheckpointState> Checkpoints)
{
    public string ComputeSha256()
    {
        RecoveryContractEncoding.Require(!Shadows.IsDefault && !Checkpoints.IsDefault && Shadows.All(item => item?.Shadow is not null) && Checkpoints.All(item => item is not null),
            "The recovery baseline is incomplete.");
        var ordered = this with
        {
            Shadows = Shadows.OrderBy(item => item.Shadow.Name, StringComparer.Ordinal).ToImmutableArray(),
            Checkpoints = Checkpoints.OrderBy(item => item.Database, StringComparer.Ordinal).ToImmutableArray(),
        };
        return RecoveryContractEncoding.Digest("Legacy.Maliev.DataMigration.RecoveryJournalBaseline.v1", JsonSerializer.Serialize(ordered, RecoveryContractEncoding.Options));
    }
}

public enum RecoveryDatabaseOperation
{
    /// <summary>Independently revalidate the signed checkpoint and retained target, then deliver locally.</summary>
    RevalidateCheckpointAndDeliver = 1,
    /// <summary>Reconcile the retained candidate: checkpoint/deliver a fully matching commit, or copy only a proved empty candidate. Partial state is never writable.</summary>
    ReconcileOwnedShadowAndReuseOnlyIfEmpty = 2,
    /// <summary>Create a new exactly owned shadow, copy and verify, checkpoint, then deliver locally.</summary>
    CreateCopyAndDeliver = 3,
}

public sealed record PermittedDatabaseRecovery(string Database, RecoveryDatabaseOperation Operation);

public sealed record ResumeAuthorizationPayload(
    MigrationRunIdentity Identity,
    string AdmissionSha256,
    string ContinuitySha256,
    string BaselineSha256,
    string LocalBindingSha256,
    FreshRunnerObservation Runner,
    FreshTargetObservation Target,
    ImmutableArray<PermittedDatabaseRecovery> PermittedOperations,
    Guid Nonce,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc);

public sealed record RecoveryAuthorityRoles(
    string BackupKeyId,
    string AuthorizationKeyId,
    string ExecutionKeyId,
    string ProvenanceKeyId,
    string FinalEvidenceKeyId);

public sealed record RecoveryAuthorityVerificationOptions(
    GuardedRunnerPolicy RunnerPolicy,
    RecoveryAuthorityRoles Roles,
    IReceiptAttestationTrustStore TrustStore,
    TimeSpan? MaximumObservationAge = null);
