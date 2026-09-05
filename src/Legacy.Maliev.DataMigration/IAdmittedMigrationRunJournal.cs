namespace Legacy.Maliev.DataMigration;

/// <summary>Authenticated consistent planning state. It never grants a live execution lease.</summary>
public sealed record RecoveryJournalSnapshot(InitialMigrationAdmission Admission, RecoveryJournalBaseline Baseline,
    DateTimeOffset ObservedAtUtc, DateTimeOffset? LeaseExpiresAtUtc);

/// <summary>Mandatory admission and explicit resume boundary for the incremental coordinator.</summary>
public interface IAdmittedMigrationRunJournal : IMigrationRunJournal
{
    Task<MigrationRunLease> AcquireInitialAsync(InitialMigrationAdmission admission, RestoredSourceObservation source,
        LocalExecutionBinding localBinding, CancellationToken cancellationToken);

    Task<RecoveryJournalSnapshot> ReadRecoverySnapshotAsync(MigrationRunIdentity identity, CancellationToken cancellationToken);

    Task<MigrationRunLease> AcquireResumeAsync(SourceContinuityAttestation continuity, ResumeAuthorizationReceipt authorization,
        RestoredSourceObservation source, LocalExecutionBinding localBinding, FreshRunnerObservation runner,
        FreshTargetObservation target, CancellationToken cancellationToken);
}
