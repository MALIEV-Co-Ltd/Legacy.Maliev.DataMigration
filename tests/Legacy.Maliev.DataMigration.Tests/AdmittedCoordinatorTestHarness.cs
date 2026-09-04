using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed class AdmittedCoordinatorTestHarness : IDisposable
{
    internal readonly string Root = Path.Combine(Path.GetTempPath(), "admitted-coordinator-" + Guid.NewGuid().ToString("N"));
    internal string Staging => StagingOverride ?? Path.Combine(Root, "staging");
    internal string? StagingOverride { get; set; }
    internal string Output => OutputOverride ?? Path.Combine(Root, "final");
    internal string? OutputOverride { get; set; }
    internal RecoveryAuthorityTestData Data = null!;
    internal FreshSchemaPlan Plan = null!;
    internal WindowsLocalRunAuthority Authority = null!;
    internal Journal RunJournal = null!;
    internal SourceAdapter Source = null!;
    internal TargetAdapter Target = null!;
    internal DumpAdapter Dump = new();
    internal ArchiveVerifier Local = new();
    internal List<IncrementalMigrationProgress> Progress = [];
    internal string? FailingSourceDatabase;
    internal bool SourceDrift { get; set; }
    internal bool FailReadiness { get; set; }
    internal bool FailSettlement { get; set; }
    internal bool UnownedRecovery { get; set; }
    internal int SourceObservations;
    internal int ReadinessCalls;
    internal Exception? CompleteSourceFailure { get; set; }
    internal int SourceRowId { get; set; } = 1;
    internal Func<ValueTask> Cleanup = () => ValueTask.CompletedTask;
    internal IMigrationEvidenceSigner? SignerOverride { get; set; }
    internal RecoveryAuthorityVerificationOptions? VerificationOverride { get; set; }
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    internal ReadOnlyMemory<byte> RootKey => _key;

    internal static async Task<AdmittedCoordinatorTestHarness> CreateAsync()
    {
        var value = new AdmittedCoordinatorTestHarness();
        value.Authority = WindowsLocalRunAuthority.AcquireFresh(value.Staging);
        value.Data = await RecoveryAuthorityTestData.CreateAsync(prepare: false, resumeDelay: TimeSpan.Zero, admittedAt: DateTimeOffset.UtcNow.AddSeconds(-1), webOriginals: true);
        value.Data.Binding = value.Authority.Binding;
        value.Data.AdmissionPayload = value.Data.AdmissionPayload with { LocalBinding = value.Data.Binding };
        value.Data.Admission = value.Data.Verifier.PrepareAdmission(value.Data.AdmissionPayload, value.Data.Signers[2], value.Data.AdmittedAt);
        value.Plan = JsonSerializer.Deserialize<FreshSchemaPlan>(value.Data.AdmissionPayload.OriginalSchemaPlanJson, RecoveryAuthorityTestData.ProducerJson)!;
        value.RunJournal = new(value);
        value.Source = new(value);
        value.Target = new(value);
        return value;
    }

    internal AdmittedSequentialMigrationCoordinator Coordinator(Action<IncrementalMigrationProgress>? progress = null)
    {
        var runtime = new AdmittedCoordinatorRuntime(Source, Target, Target, RunJournal, Dump, Local,
            _ => { ReadinessCalls++; return FailReadiness ? Task.FromException(new IOException("readiness failure")) : Task.CompletedTask; },
            _ =>
            {
                SourceObservations++;
                RestoredSourceObservation current = Data.Source with { ObservedAtUtc = DateTimeOffset.UtcNow };
                return Task.FromResult(SourceDrift ? current with { State = current.State with { ConfiguredEndpoint = "changed" } } : current);
            },
            _ => Task.FromResult(Data.Runner with { ObservedAtUtc = DateTimeOffset.UtcNow }),
            _ => Task.FromResult(Data.Target with { ObservedAtUtc = DateTimeOffset.UtcNow }),
            (shadow, _) => FailSettlement ? Task.FromException<CloudNativePgShadowSettlement>(new IOException("unsettled")) : Task.FromResult(new CloudNativePgShadowSettlement(shadow, "uid", "1", 1, true)),
            () => Cleanup());
        return new(Data.Admission, VerificationOverride ?? new(new(Plan.SourceCommitSha, Data.AdmissionPayload.Identity.RunnerDigestSha256), RecoveryAuthorityTestData.Roles, Data.Trust),
            SignerOverride ?? Data.Signers[2], runtime, "coordinator-test", _key, Output, value => { Progress.Add(value); progress?.Invoke(value); });
    }

    internal (SourceContinuityAttestation, ResumeAuthorizationReceipt) ResumeAuthority(RecoveryJournalBaseline? baseline = null)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        RestoredSourceObservation observed = Data.Source with { ObservedAtUtc = now };
        SourceContinuityAttestation continuity = SourceContinuityAttestation.Sign(new(Guid.NewGuid(), RecoveryAuthorityVerifier.ComputeIdentitySha256(Data.AdmissionPayload.Identity),
            Data.Admission.ComputeSha256(), Data.AdmissionPayload.VerifiedRestoreSha256, DatabaseInventory.InventorySha256,
            Data.AdmissionPayload.SourceObservation.ComputeSha256(), observed, observed.ComputeSha256(), observed.ComputeStableStateSha256(),
            Data.AdmittedAt, now, RecoveryAuthorityVerifier.ContinuityStatementVersion, RecoveryAuthorityVerifier.ContinuityStatement,
            now, now.AddMinutes(30)), Data.Signers[3]);
        ResumeAuthorizationReceipt resume = Data.Verifier.PrepareResume(Data.Admission, continuity, baseline ?? RunJournal.Baseline(), observed, Data.Binding,
            Data.Runner with { ObservedAtUtc = now }, Data.Target with { ObservedAtUtc = now }, Guid.NewGuid(), now, now.AddMinutes(30), Data.Signers[1], now);
        return (continuity, resume);
    }

    internal void BindPlan(FreshSchemaPlan plan)
    {
        Plan = plan;
        ExecutionAuthorizationReceipt original = JsonSerializer.Deserialize<ExecutionAuthorizationReceipt>(Data.AdmissionPayload.OriginalAuthorizationJson, RecoveryAuthorityTestData.ProducerJson)!;
        ExecutionAuthorizationReceipt authorization = original with { SchemaPlanSha256 = SchemaPlanCanonicalizer.ComputeSha256(plan), AttestationSignature = null };
        Assert.True(ExecutionAuthorizationAttestation.TryCreatePayload(authorization, out byte[] payload));
        authorization = authorization with { AttestationSignature = Convert.ToBase64String(Data.Signers[1].Sign(payload)) };
        Data.Source = Data.Source with { State = Data.Source.State with { SchemaPlanSha256 = authorization.SchemaPlanSha256! } };
        Data.AdmissionPayload = Data.AdmissionPayload with
        {
            Identity = Data.AdmissionPayload.Identity with { SchemaPlanSha256 = authorization.SchemaPlanSha256! },
            OriginalSchemaPlanJson = JsonSerializer.Serialize(plan, RecoveryAuthorityTestData.ProducerJson),
            OriginalAuthorizationJson = JsonSerializer.Serialize(authorization, RecoveryAuthorityTestData.ProducerJson),
            OriginalAuthorizationSha256 = RecoveryAuthorityTestData.Hash(payload),
            SourceObservation = Data.Source with { ObservedAtUtc = Data.AdmissionPayload.SourceObservation.ObservedAtUtc },
        };
        Data.Admission = Data.Verifier.PrepareAdmission(Data.AdmissionPayload, Data.Signers[2], Data.AdmittedAt);
    }

    internal string Archive(string database)
    {
        return Path.Combine(Staging, database, "archive.aes256");
    }

    public void Dispose()
    {
        Authority?.Dispose();
        Data?.Dispose();
        if (Directory.Exists(Root)) { Directory.Delete(Root, true); }
    }

    internal sealed class Journal(AdmittedCoordinatorTestHarness owner) : IAdmittedMigrationRunJournal
    {
        internal readonly Dictionary<string, ShadowDatabase> Shadows = new(StringComparer.Ordinal);
        internal readonly Dictionary<string, DatabaseMigrationCheckpoint> Checkpoints = new(StringComparer.Ordinal);
        internal MigrationRunLease? Lease;
        internal string Status = "in_progress";
        internal MigrationExecutionReceipt? Receipt;
        internal bool LoseCheckpointAck;
        internal bool LoseCompletionAck;
        internal bool RejectLease { get; set; }
        internal bool FailFailureReport { get; set; }
        internal int InitialCalls, ResumeCalls, LegacyCalls;
        internal int Heartbeats;
        internal Func<Task>? HeartbeatWait { get; set; }
        internal DateTimeOffset? ObservedAtUtc { get; set; }
        internal Action<DatabaseMigrationCheckpoint>? ValidateCheckpoint { get; set; }
        internal Action<MigrationExecutionReceipt>? ValidateCompletion { get; set; }
        internal Func<RecoveryJournalSnapshot, RecoveryJournalSnapshot>? SnapshotTransform { get; set; }
        internal RecoveryJournalBaseline Baseline()
        {
            return new(owner.Data.AdmissionPayload.Identity, owner.Data.Admission.ComputeSha256(), Status,
            Lease?.Owner ?? "runner", Lease?.Attempt ?? 1, Lease?.FencingToken ?? Guid.NewGuid(), Receipt is null ? null : JsonSerializer.Serialize(Receipt), "[]",
            Shadows.Values.Select(shadow => new RecoveryShadowState(shadow, "pending", 0, null)).ToImmutableArray(),
            Checkpoints.Values.Select(cp => new RecoveryCheckpointState(cp.Database.Database, Encoding.UTF8.GetString(MigrationEvidenceAttestation.SerializeCheckpoint(cp)))).ToImmutableArray());
        }

        public Task<RecoveryJournalSnapshot> ReadRecoverySnapshotAsync(MigrationRunIdentity identity, CancellationToken cancellationToken)
        {
            owner.AuthorityBindingHeld();
            var snapshot = new RecoveryJournalSnapshot(owner.Data.Admission, Baseline(), ObservedAtUtc ?? DateTimeOffset.UtcNow, Lease?.ExpiresAtUtc);
            return Task.FromResult(SnapshotTransform?.Invoke(snapshot) ?? snapshot);
        }
        public Task<MigrationRunLease> AcquireInitialAsync(InitialMigrationAdmission admission, RestoredSourceObservation source, LocalExecutionBinding localBinding, CancellationToken cancellationToken)
        {
            owner.AuthorityBindingHeld(); InitialCalls++;
            owner.Data.Verifier.ValidateInitialAcquisition(admission, source, localBinding, DateTimeOffset.UtcNow);
            Lease = new(admission.Payload.Identity, "runner", 1, DateTimeOffset.UtcNow.AddSeconds(10)) { FencingToken = Guid.NewGuid() };
            return Task.FromResult(Lease);
        }
        public Task<MigrationRunLease> AcquireResumeAsync(SourceContinuityAttestation continuity, ResumeAuthorizationReceipt authorization, RestoredSourceObservation source,
            LocalExecutionBinding localBinding, FreshRunnerObservation runner, FreshTargetObservation target, CancellationToken cancellationToken)
        {
            owner.AuthorityBindingHeld(); ResumeCalls++;
            owner.Data.Verifier.ValidateResume(owner.Data.Admission, continuity, authorization, Baseline(), source, localBinding, runner, target, DateTimeOffset.UtcNow);
            Lease = new(owner.Data.AdmissionPayload.Identity, "resumed", Lease!.Attempt + 1, DateTimeOffset.UtcNow.AddSeconds(10)) { FencingToken = Guid.NewGuid() };
            Status = "in_progress";
            return Task.FromResult(Lease);
        }
        public Task<MigrationRunStartResult> TryBeginAsync(MigrationRunIdentity identity, CancellationToken cancellationToken) { LegacyCalls++; throw new InvalidOperationException("legacy bypass"); }
        public async Task<MigrationRunLease> HeartbeatAsync(MigrationRunLease lease, CancellationToken cancellationToken)
        {
            owner.AuthorityBindingHeld(); Heartbeats++;
            if (HeartbeatWait is not null) { await HeartbeatWait(); }
            return RejectLease
                ? throw new MigrationExecutionException("run_lease_lost", "lost")
                : (Lease = lease with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(10) });
        }
        public Task RegisterShadowAsync(MigrationRunLease lease, ShadowDatabase shadow, CancellationToken cancellationToken)
        { owner.AuthorityBindingHeld(); Shadows.Add(shadow.Database, shadow); return Task.CompletedTask; }
        public Task<IReadOnlyList<ShadowDatabase>> GetPendingShadowsAsync(MigrationRunLease lease, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<ShadowDatabase>>(Shadows.Values.ToArray());
        }

        public Task RecordCheckpointAsync(MigrationRunLease lease, DatabaseMigrationCheckpoint checkpoint, CancellationToken cancellationToken)
        {
            owner.AuthorityBindingHeld();
            new DatabaseMigrationCheckpointVerifier(new(owner.Data.AdmissionPayload.Identity, owner.Plan, owner.Data.Trust)).Validate(checkpoint, Shadows[checkpoint.Database.Database]);
            ValidateCheckpoint?.Invoke(checkpoint);
            Checkpoints.Add(checkpoint.Database.Database, checkpoint);
            if (LoseCheckpointAck) { LoseCheckpointAck = false; throw new IOException("checkpoint acknowledgement lost"); }
            return Task.CompletedTask;
        }
        public Task<IReadOnlyList<DatabaseMigrationCheckpoint>> GetCheckpointsAsync(MigrationRunLease lease, CancellationToken cancellationToken)
        {
            return Status == "completed"
            ? throw new InvalidOperationException("completed lease read")
            : Task.FromResult<IReadOnlyList<DatabaseMigrationCheckpoint>>(Checkpoints.Values.ToArray());
        }
        public Task RecordCompletedAsync(MigrationExecutionReceipt receipt, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("unleased completion");
        }

        public Task RecordCompletedAsync(MigrationRunLease lease, MigrationExecutionReceipt receipt, CancellationToken cancellationToken)
        {
            owner.AuthorityBindingHeld(); Assert.Equal(DatabaseInventory.ActiveDatabases.Count, Checkpoints.Count);
            Assert.Equal(DatabaseInventory.ActiveDatabases.Count, Directory.EnumerateDirectories(owner.Staging).Count(path => !Path.GetFileName(path).StartsWith('.')));
            ValidateCompletion?.Invoke(receipt);
            Receipt = receipt; Status = "completed";
            if (LoseCompletionAck) { LoseCompletionAck = false; throw new IOException("completion acknowledgement lost"); }
            return Task.CompletedTask;
        }
        public Task RecordFailedAsync(MigrationFailureReceipt receipt, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("unleased failure");
        }

        public Task RecordFailedAsync(MigrationRunLease lease, MigrationFailureReceipt receipt, CancellationToken cancellationToken)
        { Assert.Empty(receipt.Cleanup); if (FailFailureReport) { throw new InvalidOperationException("report failure"); } if (Status != "completed") { Status = "failed"; } return Task.CompletedTask; }
        public Task RecordShadowCleanupAsync(MigrationRunLease lease, ShadowCleanupOutcome outcome, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("automatic cleanup");
        }
    }

    internal void AuthorityBindingHeld()
    {
        _ = Assert.Throws<IOException>(() => WindowsLocalRunAuthority.AcquireResume(Staging, Data.Binding));
    }

    internal sealed class SourceAdapter(AdmittedCoordinatorTestHarness owner) : IReadOnlySqlServerMigrationSource
    {
        internal List<string> Started = [];
        internal Dictionary<string, int> Reads = new(StringComparer.Ordinal);
        public Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            if (Started.Count > 0 && !owner.RunJournal.Checkpoints.ContainsKey(database))
            {
                string previous = Started[^1];
                Assert.True(File.Exists(owner.Archive(previous)), "Next database began before prior durable local verification.");
            }
            Started.Add(database);
            return database == owner.FailingSourceDatabase ? throw new IOException("later source failure") : Task.CompletedTask;
        }
        public Task<SourceSchemaEvidence> InspectSchemaAsync(string database, CancellationToken cancellationToken)
        {
            DatabaseSchemaPlan plan = owner.Plan.Databases.Single(item => item.Database == database);
            return Task.FromResult(new SourceSchemaEvidence(database, plan.SourceSchemaSha256, plan.Tables.Select(table => new SourceTableInventory(table.SourceSchema, table.SourceTable, table.SourceColumns)).ToArray()));
        }
        public async IAsyncEnumerable<MigrationRow> ReadTableAsync(string database, TableCopyPlan table, [EnumeratorCancellation] CancellationToken cancellationToken)
        { Reads[database] = Reads.GetValueOrDefault(database) + 1; yield return new(new Dictionary<string, object?> { ["ID"] = owner.SourceRowId }); await Task.CompletedTask; }
        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyOrphansAsync(string database, TableCopyPlan table, CancellationToken cancellationToken)
        {
            return Empty();
        }

        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyRelationshipsAsync(string database, TableCopyPlan table, CancellationToken cancellationToken)
        {
            return Empty();
        }

        public Task<IReadOnlyDictionary<string, long>> InspectSequenceNextValuesAsync(string database, DatabaseSchemaPlan plan, CancellationToken cancellationToken)
        {
            return Empty();
        }

        public Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            return owner.CompleteSourceFailure is { } failure ? Task.FromException(failure) : Task.CompletedTask;
        }

        public Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
    internal static Task<IReadOnlyDictionary<string, long>> Empty()
    {
        return Task.FromResult<IReadOnlyDictionary<string, long>>(new Dictionary<string, long>());
    }

    internal sealed class TargetAdapter(AdmittedCoordinatorTestHarness owner) : IPostgreSqlShadowTarget, IPostgreSqlShadowRecoveryTarget
    {
        internal Dictionary<string, List<MigrationRow>> Rows = new(StringComparer.Ordinal);
        internal Dictionary<string, int> Copies = new(StringComparer.Ordinal);
        internal List<ShadowDatabase> Created = [];
        internal bool LoseCommitAck;
        internal bool Partial { get; set; }
        internal bool FailCopy { get; set; }
        public Task<ShadowDatabase> CreateUniqueEmptyShadowAsync(ShadowDatabase plannedShadow, CancellationToken cancellationToken)
        { Created.Add(plannedShadow); Rows.Add(plannedShadow.Database, []); return Task.FromResult(plannedShadow); }
        public Task<bool> IsEmptyAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("weak empty predicate");
        }

        public Task<IPostgreSqlWholeDatabaseTransaction> BeginWholeDatabaseTransactionAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            return Task.FromResult<IPostgreSqlWholeDatabaseTransaction>(new Transaction(this, shadow));
        }

        public Task DeleteRunOwnedShadowAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("automatic delete");
        }

        public Task<IPostgreSqlShadowRecoverySession> BeginReadOnlyRecoveryAsync(ShadowDatabase originalShadow, CancellationToken cancellationToken)
        {
            Assert.Equal(owner.RunJournal.Shadows[originalShadow.Database], originalShadow);
            return Task.FromResult<IPostgreSqlShadowRecoverySession>(new Recovery(this,
                owner.UnownedRecovery ? originalShadow with { FencingToken = Guid.NewGuid() } : originalShadow));
        }
        internal static TableReconciliationEvidence Evidence(TableCopyPlan table, IEnumerable<MigrationRow> rows)
        { using var collector = new TableEvidenceCollector(table); foreach (MigrationRow row in rows) { collector.Append(row); } return collector.Finish(); }
        private sealed class Recovery(TargetAdapter target, ShadowDatabase shadow) : IPostgreSqlShadowRecoverySession
        {
            public Task<PostgreSqlShadowRecoveryInspection> InspectAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken)
            {
                if (target.Partial) { throw new MigrationExecutionException("shadow_recovery_partial", "partial"); }
                bool empty = target.Rows[shadow.Database].Count == 0;
                return Task.FromResult(new PostgreSqlShadowRecoveryInspection(shadow, empty, empty ? null : plan.TargetSchemaSha256,
                    empty ? [] : plan.Tables.Select(table => Evidence(table, target.Rows[shadow.Database])).ToArray(), new Dictionary<string, long>()));
            }
            public ValueTask DisposeAsync()
            {
                return ValueTask.CompletedTask;
            }
        }
        private sealed class Transaction(TargetAdapter target, ShadowDatabase shadow) : IPostgreSqlWholeDatabaseTransaction
        {
            private readonly List<MigrationRow> _rows = [];
            public Task ApplySchemaAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken)
            {
                return Task.CompletedTask;
            }

            public Task FinalizeSchemaAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken)
            {
                return Task.CompletedTask;
            }

            public Task<long> CopyBatchAsync(TableCopyPlan table, IReadOnlyList<MigrationRow> rows, CancellationToken cancellationToken)
            { target.Copies[shadow.Database] = target.Copies.GetValueOrDefault(shadow.Database) + 1; if (target.FailCopy) { throw new IOException("copy failure"); } _rows.AddRange(rows); return Task.FromResult((long)rows.Count); }
            public Task<string> InspectSchemaAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken)
            {
                return Task.FromResult(plan.TargetSchemaSha256);
            }

            public Task<TableReconciliationEvidence> InspectTableAsync(TableCopyPlan table, CancellationToken cancellationToken)
            {
                return Task.FromResult(Evidence(table, _rows));
            }

            public Task<IReadOnlyDictionary<string, long>> InspectSequenceNextValuesAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken)
            {
                return Empty();
            }

            public Task CommitAsync(CancellationToken cancellationToken)
            { target.Rows[shadow.Database] = _rows; if (target.LoseCommitAck) { target.LoseCommitAck = false; throw new IOException("commit acknowledgement lost"); } return Task.CompletedTask; }
            public Task RollbackAsync(CancellationToken cancellationToken)
            {
                return Task.CompletedTask;
            }

            public ValueTask DisposeAsync()
            {
                return ValueTask.CompletedTask;
            }
        }
    }
    internal sealed class DumpAdapter : IPostgreSqlDumpSource
    {
        internal Dictionary<string, int> Counts = new(StringComparer.Ordinal);
        internal string? FailDatabase { get; set; }
        internal Func<string, CancellationToken, Task<Stream>>? Open { get; set; }
        public Task<Stream> OpenDumpAsync(string database, string shadowDatabase, CancellationToken cancellationToken)
        {
            Counts[database] = Counts.GetValueOrDefault(database) + 1;
            return FailDatabase == database
                ? throw new IOException("dump failed")
                : Open?.Invoke(database, cancellationToken) ?? Task.FromResult<Stream>(new MemoryStream(Encoding.UTF8.GetBytes("synthetic:" + database)));
        }
    }
    internal sealed class ArchiveVerifier : ILocalDatabaseArchiveVerifier
    {
        internal string? FailDatabase { get; set; }
        internal Func<string, CancellationToken, Task>? OnVerify { get; set; }
        public async Task VerifyAsync(Stream authenticatedPlaintext, DatabaseMigrationCheckpoint checkpoint, CancellationToken cancellationToken)
        {
            using var reader = new StreamReader(authenticatedPlaintext, leaveOpen: true);
            Assert.Equal("synthetic:" + checkpoint.Database.Database, await reader.ReadToEndAsync(cancellationToken));
            if (OnVerify is not null) { await OnVerify(checkpoint.Database.Database, cancellationToken); }
            if (FailDatabase == checkpoint.Database.Database) { throw new IOException("restore failed"); }
        }
    }
}
