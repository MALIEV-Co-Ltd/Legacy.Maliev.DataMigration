using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class AdmittedCoordinatorBoundaryTests
{
    [WindowsLocalRunTheory]
    [InlineData("admission")]
    [InlineData("identity")]
    [InlineData("owner")]
    [InlineData("attempt")]
    [InlineData("fence")]
    [InlineData("expired")]
    [InlineData("stale")]
    [InlineData("future")]
    [InlineData("offset")]
    [InlineData("status")]
    [InlineData("shadow")]
    [InlineData("checkpoints")]
    public async Task SigningSnapshot_InvalidAfterFirstArtifact_RejectsBeforeNewSignatureOrPublication(string fault)
    {
        using var harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        var signer = new CountingSigner(harness.Data.Signers[2]);
        harness.SignerOverride = signer;
        string first = DatabaseInventory.ActiveDatabases[0], second = DatabaseInventory.ActiveDatabases[1];
        byte[]? original = null;
        harness.Local.OnVerify = (database, _) =>
        {
            if (database == first)
            {
                harness.RunJournal.SnapshotTransform = snapshot =>
                {
                    original = File.ReadAllBytes(harness.Archive(first));
                    return fault switch
                    {
                        "admission" => snapshot with { Admission = InitialMigrationAdmission.Parse(snapshot.Admission.ExactJson + " ") },
                        "identity" => snapshot with { Baseline = snapshot.Baseline with { Identity = snapshot.Baseline.Identity with { RunId = Guid.NewGuid() } } },
                        "owner" => snapshot with { Baseline = snapshot.Baseline with { LeaseOwner = "other" } },
                        "attempt" => snapshot with { Baseline = snapshot.Baseline with { LeaseAttempt = snapshot.Baseline.LeaseAttempt + 1 } },
                        "fence" => snapshot with { Baseline = snapshot.Baseline with { FencingToken = Guid.NewGuid() } },
                        "expired" => snapshot with { LeaseExpiresAtUtc = snapshot.ObservedAtUtc },
                        "stale" => snapshot with { ObservedAtUtc = harness.Data.AdmittedAt.AddMinutes(-1) },
                        "future" => snapshot with { ObservedAtUtc = DateTimeOffset.UtcNow.AddMinutes(1) },
                        "offset" => snapshot with { ObservedAtUtc = snapshot.ObservedAtUtc.ToOffset(TimeSpan.FromHours(1)) },
                        "status" => snapshot with { Baseline = snapshot.Baseline with { Status = "failed" } },
                        "shadow" => snapshot with { Baseline = snapshot.Baseline with { Shadows = [.. snapshot.Baseline.Shadows.Where(item => item.Shadow.Database != second)] } },
                        "checkpoints" => snapshot with { Baseline = snapshot.Baseline with { Checkpoints = [] } },
                        _ => throw new InvalidOperationException(),
                    };
                };
            }
            return Task.CompletedTask;
        };
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default));
        Assert.NotNull(original);
        Assert.Equal(original, await File.ReadAllBytesAsync(harness.Archive(first)));
        Assert.Equal(1, signer.Checkpoints);
        Assert.Equal(0, signer.Completions);
        _ = Assert.Single(harness.RunJournal.Checkpoints);
        Assert.False(File.Exists(harness.Archive(second)));
        Assert.False(Directory.Exists(harness.Output));
    }

    private sealed class CountingSigner(IMigrationEvidenceSigner inner) : IMigrationEvidenceSigner
    {
        internal int Checkpoints, Completions;
        public string KeyId => inner.KeyId;
        public string PublicKeyFingerprintSha256 => inner.PublicKeyFingerprintSha256;
        public byte[] Sign(ReadOnlySpan<byte> payload)
        {
            if (payload.StartsWith("legacy-maliev-database-checkpoint-v1\0"u8)) { Checkpoints++; }
            if (payload.StartsWith("legacy-maliev-migration-success-v1\0"u8)) { Completions++; }
            return inner.Sign(payload);
        }
    }

    [WindowsLocalRunFact]
    public async Task Initial_JournalClockBehindHost_SignsCheckpointInJournalClockDomain()
    {
        using var harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        DateTimeOffset observed = harness.Data.AdmittedAt.AddMilliseconds(500);
        harness.RunJournal.ObservedAtUtc = observed;
        DatabaseMigrationCheckpoint? candidate = null;
        harness.RunJournal.ValidateCheckpoint = checkpoint =>
        {
            candidate = checkpoint;
            RecoveryJournalBaseline baseline = harness.RunJournal.Baseline();
            string json = Encoding.UTF8.GetString(MigrationEvidenceAttestation.SerializeCheckpoint(checkpoint));
            _ = harness.Data.Verifier.GetPermittedOperations(harness.Data.Admission,
                baseline with { Checkpoints = baseline.Checkpoints.Add(new(checkpoint.Database.Database, json)) }, observed);
        };
        Exception? failure = await Record.ExceptionAsync(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default));
        Assert.NotNull(candidate);
        // All other terms of the production checkpoint gate hold; only the clock-domain upper bound can reject.
        Assert.Equal(RecoveryAuthorityTestData.Roles.ExecutionKeyId, candidate.AttestationKeyId);
        Assert.True(candidate.CommittedAtUtc >= harness.Data.AdmittedAt);
        new DatabaseMigrationCheckpointVerifier(new(harness.Data.AdmissionPayload.Identity, harness.Plan, harness.Data.Trust))
            .Validate(candidate, harness.RunJournal.Shadows[candidate.Database.Database]);
        Assert.True(failure is null, $"checkpoint={candidate.CommittedAtUtc:O}; journal={observed:O}; failure={failure}");
        Assert.All(harness.RunJournal.Checkpoints.Values, checkpoint => Assert.Equal(observed, checkpoint.CommittedAtUtc));
    }

    [WindowsLocalRunFact]
    public async Task Completion_JournalClockBehindHost_SignsAfterFullCheckpointSetInJournalClockDomain()
    {
        using var harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        DateTimeOffset observed = default;
        harness.Local.OnVerify = (database, _) =>
        {
            if (database == DatabaseInventory.ActiveDatabases[^1])
            {
                observed = harness.RunJournal.Checkpoints.Values.Max(checkpoint => checkpoint.CommittedAtUtc).AddTicks(1);
                harness.RunJournal.ObservedAtUtc = observed;
            }
            return Task.CompletedTask;
        };
        MigrationExecutionReceipt? candidate = null;
        harness.RunJournal.ValidateCompletion = receipt =>
        {
            candidate = receipt;
            RecoveryJournalBaseline baseline = harness.RunJournal.Baseline() with
            { Status = "completed", TerminalReceiptSignedJson = JsonSerializer.Serialize(receipt) };
            _ = AdmittedSequentialMigrationCoordinator.ValidateCompletion(harness.Data.Admission,
                new(new(harness.Plan.SourceCommitSha, harness.Data.AdmissionPayload.Identity.RunnerDigestSha256), RecoveryAuthorityTestData.Roles, harness.Data.Trust),
                new(harness.Data.Admission, baseline, observed, harness.RunJournal.Lease!.ExpiresAtUtc));
        };
        Exception? failure = await Record.ExceptionAsync(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default));
        Assert.NotNull(candidate);
        Assert.All(harness.RunJournal.Checkpoints.Values, checkpoint => Assert.True(checkpoint.CommittedAtUtc <= observed));
        Assert.True(failure is null, $"completion={candidate.CompletedAtUtc:O}; journal={observed:O}; failure={failure}");
        Assert.Equal(observed, candidate.CompletedAtUtc);
    }

    [WindowsLocalRunTheory]
    [InlineData("publication")]
    [InlineData("authentication")]
    [InlineData("unowned")]
    public async Task LaterBoundaryFailure_PreservesEarlierArtifactAndStopsBeforeNextDatabase(string fault)
    {
        using var harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        string first = DatabaseInventory.ActiveDatabases[0], second = DatabaseInventory.ActiveDatabases[1];
        byte[]? original = null;
        harness.Local.OnVerify = async (database, token) =>
        {
            if (database == first) { harness.UnownedRecovery = fault == "unowned"; }
            if (database != second) { return; }
            original = await File.ReadAllBytesAsync(harness.Archive(first), token);
            if (fault == "publication") { _ = Directory.CreateDirectory(Path.Combine(harness.Staging, second)); }
        };
        if (fault == "authentication")
        {
            // Change already encrypted bytes while the native source is being disposed;
            // metadata/authentication must reject them before restore/publication.
            harness.Dump.Open = (database, _) => Task.FromResult<Stream>(new CorruptingDump(database, () =>
            {
                if (database != second) { return; }
                original = File.ReadAllBytes(harness.Archive(first));
                string pending = Directory.EnumerateDirectories(harness.Staging, ".pending-*").Single();
                using var encrypted = new FileStream(Path.Combine(pending, "archive.aes256"), FileMode.Open, FileAccess.ReadWrite);
                encrypted.Position = encrypted.Length - 1;
                int last = encrypted.ReadByte(); encrypted.Position--; encrypted.WriteByte((byte)(last ^ 1));
            }));
        }
        Assert.NotNull(await Record.ExceptionAsync(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default)));
        if (original is not null) { Assert.Equal(original, await File.ReadAllBytesAsync(harness.Archive(first))); }
        Assert.True(File.Exists(harness.Archive(first)));
        Assert.False(File.Exists(harness.Archive(second)));
        Assert.Equal(1, harness.Target.Copies[first]); Assert.Equal(1, harness.Dump.Counts[first]);
        Assert.DoesNotContain(DatabaseInventory.ActiveDatabases[2], harness.Source.Started);
    }

    [WindowsLocalRunTheory]
    [InlineData("receipt")]
    [InlineData("checkpoint")]
    [InlineData("key")]
    [InlineData("local-inventory")]
    public async Task CompletedLocalFinalizer_RejectsIncompleteOrUnauthenticatedStateWithoutRemoteCalls(string fault)
    {
        using var harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        harness.RunJournal.LoseCompletionAck = true;
        _ = await Assert.ThrowsAsync<IOException>(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default));
        RecoveryJournalBaseline baseline = harness.RunJournal.Baseline();
        if (fault == "receipt") { baseline = baseline with { TerminalReceiptSignedJson = "{}" }; }
        if (fault == "checkpoint") { baseline = baseline with { Checkpoints = baseline.Checkpoints.RemoveAt(0) }; }
        if (fault == "local-inventory") { Directory.Move(Path.Combine(harness.Staging, DatabaseInventory.ActiveDatabases[0]), Path.Combine(harness.Root, "retained-artifact")); }
        int heartbeats = harness.RunJournal.Heartbeats, observations = harness.SourceObservations;
        var snapshot = new RecoveryJournalSnapshot(harness.Data.Admission, baseline, DateTimeOffset.UtcNow, null);
        Assert.NotNull(await Record.ExceptionAsync(() => CompletedLocalMigrationFinalizer.FinalizeAsync(snapshot,
            new(new(harness.Plan.SourceCommitSha, harness.Data.AdmissionPayload.Identity.RunnerDigestSha256), RecoveryAuthorityTestData.Roles, harness.Data.Trust),
            harness.Staging, harness.Output, "coordinator-test", fault == "key" ? new byte[32] : harness.RootKey, default)));
        Assert.False(Directory.Exists(harness.Output)); Assert.Equal(0, harness.RunJournal.ResumeCalls);
        Assert.Equal(heartbeats, harness.RunJournal.Heartbeats); Assert.Equal(observations, harness.SourceObservations);
        using var authority = WindowsLocalRunAuthority.AcquireResume(harness.Staging, harness.Data.Binding);
    }

    private sealed class CorruptingDump(string database, Action disposed)
        : MemoryStream(Encoding.UTF8.GetBytes("synthetic:" + database))
    {
        public override ValueTask DisposeAsync() { disposed(); return base.DisposeAsync(); }
    }

    [WindowsLocalRunFact]
    public async Task ConfirmedCommit_LaterSourceCompletionFails_ReportsActualCommitWithoutSigningCheckpoint()
    {
        using var harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        var original = new IOException("source completion failure");
        harness.CompleteSourceFailure = original;
        Exception failure = await Record.ExceptionAsync(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default));
        Assert.Same(original, failure); Assert.Empty(harness.RunJournal.Checkpoints); Assert.Empty(harness.Dump.Counts);
        Assert.Equal(1, harness.Progress.LastOrDefault()?.RemoteCommitted ?? 0);
    }

    [WindowsLocalRunFact]
    public async Task Resume_LocalLockUnavailable_CoordinatorRemainsDisposableWithoutRemoteAcquisition()
    {
        using var harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        harness.FailingSourceDatabase = DatabaseInventory.ActiveDatabases[1];
        _ = await Assert.ThrowsAsync<IOException>(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default));
        var (continuity, authorization) = harness.ResumeAuthority();
        using var competing = WindowsLocalRunAuthority.AcquireResume(harness.Staging, harness.Data.Binding);
        var coordinator = harness.Coordinator();
        _ = await Assert.ThrowsAsync<IOException>(() => coordinator.ResumeAsync(continuity, authorization, default));
        await coordinator.DisposeAsync();
        Assert.Equal(0, harness.RunJournal.ResumeCalls);
    }

    [WindowsLocalRunTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LocalPublication_LeaseOrLocalAuthorityLost_PreservesEarlierBytes(bool localAuthority)
    {
        using var harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        string first = DatabaseInventory.ActiveDatabases[0], second = DatabaseInventory.ActiveDatabases[1];
        byte[]? before = null;
        harness.Local.OnVerify = async (database, token) =>
        {
            if (database != second) { return; }
            before = await File.ReadAllBytesAsync(harness.Archive(first), token);
            if (localAuthority) { harness.Authority.Dispose(); }
            else { harness.RunJournal.RejectLease = true; }
        };
        Assert.NotNull(await Record.ExceptionAsync(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default)));
        Assert.NotNull(before); Assert.Equal(before, await File.ReadAllBytesAsync(harness.Archive(first)));
        Assert.False(Directory.Exists(Path.Combine(harness.Staging, second)));
        Assert.Equal(2, harness.RunJournal.Checkpoints.Count);
        Assert.Equal(2, harness.Progress[^1].RemoteCommitted); Assert.Equal(2, harness.Progress[^1].Downloaded); Assert.Equal(1, harness.Progress[^1].LocalVerified);
    }

    [WindowsLocalRunFact]
    public async Task Cancellation_AwaitsDumpDisposalBeforeReleasingAuthority_AndPreservesPrimaryError()
    {
        using var harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        using var cancellation = new CancellationTokenSource();
        var dump = new HeldDump();
        harness.Dump.Open = (_, _) => Task.FromResult<Stream>(dump);
        harness.RunJournal.FailFailureReport = true;
        Task operation = harness.Coordinator().ExecuteInitialAsync(harness.Authority, cancellation.Token);
        await dump.Reading.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await cancellation.CancelAsync();
        await dump.Disposing.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(operation.IsCompleted); harness.AuthorityBindingHeld();
        dump.Release.SetResult();
        Exception failure = await Record.ExceptionAsync(() => operation);
        _ = Assert.IsType<OperationCanceledException>(failure, exactMatch: false);
        Assert.Equal(nameof(IOException), failure.Data["snapshot_dump_cleanup_failure"]);
        Assert.Equal(nameof(InvalidOperationException), failure.Data["journal_failure_reporting_failure"]);
        Assert.False(Directory.Exists(Path.Combine(harness.Staging, DatabaseInventory.ActiveDatabases[0])));
        using var reacquired = WindowsLocalRunAuthority.AcquireResume(harness.Staging, harness.Data.Binding);
    }

    [WindowsLocalRunFact]
    public async Task Cancellation_AwaitsBackgroundHeartbeatBeforeReleasingAuthority()
    {
        using var harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        harness.Local.OnVerify = async (database, token) =>
        {
            harness.RunJournal.HeartbeatWait = async () => { _ = entered.TrySetResult(); await release.Task; };
            await Task.Delay(Timeout.Infinite, token);
        };
        Task operation = harness.Coordinator().ExecuteInitialAsync(harness.Authority, cancellation.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(8));
        await cancellation.CancelAsync();
        Assert.False(operation.IsCompleted); harness.AuthorityBindingHeld();
        release.SetResult();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);
        using var reacquired = WindowsLocalRunAuthority.AcquireResume(harness.Staging, harness.Data.Binding);
    }

    [WindowsLocalRunTheory]
    [InlineData("source")]
    [InlineData("target")]
    [InlineData("checkpoint")]
    public async Task Resume_IndependentSourceTargetAndSignedCheckpointComparison_RejectsDivergence(string change)
    {
        using var harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        string first = DatabaseInventory.ActiveDatabases[0];
        harness.FailingSourceDatabase = DatabaseInventory.ActiveDatabases[1];
        _ = await Assert.ThrowsAsync<IOException>(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default));
        byte[] before = await File.ReadAllBytesAsync(harness.Archive(first));
        if (change is "source" or "checkpoint") { harness.SourceRowId = 2; }
        if (change is "target" or "checkpoint") { harness.Target.Rows[first] = [new(new Dictionary<string, object?> { ["ID"] = 2 })]; }
        harness.FailingSourceDatabase = null; harness.Source.Started.Clear();
        var (continuity, authorization) = harness.ResumeAuthority();
        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => harness.Coordinator().ResumeAsync(continuity, authorization, default));
        Assert.Equal(change == "checkpoint" ? "checkpoint_reconciliation_mismatch" : "shadow_reconciliation_failed", failure.Code);
        Assert.Equal(before, await File.ReadAllBytesAsync(harness.Archive(first))); Assert.Equal(1, harness.Dump.Counts[first]);
    }

    [WindowsLocalRunFact]
    public async Task Resume_ExactOwnedVerifiedEmptyCandidate_IsReusedWithoutProvisioningOrRelabeling()
    {
        using var harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        harness.Target.FailCopy = true;
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default));
        string first = DatabaseInventory.ActiveDatabases[0];
        ShadowDatabase original = harness.RunJournal.Shadows[first];
        harness.Target.FailCopy = false; harness.Source.Started.Clear();
        var (continuity, authorization) = harness.ResumeAuthority();
        _ = await harness.Coordinator().ResumeAsync(continuity, authorization, default);
        Assert.Equal(original, harness.RunJournal.Shadows[first]);
        _ = Assert.Single(harness.Target.Created, item => item.Database == first);
    }

    private sealed class HeldDump : Stream
    {
        internal TaskCompletionSource Reading { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Disposing { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        { Reading.SetResult(); await Task.Delay(Timeout.Infinite, cancellationToken); return 0; }
        public override async ValueTask DisposeAsync()
        { Disposing.SetResult(); await Release.Task; await base.DisposeAsync(); throw new IOException("native cleanup failure"); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override void Flush()
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }
}
