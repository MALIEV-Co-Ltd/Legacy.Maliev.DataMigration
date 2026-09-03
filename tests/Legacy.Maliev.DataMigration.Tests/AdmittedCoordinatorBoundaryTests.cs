namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class AdmittedCoordinatorBoundaryTests
{
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
        : MemoryStream(System.Text.Encoding.UTF8.GetBytes("synthetic:" + database))
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
