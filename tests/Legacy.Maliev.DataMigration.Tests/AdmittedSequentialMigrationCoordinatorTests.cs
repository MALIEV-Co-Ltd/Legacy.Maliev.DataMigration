namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class AdmittedSequentialMigrationCoordinatorTests
{
    [WindowsLocalRunFact]
    public async Task HostFactory_ProducerOriginalsReachTargetBindingGuardBeforeExternalAccess()
    {
        using AdmittedCoordinatorTestHarness harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        string existingExecutable = Environment.ProcessPath!;
        var options = new AdmittedCoordinatorHostOptions(harness.Data.Admission,
            new(new(harness.Plan.SourceCommitSha, harness.Data.AdmissionPayload.Identity.RunnerDigestSha256), RecoveryAuthorityTestData.Roles, harness.Data.Trust),
            harness.Data.Signers[2], "unused", new("unused"), "unused",
            new(new Uri("https://unused.test"), "wrong-namespace", "wrong-cluster", "unused", "unused", "unused", TimeSpan.FromSeconds(1)),
            new(new Uri("https://unused.test"), "unused", "unused"),
            new("unused", "unused", "unused", "unused", "unused", existingExecutable),
            existingExecutable, harness.Root, "test", new byte[32], harness.Output);
        MigrationExecutionException failure = Assert.Throws<MigrationExecutionException>(() => AdmittedSequentialMigrationCoordinator.CreateForHost(options));
        Assert.Equal("host_target_configuration_mismatch", failure.Code);
        Assert.Equal(0, harness.RunJournal.InitialCalls);
        Assert.Empty(harness.Target.Created);
    }

    [WindowsLocalRunFact]
    public async Task HostFactory_MissingNativeRuntime_RejectsBeforeCreatingOrMutatingRemoteState()
    {
        using AdmittedCoordinatorTestHarness harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        var options = new AdmittedCoordinatorHostOptions(harness.Data.Admission,
            new(new(harness.Plan.SourceCommitSha, harness.Data.AdmissionPayload.Identity.RunnerDigestSha256), RecoveryAuthorityTestData.Roles, harness.Data.Trust),
            harness.Data.Signers[2], "unused", new("unused"), "unused", null!, null!, null!,
            Path.Combine(harness.Root, "missing.exe"), harness.Root, "test", new byte[32], harness.Output);
        MigrationExecutionException failure = Assert.Throws<MigrationExecutionException>(() => AdmittedSequentialMigrationCoordinator.CreateForHost(options));
        Assert.Equal("host_native_runtime_required", failure.Code);
        Assert.Empty(harness.Target.Created);
    }

    [WindowsLocalRunFact]
    public async Task Initial_OutputInsideStaging_RejectsBeforeJournalOrCopy()
    {
        using AdmittedCoordinatorTestHarness harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        harness.OutputOverride = Path.Combine(harness.Staging, "bad-final");
        Exception? error = await Record.ExceptionAsync(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default));
        Assert.NotNull(error);
        Assert.Equal(0, harness.RunJournal.InitialCalls);
        Assert.Empty(harness.Target.Created);
    }
    [WindowsLocalRunTheory]
    [InlineData("commit")]
    [InlineData("checkpoint")]
    public async Task Resume_IndependentAcknowledgementLoss_ReconcilesWithoutRecopy(string loss)
    {
        using AdmittedCoordinatorTestHarness harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        harness.Target.LoseCommitAck = loss == "commit";
        harness.RunJournal.LoseCheckpointAck = loss == "checkpoint";
        _ = await Record.ExceptionAsync(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default));
        string first = DatabaseInventory.ActiveDatabases[0];
        Assert.Equal(1, harness.Target.Copies[first]);
        Assert.Empty(harness.Dump.Counts);
        Assert.Equal(loss == "checkpoint" ? 1 : 0, harness.RunJournal.Checkpoints.Count);
        ShadowDatabase original = harness.RunJournal.Shadows[first];
        harness.Source.Started.Clear();
        var (continuity, authorization) = harness.ResumeAuthority();
        _ = await harness.Coordinator().ResumeAsync(continuity, authorization, default);
        Assert.Equal(1, harness.Target.Copies[first]);
        Assert.Equal(2, harness.Source.Reads[first]);
        Assert.Equal(original, harness.RunJournal.Shadows[first]);
    }

    [WindowsLocalRunTheory]
    [InlineData("dump")]
    [InlineData("restore")]
    [InlineData("settlement")]
    [InlineData("source")]
    [InlineData("partial")]
    [InlineData("local")]
    public async Task Resume_LaterBoundaryFailure_PreservesFirstArtifact(string fault)
    {
        using AdmittedCoordinatorTestHarness harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        string first = DatabaseInventory.ActiveDatabases[0], second = DatabaseInventory.ActiveDatabases[1];
        harness.FailingSourceDatabase = second;
        _ = await Assert.ThrowsAsync<IOException>(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default));
        byte[] original = await File.ReadAllBytesAsync(harness.Archive(first));
        harness.FailingSourceDatabase = null; harness.Source.Started.Clear();
        var (continuity, authorization) = harness.ResumeAuthority();
        harness.Dump.FailDatabase = fault == "dump" ? second : null;
        harness.Local.FailDatabase = fault == "restore" ? second : null;
        harness.FailSettlement = fault == "settlement";
        harness.SourceDrift = fault == "source";
        harness.Target.Partial = fault == "partial";
        if (fault == "local") { harness.RunJournal.Checkpoints.Clear(); }
        Assert.NotNull(await Record.ExceptionAsync(() => harness.Coordinator().ResumeAsync(continuity, authorization, default)));
        Assert.Equal(original, await File.ReadAllBytesAsync(harness.Archive(first)));
        Assert.Equal(1, harness.Target.Copies[first]); Assert.Equal(1, harness.Dump.Counts[first]);
    }

    [WindowsLocalRunFact]
    public async Task Initial_ReadinessFailure_PrecedesJournalAndHoldsAuthorityThroughCleanup()
    {
        using AdmittedCoordinatorTestHarness harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        harness.FailReadiness = true;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        harness.Cleanup = async () => { entered.SetResult(); await release.Task; };
        Task<IncrementalMigrationResult> operation = harness.Coordinator().ExecuteInitialAsync(harness.Authority, default);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(operation.IsCompleted); harness.AuthorityBindingHeld();
        release.SetResult();
        _ = await Assert.ThrowsAsync<IOException>(() => operation);
        Assert.Equal(0, harness.RunJournal.InitialCalls); Assert.Empty(harness.Target.Created);
        using WindowsLocalRunAuthority reacquired = WindowsLocalRunAuthority.AcquireResume(harness.Staging, harness.Data.Binding);
    }

    [WindowsLocalRunFact]
    public async Task Completed_LostAcknowledgement_FinalizesAndReplaysWithoutLeaseOrRemoteReads()
    {
        using AdmittedCoordinatorTestHarness harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        harness.RunJournal.LoseCompletionAck = true;
        _ = await Assert.ThrowsAsync<IOException>(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default));
        var snapshot = new RecoveryJournalSnapshot(harness.Data.Admission, harness.RunJournal.Baseline(), DateTimeOffset.UtcNow, null);
        int observations = harness.SourceObservations, readiness = harness.ReadinessCalls, heartbeats = harness.RunJournal.Heartbeats;
        harness.SourceDrift = true; harness.FailReadiness = true; harness.RunJournal.RejectLease = true;
        _ = await CompletedLocalMigrationFinalizer.FinalizeAsync(snapshot,
            new(new(harness.Plan.SourceCommitSha, harness.Data.AdmissionPayload.Identity.RunnerDigestSha256), RecoveryAuthorityTestData.Roles, harness.Data.Trust),
            harness.Staging, harness.Output, "coordinator-test", harness.RootKey, default);
        byte[] manifest = await File.ReadAllBytesAsync(Path.Combine(harness.Output, "manifest.json"));
        _ = await CompletedLocalMigrationFinalizer.FinalizeAsync(snapshot,
            new(new(harness.Plan.SourceCommitSha, harness.Data.AdmissionPayload.Identity.RunnerDigestSha256), RecoveryAuthorityTestData.Roles, harness.Data.Trust),
            harness.Staging, harness.Output, "coordinator-test", harness.RootKey, default);
        Assert.Equal(manifest, await File.ReadAllBytesAsync(Path.Combine(harness.Output, "manifest.json")));
        Assert.Equal(observations, harness.SourceObservations); Assert.Equal(readiness, harness.ReadinessCalls); Assert.Equal(heartbeats, harness.RunJournal.Heartbeats);
        Assert.Equal(0, harness.RunJournal.ResumeCalls);
    }

    [WindowsLocalRunFact]
    public async Task Initial_LaterFailureThenNewCoordinatorResume_PreservesFirstBytesOwnershipAndDumpCount()
    {
        using AdmittedCoordinatorTestHarness harness = await AdmittedCoordinatorTestHarness.CreateAsync();
        string first = DatabaseInventory.ActiveDatabases[0], second = DatabaseInventory.ActiveDatabases[1];
        harness.FailingSourceDatabase = second;
        _ = await Assert.ThrowsAsync<IOException>(() => harness.Coordinator().ExecuteInitialAsync(harness.Authority, default));
        byte[] bytes = await File.ReadAllBytesAsync(harness.Archive(first));
        ShadowDatabase original = harness.RunJournal.Shadows[first];
        Assert.Equal(1, harness.Target.Copies[first]);
        Assert.Equal(1, harness.Dump.Counts[first]);
        harness.FailingSourceDatabase = null;
        harness.Source.Started.Clear();
        (SourceContinuityAttestation continuity, ResumeAuthorizationReceipt authorization) = harness.ResumeAuthority();
        IncrementalMigrationResult completed = await harness.Coordinator().ResumeAsync(continuity, authorization, default);
        Assert.Equal(bytes, await File.ReadAllBytesAsync(harness.Archive(first)));
        Assert.Equal(original, harness.RunJournal.Shadows[first]);
        Assert.Equal(1, harness.Target.Copies[first]);
        Assert.Equal(1, harness.Dump.Counts[first]);
        Assert.Equal(DatabaseInventory.ActiveDatabases, completed.Receipt.Databases.Select(item => item.Database));
        Assert.Equal(DatabaseInventory.ActiveDatabases.Count, completed.Progress.LocalVerified);
        Assert.Equal(0, harness.RunJournal.LegacyCalls);
    }
}
