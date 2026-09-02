using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed partial class PostgreSqlJournalRecoveryAuthorityTests(PostgreSqlAdapterFixture fixture)
{
    [Theory]
    [InlineData("missing-checkpoint")]
    [InlineData("mismatched-receipt")]
    [InlineData("signature")]
    [InlineData("extra-database")]
    [InlineData("early-completion")]
    public async Task Completion_RejectsAnythingExceptFullPersistedSignedCheckpointEvidence(string invalid)
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = await journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default);
        DatabaseMigrationCheckpoint[] checkpoints = Checkpoints(data, lease);
        foreach (DatabaseMigrationCheckpoint checkpoint in invalid == "missing-checkpoint" ? checkpoints.Skip(1) : checkpoints)
        {
            await journal.RegisterShadowAsync(lease, checkpoint.Shadow, default);
            await journal.RecordCheckpointAsync(lease, checkpoint, default);
        }
        MigrationExecutionReceipt receipt = Completion(data, lease, checkpoints);
        if (invalid == "mismatched-receipt") { receipt = Sign(data, receipt with { Databases = [.. receipt.Databases.Select((item, index) => index == 0 ? item with { TotalRows = 77 } : item)] }); }
        if (invalid == "signature") { receipt = receipt with { AttestationSignature = "bad" }; }
        if (invalid == "extra-database") { receipt = Sign(data, receipt with { Databases = [.. receipt.Databases, receipt.Databases[0]] }); }
        if (invalid == "early-completion") { receipt = Sign(data, receipt with { CompletedAtUtc = data.AdmittedAt.AddSeconds(-1) }); }
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.RecordCompletedAsync(lease, receipt, default));
        Assert.Equal("in_progress", await ScalarAsync($"SELECT status FROM \"{schema}\".migration_runs"));
    }

    [Fact]
    public async Task CompletedSnapshot_ReturnsExactVerifiedReceiptAndCheckpointsWithoutLease()
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = await journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default);
        DatabaseMigrationCheckpoint[] checkpoints = Checkpoints(data, lease);
        foreach (DatabaseMigrationCheckpoint checkpoint in checkpoints)
        {
            await journal.RegisterShadowAsync(lease, checkpoint.Shadow, default);
            await journal.RecordCheckpointAsync(lease, checkpoint, default);
        }
        MigrationExecutionReceipt receipt = Completion(data, lease, checkpoints);
        await journal.RecordCompletedAsync(lease, receipt, default);
        RecoveryJournalSnapshot snapshot = await Journal(data, schema).ReadRecoverySnapshotAsync(lease.Identity, default);
        Assert.Equal("completed", snapshot.Baseline.Status);
        Assert.Equal(JsonSerializer.Serialize(receipt), snapshot.Baseline.TerminalReceiptSignedJson);
        Assert.Equal(checkpoints.Length, snapshot.Baseline.Checkpoints.Length);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.HeartbeatAsync(lease, default));
    }

    [Fact]
    public async Task InitialAdmission_PersistsExactSignedTextWithFirstLease_AndLegacyCannotReacquire()
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = await journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default);
        RecoveryJournalSnapshot snapshot = await journal.ReadRecoverySnapshotAsync(lease.Identity, default);
        Assert.Equal(data.Admission.ExactJson, snapshot.Admission.ExactJson);
        Assert.Equal("in_progress", snapshot.Baseline.Status);
        Assert.Equal(lease.Owner, snapshot.Baseline.LeaseOwner);
        Assert.Equal(1, snapshot.Baseline.LeaseAttempt);
        Assert.Equal(lease.FencingToken, snapshot.Baseline.FencingToken);
        await journal.RecordFailedAsync(lease, Failure(lease), default);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => Journal(data, schema).TryBeginAsync(lease.Identity, default));
        Assert.Equal("failed", (await journal.ReadRecoverySnapshotAsync(lease.Identity, default)).Baseline.Status);
    }

    [Fact]
    public async Task Snapshot_MissingSchemaDoesNotCreateAnything()
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(() => Journal(data, schema).ReadRecoverySnapshotAsync(data.Admission.Payload.Identity, default));
        Assert.Equal("run_not_admitted", error.Code);
        Assert.Equal(0L, await ScalarAsync("SELECT count(*) FROM pg_namespace WHERE nspname = $1", schema));
    }

    [Fact]
    public async Task Resume_ConsumesNonceWithExactBaseline_AndPreservesOriginalShadowOwnership()
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease first = await journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default);
        var shadow = new ShadowDatabase(GuardedShadowMigrationRunner.CreateShadowName("Order", first.Identity.RunId), first.Identity.RunId.ToString("D"), "Order")
        { OwnerAttempt = first.Attempt, FencingToken = first.FencingToken };
        await journal.RegisterShadowAsync(first, shadow, default);
        await journal.RecordFailedAsync(first, Failure(first), default);
        data.Baseline = (await journal.ReadRecoverySnapshotAsync(first.Identity, default)).Baseline;
        Assert.Contains("synthetic_failure", data.Baseline.FailureHistoryJson, StringComparison.Ordinal);
        data.Resume = data.PrepareResume();
        MigrationRunLease next = await ResumeAsync(journal, data);
        Assert.Equal(2, next.Attempt);
        Assert.NotEqual(first.FencingToken, next.FencingToken);
        Assert.Equal(shadow, Assert.Single((await journal.ReadRecoverySnapshotAsync(first.Identity, default)).Baseline.Shadows).Shadow);
        await journal.RecordFailedAsync(next, Failure(next), default);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => ResumeAsync(journal, data));
    }

    private PostgreSqlMigrationRunJournal Journal(RecoveryAuthorityTestData data, string schema)
    {
        return new(new(fixture.ControlConnectionString, schema,
        CheckpointVerification: new(data.Admission.Payload.Identity, JsonSerializer.Deserialize<FreshSchemaPlan>(data.Admission.Payload.OriginalSchemaPlanJson)!, data.Trust),
        RecoveryVerification: new(new(data.Admission.Payload.Identity.SourceCommitSha, data.Admission.Payload.Identity.RunnerDigestSha256), RecoveryAuthorityTestData.Roles, data.Trust)));
    }

    private static DatabaseMigrationCheckpoint[] Checkpoints(RecoveryAuthorityTestData data, MigrationRunLease lease)
    {
        FreshSchemaPlan plan = JsonSerializer.Deserialize<FreshSchemaPlan>(data.Admission.Payload.OriginalSchemaPlanJson)!;
        return plan.Databases.Select(database =>
        {
            var shadow = new ShadowDatabase(GuardedShadowMigrationRunner.CreateShadowName(database.Database, lease.Identity.RunId), lease.Identity.RunId.ToString("D"), database.Database)
            { OwnerAttempt = lease.Attempt, FencingToken = lease.FencingToken };
            var evidence = new TableReconciliationEvidence("public.Rows", 1, new('c', 64), new('d', 64), new Dictionary<string, long> { ["ID"] = 0 }, new Dictionary<string, long>());
            string hash = RecoveryAuthorityTestData.Hash($"public.Rows|1|{new string('c', 64)}|{new string('d', 64)}");
            var checkpoint = new DatabaseMigrationCheckpoint(lease.Identity, shadow,
                new(database.Database, shadow.Name, 1, hash) { OwnerAttempt = shadow.OwnerAttempt, FencingToken = shadow.FencingToken },
                new(database.Database, database.SourceSchemaSha256, database.TargetSchemaSha256, [evidence]), DateTimeOffset.UtcNow, "execution", null);
            return checkpoint with { AttestationSignature = Convert.ToBase64String(data.Signers[2].Sign(MigrationEvidenceAttestation.CreatePayload(checkpoint))) };
        }).ToArray();
    }

    private static MigrationExecutionReceipt Completion(RecoveryAuthorityTestData data, MigrationRunLease lease, DatabaseMigrationCheckpoint[] checkpoints)
    {
        return Sign(data,
        new(lease.Identity.RunId, lease.Identity.SourceCommitSha, lease.Identity.SchemaPlanSha256, lease.Identity.BackupManifestSha256, lease.Identity.RunnerDigestSha256,
            lease.Identity.TargetGeneration, DateTimeOffset.UtcNow, checkpoints.Select(item => item.Database).ToArray(), checkpoints.Select(item => item.Reconciliation).ToArray(), "execution", null));
    }

    private static MigrationExecutionReceipt Sign(RecoveryAuthorityTestData data, MigrationExecutionReceipt receipt)
    {
        return receipt with
        { AttestationSignature = Convert.ToBase64String(data.Signers[2].Sign(MigrationEvidenceAttestation.CreatePayload(receipt))) };
    }

    private static Task<RecoveryAuthorityTestData> FreshDataAsync()
    {
        return RecoveryAuthorityTestData.CreateAsync(resumeDelay: TimeSpan.Zero, admittedAt: DateTimeOffset.UtcNow.AddSeconds(-1));
    }

    private static Task<MigrationRunLease> ResumeAsync(PostgreSqlMigrationRunJournal journal, RecoveryAuthorityTestData data)
    {
        return journal.AcquireResumeAsync(data.Continuity, data.Resume, data.Source, data.Binding, data.Runner, data.Target, default);
    }

    private static MigrationFailureReceipt Failure(MigrationRunLease lease)
    {
        return new(lease.Identity.RunId, lease.Identity.SourceCommitSha, lease.Identity.SchemaPlanSha256,
        lease.Identity.BackupManifestSha256, lease.Identity.RunnerDigestSha256, lease.Identity.TargetGeneration, DateTimeOffset.UtcNow, "synthetic_failure", [], [], "execution", null);
    }

    private async Task<object?> ScalarAsync(string sql, params object[] parameters)
    {
        await using var connection = new NpgsqlConnection(fixture.ControlConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        foreach (object parameter in parameters) { _ = command.Parameters.AddWithValue(parameter); }
        return await command.ExecuteScalarAsync();
    }
}
