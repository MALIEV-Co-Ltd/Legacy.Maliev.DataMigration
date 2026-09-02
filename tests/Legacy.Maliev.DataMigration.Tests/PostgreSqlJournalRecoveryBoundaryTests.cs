using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed partial class PostgreSqlJournalRecoveryAuthorityTests
{
    [Theory]
    [InlineData("deleted")]
    [InlineData("same-attempt-different-database")]
    public async Task RegisteredAdmittedShadow_CannotBeRelabeledEvenOnSameAttemptOrAfterDeletion(string scenario)
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = await journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default);
        ShadowDatabase original = Checkpoints(data, lease)[0].Shadow;
        await journal.RegisterShadowAsync(lease, original, default);
        if (scenario == "deleted")
        {
            await journal.RecordShadowCleanupAsync(lease, new(original.Name, true, null) { OwnerAttempt = original.OwnerAttempt, FencingToken = original.FencingToken }, default);
        }
        ShadowDatabase changed = scenario == "deleted" ? original : original with { Database = "another-database" };
        string before = (string)(await ScalarAsync($"SELECT row_to_json(s)::text FROM \"{schema}\".migration_run_shadows s"))!;
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.RegisterShadowAsync(lease, changed, default));
        Assert.Equal(before, await ScalarAsync($"SELECT row_to_json(s)::text FROM \"{schema}\".migration_run_shadows s"));
    }

    [Fact]
    public async Task AdmittedCheckpoint_RejectsWrongConfiguredSigningRoleAtPersistence()
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = await journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default);
        DatabaseMigrationCheckpoint checkpoint = Checkpoints(data, lease)[0] with { AttestationKeyId = "provenance" };
        checkpoint = checkpoint with { AttestationSignature = Convert.ToBase64String(data.Signers[3].Sign(MigrationEvidenceAttestation.CreatePayload(checkpoint))) };
        await journal.RegisterShadowAsync(lease, checkpoint.Shadow, default);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.RecordCheckpointAsync(lease, checkpoint, default));
        Assert.Equal(0L, await ScalarAsync($"SELECT count(*) FROM \"{schema}\".migration_database_checkpoints"));
    }

    [Fact]
    public async Task AdmittedCheckpoint_LegacyReadCannotAcceptWrongRoleStoredCheckpoint()
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = await journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default);
        DatabaseMigrationCheckpoint checkpoint = Checkpoints(data, lease)[0] with { AttestationKeyId = "provenance" };
        checkpoint = checkpoint with { AttestationSignature = Convert.ToBase64String(data.Signers[3].Sign(MigrationEvidenceAttestation.CreatePayload(checkpoint))) };
        await journal.RegisterShadowAsync(lease, checkpoint.Shadow, default);
        _ = await ScalarAsync($"INSERT INTO \"{schema}\".migration_database_checkpoints VALUES ($1, $2, $3)", lease.Identity.RunId,
            checkpoint.Database.Database, Encoding.UTF8.GetString(MigrationEvidenceAttestation.SerializeCheckpoint(checkpoint)));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.GetCheckpointsAsync(lease, default));
    }

    [Fact]
    public async Task Completion_RechecksPersistedCheckpointAfterRowWait_NotCallerEvidence()
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
        await using var blocker = new NpgsqlConnection(fixture.ControlConnectionString);
        await blocker.OpenAsync();
        await using NpgsqlTransaction transaction = await blocker.BeginTransactionAsync();
        await using (var hold = new NpgsqlCommand($"SELECT 1 FROM \"{schema}\".migration_runs FOR UPDATE", blocker, transaction)) { _ = await hold.ExecuteScalarAsync(); }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task terminal = journal.RecordCompletedAsync(lease, receipt, timeout.Token);
        try
        {
            string query = await PostgreSqlJournalTerminalAuthorityTests.WaitForBlockedQueryAsync(fixture.ControlConnectionString, schema, timeout.Token);
            Assert.Contains("FOR UPDATE", query, StringComparison.Ordinal);
            await using var corrupt = new NpgsqlCommand($"DELETE FROM \"{schema}\".migration_database_checkpoints WHERE source_database = $1", blocker, transaction);
            _ = corrupt.Parameters.AddWithValue(checkpoints[0].Database.Database);
            Assert.Equal(1, await corrupt.ExecuteNonQueryAsync());
        }
        finally { await transaction.CommitAsync(); }
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => terminal);
        Assert.Equal("in_progress", await ScalarAsync($"SELECT status FROM \"{schema}\".migration_runs"));
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("attempt")]
    [InlineData("fence")]
    [InlineData("status")]
    [InlineData("failure-history")]
    [InlineData("receipt")]
    [InlineData("shadow-cleanup")]
    [InlineData("shadow-error")]
    [InlineData("shadow-owner")]
    [InlineData("checkpoint")]
    public async Task Resume_AnySubstantiveBaselineDriftRejectsWithoutConsumingNonce(string drift)
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = await journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default);
        DatabaseMigrationCheckpoint checkpoint = Checkpoints(data, lease)[0];
        await journal.RegisterShadowAsync(lease, checkpoint.Shadow, default);
        await journal.RecordCheckpointAsync(lease, checkpoint, default);
        await journal.RecordFailedAsync(lease, Failure(lease), default);
        data.Baseline = (await journal.ReadRecoverySnapshotAsync(lease.Identity, default)).Baseline;
        data.Resume = PrepareCurrentResume(data);
        string change = drift switch
        {
            "owner" => "migration_runs SET lease_owner = 'different'",
            "attempt" => "migration_runs SET lease_attempt = 9",
            "fence" => "migration_runs SET fencing_token = '11111111-1111-1111-1111-111111111111'",
            "status" => "migration_runs SET status = 'in_progress'",
            "failure-history" => "migration_runs SET failure_receipts = '[{\"changed\":true}]'::jsonb",
            "receipt" => "migration_runs SET receipt_signed_json = 'changed'",
            "shadow-cleanup" => "migration_run_shadows SET cleanup_attempts = 1",
            "shadow-error" => "migration_run_shadows SET last_error_code = 'changed'",
            "shadow-owner" => "migration_run_shadows SET owner_attempt = 9",
            _ => "migration_database_checkpoints SET checkpoint_json = '{}'",
        };
        _ = await ScalarAsync($"UPDATE \"{schema}\".{change}");
        string before = (string)(await ScalarAsync($"SELECT row_to_json(r)::text FROM \"{schema}\".migration_runs r"))!;
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => ResumeAsync(journal, data));
        Assert.Equal(before, await ScalarAsync($"SELECT row_to_json(r)::text FROM \"{schema}\".migration_runs r"));
        Assert.Equal(0L, await ScalarAsync($"SELECT count(*) FROM \"{schema}\".migration_resume_authorizations"));
    }

    [Fact]
    public async Task Snapshot_ReadonlyConnectionAndConcurrentCommit_UsesOneConsistentSnapshot()
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = await journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default);
        DatabaseMigrationCheckpoint checkpoint = Checkpoints(data, lease)[0];
        await journal.RegisterShadowAsync(lease, checkpoint.Shadow, default);
        RecoveryJournalSnapshot before = await journal.ReadRecoverySnapshotAsync(lease.Identity, default);
        var builder = new NpgsqlConnectionStringBuilder(fixture.ControlConnectionString) { Options = "-c default_transaction_read_only=on" };
        var readOnly = new PostgreSqlMigrationRunJournal(new(builder.ConnectionString, schema,
            RecoveryVerification: new(new(lease.Identity.SourceCommitSha, lease.Identity.RunnerDigestSha256), RecoveryAuthorityTestData.Roles, data.Trust)));
        await using var blocker = new NpgsqlConnection(fixture.ControlConnectionString);
        await blocker.OpenAsync();
        await using NpgsqlTransaction transaction = await blocker.BeginTransactionAsync();
        await using (var hold = new NpgsqlCommand($"LOCK TABLE \"{schema}\".migration_run_shadows IN ACCESS EXCLUSIVE MODE", blocker, transaction)) { _ = await hold.ExecuteNonQueryAsync(); }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<RecoveryJournalSnapshot> read = readOnly.ReadRecoverySnapshotAsync(lease.Identity, timeout.Token);
        try
        {
            string query = await PostgreSqlJournalTerminalAuthorityTests.WaitForBlockedQueryAsync(fixture.ControlConnectionString, schema, timeout.Token);
            Assert.Contains("SELECT shadow_name", query, StringComparison.Ordinal);
            // The reader already observed the run row. Commit a new status and checkpoint together
            // while its next table read waits; neither new fact may leak into its older snapshot.
            _ = await ScalarAsync($"""
                WITH updated AS (UPDATE "{schema}".migration_runs SET status = 'failed' RETURNING run_id)
                INSERT INTO "{schema}".migration_database_checkpoints SELECT run_id, $1, $2 FROM updated
                """, checkpoint.Database.Database, Encoding.UTF8.GetString(MigrationEvidenceAttestation.SerializeCheckpoint(checkpoint)));
        }
        finally { await transaction.CommitAsync(); }
        RecoveryJournalSnapshot actual = await read;
        Assert.Equal(before.Baseline.ComputeSha256(), actual.Baseline.ComputeSha256());
        RecoveryJournalSnapshot after = await readOnly.ReadRecoverySnapshotAsync(lease.Identity, default);
        Assert.Equal("failed", after.Baseline.Status);
        _ = Assert.Single(after.Baseline.Checkpoints);
    }

    [Fact]
    public async Task Resume_LiveLeaseRejected_ButRoutineHeartbeatDoesNotChangeBaseline()
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = await journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default);
        data.Baseline = (await journal.ReadRecoverySnapshotAsync(lease.Identity, default)).Baseline;
        data.Resume = PrepareCurrentResume(data);
        _ = await journal.HeartbeatAsync(lease, default);
        Assert.Equal(data.Baseline.ComputeSha256(), (await journal.ReadRecoverySnapshotAsync(lease.Identity, default)).Baseline.ComputeSha256());
        Assert.Equal("run_lease_live", (await Assert.ThrowsAsync<MigrationExecutionException>(() => ResumeAsync(journal, data))).Code);
        _ = await ScalarAsync($"UPDATE \"{schema}\".migration_runs SET lease_expires_at_utc = clock_timestamp() - interval '1 second'");
        Assert.Equal(2, (await ResumeAsync(journal, data)).Attempt);
    }

    [Fact]
    public async Task Resume_LeaseWriteFailureRollsBackConsumedNonceAndRetainsExactBaseline()
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = await journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default);
        await journal.RecordFailedAsync(lease, Failure(lease), default);
        data.Baseline = (await journal.ReadRecoverySnapshotAsync(lease.Identity, default)).Baseline;
        data.Resume = PrepareCurrentResume(data);
        _ = await ScalarAsync($"""
            CREATE FUNCTION "{schema}".reject_lease() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'synthetic lease failure'; END $$;
            CREATE TRIGGER reject_lease BEFORE UPDATE ON "{schema}".migration_runs FOR EACH ROW EXECUTE FUNCTION "{schema}".reject_lease();
            """);
        _ = await Assert.ThrowsAsync<PostgresException>(() => ResumeAsync(journal, data));
        Assert.Equal(0L, await ScalarAsync($"SELECT count(*) FROM \"{schema}\".migration_resume_authorizations"));
        Assert.Equal(data.Baseline.ComputeSha256(), (await journal.ReadRecoverySnapshotAsync(lease.Identity, default)).Baseline.ComputeSha256());
        _ = await ScalarAsync($"DROP TRIGGER reject_lease ON \"{schema}\".migration_runs");
        Assert.Equal(2, (await ResumeAsync(journal, data)).Attempt);
        Assert.Equal(data.Resume.ExactJson, await ScalarAsync($"SELECT authorization_signed_json FROM \"{schema}\".migration_resume_authorizations"));
        Assert.Equal(data.Continuity.ExactJson, await ScalarAsync($"SELECT continuity_signed_json FROM \"{schema}\".migration_resume_authorizations"));
    }
    private static ResumeAuthorizationReceipt PrepareCurrentResume(RecoveryAuthorityTestData data)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return data.Verifier.PrepareResume(data.Admission, data.Continuity, data.Baseline, data.Source, data.Binding, data.Runner, data.Target,
            Guid.NewGuid(), now, data.Continuity.Payload.ExpiresAtUtc, data.Signers[1], now);
    }
}
