using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed partial class PostgreSqlJournalRecoveryAuthorityTests
{
    [Fact]
    public async Task Snapshot_MissingResumeSchemaFailsReadonlyWithoutRepair()
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = await journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default);
        _ = await ScalarAsync($"DROP TABLE \"{schema}\".migration_resume_authorizations");
        Assert.Equal("run_not_admitted", (await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.ReadRecoverySnapshotAsync(lease.Identity, default))).Code);
        Assert.Equal(0L, await ScalarAsync("SELECT count(*) FROM pg_tables WHERE schemaname = $1 AND tablename = 'migration_resume_authorizations'", schema));
    }

    [Fact]
    public async Task InitialAdmission_OriginalApprovalExpiresDuringInsertLockWait_RollsBack()
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        _ = await journal.TryBeginAsync(data.Admission.Payload.Identity with { RunId = Guid.NewGuid() }, default);
        ExecutionAuthorizationReceipt original = JsonSerializer.Deserialize<ExecutionAuthorizationReceipt>(data.Admission.Payload.OriginalAuthorizationJson)!;
        original = original with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(2) };
        Assert.True(ExecutionAuthorizationAttestation.TryCreatePayload(original, out byte[] payload));
        original = original with { AttestationSignature = Convert.ToBase64String(data.Signers[1].Sign(payload)) };
        InitialMigrationAdmission admission = data.Verifier.PrepareAdmission(data.AdmissionPayload with
        { OriginalAuthorizationJson = JsonSerializer.Serialize(original), OriginalAuthorizationSha256 = RecoveryAuthorityTestData.Hash(payload) }, data.Signers[2], data.AdmittedAt);
        data.Verifier.ValidateInitialAcquisition(admission, data.Source, data.Binding, DateTimeOffset.UtcNow);
        long key = System.Security.Cryptography.RandomNumberGenerator.GetInt32(1, int.MaxValue);
        await using var blocker = new NpgsqlConnection(fixture.ControlConnectionString);
        await blocker.OpenAsync();
        await using (var setup = new NpgsqlCommand($"""
            CREATE FUNCTION "{schema}".pause_initial() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN PERFORM pg_advisory_xact_lock({key}); RETURN NEW; END $$;
            CREATE TRIGGER pause_initial BEFORE INSERT ON "{schema}".migration_runs FOR EACH ROW EXECUTE FUNCTION "{schema}".pause_initial();
            SELECT pg_advisory_lock({key});
            """, blocker)) { _ = await setup.ExecuteNonQueryAsync(); }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<MigrationRunLease> acquire = journal.AcquireInitialAsync(admission, data.Source, data.Binding, timeout.Token);
        try
        {
            string query = await PostgreSqlJournalTerminalAuthorityTests.WaitForBlockedQueryAsync(fixture.ControlConnectionString, schema, timeout.Token);
            Assert.Contains("INSERT INTO", query, StringComparison.Ordinal);
            await using var clock = new NpgsqlCommand("SELECT clock_timestamp() >= $1", blocker);
            _ = clock.Parameters.AddWithValue(original.ExpiresAtUtc);
            while (!(bool)(await clock.ExecuteScalarAsync(timeout.Token))!) { await Task.Delay(10, timeout.Token); }
        }
        finally
        {
            await using var release = new NpgsqlCommand($"SELECT pg_advisory_unlock({key})", blocker);
            _ = await release.ExecuteScalarAsync();
        }
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => acquire);
        Assert.Equal(0L, await ScalarAsync($"SELECT count(*) FROM \"{schema}\".migration_runs WHERE run_id = $1", admission.Payload.Identity.RunId));
    }

    [Theory]
    [InlineData("expired-original")]
    [InlineData("changed-source")]
    [InlineData("changed-binding")]
    [InlineData("invalid-signature")]
    public async Task InitialAdmission_InvalidCurrentGatesRollBackAdmissionAndFirstLease(string invalid)
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync(resumeDelay: TimeSpan.Zero,
            admittedAt: DateTimeOffset.UtcNow.AddMinutes(invalid == "expired-original" ? -120 : -1));
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        RestoredSourceObservation source = invalid == "changed-source" ? data.Source with { State = data.Source.State with { ConfiguredEndpoint = "other" } } : data.Source;
        LocalExecutionBinding binding = invalid == "changed-binding" ? data.Binding with { HostIdentity = "other" } : data.Binding;
        InitialMigrationAdmission admission = invalid == "invalid-signature" ? InitialMigrationAdmission.Parse(data.Admission.ExactJson.Replace("\"AttestationSignature\":\"", "\"AttestationSignature\":\"bad", StringComparison.Ordinal)) : data.Admission;
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.AcquireInitialAsync(admission, source, binding, default));
        Assert.Equal(0L, await ScalarAsync($"SELECT count(*) FROM \"{schema}\".migration_runs"));
        Assert.Equal(0L, await ScalarAsync($"SELECT count(*) FROM \"{schema}\".migration_resume_authorizations"));
    }

    [Fact]
    public async Task InitialAdmission_ExistingUnadmittedRunIsNeverAdopted()
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease legacy = (await journal.TryBeginAsync(data.Admission.Payload.Identity, default)).Lease!;
        await journal.RecordFailedAsync(legacy, Failure(legacy), default);
        string before = (string)(await ScalarAsync($"SELECT row_to_json(r)::text FROM \"{schema}\".migration_runs r"))!;
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default));
        Assert.Equal("run_not_admitted", (await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.ReadRecoverySnapshotAsync(legacy.Identity, default))).Code);
        Assert.Equal(before, await ScalarAsync($"SELECT row_to_json(r)::text FROM \"{schema}\".migration_runs r"));
    }

    [Fact]
    public async Task Resume_ConcurrentSameApprovalHasExactlyOneWinner_AndNonceCannotBeReauthorized()
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = await journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default);
        await journal.RecordFailedAsync(lease, Failure(lease), default);
        data.Baseline = (await journal.ReadRecoverySnapshotAsync(lease.Identity, default)).Baseline;
        data.Resume = PrepareCurrentResume(data);
        Guid nonce = data.Resume.Payload.Nonce;
        async Task<MigrationRunLease?> AttemptAsync()
        {
            try { return await ResumeAsync(journal, data); }
            catch (MigrationExecutionException) { return null; }
        }
        MigrationRunLease?[] attempts = await Task.WhenAll(AttemptAsync(), AttemptAsync());
        MigrationRunLease winner = Assert.Single(attempts, item => item is not null)!;
        Assert.Equal(2, winner.Attempt);
        Assert.Equal(1L, await ScalarAsync($"SELECT count(*) FROM \"{schema}\".migration_resume_authorizations"));
        await journal.RecordFailedAsync(winner, Failure(winner), default);
        data.Baseline = (await journal.ReadRecoverySnapshotAsync(lease.Identity, default)).Baseline;
        ResumeAuthorizationReceipt fresh = PrepareCurrentResume(data);
        data.Resume = ResumeAuthorizationReceipt.Sign(fresh.Payload with { Nonce = nonce }, data.Signers[1]);
        Assert.Equal("resume_nonce_reused", (await Assert.ThrowsAsync<MigrationExecutionException>(() => ResumeAsync(journal, data))).Code);
    }

    [Fact]
    public async Task Resume_ApprovalExpiresDuringActualRowLockWait_IsNotConsumed()
    {
        using var data = await FreshDataAsync();
        string schema = $"recovery_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = await journal.AcquireInitialAsync(data.Admission, data.Source, data.Binding, default);
        await journal.RecordFailedAsync(lease, Failure(lease), default);
        data.Baseline = (await journal.ReadRecoverySnapshotAsync(lease.Identity, default)).Baseline;
        ResumeAuthorizationReceipt fresh = PrepareCurrentResume(data);
        data.Resume = ResumeAuthorizationReceipt.Sign(fresh.Payload with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(2) }, data.Signers[1]);
        data.Verifier.ValidateResume(data.Admission, data.Continuity, data.Resume, data.Baseline, data.Source, data.Binding, data.Runner, data.Target, DateTimeOffset.UtcNow);
        await using var blocker = new NpgsqlConnection(fixture.ControlConnectionString);
        await blocker.OpenAsync();
        await using NpgsqlTransaction transaction = await blocker.BeginTransactionAsync();
        await using (var hold = new NpgsqlCommand($"SELECT 1 FROM \"{schema}\".migration_runs FOR UPDATE", blocker, transaction)) { _ = await hold.ExecuteScalarAsync(); }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<MigrationRunLease> acquire = journal.AcquireResumeAsync(data.Continuity, data.Resume, data.Source, data.Binding, data.Runner, data.Target, timeout.Token);
        try
        {
            string query = await PostgreSqlJournalTerminalAuthorityTests.WaitForBlockedQueryAsync(fixture.ControlConnectionString, schema, timeout.Token);
            Assert.Contains("FOR UPDATE", query, StringComparison.Ordinal);
            await using var clock = new NpgsqlCommand("SELECT clock_timestamp() >= $1", blocker, transaction);
            _ = clock.Parameters.AddWithValue(data.Resume.Payload.ExpiresAtUtc);
            while (!(bool)(await clock.ExecuteScalarAsync(timeout.Token))!) { await Task.Delay(10, timeout.Token); }
        }
        finally { await transaction.CommitAsync(); }
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => acquire);
        Assert.Equal(data.Baseline.ComputeSha256(), (await journal.ReadRecoverySnapshotAsync(lease.Identity, default)).Baseline.ComputeSha256());
        Assert.Equal(0L, await ScalarAsync($"SELECT count(*) FROM \"{schema}\".migration_resume_authorizations"));
    }
}
