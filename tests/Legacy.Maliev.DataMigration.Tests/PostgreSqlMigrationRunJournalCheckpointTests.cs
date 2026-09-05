using System.Text.Json;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlMigrationRunJournalCheckpointTests(PostgreSqlAdapterFixture fixture)
{
    private static readonly JsonSerializerOptions IndentedJson = new() { WriteIndented = true };

    [Fact]
    public async Task Checkpoint_PersistsTheSameDetachedBytesThatWereVerified()
    {
        using var data = new CheckpointTestData();
        string schema = NewSchema();
        PostgreSqlMigrationRunJournal initial = Journal(data, schema);
        MigrationRunLease lease = (await initial.TryBeginAsync(data.Identity, default)).Lease!;
        DatabaseMigrationCheckpoint checkpoint = data.ForLease(lease);
        await initial.RegisterShadowAsync(lease, checkpoint.Shadow, default);
        var mutableCounts = (Dictionary<string, long>)checkpoint.Reconciliation.Tables[0].NullCounts;
        var trust = new MutatingTrustStore(data.Options.TrustStore, () => mutableCounts["Value"] = 1);
        var journal = new PostgreSqlMigrationRunJournal(new(fixture.ControlConnectionString, schema,
            CheckpointVerification: data.Options with { TrustStore = trust }));

        await journal.RecordCheckpointAsync(lease, checkpoint, default);

        Assert.Equal(1, mutableCounts["Value"]);
        DatabaseMigrationCheckpoint restored = Assert.Single(await initial.GetCheckpointsAsync(lease, default));
        Assert.Equal(0, restored.Reconciliation.Tables[0].NullCounts["Value"]);
    }

    [Fact]
    public async Task Checkpoint_IdenticalReplayIsDurableAcrossInstancesAndConflictingReplayFails()
    {
        using var data = new CheckpointTestData();
        string schema = NewSchema();
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = (await journal.TryBeginAsync(data.Identity, default)).Lease!;
        DatabaseMigrationCheckpoint checkpoint = data.ForLease(lease);
        await journal.RegisterShadowAsync(lease, checkpoint.Shadow, default);
        await journal.RecordCheckpointAsync(lease, checkpoint, default);
        await Journal(data, schema).RecordCheckpointAsync(lease, checkpoint, default);

        DatabaseMigrationCheckpoint restored = Assert.Single(await Journal(data, schema).GetCheckpointsAsync(lease, default));
        Assert.Equal(checkpoint.AttestationSignature, restored.AttestationSignature);
        Assert.Equal(MigrationEvidenceAttestation.CreatePayload(checkpoint), MigrationEvidenceAttestation.CreatePayload(restored));
        DatabaseMigrationCheckpoint conflict = data.Sign(checkpoint with { CommittedAtUtc = checkpoint.CommittedAtUtc.AddSeconds(1) });
        Assert.Equal("checkpoint_conflict", (await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.RecordCheckpointAsync(lease, conflict, default))).Code);
        Assert.Equal(checkpoint.AttestationSignature, Assert.Single(await journal.GetCheckpointsAsync(lease, default)).AttestationSignature);
    }

    [Fact]
    public async Task Checkpoint_FailureAndNewLeaseRetainOriginalOwnershipWithoutReregistration()
    {
        using var data = new CheckpointTestData();
        string schema = NewSchema();
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = (await journal.TryBeginAsync(data.Identity, default)).Lease!;
        DatabaseMigrationCheckpoint checkpoint = data.ForLease(lease);
        await journal.RegisterShadowAsync(lease, checkpoint.Shadow, default);
        await journal.RecordCheckpointAsync(lease, checkpoint, default);
        MigrationRunIdentity identity = data.Identity;
        await journal.RecordFailedAsync(lease, new(identity.RunId, identity.SourceCommitSha, identity.SchemaPlanSha256,
            identity.BackupManifestSha256, identity.RunnerDigestSha256, identity.TargetGeneration, DateTimeOffset.UtcNow,
            "test_failure", [], [], "test-key", null), default);

        PostgreSqlMigrationRunJournal restarted = Journal(data, schema);
        MigrationRunLease next = (await restarted.TryBeginAsync(data.Identity, default)).Lease!;
        Assert.Equal(2, next.Attempt);
        DatabaseMigrationCheckpoint recovered = Assert.Single(await restarted.GetCheckpointsAsync(next, default));
        Assert.Equal(checkpoint.Shadow, recovered.Shadow);
        Assert.NotEqual(next.FencingToken, recovered.Shadow.FencingToken);
        await restarted.RecordCheckpointAsync(next, recovered, default);
        Assert.Equal([checkpoint.Shadow], await restarted.GetPendingShadowsAsync(next, default));
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("attempt")]
    [InlineData("fence")]
    [InlineData("identity")]
    [InlineData("expired")]
    [InlineData("taken-over")]
    public async Task Checkpoint_InvalidLeaseCannotReadOrWriteEvenWithPastClientClock(string corruption)
    {
        using var data = new CheckpointTestData();
        string schema = NewSchema();
        PostgreSqlMigrationRunJournal journal = Journal(data, schema, new FixedTimeProvider(DateTimeOffset.UtcNow.AddYears(-1)));
        MigrationRunLease lease = (await journal.TryBeginAsync(data.Identity, default)).Lease!;
        DatabaseMigrationCheckpoint checkpoint = data.ForLease(lease);
        await journal.RegisterShadowAsync(lease, checkpoint.Shadow, default);
        await journal.RecordCheckpointAsync(lease, checkpoint, default);
        if (corruption is "expired" or "taken-over")
        {
            await ExpireAsync(schema, data.Identity.RunId);
            if (corruption == "taken-over")
            {
                Assert.Equal(MigrationRunStartStatus.Acquired, (await Journal(data, schema).TryBeginAsync(data.Identity, default)).Status);
            }
        }
        MigrationRunLease invalid = corruption switch
        {
            "owner" => lease with { Owner = "other-owner" },
            "attempt" => lease with { Attempt = lease.Attempt + 1 },
            "fence" => lease with { FencingToken = Guid.NewGuid() },
            "identity" => lease with { Identity = lease.Identity with { TargetGeneration = "other" } },
            _ => lease,
        };
        Assert.Equal("run_lease_lost", (await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.RecordCheckpointAsync(invalid, checkpoint, default))).Code);
        Assert.Equal("run_lease_lost", (await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.GetCheckpointsAsync(invalid, default))).Code);
        if (corruption is "expired" or "taken-over")
        {
            Assert.Equal("run_lease_lost", (await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.HeartbeatAsync(lease, default))).Code);
        }
    }

    [Fact]
    public async Task Checkpoint_MissingTrustConfigurationFailsClosed()
    {
        using var data = new CheckpointTestData();
        var journal = new PostgreSqlMigrationRunJournal(new(fixture.ControlConnectionString, NewSchema()));
        MigrationRunLease lease = (await journal.TryBeginAsync(data.Identity, default)).Lease!;
        Assert.Equal("checkpoint_verifier_required", (await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.RecordCheckpointAsync(lease, data.ForLease(lease), default))).Code);
        Assert.Equal("checkpoint_verifier_required", (await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.GetCheckpointsAsync(lease, default))).Code);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("changed")]
    [InlineData("deleted")]
    public async Task Checkpoint_RequiresOriginalRegisteredInventoryOnRecordAndRead(string corruption)
    {
        using var data = new CheckpointTestData();
        string schema = NewSchema();
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = (await journal.TryBeginAsync(data.Identity, default)).Lease!;
        DatabaseMigrationCheckpoint checkpoint = data.ForLease(lease);
        Assert.Equal("checkpoint_inventory_invalid", (await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.RecordCheckpointAsync(lease, checkpoint, default))).Code);
        await journal.RegisterShadowAsync(lease, checkpoint.Shadow, default);
        await journal.RecordCheckpointAsync(lease, checkpoint, default);
        string sql = corruption switch
        {
            "missing" => $"DELETE FROM \"{schema}\".migration_run_shadows WHERE run_id = $1",
            "changed" => $"UPDATE \"{schema}\".migration_run_shadows SET owner_attempt = 77 WHERE run_id = $1",
            _ => $"UPDATE \"{schema}\".migration_run_shadows SET cleanup_status = 'deleted' WHERE run_id = $1",
        };
        await ExecuteAsync(sql, data.Identity.RunId);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.GetCheckpointsAsync(lease, default));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.RecordCheckpointAsync(lease, checkpoint, default));
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("identity")]
    [InlineData("noncanonical")]
    [InlineData("malformed")]
    public async Task Checkpoint_StoredPayloadIsRevalidatedOnRead(string corruption)
    {
        using var data = new CheckpointTestData();
        string schema = NewSchema();
        PostgreSqlMigrationRunJournal journal = Journal(data, schema);
        MigrationRunLease lease = (await journal.TryBeginAsync(data.Identity, default)).Lease!;
        DatabaseMigrationCheckpoint checkpoint = data.ForLease(lease);
        await journal.RegisterShadowAsync(lease, checkpoint.Shadow, default);
        await journal.RecordCheckpointAsync(lease, checkpoint, default);
        string payload = corruption switch
        {
            "signature" => Encoding.UTF8.GetString(MigrationEvidenceAttestation.SerializeCheckpoint(checkpoint with { AttestationSignature = "bad" })),
            "identity" => Encoding.UTF8.GetString(MigrationEvidenceAttestation.SerializeCheckpoint(data.Sign(checkpoint with { Identity = checkpoint.Identity with { TargetGeneration = "other" } }))),
            "malformed" => "{",
            _ => JsonSerializer.Serialize(checkpoint, IndentedJson),
        };
        await ExecuteAsync($"UPDATE \"{schema}\".migration_database_checkpoints SET checkpoint_json = $2 WHERE run_id = $1", data.Identity.RunId, payload);
        Assert.Equal("checkpoint_invalid", (await Assert.ThrowsAsync<MigrationExecutionException>(() => journal.GetCheckpointsAsync(lease, default))).Code);
    }

    [Fact]
    public async Task MigrationRunJournal_ClientClockCannotExpireLiveLeaseOrExtendLeasePastServerDuration()
    {
        using var data = new CheckpointTestData();
        string schema = NewSchema();
        DateTimeOffset serverBeforeAcquire = await ReadServerTimeAsync();
        PostgreSqlMigrationRunJournal past = Journal(data, schema, new FixedTimeProvider(serverBeforeAcquire.AddYears(-10)));
        MigrationRunLease lease = (await past.TryBeginAsync(data.Identity, default)).Lease!;
        DateTimeOffset serverAfterAcquire = await ReadServerTimeAsync();
        Assert.InRange(lease.ExpiresAtUtc, serverBeforeAcquire.AddSeconds(60), serverAfterAcquire.AddSeconds(60));
        PostgreSqlMigrationRunJournal future = Journal(data, schema, new FixedTimeProvider(serverBeforeAcquire.AddYears(10)));
        Assert.Equal(MigrationRunStartStatus.InProgress, (await future.TryBeginAsync(data.Identity, default)).Status);
        DateTimeOffset serverBeforeHeartbeat = await ReadServerTimeAsync();
        MigrationRunLease renewed = await future.HeartbeatAsync(lease, default);
        DateTimeOffset serverAfterHeartbeat = await ReadServerTimeAsync();
        Assert.InRange(renewed.ExpiresAtUtc, serverBeforeHeartbeat.AddSeconds(60), serverAfterHeartbeat.AddSeconds(60));
    }

    private PostgreSqlMigrationRunJournal Journal(CheckpointTestData data, string schema, TimeProvider? clock = null)
    {
        return new(new(
        fixture.ControlConnectionString, schema, Guid.NewGuid().ToString("N"), TimeSpan.FromMinutes(1), clock,
        CheckpointVerification: data.Options));
    }

    private static string NewSchema()
    {
        return $"checkpoint_{Guid.NewGuid():N}";
    }

    private Task ExpireAsync(string schema, Guid runId)
    {
        return ExecuteAsync(
        $"UPDATE \"{schema}\".migration_runs SET lease_expires_at_utc = clock_timestamp() - interval '1 second' WHERE run_id = $1", runId);
    }

    private async Task<DateTimeOffset> ReadServerTimeAsync()
    {
        await using var connection = new NpgsqlConnection(fixture.ControlConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT clock_timestamp();", connection);
        return new DateTimeOffset((DateTime)(await command.ExecuteScalarAsync())!);
    }

    private async Task ExecuteAsync(string sql, Guid runId, string? payload = null)
    {
        await using var connection = new NpgsqlConnection(fixture.ControlConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = command.Parameters.AddWithValue(runId);
        if (payload is not null)
        {
            _ = command.Parameters.AddWithValue(payload);
        }
        Assert.Equal(1, await command.ExecuteNonQueryAsync());
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }

    private sealed class MutatingTrustStore(IReceiptAttestationTrustStore inner, Action mutate) : IReceiptAttestationTrustStore
    {
        public bool ContainsKey(string keyId)
        {
            return inner.ContainsKey(keyId);
        }

        public bool TryGetPublicKeyFingerprintSha256(string keyId, out string fingerprintSha256)
        {
            return inner.TryGetPublicKeyFingerprintSha256(keyId, out fingerprintSha256);
        }

        public bool Verify(string keyId, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature)
        {
            bool trusted = inner.Verify(keyId, payload, signature);
            mutate();
            return trusted;
        }
    }
}
