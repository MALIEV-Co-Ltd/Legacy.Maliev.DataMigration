using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlMigrationRunJournalCrashRecoveryTests(PostgreSqlAdapterFixture fixture)
{
    private static readonly DateTimeOffset Now = new(2026, 8, 29, 8, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CompletedReceipt_JournalRoundTripPreservesHistoricalSignedPayloadBytes(bool legacyJsonbOnly)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string schema = $"journal_{Guid.NewGuid():N}";
        PostgreSqlMigrationRunJournal journal = Journal(schema, "worker-a", TimeProvider.System);
        MigrationRunIdentity identity = Identity();
        MigrationRunLease lease = (await journal.TryBeginAsync(identity, default)).Lease!;
        var table = new TableReconciliationEvidence("public.Items", 1, new string('e', 64), new string('f', 64),
            new Dictionary<string, long> { ["zz"] = 0, ["a"] = 0 }, new Dictionary<string, long>())
        {
            ForeignKeyRelationshipCounts = new Dictionary<string, long> { ["zz"] = 1, ["a"] = 1 },
        };
        var unsigned = new MigrationExecutionReceipt(identity.RunId, identity.SourceCommitSha, identity.SchemaPlanSha256,
            identity.BackupManifestSha256, identity.RunnerDigestSha256, identity.TargetGeneration, DateTimeOffset.UtcNow,
            [new("Order", "legacy_shadow_order_test", 1, new string('e', 64))],
            [new("Order", new string('a', 64), new string('b', 64), [table])
            {
                SequenceNextValues = new Dictionary<string, long> { ["zz"] = 2, ["a"] = 2 },
            }], "synthetic-test-key", null);
        byte[] signedPayload = MigrationEvidenceAttestation.CreatePayload(unsigned);
        byte[] signature = key.SignData(signedPayload, HashAlgorithmName.SHA256);
        MigrationExecutionReceipt signed = unsigned with { AttestationSignature = Convert.ToBase64String(signature) };
        Assert.True(key.VerifyData(MigrationEvidenceAttestation.CreatePayload(signed), signature, HashAlgorithmName.SHA256));

        await journal.RecordCompletedAsync(lease, signed, default);
        await using var connection = new NpgsqlConnection(fixture.ControlConnectionString);
        await connection.OpenAsync();
        if (legacyJsonbOnly)
        {
            // Simulate the pre-upgrade schema. Schema initialization must add only a NULL text column,
            // never repair or re-sign the historical JSONB document.
            await using var downgrade = new NpgsqlCommand($"ALTER TABLE \"{schema}\".migration_runs DROP COLUMN receipt_signed_json", connection);
            _ = await downgrade.ExecuteNonQueryAsync();
        }
        await using var readJsonb = new NpgsqlCommand($"SELECT receipt_json::text FROM \"{schema}\".migration_runs WHERE run_id = $1", connection);
        _ = readJsonb.Parameters.AddWithValue(identity.RunId);
        string storedLegacyJson = (string)(await readJsonb.ExecuteScalarAsync())!;
        MigrationRunStartResult replay = await Journal(schema, "worker-b", TimeProvider.System).TryBeginAsync(identity, default);

        Assert.Equal(MigrationRunStartStatus.AlreadyCompleted, replay.Status);
        Assert.Null(replay.Lease);
        MigrationExecutionReceipt restored = Assert.IsType<MigrationExecutionReceipt>(replay.CompletedReceipt);
        Assert.Equal(!legacyJsonbOnly, key.VerifyData(MigrationEvidenceAttestation.CreatePayload(restored),
            Convert.FromBase64String(restored.AttestationSignature!), HashAlgorithmName.SHA256));
        Assert.Equal(storedLegacyJson, await readJsonb.ExecuteScalarAsync());
        await using var readSigned = new NpgsqlCommand($"SELECT receipt_signed_json FROM \"{schema}\".migration_runs WHERE run_id = $1", connection);
        _ = readSigned.Parameters.AddWithValue(identity.RunId);
        if (legacyJsonbOnly)
        {
            _ = Assert.IsType<DBNull>(await readSigned.ExecuteScalarAsync());
        }
        else
        {
            Assert.Equal(signedPayload, MigrationEvidenceAttestation.CreatePayload(restored));
            Assert.Equal(JsonSerializer.Serialize(signed), JsonSerializer.Serialize(restored));
            Assert.Equal(JsonSerializer.Serialize(signed), await readSigned.ExecuteScalarAsync());
        }
    }

    [Fact]
    public async Task TryBegin_LeaseExpiresWhileQueuedOnRunRowLock_UsesFreshServerTimeAfterLock()
    {
        string schema = $"journal_{Guid.NewGuid():N}";
        MigrationRunIdentity identity = Identity();
        MigrationRunLease first = (await Journal(schema, "worker-a", TimeProvider.System).TryBeginAsync(identity, default)).Lease!;
        await using var barrier = new NpgsqlConnection(fixture.ControlConnectionString);
        await barrier.OpenAsync();
        long barrierKey = RandomNumberGenerator.GetInt32(1, int.MaxValue);
        await using (var setup = new NpgsqlCommand($"""
            CREATE FUNCTION "{schema}".pause_admission() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN PERFORM pg_advisory_xact_lock({barrierKey}); RETURN NEW; END $$;
            CREATE TRIGGER pause_admission BEFORE INSERT ON "{schema}".migration_runs
            FOR EACH ROW EXECUTE FUNCTION "{schema}".pause_admission();
            SELECT pg_advisory_lock({barrierKey});
            """, barrier))
        {
            _ = await setup.ExecuteNonQueryAsync();
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<MigrationRunStartResult> admission = Journal(schema, "worker-b", TimeProvider.System).TryBeginAsync(identity, timeout.Token);
        try
        {
            // The insert trigger runs after schema DDL and the first server-time read. Establishing
            // the row lock now ensures this test queues on FOR UPDATE, not on schema initialization.
            await WaitForBlockedQueryAsync(barrier, schema, "INSERT INTO", timeout.Token);
            await using var owner = new NpgsqlConnection(fixture.ControlConnectionString);
            await owner.OpenAsync(timeout.Token);
            await using NpgsqlTransaction ownerTransaction = await owner.BeginTransactionAsync(timeout.Token);
            await using var expiry = new NpgsqlCommand($"""
                UPDATE "{schema}".migration_runs
                SET lease_expires_at_utc = clock_timestamp() + interval '1 second'
                WHERE run_id = $1 RETURNING lease_expires_at_utc;
                """, barrier);
            _ = expiry.Parameters.AddWithValue(identity.RunId);
            DateTime expiration = (DateTime)(await expiry.ExecuteScalarAsync(timeout.Token))!;
            await using (var holdRow = new NpgsqlCommand($"SELECT 1 FROM \"{schema}\".migration_runs WHERE run_id = $1 FOR UPDATE", owner, ownerTransaction))
            {
                _ = holdRow.Parameters.AddWithValue(identity.RunId);
                Assert.Equal(1, await holdRow.ExecuteScalarAsync(timeout.Token));
            }
            await using (var release = new NpgsqlCommand($"SELECT pg_advisory_unlock({barrierKey})", barrier))
            {
                Assert.True((bool)(await release.ExecuteScalarAsync(timeout.Token))!);
            }
            await WaitForBlockedQueryAsync(barrier, schema, "FOR UPDATE", timeout.Token);
            await using var serverTime = new NpgsqlCommand("SELECT clock_timestamp() >= $1", barrier);
            _ = serverTime.Parameters.AddWithValue(expiration);
            while (!(bool)(await serverTime.ExecuteScalarAsync(timeout.Token))!)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(10), timeout.Token);
            }
            await ownerTransaction.CommitAsync(timeout.Token);

            MigrationRunStartResult resumed = await admission.WaitAsync(timeout.Token);
            Assert.Equal(MigrationRunStartStatus.Acquired, resumed.Status);
            Assert.Equal(first.Attempt + 1, resumed.Lease!.Attempt);
            Assert.NotEqual(first.FencingToken, resumed.Lease.FencingToken);
            Assert.True(resumed.Lease.ExpiresAtUtc > new DateTimeOffset(expiration));
        }
        finally
        {
            await timeout.CancelAsync();
            await using var release = new NpgsqlCommand($"SELECT pg_advisory_unlock({barrierKey})", barrier);
            _ = await release.ExecuteScalarAsync();
            try { _ = await admission; }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
        }
    }

    private static async Task WaitForBlockedQueryAsync(NpgsqlConnection observer, string schema, string queryFragment, CancellationToken token)
    {
        await using var command = new NpgsqlCommand("""
            SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                WHERE pid <> pg_backend_pid() AND datname = current_database()
                  AND strpos(query, $1) > 0 AND strpos(query, $2) > 0
                  AND wait_event_type = 'Lock' AND cardinality(pg_blocking_pids(pid)) > 0)
            """, observer);
        _ = command.Parameters.AddWithValue(schema);
        _ = command.Parameters.AddWithValue(queryFragment);
        while (!(bool)(await command.ExecuteScalarAsync(token))!)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(10), token);
        }
    }

    [Fact]
    public async Task LiveLease_BlocksSecondOwnerAndHeartbeatExtendsExpiry()
    {
        string schema = $"journal_{Guid.NewGuid():N}";
        var clock = new MutableTimeProvider(Now);
        PostgreSqlMigrationRunJournal first = Journal(schema, "worker-a", clock);
        PostgreSqlMigrationRunJournal second = Journal(schema, "worker-b", clock);
        MigrationRunIdentity identity = Identity();

        MigrationRunStartResult acquired = await first.TryBeginAsync(identity, CancellationToken.None);
        await using var observer = new NpgsqlConnection(fixture.ControlConnectionString);
        await observer.OpenAsync();
        await using var serverTime = new NpgsqlCommand("SELECT clock_timestamp()", observer);
        DateTimeOffset beforeHeartbeat = new((DateTime)(await serverTime.ExecuteScalarAsync())!);
        clock.Advance(TimeSpan.FromSeconds(50));
        MigrationRunLease renewed = await first.HeartbeatAsync(acquired.Lease!, CancellationToken.None);
        DateTimeOffset afterHeartbeat = new((DateTime)(await serverTime.ExecuteScalarAsync())!);
        clock.Advance(TimeSpan.FromSeconds(20));
        MigrationRunStartResult blocked = await second.TryBeginAsync(identity, CancellationToken.None);

        Assert.Equal(MigrationRunStartStatus.InProgress, blocked.Status);
        Assert.Equal("worker-a", renewed.Owner);
        Assert.Equal(1, renewed.Attempt);
        Assert.True(renewed.ExpiresAtUtc > acquired.Lease!.ExpiresAtUtc);
        Assert.InRange(renewed.ExpiresAtUtc, beforeHeartbeat.AddSeconds(60), afterHeartbeat.AddSeconds(60));
    }

    [Fact]
    public async Task ExpiredLease_IsTakenOverAndReturnsDurablePendingShadowInventory()
    {
        string schema = $"journal_{Guid.NewGuid():N}";
        var clock = new MutableTimeProvider(Now);
        PostgreSqlMigrationRunJournal crashed = Journal(schema, "crashed-worker", clock);
        PostgreSqlMigrationRunJournal restarted = Journal(schema, "restart-worker", clock);
        MigrationRunIdentity identity = Identity();
        MigrationRunLease firstLease = (await crashed.TryBeginAsync(identity, CancellationToken.None)).Lease!;
        var shadow = new ShadowDatabase(
            $"legacy_shadow_order_{Guid.NewGuid():N}",
            identity.RunId.ToString("D"),
            "Order")
        { OwnerAttempt = firstLease.Attempt, FencingToken = firstLease.FencingToken };
        await crashed.RegisterShadowAsync(firstLease, shadow, CancellationToken.None);

        clock.Advance(TimeSpan.FromSeconds(61));
        await ExpireAsync(schema, identity.RunId);
        MigrationRunStartResult takeover = await restarted.TryBeginAsync(identity, CancellationToken.None);

        Assert.Equal(MigrationRunStartStatus.Acquired, takeover.Status);
        Assert.Equal("restart-worker", takeover.Lease!.Owner);
        Assert.Equal(2, takeover.Lease.Attempt);
        Assert.NotEqual(firstLease.FencingToken, takeover.Lease.FencingToken);
        Assert.Equal([shadow], takeover.PendingShadows);
        MigrationExecutionException staleOwner = await Assert.ThrowsAsync<MigrationExecutionException>(
            () => crashed.HeartbeatAsync(firstLease, CancellationToken.None));
        Assert.Equal("run_lease_lost", staleOwner.Code);
    }

    [Fact]
    public async Task CleanupFailure_RemainsPendingUntilOwnedRetryRecordsDeletion()
    {
        string schema = $"journal_{Guid.NewGuid():N}";
        var clock = new MutableTimeProvider(Now);
        PostgreSqlMigrationRunJournal crashed = Journal(schema, "crashed-worker", clock);
        PostgreSqlMigrationRunJournal restarted = Journal(schema, "restart-worker", clock);
        MigrationRunIdentity identity = Identity();
        MigrationRunLease firstLease = (await crashed.TryBeginAsync(identity, CancellationToken.None)).Lease!;
        var shadow = new ShadowDatabase(
            $"legacy_shadow_order_{Guid.NewGuid():N}",
            identity.RunId.ToString("D"),
            "Order")
        { OwnerAttempt = firstLease.Attempt, FencingToken = firstLease.FencingToken };
        await crashed.RegisterShadowAsync(firstLease, shadow, CancellationToken.None);
        clock.Advance(TimeSpan.FromSeconds(61));
        await ExpireAsync(schema, identity.RunId);
        MigrationRunStartResult takeover = await restarted.TryBeginAsync(identity, CancellationToken.None);
        MigrationRunLease takeoverLease = Assert.IsType<MigrationRunLease>(takeover.Lease);

        await restarted.RecordShadowCleanupAsync(
            takeoverLease,
            new ShadowCleanupOutcome(shadow.Name, false, "transient")
            {
                OwnerAttempt = shadow.OwnerAttempt,
                FencingToken = shadow.FencingToken,
            },
            CancellationToken.None);
        Assert.Equal([shadow], await restarted.GetPendingShadowsAsync(takeoverLease, CancellationToken.None));

        await restarted.RecordShadowCleanupAsync(
            takeoverLease,
            new ShadowCleanupOutcome(shadow.Name, true, null)
            {
                OwnerAttempt = shadow.OwnerAttempt,
                FencingToken = shadow.FencingToken,
            },
            CancellationToken.None);
        Assert.Empty(await restarted.GetPendingShadowsAsync(takeoverLease, CancellationToken.None));

        ShadowDatabase successor = shadow with
        {
            OwnerAttempt = takeoverLease.Attempt,
            FencingToken = takeoverLease.FencingToken,
        };
        await restarted.RegisterShadowAsync(takeoverLease, successor, CancellationToken.None);
        Assert.Equal([successor], await restarted.GetPendingShadowsAsync(takeoverLease, CancellationToken.None));
        MigrationExecutionException staleCleanup = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            restarted.RecordShadowCleanupAsync(
                takeoverLease,
                new ShadowCleanupOutcome(shadow.Name, true, null)
                {
                    OwnerAttempt = shadow.OwnerAttempt,
                    FencingToken = shadow.FencingToken,
                },
                CancellationToken.None));
        Assert.Equal("shadow_inventory_invalid", staleCleanup.Code);
        Assert.Equal([successor], await restarted.GetPendingShadowsAsync(takeoverLease, CancellationToken.None));

        await using var connection = new NpgsqlConnection(fixture.ControlConnectionString);
        await connection.OpenAsync(CancellationToken.None);
        await using var command = new NpgsqlCommand(
            $"SELECT cleanup_attempts FROM \"{schema}\".migration_run_shadows WHERE run_id = $1 AND shadow_name = $2;",
            connection);
        _ = command.Parameters.AddWithValue(identity.RunId);
        _ = command.Parameters.AddWithValue(shadow.Name);
        Assert.Equal(2, Convert.ToInt32(
            await command.ExecuteScalarAsync(CancellationToken.None),
            System.Globalization.CultureInfo.InvariantCulture));
    }

    private async Task ExpireAsync(string schema, Guid runId)
    {
        await using var connection = new NpgsqlConnection(fixture.ControlConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            $"UPDATE \"{schema}\".migration_runs SET lease_expires_at_utc = clock_timestamp() - interval '1 second' WHERE run_id = $1", connection);
        _ = command.Parameters.AddWithValue(runId);
        Assert.Equal(1, await command.ExecuteNonQueryAsync());
    }

    private PostgreSqlMigrationRunJournal Journal(string schema, string owner, TimeProvider clock)
    {
        return new PostgreSqlMigrationRunJournal(new PostgreSqlMigrationRunJournalOptions(
            fixture.ControlConnectionString,
            schema,
            owner,
            TimeSpan.FromMinutes(1),
            clock));
    }

    private static MigrationRunIdentity Identity()
    {
        return new(
            Guid.NewGuid(),
            new string('a', 40),
            new string('b', 64),
            new string('c', 64),
            new string('d', 64),
            "generation-test");
    }

    private sealed class MutableTimeProvider(DateTimeOffset current) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return current;
        }

        public void Advance(TimeSpan duration)
        {
            current += duration;
        }
    }
}
