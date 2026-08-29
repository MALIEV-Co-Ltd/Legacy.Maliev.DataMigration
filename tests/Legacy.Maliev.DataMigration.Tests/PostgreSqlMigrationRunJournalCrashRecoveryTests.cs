using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlMigrationRunJournalCrashRecoveryTests(PostgreSqlAdapterFixture fixture)
{
    private static readonly DateTimeOffset Now = new(2026, 8, 29, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task LiveLease_BlocksSecondOwnerAndHeartbeatExtendsExpiry()
    {
        string schema = $"journal_{Guid.NewGuid():N}";
        var clock = new MutableTimeProvider(Now);
        PostgreSqlMigrationRunJournal first = Journal(schema, "worker-a", clock);
        PostgreSqlMigrationRunJournal second = Journal(schema, "worker-b", clock);
        MigrationRunIdentity identity = Identity();

        MigrationRunStartResult acquired = await first.TryBeginAsync(identity, CancellationToken.None);
        clock.Advance(TimeSpan.FromSeconds(50));
        MigrationRunLease renewed = await first.HeartbeatAsync(acquired.Lease!, CancellationToken.None);
        clock.Advance(TimeSpan.FromSeconds(20));
        MigrationRunStartResult blocked = await second.TryBeginAsync(identity, CancellationToken.None);

        Assert.Equal(MigrationRunStartStatus.InProgress, blocked.Status);
        Assert.Equal("worker-a", renewed.Owner);
        Assert.Equal(1, renewed.Attempt);
        Assert.Equal(Now.AddSeconds(110), renewed.ExpiresAtUtc);
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

        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
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

    private PostgreSqlMigrationRunJournal Journal(string schema, string owner, TimeProvider clock)
    {
        return new PostgreSqlMigrationRunJournal(new PostgreSqlMigrationRunJournalOptions(
            fixture.ConnectionString,
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
