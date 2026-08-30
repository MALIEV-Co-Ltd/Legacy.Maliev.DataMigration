namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlShadowTargetCrashRecoveryTests(PostgreSqlAdapterFixture fixture)
{
    private static readonly DateTimeOffset Now = new(2026, 8, 29, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task RestartedLease_ConcreteJournalAndTargetCleanAbandonedShadowBeforeReplay()
    {
        string schema = $"journal_{Guid.NewGuid():N}";
        var clock = new MutableTimeProvider(Now);
        var crashed = new PostgreSqlMigrationRunJournal(new PostgreSqlMigrationRunJournalOptions(
            fixture.ControlConnectionString,
            schema,
            "crashed-worker",
            TimeSpan.FromMinutes(1),
            clock));
        var restarted = new PostgreSqlMigrationRunJournal(new PostgreSqlMigrationRunJournalOptions(
            fixture.ControlConnectionString,
            schema,
            "restart-worker",
            TimeSpan.FromMinutes(1),
            clock));
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        var identity = new MigrationRunIdentity(
            Guid.NewGuid(),
            new string('a', 40),
            new string('b', 64),
            new string('c', 64),
            new string('d', 64),
            "generation-test");
        MigrationRunLease crashedLease = Assert.IsType<MigrationRunLease>(
            (await crashed.TryBeginAsync(identity, CancellationToken.None)).Lease);
        var abandoned = new ShadowDatabase(
            $"legacy_shadow_order_{Guid.NewGuid():N}",
            identity.RunId.ToString("D"),
            "Order")
        {
            OwnerAttempt = crashedLease.Attempt,
            FencingToken = crashedLease.FencingToken,
        };
        await crashed.RegisterShadowAsync(crashedLease, abandoned, CancellationToken.None);
        ShadowDatabase createdAbandoned = await target.CreateUniqueEmptyShadowAsync(abandoned, CancellationToken.None);
        Assert.Equal(abandoned, createdAbandoned);

        clock.Advance(TimeSpan.FromSeconds(61));
        MigrationRunStartResult takeover = await restarted.TryBeginAsync(identity, CancellationToken.None);
        MigrationRunLease restartedLease = Assert.IsType<MigrationRunLease>(takeover.Lease);
        ShadowDatabase pending = Assert.Single(takeover.PendingShadows!);

        await target.DeleteRunOwnedShadowAsync(pending, CancellationToken.None);
        await restarted.RecordShadowCleanupAsync(
            restartedLease,
            new ShadowCleanupOutcome(pending.Name, true, null)
            {
                OwnerAttempt = pending.OwnerAttempt,
                FencingToken = pending.FencingToken,
            },
            CancellationToken.None);

        Assert.Empty(await restarted.GetPendingShadowsAsync(restartedLease, CancellationToken.None));

        var replay = pending with
        {
            OwnerAttempt = restartedLease.Attempt,
            FencingToken = restartedLease.FencingToken,
        };
        await restarted.RegisterShadowAsync(restartedLease, replay, CancellationToken.None);
        replay = await target.CreateUniqueEmptyShadowAsync(replay, CancellationToken.None);
        try
        {
            Assert.True(await target.IsEmptyAsync(replay, CancellationToken.None));
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(replay, CancellationToken.None);
            await restarted.RecordShadowCleanupAsync(
                restartedLease,
                new ShadowCleanupOutcome(replay.Name, true, null)
                {
                    OwnerAttempt = replay.OwnerAttempt,
                    FencingToken = replay.FencingToken,
                },
                CancellationToken.None);
        }

        Assert.Empty(await restarted.GetPendingShadowsAsync(restartedLease, CancellationToken.None));
    }

    [Fact]
    public async Task DeleteRunOwnedShadowAsync_ExactMissingRegisteredShadow_IsIdempotent()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        string runId = Guid.NewGuid().ToString("D");
        var plannedButNeverCreated = new ShadowDatabase(
            $"legacy_shadow_order_{Guid.NewGuid():N}",
            runId,
            "Order")
        { OwnerAttempt = 1, FencingToken = Guid.NewGuid() };

        await target.DeleteRunOwnedShadowAsync(plannedButNeverCreated, CancellationToken.None);
    }

    [Fact]
    public async Task StaleAttempt_CannotDeleteSuccessorWithSameDatabaseName()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        string runId = Guid.NewGuid().ToString("D");
        string name = $"legacy_shadow_order_{Guid.NewGuid():N}";
        var first = new ShadowDatabase(name, runId, "Order")
        {
            OwnerAttempt = 1,
            FencingToken = Guid.NewGuid(),
        };
        first = await target.CreateUniqueEmptyShadowAsync(first, CancellationToken.None);
        await target.DeleteRunOwnedShadowAsync(first, CancellationToken.None);

        var successor = first with { OwnerAttempt = 2, FencingToken = Guid.NewGuid() };
        successor = await target.CreateUniqueEmptyShadowAsync(successor, CancellationToken.None);
        try
        {
            MigrationExecutionException stale = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                target.DeleteRunOwnedShadowAsync(first, CancellationToken.None));

            Assert.Equal("shadow_ownership_invalid", stale.Code);
            Assert.True(await target.IsEmptyAsync(successor, CancellationToken.None));
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(successor, CancellationToken.None);
        }
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
