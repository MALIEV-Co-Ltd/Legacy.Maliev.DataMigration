namespace Legacy.Maliev.DataMigration.Tests;

public sealed class MigrationLeaseHeartbeatTests
{
    [Fact]
    public async Task LongOperation_IsHeartbeatedContinuously()
    {
        var journal = new HeartbeatJournal();
        var identity = new MigrationRunIdentity(
            Guid.NewGuid(), new string('a', 40), new string('b', 64),
            new string('c', 64), new string('d', 64), "test");
        var lease = new MigrationRunLease(
            identity,
            "worker",
            1,
            DateTimeOffset.UtcNow.AddSeconds(2))
        {
            FencingToken = Guid.NewGuid(),
        };

        await using var heartbeat = new MigrationLeaseHeartbeat(journal, lease, CancellationToken.None);
        heartbeat.Start();
        await journal.SecondSuccessfulHeartbeat.WaitAsync(TimeSpan.FromSeconds(6));
        await heartbeat.StopAsync();

        Assert.True(journal.HeartbeatCount >= 2);
        Assert.Equal(lease.FencingToken, heartbeat.CurrentLease.FencingToken);
    }

    [Fact]
    public async Task TransientHeartbeatFailure_IsRetriedBeforeLeaseExpiry()
    {
        var journal = new HeartbeatJournal { FailuresRemaining = 1 };
        var identity = new MigrationRunIdentity(
            Guid.NewGuid(), new string('a', 40), new string('b', 64),
            new string('c', 64), new string('d', 64), "test");
        var lease = new MigrationRunLease(
            identity,
            "worker",
            1,
            DateTimeOffset.UtcNow.AddSeconds(2))
        {
            FencingToken = Guid.NewGuid(),
        };

        await using var heartbeat = new MigrationLeaseHeartbeat(journal, lease, CancellationToken.None);
        heartbeat.Start();
        await journal.SecondSuccessfulHeartbeat.WaitAsync(TimeSpan.FromSeconds(6));
        await heartbeat.StopAsync();

        Assert.True(journal.HeartbeatCount >= 2);
        Assert.Null(heartbeat.Failure);
        Assert.False(heartbeat.ExecutionToken.IsCancellationRequested);
    }

    private sealed class HeartbeatJournal : IMigrationRunJournal
    {
        private readonly TaskCompletionSource _secondSuccessfulHeartbeat = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private int _heartbeatCount;

        public Task SecondSuccessfulHeartbeat => _secondSuccessfulHeartbeat.Task;

        public Task RecordCheckpointAsync(MigrationRunLease lease, DatabaseMigrationCheckpoint checkpoint, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyList<DatabaseMigrationCheckpoint>> GetCheckpointsAsync(MigrationRunLease lease, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public int HeartbeatCount => Volatile.Read(ref _heartbeatCount);
        public int FailuresRemaining { get; init; }

        public Task<MigrationRunLease> HeartbeatAsync(MigrationRunLease lease, CancellationToken cancellationToken)
        {
            int count = Interlocked.Increment(ref _heartbeatCount);
            if (FailuresRemaining >= count)
            {
                throw new TimeoutException("transient control-channel timeout");
            }

            if (count >= 2)
            {
                _ = _secondSuccessfulHeartbeat.TrySetResult();
            }

            return Task.FromResult(lease with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(2) });
        }

        public Task<MigrationRunStartResult> TryBeginAsync(MigrationRunIdentity identity, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task RecordCompletedAsync(MigrationExecutionReceipt receipt, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task RecordCompletedAsync(MigrationRunLease lease, MigrationExecutionReceipt receipt, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task RecordFailedAsync(MigrationFailureReceipt receipt, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task RecordFailedAsync(MigrationRunLease lease, MigrationFailureReceipt receipt, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task RegisterShadowAsync(MigrationRunLease lease, ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyList<ShadowDatabase>> GetPendingShadowsAsync(MigrationRunLease lease, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task RecordShadowCleanupAsync(MigrationRunLease lease, ShadowCleanupOutcome outcome, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }
    }
}
