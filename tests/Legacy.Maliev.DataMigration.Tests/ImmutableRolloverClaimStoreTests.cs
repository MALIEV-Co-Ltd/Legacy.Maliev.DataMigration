using System.Collections.Concurrent;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ImmutableRolloverClaimStoreTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 29, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Reserve_ReadbackAndTwoUniqueReservations_RejectsCompetingClaims()
    {
        var gateway = new MemoryGateway(Now);
        var store = new ImmutableRolloverClaimStore(gateway);
        ImmutableRolloverClaim first = Claim();
        ImmutableRolloverClaim observed = await store.ReserveVerifiedAsync(first, Now,
            CancellationToken.None);
        Assert.Equal(first.ClaimId, observed.ClaimId);
        Assert.Equal(first.InitialMetadata, observed.InitialMetadata);
        Assert.Equal(4, gateway.Count);

        ImmutableRolloverClaim sameReceipt = Claim() with
        {
            HistoricalReceiptSha256 = first.HistoricalReceiptSha256,
            FuturePlanSha256 = Hash('4'),
        };
        await AssertCodeAsync("delta_rollover_claim_conflict", () =>
            store.ReserveVerifiedAsync(sameReceipt, Now, CancellationToken.None));

        ImmutableRolloverClaim sameFuture = Claim() with
        {
            HistoricalReceiptSha256 = Hash('5'),
            FuturePlanSha256 = first.FuturePlanSha256,
        };
        await AssertCodeAsync("delta_rollover_claim_conflict", () =>
            store.ReserveVerifiedAsync(sameFuture, Now, CancellationToken.None));
        await AssertCodeAsync("delta_rollover_claim_object_missing", () =>
            store.ReadAsync(sameFuture.ClaimId, sameFuture.InitialAttestationSha256, Now,
                CancellationToken.None));

        ImmutableRolloverClaim differentPlanSameGeneration = Claim() with
        {
            HistoricalReceiptSha256 = Hash('7'),
            FuturePlanSha256 = Hash('8'),
        };
        await AssertCodeAsync("delta_rollover_claim_conflict", () =>
            store.ReserveVerifiedAsync(differentPlanSameGeneration, Now,
                CancellationToken.None));
    }

    [Theory]
    [InlineData(false, 31_557_600, true, false)]
    [InlineData(true, 604_800, true, false)]
    [InlineData(true, 31_557_600, false, false)]
    [InlineData(true, 31_557_600, true, true)]
    public async Task Reserve_RejectsUnsafeBucketPolicy(bool locked, long seconds,
        bool uniform, bool versioning)
    {
        var gateway = new MemoryGateway(Now)
        {
            Policy = new(locked, seconds, uniform, versioning),
        };
        var store = new ImmutableRolloverClaimStore(gateway);
        await AssertCodeAsync("delta_rollover_claim_bucket_policy_invalid", () =>
            store.ReserveVerifiedAsync(Claim(), Now, CancellationToken.None));
        Assert.Equal(0, gateway.Count);
    }

    [Fact]
    public async Task Read_RejectsTamperMissingReservationAndExpiredRetention()
    {
        var gateway = new MemoryGateway(Now);
        var store = new ImmutableRolloverClaimStore(gateway);
        ImmutableRolloverClaim claim = await store.ReserveVerifiedAsync(Claim(), Now,
            CancellationToken.None);
        await AssertCodeAsync("delta_rollover_claim_identity_invalid", () =>
            store.ReadAsync(claim.ClaimId, Hash('9'), Now,
                CancellationToken.None));
        await AssertCodeAsync("delta_rollover_claim_shape_invalid", () =>
            store.ReadAsync(claim.ClaimId, claim.InitialAttestationSha256,
                claim.ExpiresAtUtc, CancellationToken.None));

        gateway.Remove("claims/v1/old-receipts/" + claim.HistoricalReceiptSha256);
        await AssertCodeAsync("delta_rollover_claim_object_missing", () =>
            store.ReadAsync(claim.ClaimId, claim.InitialAttestationSha256, Now,
                CancellationToken.None));

        var shortRetention = new MemoryGateway(Now) { Retention = TimeSpan.FromDays(7) };
        await AssertCodeAsync("delta_rollover_claim_retention_invalid", () =>
            new ImmutableRolloverClaimStore(shortRetention).ReserveVerifiedAsync(Claim(), Now,
                CancellationToken.None));
    }

    [Fact]
    public async Task Reserve_RejectsChangedOrMalformedTargetGeneration()
    {
        var store = new ImmutableRolloverClaimStore(new MemoryGateway(Now));
        await AssertCodeAsync("delta_rollover_claim_shape_invalid", () =>
            store.ReserveVerifiedAsync(Claim() with { TargetGeneration = "docker:target-generation" },
                Now, CancellationToken.None));
        await AssertCodeAsync("delta_rollover_claim_shape_invalid", () =>
            store.ReserveVerifiedAsync(Claim() with
            {
                TargetGeneration = $"docker:{Hash('a')}:1700000000000:1700000001000:123456",
            }, Now, CancellationToken.None));
    }

    [Fact]
    public async Task Ordinal_ConcurrentCreateReplayAndGap_FailClosed()
    {
        var gateway = new MemoryGateway(Now);
        var store = new ImmutableRolloverClaimStore(gateway);
        ImmutableRolloverClaim claim = await store.ReserveVerifiedAsync(Claim(), Now,
            CancellationToken.None);
        await AssertCodeAsync("delta_rollover_claim_object_missing", () =>
            store.ReserveOrdinalAsync(claim, 2, Hash('a'), Guid.NewGuid(), Now,
                CancellationToken.None));

        Task first = store.ReserveOrdinalAsync(claim, 1, Hash('b'), Guid.NewGuid(), Now,
            CancellationToken.None);
        Task second = store.ReserveOrdinalAsync(claim, 1, Hash('c'), Guid.NewGuid(), Now,
            CancellationToken.None);
        Exception?[] outcomes = await Task.WhenAll(ObserveAsync(first), ObserveAsync(second));
        _ = Assert.Single(outcomes, outcome => outcome is null);
        _ = Assert.Single(outcomes, outcome => outcome is DeltaExecutionException
        { Code: "delta_rollover_claim_conflict" });

        await store.ReserveOrdinalAsync(claim, 2, Hash('d'), Guid.NewGuid(), Now,
            CancellationToken.None);
        await AssertCodeAsync("delta_rollover_claim_conflict", () =>
            store.ReserveOrdinalAsync(claim, 2, Hash('e'), Guid.NewGuid(), Now,
                CancellationToken.None));
    }

    private static async Task<Exception?> ObserveAsync(Task task)
    {
        try { await task; return null; }
        catch (Exception exception) { return exception; }
    }

    private static async Task AssertCodeAsync(string code, Func<Task> action)
    {
        DeltaExecutionException exception = await Assert.ThrowsAsync<DeltaExecutionException>(action);
        Assert.Equal(code, exception.Code);
    }

    private static ImmutableRolloverClaim Claim()
    {
        return new("1.0", Guid.NewGuid(), Hash('1'), Hash('2'), Hash('3'),
            Hash('4'), $"docker:{Hash('a')}:1700000000000:1700000001000:{Now.AddYears(-1).ToUnixTimeMilliseconds()}",
            "legacy-maliev-exact23-postgres-data",
            Now.AddYears(-1), Hash('5'),
            [.. DatabaseInventory.ActiveDatabases.Select(database =>
                new HistoricalLocalMetadataBinding(database,
                    PairedLocalTransitionMetadataState.SettledPrior, Hash('6')))],
            Now, Now.Add(ImmutableRolloverClaimStore.MaximumClaimAge));
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    private sealed class MemoryGateway(DateTimeOffset now) : IRolloverClaimObjectGateway
    {
        private readonly ConcurrentDictionary<string, RolloverClaimObject> _objects =
            new(StringComparer.Ordinal);
        private long _generation;
        public int Count => _objects.Count;
        public TimeSpan Retention { get; init; } = TimeSpan.FromSeconds(
            ImmutableRolloverClaimStore.MinimumRetentionSeconds);
        public RolloverClaimBucketPolicy Policy { get; init; } = new(true,
            ImmutableRolloverClaimStore.MinimumRetentionSeconds, true, false);

        public Task<RolloverClaimBucketPolicy> ReadPolicyAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Policy);
        }

        public Task<RolloverClaimObject> CreateOnlyAsync(string name, byte[] content,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidate = new RolloverClaimObject(Interlocked.Increment(ref _generation),
                now, now.Add(Retention), [.. content]);
            return !_objects.TryAdd(name, candidate)
                ? throw new DeltaExecutionException("delta_rollover_claim_conflict",
                    "The immutable rollover object exists.")
                : Task.FromResult(candidate);
        }

        public Task<RolloverClaimObject?> ReadAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _ = _objects.TryGetValue(name, out RolloverClaimObject? value);
            return Task.FromResult(value);
        }

        public void Remove(string name)
        {
            _ = _objects.TryRemove(name, out _);
        }
    }
}
