using System.Collections.Concurrent;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SourceBackedLocalRepairClaimStoreTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 2, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task FreshRepairReservesDistinctDomainAndCannotReplay()
    {
        var gateway = new Gateway();
        var store = new SourceBackedLocalRepairClaimStore(gateway);
        SourceBackedLocalRepairClaim claim = Claim();
        SourceBackedLocalRepairClaim observed = await store.ReserveAsync(claim, Now, CancellationToken.None);
        Assert.Equal(System.Text.Json.JsonSerializer.Serialize(claim), System.Text.Json.JsonSerializer.Serialize(observed));
        Assert.False(SourceBackedLocalRepairClaim.AuthorizesExecution);
        Assert.Contains(gateway.Names, name => name.StartsWith("source-backed-local-repair/v1/active/", StringComparison.Ordinal));
        Assert.DoesNotContain(gateway.Names, name => name.StartsWith("claims/v1/old-receipts/", StringComparison.Ordinal));
        await Code("delta_rollover_claim_conflict", () => store.ReserveAsync(claim, Now, CancellationToken.None));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RepairAndHistoricalClaimsCannotReserveSameTargetInEitherOrder(bool repairFirst)
    {
        var gateway = new Gateway();
        var repairStore = new SourceBackedLocalRepairClaimStore(gateway);
        var historicalStore = new ImmutableRolloverClaimStore(gateway);
        SourceBackedLocalRepairClaim repair = Claim();
        var historical = new ImmutableRolloverClaim("1.0", Guid.NewGuid(), Hash('1'), Hash('2'), Hash('3'),
            Hash('9'), repair.TargetGeneration, repair.VolumeName, repair.VolumeCreatedAtUtc,
            repair.SystemIdentifierSha256, repair.InitialMetadata, Now, repair.ExpiresAtUtc);
        if (repairFirst)
        {
            _ = await repairStore.ReserveAsync(repair, Now, CancellationToken.None);
            await Code("delta_rollover_claim_conflict", () => historicalStore.ReserveVerifiedAsync(historical, Now, CancellationToken.None));
        }
        else
        {
            _ = await historicalStore.ReserveVerifiedAsync(historical, Now, CancellationToken.None);
            await Code("delta_rollover_claim_conflict", () => repairStore.ReserveAsync(repair, Now, CancellationToken.None));
        }
    }

    [Theory]
    [InlineData(false, 31557600, true, false)]
    [InlineData(true, 604800, true, false)]
    [InlineData(true, 31557600, false, false)]
    [InlineData(true, 31557600, true, true)]
    public async Task UnsafeRetentionFailsBeforeAnyReservation(bool locked, long seconds, bool uniform, bool versioned)
    {
        var gateway = new Gateway { Policy = new(locked, seconds, uniform, versioned) };
        var store = new SourceBackedLocalRepairClaimStore(gateway);
        await Code("delta_source_repair_claim_policy_invalid", () => store.ReserveAsync(Claim(), Now, CancellationToken.None));
        Assert.Empty(gateway.Names);
    }

    [Theory]
    [InlineData("preimage")]
    [InlineData("capture")]
    [InlineData("metadata")]
    [InlineData("generation")]
    [InlineData("volume")]
    [InlineData("expiry")]
    public async Task InvalidRepairBindingsCannotReserve(string mutation)
    {
        SourceBackedLocalRepairClaim original = Claim();
        SourceBackedLocalRepairClaim changed = mutation switch
        {
            "preimage" => original with { PreimageSha256 = "invalid" },
            "capture" => original with { SourceCaptureSha256 = new string('A', 64) },
            "metadata" => original with { InitialMetadata = [] },
            "generation" => original with { TargetGeneration = "docker:short:1:2:3" },
            "volume" => original with { VolumeName = "unapproved" },
            _ => original with { ExpiresAtUtc = Now },
        };
        var gateway = new Gateway();
        var store = new SourceBackedLocalRepairClaimStore(gateway);
        await Code("delta_source_repair_claim_shape_invalid", () => store.ReserveAsync(changed, Now, CancellationToken.None));
        Assert.Empty(gateway.Names);
    }

    [Fact]
    public async Task CurrentReadAuthenticatesAllReservationsAndExpiry()
    {
        var gateway = new Gateway();
        var store = new SourceBackedLocalRepairClaimStore(gateway);
        SourceBackedLocalRepairClaim claim = await store.ReserveAsync(Claim(), Now, CancellationToken.None);
        await Code("delta_source_repair_claim_identity_invalid", () => store.ReadAsync(claim.ClaimId, Hash('9'), Now, CancellationToken.None));
        await Code("delta_source_repair_claim_shape_invalid", () => store.ReadAsync(claim.ClaimId, claim.AdmissionSha256, claim.ExpiresAtUtc, CancellationToken.None));
        string preimage = "source-backed-local-repair/v1/preimages/" + claim.PreimageSha256;
        gateway.Replace(preimage, "{}"u8.ToArray());
        await Code("delta_source_repair_claim_reservation_invalid", () => store.ReadAsync(claim.ClaimId, claim.AdmissionSha256, Now, CancellationToken.None));
        gateway.Remove(preimage);
        await Code("delta_source_repair_claim_object_missing", () => store.ReadAsync(claim.ClaimId, claim.AdmissionSha256, Now, CancellationToken.None));
    }

    [Fact]
    public async Task InsufficientObjectRetentionCannotPublishActiveClaim()
    {
        var gateway = new Gateway { Retention = TimeSpan.FromMinutes(10) };
        var store = new SourceBackedLocalRepairClaimStore(gateway);
        await Code("delta_source_repair_claim_retention_invalid", () => store.ReserveAsync(Claim(), Now, CancellationToken.None));
        Assert.DoesNotContain(gateway.Names, name => name.Contains("/active/", StringComparison.Ordinal));
    }

    [Fact]
    public async Task InterruptedPublicationRetainsReservationAndRejectsReplacement()
    {
        var gateway = new Gateway { FailCreateNumber = 3 };
        var store = new SourceBackedLocalRepairClaimStore(gateway);
        SourceBackedLocalRepairClaim first = Claim();
        _ = await Assert.ThrowsAsync<IOException>(() => store.ReserveAsync(first, Now, CancellationToken.None));
        Assert.Equal(2, gateway.Names.Length);
        await Code("delta_source_repair_claim_object_missing", () => store.ReadAsync(first.ClaimId, first.AdmissionSha256, Now, CancellationToken.None));
        await Code("delta_rollover_claim_conflict", () => store.ReserveAsync(first with { ClaimId = Guid.NewGuid(), PreimageSha256 = Hash('9') }, Now, CancellationToken.None));
    }

    [Fact]
    public async Task ConcurrentClaimsForSameTargetHaveOneWinner()
    {
        var gateway = new Gateway { UseCompetitionBarrier = true };
        var store = new SourceBackedLocalRepairClaimStore(gateway);
        SourceBackedLocalRepairClaim first = Claim();
        SourceBackedLocalRepairClaim second = Claim() with { PreimageSha256 = Hash('9'), FuturePlanSha256 = Hash('8') };
        Task<Exception?>[] attempts = [Try(store.ReserveAsync(first, Now, CancellationToken.None)),
            Try(store.ReserveAsync(second, Now, CancellationToken.None))];
        Exception?[] results = await Task.WhenAll(attempts);
        Assert.Equal(2, gateway.TargetArrivals);
        Assert.Equal(2, gateway.Names.Count(name => name.Contains("/preimages/", StringComparison.Ordinal)));
        _ = Assert.Single(gateway.Names, name => name.Contains("/active/", StringComparison.Ordinal));
        _ = Assert.Single(results, item => item is null);
        Assert.Equal("delta_rollover_claim_conflict", Assert.IsType<DeltaExecutionException>(Assert.Single(results, item => item is not null)).Code);
    }

    private static async Task<Exception?> Try(Task task)
    {
        try { await task; return null; }
        catch (Exception exception) { return exception; }
    }
    private static SourceBackedLocalRepairClaim Claim()
    {
        return new("1.0", Guid.NewGuid(), Hash('1'), Hash('2'), Hash('3'), Hash('4'),
        $"docker:{Hash('a')}:1700000000000:1700000001000:{Now.AddYears(-1).ToUnixTimeMilliseconds()}",
        "legacy-maliev-exact23-postgres-data", Now.AddYears(-1), Hash('5'),
        [.. DatabaseInventory.ActiveDatabases.Select(database => new HistoricalLocalMetadataBinding(database,
            PairedLocalTransitionMetadataState.SettledPrior, Hash('6')))], Now, Now.AddDays(364));
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    private static async Task Code(string code, Func<Task> action)
    {
        Assert.Equal(code, (await Assert.ThrowsAsync<DeltaExecutionException>(action)).Code);
    }

    private sealed class Gateway : IRolloverClaimObjectGateway
    {
        private readonly ConcurrentDictionary<string, RolloverClaimObject> _objects = new(StringComparer.Ordinal);
        private long _generation;
        private int _targetArrivals;
        private readonly TaskCompletionSource _competition = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool UseCompetitionBarrier { get; init; }
        public int TargetArrivals => Volatile.Read(ref _targetArrivals);
        public TimeSpan Retention { get; init; } = TimeSpan.FromDays(365.25);
        public int FailCreateNumber { get; init; }
        public void Remove(string name)
        {
            _ = _objects.TryRemove(name, out _);
        }

        public void Replace(string name, byte[] bytes)
        {
            _objects[name] = _objects[name] with { Content = bytes };
        }

        public string[] Names => [.. _objects.Keys];
        public RolloverClaimBucketPolicy Policy { get; init; } = new(true, 31557600, true, false);
        public Task<RolloverClaimBucketPolicy> ReadPolicyAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(Policy);
        }

        public Task<RolloverClaimObject?> ReadAsync(string name, CancellationToken cancellationToken)
        {
            return Task.FromResult(_objects.TryGetValue(name, out RolloverClaimObject? value) ? value : null);
        }

        public async Task<RolloverClaimObject> CreateOnlyAsync(string name, byte[] content, CancellationToken cancellationToken)
        {
            if (UseCompetitionBarrier && name.StartsWith("claims/v1/target-generations/", StringComparison.Ordinal))
            {
                if (Interlocked.Increment(ref _targetArrivals) == 2) { _ = _competition.TrySetResult(); }
                await _competition.Task.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
            }
            long generation = Interlocked.Increment(ref _generation);
            if (generation == FailCreateNumber) { throw new IOException("Simulated publication interruption."); }
            var value = new RolloverClaimObject(generation, Now, Now.Add(Retention), [.. content]);
            return !_objects.TryAdd(name, value)
                ? throw new DeltaExecutionException("delta_rollover_claim_conflict", "Already reserved.")
                : value;
        }
    }
}
