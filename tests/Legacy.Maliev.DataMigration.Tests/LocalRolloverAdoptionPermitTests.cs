namespace Legacy.Maliev.DataMigration.Tests;

public sealed class LocalRolloverAdoptionPermitTests
{
    [Fact]
    public async Task FreshIdentity_RejectsContainerRestartOnSameVolume()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset volumeCreated = now.AddDays(-1);
        string generation = $"docker:{Hash('1')}:1700000000000:1700000001000:{volumeCreated.ToUnixTimeMilliseconds()}";
        var claim = new ImmutableRolloverClaim("1.0", Guid.NewGuid(), Hash('2'), Hash('3'),
            Hash('4'), Hash('5'), generation, "legacy-maliev-exact23-postgres-data",
            volumeCreated, Hash('6'),
            [.. DatabaseInventory.ActiveDatabases.Select(database =>
                new HistoricalLocalMetadataBinding(database,
                    PairedLocalTransitionMetadataState.SettledPrior, Hash('7')))],
            now.AddMinutes(-1), now.AddDays(1));
        var continuation = new HistoricalLocalMixedContinuation("1.0", claim.ClaimId,
            claim.InitialAttestationSha256, claim.FuturePlanSha256,
            claim.TargetGeneration, Guid.NewGuid(), 1,
            [.. DatabaseInventory.ActiveDatabases.Select(database =>
                new HistoricalLocalRolloverDatabaseState(database,
                    HistoricalLocalRolloverDatabasePhase.Prior, Hash('7'), null))],
            now.AddMinutes(-1), now.AddMinutes(10), "test", null);
        var authorization = new PairedLocalTransitionAuthorization("1.0",
            continuation.AuthorizationId, Guid.NewGuid(), claim.FuturePlanSha256,
            Hash('8'), Hash('9'), Hash('a'), Hash('b'), new DeltaTargetAuthority(
                DeltaTargetAuthorityKind.LocalAspire,
                "aspire://legacy-postgres-main-local/persistent-test", Hash('6')),
            Hash('c'), now.AddMinutes(-1), now.AddMinutes(10), "test", null);
        var same = new HistoricalCurrentLocalObservation(Hash('1'), generation,
            claim.VolumeName, volumeCreated, "/volume", "/data", "/data",
            claim.SystemIdentifierSha256);
        int observations = 0;
        var permit = new LocalRolloverAdoptionPermit(claim, continuation,
            authorization, TimeProvider.System, _ => Task.FromResult(
                Interlocked.Increment(ref observations) == 1 ? same : same with
                {
                    ContainerId = Hash('d'),
                    DockerGeneration = generation.Replace(Hash('1'), Hash('d'),
                        StringComparison.Ordinal),
                }));
        await permit.RequireFreshTargetIdentityAsync(CancellationToken.None);
        DeltaExecutionException restarted = await Assert.ThrowsAsync<DeltaExecutionException>(
            () => permit.RequireFreshTargetIdentityAsync(CancellationToken.None));
        Assert.Equal("delta_rollover_target_identity_changed", restarted.Code);
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }
}
