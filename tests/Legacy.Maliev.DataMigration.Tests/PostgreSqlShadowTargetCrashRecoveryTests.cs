namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlShadowTargetCrashRecoveryTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task DeleteRunOwnedShadowAsync_ExactMissingRegisteredShadow_IsIdempotent()
    {
        var target = new PostgreSqlShadowTarget(new PostgreSqlShadowTargetOptions(fixture.ConnectionString));
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
        var target = new PostgreSqlShadowTarget(new PostgreSqlShadowTargetOptions(fixture.ConnectionString));
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
}
