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
            "Order");

        await target.DeleteRunOwnedShadowAsync(plannedButNeverCreated, CancellationToken.None);
    }
}
