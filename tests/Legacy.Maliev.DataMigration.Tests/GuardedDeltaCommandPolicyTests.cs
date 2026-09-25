using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class GuardedDeltaCommandPolicyTests
{
    [Fact]
    public void AppHost_CanInvokeOnlyLocalApply()
    {
        Assert.True(GuardedDeltaCommandPolicy.IsAppHostCallable("apply-delta-local"));
        Assert.False(GuardedDeltaCommandPolicy.IsAppHostCallable("apply-delta-production"));
        Assert.False(GuardedDeltaCommandPolicy.IsAppHostCallable("plan-delta"));
        Assert.False(GuardedDeltaCommandPolicy.IsAppHostCallable("inspect-target-schema-gaps"));
        Assert.False(GuardedDeltaCommandPolicy.IsAppHostCallable("verify-disposable-delta-proof"));
        Assert.False(GuardedDeltaCommandPolicy.IsAppHostCallable("authorize-delta"));
        Assert.False(GuardedDeltaCommandPolicy.IsAppHostCallable("reconcile-delta"));
    }

    [Theory]
    [InlineData("owner", "apply-delta-production")]
    [InlineData("owner", "authorize-delta")]
    [InlineData("owner", "verify-disposable-delta-proof")]
    [InlineData("operator", "plan-delta")]
    [InlineData("operator", "inspect-target-schema-gaps")]
    [InlineData("operator", "apply-delta-local")]
    [InlineData("apphost", "apply-delta-local")]
    public void AllowedCallerCommandPairs_AreAccepted(string caller, string command)
    {
        GuardedDeltaCommandPolicy.ValidateCaller(command, caller);
    }

    [Theory]
    [InlineData("apphost", "apply-delta-production")]
    [InlineData("apphost", "authorize-delta")]
    [InlineData("apphost", "inspect-target-schema-gaps")]
    [InlineData("operator", "apply-delta-production")]
    [InlineData("operator", "authorize-delta")]
    [InlineData("operator", "verify-disposable-delta-proof")]
    [InlineData("", "plan-delta")]
    public void PrivilegeEscalationPairs_FailClosed(string caller, string command)
    {
        MigrationConsoleException exception = Assert.Throws<MigrationConsoleException>(() =>
            GuardedDeltaCommandPolicy.ValidateCaller(command, caller));

        Assert.Equal("delta_caller_invalid", exception.Code);
    }
}
