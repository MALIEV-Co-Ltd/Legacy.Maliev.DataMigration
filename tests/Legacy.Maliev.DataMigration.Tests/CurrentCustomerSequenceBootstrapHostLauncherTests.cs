using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentCustomerSequenceBootstrapHostLauncherTests
{
    [Fact]
    public void Waiting_child_route_accepts_only_one_absolute_configuration_reference()
    {
        string path = Path.GetFullPath("customer-child.json");
        Assert.Equal(new ConsoleInvocation(CustomerGuardedBootstrapHostLauncher.ChildCommand, path),
            ConsoleInvocation.Parse([CustomerGuardedBootstrapHostLauncher.ChildCommand, path]));
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([CustomerGuardedBootstrapHostLauncher.ChildCommand, "relative.json"]));
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([CustomerGuardedBootstrapHostLauncher.ChildCommand, path, "extra"]));
    }
    [Theory]
    [InlineData("native-component", 6, 55)]
    [InlineData("maintenance-component", 4, 38)]
    public void Fixed_filter_contains_only_exact_methods_with_finite_lease(string group, int count, int minutes)
    {
        string[] filters = CustomerGuardedBootstrapHostLauncher.Filter(group).Split('|');
        Assert.Equal(count, filters.Length); Assert.Equal(count, filters.Distinct(StringComparer.Ordinal).Count());
        Assert.All(filters, item => Assert.StartsWith("FullyQualifiedName=Legacy.Maliev.DataMigration.Tests.CurrentCustomerSequenceGuardedNativeExecutionTests.Customer_sequence_", item, StringComparison.Ordinal));
        Assert.DoesNotContain('~', CustomerGuardedBootstrapHostLauncher.Filter(group));
        Assert.Equal(TimeSpan.FromMinutes(minutes), CustomerGuardedBootstrapHostLauncher.Lease(group));
    }
    [Theory]
    [InlineData("persistent")]
    [InlineData("native")]
    [InlineData("*")]
    [InlineData("")]
    public void Unknown_or_generalized_host_group_is_rejected(string group)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerGuardedBootstrapHostLauncher.Filter(group));
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerGuardedBootstrapHostLauncher.Lease(group));
    }
}
