using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentOwnerIsoProofChildRoutingTests
{
    [Theory]
    [InlineData("owner-iso-bootstrap-host-child")]
    [InlineData("owner-iso-named-closed-host-child")]
    public void Child_route_accepts_only_two_arguments_and_an_absolute_held_reference(string command)
    {
        string path = Path.Combine(Path.GetTempPath(), "iso-owned-child.json");
        Assert.Equal(new ConsoleInvocation(command, path), ConsoleInvocation.Parse([command, path]));
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([command]));
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([command, "relative.json"]));
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([command, "--config", path]));
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([command, path, "apply-current-owner-iso-repair"]));
    }
}
