using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineCapabilityTests
{
    [Fact]
    public async Task Cancelled_capability_authentication_stops_before_issuer_or_images()
    {
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CurrentAuthArchiveGenuineCapability.AuthenticateConsoleOwnedIssuerAsync(null!, cancelled.Token));
    }

    [Fact]
    public async Task Arbitrary_object_is_not_a_Console_owned_issuer()
    {
        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            CurrentAuthArchiveGenuineCapability.AuthenticateConsoleOwnedIssuerAsync(new object(), CancellationToken.None));
        Assert.Equal("current_auth_archive_genuine_capability_invalid", failure.Code);
    }

    [Fact]
    public void Serialized_facts_cannot_construct_issuer_or_capability()
    {
        _ = Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<CurrentAuthArchiveGenuineIssuer>("{}"));
        _ = Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<CurrentAuthArchiveGenuineCapability>("{}"));
    }
}
