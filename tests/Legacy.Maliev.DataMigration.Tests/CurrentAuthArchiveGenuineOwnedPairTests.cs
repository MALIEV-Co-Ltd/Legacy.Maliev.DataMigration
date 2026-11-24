using System.Reflection;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineOwnedPairTests
{
    [Fact]
    public async Task Cancelled_owned_pair_creation_cannot_read_inputs_or_create_targets()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CurrentAuthArchiveGenuineOwnedPair.CreateAsync(null!, cancelled.Token));
    }

    [Fact]
    public void Serialized_endpoints_or_target_identities_cannot_construct_owned_pair()
    {
        Assert.Empty(typeof(CurrentAuthArchiveGenuineOwnedPair).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        _ = Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<CurrentAuthArchiveGenuineOwnedPair>(
            """{"AdminConnection":"Host=127.0.0.1;Database=Auth","ContainerId":"existing","Scope":{}}"""));
    }
}
