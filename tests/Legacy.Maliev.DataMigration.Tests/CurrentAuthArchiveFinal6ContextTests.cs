using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveFinal6ContextTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(6)]
    [InlineData(10)]
    [InlineData(17)]
    public async Task An_SDK_host_cannot_open_the_actual_source_context_or_create_targets(int value)
    {
        string root = Path.Combine(Path.GetTempPath(), "uncreated-final6-context-" + Guid.NewGuid().ToString("N"));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthArchiveFinal6CaseContext.OpenAsync(
            Path.Combine(root, "input.json"), (CurrentAuthArchiveProofCaseV2)value, CancellationToken.None));
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public void Deserialized_positive_fields_cannot_construct_a_live_Final6_case_context()
    {
        _ = Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<CurrentAuthArchiveFinal6CaseContext>(
            "{\"Verified\":true,\"Case\":1,\"Profile\":6}"));
    }
}
