using System.Text.Json;
using System.Text.Json.Nodes;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineDualInputTests
{
    [Fact]
    public async Task Cancelled_dual_helper_stops_before_protected_input_or_fixture_access()
    {
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CurrentAuthArchiveGenuineDualInputReader.RunAsync("not-a-protected-path", cancelled.Token));
    }

    [Fact]
    public void Another_input_family_cannot_select_the_fixed_dual_helper()
    {
        _ = Assert.Throws<MigrationExecutionException>(() =>
            CurrentAuthArchiveGenuineDualInputContract.Require(new("unreviewed-family", null!)));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("operation")]
    [InlineData("container")]
    [InlineData("volume")]
    [InlineData("removed")]
    [InlineData("sdk")]
    [InlineData("cleanup-failed")]
    [InlineData("unverified")]
    [InlineData("remaining-container")]
    [InlineData("remaining-volume")]
    [InlineData("remaining-listener")]
    [InlineData("backwards-clock")]
    public void Final_helper_publication_requires_exact_completed_cleanup_and_absence(string fault)
    {
        Guid operation = Guid.NewGuid();
        string id = new('a', 64), name = "legacy-delta-proof-synthetic";
        var target = new CurrentAuthArchiveComponentTargetSubject("binding", id, name, name, "image", "pgdata", "generation",
            "target", "container", "volume", "system", "fleet", "auth", "catalog", "policy");
        DateTimeOffset removed = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        JsonObject disposal = JsonSerializer.SerializeToNode(new
        {
            Operation = operation,
            _id = id,
            volume = name,
            removed = true,
            sdkDisposed = true,
            cleanupFailed = false,
            verifiedAbsence = true,
            removedAtUtc = removed,
            completedAtUtc = removed.AddSeconds(2),
        })!.AsObject();
        JsonObject absence = JsonSerializer.SerializeToNode(new
        {
            Operation = operation,
            _id = id,
            volume = name,
            observedPort = 35432,
            observedAtUtc = removed.AddSeconds(1),
            containerIds = Array.Empty<string>(),
            containerNames = Array.Empty<string>(),
            volumeNames = Array.Empty<string>(),
            listeningPorts = Array.Empty<int>(),
        })!.AsObject();
        switch (fault)
        {
            case "none": break;
            case "operation": disposal["Operation"] = Guid.NewGuid(); break;
            case "container": absence["_id"] = new string('b', 64); break;
            case "volume": disposal["volume"] = "unrelated-volume"; break;
            case "removed": disposal["removed"] = false; break;
            case "sdk": disposal["sdkDisposed"] = false; break;
            case "cleanup-failed": disposal["cleanupFailed"] = true; break;
            case "unverified": disposal["verifiedAbsence"] = false; break;
            case "remaining-container": absence["containerIds"] = new JsonArray(JsonValue.Create(id)); break;
            case "remaining-volume": absence["volumeNames"] = new JsonArray(JsonValue.Create(name)); break;
            case "remaining-listener": absence["listeningPorts"] = new JsonArray(JsonValue.Create(35432)); break;
            case "backwards-clock": absence["observedAtUtc"] = removed.AddSeconds(-1); break;
            default: throw new InvalidOperationException();
        }
        void Require()
        {
            CurrentAuthArchiveGenuineDualInputReader.RequireCleanupRecords(
            JsonSerializer.SerializeToUtf8Bytes(disposal), JsonSerializer.SerializeToUtf8Bytes(absence), operation, target, 35432);
        }

        if (fault == "none") { Require(); }
        else { _ = Assert.Throws<MigrationExecutionException>(Require); }
    }
}
