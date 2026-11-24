using System.Text.Json;
using System.Text.Json.Nodes;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveDefinitionAnchorTests
{
    [Theory]
    [InlineData("removed", false, true)]
    [InlineData("owned", true, false)]
    [InlineData("renamed", true, false)]
    [InlineData("rebound", false, false)]
    [InlineData("renamed-and-rebound", true, false)]
    [InlineData("malformed", true, false)]
    public void Cleanup_and_absence_follow_the_recorded_container_id_after_name_changes(string state, bool absenceRejects, bool cleanupAccepts)
    {
        string id = new('b', 64), foreign = new('c', 64), name = "legacy-delta-proof-synthetic";
        string[] inventory = state switch
        {
            "removed" => [],
            "owned" => [id + "|" + name],
            "renamed" => [id + "|renamed"],
            "rebound" => [foreign + "|" + name],
            "renamed-and-rebound" => [id + "|renamed", foreign + "|" + name],
            "malformed" => ["unknown"],
            _ => throw new InvalidOperationException(),
        };
        if (absenceRejects) { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveDefinitionAnchorOwner.RequireRecordedContainerAbsent(id, inventory)); }
        else { CurrentAuthArchiveDefinitionAnchorOwner.RequireRecordedContainerAbsent(id, inventory); }
        if (cleanupAccepts) { Assert.Empty(CurrentAuthArchiveDefinitionAnchorOwner.RequireRecordedContainerForCleanup(id, name, inventory)); }
        else if (state == "owned") { Assert.Equal(id, Assert.Single(CurrentAuthArchiveDefinitionAnchorOwner.RequireRecordedContainerForCleanup(id, name, inventory))); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveDefinitionAnchorOwner.RequireRecordedContainerForCleanup(id, name, inventory)); }
    }

    [Theory]
    [InlineData("Legacy.Maliev.DataMigration.Tests.dll", true)]
    [InlineData("runtimes/win-x64/native/Microsoft.Data.SqlClient.SNI.dll", true)]
    [InlineData("Fixtures/2026-08-12-ga4-quotation-lifecycle.sql", true)]
    [InlineData("database-disposition.json", true)]
    [InlineData("customer-report.json", false)]
    [InlineData("evidence.trx", false)]
    [InlineData("private.pem", false)]
    [InlineData("../testhost.dll", false)]
    [InlineData("folder/../testhost.dll", false)]
    [InlineData("C:/outside/testhost.dll", false)]
    [InlineData("testhost.dll:stream", false)]
    public void Definition_bundle_copy_is_limited_to_accepted_code_and_fixed_synthetic_assets(string relative, bool expected)
    {
        Assert.Equal(expected, CurrentAuthArchiveDefinitionCodeCopy.ApprovedAsset(relative));
    }

    [Theory]
    [InlineData("Legacy.Maliev.DataMigration.Tests.dll", true)]
    [InlineData("runtimes/win-x64/native/Microsoft.Data.SqlClient.SNI.dll", true)]
    [InlineData("Legacy.Maliev.DataMigration.Tests.deps.json", true)]
    [InlineData("database-disposition.json", true)]
    [InlineData("Fixtures/bd201a5-quotation-accepted-outcome.sql", true)]
    [InlineData("case-proof.json", false)]
    [InlineData("reports/customer.csv", false)]
    [InlineData("../outside.dll", false)]
    [InlineData("x/../../outside.dll", false)]
    [InlineData("C:\\outside.dll", false)]
    [InlineData("x//other.dll", false)]
    [InlineData("evidence-private.pem", false)]
    [InlineData("Fixtures/arbitrary.sql", false)]
    public void Definition_bundle_copy_contains_only_fixed_build_assets(string relative, bool expected)
    {
        Assert.Equal(expected, CurrentAuthArchiveDefinitionCodeCopy.ApprovedAsset(relative));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("purpose")]
    [InlineData("parent")]
    [InlineData("extra-label")]
    [InlineData("existing")]
    [InlineData("options")]
    [InlineData("old")]
    [InlineData("root")]
    [InlineData("kind")]
    [InlineData("expiry")]
    public void Definition_anchor_volume_has_a_distinct_exact_parent_bound_lifecycle(string fault)
    {
        var intent = Intent(); var volume = Volume(intent);
        switch (fault)
        {
            case "purpose": volume["Labels"]!["codex.repair.purpose"] = "current-auth-local-session-archive-proof"; break;
            case "parent": volume["Labels"]![CurrentAuthArchiveDefinitionAnchorOwner.ParentLabel] = new string('e', 64); break;
            case "extra-label": volume["Labels"]!["other"] = "unrelated"; break;
            case "existing": intent = intent with { BeforeVolumes = [volume["Name"]!.GetValue<string>()] }; break;
            case "options": volume["Options"] = new JsonObject { ["device"] = "persistent" }; break;
            case "old": volume["CreatedAt"] = intent.BeganAtUtc.AddTicks(-1).ToString("O"); break;
            case "root": intent = intent with { Root = Path.Combine(Path.GetTempPath(), "other") }; break;
            case "kind": intent = intent with { Kind = "old" }; break;
            case "expiry": intent = intent with { ExpiresAtUtc = intent.ExpiresAtUtc.AddSeconds(1) }; break;
            default:
                break;
        }
        using var bytes = JsonDocument.Parse(volume.ToJsonString());
        if (fault == "none") { CurrentAuthArchiveDefinitionAnchorOwner.RequireVolume(bytes.RootElement, intent); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveDefinitionAnchorOwner.RequireVolume(bytes.RootElement, intent)); }
    }

    [Theory]
    [InlineData("none")]
    [InlineData("image")]
    [InlineData("id")]
    [InlineData("memory")]
    [InlineData("mount")]
    [InlineData("port")]
    [InlineData("bind")]
    [InlineData("existing")]
    public void Definition_anchor_container_cannot_adopt_another_resource_or_persistent_mount(string fault)
    {
        var intent = Intent(); var volume = Volume(intent);
        var container = new JsonObject
        {
            ["Id"] = new string('b', 64),
            ["Image"] = "sha256:" + new string('c', 64),
            ["Name"] = "/" + volume["Name"]!.GetValue<string>(),
            ["Created"] = intent.BeganAtUtc.AddSeconds(2).ToString("O"),
            ["Config"] = new JsonObject { ["Image"] = CurrentAuthArchiveDefinitionAnchorOwner.Image, ["Labels"] = volume["Labels"]!.DeepClone() },
            ["HostConfig"] = new JsonObject
            {
                ["Memory"] = 512L * 1024 * 1024,
                ["MemorySwap"] = 512L * 1024 * 1024,
                ["NanoCpus"] = 750_000_000L,
                ["Binds"] = null,
                ["VolumesFrom"] = null,
                ["Tmpfs"] = null
            },
            ["Mounts"] = new JsonArray(new JsonObject { ["Type"] = "volume", ["Name"] = volume["Name"]!.GetValue<string>(), ["Destination"] = "/var/lib/postgresql", ["RW"] = true }),
            ["NetworkSettings"] = new JsonObject { ["Ports"] = new JsonObject { ["5432/tcp"] = new JsonArray(new JsonObject { ["HostIp"] = "127.0.0.1", ["HostPort"] = "33333" }) } },
        };
        switch (fault)
        {
            case "image": container["Config"]!["Image"] = "postgres:latest"; break;
            case "id": container["Id"] = "unbound"; break;
            case "memory": container["HostConfig"]!["Memory"] = 0; break;
            case "mount": container["Mounts"]![0]!["Name"] = "persistent-volume"; break;
            case "port": container["NetworkSettings"]!["Ports"]!["5432/tcp"]![0]!["HostIp"] = "0.0.0.0"; break;
            case "bind": container["HostConfig"]!["Binds"] = new JsonArray(JsonValue.Create("C:\\persistent:/outside")); break;
            case "existing": intent = intent with { BeforeContainers = [new string('b', 64) + "|unrelated"] }; break;
            default:
                break;
        }
        using var containerBytes = JsonDocument.Parse(container.ToJsonString()); using var volumeBytes = JsonDocument.Parse(volume.ToJsonString());
        if (fault == "none") { CurrentAuthArchiveDefinitionAnchorOwner.RequireContainer(containerBytes.RootElement, volumeBytes.RootElement, intent); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveDefinitionAnchorOwner.RequireContainer(containerBytes.RootElement, volumeBytes.RootElement, intent)); }
    }

    private static CurrentAuthArchiveDefinitionAnchorIntent Intent()
    {
        Guid operation = Guid.NewGuid(); string root = Path.Combine(Path.GetTempPath(), "auth-definition-anchor-" + operation.ToString("N"));
        var binding = new LocalExecutionBinding(1, "synthetic-host", "synthetic-volume", root, "synthetic-root-id", "run.lock", "synthetic-lock-id", 1);
        DateTimeOffset began = new(2026, 11, 24, 0, 0, 0, TimeSpan.Zero);
        return new("current-auth-archive-definition-anchor-intent-v2", operation, new('a', 40), new('d', 64), root, binding, began, began.AddMinutes(8), [], []);
    }
    private static JsonObject Volume(CurrentAuthArchiveDefinitionAnchorIntent intent)
    {
        return new()
        {
            ["Name"] = "legacy-delta-proof-" + intent.OperationId.ToString("N"),
            ["Driver"] = "local",
            ["Scope"] = "local",
            ["CreatedAt"] = intent.BeganAtUtc.AddSeconds(1).ToString("O"),
            ["Options"] = null,
            ["Labels"] = new JsonObject
            {
                ["codex.repair.purpose"] = "current-auth-repair-proof",
                ["codex.repair.operation"] = intent.OperationId.ToString("D"),
                ["codex.repair.run-binding"] = intent.Binding.ComputeSha256(),
                [CurrentAuthArchiveDefinitionAnchorOwner.ParentLabel] = intent.ParentBindingSha256
            },
        };
    }
}
