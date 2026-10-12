using System.Text.Json;
using System.Text.Json.Nodes;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAppOwnedV3RepairLocalTargetTests
{
    private static readonly Guid Operation = Guid.Parse("8fa15256-12b3-4978-9949-b9629f38e1d0");
    private static readonly string Binding = new('b', 64);
    private static readonly string Container = new('c', 64);
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-12T14:00:00Z", System.Globalization.CultureInfo.InvariantCulture);

    [Fact]
    public void Closed_decoder_rejects_duplicate_properties_at_every_depth()
    {
        foreach (string json in new[] { "{\"Path\":\"a\",\"path\":\"b\",\"Sha256\":\"c\"}",
            "{\"Nested\":{\"Key\":1,\"key\":2}}", "[{\"Key\":1,\"Key\":2}]" })
        {
            _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.DecodeV3<JsonElement>(System.Text.Encoding.UTF8.GetBytes(json)));
        }
    }

    [Fact]
    public void Closed_decoder_rejects_unknown_configuration_members()
    {
        _ = Assert.Throws<JsonException>(() => MigrationConsole.DecodeV3<CurrentAppOwnedRepairArtifact>(
            "{\"path\":\"a\",\"sha256\":\"b\",\"environmentCallback\":\"unsafe\"}"u8.ToArray()));
        CurrentAppOwnedRepairArtifact actual = MigrationConsole.DecodeV3<CurrentAppOwnedRepairArtifact>(
            "{\"path\":\"a\",\"sha256\":\"b\"}"u8.ToArray());
        Assert.Equal(new CurrentAppOwnedRepairArtifact("a", "b"), actual);
    }

    [Fact]
    public void Proof_volume_is_exclusively_referenced_even_by_stopped_containers()
    {
        CurrentAppOwnedV3RepairLocalTarget.RequireVolumeConsumers(Container + "\r\n", Container);
        foreach (string output in new[] { "", new string('d', 64), Container + "\n" + new string('d', 64), Container + "\n" + Container })
        {
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedV3RepairLocalTarget.RequireVolumeConsumers(output, Container));
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Claim_requires_exact_authority_container_and_separate_volume(bool persistent)
    {
        DeltaTargetAuthority authority = Authority(persistent);
        CurrentAppOwnedRepairTargetPins target = Pins(persistent);
        Assert.Equal(persistent, CurrentAppOwnedV3RepairLocalTarget.RequireClaim(authority, Operation, Binding, target));
        foreach (string fault in new[] { "kind", "id", "volume", "empty-operation", "binding", "container" })
        {
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedV3RepairLocalTarget.RequireClaim(
                fault == "kind" ? authority with { Kind = DeltaTargetAuthorityKind.ProductionCloudNativePg } :
                fault == "id" ? authority with { AuthorityId = authority.AuthorityId + "0" } : authority,
                fault == "empty-operation" ? Guid.Empty : Operation,
                fault == "binding" ? "invalid" : Binding,
                fault == "volume" ? Pins(!persistent) : fault == "container" ? target with { DockerContainerId = new string('d', 64) } : target));
        }
    }

    [Fact]
    public void Disposable_metadata_requires_bound_labels_fresh_unconfigured_volume_and_single_mount()
    {
        (JsonObject container, JsonObject volume) = Metadata();
        Require(container, volume);
        foreach (string fault in new[] { "container-purpose", "container-operation", "volume-binding", "missing-labels",
            "extra-mount", "bind-mount", "read-only", "wrong-volume", "driver-options", "future", "stale-volume", "stale-container" })
        {
            (container, volume) = Metadata();
            switch (fault)
            {
                case "container-purpose": container["Config"]!["Labels"]!["codex.repair.purpose"] = "other"; break;
                case "container-operation": container["Config"]!["Labels"]!["codex.repair.operation"] = Guid.NewGuid().ToString("D"); break;
                case "volume-binding": volume["Labels"]!["codex.repair.run-binding"] = new string('e', 64); break;
                case "missing-labels": _ = volume.Remove("Labels"); break;
                case "extra-mount": ((JsonArray)container["Mounts"]!).Add(JsonSerializer.SerializeToNode(new { RW = false, Type = "volume", Name = "legacy-maliev-exact23-postgres-data" })); break;
                case "bind-mount": container["Mounts"]![0]!["Type"] = "bind"; break;
                case "read-only": container["Mounts"]![0]!["RW"] = false; break;
                case "wrong-volume": container["Mounts"]![0]!["Name"] = "legacy-maliev-exact23-postgres-data"; break;
                case "driver-options": volume["Options"] = JsonSerializer.SerializeToNode(new { device = "/persistent", type = "none", o = "bind" }); break;
                case "future": container["Created"] = Now.AddSeconds(1).ToString("O"); break;
                case "stale-volume": volume["CreatedAt"] = Now.AddHours(-5).ToString("O"); break;
                case "stale-container": container["Created"] = Now.AddHours(-5).ToString("O"); volume["CreatedAt"] = Now.AddHours(-6).ToString("O"); break;
                default:
                    break;
            }
            _ = Assert.Throws<MigrationExecutionException>(() => Require(container, volume));
        }
    }

    private static void Require(JsonObject container, JsonObject volume)
    {
        using JsonDocument c = JsonDocument.Parse(container.ToJsonString());
        using JsonDocument v = JsonDocument.Parse(volume.ToJsonString());
        CurrentAppOwnedV3RepairLocalTarget.RequireDisposableMetadata(c.RootElement, v.RootElement, Operation, Binding, Now);
    }

    private static (JsonObject, JsonObject) Metadata()
    {
        var labels = new Dictionary<string, string>
        {
            ["codex.repair.purpose"] = "current-app-owned-v3-proof",
            ["codex.repair.operation"] = Operation.ToString("D"),
            ["codex.repair.run-binding"] = Binding,
        };
        return ((JsonObject)JsonSerializer.SerializeToNode(new
        {
            Config = new { Labels = labels },
            Created = Now.AddMinutes(-1).ToString("O"),
            Mounts = new[] { new { RW = true, Type = "volume", Name = "legacy-delta-proof-" + Operation.ToString("N") } },
        })!, (JsonObject)JsonSerializer.SerializeToNode(new
        { Labels = labels, CreatedAt = Now.AddMinutes(-2).ToString("O"), Options = (object?)null })!);
    }

    private static DeltaTargetAuthority Authority(bool persistent)
    {
        return new(DeltaTargetAuthorityKind.LocalAspire,
        "aspire://legacy-postgres-main-local/" + (persistent ? "persistent-" : "disposable-") + Container[..12], new string('a', 64));
    }

    private static CurrentAppOwnedRepairTargetPins Pins(bool persistent)
    {
        return new(Container,
            persistent ? "legacy-maliev-exact23-postgres-data" : "legacy-delta-proof-" + Operation.ToString("N"),
            "image", "reference", "/pg_hba.conf", new string('d', 64), null, null);
    }
}
