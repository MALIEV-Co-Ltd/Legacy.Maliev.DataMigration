using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static class Production181SemanticResource
{
    internal static bool DeclaredMount(JsonElement host, string volume)
    {
        if (!host.TryGetProperty("Mounts", out var declared) || declared.ValueKind != JsonValueKind.Array || declared.GetArrayLength() != 1) { return false; }
        var mount = declared[0]; return mount.GetProperty("Type").GetString() == "volume" && mount.GetProperty("Source").GetString() == volume &&
            mount.GetProperty("Target").GetString() == "/var/lib/postgresql" && !mount.GetProperty("ReadOnly").GetBoolean() && mount.GetProperty("VolumeOptions").GetProperty("NoCopy").GetBoolean();
    }
    internal static bool NamedLabels(JsonElement volume, Guid run)
    {
        var labels = volume.GetProperty("Labels"); return labels.ValueKind == JsonValueKind.Object && labels.EnumerateObject().Count() == 4 &&
            labels.GetProperty("codex.repair.purpose").GetString() == Production181EngineContract.Purpose && labels.GetProperty("codex.repair.run").GetString() == run.ToString("D") &&
            labels.GetProperty("codex.repair.operation").GetString() == run.ToString("D") && CurrentCustomerSequenceRepairPermit.HashShape(labels.GetProperty("codex.repair.run-binding").GetString() ?? string.Empty);
    }
}
