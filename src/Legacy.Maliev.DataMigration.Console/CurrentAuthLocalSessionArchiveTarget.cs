using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static class CurrentAuthLocalSessionArchiveTarget
{
    internal static void RequireDisposable(JsonElement container, JsonElement volume, Guid operation, string binding, DateTimeOffset now, bool comparison = false)
    {
        try
        {
            string name = "legacy-delta-proof-" + operation.ToString("N") + (comparison ? "-comparison" : ""); JsonElement[] mounts = [.. container.GetProperty("Mounts").EnumerateArray()];
            DateTimeOffset created = container.GetProperty("Created").GetDateTimeOffset(), volumeCreated = volume.GetProperty("CreatedAt").GetDateTimeOffset();
            JsonElement options = volume.GetProperty("Options");
            if (operation == Guid.Empty || !CurrentAuthRepairPermit.HashShape(binding) || container.GetProperty("Name").GetString() != "/" + name || mounts.Length != 1 ||
                mounts[0].GetProperty("Type").GetString() != "volume" || mounts[0].GetProperty("Name").GetString() != name || !mounts[0].GetProperty("RW").GetBoolean() ||
                volume.GetProperty("Name").GetString() != name || (options.ValueKind != JsonValueKind.Null && (options.ValueKind != JsonValueKind.Object || options.EnumerateObject().Any())) ||
                created > now || volumeCreated > created || created < now.AddHours(-4) || volumeCreated < now.AddHours(-4)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            Labels(container.GetProperty("Config").GetProperty("Labels")); Labels(volume.GetProperty("Labels"));
            void Labels(JsonElement labels)
            {
                if (labels.GetProperty("codex.repair.purpose").GetString() != "current-auth-local-session-archive-proof" ||
                    labels.GetProperty("codex.repair.operation").GetString() != operation.ToString("D") || labels.GetProperty("codex.repair.run-binding").GetString() != binding)
                { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            }
        }
        catch (Exception failure) when (failure is JsonException or InvalidOperationException or KeyNotFoundException or FormatException) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
    }
}
