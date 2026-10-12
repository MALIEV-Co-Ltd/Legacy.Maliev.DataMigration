using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Separates the existing persistent target from an explicitly isolated Console proof.</summary>
internal static class CurrentAppOwnedV3RepairLocalTarget
{
    internal static void RequireVolumeConsumers(string output, string containerId)
    {
        string[] consumers = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (consumers.Length != 1 || consumers[0] != containerId)
        { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
    }

    internal static bool RequireClaim(DeltaTargetAuthority authority, Guid operationId,
        string runBindingSha256, CurrentAppOwnedRepairTargetPins target)
    {
        if (authority.Kind != DeltaTargetAuthorityKind.LocalAspire || operationId == Guid.Empty ||
            !CurrentAppOwnedV3RepairPermit.HashShape(runBindingSha256) ||
            target.DockerContainerId is not { Length: 64 } id ||
            !id.All(value => value is (>= '0' and <= '9') or (>= 'a' and <= 'f')))
        { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        bool persistent = DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(authority);
        string prefix = persistent ? "persistent-" : "disposable-";
        return (!persistent && !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(authority)) ||
            authority.AuthorityId != "aspire://legacy-postgres-main-local/" + prefix + id[..12] ||
            target.DockerVolume != (persistent ? "legacy-maliev-exact23-postgres-data" :
                "legacy-delta-proof-" + operationId.ToString("N"))
            ? throw CurrentAppOwnedV3RepairPermit.Invalid()
            : persistent;
    }

    internal static void RequireDisposableMetadata(JsonElement container, JsonElement volume,
        Guid operationId, string runBindingSha256, DateTimeOffset now)
    {
        try
        {
            RequireLabels(container.GetProperty("Config").GetProperty("Labels"));
            RequireLabels(volume.GetProperty("Labels"));
            string name = "legacy-delta-proof-" + operationId.ToString("N");
            JsonElement[] mounts = [.. container.GetProperty("Mounts").EnumerateArray()];
            JsonElement options = volume.GetProperty("Options");
            DateTimeOffset created = container.GetProperty("Created").GetDateTimeOffset();
            DateTimeOffset volumeCreated = volume.GetProperty("CreatedAt").GetDateTimeOffset();
            if (operationId == Guid.Empty || !CurrentAppOwnedV3RepairPermit.HashShape(runBindingSha256) ||
                mounts.Length != 1 || !mounts[0].GetProperty("RW").GetBoolean() ||
                mounts[0].GetProperty("Type").GetString() != "volume" || mounts[0].GetProperty("Name").GetString() != name ||
                (options.ValueKind != JsonValueKind.Null &&
                    (options.ValueKind != JsonValueKind.Object || options.EnumerateObject().Any())) ||
                created > now || volumeCreated > created || created < now.AddHours(-4) || volumeCreated < now.AddHours(-4))
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }

            void RequireLabels(JsonElement labels)
            {
                if (labels.ValueKind != JsonValueKind.Object ||
                    labels.GetProperty("codex.repair.purpose").GetString() != "current-app-owned-v3-proof" ||
                    labels.GetProperty("codex.repair.operation").GetString() != operationId.ToString("D") ||
                    labels.GetProperty("codex.repair.run-binding").GetString() != runBindingSha256)
                { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            }
        }
        catch (Exception failure) when (failure is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
    }
}
