using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

// A separate, fixed metadata admission. The persistent and earlier disposable
// helpers remain untouched and cannot fall through into this branch.
internal static class CurrentOwnerIsoNamedClosedTarget
{
    internal const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";

    internal static void Require(CurrentOwnerIsoRepairScope scope, CurrentAppOwnedRepairTargetPins target,
        JsonElement container, JsonElement volume, int port, DateTimeOffset now)
    {
        if (scope.ProofAdmission != CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap ||
            scope.BootstrapSubject is not { } bootstrap || bootstrap.ClosedPrecursorPins is null ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) ||
            DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(scope.Target)) { throw Invalid(); }
        try
        {
            string containerName = "iso-closed-bootstrap-" + scope.OperationId.ToString("N");
            string volumeName = "iso-closed-bootstrap-data-" + scope.OperationId.ToString("N");
            string id = bootstrap.ContainerId ?? throw Invalid();
            if (scope.OperationId == Guid.Empty || id.Length != 64 ||
                !id.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f')) ||
                scope.Target.AuthorityId != "aspire://legacy-postgres-main-local/disposable-" + id[..12] ||
                bootstrap.ContainerName != containerName || bootstrap.NamedVolume != volumeName ||
                bootstrap.LoopbackPort != port || target.DockerContainerId != id || target.DockerVolume != volumeName ||
                target.DockerImageReference != Image || container.GetProperty("Name").GetString() != "/" + containerName)
            { throw Invalid(); }
            CurrentOwnerIsoRepairLocalTarget.RequireProofIdentity(container, volume, scope, target, id, port);
            RequireLabels(container.GetProperty("Config").GetProperty("Labels"));
            RequireLabels(volume.GetProperty("Labels"));
            DateTimeOffset created = container.GetProperty("Created").GetDateTimeOffset();
            DateTimeOffset volumeCreated = volume.GetProperty("CreatedAt").GetDateTimeOffset();
            JsonElement options = volume.GetProperty("Options"), host = container.GetProperty("HostConfig");
            if (created != bootstrap.NamedCreatedAtUtc || volumeCreated != bootstrap.NamedVolumeCreatedAtUtc || bootstrap.NamedLeaseExpiresAtUtc is not { } lease || lease <= now || scope.Maintenance.ExpiresAtUtc > lease ||
                lease - volumeCreated > TimeSpan.FromMinutes(8) || container.GetProperty("Config").GetProperty("PgData").GetString() != "/var/lib/postgresql/18/docker" ||
                !container.GetProperty("State").GetProperty("Running").GetBoolean() || created > now || volumeCreated > created || created < scope.Maintenance.IssuedAtUtc.AddMinutes(-8) ||
                volumeCreated < scope.Maintenance.IssuedAtUtc.AddMinutes(-8) || now >= scope.Maintenance.ExpiresAtUtc ||
                host.GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 ||
                host.GetProperty("MemorySwap").GetInt64() != 512L * 1024 * 1024 ||
                host.GetProperty("NanoCpus").GetInt64() != 750_000_000 ||
                (options.ValueKind != JsonValueKind.Null && (options.ValueKind != JsonValueKind.Object || options.EnumerateObject().Any())))
            { throw Invalid(); }
            RequireEmpty(host.GetProperty("Tmpfs")); RequireEmpty(host.GetProperty("Binds")); RequireEmpty(host.GetProperty("VolumesFrom"));
            void RequireLabels(JsonElement labels)
            {
                if (labels.ValueKind != JsonValueKind.Object || labels.GetProperty("codex.repair.purpose").GetString() != "current-owner-iso-closed-bootstrap" ||
                    labels.GetProperty("codex.repair.operation").GetString() != scope.OperationId.ToString("D") ||
                    labels.GetProperty("codex.repair.run-binding").GetString() != scope.RunBindingSha256) { throw Invalid(); }
            }
        }
        catch (Exception failure) when (failure is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or MigrationConsoleException)
        { throw Invalid(); }
    }

    private static void RequireEmpty(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Null &&
            (value.ValueKind == JsonValueKind.Object ? value.EnumerateObject().Any() :
             value.ValueKind != JsonValueKind.Array || value.EnumerateArray().Any())) { throw Invalid(); }
    }
    private static MigrationExecutionException Invalid()
    {
        return new("iso_named_closed_target_invalid", "Only the exact current run-owned named disposable target is admitted.");
    }
}
