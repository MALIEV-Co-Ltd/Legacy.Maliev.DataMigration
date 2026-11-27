using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Live read-only custody for the two existing target identities; provisions no infrastructure.</summary>
internal sealed class CompanyStoragePersistentTarget : IDisposable
{
    private readonly CurrentAppOwnedRepairTargetPins _pins;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly string _root;
    private readonly CloudNativePgTargetObserver? _cloud;
    internal CompanyStoragePersistentTarget(CurrentAppOwnedRepairTargetPins pins, CurrentAppOwnedRepairCustody files, string root)
    {
        _pins = CompanyStorageRepairProtocol.Copy(pins); _files = files; _root = root;
        if (pins.CloudOptions is not null)
        {
            _ = files.Read(pins.CloudOptions.ServiceAccountTokenFile, sharedReader: true);
            _ = files.Read(pins.CloudOptions.ServiceAccountCaFile, sharedReader: true);
            _cloud = CloudNativePgTargetObserver.CreateForCurrentAppOwnedRepair(pins.CloudOptions);
        }
    }

    internal async Task RequireAsync(CompanyStorageRepairIntent scope, int port, CancellationToken ct)
    {
        _files.Require();
        if (scope.Kind != CompanyStorageRepairProtocol.IntentKind || _pins.HbaPath != scope.Maintenance.HbaPath ||
            CompanyStorageRepairProtocol.Hash(JsonSerializer.SerializeToUtf8Bytes(_pins)) != scope.TargetObservationSha256)
        { throw Invalid(); }
        if (scope.Target.Kind == DeltaTargetAuthorityKind.LocalAspire)
        {
            if (!OperatingSystem.IsWindows() || !DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(scope.Target) ||
                _pins.CloudOptions is not null || _pins.CloudObservation is not null || _pins.DockerContainerId is not { Length: 64 } ||
                _pins.DockerVolume != "legacy-maliev-exact23-postgres-data" || _pins.HbaStatSha256 is not { Length: 64 })
            { throw Invalid(); }
            if (!CurrentAppOwnedRepairLocalTarget.RequireClaim(scope.Target, scope.IntentId, scope.RunBindingSha256, _pins)) { throw Invalid(); }
            string container = await DockerAsync(["inspect", _pins.DockerContainerId], ct).ConfigureAwait(false);
            string volume = await DockerAsync(["volume", "inspect", _pins.DockerVolume], ct).ConfigureAwait(false);
            var actual = DockerLocalTargetObservation.Parse(container, volume, _pins.DockerContainerId, _pins.DockerVolume, port, persistent: true);
            using var metadata = JsonDocument.Parse(container); var item = metadata.RootElement.EnumerateArray().Single();
            if (item.GetProperty("Image").GetString() != _pins.DockerImageId || item.GetProperty("Config").GetProperty("Image").GetString() != _pins.DockerImageReference ||
                LocalDockerGenerationGuard.ComposeGeneration(actual) != scope.TargetGeneration) { throw Invalid(); }
            string consumers = await DockerAsync(["ps", "--all", "--no-trunc", "--filter", "volume=" + _pins.DockerVolume, "--format", "{{.ID}}"], ct).ConfigureAwait(false);
            CurrentAppOwnedRepairLocalTarget.RequireVolumeConsumers(consumers, _pins.DockerContainerId);
            string stat = await DockerAsync(["exec", _pins.DockerContainerId, "env", "TZ=UTC", "LC_ALL=C", "stat",
                "--printf=%d|%i|%f|%u|%g|%h|%s|%y|%z", "--", _pins.HbaPath], ct).ConfigureAwait(false);
            if (CompanyStorageRepairProtocol.Hash(Encoding.UTF8.GetBytes(stat)) != _pins.HbaStatSha256) { throw Invalid(); }
            string capacity = await DockerAsync(["exec", _pins.DockerContainerId, "df", "-Pk", "--", actual.PgData], ct).ConfigureAwait(false);
            DockerLocalTargetObservation.RequireCapacity(capacity);
        }
        else
        {
            if (scope.Target.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg || scope.TargetNamespace != "maliev-legacy" || scope.TargetCluster != "legacy-postgres-main" ||
                _cloud is null || _pins.CloudObservation is null || _pins.DockerContainerId is not null || _pins.DockerVolume is not null)
            { throw Invalid(); }
            var actual = await _cloud.ObserveAsync("maliev-legacy", "legacy-postgres-main", ct).ConfigureAwait(false);
            if (!actual.SameRuntimeTarget(_pins.CloudObservation) || "cnpg:" + actual.Uid + ":" + actual.Generation.ToString(CultureInfo.InvariantCulture) != scope.TargetGeneration ||
                !actual.Ready || actual.ReadyInstances != 2 || actual.Instances != 2 || !actual.ConsistentSystemId || !actual.ContinuousArchiving || !actual.LastBackupSucceeded)
            { throw Invalid(); }
        }
        _files.Require();
    }

    private Task<string> DockerAsync(IReadOnlyList<string> arguments, CancellationToken ct)
    {
        return CurrentAppOwnedRepairDockerProcess.RunDockerAsync(arguments, ct, async frame =>
    {
        await _files.WriteNewAsync(Path.Combine(_root, $"company-resource-{frame.RunId:N}-{Guid.NewGuid():N}.json"), JsonSerializer.SerializeToUtf8Bytes(frame), CancellationToken.None).ConfigureAwait(false);
        if (frame.CleanupFailed) { throw Invalid(); }
    });
    }

    public void Dispose()
    {
        _cloud?.Dispose();
    }

    private static MigrationExecutionException Invalid()
    {
        return CompanyStorageRepairProtocol.Invalid();
    }
}
