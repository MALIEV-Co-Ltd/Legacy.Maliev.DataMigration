using System.Collections.Immutable;

namespace Legacy.Maliev.DataMigration.Tests;

internal static class ProviderNeutralSourceObservationFixture
{
    internal const string ContainerId = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    internal const string ImageId = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    internal const string Fingerprint = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    internal static RestoredSourceObservation Create(DateTimeOffset observedAtUtc)
    {
        var identity = new FileSystemObjectIdentity("device", "inode", "directory");
        var image = new DockerObservedImage(
            ImageId,
            "2026-09-01T00:00:00Z",
            "linux",
            "amd64",
            ["mcr.microsoft.com/mssql/server@sha256:" + new string('a', 64)],
            ["sha256:" + new string('b', 64)]);
        var layer = new DockerObservedLayer("overlay2", ContainerId, "lower", "merged", "upper", "work", "properties");
        var volume = new DockerObservedVolume(
            "backup-volume", "local", "2026-09-01T00:00:00Z", "/var/lib/docker/volumes/backup-volume/_data",
            "local", "run-1", "backup-binding", Fingerprint);
        var mount = new DockerObservedMount(
            "volume", "backup-volume", "/var/lib/docker/volumes/backup-volume/_data", "/backup",
            "local", "ro", false, string.Empty, "properties", volume, identity);
        var network = new DockerObservedNetwork("bridge", "network-id", "endpoint-id", "172.18.0.2", "properties");
        var docker = new LocalDockerResourceState(
            "default",
            "npipe://docker_engine",
            "daemon",
            "/var/lib/docker",
            ContainerId,
            "restore-test",
            "2026-09-01T00:00:00Z",
            "2026-09-01T00:00:01Z",
            "restore-host",
            "run-1",
            true,
            "bridge",
            image,
            layer,
            identity,
            [mount],
            [network],
            [new DockerObservedPort("127.0.0.1", 15433, 1433)]);
        ImmutableArray<SqlObservedFile> files =
        [
            .. DatabaseInventory.ActiveDatabases.Select((name, index) =>
                new SqlObservedFile(index + 5, 1, 0, $"/var/opt/mssql/data/{name}.mdf")),
        ];
        var sql = new SqlRestoredSourceState(
            "172.18.0.2",
            1433,
            "restore-host",
            "restore-host",
            "16",
            true,
            [.. DatabaseInventory.ActiveDatabases.Select((name, index) =>
                new SqlObservedDatabase(index + 5, name, Guid.Parse($"00000000-0000-0000-0000-{index + 1:D12}"), true, 1, 0))],
            files);
        ImmutableArray<SourceFileStorageBinding> bindings =
        [
            .. files.Select(file => new SourceFileStorageBinding(file, file.PhysicalName, identity)),
        ];
        return new RestoredSourceObservation(
            observedAtUtc,
            new RestoredSourceState(
                new string('c', 64),
                new string('d', 64),
                DatabaseInventory.InventorySha256,
                "tcp:127.0.0.1,15433",
                docker,
                sql,
                bindings));
    }

    internal static VerifiedRestoreReceipt CreateReceipt(DateTimeOffset restoredAtUtc)
    {
        return new VerifiedRestoreReceipt(
            "1.0",
            restoredAtUtc,
            DatabaseInventory.InventorySha256,
            new string('d', 64),
            new VerifiedRestoreResourceEvidence(
                "mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04@sha256:" + new string('a', 64),
                ImageId,
                ContainerId,
                "restore-test",
                "run-1",
                "backup-volume",
                "backup-volume",
                "backup-binding",
                Fingerprint,
                "/backup",
                true,
                "alpine:3.20@sha256:" + new string('b', 64),
                "16"),
            [.. DatabaseInventory.ActiveDatabases.Select(name =>
                new VerifiedRestoreArtifactEvidence(name, 1, new string('d', 64), 1, new string('d', 64), true, true, true))],
            RestoreCleanupDisposition.Pending,
            null,
            "test",
            null);
    }
}
