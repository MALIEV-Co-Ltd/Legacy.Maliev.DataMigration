using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

public sealed record FileSystemObjectIdentity(string Device, string Inode, string Type);
public sealed record DockerObservedVolume(string Name, string Driver, string CreatedAt, string Mountpoint, string Scope,
    string RunBinding, string VolumeBinding, string Fingerprint);
public sealed record DockerObservedMount(string Type, string Name, string Source, string Destination, string Driver,
    string Mode, bool ReadWrite, string Propagation, string Properties, DockerObservedVolume Volume, FileSystemObjectIdentity FileSystemIdentity);
public sealed record DockerObservedNetwork(string Name, string NetworkId, string EndpointId, string Address, string Properties);
public sealed record DockerObservedPort(string HostAddress, int HostPort, int ContainerPort);
public sealed record DockerObservedLayer(string Driver, string Id, string LowerDir, string MergedDir, string UpperDir, string WorkDir, string Properties);
public sealed record DockerObservedImage(string Id, string CreatedAt, string Os, string Architecture, ImmutableArray<string> RepoDigests, ImmutableArray<string> Layers);
public sealed record LocalDockerResourceState(string Context, string DockerHost, string DaemonId, string DockerRootDir,
    string ContainerId, string ContainerName, string CreatedAt, string StartedAt, string Hostname, string RunBinding,
    bool ReadonlyRootfs, string NetworkMode, DockerObservedImage Image, DockerObservedLayer Layer, FileSystemObjectIdentity Root,
    ImmutableArray<DockerObservedMount> Mounts, ImmutableArray<DockerObservedNetwork> Networks, ImmutableArray<DockerObservedPort> Ports);
public sealed record SqlObservedDatabase(int DatabaseId, string Name, Guid DatabaseGuid, bool ReadOnly, int SnapshotIsolationState, int State);
public sealed record SqlObservedFile(int DatabaseId, int FileId, int Type, string PhysicalName);
public sealed record SqlRestoredSourceState(string LocalAddress, int LocalPort, string MachineName, string ServerName,
    string ProductMajorVersion, bool CompleteMetadataVisibility, ImmutableArray<SqlObservedDatabase> Databases, ImmutableArray<SqlObservedFile> Files);
public sealed record SourceFileStorageBinding(SqlObservedFile File, string StoragePath, FileSystemObjectIdentity FileSystemIdentity);
public sealed record RestoredSourceState(string VerifiedRestoreSha256, string SchemaPlanSha256, string InventorySha256,
    string ConfiguredEndpoint, LocalDockerResourceState Docker, SqlRestoredSourceState Sql, ImmutableArray<SourceFileStorageBinding> Files);
public sealed record RestoredSourceObservation(DateTimeOffset ObservedAtUtc, RestoredSourceState State)
{
    /// <summary>Full observation digest for downstream signing; this method neither signs nor authorizes execution.</summary>
    public string ComputeSha256()
    {
        return ObservationDigest.Compute("RestoredSourceObservation.v1", this);
    }

    /// <summary>Compares every measured stable fact, excluding only observation freshness, not historical continuity.</summary>
    public string ComputeStableStateSha256()
    {
        return ObservationDigest.Compute("RestoredSourceStableState.v1", State);
    }
}

internal static class ObservationDigest
{
    internal static string Compute<T>(string domain, T value)
    {
        return Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes("Legacy.Maliev.DataMigration." + domain + "\n" + JsonSerializer.Serialize(value)))).ToLowerInvariant();
    }
}
