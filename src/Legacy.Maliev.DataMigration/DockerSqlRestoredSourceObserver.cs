using System.Collections.Immutable;
using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using static Legacy.Maliev.DataMigration.LocalDockerResourceObserver;

namespace Legacy.Maliev.DataMigration;

/// <summary>Current source state only. GUIDs and read-only flags do not prove absence of intervening writes or re-restores.</summary>
public sealed partial class DockerSqlRestoredSourceObserver
{
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly LocalDockerResourceObserver _docker;
    private readonly Func<string, CancellationToken, Task<SqlRestoredSourceState>> _sql;
    private readonly Func<DateTimeOffset> _clock;

    public DockerSqlRestoredSourceObserver(IReceiptAttestationTrustStore trust)
        : this(trust, new LocalDockerResourceObserver(), SqlServerSourceMetadataObserver.ObserveAsync, () => DateTimeOffset.UtcNow) { }

    internal DockerSqlRestoredSourceObserver(IReceiptAttestationTrustStore trust, LocalDockerResourceObserver docker,
        Func<string, CancellationToken, Task<SqlRestoredSourceState>> sql, Func<DateTimeOffset> clock)
    {
        _trust = trust;
        _docker = docker;
        _sql = sql;
        _clock = clock;
    }

    public async Task<RestoredSourceObservation> ObserveAsync(string connectionString, VerifiedRestoreReceipt receipt,
        FreshSchemaPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(plan);
        // The receipt is authenticated here; approval of the supplied plan is an admission-layer responsibility.
        // Neither expectation substitutes for the independent observations below.
        Require(VerifiedRestoreReceiptAttestation.Verify(receipt, _trust) && receipt.CleanupDisposition == RestoreCleanupDisposition.Pending,
            "restore_receipt");
        Require(ExactInventory(plan.Databases.Select(database => database.Database)), "plan_inventory");
        Require(VerifiedRestoreReceiptAttestation.TryCreatePayload(receipt, out byte[] receiptPayload), "restore_receipt");
        string receiptDigest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(receiptPayload)).ToLowerInvariant();
        string planDigest = SchemaPlanCanonicalizer.ComputeSha256(plan);
        (string connection, int port) = ValidateConnection(connectionString);
        string endpoint = "tcp:127.0.0.1," + port.ToString(CultureInfo.InvariantCulture);
        LocalDockerResourceState docker = await _docker.ObserveAsync(receipt.Resources.ContainerId, cancellationToken, receipt.Resources.SqlServerImageId).ConfigureAwait(false);
        ValidateRestoreBinding(docker, receipt.Resources, port);
        SqlRestoredSourceState sql = Normalize(await _sql(connection, cancellationToken).ConfigureAwait(false));
        ValidateSql(sql, docker, port);
        ImmutableArray<SourceFileStorageBinding> files = await ObserveFilesAsync(docker, sql, cancellationToken).ConfigureAwait(false);
        // No snapshot of the Docker daemon spans SQL calls. Repeat all facts and reject any visible transition.
        SqlRestoredSourceState repeatedSql = Normalize(await _sql(connection, cancellationToken).ConfigureAwait(false));
        Require(ObservationDigest.Compute("SqlSourceState.v1", sql) == ObservationDigest.Compute("SqlSourceState.v1", repeatedSql), "changed_sql_state");
        ImmutableArray<SourceFileStorageBinding> repeatedFiles = await ObserveFilesAsync(docker, repeatedSql, cancellationToken).ConfigureAwait(false);
        Require(ObservationDigest.Compute("SourceFiles.v1", files) == ObservationDigest.Compute("SourceFiles.v1", repeatedFiles), "changed_files");
        LocalDockerResourceState repeatedDocker = await _docker.ObserveAsync(receipt.Resources.ContainerId, cancellationToken, receipt.Resources.SqlServerImageId).ConfigureAwait(false);
        Require(ObservationDigest.Compute("DockerResource.v1", docker) == ObservationDigest.Compute("DockerResource.v1", repeatedDocker), "changed_docker_state");
        DateTimeOffset now = _clock();
        Require(now.Offset == TimeSpan.Zero && now >= receipt.RestoredAtUtc, "freshness");
        return new(now, new(receiptDigest, planDigest, DatabaseInventory.InventorySha256, endpoint, docker, sql, files));
    }

    private async Task<ImmutableArray<SourceFileStorageBinding>> ObserveFilesAsync(LocalDockerResourceState docker, SqlRestoredSourceState sql, CancellationToken token)
    {
        var result = ImmutableArray.CreateBuilder<SourceFileStorageBinding>();
        Require(sql.Files.All(file => IsAbsoluteLinuxPath(file.PhysicalName) && file.Type is 0 or 1), "data_file");
        ImmutableArray<FileSystemObjectIdentity> identities = await _docker.StatManyAsync(docker.DockerHost, docker.ContainerId,
            sql.Files.Select(file => file.PhysicalName).ToArray(), token).ConfigureAwait(false);
        for (int index = 0; index < sql.Files.Length; index++)
        {
            SqlObservedFile file = sql.Files[index];
            DockerObservedMount? mount = docker.Mounts.Where(mount => file.PhysicalName.StartsWith(mount.Destination + "/", StringComparison.Ordinal))
                .OrderByDescending(mount => mount.Destination.Length).FirstOrDefault();
            string storage = mount?.Destination ?? "/";
            FileSystemObjectIdentity identity = identities[index];
            Require(identity.Device == (mount?.FileSystemIdentity ?? docker.Root).Device, "data_file_storage");
            result.Add(new(file, storage, identity));
        }
        return result.ToImmutable();
    }

    private static void ValidateRestoreBinding(LocalDockerResourceState docker, VerifiedRestoreResourceEvidence expected, int port)
    {
        Require(docker.ContainerId == expected.ContainerId && docker.ContainerName == expected.ContainerName && docker.RunBinding == expected.RunBinding &&
            docker.Image.Id == expected.SqlServerImageId, "restore_resource");
        string repositoryDigest = "mcr.microsoft.com/mssql/server" + expected.SqlServerImage[expected.SqlServerImage.IndexOf("@sha256:", StringComparison.Ordinal)..];
        Require(docker.Image.RepoDigests.Contains(repositoryDigest, StringComparer.Ordinal), "restore_image");
        DockerObservedMount? backup = docker.Mounts.SingleOrDefault(mount => mount.Destination == expected.MountPath);
        Require(backup is not null && !backup.ReadWrite && expected.MountReadOnly && backup.Name == expected.VolumeName && backup.Volume.Name == expected.VolumeId &&
            backup.Volume.RunBinding == expected.RunBinding && backup.Volume.VolumeBinding == expected.VolumeBinding && backup.Volume.Fingerprint == expected.VolumeFingerprint,
            "backup_volume");
        Require(docker.Ports.Count(binding => binding.HostAddress == "127.0.0.1" && binding.HostPort == port && binding.ContainerPort == 1433) == 1,
            "published_endpoint");
    }

    private static void ValidateSql(SqlRestoredSourceState sql, LocalDockerResourceState docker, int port)
    {
        Require(sql.CompleteMetadataVisibility && ExactInventory(sql.Databases.Select(database => database.Name)), "sql_inventory");
        Require(sql.Databases.Select(database => database.DatabaseId).Distinct().Count() == sql.Databases.Length &&
            sql.Databases.All(database => database.DatabaseId > 4 && database.DatabaseGuid != Guid.Empty && database.ReadOnly &&
                database.SnapshotIsolationState == 1 && database.State == 0), "database_flags");
        Require(sql.ProductMajorVersion == "16" && sql.MachineName == docker.Hostname && sql.ServerName == docker.Hostname &&
            docker.Networks.Any(network => network.Address == sql.LocalAddress) &&
            docker.Ports.Any(binding => binding.HostAddress == "127.0.0.1" && binding.HostPort == port && binding.ContainerPort == sql.LocalPort), "sql_endpoint");
        Require(sql.Databases.All(database => sql.Files.Any(file => file.DatabaseId == database.DatabaseId && file.Type == 0)) &&
            sql.Files.All(file => sql.Databases.Any(database => database.DatabaseId == file.DatabaseId) && file.FileId > 0) &&
            sql.Files.Select(file => (file.DatabaseId, file.FileId)).Distinct().Count() == sql.Files.Length &&
            sql.Files.Select(file => file.PhysicalName).Distinct(StringComparer.Ordinal).Count() == sql.Files.Length, "data_files");
    }

    private static bool ExactInventory(IEnumerable<string> names)
    {
        return names.Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal);
    }

    private static SqlRestoredSourceState Normalize(SqlRestoredSourceState sql)
    {
        return sql with
        {
            Databases = sql.Databases.OrderBy(database => database.Name, StringComparer.Ordinal).ToImmutableArray(),
            Files = sql.Files.OrderBy(file => file.DatabaseId).ThenBy(file => file.FileId).ToImmutableArray(),
        };
    }

    private static (string Connection, int Port) ValidateConnection(string connectionString)
    {
        try
        {
            var builder = new SqlConnectionStringBuilder(connectionString);
            Match endpoint = LoopbackEndpoint().Match(builder.DataSource);
            Require(endpoint.Success && string.IsNullOrEmpty(builder.FailoverPartner) && !builder.UserInstance &&
                string.IsNullOrEmpty(builder.AttachDBFilename) && !builder.MultiSubnetFailover, "configured_endpoint");
            int port = int.Parse(endpoint.Groups[1].Value, CultureInfo.InvariantCulture);
            Require(port is > 0 and <= 65535, "configured_endpoint");
            builder.DataSource = "tcp:127.0.0.1," + port.ToString(CultureInfo.InvariantCulture);
            builder.InitialCatalog = "master";
            builder.Pooling = false;
            builder.Enlist = false;
            builder.ConnectRetryCount = 0;
            builder.ApplicationIntent = ApplicationIntent.ReadOnly;
            return (builder.ConnectionString, port);
        }
        catch (ArgumentException) { throw Reject("configured_endpoint"); }
    }
    [GeneratedRegex("^(?:tcp:)?127\\.0\\.0\\.1,([0-9]{1,5})$", RegexOptions.CultureInvariant)] private static partial Regex LoopbackEndpoint();
}
