using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
using DotNet.Testcontainers.Volumes;
using Microsoft.Data.SqlClient;
using Testcontainers.MsSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class RestoredSourceObserverIntegrationTests
{
    [SqlServerIntegrationFact]
    public async Task Observe_DisposableSqlContainer_BindsActualEndpointStorageAndFlags()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        CancellationToken token = timeout.Token;
        string name = "source-observer-" + Guid.NewGuid().ToString("N");
        await using IVolume backup = new VolumeBuilder().WithName(name + "-backup")
            .WithLabel("com.maliev.legacy.restore-run", "run-1")
            .WithLabel("com.maliev.legacy.restore-volume-binding", "backup-binding")
            .WithLabel("com.maliev.legacy.restore-volume-fingerprint", SourceObservationFixture.Fingerprint).Build();
        await using IVolume data = new VolumeBuilder().WithName(name + "-data").Build();
        await backup.CreateAsync(token);
        await data.CreateAsync(token);
        await using MsSqlContainer container = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04")
            .WithName(name).WithLabel("com.maliev.legacy.restore-run", "run-1")
            .WithVolumeMount(backup, "/backup", AccessMode.ReadOnly)
            .WithVolumeMount(data, "/var/opt/mssql", AccessMode.ReadWrite)
            .WithCreateParameterModifier(parameters =>
            {
                foreach (IList<Docker.DotNet.Models.PortBinding> bindings in parameters.HostConfig!.PortBindings!.Values)
                {
                    foreach (Docker.DotNet.Models.PortBinding binding in bindings) { binding.HostIP = "127.0.0.1"; }
                }
            }).Build();
        await container.StartAsync(token);
        string connectionString = container.GetConnectionString();
        await using (var connection = new SqlConnection(connectionString))
        {
            await connection.OpenAsync(token);
            foreach (string database in DatabaseInventory.ActiveDatabases)
            {
                await using var command = new SqlCommand($"CREATE DATABASE [{database}]; ALTER DATABASE [{database}] SET ALLOW_SNAPSHOT_ISOLATION ON; ALTER DATABASE [{database}] SET READ_ONLY;", connection) { CommandTimeout = 60 };
                _ = await command.ExecuteNonQueryAsync(token);
            }
        }
        var docker = new LocalDockerResourceObserver();
        LocalDockerResourceState resources = await docker.ObserveAsync(container.Id, token);
        using var fixture = new SourceObservationFixture { Now = DateTimeOffset.UtcNow };
        string pinnedImage = "mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04" + resources.Image.RepoDigests[0][resources.Image.RepoDigests[0].IndexOf("@sha256:", StringComparison.Ordinal)..];
        fixture.Receipt = fixture.Sign(fixture.Receipt with
        {
            Resources = fixture.Receipt.Resources with
            {
                ContainerId = container.Id,
                ContainerName = name,
                VolumeName = backup.Name,
                VolumeId = backup.Name,
                SqlServerImage = pinnedImage,
                SqlServerImageId = resources.Image.Id,
            },
        });
        DockerSqlRestoredSourceObserver observer = fixture.CreateProductionObserver();
        RestoredSourceObservation first = await observer.ObserveAsync(connectionString, fixture.Receipt, fixture.Plan, token);
        RestoredSourceObservation second = await observer.ObserveAsync(connectionString, fixture.Receipt, fixture.Plan, token);
        Assert.Equal(first.ComputeStableStateSha256(), second.ComputeStableStateSha256());
        Assert.NotEqual(first.ComputeSha256(), second.ComputeSha256());
        Assert.Equal(container.Id, first.State.Docker.ContainerId);
        Assert.All(first.State.Sql.Databases, database => Assert.True(database.ReadOnly && database.SnapshotIsolationState == 1));
        Assert.All(first.State.Files, file => Assert.Equal("/var/opt/mssql", file.StoragePath));
        Assert.False(Assert.Single(first.State.Docker.Mounts.Where(mount => mount.Destination == "/backup")).ReadWrite);
        Assert.True(Assert.Single(first.State.Docker.Mounts.Where(mount => mount.Destination == "/var/opt/mssql")).ReadWrite);
        string databaseName = DatabaseInventory.ActiveDatabases[0];
        await using (var connection = new SqlConnection(connectionString))
        {
            await connection.OpenAsync(token);
            await using var command = new SqlCommand($"ALTER DATABASE [{databaseName}] SET READ_WRITE;", connection);
            _ = await command.ExecuteNonQueryAsync(token);
        }
        MigrationExecutionException rejected = await Assert.ThrowsAsync<MigrationExecutionException>(() => observer.ObserveAsync(connectionString, fixture.Receipt, fixture.Plan, token));
        Assert.Equal("source_observation_database_flags", rejected.Code);
    }
}
