using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class RestoredSourceObserverTests
{
    [Fact]
    public async Task Observe_All48FilesTwice_ChecksEveryPathInBothPassesWithBoundedProcesses()
    {
        using var fixture = new SourceObservationFixture();
        fixture.Sql = fixture.Sql with
        {
            Files = fixture.Sql.Files.SelectMany(file => new[] { file, file with { FileId = 2, Type = 1, PhysicalName = file.PhysicalName + ".ldf" } }).ToImmutableArray()
        };
        RestoredSourceObservation first = await fixture.ObserveAsync();
        fixture.Now = fixture.Now.AddSeconds(1);
        RestoredSourceObservation second = await fixture.ObserveAsync();
        string[] paths = fixture.Sql.Files.Select(file => file.PhysicalName).ToArray();
        IReadOnlyList<string>[] commands = fixture.Docker.Commands.Where(command => command.Contains("exec") && command.Any(paths.Contains)).ToArray();
        Assert.Equal(48, paths.Length);
        foreach (string path in paths)
        {
            Assert.Equal(4, commands.Count(command => command.Contains("readlink") && command.Contains(path)));
            Assert.Equal(4, commands.Count(command => command.Contains("stat") && command.Contains(path)));
        }
        Assert.Equal(paths, first.State.Files.Select(file => file.File.PhysicalName));
        Assert.All(first.State.Files, file => Assert.Equal(new FileSystemObjectIdentity("7", "903", "regular file"), file.FileSystemIdentity));
        var legacyEquivalent = first with { State = first.State with { Files = fixture.Sql.Files.Select(file => new SourceFileStorageBinding(file, "/", new("7", "903", "regular file"))).ToImmutableArray() } };
        Assert.Equal(legacyEquivalent.ComputeSha256(), first.ComputeSha256());
        Assert.Equal(first.ComputeStableStateSha256(), second.ComputeStableStateSha256());
        Assert.NotEqual(first.ComputeSha256(), second.ComputeSha256());
        Assert.Equal(16, commands.Length);
    }

    [Theory]
    [InlineData("device", "source_observation_data_file_storage")]
    [InlineData("second-pass", "source_observation_changed_files")]
    public async Task Observe_BatchedFileIdentityViolation_RejectsCompleteObservation(string failure, string code)
    {
        using var fixture = new SourceObservationFixture();
        int statPasses = 0;
        fixture.Docker.BatchResult = (args, output) =>
        {
            if (args.Contains("stat"))
            {
                statPasses++;
                string[] fields = output.Split('\0');
                if (failure == "device") { fields[1] = "8"; }
                else if (statPasses == 2) { fields[2] = "904"; }
                output = string.Join('\0', fields);
            }
            return new(0, output, "");
        };
        var error = await Assert.ThrowsAsync<MigrationExecutionException>(fixture.ObserveAsync);
        Assert.Equal(code, error.Code);
        Assert.Equal(failure == "device" ? 1 : 2, statPasses);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Observe_InvalidLastFile_RejectsBeforeAnySqlFileProcess(bool invalidType)
    {
        using var fixture = new SourceObservationFixture();
        SqlObservedFile last = fixture.Sql.Files[^1];
        fixture.Sql = fixture.Sql with { Files = fixture.Sql.Files.Add(last with { FileId = 2, Type = invalidType ? 2 : 1, PhysicalName = invalidType ? "/data/invalid" : "/data/../invalid" }) };
        var error = await Assert.ThrowsAsync<MigrationExecutionException>(fixture.ObserveAsync);
        Assert.Equal("source_observation_data_file", error.Code);
        Assert.DoesNotContain(fixture.Docker.Commands, command => command.Any(arg => fixture.Sql.Files.Any(file => file.PhysicalName == arg)));
    }

    [Fact]
    public async Task Observe_BatchedFiles_PreservesMountVersusRootBindings()
    {
        using var fixture = new SourceObservationFixture();
        fixture.Sql = fixture.Sql with { Files = fixture.Sql.Files.SetItem(0, fixture.Sql.Files[0] with { PhysicalName = "/backup/data.mdf" }) };
        RestoredSourceObservation result = await fixture.ObserveAsync();
        Assert.Equal("/backup", result.State.Files[0].StoragePath);
        Assert.All(result.State.Files.Skip(1), file => Assert.Equal("/", file.StoragePath));
    }

    [Fact]
    public async Task Observe_ExactReceiptInventoryAndResources_BindsFreshAndStableDigests()
    {
        using var fixture = new SourceObservationFixture();
        RestoredSourceObservation first = await fixture.ObserveAsync();
        fixture.Now = fixture.Now.AddSeconds(1);
        RestoredSourceObservation second = await fixture.ObserveAsync();
        Assert.NotEqual(first.ComputeSha256(), second.ComputeSha256());
        Assert.Equal(first.ComputeStableStateSha256(), second.ComputeStableStateSha256());
        Assert.NotEqual(first.ComputeSha256(), first.ComputeStableStateSha256());
        Assert.Equal(DatabaseInventory.ActiveDatabases, first.State.Sql.Databases.Select(item => item.Name));
        Assert.All(first.State.Files, file => Assert.Equal("/", file.StoragePath));
        Assert.Equal("901", first.State.Docker.Root.Inode);
    }

    [Theory]
    [InlineData("untrusted")]
    [InlineData("removed")]
    [InlineData("plan-inventory")]
    [InlineData("database-name")]
    [InlineData("database-extra")]
    [InlineData("database-guid")]
    [InlineData("database-readonly")]
    [InlineData("database-snapshot")]
    [InlineData("database-offline")]
    [InlineData("hidden-metadata")]
    [InlineData("sql-ip")]
    [InlineData("sql-port")]
    [InlineData("sql-host")]
    [InlineData("sql-version")]
    [InlineData("file-missing")]
    [InlineData("endpoint")]
    [InlineData("docker-changed")]
    [InlineData("network-mode-changed")]
    [InlineData("mount-properties-changed")]
    [InlineData("restore-image")]
    [InlineData("restore-image-digest")]
    [InlineData("restore-container-name")]
    [InlineData("backup-volume-id")]
    [InlineData("backup-fingerprint")]
    [InlineData("backup-mount")]
    public async Task Observe_UnverifiableBoundary_Rejects(string failure)
    {
        using var fixture = new SourceObservationFixture();
        switch (failure)
        {
            case "untrusted": fixture.Receipt = fixture.Receipt with { AttestationSignature = "bad" }; break;
            case "removed": fixture.Receipt = fixture.Sign(fixture.Receipt with { CleanupDisposition = RestoreCleanupDisposition.Removed, CleanedAtUtc = fixture.Now }); break;
            case "plan-inventory": fixture.Plan = fixture.Plan with { Databases = fixture.Plan.Databases.Skip(1).ToArray() }; break;
            case "database-name": fixture.Sql = fixture.Sql with { Databases = fixture.Sql.Databases.SetItem(0, fixture.Sql.Databases[0] with { Name = "wrong" }) }; break;
            case "database-extra": fixture.Sql = fixture.Sql with { Databases = fixture.Sql.Databases.Add(fixture.Sql.Databases[0] with { Name = "extra" }) }; break;
            case "database-guid": fixture.Sql = fixture.Sql with { Databases = fixture.Sql.Databases.SetItem(0, fixture.Sql.Databases[0] with { DatabaseGuid = Guid.Empty }) }; break;
            case "database-readonly": fixture.Sql = fixture.Sql with { Databases = fixture.Sql.Databases.SetItem(0, fixture.Sql.Databases[0] with { ReadOnly = false }) }; break;
            case "database-snapshot": fixture.Sql = fixture.Sql with { Databases = fixture.Sql.Databases.SetItem(0, fixture.Sql.Databases[0] with { SnapshotIsolationState = 0 }) }; break;
            case "database-offline": fixture.Sql = fixture.Sql with { Databases = fixture.Sql.Databases.SetItem(0, fixture.Sql.Databases[0] with { State = 6 }) }; break;
            case "hidden-metadata": fixture.Sql = fixture.Sql with { CompleteMetadataVisibility = false }; break;
            case "sql-ip": fixture.Sql = fixture.Sql with { LocalAddress = "172.18.0.9" }; break;
            case "sql-port": fixture.Sql = fixture.Sql with { LocalPort = 1444 }; break;
            case "sql-host": fixture.Sql = fixture.Sql with { MachineName = "other" }; break;
            case "sql-version": fixture.Sql = fixture.Sql with { ProductMajorVersion = "17" }; break;
            case "file-missing": fixture.Sql = fixture.Sql with { Files = [] }; break;
            case "endpoint": fixture.Connection = "Server=remote.example,15433;User ID=sa;Pass" + "word=do-not-log;TrustServerCertificate=true"; break;
            case "docker-changed": fixture.Docker.ChangeOnRepeat = true; break;
            case "network-mode-changed": fixture.Docker.Failure = "network-mode-changed"; break;
            case "mount-properties-changed": fixture.Docker.Failure = "mount-properties-changed"; break;
            case "restore-image": fixture.Receipt = fixture.Sign(fixture.Receipt with { Resources = fixture.Receipt.Resources with { SqlServerImageId = "sha256:" + new string('b', 64) } }); break;
            case "restore-image-digest": fixture.Receipt = fixture.Sign(fixture.Receipt with { Resources = fixture.Receipt.Resources with { SqlServerImage = "mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04@sha256:" + new string('b', 64) } }); break;
            case "restore-container-name": fixture.Receipt = fixture.Sign(fixture.Receipt with { Resources = fixture.Receipt.Resources with { ContainerName = "other" } }); break;
            case "backup-volume-id": fixture.Receipt = fixture.Sign(fixture.Receipt with { Resources = fixture.Receipt.Resources with { VolumeId = "other" } }); break;
            case "backup-fingerprint": fixture.Receipt = fixture.Sign(fixture.Receipt with { Resources = fixture.Receipt.Resources with { VolumeFingerprint = new string('a', 64) } }); break;
            case "backup-mount": fixture.Receipt = fixture.Sign(fixture.Receipt with { Resources = fixture.Receipt.Resources with { MountPath = "/elsewhere" } }); break;
            default:
                break;
        }
        MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(fixture.ObserveAsync);
        Assert.StartsWith("source_observation_", error.Code);
        Assert.DoesNotContain("do-not-log", error.ToString());
        if (failure == "restore-image") { Assert.DoesNotContain(fixture.Docker.Commands, command => command.Contains("exec")); }
    }

    [Fact]
    public async Task StableDigest_EveryMeasuredScalarExceptFreshness_AffectsComparison()
    {
        using var fixture = new SourceObservationFixture();
        RestoredSourceObservation observation = await fixture.ObserveAsync();
        JsonNode json = JsonSerializer.SerializeToNode(observation.State)!;
        foreach (string[] path in ScalarPaths(json, []))
        {
            JsonNode altered = json.DeepClone();
            JsonNode parent = altered;
            foreach (string segment in path[..^1]) { parent = parent is JsonArray array ? array[int.Parse(segment, System.Globalization.CultureInfo.InvariantCulture)]! : parent[segment]!; }
            string last = path[^1];
            JsonNode value = parent is JsonArray values ? values[int.Parse(last, System.Globalization.CultureInfo.InvariantCulture)]! : parent[last]!;
            JsonValueKind kind = value.GetValueKind();
            JsonNode replacement = kind == JsonValueKind.True ? JsonValue.Create(false)! :
                kind == JsonValueKind.False ? JsonValue.Create(true)! :
                kind == JsonValueKind.Number ? JsonValue.Create(value.GetValue<int>() + 1)! :
                JsonValue.Create(value.GetValue<string>() == Guid.Empty.ToString() ? Guid.NewGuid().ToString() : ChangeString(value.GetValue<string>()))!;
            if (parent is JsonArray arrayParent) { arrayParent[int.Parse(last, System.Globalization.CultureInfo.InvariantCulture)] = replacement; } else { parent[last] = replacement; }
            RestoredSourceState state = altered.Deserialize<RestoredSourceState>()!;
            var changed = new RestoredSourceObservation(observation.ObservedAtUtc, state);
            Assert.NotEqual(observation.ComputeStableStateSha256(), changed.ComputeStableStateSha256());
        }
    }

    private static string ChangeString(string value)
    {
        return Guid.TryParse(value, out _) ? Guid.Empty.ToString() : value + "changed";
    }

    private static IEnumerable<string[]> ScalarPaths(JsonNode node, string[] path)
    {
        if (node is JsonObject obj)
        {
            foreach ((string name, JsonNode? child) in obj) { if (child is not null) { foreach (string[] result in ScalarPaths(child, [.. path, name])) { yield return result; } } }
        }
        else if (node is JsonArray array)
        {
            for (int index = 0; index < array.Count; index++) { foreach (string[] result in ScalarPaths(array[index]!, [.. path, index.ToString(System.Globalization.CultureInfo.InvariantCulture)])) { yield return result; } }
        }
        else { yield return path; }
    }
}

internal sealed class SourceObservationFixture : IDisposable
{
    internal const string ContainerId = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    internal const string ImageId = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    internal const string Fingerprint = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    internal DateTimeOffset Now = DateTimeOffset.Parse("2026-09-02T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
    internal string Connection = "Server=127.0.0.1,15433;User ID=sa;Pass" + "word=do-not-log;TrustServerCertificate=true";
    internal VerifiedRestoreReceipt Receipt;
    internal FreshSchemaPlan Plan;
    internal SqlRestoredSourceState Sql;
    internal readonly FakeDockerProcess Docker = new();

    internal SourceObservationFixture()
    {
        Receipt = Sign(new("1.0", Now, DatabaseInventory.InventorySha256, new string('d', 64),
            new("mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04@sha256:" + new string('a', 64),
                ImageId, ContainerId, "restore-test", "run-1", "backup-volume", "backup-volume", "backup-binding", Fingerprint,
                "/backup", true, "alpine:3.20@sha256:" + new string('b', 64), "16"),
            DatabaseInventory.ActiveDatabases.Select(name => new VerifiedRestoreArtifactEvidence(name, 1, new string('d', 64), 1, new string('d', 64), true, true, true)).ToArray(),
            RestoreCleanupDisposition.Pending, null, "test", null));
        Plan = new("2.0", Now, new string('a', 40), DatabaseInventory.ActiveDatabases.Select(name =>
            new DatabaseSchemaPlan(name, "v1", new string('a', 64), new string('b', 64), [])).ToArray());
        Sql = new("172.18.0.2", 1433, "restore-host", "restore-host", "16", true,
            DatabaseInventory.ActiveDatabases.Select((name, index) => new SqlObservedDatabase(index + 5, name, Guid.NewGuid(), true, 1, 0)).ToImmutableArray(),
            DatabaseInventory.ActiveDatabases.Select((name, index) => new SqlObservedFile(index + 5, 1, 0, $"/var/opt/mssql/data/{name}.mdf")).ToImmutableArray());
    }

    internal VerifiedRestoreReceipt Sign(VerifiedRestoreReceipt receipt)
    {
        return VerifiedRestoreReceiptAttestation.Sign(receipt, _key);
    }

    internal DockerSqlRestoredSourceObserver CreateProductionObserver()
    {
        return new(new ReceiptAttestationTrustStore([new("test", _key.ExportSubjectPublicKeyInfo())]));
    }

    internal Task<RestoredSourceObservation> ObserveAsync()
    {
        return new DockerSqlRestoredSourceObserver(
            new ReceiptAttestationTrustStore([new("test", _key.ExportSubjectPublicKeyInfo())]),
            new LocalDockerResourceObserver(Docker), (_, _) => Task.FromResult(Sql), () => Now)
            .ObserveAsync(Connection, Receipt, Plan, CancellationToken.None);
    }

    public void Dispose()
    {
        _key.Dispose();
    }
}
