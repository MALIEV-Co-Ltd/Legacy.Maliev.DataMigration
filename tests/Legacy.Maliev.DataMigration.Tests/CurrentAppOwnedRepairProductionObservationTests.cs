using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAppOwnedRepairProductionObservationTests
{
    [WindowsLocalRunTheory]
    [InlineData(null)]
    [MemberData(nameof(RuntimeFieldNames))]
    public async Task Console_cloud_boundary_tolerates_only_later_resource_version_changes(string? changed)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await using var tls = new HostTlsTestServer { ResponseBody = ClusterJson, ResponseStatusCode = 200 };
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Path.Combine(tls.Root, "repair-custody"));
        string root = authority.Binding.ArtifactRootCanonicalPath;
        string token = Path.Combine(root, "kubernetes-token.txt"), ca = Path.Combine(root, "kubernetes-ca.pem");
        File.Copy(tls.TokenPath, token);
        File.Copy(tls.CaPath, ca);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        using JsonDocument cluster = JsonDocument.Parse(ClusterJson);
        CloudNativePgTargetObservation observed = CloudNativePgTargetObservationParser.Parse(cluster.RootElement,
            "maliev-legacy", "legacy-postgres-main");
        CurrentAppOwnedDatabaseSnapshot[] baseline = [.. DatabaseInventory.ActiveDatabases.Select(database =>
            new CurrentAppOwnedDatabaseSnapshot(database, [], [], []))];
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string binding = authority.Binding.ComputeSha256();
        var scope = new CurrentAppOwnedRepairScope(Guid.NewGuid(), CurrentAppOwnedRepairOperation.CreateEightTables,
            new string('a', 40), new string('b', 64), new string('c', 64),
            CurrentAppOwnedRepairManifest.OperationSha256(CurrentAppOwnedRepairOperation.CreateEightTables),
            new(DeltaTargetAuthorityKind.ProductionCloudNativePg, "gke://maliev-website/native-observation-fixture", new string('d', 64)),
            "maliev-legacy", "legacy-postgres-main", "cnpg:uid-a:7", new string('e', 64), binding,
            CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.CreateEightTables)
                .ToDictionary(database => database, _ => new string('f', 64), StringComparer.Ordinal),
            CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(baseline)), new string('a', 64),
            new string('b', 64), new string('c', 64),
            new("fixture", "legacy-maliev-current-app-owned-eight-v1:" + binding, now, now.AddMinutes(30),
                now, now, new string('d', 64), new string('e', 64), "/fixture/pg_hba.conf"));

        // The malformed ordinary connection is reached only after successful cloud comparison.
        // It is a boundary sentinel, not successful admission; no PostgreSQL connection is opened.
        CloudNativePgTargetObservation pin = observed with { ResourceVersion = "previous-api-revision" };
        if (changed is not null) { pin = Mutate(pin, changed); }
        var target = new CurrentAppOwnedRepairTargetPins(null, null, null, null, "/fixture/pg_hba.conf", null,
            new(tls.Address, token, ca), pin);
        CurrentAppOwnedRepairScope bound = scope with
        { TargetObservationSha256 = CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(target)) };
        using var environment = new CurrentAppOwnedRepairConsoleEnvironment(authority, files, target,
            new Npgsql.NpgsqlConnectionStringBuilder
            {
                Host = "127.0.0.1",
                Port = 5432,
                Username = "fixture",
                Password = Guid.NewGuid().ToString("N"),
                Pooling = false,
            }.ConnectionString,
            "unsupported-observation-test-key=value", baseline,
            CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerColumnsV1),
            CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2), bound);
        int requests = tls.Requests;
        if (changed is null)
        {
            _ = await Assert.ThrowsAsync<ArgumentException>(() => environment.RequireResourceAndCustodyAsync(bound, timeout.Token));
        }
        else
        {
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => environment.RequireResourceAndCustodyAsync(bound, timeout.Token));
        }
        Assert.Equal(requests + 1, tls.Requests);
        files.Require();
    }

    [Fact]
    public void Stable_double_read_still_rejects_resource_version_drift_within_observation()
    {
        string stableShape = ClusterJson.Replace(", \"observedGeneration\": 7", string.Empty, StringComparison.Ordinal);
        using JsonDocument first = JsonDocument.Parse(stableShape);
        using JsonDocument second = JsonDocument.Parse(stableShape.Replace("\"resourceVersion\": \"100\"",
            "\"resourceVersion\": \"101\"", StringComparison.Ordinal));
        RuntimeAttestationException failure = Assert.Throws<RuntimeAttestationException>(() =>
            CloudNativePgTargetObservationParser.ParseStableDoubleRead(first.RootElement, second.RootElement,
                "maliev-legacy", "legacy-postgres-main"));
        Assert.Equal("runtime_target_drift", failure.Code);
    }

    public static TheoryData<string?> RuntimeFieldNames
    {
        get
        {
            var cases = new TheoryData<string?>();
            foreach (PropertyInfo property in RuntimeFields()) { cases.Add(property.Name); }
            return cases;
        }
    }

    private static IEnumerable<PropertyInfo> RuntimeFields()
    {
        // Include future init properties automatically; computed health properties are excluded.
        return typeof(CloudNativePgTargetObservation).GetProperties().Where(x => x.SetMethod is not null &&
            x.Name != nameof(CloudNativePgTargetObservation.ResourceVersion));
    }

    private static CloudNativePgTargetObservation Mutate(CloudNativePgTargetObservation value, string property)
    {
        JsonObject fields = JsonSerializer.SerializeToNode(value)!.AsObject();
        Type type = typeof(CloudNativePgTargetObservation).GetProperty(property)!.PropertyType;
        fields[property] = type == typeof(string)
            ? JsonValue.Create(fields[property]!.GetValue<string>() + "-changed")
            : type == typeof(bool)
                ? JsonValue.Create(!fields[property]!.GetValue<bool>())
                : type == typeof(int)
                    ? JsonValue.Create(fields[property]!.GetValue<int>() + 1)
                    : type == typeof(long)
                        ? JsonValue.Create(fields[property]!.GetValue<long>() + 1)
                        : throw new InvalidOperationException("Add an exact mutation for the new observation property type.");
        return fields.Deserialize<CloudNativePgTargetObservation>()!;
    }

    private const string ClusterJson = """
        {
          "metadata": { "name": "legacy-postgres-main", "namespace": "maliev-legacy", "uid": "uid-a", "resourceVersion": "100", "generation": 7 },
          "spec": { "instances": 2 },
          "status": {
            "phase": "Cluster in healthy state", "instances": 2, "readyInstances": 2, "observedGeneration": 7,
            "currentPrimary": "legacy-postgres-main-1", "targetPrimary": "legacy-postgres-main-1",
            "systemID": "123456789", "pvcCount": 2,
            "instanceNames": ["legacy-postgres-main-1", "legacy-postgres-main-2"],
            "instancesStatus": { "healthy": ["legacy-postgres-main-1", "legacy-postgres-main-2"] },
            "healthyPVC": ["legacy-postgres-main-1", "legacy-postgres-main-2"],
            "danglingPVC": [], "initializingPVC": [], "resizingPVC": [], "unusablePVC": [],
            "conditions": [
              { "type": "Ready", "status": "True", "reason": "ClusterIsReady" },
              { "type": "ConsistentSystemID", "status": "True", "reason": "Unique" },
              { "type": "ContinuousArchiving", "status": "True", "reason": "ContinuousArchivingSuccess" },
              { "type": "LastBackupSucceeded", "status": "True", "reason": "LastBackupSucceeded" }
            ]
          }
        }
        """;
}
