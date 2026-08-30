using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class RuntimeAttestationTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"legacy-runtime-{Guid.NewGuid():N}");

    [Fact]
    public async Task Runner_manifest_is_deterministic_and_binds_every_published_file()
    {
        _ = Directory.CreateDirectory(_root);
        await File.WriteAllTextAsync(Path.Combine(_root, "runner.dll"), "runner-v1");
        _ = Directory.CreateDirectory(Path.Combine(_root, "runtimes"));
        await File.WriteAllTextAsync(Path.Combine(_root, "runtimes", "dependency.dll"), "dependency-v1");

        RunnerArtifactManifest first = await RunnerArtifactManifestMeasurer.MeasureAsync(_root, CancellationToken.None);
        RunnerArtifactManifest second = await RunnerArtifactManifestMeasurer.MeasureAsync(_root, CancellationToken.None);

        Assert.Equal(first.ManifestSha256, second.ManifestSha256);
        Assert.Equal(["runner.dll", "runtimes/dependency.dll"], first.Files.Select(file => file.RelativePath));

        await File.WriteAllTextAsync(Path.Combine(_root, "runtimes", "dependency.dll"), "dependency-v2");
        RunnerArtifactManifest changed = await RunnerArtifactManifestMeasurer.MeasureAsync(_root, CancellationToken.None);
        Assert.NotEqual(first.ManifestSha256, changed.ManifestSha256);
    }

    [Fact]
    public async Task Runner_manifest_rejects_a_symbolic_link_inside_the_publication()
    {
        _ = Directory.CreateDirectory(_root);
        string external = Path.Combine(Path.GetTempPath(), $"legacy-runtime-external-{Guid.NewGuid():N}");
        _ = Directory.CreateDirectory(external);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(_root, "runner.dll"), "runner-v1");
            await File.WriteAllTextAsync(Path.Combine(external, "injected.dll"), "injected");
            try
            {
                _ = Directory.CreateSymbolicLink(Path.Combine(_root, "linked-runtime"), external);
            }
            catch (UnauthorizedAccessException) when (OperatingSystem.IsWindows())
            {
                return; // Windows hosts without Developer Mode cannot construct this adversarial fixture.
            }

            RuntimeAttestationException exception = await Assert.ThrowsAsync<RuntimeAttestationException>(() =>
                RunnerArtifactManifestMeasurer.MeasureAsync(_root, CancellationToken.None));

            Assert.Equal("runtime_runner_link_forbidden", exception.Code);
        }
        finally
        {
            if (Directory.Exists(external))
            {
                Directory.Delete(external, recursive: true);
            }
        }
    }

    [Theory]
    [InlineData("Failed", 2, 2, "runtime_target_unhealthy")]
    [InlineData("Cluster in healthy state", 2, 1, "runtime_target_unhealthy")]
    public void Target_observation_rejects_an_unhealthy_cluster(
        string phase,
        int instances,
        int readyInstances,
        string expectedCode)
    {
        using JsonDocument document = JsonDocument.Parse(ClusterJson(phase, instances, readyInstances));

        RuntimeAttestationException exception = Assert.Throws<RuntimeAttestationException>(() =>
            CloudNativePgTargetObservationParser.Parse(document.RootElement, "maliev-legacy", "legacy-postgres-main"));

        Assert.Equal(expectedCode, exception.Code);
    }

    [Fact]
    public async Task Verifier_rejects_target_replacement_or_resource_version_drift()
    {
        _ = Directory.CreateDirectory(_root);
        await File.WriteAllTextAsync(Path.Combine(_root, "runner.dll"), "runner-v1");
        RunnerArtifactManifest manifest = await RunnerArtifactManifestMeasurer.MeasureAsync(_root, CancellationToken.None);
        CloudNativePgTargetObservation authorized = HealthyObservation("uid-a", "100");
        var authorization = new ExecutionAuthorizationReceipt(
            "2.1", Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(30),
            new string('a', 40), new string('b', 64), new string('c', 64), manifest.ManifestSha256,
            authorized.Generation.ToString(System.Globalization.CultureInfo.InvariantCulture), DatabaseInventory.ActiveDatabases,
            "shadow-only", "auth-key", "signature")
        { TargetObservation = authorized };
        var verifier = new RuntimeAttestationVerifier(
            _root,
            new StubObserver(HealthyObservation("uid-b", "101")),
            "maliev-legacy",
            "legacy-postgres-main");

        RuntimeAttestationException exception = await Assert.ThrowsAsync<RuntimeAttestationException>(() =>
            verifier.VerifyAsync(authorization, CancellationToken.None));

        Assert.Equal("runtime_target_drift", exception.Code);
    }

    [Fact]
    public void Authorization_payload_binds_the_complete_target_observation()
    {
        CloudNativePgTargetObservation target = HealthyObservation("uid-a", "100");
        var authorization = new ExecutionAuthorizationReceipt(
            "2.1", Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(30),
            new string('a', 40), new string('b', 64), new string('c', 64), new string('d', 64), "7",
            DatabaseInventory.ActiveDatabases, "shadow-only", "auth-key", null)
        { TargetObservation = target };

        Assert.True(ExecutionAuthorizationAttestation.TryCreatePayload(authorization, out byte[] original));
        Assert.True(ExecutionAuthorizationAttestation.TryCreatePayload(
            authorization with { TargetObservation = target with { Uid = "uid-replaced" } }, out byte[] replaced));

        Assert.NotEqual(original, replaced);
    }

    private static CloudNativePgTargetObservation HealthyObservation(string uid, string resourceVersion)
    {
        return new(
        "maliev-legacy", "legacy-postgres-main", uid, resourceVersion, 7, 7,
        "Cluster in healthy state", 2, 2, "legacy-postgres-main-1", "legacy-postgres-main-1",
        true, true, true, true);
    }

    private static string ClusterJson(string phase, int instances, int readyInstances)
    {
        return $$"""
        {
          "metadata": { "name": "legacy-postgres-main", "namespace": "maliev-legacy", "uid": "uid-a", "resourceVersion": "100", "generation": 7 },
          "spec": { "instances": {{instances}} },
          "status": {
            "phase": "{{phase}}", "readyInstances": {{readyInstances}}, "observedGeneration": 7,
            "currentPrimary": "legacy-postgres-main-1", "targetPrimary": "legacy-postgres-main-1",
            "conditions": [
              { "type": "Ready", "status": "True" },
              { "type": "ConsistentSystemID", "status": "True" },
              { "type": "ContinuousArchiving", "status": "True" },
              { "type": "LastBackupSucceeded", "status": "True" }
            ]
          }
        }
        """;
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class StubObserver(CloudNativePgTargetObservation observation) : ICloudNativePgTargetObserver
    {
        public Task<CloudNativePgTargetObservation> ObserveAsync(string @namespace, string cluster, CancellationToken cancellationToken)
        {
            return Task.FromResult(observation);
        }
    }
}
