using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class RuntimeAttestationTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"legacy-runtime-{Guid.NewGuid():N}");

    [Fact]
    public async Task Runner_manifest_is_deterministic_and_binds_every_published_file()
    {
        CreateOwnerOnlyDirectory(_root);
        string runnerPath = Path.Combine(_root, "runner.dll");
        await File.WriteAllTextAsync(runnerPath, "runner-v1");
        ProtectFile(runnerPath);
        CreateOwnerOnlyDirectory(Path.Combine(_root, "runtimes"));
        string dependencyPath = Path.Combine(_root, "runtimes", "dependency.dll");
        await File.WriteAllTextAsync(dependencyPath, "dependency-v1");
        ProtectFile(dependencyPath);

        RunnerArtifactManifest first = await RunnerArtifactManifestMeasurer.MeasureAsync(_root, CancellationToken.None);
        RunnerArtifactManifest second = await RunnerArtifactManifestMeasurer.MeasureAsync(_root, CancellationToken.None);

        Assert.Equal(first.ManifestSha256, second.ManifestSha256);
        Assert.Equal(["runner.dll", "runtimes/dependency.dll"], first.Files.Select(file => file.RelativePath));

        await File.WriteAllTextAsync(dependencyPath, "dependency-v2");
        RunnerArtifactManifest changed = await RunnerArtifactManifestMeasurer.MeasureAsync(_root, CancellationToken.None);
        Assert.NotEqual(first.ManifestSha256, changed.ManifestSha256);
    }

    [Fact]
    public async Task Linux_path_identity_matches_the_exclusive_open_handle_without_reopening_the_file()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        string runnerPath = await CreateSingleFilePublicationAsync();
        await using FileStream stream = SecureLocalFile.OpenRead(runnerPath);

        Assert.Equal(SecureLocalFile.GetHandleIdentity(stream), SecureLocalFile.GetPathIdentity(runnerPath));
    }

    [Fact]
    public async Task Runner_manifest_rejects_a_symbolic_link_inside_the_publication()
    {
        CreateOwnerOnlyDirectory(_root);
        string external = Path.Combine(Path.GetTempPath(), $"legacy-runtime-external-{Guid.NewGuid():N}");
        _ = Directory.CreateDirectory(external);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(_root, "runner.dll"), "runner-v1");
            ProtectFile(Path.Combine(_root, "runner.dll"));
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

    [Fact]
    public async Task Runner_manifest_rejects_concurrent_in_place_mutation()
    {
        string runnerPath = await CreateSingleFilePublicationAsync();

        RuntimeAttestationException exception = await Assert.ThrowsAsync<RuntimeAttestationException>(() =>
            RunnerArtifactManifestMeasurer.MeasureAsync(_root, async cancellationToken =>
            {
                await File.WriteAllTextAsync(runnerPath, "mutated-content", cancellationToken);
            }, CancellationToken.None));

        AssertMutationRejected(exception);
    }

    [Fact]
    public async Task Runner_manifest_rejects_same_file_set_replacement()
    {
        string runnerPath = await CreateSingleFilePublicationAsync();
        string displaced = Path.Combine(Path.GetTempPath(), $"displaced-runner-{Guid.NewGuid():N}.dll");
        try
        {
            RuntimeAttestationException exception = await Assert.ThrowsAsync<RuntimeAttestationException>(() =>
                RunnerArtifactManifestMeasurer.MeasureAsync(_root, async cancellationToken =>
                {
                    File.Move(runnerPath, displaced);
                    await File.WriteAllTextAsync(runnerPath, "replacement", cancellationToken);
                    ProtectFile(runnerPath);
                }, CancellationToken.None));

            AssertMutationRejected(exception);
        }
        finally
        {
            if (File.Exists(displaced))
            {
                File.Delete(displaced);
            }
        }
    }

    [Fact]
    public async Task Runner_manifest_rejects_publication_directory_swap()
    {
        _ = await CreateSingleFilePublicationAsync();
        string displacedRoot = _root + "-displaced";
        try
        {
            RuntimeAttestationException exception = await Assert.ThrowsAsync<RuntimeAttestationException>(() =>
                RunnerArtifactManifestMeasurer.MeasureAsync(_root, async cancellationToken =>
                {
                    Directory.Move(_root, displacedRoot);
                    CreateOwnerOnlyDirectory(_root);
                    string replacement = Path.Combine(_root, "runner.dll");
                    await File.WriteAllTextAsync(replacement, "runner-v1", cancellationToken);
                    ProtectFile(replacement);
                }, CancellationToken.None));

            AssertMutationRejected(exception);
        }
        finally
        {
            if (Directory.Exists(displacedRoot))
            {
                Directory.Delete(displacedRoot, recursive: true);
            }
        }
    }

    [Fact]
    public async Task Runner_manifest_rejects_file_to_symlink_swap()
    {
        string runnerPath = await CreateSingleFilePublicationAsync();
        string external = Path.Combine(Path.GetTempPath(), $"external-runner-{Guid.NewGuid():N}.dll");
        await File.WriteAllTextAsync(external, "runner-v1");
        try
        {
            RuntimeAttestationException exception = await Assert.ThrowsAsync<RuntimeAttestationException>(() =>
                RunnerArtifactManifestMeasurer.MeasureAsync(_root, cancellationToken =>
                {
                    File.Delete(runnerPath);
                    FileSystemInfo link = File.CreateSymbolicLink(runnerPath, external);
                    Assert.NotNull(link);
                    return Task.CompletedTask;
                }, CancellationToken.None));

            AssertMutationRejected(exception);
        }
        finally
        {
            if (File.Exists(external))
            {
                File.Delete(external);
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
        CreateOwnerOnlyDirectory(_root);
        string runnerPath = Path.Combine(_root, "runner.dll");
        await File.WriteAllTextAsync(runnerPath, "runner-v1");
        ProtectFile(runnerPath);
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

    [Theory]
    [InlineData("https://attacker.example", "/var/run/secrets/kubernetes.io/serviceaccount/token", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")]
    [InlineData("https://kubernetes.default.svc", "C:/caller/token", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")]
    [InlineData("https://kubernetes.default.svc", "/var/run/secrets/kubernetes.io/serviceaccount/token", "C:/caller/ca.crt")]
    public void Target_observer_rejects_substituted_endpoint_or_trust_paths(string apiServer, string tokenPath, string caPath)
    {
        _ = Assert.Throws<ArgumentException>(() => new CloudNativePgTargetObserver(new(new Uri(apiServer), tokenPath, caPath)));
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

    private static void CreateOwnerOnlyDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            OwnerProtectedDirectory.CreateNew(path);
        }

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static void ProtectFile(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    private async Task<string> CreateSingleFilePublicationAsync()
    {
        CreateOwnerOnlyDirectory(_root);
        string path = Path.Combine(_root, "runner.dll");
        await File.WriteAllTextAsync(path, "runner-v1");
        ProtectFile(path);
        return path;
    }

    private static void AssertMutationRejected(RuntimeAttestationException exception)
    {
        Assert.True(exception.Code is
            "runtime_runner_manifest_mutated" or
            "runtime_runner_measurement_failed" or
            "runtime_runner_boundary_invalid" or
            "runtime_runner_link_forbidden", exception.Code);
    }

    private sealed class StubObserver(CloudNativePgTargetObservation observation) : ICloudNativePgTargetObserver
    {
        public Task<CloudNativePgTargetObservation> ObserveAsync(string @namespace, string cluster, CancellationToken cancellationToken)
        {
            return Task.FromResult(observation);
        }
    }
}
