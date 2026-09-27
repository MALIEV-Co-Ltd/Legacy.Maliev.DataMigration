using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class PairedLocalTemplateProjectorTests
{
    private static readonly string[] PgDataEnvironment = ["PGDATA=/var/lib/postgresql/18/docker"];

    [Fact]
    public async Task Fresh_independent_observations_project_executable_local_pair_without_private_key_paths()
    {
        await using Fixture fixture = await Fixture.CreateAsync();
        var observer = new Observer();
        string configPath = Path.Combine(fixture.Directory, "candidate.json");
        await MigrationConsole.WriteNewJsonForTestsAsync(configPath,
            new { pairedLocalTemplate = fixture.Candidate }, CancellationToken.None);
        using var output = new StringWriter();
        using var error = new StringWriter();
        int result = await MigrationConsole.RunPairedTemplateForTestsAsync(
            ["project-paired-local-template", "--config", configPath], output, error,
            fixture.Environment, observer, CancellationToken.None);

        Assert.Equal(0, result);
        Assert.Equal(string.Empty, error.ToString());
        Assert.Equal("project_paired_local_template_complete" + Environment.NewLine, output.ToString());
        Assert.Equal(2, observer.Calls);
        using JsonDocument json = JsonDocument.Parse(await File.ReadAllTextAsync(fixture.Candidate.OutputPath));
        JsonElement delta = json.RootElement.GetProperty("delta");
        Assert.True(delta.GetProperty("allowPlanSigning").GetBoolean());
        Assert.True(delta.GetProperty("allowAuthorizationSigning").GetBoolean());
        Assert.True(delta.GetProperty("allowExecution").GetBoolean());
        Assert.True(delta.GetProperty("useCapturedSource").GetBoolean());
        Assert.True(delta.GetProperty("useQuotationPhysicalTransition").GetBoolean());
        Assert.Equal("live-readonly-comparison", delta.GetProperty("sourceMode").GetString());
        Assert.StartsWith("aspire://legacy-postgres-main-local/disposable-", delta.GetProperty("targetAuthority")
            .GetProperty("authorityId").GetString(), StringComparison.Ordinal);
        Assert.StartsWith("aspire://legacy-postgres-main-local/persistent-", delta.GetProperty("pairedPersistentTarget")
            .GetProperty("targetAuthority").GetProperty("authorityId").GetString(), StringComparison.Ordinal);
        string content = await File.ReadAllTextAsync(fixture.Candidate.OutputPath);
        Assert.DoesNotContain("private", content, StringComparison.OrdinalIgnoreCase);
        Assert.True(OwnerProtectedFilePolicy.IsOwnerOnly(fixture.Candidate.OutputPath));
    }

    [Fact]
    public async Task Reused_target_or_signing_role_never_publishes_a_template()
    {
        await using Fixture fixture = await Fixture.CreateAsync();
        var reusedTarget = fixture.Candidate with
        {
            Persistent = fixture.Candidate.Persistent with
            {
                DockerContainerId = fixture.Candidate.Disposable.DockerContainerId,
                DockerVolumeName = fixture.Candidate.Disposable.DockerVolumeName,
            },
        };
        MigrationConsoleException targetFailure = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            MigrationConsole.ProjectPairedLocalTemplateAsync(reusedTarget, fixture.Environment,
                new Observer(), CancellationToken.None));
        Assert.Equal("delta_paired_template_role_invalid", targetFailure.Code);
        Assert.False(File.Exists(fixture.Candidate.OutputPath));

        var reusedRole = fixture.Candidate with
        {
            Persistent = fixture.Candidate.Persistent with { EvidenceKey = fixture.Candidate.Disposable.PlanKey },
        };
        MigrationConsoleException keyFailure = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            MigrationConsole.ProjectPairedLocalTemplateAsync(reusedRole, fixture.Environment,
                new Observer(), CancellationToken.None));
        Assert.Equal("delta_paired_template_key_reuse", keyFailure.Code);
        Assert.False(File.Exists(fixture.Candidate.OutputPath));
    }

    [Fact]
    public async Task Swapped_disposable_and_persistent_volumes_fail_before_observation()
    {
        await using Fixture fixture = await Fixture.CreateAsync();
        var observer = new Observer();
        var swapped = fixture.Candidate with
        {
            Disposable = fixture.Candidate.Disposable with
            {
                DockerVolumeName = "legacy-maliev-exact23-postgres-data",
            },
            Persistent = fixture.Candidate.Persistent with
            {
                DockerVolumeName = "legacy-delta-proof-swapped",
            },
        };
        MigrationConsoleException failure = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            MigrationConsole.ProjectPairedLocalTemplateAsync(swapped, fixture.Environment,
                observer, CancellationToken.None));
        Assert.Equal("delta_paired_template_role_invalid", failure.Code);
        Assert.Equal(0, observer.Calls);
        Assert.False(File.Exists(fixture.Candidate.OutputPath));
    }

    [Fact]
    public async Task Missing_private_signer_or_unprotected_connection_fails_before_observation()
    {
        await using Fixture fixture = await Fixture.CreateAsync();
        var observer = new Observer();
        MigrationConsoleException missing = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            MigrationConsole.ProjectPairedLocalTemplateAsync(fixture.Candidate,
                variable => variable == "LEGACY_MIGRATION_PERSISTENT_DELTA_EVIDENCE_SIGNING_KEY_FILE" ?
                    null : fixture.Environment(variable), observer, CancellationToken.None));
        Assert.Equal("delta_paired_template_private_key_missing_or_reused", missing.Code);
        Assert.Equal(0, observer.Calls);

        string unprotected = Path.Combine(fixture.Directory, "unprotected.connection");
        await File.WriteAllTextAsync(unprotected, "Host=127.0.0.1");
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(unprotected, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                UnixFileMode.GroupRead);
        }
        else
        {
            // An absent protected connection has the same fail-closed boundary on Windows.
            File.Delete(unprotected);
        }
        var badConnection = fixture.Candidate with
        {
            Persistent = fixture.Candidate.Persistent with { TargetConnectionFile = unprotected },
        };
        MigrationConsoleException aclFailure = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            MigrationConsole.ProjectPairedLocalTemplateAsync(badConnection,
                fixture.Environment, observer, CancellationToken.None));
        Assert.Equal("delta_target_connection_unprotected", aclFailure.Code);
        Assert.Equal(0, observer.Calls);
        Assert.False(File.Exists(fixture.Candidate.OutputPath));
    }

    [Fact]
    public async Task Missing_schema_or_non_owner_cannot_publish_a_template()
    {
        await using Fixture fixture = await Fixture.CreateAsync();
        var observer = new Observer();
        MigrationConsoleException caller = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            MigrationConsole.ProjectPairedLocalTemplateAsync(fixture.Candidate,
                variable => variable == "LEGACY_MIGRATION_CALLER" ? "operator" : fixture.Environment(variable),
                observer, CancellationToken.None));
        Assert.Equal("delta_paired_template_caller_invalid", caller.Code);

        var missing = fixture.Candidate with { SchemaPlanPath = Path.Combine(fixture.Directory, "missing-schema.json") };
        MigrationConsoleException schema = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            MigrationConsole.ProjectPairedLocalTemplateAsync(missing,
                fixture.Environment, observer, CancellationToken.None));
        Assert.Equal("delta_schema_plan_unprotected", schema.Code);
        var wrongRunner = fixture.Candidate with { RunnerAssemblyPath = fixture.Candidate.SourceConnectionFile };
        MigrationConsoleException runner = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            MigrationConsole.ProjectPairedLocalTemplateAsync(wrongRunner,
                fixture.Environment, observer, CancellationToken.None));
        Assert.Equal("delta_paired_template_input_invalid", runner.Code);
        Assert.Equal(0, observer.Calls);
        Assert.False(File.Exists(fixture.Candidate.OutputPath));
    }

    [Fact]
    public void Docker_inspection_rejects_changed_volume_loopback_and_running_state()
    {
        string id = new('a', 64);
        string volume = "legacy-delta-proof-a";
        string container = JsonSerializer.Serialize(new[] { new
        {
            Id = id,
            Name = "/" + volume,
            Created = "2026-09-27T00:00:00Z",
            State = new { Running = true, StartedAt = "2026-09-27T00:01:00Z" },
            Config = new { Env = PgDataEnvironment },
            Mounts = new[] { new { Type = "volume", Name = volume, Destination = "/var/lib/postgresql", RW = true } },
            NetworkSettings = new { Ports = new Dictionary<string, object>
            {
                ["5432/tcp"] = new[] { new { HostIp = "127.0.0.1", HostPort = "54321" } },
            } },
        } });
        string volumeJson = JsonSerializer.Serialize(new[] { new
        {
            Name = volume, Driver = "local", CreatedAt = "2026-09-26T00:00:00Z",
        } });
        Assert.Equal(id, DockerLocalTargetObservation.Parse(container, volumeJson, id, volume, 54321).ContainerId);
        Assert.Equal("delta_paired_template_docker_observation_invalid",
            Assert.Throws<MigrationConsoleException>(() => DockerLocalTargetObservation.Parse(container,
                volumeJson, id, volume, 54322)).Code);
        Assert.Equal("delta_paired_template_docker_observation_invalid",
            Assert.Throws<MigrationConsoleException>(() => DockerLocalTargetObservation.Parse(container,
                volumeJson.Replace(volume, "wrong-volume", StringComparison.Ordinal), id, volume, 54321)).Code);
        Assert.Equal("delta_paired_template_docker_observation_invalid",
            Assert.Throws<MigrationConsoleException>(() => DockerLocalTargetObservation.Parse(
                container.Replace("\"Running\":true", "\"Running\":false", StringComparison.Ordinal),
                volumeJson, id, volume, 54321)).Code);
        string persistentVolume = "legacy-maliev-exact23-postgres-data";
        Assert.Equal("delta_paired_template_docker_observation_invalid",
            Assert.Throws<MigrationConsoleException>(() => DockerLocalTargetObservation.Parse(
                container.Replace(volume, persistentVolume, StringComparison.Ordinal),
                volumeJson.Replace(volume, persistentVolume, StringComparison.Ordinal),
                id, persistentVolume, 54321)).Code);
    }

    [Fact]
    public void Docker_capacity_must_exceed_the_reviewed_ten_gib_floor()
    {
        DockerLocalTargetObservation.RequireCapacity(
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/test 40000000 1000000 12000000 10% /var/lib/postgresql\n");
        Assert.Equal("delta_paired_template_capacity_insufficient",
            Assert.Throws<MigrationConsoleException>(() => DockerLocalTargetObservation.RequireCapacity(
                "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/test 20000000 1000000 9000000 10% /var/lib/postgresql\n")).Code);
        Assert.Equal("delta_paired_template_capacity_insufficient",
            Assert.Throws<MigrationConsoleException>(() => DockerLocalTargetObservation.RequireCapacity(
                "df unavailable")).Code);
    }

    [Fact]
    public void Local_apply_requires_same_signed_docker_generation_and_persistent_authority()
    {
        string id = new('a', 64);
        var plan = new DeltaSynchronizationPlan("1.4", Guid.NewGuid(), new string('b', 40),
            DateTimeOffset.UtcNow, new string('1', 64), new string('2', 64), new string('3', 64),
            "local-aspire", "legacy-postgres-main-local", "docker:" + id + ":1:2:3", new string('4', 64),
            new string('5', 64), new string('6', 64), DateTimeOffset.UtcNow, [], "plan-key", "signature")
        {
            TargetAuthority = new(DeltaTargetAuthorityKind.LocalAspire,
                "aspire://legacy-postgres-main-local/persistent-" + id[..12], new string('7', 64)),
        };
        Assert.Equal(id, LocalDockerGenerationGuard.RequireContainerId(plan));
        Assert.Equal("delta_paired_local_docker_generation_required",
            Assert.Throws<DeltaExecutionException>(() => LocalDockerGenerationGuard.RequireContainerId(
                plan with { TargetGeneration = "claimed-generation" })).Code);
        Assert.Equal("delta_paired_local_docker_generation_invalid",
            Assert.Throws<DeltaExecutionException>(() => LocalDockerGenerationGuard.RequireContainerId(
                plan with
                {
                    TargetAuthority = plan.TargetAuthority with
                    {
                        AuthorityId = "aspire://legacy-postgres-main-local/persistent-wrong",
                    }
                })).Code);
        Assert.Equal("delta_paired_local_docker_generation_invalid",
            Assert.Throws<DeltaExecutionException>(() => LocalDockerGenerationGuard.RequireContainerId(
                plan with { TargetGeneration = "docker:" + id })).Code);
        Assert.Equal("delta_paired_local_docker_generation_required",
            Assert.Throws<DeltaExecutionException>(() => LocalDockerGenerationGuard.RequireContainerId(
                plan with
                {
                    TargetAuthority = new(DeltaTargetAuthorityKind.ProductionCloudNativePg,
                    "gke://maliev-website/production", new string('7', 64))
                })).Code);
    }

    [Fact]
    public void Docker_generation_changes_on_container_restart_or_volume_recreation()
    {
        string id = new('a', 64);
        var first = new DockerLocalTargetObservation(id, "legacy-maliev-exact23-postgres-data",
            "/var/lib/postgresql", "/var/lib/postgresql/18/docker",
            DateTimeOffset.FromUnixTimeMilliseconds(1_000), DateTimeOffset.FromUnixTimeMilliseconds(2_000),
            DateTimeOffset.FromUnixTimeMilliseconds(500));
        string generation = LocalDockerGenerationGuard.ComposeGeneration(first);
        Assert.True(LocalDockerGenerationGuard.IsGenerationFor(generation, id));
        Assert.NotEqual(generation, LocalDockerGenerationGuard.ComposeGeneration(first with
        {
            ContainerStartedAtUtc = DateTimeOffset.FromUnixTimeMilliseconds(3_000),
        }));
        Assert.NotEqual(generation, LocalDockerGenerationGuard.ComposeGeneration(first with
        {
            VolumeCreatedAtUtc = DateTimeOffset.FromUnixTimeMilliseconds(600),
        }));
    }

    private sealed class Observer : IPairedLocalTemplateObserver
    {
        public int Calls { get; private set; }

        public Task<ObservedPairedLocalTarget> ObserveAsync(PairedLocalTemplateTarget candidate,
            string connectionString, FreshSchemaPlan schema, CancellationToken cancellationToken)
        {
            Calls++;
            bool persistent = candidate.DockerVolumeName == "legacy-maliev-exact23-postgres-data";
            string label = persistent ? "persistent-" : "disposable-";
            int port = persistent ? 54322 : 54321;
            return Task.FromResult(new ObservedPairedLocalTarget(candidate.DockerContainerId,
                candidate.DockerVolumeName, port, "docker:" + candidate.DockerContainerId + ":1:2:3",
                new string(persistent ? 'd' : 'c', 64),
                new(DeltaTargetAuthorityKind.LocalAspire,
                    "aspire://legacy-postgres-main-local/" + label + candidate.DockerContainerId[..12],
                    new string(persistent ? 'f' : 'e', 64)), DateTimeOffset.UtcNow));
        }
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly Dictionary<string, string> _environment = new(StringComparer.Ordinal);
        public required string Directory { get; init; }
        public required PairedLocalTemplateCommandConfiguration Candidate { get; init; }
        public string? Environment(string variable)
        {
            return _environment.GetValueOrDefault(variable);
        }

        public static async Task<Fixture> CreateAsync()
        {
            string directory = Path.Combine(Path.GetTempPath(), "paired-template-projector-tests", Guid.NewGuid().ToString("N"));
            OwnerProtectedDirectory.CreateNew(directory);
            var environment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["LEGACY_DEPLOY_ENABLED"] = "false",
                ["LEGACY_MIGRATION_CALLER"] = "owner",
            };
            async Task<DeltaTrustedKeyReference> KeyAsync(string id, string variable)
            {
                using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                using var signer = new P256MigrationEvidenceSigner(id, key.ExportECPrivateKeyPem());
                string privatePath = Path.Combine(directory, id + ".private");
                string publicPath = Path.Combine(directory, id + ".public");
                await WriteOwnerOnlyAsync(privatePath, key.ExportECPrivateKeyPem());
                await WriteOwnerOnlyAsync(publicPath, Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()));
                environment[variable] = privatePath;
                return new(id, publicPath);
            }
            DeltaTrustedKeyReference dp = await KeyAsync("disposable-plan", "LEGACY_MIGRATION_DELTA_PLAN_SIGNING_KEY_FILE");
            DeltaTrustedKeyReference da = await KeyAsync("disposable-authorization", "LEGACY_MIGRATION_DELTA_AUTHORIZATION_SIGNING_KEY_FILE");
            DeltaTrustedKeyReference de = await KeyAsync("disposable-evidence", "LEGACY_MIGRATION_DELTA_EVIDENCE_SIGNING_KEY_FILE");
            DeltaTrustedKeyReference pp = await KeyAsync("persistent-plan", "LEGACY_MIGRATION_PERSISTENT_DELTA_PLAN_SIGNING_KEY_FILE");
            DeltaTrustedKeyReference pa = await KeyAsync("persistent-authorization", "LEGACY_MIGRATION_PERSISTENT_DELTA_AUTHORIZATION_SIGNING_KEY_FILE");
            DeltaTrustedKeyReference pe = await KeyAsync("persistent-evidence", "LEGACY_MIGRATION_PERSISTENT_DELTA_EVIDENCE_SIGNING_KEY_FILE");
            string schemaPath = Path.Combine(directory, "schema.json");
            var databases = DatabaseInventory.ActiveDatabases.Select(name => new DatabaseSchemaPlan(name,
                "1.0", new string('a', 64), new string('b', 64), [])
            {
                SourceDispositionProfile = name == "Quotation" ? "quotation-outboxes-v1" : null,
            }).ToArray();
            await MigrationConsole.WriteNewJsonForTestsAsync(schemaPath,
                new FreshSchemaPlan("2.0", DateTimeOffset.UtcNow, new string('a', 40), databases),
                CancellationToken.None);
            string source = Path.Combine(directory, "source.connection");
            string disposable = Path.Combine(directory, "disposable.connection");
            string persistent = Path.Combine(directory, "persistent.connection");
            await WriteOwnerOnlyAsync(source, "source-placeholder");
            await WriteOwnerOnlyAsync(disposable, "disposable-placeholder");
            await WriteOwnerOnlyAsync(persistent, "persistent-placeholder");
            string runner = typeof(MigrationConsole).Assembly.Location;
            var candidate = new PairedLocalTemplateCommandConfiguration(schemaPath,
                Path.Combine(directory, "template.json"), source, runner, new string('1', 64),
                new string('2', 64),
                new(disposable, new string('a', 64), "legacy-delta-proof-a", dp, da, de),
                new(persistent, new string('b', 64), "legacy-maliev-exact23-postgres-data", pp, pa, pe));
            var fixture = new Fixture { Directory = directory, Candidate = candidate };
            foreach ((string key, string value) in environment) { fixture._environment[key] = value; }
            return fixture;
        }

        public ValueTask DisposeAsync()
        {
            System.IO.Directory.Delete(Directory, recursive: true);
            return ValueTask.CompletedTask;
        }

        private static async Task WriteOwnerOnlyAsync(string path, string content)
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.Asynchronous,
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }
            await using var stream = new FileStream(path, options);
            await stream.WriteAsync(Encoding.UTF8.GetBytes(content));
            await stream.FlushAsync();
        }
    }
}
