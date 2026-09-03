using System.Text.Json;
using System.Text.Json.Nodes;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class IncrementalConsoleTests : IDisposable
{
    private static readonly JsonSerializerOptions WireOptions = new(JsonSerializerDefaults.Web) { UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow };
    private readonly string _root = Path.Combine(Path.GetTempPath(), "incremental-console-" + Guid.NewGuid().ToString("N"));

    public IncrementalConsoleTests() { OwnerProtectedDirectory.CreateNew(_root); }

    [Theory]
    [InlineData("plan-incremental")]
    [InlineData("plan-resume")]
    [InlineData("authorize-resume")]
    [InlineData("resume-shadow")]
    [InlineData("finalize-local")]
    [InlineData("execute-shadow")]
    public async Task MissingIncrementalConfiguration_FailsBeforeRuntimeOrRootCreation(string command)
    {
        string path = await WriteAsync("config.json", new { });
        using var error = new StringWriter();
        int code = await MigrationConsole.RunAsync([command, "--config", path], TextWriter.Null, error,
            name => name == "LEGACY_DEPLOY_ENABLED" ? "false" : null, CancellationToken.None);
        Assert.Equal(65, code);
        Assert.Equal("incremental_configuration_missing" + Environment.NewLine, error.ToString());
        _ = Assert.Single(Directory.GetFileSystemEntries(_root));
    }

    [Fact]
    public async Task LegacyExecutionConfiguration_CannotReachCompatibilityRunner()
    {
        string path = await WriteAsync("config.json", new
        {
            executeShadow = new
            {
                receiptPath = "absent",
                planPath = "absent",
                authorizationPath = "absent",
                outputPath = "absent",
                receiptTrustedKeys = Array.Empty<object>(),
                authorizationTrustedKeys = Array.Empty<object>(),
                evidenceKeyId = "execution",
                expectedControlRole = "control",
                expectedShadowAdminRole = "shadow",
            }
        });
        using var error = new StringWriter();
        int code = await MigrationConsole.RunAsync(["execute-shadow", "--config", path], TextWriter.Null, error,
            name => name == "LEGACY_DEPLOY_ENABLED" ? "false" : null, CancellationToken.None);
        Assert.Equal(65, code);
        Assert.Equal("incremental_configuration_missing" + Environment.NewLine, error.ToString());
    }

    private async Task<string> WriteAsync<T>(string name, T value)
    {
        string path = Path.Combine(_root, name);
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(value, WireOptions));
        if (!OperatingSystem.IsWindows()) { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
        return path;
    }

    public void Dispose() { Directory.Delete(_root, recursive: true); }

    [Fact]
    public async Task InitialPlanning_ReadOnlyObservationsWithoutSigningLockOrRoot()
    {
        using var fixture = await AdmittedCoordinatorTestHarness.CreateAsync();
        fixture.Authority.Dispose();
        fixture.StagingOverride = Path.Combine(_root, "new-staging");
        var runtime = new Runtime(fixture);
        string config = await FixtureAsync(fixture);
        var (Code, Output, Error) = await RunAsync("plan-incremental", config, runtime);
        Assert.Equal(0, Code);
        Assert.Equal(string.Empty, Error);
        Assert.False(Directory.Exists(fixture.Staging));
        Assert.Equal(1, runtime.Observations);
        Assert.Equal(0, runtime.Executions);
        Assert.Equal(0, fixture.ReadinessCalls);
        Assert.Contains("readonly_preflight_complete", Output);
    }

    [Fact]
    public async Task InitialExecution_TransfersFreshHeldBindingAndPreservesExpectedResultWire()
    {
        using var fixture = await AdmittedCoordinatorTestHarness.CreateAsync();
        fixture.Authority.Dispose();
        fixture.StagingOverride = Path.Combine(_root, "new-staging");
        string config = await FixtureAsync(fixture, allowExecution: true);
        var runtime = new Runtime(fixture);
        var (Code, Output, Error) = await RunAsync("execute-shadow", config, runtime);
        Assert.True(Code == 0, Error);
        Assert.True(runtime.HeldAtTransfer);
        Assert.Equal(1, fixture.ReadinessCalls);
        string wire = await File.ReadAllTextAsync(Path.Combine(_root, "result.json"));
        MigrationExecutionResult execution = JsonSerializer.Deserialize<MigrationExecutionResult>(wire, WireOptions)!;
        Assert.Equal(MigrationExecutionStatus.Completed, execution.Status);
        Assert.Equal(DatabaseInventory.ActiveDatabases.Count, execution.Receipt.Databases.Count);
        Assert.Equal(fixture.RunJournal.Baseline().TerminalReceiptSignedJson, JsonSerializer.Serialize(execution.Receipt));
        Assert.Contains("\"remoteCommitted\":" + DatabaseInventory.ActiveDatabases.Count, Output);
        Assert.Contains("\"downloaded\":" + DatabaseInventory.ActiveDatabases.Count, Output);
        Assert.Contains("\"localVerified\":" + DatabaseInventory.ActiveDatabases.Count, Output);
    }

    [Theory]
    [InlineData("resume-shadow")]
    [InlineData("authorize-resume")]
    public async Task MissingExternalContinuity_StopsBeforeRuntime(string command)
    {
        using var fixture = await AdmittedCoordinatorTestHarness.CreateAsync();
        string config = await FixtureAsync(fixture, allowExecution: true, allowSigning: true);
        var runtime = new Runtime(fixture);
        var (Code, Output, Error) = await RunAsync(command, config, runtime);
        Assert.Equal(65, Code);
        Assert.Equal("incremental_continuity_required" + Environment.NewLine, Error);
        Assert.Equal(0, runtime.Observations);
        Assert.Equal(0, runtime.Executions);
    }

    [Theory]
    [InlineData("execute-shadow")]
    [InlineData("resume-shadow")]
    [InlineData("authorize-resume")]
    public async Task ExplicitGateRequired_BeforeArtifactsOrRuntime(string command)
    {
        string config = await WriteAsync("config.json", new { incremental = new IncrementalCommandConfiguration(_root, _root, "s", "output", "commit", "digest") });
        using var error = new StringWriter();
        int exit = await MigrationConsole.RunAsync([command, "--config", config], TextWriter.Null, error,
            name => name == "LEGACY_DEPLOY_ENABLED" ? "false" : null, CancellationToken.None);
        Assert.Equal(65, exit);
        Assert.Contains("incremental_owner_approval_required", error.ToString());
    }

    [Fact]
    public async Task LocalFinalization_DoesNotRequestRemoteConfigurationOrExecutionSigner()
    {
        using var fixture = await AdmittedCoordinatorTestHarness.CreateAsync();
        await using (AdmittedSequentialMigrationCoordinator coordinator = fixture.Coordinator())
        { _ = await coordinator.ExecuteInitialAsync(fixture.Authority, CancellationToken.None); }
        string config = await FixtureAsync(fixture);
        JsonObject json = JsonNode.Parse(await File.ReadAllTextAsync(config))!.AsObject();
        JsonObject incremental = json["incremental"]!.AsObject();
        incremental["runtime"] = null;
        incremental["completedSnapshotPath"] = await WriteAsync("completed.json", new
        { admissionJson = fixture.Data.Admission.ExactJson, baseline = fixture.RunJournal.Baseline(), observedAtUtc = DateTimeOffset.UtcNow, leaseExpiresAtUtc = (DateTimeOffset?)null });
        await File.WriteAllTextAsync(config, json.ToJsonString());
        var runtime = new Runtime(fixture) { Forbid = true };
        var (Code, Output, Error) = await RunAsync("finalize-local", config, runtime, localOnly: true);
        Assert.True(Code == 0, Error);
        Assert.Equal(0, runtime.Executions);
        Assert.Contains("\"downloaded\":0", Output);
    }

    private async Task<string> FixtureAsync(AdmittedCoordinatorTestHarness fixture, bool allowExecution = false, bool allowSigning = false)
    {
        string[] ids = ["backup", "authorization", "execution", "provenance", "final"];
        var roles = new Dictionary<string, object>();
        for (int index = 0; index < ids.Length; index++)
        {
            string keyPath = await WriteTextAsync(ids[index] + ".public", Convert.ToBase64String(fixture.Data.Signers[index].ExportSubjectPublicKeyInfo()));
            roles[index == 4 ? "finalEvidence" : ids[index]] = new { keyId = ids[index], subjectPublicKeyInfoPath = keyPath };
        }
        _ = await WriteTextAsync("execution.private", fixture.Data.PrivateKeyPems[2]);
        _ = await WriteTextAsync("authorization.private", fixture.Data.PrivateKeyPems[1]);
        _ = await WriteTextAsync("snapshot.key", Convert.ToBase64String(fixture.RootKey.Span));
        string connection = await WriteTextAsync("connection", "test-only-seam");
        var runtime = new IncrementalRuntimeConfiguration(connection, connection, connection, connection, connection, "control", "shadow",
            "C:/Program Files/PostgreSQL/18/bin/pg_dump.exe", "C:/Program Files/PostgreSQL/18/bin/pg_restore.exe", "container", "image", "system",
            new Uri("https://kube.example.test"), connection, connection);
        var config = new IncrementalCommandConfiguration(fixture.Staging, fixture.Output, "coordinator-test", Path.Combine(_root, "result.json"),
            fixture.Plan.SourceCommitSha, fixture.Data.Runner.RunnerDigestSha256,
            ReceiptPath: await WriteTextAsync("backup.json", fixture.Data.AdmissionPayload.OriginalBackupReceiptJson),
            PlanPath: await WriteTextAsync("plan.json", fixture.Data.AdmissionPayload.OriginalSchemaPlanJson),
            AuthorizationPath: await WriteTextAsync("authorization.json", fixture.Data.AdmissionPayload.OriginalAuthorizationJson),
            VerifiedRestoreReceiptPath: await WriteTextAsync("restore.json", fixture.Data.AdmissionPayload.OriginalVerifiedRestoreReceiptJson),
            AdmissionPath: fixture.StagingOverride is not null ? Path.Combine(_root, "new-admission.json") : await WriteTextAsync("admission.json", fixture.Data.Admission.ExactJson), Runtime: runtime,
            AllowExecution: allowExecution, AllowSigning: allowSigning, ResumeExpiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(15));
        return await WriteAsync("config.json", new { incremental = config, signingRoles = roles });
    }

    private async Task<string> WriteTextAsync(string name, string text)
    {
        string path = Path.Combine(_root, name);
        await File.WriteAllTextAsync(path, text);
        return path;
    }

    private async Task<(int Code, string Output, string Error)> RunAsync(string command, string config, IIncrementalConsoleRuntime runtime, bool localOnly = false, string? keyPath = null)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await MigrationConsole.RunIncrementalForTestsAsync([command, "--config", config], output, error, name => name switch
        {
            "LEGACY_DEPLOY_ENABLED" => "false",
            "LEGACY_MIGRATION_SNAPSHOT_ENCRYPTION_KEY_FILE" => keyPath ?? Path.Combine(_root, "snapshot.key"),
            "LEGACY_MIGRATION_EXECUTION_SIGNING_KEY_FILE" when !localOnly => Path.Combine(_root, "execution.private"),
            "LEGACY_MIGRATION_AUTHORIZATION_SIGNING_KEY_FILE" when !localOnly => Path.Combine(_root, "authorization.private"),
            _ => throw new InvalidOperationException("Unexpected credential request"),
        }, runtime, CancellationToken.None);
        return (code, output.ToString(), error.ToString());
    }

    private sealed class Runtime(AdmittedCoordinatorTestHarness fixture) : IIncrementalConsoleRuntime
    {
        internal int Observations, Executions;
        internal bool HeldAtTransfer, Forbid;
        internal Exception? ObservationFailure;
        public Task<IncrementalReadOnlyObservation> ObserveAsync(IncrementalReadOnlyRequest request, CancellationToken token)
        {
            Assert.False(Forbid); Observations++;
            if (ObservationFailure is not null) { throw ObservationFailure; }
            DateTimeOffset now = DateTimeOffset.UtcNow;
            return Task.FromResult(new IncrementalReadOnlyObservation(fixture.Data.Source with { ObservedAtUtc = now },
                fixture.Data.Runner with { ObservedAtUtc = now }, fixture.Data.Target with { ObservedAtUtc = now }));
        }
        public Task<RecoveryJournalSnapshot> ReadSnapshotAsync(IncrementalReadOnlyRequest request, CancellationToken token)
        {
            Assert.False(Forbid); Assert.Equal(fixture.Data.Admission.Payload.Identity, request.Identity);
            return Task.FromResult(new RecoveryJournalSnapshot(fixture.Data.Admission, fixture.RunJournal.Baseline(), DateTimeOffset.UtcNow, fixture.RunJournal.Lease?.ExpiresAtUtc));
        }
        public AdmittedSequentialMigrationCoordinator CreateExecution(AdmittedCoordinatorHostOptions options, Action<IncrementalMigrationProgress> progress)
        {
            Assert.False(Forbid); Executions++;
            Assert.Equal(AppContext.BaseDirectory, options.RunnerPublishDirectory);
            if (options.Admission.ExactJson != fixture.Data.Admission.ExactJson)
            {
                _ = Assert.Throws<IOException>(() => WindowsLocalRunAuthority.AcquireResume(fixture.Staging, options.Admission.Payload.LocalBinding));
                HeldAtTransfer = true;
                fixture.Data.Admission = options.Admission; fixture.Data.AdmissionPayload = options.Admission.Payload;
                fixture.Data.Binding = options.Admission.Payload.LocalBinding; fixture.Data.AdmittedAt = options.Admission.Payload.AdmittedAtUtc;
            }
            return fixture.Coordinator(progress);
        }
    }

    [Theory]
    [InlineData("runtime")]
    [InlineData("native")]
    [InlineData("root")]
    [InlineData("nested-output")]
    [InlineData("unknown-runtime-directory")]
    [InlineData("expired-authorization")]
    public async Task UnsafeOrMissingConfiguration_RejectsBeforeRootOrRuntime(string fault)
    {
        using var fixture = await AdmittedCoordinatorTestHarness.CreateAsync();
        fixture.Authority.Dispose(); fixture.StagingOverride = Path.Combine(_root, "new-staging");
        string config = await FixtureAsync(fixture, allowExecution: true);
        JsonObject json = JsonNode.Parse(await File.ReadAllTextAsync(config))!.AsObject();
        JsonObject command = json["incremental"]!.AsObject();
        switch (fault)
        {
            case "runtime": command["runtime"] = null; break;
            case "native": command["runtime"]!["pgDumpPath"] = Path.Combine(_root, "absent.exe"); break;
            case "root": command["artifactRoot"] = "relative"; break;
            case "nested-output": command["outputDirectory"] = Path.Combine(fixture.Staging, "nested"); break;
            case "unknown-runtime-directory": command["runnerPublishDirectory"] = _root; break;
            case "expired-authorization":
                ExecutionAuthorizationReceipt original = JsonSerializer.Deserialize<ExecutionAuthorizationReceipt>(fixture.Data.AdmissionPayload.OriginalAuthorizationJson)!;
                await File.WriteAllTextAsync(Path.Combine(_root, "authorization.json"), JsonSerializer.Serialize(original with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(-1) }));
                break;
            default:
                break;
        }
        await File.WriteAllTextAsync(config, json.ToJsonString());
        var runtime = new Runtime(fixture);
        var (Code, Output, Error) = await RunAsync("execute-shadow", config, runtime);
        Assert.NotEqual(0, Code);
        Assert.Equal(0, runtime.Observations); Assert.Equal(0, runtime.Executions);
        Assert.False(Directory.Exists(fixture.Staging));
    }

    [Fact]
    public async Task ReadinessCredentialFailure_IsSecretSafeAndPrecedesRemoteMutation()
    {
        using var fixture = await AdmittedCoordinatorTestHarness.CreateAsync();
        fixture.Authority.Dispose(); fixture.StagingOverride = Path.Combine(_root, "new-staging"); fixture.FailReadiness = true;
        string config = await FixtureAsync(fixture, allowExecution: true);
        var (Code, Output, Error) = await RunAsync("execute-shadow", config, new Runtime(fixture));
        Assert.Equal(70, Code);
        Assert.Contains("incremental_io_failed", Error);
        Assert.Equal(1, fixture.ReadinessCalls);
        Assert.Equal(0, fixture.RunJournal.InitialCalls);
        Assert.Empty(fixture.Target.Copies);
        Assert.DoesNotContain("readiness failure", Error + Output);
        Assert.Contains("\"localVerified\":0", Output);
    }

    [Theory]
    [InlineData("admission-inside")]
    [InlineData("admission-exists")]
    [InlineData("result-exists")]
    public async Task InitialPublicationConfiguration_RejectsBeforePermanentSetup(string fault)
    {
        using var fixture = await AdmittedCoordinatorTestHarness.CreateAsync();
        fixture.Authority.Dispose(); fixture.StagingOverride = Path.Combine(_root, "new-staging");
        string config = await FixtureAsync(fixture, allowExecution: true);
        JsonObject json = JsonNode.Parse(await File.ReadAllTextAsync(config))!.AsObject();
        JsonObject command = json["incremental"]!.AsObject();
        if (fault == "admission-inside") { command["admissionPath"] = Path.Combine(fixture.Staging, "admission.json"); }
        else { command[fault == "admission-exists" ? "admissionPath" : "outputPath"] = Path.Combine(_root, "backup.json"); }
        await File.WriteAllTextAsync(config, json.ToJsonString());
        var (Code, Output, Error) = await RunAsync("execute-shadow", config, new Runtime(fixture));
        Assert.NotEqual(0, Code);
        Assert.False(Directory.Exists(fixture.Staging));
        Assert.Equal(0, fixture.RunJournal.InitialCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Diagnostics_OnlySafeMetadataAndOriginalFailureCode(bool reconciliation)
    {
        using var fixture = await AdmittedCoordinatorTestHarness.CreateAsync();
        fixture.Authority.Dispose(); fixture.StagingOverride = Path.Combine(_root, "new-staging");
        string config = await FixtureAsync(fixture);
        const string secret = "Pass" + "word=do-not-print; row customer private";
        var runtime = new Runtime(fixture)
        {
            ObservationFailure = reconciliation
            ? new MigrationExecutionException("shadow_reconciliation_failed", secret)
            { Reconciliation = new("Order", "public.Order", "row-count", "2", "3") { Field = "Id" } }
            : new IOException(secret)
        };
        var (Code, Output, Error) = await RunAsync("plan-incremental", config, runtime);
        Assert.Equal(70, Code);
        Assert.DoesNotContain(secret, Error + Output);
        if (reconciliation)
        {
            Assert.Contains("shadow_reconciliation_failed", Error);
            Assert.Contains("\"check\":\"row-count\"", Error);
            Assert.Contains("\"expected\":\"2\"", Error);
            Assert.Contains("\"observed\":\"3\"", Error);
        }
    }

    [Fact]
    public async Task InterruptedConsole_NewConsoleResumesRetainedBytesAndCompletedLocalReplay()
    {
        using var fixture = await AdmittedCoordinatorTestHarness.CreateAsync();
        fixture.Authority.Dispose(); fixture.StagingOverride = Path.Combine(_root, "new-staging");
        fixture.FailingSourceDatabase = DatabaseInventory.ActiveDatabases[1];
        string config = await FixtureAsync(fixture, allowExecution: true, allowSigning: true);
        var (Code, Output, Error) = await RunAsync("execute-shadow", config, new Runtime(fixture));
        Assert.Equal(70, Code);
        string archive = Directory.GetFiles(fixture.Staging, "archive.aes256", SearchOption.AllDirectories).Single();
        byte[] bytes = await File.ReadAllBytesAsync(archive);
        var (continuity, _) = fixture.ResumeAuthority();
        string continuityPath = await WriteTextAsync("continuity.json", continuity.ExactJson);
        JsonObject json = JsonNode.Parse(await File.ReadAllTextAsync(config))!.AsObject();
        JsonObject command = json["incremental"]!.AsObject();
        command["continuityPath"] = continuityPath; command["outputPath"] = Path.Combine(_root, "resume.json");
        await File.WriteAllTextAsync(config, json.ToJsonString());
        var signed = await RunAsync("authorize-resume", config, new Runtime(fixture));
        Assert.True(signed.Code == 0, signed.Error);
        ResumeAuthorizationReceipt approval = ResumeAuthorizationReceipt.Parse(await File.ReadAllTextAsync(Path.Combine(_root, "resume.json")));
        Assert.Equal(continuity.ComputeSha256(), approval.Payload.ContinuitySha256);
        command["resumeAuthorizationPath"] = Path.Combine(_root, "resume.json"); command["outputPath"] = Path.Combine(_root, "result.json");
        await File.WriteAllTextAsync(config, json.ToJsonString());
        fixture.FailingSourceDatabase = null;
        var resumed = await RunAsync("resume-shadow", config, new Runtime(fixture));
        Assert.True(resumed.Code == 0, resumed.Error);
        Assert.Equal(bytes, await File.ReadAllBytesAsync(archive));
        Assert.Equal(1, fixture.Target.Copies[DatabaseInventory.ActiveDatabases[0]]);
        Assert.Equal(1, fixture.Dump.Counts[DatabaseInventory.ActiveDatabases[0]]);
        command["outputPath"] = Path.Combine(_root, "completed.json");
        await File.WriteAllTextAsync(config, json.ToJsonString());
        var snapshot = await RunAsync("plan-resume", config, new Runtime(fixture));
        Assert.True(snapshot.Code == 0, snapshot.Error);
        command["completedSnapshotPath"] = Path.Combine(_root, "completed.json"); command["runtime"] = null; command["outputPath"] = Path.Combine(_root, "result.json");
        await File.WriteAllTextAsync(config, json.ToJsonString());
        var final = await RunAsync("finalize-local", config, new Runtime(fixture) { Forbid = true }, localOnly: true);
        Assert.True(final.Code == 0, final.Error);
        Assert.Contains("\"downloaded\":0", final.Output);
        Assert.Equal(bytes, await File.ReadAllBytesAsync(archive));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidOrEmbeddedRootKey_RejectsBeforeSetup(bool embedded)
    {
        using var fixture = await AdmittedCoordinatorTestHarness.CreateAsync();
        fixture.Authority.Dispose(); fixture.StagingOverride = Path.Combine(_root, "new-staging");
        string config = await FixtureAsync(fixture, allowExecution: true);
        string key = embedded ? Path.Combine(fixture.Staging, "key") : await WriteTextAsync("snapshot.key", "invalid-secret-do-not-print");
        var (Code, Output, Error) = await RunAsync("execute-shadow", config, new Runtime(fixture), keyPath: key);
        Assert.Equal(65, Code);
        Assert.DoesNotContain("invalid-secret", Error);
        Assert.False(Directory.Exists(fixture.Staging));
        Assert.Equal(0, fixture.RunJournal.InitialCalls);
    }

    [Fact]
    public async Task ConcreteReadonlyRuntime_RejectsUnsafeHostTrustBeforeRootOrRemoteWrite()
    {
        using var fixture = await AdmittedCoordinatorTestHarness.CreateAsync();
        fixture.Authority.Dispose(); fixture.StagingOverride = Path.Combine(_root, "new-staging");
        string config = await FixtureAsync(fixture, allowExecution: true);
        var (Code, Output, Error) = await RunAsync("execute-shadow", config, new DefaultIncrementalConsoleRuntime());
        Assert.NotEqual(0, Code);
        Assert.False(Directory.Exists(fixture.Staging));
        Assert.DoesNotContain("test-only-seam", Error);
    }

    [Fact]
    public async Task ProgressSinkFailure_DoesNotReplacePrimaryExecutionFailure()
    {
        using var fixture = await AdmittedCoordinatorTestHarness.CreateAsync();
        fixture.Authority.Dispose(); fixture.StagingOverride = Path.Combine(_root, "new-staging");
        fixture.CompleteSourceFailure = new MigrationExecutionException("source_completion_failed", "private provider detail");
        string config = await FixtureAsync(fixture, allowExecution: true);
        using var error = new StringWriter();
        using var output = new FailedOutput();
        int exit = await MigrationConsole.RunIncrementalForTestsAsync(["execute-shadow", "--config", config], output, error, name => name switch
        {
            "LEGACY_DEPLOY_ENABLED" => "false",
            "LEGACY_MIGRATION_SNAPSHOT_ENCRYPTION_KEY_FILE" => Path.Combine(_root, "snapshot.key"),
            "LEGACY_MIGRATION_EXECUTION_SIGNING_KEY_FILE" => Path.Combine(_root, "execution.private"),
            _ => null,
        }, new Runtime(fixture), CancellationToken.None);
        Assert.Equal(70, exit);
        Assert.Equal("source_completion_failed" + Environment.NewLine, error.ToString());
    }

    private sealed class FailedOutput : StringWriter
    {
        public override void WriteLine(string? value)
        {
            throw new IOException("sink failed");
        }

        public override Task WriteLineAsync(string? value)
        {
            return Task.FromException(new IOException("sink failed"));
        }
    }
}
