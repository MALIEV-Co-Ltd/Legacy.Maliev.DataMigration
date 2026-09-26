using System.Security.Cryptography;
using System.Text;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class GuardedDeltaCommandPolicyTests
{
    [Fact]
    public void AppHost_CanInvokeOnlyLocalApply()
    {
        Assert.True(GuardedDeltaCommandPolicy.IsAppHostCallable("apply-delta-local"));
        Assert.False(GuardedDeltaCommandPolicy.IsAppHostCallable("apply-delta-production"));
        Assert.False(GuardedDeltaCommandPolicy.IsAppHostCallable("plan-delta"));
        Assert.False(GuardedDeltaCommandPolicy.IsAppHostCallable("plan-paired-delta"));
        Assert.False(GuardedDeltaCommandPolicy.IsAppHostCallable("inspect-target-schema-gaps"));
        Assert.False(GuardedDeltaCommandPolicy.IsAppHostCallable("verify-disposable-delta-proof"));
        Assert.False(GuardedDeltaCommandPolicy.IsAppHostCallable("authorize-delta"));
        Assert.False(GuardedDeltaCommandPolicy.IsAppHostCallable("reconcile-delta"));
    }

    [Theory]
    [InlineData("owner", "apply-delta-production")]
    [InlineData("owner", "authorize-delta")]
    [InlineData("owner", "verify-disposable-delta-proof")]
    [InlineData("owner", "plan-paired-delta")]
    [InlineData("operator", "plan-delta")]
    [InlineData("operator", "inspect-target-schema-gaps")]
    [InlineData("operator", "apply-delta-local")]
    [InlineData("apphost", "apply-delta-local")]
    public void AllowedCallerCommandPairs_AreAccepted(string caller, string command)
    {
        GuardedDeltaCommandPolicy.ValidateCaller(command, caller);
    }

    [Theory]
    [InlineData("apphost", "apply-delta-production")]
    [InlineData("apphost", "authorize-delta")]
    [InlineData("apphost", "inspect-target-schema-gaps")]
    [InlineData("operator", "apply-delta-production")]
    [InlineData("operator", "authorize-delta")]
    [InlineData("operator", "verify-disposable-delta-proof")]
    [InlineData("operator", "plan-paired-delta")]
    [InlineData("", "plan-delta")]
    public void PrivilegeEscalationPairs_FailClosed(string caller, string command)
    {
        MigrationConsoleException exception = Assert.Throws<MigrationConsoleException>(() =>
            GuardedDeltaCommandPolicy.ValidateCaller(command, caller));

        Assert.Equal("delta_caller_invalid", exception.Code);
    }

    [Fact]
    public async Task Ordinary_plan_command_rejects_a_paired_target_before_runtime()
    {
        string directory = Path.Combine(Path.GetTempPath(), "legacy-paired-console-tests",
            Guid.NewGuid().ToString("N"));
        OwnerProtectedDirectory.CreateNew(directory);
        try
        {
            string config = Path.Combine(directory, "config.json");
            await MigrationConsole.WriteNewJsonForTestsAsync(config,
                new { delta = new { pairedPersistentTarget = new { } } }, CancellationToken.None);
            using var error = new StringWriter();

            int result = await MigrationConsole.RunDeltaForTestsAsync(
                ["plan-delta", "--config", config], TextWriter.Null, error,
                name => name switch
                {
                    "LEGACY_DEPLOY_ENABLED" => "false",
                    "LEGACY_MIGRATION_CALLER" => "owner",
                    _ => throw new InvalidOperationException("The command reached key projection."),
                }, new DefaultGuardedDeltaConsoleRuntime(), CancellationToken.None);

            Assert.Equal(65, result);
            Assert.Equal("delta_paired_plan_command_invalid" + Environment.NewLine, error.ToString());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Paired_plan_post_capture_fence_rejects_either_changed_target_identity(
        bool changedDisposable)
    {
        var disposable = new DeltaTargetAuthority(DeltaTargetAuthorityKind.LocalAspire,
            "aspire://legacy-postgres-main-local/disposable-fence-test", new string('1', 64));
        var persistent = new DeltaTargetAuthority(DeltaTargetAuthorityKind.LocalAspire,
            "aspire://legacy-postgres-main-local/persistent-fence-test", new string('2', 64));
        var planned = new PairedCapturedDeltaPlans(null!, null!);
        var observed = new List<string>();

        DeltaExecutionException failure = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            PairedDeltaTargetIdentityFence.VerifyAfterPlanningAsync(planned,
                "disposable", disposable, "persistent", persistent,
                (connection, expected, _) =>
                {
                    observed.Add(connection);
                    bool isDisposable = connection == "disposable";
                    if (isDisposable == changedDisposable)
                    {
                        throw new DeltaExecutionException("delta_target_identity_changed",
                            "The target identity changed after captured planning.");
                    }
                    Assert.Equal(connection == "disposable" ? disposable : persistent, expected);
                    return Task.CompletedTask;
                }, CancellationToken.None));

        Assert.Equal("delta_target_identity_changed", failure.Code);
        Assert.Equal(changedDisposable ? ["disposable"] : ["disposable", "persistent"], observed);
    }

    [Fact]
    public async Task Paired_command_projects_two_distinct_signers_and_one_capture_without_apply()
    {
        string directory = Path.Combine(Path.GetTempPath(), "legacy-paired-console-tests",
            Guid.NewGuid().ToString("N"));
        OwnerProtectedDirectory.CreateNew(directory);
        try
        {
            using var disposablePrivate = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var persistentPrivate = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var disposableSigner = new P256MigrationEvidenceSigner("disposable-plan",
                disposablePrivate.ExportECPrivateKeyPem());
            using var persistentSigner = new P256MigrationEvidenceSigner("persistent-plan",
                persistentPrivate.ExportECPrivateKeyPem());
            async Task<DeltaTrustedKeyReference> AddKeyAsync(string id, ECDsa key)
            {
                using var signer = new P256MigrationEvidenceSigner(id, key.ExportECPrivateKeyPem());
                string path = Path.Combine(directory, id + ".public");
                await WriteOwnerOnlyAsync(path, Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()));
                return new DeltaTrustedKeyReference(id, path);
            }
            DeltaTrustedKeyReference disposablePlan = await AddKeyAsync("disposable-plan", disposablePrivate);
            DeltaTrustedKeyReference persistentPlan = await AddKeyAsync("persistent-plan", persistentPrivate);
            var otherKeys = new List<ECDsa>();
            try
            {
                async Task<DeltaTrustedKeyReference> OtherKeyAsync(string id)
                {
                    ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                    otherKeys.Add(key);
                    return await AddKeyAsync(id, key);
                }
                DeltaTrustedKeyReference disposableAuth = await OtherKeyAsync("disposable-auth");
                DeltaTrustedKeyReference disposableEvidence = await OtherKeyAsync("disposable-evidence");
                DeltaTrustedKeyReference persistentAuth = await OtherKeyAsync("persistent-auth");
                DeltaTrustedKeyReference persistentEvidence = await OtherKeyAsync("persistent-evidence");
                string disposablePrivatePath = Path.Combine(directory, "disposable.private");
                string persistentPrivatePath = Path.Combine(directory, "persistent.private");
                await WriteOwnerOnlyAsync(disposablePrivatePath, disposablePrivate.ExportECPrivateKeyPem());
                await WriteOwnerOnlyAsync(persistentPrivatePath, persistentPrivate.ExportECPrivateKeyPem());
                string source = Path.Combine(directory, "source.connection");
                string disposable = Path.Combine(directory, "disposable.connection");
                string persistent = Path.Combine(directory, "persistent.connection");
                await WriteOwnerOnlyAsync(source, "source-placeholder");
                await WriteOwnerOnlyAsync(disposable, "disposable-placeholder");
                await WriteOwnerOnlyAsync(persistent, "persistent-placeholder");
                string captureDirectory = Path.Combine(directory, "captures");
                OwnerProtectedDirectory.CreateNew(captureDirectory);
                string captureKey = Path.Combine(directory, "capture-key.bin");
                await WriteOwnerOnlyBytesAsync(captureKey, RandomNumberGenerator.GetBytes(32));
                Assert.True(OwnerProtectedFilePolicy.IsOwnerOnly(captureKey));
                string schemaPath = Path.Combine(directory, "schema.json");
                await MigrationConsole.WriteNewJsonForTestsAsync(schemaPath,
                    new FreshSchemaPlan("2.0", DateTimeOffset.UtcNow, new string('a', 40), []),
                    CancellationToken.None);
                var config = new DeltaCommandConfiguration(schemaPath, Path.Combine(directory, "pair.json"),
                    source, disposable, disposablePlan, disposableAuth, disposableEvidence,
                    new string('a', 64), DateTimeOffset.UtcNow, new string('b', 64), new string('c', 64),
                    "local-aspire", "legacy-postgres-main-local", "generation-1", new string('d', 64),
                    new(DeltaTargetAuthorityKind.LocalAspire,
                        "aspire://legacy-postgres-main-local/disposable-pair-test", new string('e', 64)))
                {
                    AllowPlanSigning = true,
                    SourceMode = DeltaSourceMode.LiveReadOnly,
                    UseCapturedSource = true,
                    CaptureDirectory = captureDirectory,
                    CaptureKeyFile = captureKey,
                    PairedPersistentTarget = new(persistent, persistentPlan, persistentAuth,
                        persistentEvidence, "local-aspire", "legacy-postgres-main-local",
                        "generation-2", new string('f', 64),
                        new(DeltaTargetAuthorityKind.LocalAspire,
                            "aspire://legacy-postgres-main-local/persistent-pair-test", new string('0', 64))),
                };
                string configPath = Path.Combine(directory, "config.json");
                await MigrationConsole.WriteNewJsonForTestsAsync(configPath, new { delta = config },
                    CancellationToken.None);
                var runtime = new PairedRuntimeProbe();
                using var error = new StringWriter();

                int result = await MigrationConsole.RunDeltaForTestsAsync(
                    ["plan-paired-delta", "--config", configPath], TextWriter.Null, error,
                    name => name switch
                    {
                        "LEGACY_DEPLOY_ENABLED" => "false",
                        "LEGACY_MIGRATION_CALLER" => "owner",
                        "LEGACY_MIGRATION_DELTA_PLAN_SIGNING_KEY_FILE" => disposablePrivatePath,
                        "LEGACY_MIGRATION_PERSISTENT_DELTA_PLAN_SIGNING_KEY_FILE" => persistentPrivatePath,
                        _ => null,
                    }, runtime, CancellationToken.None);

                Assert.Equal(65, result);
                Assert.Equal("paired_runtime_probe_stop" + Environment.NewLine, error.ToString());
                Assert.Equal(1, runtime.PlanCalls);
                Assert.Equal(0, runtime.ApplyCalls);
                Assert.False(File.Exists(config.OutputPath));

                string transitionConfigPath = Path.Combine(directory, "transition-config.json");
                await MigrationConsole.WriteNewJsonForTestsAsync(transitionConfigPath,
                    new
                    {
                        delta = config with
                        {
                            OutputPath = Path.Combine(directory, "transition-pair.json"),
                            UseQuotationPhysicalTransition = true,
                        }
                    }, CancellationToken.None);
                using var transitionError = new StringWriter();
                int rejected = await MigrationConsole.RunDeltaForTestsAsync(
                    ["plan-paired-delta", "--config", transitionConfigPath], TextWriter.Null,
                    transitionError, name => name switch
                    {
                        "LEGACY_DEPLOY_ENABLED" => "false",
                        "LEGACY_MIGRATION_CALLER" => "owner",
                        _ => throw new InvalidOperationException("Transition must stop before key projection."),
                    }, runtime, CancellationToken.None);
                Assert.Equal(65, rejected);
                Assert.Equal("delta_paired_plan_request_invalid" + Environment.NewLine,
                    transitionError.ToString());
                Assert.Equal(1, runtime.PlanCalls);
            }
            finally
            {
                foreach (ECDsa key in otherKeys) { key.Dispose(); }
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task WriteOwnerOnlyAsync(string path, string value)
    {
        await WriteOwnerOnlyBytesAsync(path, Encoding.UTF8.GetBytes(value));
    }

    private static async Task WriteOwnerOnlyBytesAsync(string path, byte[] bytes)
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
        await using (var stream = new FileStream(path, options))
        {
            await stream.WriteAsync(bytes);
            await stream.FlushAsync();
        }
        Assert.True(OwnerProtectedFilePolicy.IsOwnerOnly(path));
    }

    private sealed class PairedRuntimeProbe : IGuardedDeltaConsoleRuntime, IGuardedPairedDeltaConsoleRuntime
    {
        public int PlanCalls { get; private set; }
        public int ApplyCalls { get; private set; }

        public Task<PairedCapturedDeltaPlans> PlanPairedAsync(DeltaPairedPlanRuntimeRequest request,
            CancellationToken cancellationToken)
        {
            PlanCalls++;
            Assert.Equal("source-placeholder", request.SourceConnectionString);
            Assert.Equal("disposable-placeholder", request.DisposableTargetConnectionString);
            Assert.Equal("persistent-placeholder", request.PersistentTargetConnectionString);
            Assert.Equal(32, request.CaptureKey.Length);
            Assert.NotEqual(request.DisposableSigner.PublicKeyFingerprintSha256,
                request.PersistentSigner.PublicKeyFingerprintSha256);
            throw new DeltaPlanException("paired_runtime_probe_stop", "Expected test stop before publication.");
        }

        public Task<DeltaSynchronizationPlan> PlanAsync(DeltaPlanRuntimeRequest request,
            CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("Wrong plan command.");
        }
        public Task<Exact23DeltaExecutionResult> ApplyAsync(DeltaApplyRuntimeRequest request,
            CancellationToken cancellationToken)
        {
            ApplyCalls++;
            throw new InvalidOperationException("Apply is forbidden in a paired plan.");
        }
        public Task<Exact23DeltaReconciliationResult> ReconcileAsync(DeltaReconcileRuntimeRequest request,
            CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("No reconciliation yet.");
        }
    }
}
