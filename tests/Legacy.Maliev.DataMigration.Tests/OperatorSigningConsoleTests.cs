using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class OperatorSigningConsoleTests : IDisposable
{
    private const string SourceCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private readonly string _root;
    private readonly ECDsa _backupKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _executionKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _provenanceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public OperatorSigningConsoleTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"legacy-operator-signing-{Guid.NewGuid():N}");
        OwnerProtectedDirectory.CreateNew(_root);
    }

    [Fact]
    public async Task AuthorizeShadow_ReviewedExactPlanPublishesVerifiableCreateOnlyReceipt()
    {
        SigningFixture fixture = await CreateAuthorizationFixtureAsync(allow: true);
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunAsync(
            ["authorize-shadow", "--config", fixture.ConfigPath], output, error,
            name => name switch
            {
                "LEGACY_DEPLOY_ENABLED" => "false",
                "LEGACY_MIGRATION_AUTHORIZATION_SIGNING_KEY_FILE" => fixture.AuthorizationKeyPath,
                _ => null,
            }, CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        Assert.Equal("authorize_shadow_complete" + Environment.NewLine, output.ToString());
        ExecutionAuthorizationReceipt receipt = JsonSerializer.Deserialize<ExecutionAuthorizationReceipt>(
            await File.ReadAllTextAsync(fixture.OutputPath), JsonOptions)!;
        Assert.Equal(fixture.PlanSha256, receipt.SchemaPlanSha256);
        Assert.Equal(fixture.BackupManifestSha256, receipt.BackupManifestSha256);
        Assert.Equal(DatabaseInventory.ActiveDatabases, receipt.AuthorizedDatabases);
        Assert.Equal("shadow-only", receipt.Mode);
        Assert.True(ExecutionAuthorizationAttestation.TryCreatePayload(receipt, out byte[] payload));
        Assert.True(_authorizationKey.VerifyData(
            payload, Convert.FromBase64String(receipt.AttestationSignature!), HashAlgorithmName.SHA256));

        int secondExit = await MigrationConsole.RunAsync(
            ["authorize-shadow", "--config", fixture.ConfigPath], TextWriter.Null, error,
            name => name switch
            {
                "LEGACY_DEPLOY_ENABLED" => "false",
                "LEGACY_MIGRATION_AUTHORIZATION_SIGNING_KEY_FILE" => fixture.AuthorizationKeyPath,
                _ => null,
            }, CancellationToken.None);
        Assert.Equal(65, secondExit);
        Assert.Equal("authorization_publication_failed" + Environment.NewLine, error.ToString());
    }

    [Fact]
    public async Task AuthorizeShadow_WithoutExplicitOwnerReviewFailsClosed()
    {
        SigningFixture fixture = await CreateAuthorizationFixtureAsync(allow: false);
        (int exitCode, string code) = await RunAuthorizationAsync(fixture);

        Assert.Equal(65, exitCode);
        Assert.Equal("authorization_owner_review_required", code);
        Assert.False(File.Exists(fixture.OutputPath));
    }

    [Fact]
    public async Task AuthorizeShadow_ReviewedDigestMismatchFailsClosed()
    {
        SigningFixture fixture = await CreateAuthorizationFixtureAsync(allow: true, reviewedPlanSha256: new string('0', 64));
        (int exitCode, string code) = await RunAuthorizationAsync(fixture);

        Assert.Equal(65, exitCode);
        Assert.Equal("authorization_reviewed_plan_mismatch", code);
        Assert.False(File.Exists(fixture.OutputPath));
    }

    [Fact]
    public async Task AuthorizeShadow_UnsignedBackupReceiptFailsClosed()
    {
        SigningFixture fixture = await CreateAuthorizationFixtureAsync(allow: true, unsignedBackup: true);
        (int exitCode, string code) = await RunAuthorizationAsync(fixture);

        Assert.Equal(65, exitCode);
        Assert.Equal("authorization_backup_receipt_invalid", code);
        Assert.False(File.Exists(fixture.OutputPath));
    }

    [Fact]
    public async Task AuthorizeShadow_StaleApprovalWindowFailsClosed()
    {
        SigningFixture fixture = await CreateAuthorizationFixtureAsync(
            allow: true, issuedAtUtc: Now.AddHours(-2), expiresAtUtc: Now.AddHours(-1));
        (int exitCode, string code) = await RunAuthorizationAsync(fixture);

        Assert.Equal(65, exitCode);
        Assert.Equal("authorization_time_window_invalid", code);
        Assert.False(File.Exists(fixture.OutputPath));
    }

    [Fact]
    public async Task AuthorizeShadow_BackupKeyReuseFailsClosed()
    {
        SigningFixture fixture = await CreateAuthorizationFixtureAsync(allow: true, reuseBackupKey: true);
        (int exitCode, string code) = await RunAuthorizationAsync(fixture);

        Assert.Equal(65, exitCode);
        Assert.Equal("authorization_key_role_reuse", code);
        Assert.False(File.Exists(fixture.OutputPath));
    }

    [Fact]
    public async Task SignProvenance_WithoutExplicitFinalizationApprovalStopsBeforeReadingArtifactsOrKey()
    {
        string configPath = Path.Combine(_root, "provenance-config.json");
        await WriteProtectedJsonAsync(configPath, new
        {
            signProvenance = new
            {
                outputPath = "must-not-be-written.json",
                reviewedSchemaPlanSha256 = Hash("reviewed"),
                issuedAtUtc = Now,
                keyId = "provenance-key",
                allowProvenanceSigning = false,
            },
        });
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunAsync(
            ["sign-provenance", "--config", configPath], output, error,
            name => name == "LEGACY_DEPLOY_ENABLED" ? "false" : null,
            CancellationToken.None);

        Assert.Equal(65, exitCode);
        Assert.Equal("provenance_owner_review_required" + Environment.NewLine, error.ToString());
        Assert.Equal(string.Empty, output.ToString());
    }

    [Theory]
    [InlineData(RestoreCleanupDisposition.Pending, 65, "provenance_cleanup_receipt_invalid")]
    [InlineData(RestoreCleanupDisposition.Removed, 0, "")]
    public async Task SignProvenance_RequiresCompletedCleanupAndPublishesVerifiableReceipt(
        RestoreCleanupDisposition cleanup,
        int expectedExit,
        string expectedError)
    {
        ProvenanceFixture fixture = await CreateProvenanceFixtureAsync(cleanup);
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunAsync(
            ["sign-provenance", "--config", fixture.ConfigPath], output, error,
            name => name switch
            {
                "LEGACY_DEPLOY_ENABLED" => "false",
                "LEGACY_MIGRATION_PROVENANCE_SIGNING_KEY_FILE" => fixture.ProvenanceKeyPath,
                _ => null,
            }, CancellationToken.None);

        Assert.Equal(expectedExit, exitCode);
        Assert.Equal(expectedError.Length == 0 ? string.Empty : expectedError + Environment.NewLine, error.ToString());
        if (expectedExit != 0)
        {
            Assert.False(File.Exists(fixture.OutputPath));
            return;
        }
        Assert.Equal("sign_provenance_complete" + Environment.NewLine, output.ToString());
        MigrationEvidenceProvenanceReceipt receipt = JsonSerializer.Deserialize<MigrationEvidenceProvenanceReceipt>(
            await File.ReadAllTextAsync(fixture.OutputPath), JsonOptions)!;
        Assert.True(MigrationEvidenceProvenanceAttestation.TryCreatePayload(receipt, out byte[] payload));
        Assert.True(_provenanceKey.VerifyData(
            payload, Convert.FromBase64String(receipt.AttestationSignature!), HashAlgorithmName.SHA256));
    }

    private static async Task<(int ExitCode, string Code)> RunAuthorizationAsync(SigningFixture fixture)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        int exitCode = await MigrationConsole.RunAsync(
            ["authorize-shadow", "--config", fixture.ConfigPath], output, error,
            name => name switch
            {
                "LEGACY_DEPLOY_ENABLED" => "false",
                "LEGACY_MIGRATION_AUTHORIZATION_SIGNING_KEY_FILE" => fixture.AuthorizationKeyPath,
                _ => null,
            }, CancellationToken.None);
        return (exitCode, error.ToString().Trim());
    }

    private async Task<SigningFixture> CreateAuthorizationFixtureAsync(
        bool allow,
        string? reviewedPlanSha256 = null,
        bool unsignedBackup = false,
        DateTimeOffset? issuedAtUtc = null,
        DateTimeOffset? expiresAtUtc = null,
        bool reuseBackupKey = false)
    {
        FreshSchemaPlan plan = CreatePlan();
        string planSha256 = SchemaPlanCanonicalizer.ComputeSha256(plan);
        BackupReceipt backup = CreateBackupReceipt(unsignedBackup);
        string planPath = Path.Combine(_root, $"plan-{Guid.NewGuid():N}.json");
        string receiptPath = Path.Combine(_root, $"receipt-{Guid.NewGuid():N}.json");
        string trustPath = Path.Combine(_root, $"backup-{Guid.NewGuid():N}.spki");
        string keyPath = Path.Combine(_root, $"authorization-{Guid.NewGuid():N}.pem");
        string outputPath = Path.Combine(_root, $"authorization-{Guid.NewGuid():N}.json");
        string configPath = Path.Combine(_root, $"config-{Guid.NewGuid():N}.json");
        await WriteProtectedJsonAsync(planPath, plan);
        await WriteProtectedJsonAsync(receiptPath, backup);
        await WriteProtectedTextAsync(trustPath, Convert.ToBase64String(_backupKey.ExportSubjectPublicKeyInfo()));
        await WriteProtectedTextAsync(keyPath, reuseBackupKey ? _backupKey.ExportECPrivateKeyPem() : _authorizationKey.ExportECPrivateKeyPem());
        await WriteProtectedJsonAsync(configPath, new
        {
            authorizeShadow = new
            {
                receiptPath,
                planPath,
                outputPath,
                expectedSourceCommitSha = SourceCommit,
                reviewedSchemaPlanSha256 = reviewedPlanSha256 ?? planSha256,
                runnerDigestSha256 = Hash("runner"),
                targetGeneration = "review-20260830-a",
                issuedAtUtc = issuedAtUtc ?? Now.AddMinutes(-1),
                expiresAtUtc = expiresAtUtc ?? Now.AddMinutes(30),
                keyId = "authorization-key",
                receiptTrustedKeys = new[] { new { keyId = "backup-key", subjectPublicKeyInfoPath = trustPath } },
                maximumReceiptAgeMinutes = 180d,
                allowShadowAuthorization = allow,
            },
        });
        return new(configPath, outputPath, keyPath, planSha256, backup.ManifestSha256!);
    }

    private async Task<ProvenanceFixture> CreateProvenanceFixtureAsync(RestoreCleanupDisposition cleanup)
    {
        FreshSchemaPlan plan = CreatePlan();
        BackupReceipt backup = CreateBackupReceipt(unsigned: false);
        string planSha256 = SchemaPlanCanonicalizer.ComputeSha256(plan);
        const string runnerDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const string targetGeneration = "review-20260830-a";
        using var authorizationSigner = new P256MigrationEvidenceSigner("authorization-key", _authorizationKey.ExportECPrivateKeyPem());
        var backupTrust = new ReceiptAttestationTrustStore([new("backup-key", _backupKey.ExportSubjectPublicKeyInfo())]);
        ExecutionAuthorizationReceipt authorization = ReviewedExecutionAuthorizationProducer.Produce(
            new(SourceCommit, planSha256, runnerDigest, targetGeneration, Now.AddMinutes(-5), Now.AddMinutes(30), true, 180),
            backup, plan, backupTrust, authorizationSigner, Now);

        IReadOnlyList<MigratedShadowDatabase> migrated = [.. DatabaseInventory.ActiveDatabases.Select((database, index) =>
            new MigratedShadowDatabase(database, $"legacy_shadow_db_{index}_{new string((char)('a' + (index % 6)), 32)}", 0, Hash($"content:{database}")))];
        IReadOnlyList<DatabaseReconciliationEvidence> reconciliation = [.. DatabaseInventory.ActiveDatabases.Select(database =>
            new DatabaseReconciliationEvidence(database, Hash($"source:{database}"), Hash($"target:{database}"), []))];
        var unsignedExecution = new MigrationExecutionReceipt(
            authorization.RunId, SourceCommit, planSha256, backup.ManifestSha256!, runnerDigest, targetGeneration,
            Now.AddMinutes(-2), migrated, reconciliation, "execution-key", null);
        MigrationExecutionReceipt execution = unsignedExecution with
        {
            AttestationSignature = Convert.ToBase64String(_executionKey.SignData(
                MigrationEvidenceAttestation.CreatePayload(unsignedExecution), HashAlgorithmName.SHA256)),
        };
        var result = new MigrationExecutionResult(MigrationExecutionStatus.Completed, execution);

        const string digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        var unsignedRestore = new VerifiedRestoreReceipt(
            "1.0", Now.AddMinutes(-20), DatabaseInventory.InventorySha256, backup.ManifestSha256!,
            new(
                "mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04@sha256:" + digest,
                "sha256:" + digest,
                "sha256:" + new string('b', 64),
                "legacy-sql-run-1", "run-1", "legacy-volume-run-1", "legacy-volume-run-1",
                "legacy-volume-binding", new string('d', 64), "/var/opt/mssql/backup", true,
                "alpine:3.20@sha256:" + new string('c', 64), "16"),
            [.. DatabaseInventory.ActiveDatabases.Select(database =>
                new VerifiedRestoreArtifactEvidence(database, 42, digest, 42, digest, true, true, true))],
            cleanup,
            cleanup == RestoreCleanupDisposition.Removed ? Now.AddMinutes(-3) : null,
            "provenance-key",
            null);
        VerifiedRestoreReceipt restore = VerifiedRestoreReceiptAttestation.Sign(unsignedRestore, _provenanceKey);

        string planPath = Path.Combine(_root, $"provenance-plan-{Guid.NewGuid():N}.json");
        string receiptPath = Path.Combine(_root, $"provenance-backup-{Guid.NewGuid():N}.json");
        string authorizationPath = Path.Combine(_root, $"provenance-authorization-{Guid.NewGuid():N}.json");
        string executionPath = Path.Combine(_root, $"provenance-execution-{Guid.NewGuid():N}.json");
        string restorePath = Path.Combine(_root, $"provenance-restore-{Guid.NewGuid():N}.json");
        string outputPath = Path.Combine(_root, $"provenance-output-{Guid.NewGuid():N}.json");
        string configPath = Path.Combine(_root, $"provenance-config-{Guid.NewGuid():N}.json");
        string provenanceKeyPath = Path.Combine(_root, $"provenance-key-{Guid.NewGuid():N}.pem");
        string backupTrustPath = Path.Combine(_root, $"backup-trust-{Guid.NewGuid():N}.spki");
        string authorizationTrustPath = Path.Combine(_root, $"authorization-trust-{Guid.NewGuid():N}.spki");
        string executionTrustPath = Path.Combine(_root, $"execution-trust-{Guid.NewGuid():N}.spki");
        string provenanceTrustPath = Path.Combine(_root, $"provenance-trust-{Guid.NewGuid():N}.spki");
        await WriteProtectedJsonAsync(planPath, plan);
        await WriteProtectedJsonAsync(receiptPath, backup);
        await WriteProtectedJsonAsync(authorizationPath, authorization);
        await WriteProtectedJsonAsync(executionPath, result);
        await WriteProtectedJsonAsync(restorePath, restore);
        await WriteProtectedTextAsync(provenanceKeyPath, _provenanceKey.ExportECPrivateKeyPem());
        await WriteProtectedTextAsync(backupTrustPath, Convert.ToBase64String(_backupKey.ExportSubjectPublicKeyInfo()));
        await WriteProtectedTextAsync(authorizationTrustPath, Convert.ToBase64String(_authorizationKey.ExportSubjectPublicKeyInfo()));
        await WriteProtectedTextAsync(executionTrustPath, Convert.ToBase64String(_executionKey.ExportSubjectPublicKeyInfo()));
        await WriteProtectedTextAsync(provenanceTrustPath, Convert.ToBase64String(_provenanceKey.ExportSubjectPublicKeyInfo()));
        object[] BackupKeys()
        {
            return [new { keyId = "backup-key", subjectPublicKeyInfoPath = backupTrustPath }];
        }

        object[] AuthorizationKeys()
        {
            return [new { keyId = "authorization-key", subjectPublicKeyInfoPath = authorizationTrustPath }];
        }

        object[] ExecutionKeys()
        {
            return [new { keyId = "execution-key", subjectPublicKeyInfoPath = executionTrustPath }];
        }

        object[] ProvenanceKeys()
        {
            return [new { keyId = "provenance-key", subjectPublicKeyInfoPath = provenanceTrustPath }];
        }

        await WriteProtectedJsonAsync(configPath, new
        {
            signProvenance = new
            {
                outputPath,
                reviewedSchemaPlanSha256 = planSha256,
                issuedAtUtc = Now.AddMinutes(-1),
                keyId = "provenance-key",
                allowProvenanceSigning = true,
            },
            evidence = new
            {
                executionResultPath = executionPath,
                provenancePath = outputPath,
                receiptPath,
                planPath,
                authorizationPath,
                publicationDirectory = Path.Combine(_root, $"evidence-{Guid.NewGuid():N}"),
                sourceSnapshotId = authorization.RunId.ToString("D"),
                backupUri = "gs://maliev.com/database/full/2026-08-30/run-1/",
                backupObjectGeneration = "generation-20260830",
                restoreId = "restore-current",
                evidenceId = Guid.NewGuid(),
                leaseId = Guid.NewGuid(),
                leaseAcquiredAtUtc = Now.AddMinutes(-10),
                leaseExpiresAtUtc = Now.AddMinutes(20),
                backupTrustedKeys = BackupKeys(),
                authorizationTrustedKeys = AuthorizationKeys(),
                executionTrustedKeys = ExecutionKeys(),
                provenanceTrustedKeys = ProvenanceKeys(),
                evidenceKeyId = "final-evidence-key",
                verifiedRestoreReceiptPath = restorePath,
            },
        });
        return new(configPath, outputPath, provenanceKeyPath);
    }

    private BackupReceipt CreateBackupReceipt(bool unsigned)
    {
        List<BackupArtifact?> artifacts = [.. DatabaseInventory.ActiveDatabases.Select(database =>
        {
            string hash = Hash(database);
            return (BackupArtifact?)new BackupArtifact(database, "Full", $"Full_{database}_run-1.bak", 1024, hash, hash)
            {
                CompletedAtUtc = Now.AddMinutes(-30),
                GcsObject = $"database/full/2026-08-30/run-1/Full_{database}_run-1.bak",
                GcsGeneration = 1,
                GcsSha256 = hash,
            };
        })];
        string manifest = Hash(string.Join('\n', artifacts.Select(Assert.IsType<BackupArtifact>)
            .OrderBy(item => item.Database, StringComparer.Ordinal)
            .Select(item => string.Join('|', item.Database, item.BackupType, item.FileName, item.ByteLength,
                item.Sha256!.ToLowerInvariant(), item.ObservedSha256!.ToLowerInvariant()))));
        var receipt = new BackupReceipt("1.1", Now.AddMinutes(-30), DatabaseInventory.InventorySha256,
            manifest, artifacts, "backup-key", null)
        { SourceObservedAtUtc = Now.AddMinutes(-40) };
        Assert.True(ReceiptAttestation.TryCreatePayload(receipt, out byte[] payload));
        return unsigned ? receipt : receipt with
        {
            AttestationSignature = Convert.ToBase64String(_backupKey.SignData(payload, HashAlgorithmName.SHA256)),
        };
    }

    private static FreshSchemaPlan CreatePlan()
    {
        return new(
        "2.0", Now.AddMinutes(-2), SourceCommit,
        [.. DatabaseInventory.ActiveDatabases.Select(database => new DatabaseSchemaPlan(
            database, "1.0", Hash($"source:{database}"), Hash($"target:{database}"),
            [new TableCopyPlan("dbo", "Primary", "public", "Primary", ["ID", "Value"], ["ID"])
            {
                SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["ID"] = "int", ["Value"] = "nvarchar",
                },
                SourceColumns = [new("ID", "int", Hash("ID:int"), null), new("Value", "nvarchar", Hash("Value:nvarchar"), null)],
                ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["ID"] = "integer", ["Value"] = "text",
                },
                PrimaryKey = new("PK_Primary", ["ID"]),
            }]))]);
    }

    private static string Hash(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    private static JsonSerializerOptions JsonOptions { get; } = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    private static async Task WriteProtectedJsonAsync<T>(string path, T value)
    {
        await WriteProtectedTextAsync(path, JsonSerializer.Serialize(value, JsonOptions));
    }

    private static async Task WriteProtectedTextAsync(string path, string value)
    {
        await File.WriteAllTextAsync(path, value);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    public void Dispose()
    {
        _backupKey.Dispose();
        _authorizationKey.Dispose();
        _executionKey.Dispose();
        _provenanceKey.Dispose();
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed record SigningFixture(
        string ConfigPath,
        string OutputPath,
        string AuthorizationKeyPath,
        string PlanSha256,
        string BackupManifestSha256);

    private sealed record ProvenanceFixture(string ConfigPath, string OutputPath, string ProvenanceKeyPath);
}
