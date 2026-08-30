using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class AppHostMigrationEvidenceV2ProducerTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly ECDsa _backupKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _executionKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _provenanceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly DateTimeOffset _now = DateTimeOffset.UtcNow;
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"legacy-evidence-v2-{Guid.NewGuid():N}");

    [Fact]
    public void Produce_EmitsExactSignedAppHostSchemaV2WithoutEqualizingEngineSchemaHashes()
    {
        EvidenceFixture fixture = CreateFixture();

        AppHostMigrationEvidenceV2Document document = AppHostMigrationEvidenceV2Producer.Produce(
            fixture.Request,
            fixture.BackupTrust,
            fixture.AuthorizationTrust,
            fixture.ExecutionTrust,
            fixture.ProvenanceTrust,
            new P256MigrationEvidenceSigner("review-evidence", _evidenceKey.ExportECPrivateKeyPem()),
            new FixedTimeProvider(_now));

        using JsonDocument evidence = JsonDocument.Parse(document.EvidenceJson);
        JsonElement root = evidence.RootElement;
        Assert.Equal(2, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(25, root.GetProperty("databases").GetArrayLength());
        Assert.Equal(27, root.GetProperty("inventory").GetArrayLength());
        Assert.Empty(root.GetProperty("archives").EnumerateArray());
        Assert.All(root.GetProperty("databases").EnumerateArray(), database =>
        {
            Assert.NotEqual(
                database.GetProperty("sourceSchemaSha256").GetString(),
                database.GetProperty("targetSchemaSha256").GetString());
            Assert.Equal("exact", database.GetProperty("parity").GetString());
        });

        JsonElement attestation = root.GetProperty("attestation");
        byte[] payload = AppHostMigrationEvidenceV2Canonicalizer.CreatePayload(root);
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant(),
            attestation.GetProperty("payloadSha256").GetString());
        Assert.True(_evidenceKey.VerifyData(
            payload,
            Convert.FromBase64String(attestation.GetProperty("signatureBase64").GetString()!),
            HashAlgorithmName.SHA256));

        using JsonDocument baseline = JsonDocument.Parse(document.ApprovedBaselineJson);
        Assert.Equal(2, baseline.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(25, baseline.RootElement.GetProperty("databases").GetArrayLength());
    }

    [Fact]
    public void Produce_MissingRelationshipCountsFailsClosed()
    {
        EvidenceFixture fixture = CreateFixture(includeForeignKey: true, includeRelationshipEvidence: false);

        MigrationEvidenceProductionException exception = Assert.Throws<MigrationEvidenceProductionException>(() =>
            AppHostMigrationEvidenceV2Producer.Produce(
                fixture.Request,
                fixture.BackupTrust,
                fixture.AuthorizationTrust,
                fixture.ExecutionTrust,
                fixture.ProvenanceTrust,
                new P256MigrationEvidenceSigner("review-evidence", _evidenceKey.ExportECPrivateKeyPem()),
                new FixedTimeProvider(_now)));

        Assert.Equal("relationship_evidence_missing", exception.Code);
    }

    [Fact]
    public void Produce_MissingObservedSequenceFailsClosed()
    {
        EvidenceFixture fixture = CreateFixture(includeIdentity: true, includeSequenceEvidence: false);

        MigrationEvidenceProductionException exception = Assert.Throws<MigrationEvidenceProductionException>(() =>
            AppHostMigrationEvidenceV2Producer.Produce(
                fixture.Request,
                fixture.BackupTrust,
                fixture.AuthorizationTrust,
                fixture.ExecutionTrust,
                fixture.ProvenanceTrust,
                new P256MigrationEvidenceSigner("review-evidence", _evidenceKey.ExportECPrivateKeyPem()),
                new FixedTimeProvider(_now)));

        Assert.Equal("sequence_evidence_missing", exception.Code);
    }

    [Fact]
    public void Produce_DatabaseSummaryHashDoesNotMatchTableEvidenceFailsClosed()
    {
        EvidenceFixture fixture = CreateFixture(includeInvalidDatabaseContentHash: true);

        MigrationEvidenceProductionException exception = Assert.Throws<MigrationEvidenceProductionException>(() =>
            AppHostMigrationEvidenceV2Producer.Produce(
                fixture.Request,
                fixture.BackupTrust,
                fixture.AuthorizationTrust,
                fixture.ExecutionTrust,
                fixture.ProvenanceTrust,
                new P256MigrationEvidenceSigner("review-evidence", _evidenceKey.ExportECPrivateKeyPem()),
                new FixedTimeProvider(_now)));

        Assert.Equal("database_evidence_invalid", exception.Code);
    }

    [Fact]
    public void Produce_UnsignedConfigurationDoesNotMatchSignedProvenanceFailsClosed()
    {
        EvidenceFixture fixture = CreateFixture();
        AppHostMigrationEvidenceV2Request mismatched = fixture.Request with
        {
            Configuration = fixture.Request.Configuration with { RestoreId = "unsigned-override" },
        };

        MigrationEvidenceProductionException exception = Assert.Throws<MigrationEvidenceProductionException>(() =>
            AppHostMigrationEvidenceV2Producer.Produce(
                mismatched,
                fixture.BackupTrust,
                fixture.AuthorizationTrust,
                fixture.ExecutionTrust,
                fixture.ProvenanceTrust,
                new P256MigrationEvidenceSigner("review-evidence", _evidenceKey.ExportECPrivateKeyPem()),
                new FixedTimeProvider(_now)));

        Assert.Equal("provenance_binding_invalid", exception.Code);
    }

    [Fact]
    public void Produce_InvalidProvenanceSignatureCannotUseEvidenceSignerAsSigningOracle()
    {
        EvidenceFixture fixture = CreateFixture();
        AppHostMigrationEvidenceV2Request tampered = fixture.Request with
        {
            Provenance = fixture.Request.Provenance with { BackupObjectGeneration = "unsigned-override" },
            Configuration = fixture.Request.Configuration with { BackupObjectGeneration = "unsigned-override" },
        };

        MigrationEvidenceProductionException exception = Assert.Throws<MigrationEvidenceProductionException>(() =>
            AppHostMigrationEvidenceV2Producer.Produce(
                tampered,
                fixture.BackupTrust,
                fixture.AuthorizationTrust,
                fixture.ExecutionTrust,
                fixture.ProvenanceTrust,
                new P256MigrationEvidenceSigner("review-evidence", _evidenceKey.ExportECPrivateKeyPem()),
                new FixedTimeProvider(_now)));

        Assert.Equal("provenance_receipt_invalid", exception.Code);
    }

    [Fact]
    public void Produce_SignedBackupArtifactOutsideSignedProvenanceFailsClosed()
    {
        EvidenceFixture fixture = CreateFixture();
        BackupArtifact?[] artifacts = fixture.Request.BackupReceipt.Artifacts!
            .Select((artifact, index) => index == 0 ? artifact! with { GcsObject = "database/full/unrelated/backup.bak" } : artifact)
            .ToArray();
        BackupReceipt backup = SignBackupReceipt(fixture.Request.BackupReceipt with
        {
            Artifacts = artifacts,
            AttestationSignature = null,
        });
        AppHostMigrationEvidenceV2Request mismatched = fixture.Request with { BackupReceipt = backup };

        MigrationEvidenceProductionException exception = Assert.Throws<MigrationEvidenceProductionException>(() =>
            AppHostMigrationEvidenceV2Producer.Produce(
                mismatched,
                fixture.BackupTrust,
                fixture.AuthorizationTrust,
                fixture.ExecutionTrust,
                fixture.ProvenanceTrust,
                new P256MigrationEvidenceSigner("review-evidence", _evidenceKey.ExportECPrivateKeyPem()),
                new FixedTimeProvider(_now)));

        Assert.Equal("provenance_binding_invalid", exception.Code);
    }

    [Fact]
    public void Produce_DifferentKeyIdsWithSameProvenanceAndEvidenceKeyFailsBeforeSigning()
    {
        EvidenceFixture fixture = CreateFixture();
        using var sameMaterialEvidenceSigner = new P256MigrationEvidenceSigner(
            "different-evidence-key-id",
            _provenanceKey.ExportECPrivateKeyPem());

        MigrationEvidenceProductionException exception = Assert.Throws<MigrationEvidenceProductionException>(() =>
            AppHostMigrationEvidenceV2Producer.Produce(
                fixture.Request,
                fixture.BackupTrust,
                fixture.AuthorizationTrust,
                fixture.ExecutionTrust,
                fixture.ProvenanceTrust,
                sameMaterialEvidenceSigner,
                new FixedTimeProvider(_now)));

        Assert.Equal("attestation_key_role_reuse", exception.Code);
    }

    [Fact]
    public async Task ConsoleEvidenceStage_WritesVerifierCompatibleEvidenceAndReviewBaseline()
    {
        _ = Directory.CreateDirectory(_root);
        EvidenceFixture fixture = CreateFixture();
        string executionPath = await WriteJsonAsync("execution.json", fixture.Request.ExecutionResult);
        string provenancePath = await WriteJsonAsync("provenance.json", fixture.Request.Provenance);
        string receiptPath = await WriteJsonAsync("receipt.json", fixture.Request.BackupReceipt);
        string planPath = await WriteJsonAsync("plan.json", fixture.Request.SchemaPlan);
        string authorizationPath = await WriteJsonAsync("authorization.json", fixture.Request.Authorization);
        string backupKeyPath = await WriteTextAsync("backup-public.txt", Convert.ToBase64String(_backupKey.ExportSubjectPublicKeyInfo()));
        string authorizationKeyPath = await WriteTextAsync("authorization-public.txt", Convert.ToBase64String(_authorizationKey.ExportSubjectPublicKeyInfo()));
        string executionKeyPath = await WriteTextAsync("execution-public.txt", Convert.ToBase64String(_executionKey.ExportSubjectPublicKeyInfo()));
        string provenanceKeyPath = await WriteTextAsync("provenance-public.txt", Convert.ToBase64String(_provenanceKey.ExportSubjectPublicKeyInfo()));
        string provenancePrivateKeyPath = await WriteTextAsync("provenance-private.pem", _provenanceKey.ExportECPrivateKeyPem());
        string signingKeyPath = await WriteTextAsync("evidence-private.pem", _evidenceKey.ExportECPrivateKeyPem());
        string publicationDirectory = Path.Combine(_root, "publication");
        string outputPath = Path.Combine(publicationDirectory, "evidence.json");
        string baselinePath = Path.Combine(publicationDirectory, "approved-baseline.json");
        AppHostMigrationEvidenceV2Configuration producer = fixture.Request.Configuration;
        string configPath = await WriteJsonAsync("config.json", new
        {
            evidence = new
            {
                executionResultPath = executionPath,
                provenancePath,
                receiptPath,
                planPath,
                authorizationPath,
                publicationDirectory,
                sourceSnapshotId = producer.SourceSnapshotId,
                backupUri = producer.BackupUri,
                backupObjectGeneration = producer.BackupObjectGeneration,
                restoreId = producer.RestoreId,
                evidenceId = producer.EvidenceId,
                leaseId = producer.LeaseId,
                leaseAcquiredAtUtc = producer.LeaseAcquiredAtUtc,
                leaseExpiresAtUtc = producer.LeaseExpiresAtUtc,
                backupTrustedKeys = new[] { new { keyId = "backup-key", subjectPublicKeyInfoPath = backupKeyPath } },
                authorizationTrustedKeys = new[] { new { keyId = "authorization-key", subjectPublicKeyInfoPath = authorizationKeyPath } },
                executionTrustedKeys = new[] { new { keyId = "execution-key", subjectPublicKeyInfoPath = executionKeyPath } },
                provenanceTrustedKeys = new[] { new { keyId = "provenance-key", subjectPublicKeyInfoPath = provenanceKeyPath } },
                evidenceKeyId = "review-evidence",
            },
        });
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunAsync(
            ["evidence", "--config", configPath],
            output,
            error,
            name => name == "LEGACY_MIGRATION_EVIDENCE_SIGNING_KEY_FILE" ? signingKeyPath : null,
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal("evidence_complete" + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
        Assert.True(File.Exists(outputPath));
        Assert.True(File.Exists(baselinePath));
        string evidenceJson = await File.ReadAllTextAsync(outputPath);
        Assert.DoesNotContain("PRIVATE KEY", evidenceJson, StringComparison.Ordinal);
        Assert.DoesNotContain(_root, evidenceJson, StringComparison.OrdinalIgnoreCase);

        string? appHostRoot = Environment.GetEnvironmentVariable("MALIEV_APPHOST_ROOT");
        if (!string.IsNullOrWhiteSpace(appHostRoot))
        {
            string publicKeyPath = await WriteTextAsync("evidence-public.pem", _evidenceKey.ExportSubjectPublicKeyInfoPem());
            string baselineHash = Hash(await File.ReadAllTextAsync(baselinePath));
            var startInfo = new ProcessStartInfo("pwsh")
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            };
            foreach (string argument in new[]
            {
                "-NoLogo", "-NoProfile", "-File", Path.Combine(appHostRoot, "scripts", "verify-postgres-migration-evidence.ps1"),
                "-EvidencePath", outputPath,
                "-ExpectedDatabase", string.Join(',', DatabaseInventory.ActiveDatabases),
                "-RequiredAsOfUtc", _now.AddMinutes(-30).ToString("O"),
                "-TrustedPublicKeyPath", publicKeyPath,
                "-ExpectedAttestationKeyId", "review-evidence",
                "-ApprovedBaselinePath", baselinePath,
                "-ExpectedApprovedBaselineSha256", baselineHash,
                "-ConsumptionLedgerPath", Path.Combine(_root, "consumed"),
                "-ExpectedRunId", fixture.Request.ExecutionResult.Receipt.RunId.ToString("D"),
                "-ExpectedTargetGeneration", fixture.Request.ExecutionResult.Receipt.TargetGeneration,
                "-ExpectedRestoreId", producer.RestoreId,
            })
            {
                startInfo.ArgumentList.Add(argument);
            }

            using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException("PowerShell could not be started.");
            string standardError = await process.StandardError.ReadToEndAsync();
            string standardOutput = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            Assert.True(process.ExitCode == 0, standardError + standardOutput);
        }

        Directory.Delete(publicationDirectory, recursive: true);
        using var reusedKeyOutput = new StringWriter();
        using var reusedKeyError = new StringWriter();
        int reusedKeyExitCode = await MigrationConsole.RunAsync(
            ["evidence", "--config", configPath],
            reusedKeyOutput,
            reusedKeyError,
            name => name == "LEGACY_MIGRATION_EVIDENCE_SIGNING_KEY_FILE" ? provenancePrivateKeyPath : null,
            CancellationToken.None);

        Assert.Equal(65, reusedKeyExitCode);
        Assert.Equal(string.Empty, reusedKeyOutput.ToString());
        Assert.Equal("attestation_key_role_reuse" + Environment.NewLine, reusedKeyError.ToString());
        Assert.False(Directory.Exists(publicationDirectory));

        await File.WriteAllTextAsync(publicationDirectory, "blocked publication destination");
        using var rejectedOutput = new StringWriter();
        using var rejectedError = new StringWriter();
        int rejectedExitCode = await MigrationConsole.RunAsync(
            ["evidence", "--config", configPath],
            rejectedOutput,
            rejectedError,
            name => name == "LEGACY_MIGRATION_EVIDENCE_SIGNING_KEY_FILE" ? signingKeyPath : null,
            CancellationToken.None);

        Assert.Equal(65, rejectedExitCode);
        Assert.Equal(string.Empty, rejectedOutput.ToString());
        Assert.Equal("evidence_publication_failed" + Environment.NewLine, rejectedError.ToString());
        Assert.False(File.Exists(outputPath));
        Assert.False(File.Exists(baselinePath));
        Assert.Empty(Directory.EnumerateFileSystemEntries(_root, ".publication.*.tmp", SearchOption.TopDirectoryOnly));
    }

    [Fact]
    public async Task EvidencePublication_SecondArtifactFailureLeavesNoPublishedOrStagedArtifacts()
    {
        _ = Directory.CreateDirectory(_root);
        string publicationDirectory = Path.Combine(_root, "publication");
        int writes = 0;

        _ = await Assert.ThrowsAsync<IOException>(() => MigrationEvidencePublication.PublishAsync(
            new AppHostMigrationEvidenceV2Document("evidence", "baseline"),
            publicationDirectory,
            async (path, content, cancellationToken) =>
            {
                writes++;
                if (writes == 2)
                {
                    throw new IOException("simulated baseline failure");
                }

                await File.WriteAllTextAsync(path, content, cancellationToken);
            },
            CancellationToken.None));

        Assert.Equal(2, writes);
        Assert.False(Directory.Exists(publicationDirectory));
        Assert.Empty(Directory.EnumerateFileSystemEntries(_root, ".publication.*.tmp", SearchOption.TopDirectoryOnly));
    }

    private EvidenceFixture CreateFixture(
        bool includeForeignKey = false,
        bool includeRelationshipEvidence = true,
        bool includeIdentity = false,
        bool includeSequenceEvidence = true,
        bool includeInvalidDatabaseContentHash = false)
    {
        string sourceCommit = new('a', 40);
        string runnerDigest = new('b', 64);
        string manifestHash = new('c', 64);
        List<DatabaseSchemaPlan> databasePlans = [];
        List<DatabaseReconciliationEvidence> reconciliations = [];
        List<MigratedShadowDatabase> migrated = [];
        foreach ((string database, int index) in DatabaseInventory.ActiveDatabases.Select((name, index) => (name, index)))
        {
            string targetSchema = $"legacy_{index}";
            var foreignKeys = includeForeignKey && index == 0
                ? new[]
                {
                    new ForeignKeyCopyPlan("FK_Parent", ["ParentId"], targetSchema, "Records", ["Id"])
                    {
                        SourceReferencedSchema = "dbo",
                        SourceReferencedTable = "Records",
                        SourceReferencedColumns = ["Id"],
                    },
                }
                : [];
            string[] columns = includeForeignKey && index == 0 ? ["Id", "ParentId"] : ["Id"];
            var table = new TableCopyPlan("dbo", "Records", targetSchema, "Records", columns, ["Id"])
            {
                BatchSize = 512,
                ColumnTypes = columns.ToDictionary(column => column, _ => "bigint", StringComparer.Ordinal),
                SourceColumnTypes = columns.ToDictionary(column => column, _ => "bigint", StringComparer.Ordinal),
                SourceColumns = columns.Select(column => new SourceColumnInventory(column, "bigint", new string('d', 64), 8)).ToArray(),
                NullableColumns = includeForeignKey && index == 0 ? ["ParentId"] : [],
                ForeignKeys = foreignKeys,
                PrimaryKey = new PrimaryKeyCopyPlan("PK_Records", ["Id"]),
                IdentityColumns = includeIdentity && index == 0 ? ["Id"] : [],
                Identities = includeIdentity && index == 0 ? [new IdentityCopyPlan("Id", 1, 1, 10, true)] : [],
            };
            string sourceSchemaHash = Hash($"source:{database}");
            string targetSchemaHash = Hash($"target:{database}");
            databasePlans.Add(new(database, "1.0", sourceSchemaHash, targetSchemaHash, [table]));

            var relationships = includeForeignKey && index == 0 && includeRelationshipEvidence
                ? new ReadOnlyDictionary<string, long>(new Dictionary<string, long>(StringComparer.Ordinal) { ["FK_Parent"] = 1 })
                : new ReadOnlyDictionary<string, long>(new Dictionary<string, long>(StringComparer.Ordinal));
            var orphans = includeForeignKey && index == 0
                ? new ReadOnlyDictionary<string, long>(new Dictionary<string, long>(StringComparer.Ordinal) { ["FK_Parent"] = 0 })
                : new ReadOnlyDictionary<string, long>(new Dictionary<string, long>(StringComparer.Ordinal));
            var tableEvidence = new TableReconciliationEvidence(
                $"{targetSchema}.Records",
                2,
                Hash($"content:{database}"),
                Hash($"aggregate:{database}"),
                new ReadOnlyDictionary<string, long>(columns.ToDictionary(column => column, _ => 0L, StringComparer.Ordinal)),
                orphans)
            {
                ForeignKeyRelationshipCounts = relationships,
            };
            var sequences = includeIdentity && index == 0 && includeSequenceEvidence
                ? new ReadOnlyDictionary<string, long>(new Dictionary<string, long>(StringComparer.Ordinal)
                {
                    [$"{targetSchema}.Records.Id"] = 11,
                })
                : new ReadOnlyDictionary<string, long>(new Dictionary<string, long>(StringComparer.Ordinal));
            reconciliations.Add(new(database, sourceSchemaHash, targetSchemaHash, [tableEvidence])
            {
                SequenceNextValues = sequences,
            });
            string canonicalTableEvidence = $"{tableEvidence.Table}|{tableEvidence.RowCount}|{tableEvidence.ContentSha256}|{tableEvidence.AggregateSha256}";
            migrated.Add(new(
                database,
                $"shadow_{index}",
                2,
                includeInvalidDatabaseContentHash && index == 0 ? Hash($"invalid:{database}") : Hash(canonicalTableEvidence)));
        }

        var plan = new FreshSchemaPlan("2.0", _now.AddMinutes(-20), sourceCommit, databasePlans);
        string planHash = SchemaPlanCanonicalizer.ComputeSha256(plan);
        BackupReceipt backup = SignBackupReceipt(new(
            "1.1",
            _now.AddMinutes(-25),
            DatabaseInventory.InventorySha256,
            manifestHash,
            DatabaseInventory.ActiveDatabases.Select((database, index) => (BackupArtifact?)new BackupArtifact(
                database,
                "FULL",
                $"Full_{database}.bak",
                100 + index,
                Hash($"backup:{database}"),
                Hash($"backup:{database}"))
            {
                GcsObject = $"database/full/2026-08-30/{database}.bak",
                GcsGeneration = index + 1,
                GcsSha256 = Hash($"backup:{database}"),
                CompletedAtUtc = _now.AddMinutes(-25),
            }).ToArray(),
            "backup-key",
            null)
        {
            SourceObservedAtUtc = _now.AddMinutes(-26),
        });
        ExecutionAuthorizationReceipt authorization = SignAuthorization(new(
            "2.0",
            Guid.Parse("11111111-1111-4111-8111-111111111111"),
            _now.AddMinutes(-15),
            _now.AddMinutes(30),
            sourceCommit,
            planHash,
            manifestHash,
            runnerDigest,
            "shadow-generation-1",
            DatabaseInventory.ActiveDatabases,
            "shadow-only",
            "authorization-key",
            null));
        MigrationExecutionReceipt executionReceipt = SignExecution(new(
            authorization.RunId,
            sourceCommit,
            planHash,
            manifestHash,
            runnerDigest,
            "shadow-generation-1",
            _now.AddMinutes(-5),
            migrated,
            reconciliations,
            "execution-key",
            null));
        var result = new MigrationExecutionResult(MigrationExecutionStatus.Completed, executionReceipt);
        var configuration = new AppHostMigrationEvidenceV2Configuration(
            "source-current",
            "gs://maliev.com/database/full/2026-08-30/",
            "generation-20260830",
            "restore-current",
            Guid.Parse("22222222-2222-4222-8222-222222222222"),
            Guid.Parse("33333333-3333-4333-8333-333333333333"),
            _now.AddMinutes(-14),
            _now.AddMinutes(20));
        MigrationEvidenceProvenanceReceipt provenance = SignProvenance(new(
            "1.0",
            configuration.SourceSnapshotId,
            configuration.BackupUri,
            configuration.BackupObjectGeneration,
            configuration.RestoreId,
            configuration.EvidenceId,
            configuration.LeaseId,
            configuration.LeaseAcquiredAtUtc,
            configuration.LeaseExpiresAtUtc,
            authorization.RunId,
            sourceCommit,
            planHash,
            manifestHash,
            runnerDigest,
            authorization.TargetGeneration!,
            _now.AddMinutes(-10),
            "provenance-key",
            null));
        return new(
            new(result, backup, plan, authorization, configuration, provenance),
            Trust("backup-key", _backupKey),
            Trust("authorization-key", _authorizationKey),
            Trust("execution-key", _executionKey),
            Trust("provenance-key", _provenanceKey));
    }

    private BackupReceipt SignBackupReceipt(BackupReceipt receipt)
    {
        Assert.True(ReceiptAttestation.TryCreatePayload(receipt, out byte[] payload));
        return receipt with { AttestationSignature = Convert.ToBase64String(_backupKey.SignData(payload, HashAlgorithmName.SHA256)) };
    }

    private ExecutionAuthorizationReceipt SignAuthorization(ExecutionAuthorizationReceipt receipt)
    {
        Assert.True(ExecutionAuthorizationAttestation.TryCreatePayload(receipt, out byte[] payload));
        return receipt with { AttestationSignature = Convert.ToBase64String(_authorizationKey.SignData(payload, HashAlgorithmName.SHA256)) };
    }

    private MigrationExecutionReceipt SignExecution(MigrationExecutionReceipt receipt)
    {
        return receipt with
        {
            AttestationSignature = Convert.ToBase64String(_executionKey.SignData(
            MigrationEvidenceAttestation.CreatePayload(receipt),
            HashAlgorithmName.SHA256)),
        };
    }

    private static ReceiptAttestationTrustStore Trust(string keyId, ECDsa key)
    {
        return new(
        [new TrustedAttestationKey(keyId, key.ExportSubjectPublicKeyInfo())]);
    }

    private static string Hash(string value)
    {
        return Convert.ToHexString(
        SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    private async Task<string> WriteJsonAsync<T>(string name, T value)
    {
        string path = Path.Combine(_root, name);
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(value, JsonOptions));
        return path;
    }

    private MigrationEvidenceProvenanceReceipt SignProvenance(MigrationEvidenceProvenanceReceipt receipt)
    {
        Assert.True(MigrationEvidenceProvenanceAttestation.TryCreatePayload(receipt, out byte[] payload));
        return receipt with { AttestationSignature = Convert.ToBase64String(_provenanceKey.SignData(payload, HashAlgorithmName.SHA256)) };
    }

    private async Task<string> WriteTextAsync(string name, string value)
    {
        string path = Path.Combine(_root, name);
        await File.WriteAllTextAsync(path, value);
        return path;
    }

    public void Dispose()
    {
        _backupKey.Dispose();
        _authorizationKey.Dispose();
        _executionKey.Dispose();
        _provenanceKey.Dispose();
        _evidenceKey.Dispose();
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed record EvidenceFixture(
        AppHostMigrationEvidenceV2Request Request,
        ReceiptAttestationTrustStore BackupTrust,
        ReceiptAttestationTrustStore AuthorizationTrust,
        ReceiptAttestationTrustStore ExecutionTrust,
        ReceiptAttestationTrustStore ProvenanceTrust);

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return utcNow;
        }
    }
}
