using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class PreflightServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 29, 12, 0, 0, TimeSpan.Zero);
    private static readonly ECDsa ProducerSigningKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private const string ProducerKeyId = "backup-producer-1";

    [Fact]
    public void Inventory_ApprovedContract_PreservesEverySelectedProductionDatabase()
    {
        Assert.Equal(27, DatabaseInventory.Entries.Count);
        Assert.Equal(25, DatabaseInventory.ActiveDatabases.Count);
        Assert.Equal(DatabaseDisposition.Migrate, DatabaseInventory.Entries["Hangfire"].Disposition);
        Assert.Equal(DatabaseDisposition.Migrate, DatabaseInventory.Entries["Log"].Disposition);
        Assert.Equal(DatabaseDisposition.Excluded, DatabaseInventory.Entries["MachineLearning"].Disposition);
        Assert.Equal(DatabaseDisposition.Excluded, DatabaseInventory.Entries["MachineLearningData"].Disposition);
        Assert.Equal(
            new DatabaseDispositionEntry("Legacy.Maliev.ContactService", DatabaseDisposition.Migrate),
            DatabaseInventory.Entries["ContactRequest"]);
        Assert.Equal(
            new DatabaseDispositionEntry("Legacy.Maliev.CatalogService", DatabaseDisposition.Migrate),
            DatabaseInventory.Entries["LocationData"]);
    }

    [Fact]
    public void Inventory_MachineReadableArtifact_ExactlyMatchesReceiptBoundContract()
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "database-disposition.json")));
        JsonElement root = document.RootElement;
        Assert.Equal("1.0", root.GetProperty("schemaVersion").GetString());
        Assert.Equal(DatabaseInventory.InventorySha256, root.GetProperty("inventorySha256").GetString());

        Dictionary<string, DatabaseDispositionEntry> artifact = root.GetProperty("databases")
            .EnumerateArray()
            .ToDictionary(
                item => item.GetProperty("database").GetString()!,
                item => new DatabaseDispositionEntry(
                    item.GetProperty("owner").GetString()!,
                    Enum.Parse<DatabaseDisposition>(item.GetProperty("disposition").GetString()!, ignoreCase: false)),
                StringComparer.Ordinal);

        Assert.Equal(DatabaseInventory.Entries.OrderBy(item => item.Key), artifact.OrderBy(item => item.Key));
        Assert.Equal(25, root.GetProperty("selectedDatabaseCount").GetInt32());
        Assert.Equal("BackupReceipt.DatabaseInventorySha256", root.GetProperty("signatureBinding").GetString());
    }

    [Fact]
    public void Validate_ApprovedPlanAndFreshFullReceipt_ReturnsValidPlanOnlyResult()
    {
        RecordingExternalCommandExecutor executor = new();
        var result = CreateService(executor).Validate(
            CreateReceipt(),
            CreatePlan(),
            Now,
            TimeSpan.FromHours(26));

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
        Assert.Equal(0, executor.InvocationCount);
    }

    [Fact]
    public void Validate_DifferentialBackup_RejectsReceiptWithoutExternalExecution()
    {
        RecordingExternalCommandExecutor executor = new();
        var receipt = CreateReceipt(artifacts =>
        {
            artifacts[0] = artifacts[0]! with { BackupType = "Differential" };
        });

        var result = CreateService(executor).Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "backup_type_not_full");
        Assert.Equal(0, executor.InvocationCount);
    }

    [Fact]
    public void Validate_StaleReceipt_RejectsReceipt()
    {
        var receipt = CreateReceipt() with { CapturedAtUtc = Now.AddHours(-27) };

        var result = CreateService().Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "receipt_stale");
    }

    [Fact]
    public void Validate_MismatchedManifestHash_RejectsReceipt()
    {
        var receipt = CreateReceipt() with { ManifestSha256 = new string('0', 64) };

        var result = CreateService().Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "manifest_hash_mismatch");
    }

    [Fact]
    public void Validate_MismatchedArtifactHash_RejectsReceipt()
    {
        var receipt = CreateReceipt(artifacts =>
        {
            artifacts[0] = artifacts[0]! with { ObservedSha256 = new string('f', 64) };
        });

        var result = CreateService().Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "backup_hash_mismatch");
    }

    [Fact]
    public void Validate_MismatchedInventoryHash_RejectsReceipt()
    {
        var receipt = CreateReceipt() with { DatabaseInventorySha256 = new string('0', 64) };

        var result = CreateService().Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "inventory_hash_mismatch");
    }

    [Fact]
    public void Validate_MissingDatabase_RejectsReceipt()
    {
        var receipt = CreateReceipt(artifacts => artifacts.RemoveAt(0));

        var result = CreateService().Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "database_coverage_mismatch");
    }

    [Fact]
    public void Validate_ExtraDatabase_RejectsReceipt()
    {
        var receipt = CreateReceipt(artifacts => artifacts.Add(CreateArtifact("Unexpected")));

        var result = CreateService().Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "database_coverage_mismatch");
    }

    [Fact]
    public void Validate_UnknownTargetSchemaVersion_RejectsPlan()
    {
        var plan = CreatePlan();
        plan.TargetSchemaVersions![DatabaseInventory.ActiveDatabases[0]] = "future-version";

        var result = CreateService().Validate(CreateReceipt(), plan, Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "target_schema_version_unknown");
    }

    [Fact]
    public void Validate_ActiveTargetWrites_RejectsPlanWithoutExternalExecution()
    {
        RecordingExternalCommandExecutor executor = new();
        var plan = CreatePlan() with { AllowTargetWrites = true };

        var result = CreateService(executor).Validate(CreateReceipt(), plan, Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "target_writes_forbidden");
        Assert.Equal(0, executor.InvocationCount);
    }

    [Fact]
    public void Validate_RequestedExternalAction_RejectsPlanWithoutExternalExecution()
    {
        RecordingExternalCommandExecutor executor = new();
        var plan = CreatePlan() with { RequestedExternalActions = ["kubectl", "psql"] };

        var result = CreateService(executor).Validate(CreateReceipt(), plan, Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "external_actions_forbidden");
        Assert.Equal(0, executor.InvocationCount);
    }

    [Fact]
    public void Validate_UnknownAttestationKey_RejectsReceipt()
    {
        BackupReceipt receipt = CreateReceipt() with { AttestationKeyId = "caller-selected-key" };

        PreflightResult result = CreateService().Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "attestation_key_unknown");
    }

    [Fact]
    public void Validate_MissingAttestationSignature_RejectsReceipt()
    {
        BackupReceipt receipt = CreateReceipt() with { AttestationSignature = null };

        PreflightResult result = CreateService().Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "attestation_signature_missing");
    }

    [Fact]
    public void Validate_ModifiedAttestedField_RejectsReceipt()
    {
        BackupReceipt receipt = CreateReceipt();
        List<BackupArtifact?> artifacts = [.. receipt.Artifacts!];
        artifacts[0] = artifacts[0]! with { ByteLength = artifacts[0]!.ByteLength + 1 };
        receipt = receipt with { Artifacts = artifacts };

        PreflightResult result = CreateService().Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "attestation_signature_invalid");
    }

    [Fact]
    public void Validate_CallerSignedReceiptWithUntrustedPrivateKey_RejectsReceipt()
    {
        BackupReceipt receipt = CreateReceipt();
        Assert.True(ReceiptAttestation.TryCreatePayload(receipt, out byte[] payload));
        using ECDsa attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        receipt = receipt with
        {
            AttestationSignature = Convert.ToBase64String(
                attackerKey.SignData(payload, HashAlgorithmName.SHA256)),
        };

        PreflightResult result = CreateService().Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "attestation_signature_invalid");
    }

    [Fact]
    public void ReceiptAttestationTrustStore_P384TrustedKey_RejectsWithStableCurveCode()
    {
        using ECDsa p384Key = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            new ReceiptAttestationTrustStore(
            [new TrustedAttestationKey("backup-producer-p384", p384Key.ExportSubjectPublicKeyInfo())]));

        Assert.Equal("trusted_attestation_key_curve_invalid", exception.Data["code"]);
    }

    [Fact]
    public void ReceiptAttestationTrustStore_NonEcdsaTrustedKey_RejectsWithStableAlgorithmCode()
    {
        using RSA rsaKey = RSA.Create(2048);

        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            new ReceiptAttestationTrustStore(
            [new TrustedAttestationKey("backup-producer-rsa", rsaKey.ExportSubjectPublicKeyInfo())]));

        Assert.Equal("trusted_attestation_key_algorithm_invalid", exception.Data["code"]);
    }

    [Fact]
    public void Validate_NullArtifactEntry_ReturnsStableErrorWithoutThrowing()
    {
        BackupReceipt receipt = CreateReceipt();
        List<BackupArtifact?> artifacts = [.. receipt.Artifacts!];
        artifacts[0] = null;
        receipt = receipt with { Artifacts = artifacts };

        PreflightResult result = CreateService().Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "backup_artifact_missing");
    }

    [Fact]
    public void Validate_NullReceiptFields_ReturnsStableErrorsWithoutThrowing()
    {
        BackupReceipt receipt = CreateReceipt() with
        {
            SchemaVersion = null,
            DatabaseInventorySha256 = null,
            ManifestSha256 = null,
            Artifacts = null,
            AttestationKeyId = null,
            AttestationSignature = null,
        };

        PreflightResult result = CreateService().Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "receipt_schema_version_unknown");
        Assert.Contains(result.Errors, error => error.Code == "database_coverage_mismatch");
        Assert.Contains(result.Errors, error => error.Code == "attestation_key_missing");
        Assert.Contains(result.Errors, error => error.Code == "attestation_signature_missing");
    }

    [Fact]
    public void Validate_NullArtifactFields_ReturnsStableErrorWithoutThrowing()
    {
        BackupReceipt receipt = CreateReceipt();
        List<BackupArtifact?> artifacts = [.. receipt.Artifacts!];
        artifacts[0] = artifacts[0]! with
        {
            Database = null,
            BackupType = null,
            FileName = null,
            Sha256 = null,
            ObservedSha256 = null,
        };
        receipt = receipt with { Artifacts = artifacts };

        PreflightResult result = CreateService().Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "backup_artifact_invalid");
    }

    [Fact]
    public void Validate_NullPlanCollections_ReturnsStableErrorsWithoutThrowing()
    {
        MigrationPlan plan = CreatePlan() with
        {
            Mode = null,
            TargetSchemaVersions = null,
            RequestedExternalActions = null,
        };

        PreflightResult result = CreateService().Validate(CreateReceipt(), plan, Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "mode_not_plan_only");
        Assert.Contains(result.Errors, error => error.Code == "target_schema_coverage_mismatch");
    }

    private static PreflightService CreateService()
    {
        return CreateService(new RecordingExternalCommandExecutor());
    }

    private static PreflightService CreateService(IExternalCommandExecutor executor)
    {
        TrustedAttestationKey trustedKey = new(ProducerKeyId, ProducerSigningKey.ExportSubjectPublicKeyInfo());
        return new(
            executor,
            new ReceiptAttestationTrustStore([trustedKey]));
    }

    private static BackupReceipt CreateReceipt(Action<List<BackupArtifact?>>? mutate = null)
    {
        List<BackupArtifact?> artifacts = [.. DatabaseInventory.ActiveDatabases.Select(CreateArtifact)];
        mutate?.Invoke(artifacts);

        BackupReceipt unsignedReceipt = new(
            SchemaVersion: "1.1",
            CapturedAtUtc: Now.AddHours(-1),
            DatabaseInventorySha256: DatabaseInventory.InventorySha256,
            ManifestSha256: ComputeManifestSha256(artifacts),
            Artifacts: artifacts,
            AttestationKeyId: ProducerKeyId,
            AttestationSignature: null)
        {
            SourceObservedAtUtc = Now.AddHours(-2),
        };
        Assert.True(ReceiptAttestation.TryCreatePayload(unsignedReceipt, out byte[] payload));
        string signature = Convert.ToBase64String(
            ProducerSigningKey.SignData(payload, HashAlgorithmName.SHA256));
        return unsignedReceipt with { AttestationSignature = signature };
    }

    private static BackupArtifact CreateArtifact(string database)
    {
        string digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(database))).ToLowerInvariant();
        return new BackupArtifact(
            database,
            "Full",
            $"Full_{database}_2026-08-29_120000.bak",
            1024,
            digest,
            digest)
        {
            CompletedAtUtc = Now.AddHours(-1),
        };
    }

    private static MigrationPlan CreatePlan()
    {
        return new(
            Mode: "plan-only",
            AllowTargetWrites: false,
            TargetSchemaVersions: DatabaseInventory.ActiveDatabases.ToDictionary(
                database => database,
                _ => (string?)"1.0",
                StringComparer.Ordinal),
            RequestedExternalActions: []);
    }

    private static string ComputeManifestSha256(IEnumerable<BackupArtifact?> artifacts)
    {
        string canonical = string.Join(
            '\n',
            artifacts
                .Select(Assert.IsType<BackupArtifact>)
                .OrderBy(artifact => artifact.Database, StringComparer.Ordinal)
                .Select(artifact => string.Join(
                    '|',
                    artifact.Database,
                    artifact.BackupType,
                    artifact.FileName,
                    artifact.ByteLength,
                    artifact.Sha256!.ToLowerInvariant(),
                    artifact.ObservedSha256!.ToLowerInvariant())));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private sealed class RecordingExternalCommandExecutor : IExternalCommandExecutor
    {
        public int InvocationCount { get; private set; }

        public Task<int> ExecuteAsync(string command, CancellationToken cancellationToken)
        {
            InvocationCount++;
            return Task.FromResult(0);
        }
    }
}
