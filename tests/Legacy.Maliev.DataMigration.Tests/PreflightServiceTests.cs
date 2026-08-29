using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class PreflightServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 29, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Inventory_ApprovedContract_ContainsExactlyTwentyOneActiveDatabases()
    {
        Assert.Equal(23, DatabaseInventory.Entries.Count);
        Assert.Equal(21, DatabaseInventory.ActiveDatabases.Count);
        Assert.Equal(DatabaseDisposition.ArchiveOnly, DatabaseInventory.Entries["Log"].Disposition);
        Assert.Equal(DatabaseDisposition.Excluded, DatabaseInventory.Entries["MachineLearningData"].Disposition);
    }

    [Fact]
    public void Validate_ApprovedPlanAndFreshFullReceipt_ReturnsValidPlanOnlyResult()
    {
        RecordingExternalCommandExecutor executor = new();
        var result = new PreflightService(executor).Validate(
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
            artifacts[0] = artifacts[0] with { BackupType = "Differential" };
        });

        var result = new PreflightService(executor).Validate(receipt, CreatePlan(), Now, TimeSpan.FromHours(26));

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
            artifacts[0] = artifacts[0] with { ObservedSha256 = new string('f', 64) };
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
        plan.TargetSchemaVersions[DatabaseInventory.ActiveDatabases[0]] = "future-version";

        var result = CreateService().Validate(CreateReceipt(), plan, Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "target_schema_version_unknown");
    }

    [Fact]
    public void Validate_ActiveTargetWrites_RejectsPlanWithoutExternalExecution()
    {
        RecordingExternalCommandExecutor executor = new();
        var plan = CreatePlan() with { AllowTargetWrites = true };

        var result = new PreflightService(executor).Validate(CreateReceipt(), plan, Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "target_writes_forbidden");
        Assert.Equal(0, executor.InvocationCount);
    }

    [Fact]
    public void Validate_RequestedExternalAction_RejectsPlanWithoutExternalExecution()
    {
        RecordingExternalCommandExecutor executor = new();
        var plan = CreatePlan() with { RequestedExternalActions = ["kubectl", "psql"] };

        var result = new PreflightService(executor).Validate(CreateReceipt(), plan, Now, TimeSpan.FromHours(26));

        Assert.Contains(result.Errors, error => error.Code == "external_actions_forbidden");
        Assert.Equal(0, executor.InvocationCount);
    }

    private static PreflightService CreateService()
    {
        return new(new RecordingExternalCommandExecutor());
    }

    private static BackupReceipt CreateReceipt(Action<List<BackupArtifact>>? mutate = null)
    {
        List<BackupArtifact> artifacts = [.. DatabaseInventory.ActiveDatabases.Select(CreateArtifact)];
        mutate?.Invoke(artifacts);

        return new BackupReceipt(
            SchemaVersion: "1.0",
            CapturedAtUtc: Now.AddHours(-1),
            DatabaseInventorySha256: DatabaseInventory.InventorySha256,
            ManifestSha256: ComputeManifestSha256(artifacts),
            Artifacts: artifacts);
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
            digest);
    }

    private static MigrationPlan CreatePlan()
    {
        return new(
            Mode: "plan-only",
            AllowTargetWrites: false,
            TargetSchemaVersions: DatabaseInventory.ActiveDatabases.ToDictionary(
                database => database,
                _ => "1.0",
                StringComparer.Ordinal),
            RequestedExternalActions: []);
    }

    private static string ComputeManifestSha256(IEnumerable<BackupArtifact> artifacts)
    {
        string canonical = string.Join(
            '\n',
            artifacts
                .OrderBy(artifact => artifact.Database, StringComparer.Ordinal)
                .Select(artifact => string.Join(
                    '|',
                    artifact.Database,
                    artifact.BackupType,
                    artifact.FileName,
                    artifact.ByteLength,
                    artifact.Sha256.ToLowerInvariant(),
                    artifact.ObservedSha256.ToLowerInvariant())));
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
