using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class MigrationConsoleTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"legacy-console-{Guid.NewGuid():N}");

    [Fact]
    public async Task RunAsync_Receipt_ReadsKeyFromEnvironmentReferencedFileAndWritesNoLocalPaths()
    {
        _ = Directory.CreateDirectory(_root);
        var states = new List<VerifiedBackupStateArtifact>();
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            string path = Path.Combine(_root, $"Full_{database}_2026-08-30_000000.bak");
            await File.WriteAllTextAsync(path, database);
            byte[] content = await File.ReadAllBytesAsync(path);
            string hash = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            states.Add(new(database, path, $"database/full/run/{database}.bak", states.Count + 1, content.Length, hash));
        }
        string statePath = Path.Combine(_root, "backup-state.json");
        await File.WriteAllTextAsync(statePath, JsonSerializer.Serialize(new { artifacts = states }, JsonOptions));
        string outputPath = Path.Combine(_root, "receipt.json");
        string configPath = Path.Combine(_root, "config.json");
        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new
        {
            receipt = new { backupStatePath = statePath, outputPath, keyId = "producer-key" },
        }, JsonOptions));
        string keyPath = Path.Combine(_root, "signing-key.pem");
        using (ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            await File.WriteAllTextAsync(keyPath, key.ExportECPrivateKeyPem());
        }
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunAsync(
            ["receipt", "--config", configPath],
            output,
            error,
            name => name == "LEGACY_MIGRATION_RECEIPT_SIGNING_KEY_FILE" ? keyPath : null,
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.True(File.Exists(outputPath));
        string receiptJson = await File.ReadAllTextAsync(outputPath);
        Assert.DoesNotContain(_root, receiptJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PRIVATE KEY", receiptJson, StringComparison.Ordinal);
        Assert.Contains("receipt_complete", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task RunAsync_Plan_MissingSourceReferenceFailsWithoutPrintingConfiguration()
    {
        _ = Directory.CreateDirectory(_root);
        string configPath = Path.Combine(_root, "config.json");
        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new
        {
            plan = new { outputPath = Path.Combine(_root, "plan.json"), sourceCommitSha = new string('a', 40) },
        }, JsonOptions));
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunAsync(
            ["plan", "--config", configPath], output, error, _ => null, CancellationToken.None);

        Assert.Equal(65, exitCode);
        Assert.Equal("plan_source_reference_missing" + Environment.NewLine, error.ToString());
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task RunAsync_ExecuteShadow_MissingRuntimeReferencesFailsClosed()
    {
        _ = Directory.CreateDirectory(_root);
        string configPath = Path.Combine(_root, "config.json");
        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new
        {
            executeShadow = new
            {
                receiptPath = "receipt.json",
                planPath = "plan.json",
                authorizationPath = "authorization.json",
                outputPath = "execution.json",
                runnerDigestSha256 = new string('a', 64),
                receiptTrustedKeys = Array.Empty<object>(),
                authorizationTrustedKeys = Array.Empty<object>(),
                evidenceKeyId = "evidence-key",
            },
        }, JsonOptions));
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunAsync(
            ["execute-shadow", "--config", configPath], output, error, _ => null, CancellationToken.None);

        Assert.Equal(65, exitCode);
        Assert.Equal("shadow_runtime_reference_missing" + Environment.NewLine, error.ToString());
        Assert.Equal(string.Empty, output.ToString());
    }

    private static JsonSerializerOptions JsonOptions { get; } = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }
}
