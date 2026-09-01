using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Runtime.Versioning;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Exact24RunBootstrapTests
{
    [Fact]
    public async Task Bootstrap_CreatesCompleteFailClosedExact24ConfigurationAndDistinctKeys()
    {
        string parent = Path.Combine(Path.GetTempPath(), $"legacy-bootstrap-test-{Guid.NewGuid():N}");
        string outputRoot = Path.Combine(parent, "owner-runs");
        _ = Directory.CreateDirectory(parent);
        try
        {
            BootstrapResult result = await RunBootstrapAsync(outputRoot);
            Assert.True(Directory.Exists(result.RunDirectory));
            AssertOwnerOnlyDirectory(result.RunDirectory);
            AssertOwnerOnlyFile(result.ConfigPath);
            AssertOwnerOnlyFile(result.SnapshotKeyPath);

            using JsonDocument document = JsonDocument.Parse(await File.ReadAllTextAsync(result.ConfigPath));
            JsonElement root = document.RootElement;
            string[] expectedSections =
            [
                "plan", "executeShadow", "evidence", "exportLocalSnapshot", "cleanupShadows", "fullBackup",
                "restoreBackups", "authorizeShadow", "authorizeCleanup", "signProvenance",
                "quotationSchemaBaseline", "quotationPostgreSqlSnapshot", "signingRoles"
            ];
            Assert.Equal(expectedSections, root.EnumerateObject().Select(property => property.Name).ToArray());
            Assert.All(root.EnumerateObject(), property => Assert.True(char.IsLower(property.Name[0])));
            Assert.Equal(new string('a', 40), root.GetProperty("plan").GetProperty("sourceCommitSha").GetString());
            Assert.Equal("sql-main-0", root.GetProperty("fullBackup").GetProperty("expectedPodName").GetString());
            Assert.Equal("12345678-1234-1234-1234-123456789abc", root.GetProperty("fullBackup").GetProperty("expectedPodUid").GetString());
            Assert.False(root.GetProperty("fullBackup").GetProperty("allowSourceBackup").GetBoolean());
            Assert.False(root.GetProperty("authorizeShadow").GetProperty("allowShadowAuthorization").GetBoolean());
            Assert.False(root.GetProperty("authorizeCleanup").GetProperty("allowCleanupAuthorization").GetBoolean());
            Assert.False(root.GetProperty("signProvenance").GetProperty("allowProvenanceSigning").GetBoolean());
            Assert.Equal("REVIEW_REQUIRED_AFTER_FRESH_PLAN", root.GetProperty("authorizeShadow").GetProperty("reviewedSchemaPlanSha256").GetString());
            Assert.Equal("legacy_migration_shadow", root.GetProperty("executeShadow").GetProperty("expectedShadowAdminRole").GetString());
            Assert.Equal("legacy_migration_shadow", root.GetProperty("cleanupShadows").GetProperty("expectedShadowAdminRole").GetString());

            string working = root.GetProperty("fullBackup").GetProperty("localWorkingDirectory").GetString()!;
            string publication = root.GetProperty("fullBackup").GetProperty("publicationDirectory").GetString()!;
            Assert.NotEqual(working, publication);
            Assert.False(Directory.Exists(working));
            Assert.False(Directory.Exists(publication));
            Assert.False(Directory.Exists(root.GetProperty("exportLocalSnapshot").GetProperty("outputDirectory").GetString()!));
            Assert.False(Directory.Exists(root.GetProperty("evidence").GetProperty("publicationDirectory").GetString()!));

            string configText = await File.ReadAllTextAsync(result.ConfigPath);
            Assert.DoesNotContain("password", configText, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("connectionString", configText, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("PRIVATE KEY", configText, StringComparison.Ordinal);

            var publicFingerprints = new HashSet<string>(StringComparer.Ordinal);
            foreach ((string role, string privatePath) in result.SigningKeyPaths)
            {
                AssertOwnerOnlyFile(privatePath);
                string publicPath = root.GetProperty("signingRoles")
                    .GetProperty(role == "finalEvidence" ? "finalEvidence" : role)
                    .GetProperty("subjectPublicKeyInfoPath").GetString()!;
                AssertOwnerOnlyFile(publicPath);
                byte[] publicKey = Convert.FromBase64String((await File.ReadAllTextAsync(publicPath)).Trim());
                using ECDsa privateKey = ECDsa.Create();
                privateKey.ImportFromPem(await File.ReadAllTextAsync(privatePath));
                Assert.Equal(publicKey, privateKey.ExportSubjectPublicKeyInfo());
                Assert.True(publicFingerprints.Add(Convert.ToHexString(SHA256.HashData(publicKey))));
            }
            Assert.Equal(5, publicFingerprints.Count);
            Assert.Equal(32, Convert.FromBase64String((await File.ReadAllTextAsync(result.SnapshotKeyPath)).Trim()).Length);

            using var output = new StringWriter();
            using var error = new StringWriter();
            int exitCode = await MigrationConsole.RunForTestsAsync(
                ["plan", "--config", result.ConfigPath], output, error, _ => null,
                new ThrowingBackupRuntimeFactory(), CancellationToken.None);
            Assert.Equal(65, exitCode);
            Assert.Equal("plan_source_reference_missing", error.ToString().Trim());
        }
        finally
        {
            if (Directory.Exists(parent))
            {
                Directory.Delete(parent, recursive: true);
            }
        }
    }

    [Fact]
    public async Task Bootstrap_RejectsExistingUnprotectedOutputRootWithoutCreatingRun()
    {
        string parent = Path.Combine(Path.GetTempPath(), $"legacy-bootstrap-unprotected-{Guid.NewGuid():N}");
        string outputRoot = Path.Combine(parent, "runs");
        _ = Directory.CreateDirectory(outputRoot);
        try
        {
            ProcessResult result = await InvokeScriptAsync(outputRoot);
            Assert.NotEqual(0, result.ExitCode);
            Assert.Empty(Directory.EnumerateFileSystemEntries(outputRoot));
        }
        finally
        {
            if (Directory.Exists(parent))
            {
                Directory.Delete(parent, recursive: true);
            }
        }
    }

    [Fact]
    public void BootstrapScript_UsesCreateNewOwnerOnlyAndNeverAcceptsRuntimeSecrets()
    {
        string script = File.ReadAllText(ScriptPath());
        Assert.Contains("[System.IO.FileMode]::CreateNew", script, StringComparison.Ordinal);
        Assert.Contains("Assert-NoLinkAncestors", script, StringComparison.Ordinal);
        Assert.Contains("Assert-OwnerOnlyDirectory", script, StringComparison.Ordinal);
        Assert.Contains("SetAccessRuleProtection($true, $false)", script, StringComparison.Ordinal);
        Assert.Contains("allowSourceBackup = $false", script, StringComparison.Ordinal);
        Assert.Contains("allowShadowAuthorization = $false", script, StringComparison.Ordinal);
        Assert.Contains("allowCleanupAuthorization = $false", script, StringComparison.Ordinal);
        Assert.Contains("allowProvenanceSigning = $false", script, StringComparison.Ordinal);
        string parameters = script[..script.IndexOf("$ErrorActionPreference", StringComparison.Ordinal)];
        Assert.DoesNotContain("Password", parameters, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Connection", parameters, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Get-Credential", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("kubectl", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("gcloud", script, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<BootstrapResult> RunBootstrapAsync(string outputRoot)
    {
        ProcessResult process = await InvokeScriptAsync(outputRoot);
        Assert.True(process.ExitCode == 0, $"Bootstrap failed: {process.StandardError}");
        using JsonDocument result = JsonDocument.Parse(process.StandardOutput);
        JsonElement root = result.RootElement;
        return new(
            root.GetProperty("runDirectory").GetString()!,
            root.GetProperty("configPath").GetString()!,
            root.GetProperty("snapshotKeyPath").GetString()!,
            root.GetProperty("signingKeyPaths").EnumerateObject().ToDictionary(
                property => property.Name,
                property => property.Value.GetString()!,
                StringComparer.Ordinal));
    }

    private static async Task<ProcessResult> InvokeScriptAsync(string outputRoot)
    {
        string digest = new('0', 64);
        var start = new ProcessStartInfo("pwsh")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        string[] arguments =
        [
            "-NoLogo", "-NoProfile", "-NonInteractive", "-File", ScriptPath(),
            "-OutputRoot", outputRoot,
            "-SourceNamespace", "maliev-web",
            "-ExpectedPodName", "sql-main-0",
            "-ExpectedPodUid", "12345678-1234-1234-1234-123456789abc",
            "-ContainerName", "sqlserver",
            "-ReviewedSourceCommitSha", new string('a', 40),
            "-GcsBucket", "maliev-backups",
            "-StagingImage", $"docker.io/library/alpine@sha256:{digest}",
            "-SqlServerImage", $"mcr.microsoft.com/mssql/server@sha256:{digest}",
            "-SqlServerImageId", $"sha256:{digest}",
            "-PgDumpPath", Path.Combine(Path.GetTempPath(), "pg_dump")
        ];
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }
        using Process process = Process.Start(start) ?? throw new InvalidOperationException("PowerShell could not be started.");
        string stdout = await process.StandardOutput.ReadToEndAsync();
        string stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return new(process.ExitCode, stdout, stderr);
    }

    private static void AssertOwnerOnlyDirectory(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            AssertOwnerOnlyWindowsDirectory(path);
            return;
        }
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(path));
    }

    [SupportedOSPlatform("windows")]
    private static void AssertOwnerOnlyWindowsDirectory(string path)
    {
        SecurityIdentifier owner = WindowsIdentity.GetCurrent().User!;
        DirectorySecurity security = new DirectoryInfo(path).GetAccessControl();
        Assert.Equal(owner, security.GetOwner(typeof(SecurityIdentifier)));
        Assert.True(security.AreAccessRulesProtected);
        Assert.All(security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
            rule => Assert.True(rule.AccessControlType == AccessControlType.Deny || owner.Equals(rule.IdentityReference)));
    }

    private static void AssertOwnerOnlyFile(string path)
    {
        Assert.True(SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path)));
    }

    private static string ScriptPath()
    {
        return Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "../../../../../scripts/new-exact24-run-config.ps1"));
    }

    private sealed record BootstrapResult(
        string RunDirectory,
        string ConfigPath,
        string SnapshotKeyPath,
        IReadOnlyDictionary<string, string> SigningKeyPaths);

    private sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);

    private sealed class ThrowingBackupRuntimeFactory : IExact25BackupRuntimeFactory
    {
        public Task<Exact25BackupRuntime> CreateAsync(CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("The plan parser test must not create backup runtime dependencies.");
        }
    }
}
