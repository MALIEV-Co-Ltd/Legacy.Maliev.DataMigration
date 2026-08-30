using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class QuotationSchemaBaselineConsoleTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string root = Path.Combine(Path.GetTempPath(), $"quotation-schema-console-{Guid.NewGuid():N}");
    private readonly ECDsa[] roles = Enumerable.Range(0, 5).Select(_ => ECDsa.Create(ECCurve.NamedCurves.nistP256)).ToArray();

    public QuotationSchemaBaselineConsoleTests()
    {
        OwnerProtectedDirectory.CreateNew(root);
    }

    [Fact]
    public async Task Command_RejectsSchemaSignerReusedFromProtectedRoleBundle()
    {
        string[] trustPaths = new string[5];
        for (int index = 0; index < roles.Length; index++)
        {
            trustPaths[index] = Path.Combine(root, $"role-{index}.spki");
            await ProtectedTextAsync(trustPaths[index], Convert.ToBase64String(roles[index].ExportSubjectPublicKeyInfo()));
        }
        string keyPath = Path.Combine(root, "schema-key.pem");
        await ProtectedTextAsync(keyPath, roles[0].ExportECPrivateKeyPem());
        var plan = new FreshSchemaPlan("2.0", DateTimeOffset.UtcNow, new string('a', 40),
            [new DatabaseSchemaPlan("Quotation", "202608300001", new string('b', 64), new string('c', 64), [])]);
        string planPath = Path.Combine(root, "plan.json");
        await ProtectedJsonAsync(planPath, plan);
        string configPath = Path.Combine(root, "config.json");
        static object Role(string id, string path)
        {
            return new { keyId = id, subjectPublicKeyInfoPath = path };
        }

        await ProtectedJsonAsync(configPath, new
        {
            authorizeShadow = new { keyId = "authorization" },
            executeShadow = new { evidenceKeyId = "execution" },
            signProvenance = new { keyId = "provenance" },
            evidence = new { evidenceKeyId = "final" },
            signingRoles = new
            {
                backup = Role("backup", trustPaths[0]),
                authorization = Role("authorization", trustPaths[1]),
                execution = Role("execution", trustPaths[2]),
                provenance = Role("provenance", trustPaths[3]),
                finalEvidence = Role("final", trustPaths[4]),
            },
            quotationSchemaBaseline = new
            {
                planPath,
                outputPath = Path.Combine(root, "receipt.json"),
                reviewedSchemaPlanSha256 = SchemaPlanCanonicalizer.ComputeSha256(plan),
                workload = "quotation",
                sourceSnapshotId = "source-20260830",
                copyPlanId = "copy-plan-20260830",
                host = "postgres-rw",
                port = 5432,
                expiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                keyId = "quotation-schema",
                signingKeyFingerprintSha256 = Fingerprint(roles[0]),
                forbiddenSigningKeyFingerprintsSha256 = Array.Empty<string>(),
                allowSigning = true,
            },
        });
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunAsync(
            ["sign-quotation-schema-baseline", "--config", configPath], TextWriter.Null, error,
            name => name switch { "LEGACY_DEPLOY_ENABLED" => "false", "LEGACY_QUOTATION_SCHEMA_SIGNING_KEY_FILE" => keyPath, _ => null },
            CancellationToken.None);

        Assert.Equal(70, exitCode);
        Assert.Equal("quotation_schema_signing_role_invalid" + Environment.NewLine, error.ToString());
    }

    [Theory]
    [InlineData(false, 0, "")]
    [InlineData(true, 70, "quotation_snapshot_signing_role_invalid")]
    public async Task SnapshotCommand_UsesConcreteObserversAndProtectedRoleFence(bool reuseRole, int expectedExit, string expectedCode)
    {
        string suffix = Guid.NewGuid().ToString("N");
        string[] trustPaths = new string[5];
        for (int index = 0; index < roles.Length; index++)
        {
            trustPaths[index] = Path.Combine(root, $"snapshot-{suffix}-role-{index}.spki");
            await ProtectedTextAsync(trustPaths[index], Convert.ToBase64String(roles[index].ExportSubjectPublicKeyInfo()));
        }
        using ECDsa dedicated = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECDsa selectedKey = reuseRole ? roles[0] : dedicated;
        string keyPath = Path.Combine(root, $"snapshot-{suffix}-key.pem");
        await ProtectedTextAsync(keyPath, selectedKey.ExportECPrivateKeyPem());
        var plan = new FreshSchemaPlan("2.0", DateTimeOffset.UtcNow, new string('a', 40),
            [new DatabaseSchemaPlan("Quotation", "202608300001", new string('b', 64), new string('c', 64), [])]);
        string planPath = Path.Combine(root, $"snapshot-{suffix}-plan.json");
        await ProtectedJsonAsync(planPath, plan);
        string outputPath = Path.Combine(root, $"snapshot-{suffix}-receipt.json");
        string configPath = Path.Combine(root, $"snapshot-{suffix}-config.json");
        static object Role(string id, string path)
        {
            return new { keyId = id, subjectPublicKeyInfoPath = path };
        }

        await ProtectedJsonAsync(configPath, new
        {
            authorizeShadow = new { keyId = "authorization" },
            executeShadow = new { evidenceKeyId = "execution" },
            signProvenance = new { keyId = "provenance" },
            evidence = new { evidenceKeyId = "final" },
            signingRoles = new
            {
                backup = Role("backup", trustPaths[0]),
                authorization = Role("authorization", trustPaths[1]),
                execution = Role("execution", trustPaths[2]),
                provenance = Role("provenance", trustPaths[3]),
                finalEvidence = Role("final", trustPaths[4]),
            },
            quotationPostgreSqlSnapshot = new
            {
                planPath,
                outputPath,
                reviewedSchemaPlanSha256 = SchemaPlanCanonicalizer.ComputeSha256(plan),
                workload = "quotation",
                runId = Guid.Parse("34829fe9-1b24-42b5-8bdf-e38c9ed1e4bb"),
                sourceSnapshotId = "source-20260830",
                copyPlanId = "copy-plan-20260830",
                schemaHash = new string('c', 64),
                host = "postgres-rw",
                port = 5432,
                snapshotId = "cnpg-20260830-001",
                backupObjectUri = "gs://maliev-backups/quotation/snapshot.dump",
                backupObjectGeneration = 42,
                clusterNamespace = "maliev-legacy",
                clusterName = "legacy-postgres-main",
                expiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                keyId = "quotation-snapshot",
                signingKeyFingerprintSha256 = Fingerprint(selectedKey),
                forbiddenSigningKeyFingerprintsSha256 = Array.Empty<string>(),
                allowSigning = true,
            },
        });
        var runtime = new StubSnapshotRuntimeFactory(DateTimeOffset.UtcNow);
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunQuotationSnapshotForTestsAsync(
            ["sign-quotation-postgres-snapshot", "--config", configPath], TextWriter.Null, error,
            name => name switch { "LEGACY_DEPLOY_ENABLED" => "false", "LEGACY_QUOTATION_SNAPSHOT_SIGNING_KEY_FILE" => keyPath, _ => null },
            runtime, CancellationToken.None);

        Assert.Equal(expectedExit, exitCode);
        Assert.Equal(expectedCode.Length == 0 ? string.Empty : expectedCode + Environment.NewLine, error.ToString());
        Assert.Equal(!reuseRole, File.Exists(outputPath));
        Assert.Equal(reuseRole ? 0 : 1, runtime.FactoryCalls);
    }

    private static string Fingerprint(ECDsa key)
    {
        return Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
    }

    private static Task ProtectedJsonAsync<T>(string path, T value)
    {
        return ProtectedTextAsync(path, JsonSerializer.Serialize(value, JsonOptions));
    }

    private static async Task ProtectedTextAsync(string path, string value)
    {
        await File.WriteAllTextAsync(path, value);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
    public void Dispose()
    {
        foreach (ECDsa role in roles)
        {
            role.Dispose();
        }

        if (Directory.Exists(root))
        {
            Directory.Delete(root, true);
        }
    }

    private sealed class StubSnapshotRuntimeFactory(DateTimeOffset now) : IQuotationSnapshotRuntimeFactory
    {
        public int FactoryCalls { get; private set; }
        public Task<IImmutablePostgreSqlSnapshotObserver> CreateSnapshotObserverAsync(CancellationToken cancellationToken)
        {
            FactoryCalls++;
            return Task.FromResult<IImmutablePostgreSqlSnapshotObserver>(new SnapshotObserver(new(
                "cnpg-20260830-001", "gs://maliev-backups/quotation/snapshot.dump", 42, 8192, new string('d', 64), now.AddMinutes(-1))));
        }
        public ICloudNativePgTargetObserver CreateTargetObserver()
        {
            return new TargetObserver(new(
            "maliev-legacy", "legacy-postgres-main", "cluster-uid", "123", 7, 7, "Cluster in healthy state", 2, 2,
            "primary-1", "primary-1", true, true, true, true));
        }
    }
    private sealed class SnapshotObserver(ImmutablePostgreSqlSnapshotObservation value) : IImmutablePostgreSqlSnapshotObserver
    {
        public Task<ImmutablePostgreSqlSnapshotObservation> ObserveAsync(string backupObjectUri, long backupObjectGeneration, CancellationToken cancellationToken)
        {
            return Task.FromResult(value);
        }
    }
    private sealed class TargetObserver(CloudNativePgTargetObservation value) : ICloudNativePgTargetObserver
    {
        public Task<CloudNativePgTargetObservation> ObserveAsync(string namespaceName, string cluster, CancellationToken cancellationToken)
        {
            return Task.FromResult(value);
        }
    }
}
