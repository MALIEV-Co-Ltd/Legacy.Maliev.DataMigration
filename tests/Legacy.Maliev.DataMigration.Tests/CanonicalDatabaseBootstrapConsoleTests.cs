using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CanonicalDatabaseBootstrapConsoleTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"canonical-bootstrap-console-{Guid.NewGuid():N}");
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    [Fact]
    public async Task Authorize_command_emits_one_short_lived_signed_database_authorization()
    {
        using TestFiles files = await CreateFilesAsync();
        string outputPath = Path.Combine(_root, "authorization.json");
        string configPath = await WriteConfigAsync(files, outputPath, allowAuthorization: true, allowExecution: false);
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunBootstrapForTestsAsync(
            ["authorize-canonical-bootstrap", "--config", configPath], output, error,
            name => name switch
            {
                "LEGACY_DEPLOY_ENABLED" => "false",
                "LEGACY_MIGRATION_CALLER" => "owner",
                "LEGACY_MIGRATION_CANONICAL_BOOTSTRAP_AUTHORIZATION_SIGNING_KEY_FILE" => files.AuthorizationPrivateKeyPath,
                _ => null,
            },
            new RejectingRuntime(),
            new FixedTime(files.Now),
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal("authorize_canonical_bootstrap_complete" + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
        CanonicalDatabaseBootstrapAuthorization authorization = JsonSerializer.Deserialize<CanonicalDatabaseBootstrapAuthorization>(
            await File.ReadAllTextAsync(outputPath), JsonOptions)!;
        Assert.Equal("ContactRequest", authorization.Database);
        Assert.Equal(files.AuthorizationSigner.KeyId, authorization.AttestationKeyId);
        Assert.True(files.AuthorizationTrust.Verify(
            authorization.AttestationKeyId,
            CanonicalDatabaseBootstrapAuthorizationCanonicalizer.CreatePayload(authorization),
            Convert.FromBase64String(authorization.AttestationSignature!)));
    }

    [Fact]
    public async Task Execute_command_passes_the_exact_signed_target_to_the_runtime_without_printing_secrets()
    {
        using TestFiles files = await CreateFilesAsync();
        CanonicalDatabaseBootstrapAuthorization authorization = CanonicalDatabaseBootstrapAuthorizationProducer.Produce(
            files.Schema.Databases[0], "legacy-postgres-contact-request", "database-uid-1", "17", files.Authority,
            files.Now.AddMinutes(-1), files.Now.AddMinutes(9), files.AuthorizationSigner);
        string authorizationPath = Path.Combine(_root, "authorization.json");
        await File.WriteAllTextAsync(authorizationPath, JsonSerializer.Serialize(authorization, JsonOptions));
        ProtectFileOnUnix(authorizationPath);
        string outputPath = Path.Combine(_root, "receipt.json");
        string configPath = await WriteConfigAsync(
            files, outputPath, allowAuthorization: false, allowExecution: true, authorizationPath);
        var runtime = new CapturingRuntime(files.Now);
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunBootstrapForTestsAsync(
            ["bootstrap-canonical-database", "--config", configPath], output, error,
            name => name switch
            {
                "LEGACY_DEPLOY_ENABLED" => "false",
                "LEGACY_MIGRATION_CALLER" => "owner",
                "LEGACY_MIGRATION_CANONICAL_BOOTSTRAP_EXECUTION_SIGNING_KEY_FILE" => files.ExecutionPrivateKeyPath,
                _ => null,
            },
            runtime,
            new FixedTime(files.Now),
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal("bootstrap_canonical_database_complete" + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
        Assert.NotNull(runtime.Request);
        Assert.Equal("Host=protected;Database=ContactRequest", runtime.Request.TargetConnectionString);
        Assert.Equal("postgres", runtime.Request.ExpectedOwnerRole);
        Assert.Equal(authorization, runtime.Request.Authorization);
        Assert.True(File.Exists(outputPath));
    }

    [Theory]
    [InlineData("true", "owner", "canonical_database_bootstrap_deploy_gate_invalid")]
    [InlineData("false", "operator", "canonical_database_bootstrap_caller_invalid")]
    public async Task Commands_fail_before_reading_configuration_when_deploy_or_caller_gate_is_invalid(
        string deployEnabled,
        string caller,
        string expectedCode)
    {
        string missingConfig = Path.Combine(_root, "must-not-be-read.json");
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunBootstrapForTestsAsync(
            ["bootstrap-canonical-database", "--config", missingConfig], TextWriter.Null, error,
            name => name switch
            {
                "LEGACY_DEPLOY_ENABLED" => deployEnabled,
                "LEGACY_MIGRATION_CALLER" => caller,
                _ => null,
            },
            new RejectingRuntime(),
            new FixedTime(DateTimeOffset.UtcNow),
            CancellationToken.None);

        Assert.Equal(65, exitCode);
        Assert.Equal(expectedCode + Environment.NewLine, error.ToString());
    }

    private async Task<TestFiles> CreateFilesAsync()
    {
        OwnerProtectedDirectory.CreateNew(_root);
        DateTimeOffset now = new(2026, 9, 9, 5, 0, 0, TimeSpan.Zero);
        FreshSchemaPlan schema = Schema(now);
        string schemaPath = Path.Combine(_root, "schema.json");
        string connectionPath = Path.Combine(_root, "target-connection.txt");
        string authorizationPublicKeyPath = Path.Combine(_root, "authorization-public.txt");
        string executionPublicKeyPath = Path.Combine(_root, "execution-public.txt");
        string authorizationPrivateKeyPath = Path.Combine(_root, "authorization-private.pem");
        string executionPrivateKeyPath = Path.Combine(_root, "execution-private.pem");
        using ECDsa authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa executionKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var authorizationSigner = new P256MigrationEvidenceSigner("bootstrap-authorization", authorizationKey.ExportECPrivateKeyPem());
        var executionSigner = new P256MigrationEvidenceSigner("bootstrap-execution", executionKey.ExportECPrivateKeyPem());
        var authorizationTrust = new ReceiptAttestationTrustStore(
            [new(authorizationSigner.KeyId, authorizationSigner.ExportSubjectPublicKeyInfo())]);
        await File.WriteAllTextAsync(schemaPath, JsonSerializer.Serialize(schema, JsonOptions));
        await File.WriteAllTextAsync(connectionPath, "Host=protected;Database=ContactRequest");
        await File.WriteAllTextAsync(authorizationPublicKeyPath, Convert.ToBase64String(authorizationSigner.ExportSubjectPublicKeyInfo()));
        await File.WriteAllTextAsync(executionPublicKeyPath, Convert.ToBase64String(executionSigner.ExportSubjectPublicKeyInfo()));
        await File.WriteAllTextAsync(authorizationPrivateKeyPath, authorizationKey.ExportECPrivateKeyPem());
        await File.WriteAllTextAsync(executionPrivateKeyPath, executionKey.ExportECPrivateKeyPem());
        foreach (string path in new[]
        {
            schemaPath,
            connectionPath,
            authorizationPublicKeyPath,
            executionPublicKeyPath,
            authorizationPrivateKeyPath,
            executionPrivateKeyPath,
        })
        {
            ProtectFileOnUnix(path);
        }
        var authority = new DeltaTargetAuthority(
            DeltaTargetAuthorityKind.ProductionCloudNativePg,
            "gke://maliev-website/us-central1-a/maliev-legacy/legacy-postgres-main/cluster-uid",
            new string('8', 64));
        return new(now, schema, authority, schemaPath, connectionPath, authorizationPublicKeyPath,
            executionPublicKeyPath, authorizationPrivateKeyPath, executionPrivateKeyPath,
            authorizationSigner, executionSigner, authorizationTrust);
    }

    private async Task<string> WriteConfigAsync(
        TestFiles files,
        string outputPath,
        bool allowAuthorization,
        bool allowExecution,
        string? authorizationPath = null)
    {
        string configPath = Path.Combine(_root, $"config-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new
        {
            canonicalBootstrap = new
            {
                schemaPlanPath = files.SchemaPath,
                database = "ContactRequest",
                outputPath,
                targetConnectionFile = files.ConnectionPath,
                expectedOwnerRole = "postgres",
                databaseResourceName = "legacy-postgres-contact-request",
                databaseResourceUid = "database-uid-1",
                databaseResourceGeneration = "17",
                targetNamespace = "maliev-legacy",
                targetCluster = "legacy-postgres-main",
                targetAuthority = files.Authority,
                authorizationKey = new
                {
                    keyId = files.AuthorizationSigner.KeyId,
                    subjectPublicKeyInfoPath = files.AuthorizationPublicKeyPath,
                },
                executionKey = new
                {
                    keyId = files.ExecutionSigner.KeyId,
                    subjectPublicKeyInfoPath = files.ExecutionPublicKeyPath,
                },
                authorizationPath,
                authorizationExpiresAtUtc = files.Now.AddMinutes(9),
                allowAuthorizationSigning = allowAuthorization,
                allowExecution,
            },
        }, JsonOptions));
        ProtectFileOnUnix(configPath);
        return configPath;
    }

    private static FreshSchemaPlan Schema(DateTimeOffset now)
    {
        var table = new TableCopyPlan("dbo", "Items", "public", "Items", ["Id"], ["Id"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["Id"] = "integer" },
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["Id"] = "int" },
            PrimaryKey = new("PK_Items", ["Id"]),
        };
        var draft = new DatabaseSchemaPlan("ContactRequest", "1", new string('1', 64), string.Empty, [table]);
        DatabaseSchemaPlan database = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        return new("2.0", now, new string('a', 40), [database]);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private static void ProtectFileOnUnix(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }

    private sealed class RejectingRuntime : ICanonicalDatabaseBootstrapConsoleRuntime
    {
        public Task<CanonicalDatabaseBootstrapReceipt> ExecuteAsync(
            CanonicalDatabaseBootstrapConsoleRuntimeRequest request,
            CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("Runtime must not be called.");
        }
    }

    private sealed class CapturingRuntime(DateTimeOffset completedAtUtc) : ICanonicalDatabaseBootstrapConsoleRuntime
    {
        public CanonicalDatabaseBootstrapConsoleRuntimeRequest? Request { get; private set; }

        public Task<CanonicalDatabaseBootstrapReceipt> ExecuteAsync(
            CanonicalDatabaseBootstrapConsoleRuntimeRequest request,
            CancellationToken cancellationToken)
        {
            Request = request;
            return Task.FromResult(new CanonicalDatabaseBootstrapReceipt(
                "1.0", request.Authorization.AuthorizationId, request.Request.Schema.Database,
                request.Request.Schema.TargetSchemaSha256, request.Request.DatabaseResourceName,
                request.Request.DatabaseResourceUid, request.Request.DatabaseResourceGeneration,
                request.Request.TargetAuthority, completedAtUtc, request.ExecutionSigner.KeyId, "test-signature"));
        }
    }

    private sealed record TestFiles(
        DateTimeOffset Now,
        FreshSchemaPlan Schema,
        DeltaTargetAuthority Authority,
        string SchemaPath,
        string ConnectionPath,
        string AuthorizationPublicKeyPath,
        string ExecutionPublicKeyPath,
        string AuthorizationPrivateKeyPath,
        string ExecutionPrivateKeyPath,
        P256MigrationEvidenceSigner AuthorizationSigner,
        P256MigrationEvidenceSigner ExecutionSigner,
        IReceiptAttestationTrustStore AuthorizationTrust) : IDisposable
    {
        public void Dispose()
        {
            AuthorizationSigner.Dispose();
            ExecutionSigner.Dispose();
        }
    }
}
