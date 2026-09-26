using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class TargetExtensionRepairConsoleIntegrationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task SignedDdlCommandCreatesOnlyApprovedTablesOnDisposableExact23()
    {
        await using PostgreSqlContainer container = new PostgreSqlBuilder("postgres:18-alpine").Build();
        await container.StartAsync();
        string adminConnection = container.GetConnectionString();
        await using (var admin = new NpgsqlConnection(adminConnection))
        {
            await admin.OpenAsync();
            foreach (string name in DatabaseInventory.ActiveDatabases)
            {
                await using var create = new NpgsqlCommand(
                    $"CREATE DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(name)};", admin);
                _ = await create.ExecuteNonQueryAsync();
            }
        }
        var materialBuilder = new NpgsqlConnectionStringBuilder(adminConnection) { Database = "Material" };
        await using (var material = new NpgsqlConnection(materialBuilder.ConnectionString))
        {
            await material.OpenAsync();
            await using var create = new NpgsqlCommand(
                "CREATE TABLE public.\"Probe\" (\"ID\" integer NOT NULL, CONSTRAINT \"PK_Probe\" PRIMARY KEY (\"ID\"));", material);
            _ = await create.ExecuteNonQueryAsync();
        }

        string root = Path.Combine(Path.GetTempPath(), $"extension-repair-integration-{Guid.NewGuid():N}");
        OwnerProtectedDirectory.CreateNew(root);
        try
        {
            string authorityHash;
            await using (var admin = new NpgsqlConnection(adminConnection))
            {
                await admin.OpenAsync();
                await using var identifier = new NpgsqlCommand("SELECT system_identifier::text FROM pg_control_system();", admin);
                string value = (string)(await identifier.ExecuteScalarAsync() ?? throw new InvalidOperationException());
                authorityHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
            }
            var authority = new DeltaTargetAuthority(DeltaTargetAuthorityKind.LocalAspire,
                "aspire://legacy-postgres-main-local/disposable-test", authorityHash);
            DatabaseSchemaPlan materialPlan = Plan("Material", ApprovedTargetExtensionManifest.MaterialCatalogV1);
            FreshSchemaPlan schema = new("2.0", DateTimeOffset.UtcNow, new string('a', 40),
                [.. DatabaseInventory.ActiveDatabases.Select(name => name == "Material" ? materialPlan : Plan(name, null))]);
            string schemaPath = Path.Combine(root, "schema.json");
            string connectionPath = Path.Combine(root, "connection.txt");
            string keyPath = Path.Combine(root, "authorization.private.pem");
            string publicPath = Path.Combine(root, "authorization.public.spki.b64");
            string authorizationPath = Path.Combine(root, "authorization.json");
            string receiptPath = Path.Combine(root, "receipt.json");
            string authorizeConfigPath = Path.Combine(root, "authorize-config.json");
            string applyConfigPath = Path.Combine(root, "apply-config.json");
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            await File.WriteAllTextAsync(schemaPath, JsonSerializer.Serialize(schema, JsonOptions));
            await File.WriteAllTextAsync(connectionPath, adminConnection);
            await File.WriteAllTextAsync(keyPath, key.ExportECPrivateKeyPem());
            await File.WriteAllTextAsync(publicPath, Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
            await File.WriteAllTextAsync(authorizeConfigPath, Config(schemaPath, connectionPath, publicPath,
                authority, authorizationPath, null, authorize: true, execute: false));
            await File.WriteAllTextAsync(applyConfigPath, Config(schemaPath, connectionPath, publicPath,
                authority, receiptPath, authorizationPath, authorize: false, execute: true));
            foreach (string path in new[] { schemaPath, connectionPath, keyPath, publicPath, authorizeConfigPath, applyConfigPath })
            {
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
            }

            using var authorizeOutput = new StringWriter();
            using var authorizeError = new StringWriter();
            int authorized = await MigrationConsole.RunExtensionRepairForTestsAsync(
                ["authorize-target-extension-repair", "--config", authorizeConfigPath],
                authorizeOutput, authorizeError,
                name => name switch
                {
                    "LEGACY_DEPLOY_ENABLED" => "false",
                    "LEGACY_MIGRATION_CALLER" => "owner",
                    "LEGACY_MIGRATION_EXTENSION_REPAIR_AUTHORIZATION_SIGNING_KEY_FILE" => keyPath,
                    _ => null,
                }, CancellationToken.None);
            Assert.Equal(0, authorized);
            Assert.Equal(string.Empty, authorizeError.ToString());
            string originalAuthorization = await File.ReadAllTextAsync(authorizationPath);
            using (var reusedError = new StringWriter())
            {
                int reused = await MigrationConsole.RunExtensionRepairForTestsAsync(
                    ["authorize-target-extension-repair", "--config", authorizeConfigPath],
                    TextWriter.Null, reusedError,
                    name => name switch
                    {
                        "LEGACY_DEPLOY_ENABLED" => "false",
                        "LEGACY_MIGRATION_CALLER" => "owner",
                        "LEGACY_MIGRATION_EXTENSION_REPAIR_AUTHORIZATION_SIGNING_KEY_FILE" => keyPath,
                        _ => null,
                    }, CancellationToken.None);
                Assert.NotEqual(0, reused);
                Assert.Equal(originalAuthorization, await File.ReadAllTextAsync(authorizationPath));
            }

            await File.WriteAllTextAsync(receiptPath, "occupied");
            using (var occupiedError = new StringWriter())
            {
                int blocked = await MigrationConsole.RunExtensionRepairForTestsAsync(
                    ["apply-target-extension-repair", "--config", applyConfigPath],
                    TextWriter.Null, occupiedError,
                    name => name switch
                    {
                        "LEGACY_DEPLOY_ENABLED" => "false",
                        "LEGACY_MIGRATION_CALLER" => "owner",
                        _ => null,
                    }, CancellationToken.None);
                Assert.NotEqual(0, blocked);
                await using var before = new NpgsqlConnection(materialBuilder.ConnectionString);
                await before.OpenAsync();
                await using var countBefore = new NpgsqlCommand(
                    "SELECT COUNT(*) FROM pg_tables WHERE schemaname='public' AND tablename IN ('Probe','Country','Currency');", before);
                Assert.Equal(1L, await countBefore.ExecuteScalarAsync());
            }
            File.Delete(receiptPath);

            string pendingPath = Path.Combine(root, "pending-receipt.json");
            string pendingConfigPath = Path.Combine(root, "pending-config.json");
            await File.WriteAllTextAsync(pendingConfigPath, Config(schemaPath, connectionPath, publicPath,
                authority, pendingPath, authorizationPath, authorize: false, execute: true));
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(pendingConfigPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            await using (var driftConnection = new NpgsqlConnection(materialBuilder.ConnectionString))
            {
                await driftConnection.OpenAsync();
                await using var drift = new NpgsqlCommand("CREATE TABLE public.\"Unexpected\" (\"ID\" integer);", driftConnection);
                _ = await drift.ExecuteNonQueryAsync();
            }
            using (var driftError = new StringWriter())
            {
                int blocked = await MigrationConsole.RunExtensionRepairForTestsAsync(
                    ["apply-target-extension-repair", "--config", pendingConfigPath],
                    TextWriter.Null, driftError,
                    name => name switch
                    {
                        "LEGACY_DEPLOY_ENABLED" => "false",
                        "LEGACY_MIGRATION_CALLER" => "owner",
                        _ => null,
                    }, CancellationToken.None);
                Assert.NotEqual(0, blocked);
                Assert.Contains("\"pending\"", await File.ReadAllTextAsync(pendingPath));
            }
            await using (var driftConnection = new NpgsqlConnection(materialBuilder.ConnectionString))
            {
                await driftConnection.OpenAsync();
                await using var drift = new NpgsqlCommand("DROP TABLE public.\"Unexpected\";", driftConnection);
                _ = await drift.ExecuteNonQueryAsync();
            }

            using var applyOutput = new StringWriter();
            using var applyError = new StringWriter();
            int applied = await MigrationConsole.RunExtensionRepairForTestsAsync(
                ["apply-target-extension-repair", "--config", applyConfigPath],
                applyOutput, applyError,
                name => name switch
                {
                    "LEGACY_DEPLOY_ENABLED" => "false",
                    "LEGACY_MIGRATION_CALLER" => "owner",
                    _ => null,
                }, CancellationToken.None);
            Assert.Equal(0, applied);
            Assert.Equal(string.Empty, applyError.ToString());
            Assert.Contains("\"created\"", await File.ReadAllTextAsync(receiptPath));
            using (JsonDocument authorizationJson = JsonDocument.Parse(await File.ReadAllTextAsync(authorizationPath)))
            using (JsonDocument receiptJson = JsonDocument.Parse(await File.ReadAllTextAsync(receiptPath)))
            {
                Assert.Equal(authorizationJson.RootElement.GetProperty("authorizationId").GetGuid(),
                    receiptJson.RootElement.GetProperty("authorizationId").GetGuid());
                Assert.Equal(64, receiptJson.RootElement.GetProperty("authorizationEnvelopeSha256")
                    .GetString()!.Length);
                Assert.Equal("public.Country;public.Currency",
                    receiptJson.RootElement.GetProperty("reviewedMissingTables").GetString());
            }
            await using var verify = new NpgsqlConnection(materialBuilder.ConnectionString);
            await verify.OpenAsync();
            await using var count = new NpgsqlCommand(
                "SELECT COUNT(*) FROM pg_tables WHERE schemaname='public' AND tablename IN ('Probe','Country','Currency');", verify);
            Assert.Equal(3L, await count.ExecuteScalarAsync());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string Config(string schemaPath, string connectionPath, string publicPath,
        DeltaTargetAuthority authority, string outputPath, string? authorizationPath, bool authorize, bool execute)
    {
        return JsonSerializer.Serialize(new
        {
            targetExtensionRepair = new
            {
                schemaPlanPath = schemaPath,
                database = "Material",
                targetConnectionFile = connectionPath,
                targetAuthority = authority,
                reviewedMissingTables = "public.Country;public.Currency",
                authorizationKey = new { keyId = "extension-repair-test", subjectPublicKeyInfoPath = publicPath },
                outputPath,
                authorizationPath,
                authorizationExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                allowAuthorizationSigning = authorize,
                allowExecution = execute,
            },
        }, JsonOptions);
    }

    private static DatabaseSchemaPlan Plan(string database, string? profile)
    {
        var table = new TableCopyPlan("dbo", "Probe", "public", "Probe", ["ID"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["ID"] = "integer" },
            PrimaryKey = new PrimaryKeyCopyPlan("PK_Probe", ["ID"]),
        };
        var draft = new DatabaseSchemaPlan(database, "1.0", new string('b', 64), new string('0', 64), [table])
        {
            TargetExtensionProfile = profile,
        };
        return draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
    }
}
