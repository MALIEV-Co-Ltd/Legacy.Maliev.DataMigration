using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class FullSchemaTargetExtensionRepairProofFactAttribute : FactAttribute
{
    public FullSchemaTargetExtensionRepairProofFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("LEGACY_RUN_FULL_SCHEMA_EXTENSION_PROOF") != "1")
        {
            Skip = "Requires a fresh owner-protected live exact-23 schema plan and disposable-only proof inputs.";
        }
    }
}

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class FullSchemaTargetExtensionRepairProofTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [FullSchemaTargetExtensionRepairProofFact]
    public async Task FreshLiveExact23Schema_RepairsBothExtensionsOnDisposablePostgreSql()
    {
        string schemaPath = Required("LEGACY_FULL_SCHEMA_EXTENSION_PLAN_PATH");
        string sourceCommit = Required("LEGACY_FULL_SCHEMA_EXTENSION_SOURCE_COMMIT");
        string proofDirectory = Required("LEGACY_FULL_SCHEMA_EXTENSION_PROOF_DIRECTORY");
        string keyManifestPath = Path.Combine(proofDirectory, "public-manifest.json");
        Assert.True(OwnerProtectedFilePolicy.IsOwnerOnly(schemaPath));
        Assert.True(OwnerProtectedFilePolicy.IsOwnerOnly(keyManifestPath));
        OwnerProtectedFilePolicy.ValidatePublicationParent(Path.Combine(proofDirectory, "proof-output.json"));
        FreshSchemaPlan schema = JsonSerializer.Deserialize<FreshSchemaPlan>(
            await File.ReadAllTextAsync(schemaPath), JsonOptions)!;
        Assert.Equal("2.0", schema.SchemaVersion);
        Assert.Equal(sourceCommit, schema.SourceCommitSha);
        Assert.True(DateTimeOffset.UtcNow - schema.CapturedAtUtc < TimeSpan.FromHours(2));
        Assert.True(schema.Databases.Select(database => database.Database)
            .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal));
        Assert.All(schema.Databases, database => Assert.NotEmpty(database.Tables));
        Assert.Equal(ApprovedTargetExtensionManifest.MaterialCatalogV1,
            schema.Databases.Single(database => database.Database == "Material").TargetExtensionProfile);
        Assert.Equal(ApprovedTargetExtensionManifest.QuotationRequestIdempotencyV1,
            schema.Databases.Single(database => database.Database == "QuotationRequest").TargetExtensionProfile);

        using JsonDocument keys = JsonDocument.Parse(await File.ReadAllTextAsync(keyManifestPath));
        JsonElement authorizationKey = keys.RootElement.GetProperty("roles").GetProperty("authorization");
        string keyId = authorizationKey.GetProperty("keyId").GetString()!;
        string privateKeyPath = authorizationKey.GetProperty("privateKeyPath").GetString()!;
        string publicKeyPath = authorizationKey.GetProperty("publicKeyPath").GetString()!;
        Assert.True(OwnerProtectedFilePolicy.IsOwnerOnly(privateKeyPath));
        Assert.True(OwnerProtectedFilePolicy.IsOwnerOnly(publicKeyPath));

        await using PostgreSqlContainer container = new PostgreSqlBuilder("postgres:18-alpine").Build();
        await container.StartAsync();
        string connectionString = container.GetConnectionString();
        await using (var control = new NpgsqlConnection(connectionString))
        {
            await control.OpenAsync();
            foreach (DatabaseSchemaPlan database in schema.Databases)
            {
                await using var create = new NpgsqlCommand(
                    $"CREATE DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(database.Database)};", control);
                _ = await create.ExecuteNonQueryAsync();
            }
        }

        string systemIdentifier;
        await using (var control = new NpgsqlConnection(connectionString))
        {
            await control.OpenAsync();
            await using var identity = new NpgsqlCommand("SELECT system_identifier::text FROM pg_control_system();", control);
            systemIdentifier = (string)(await identity.ExecuteScalarAsync() ?? throw new InvalidOperationException());
        }
        string systemHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(systemIdentifier)))
            .ToLowerInvariant();
        var authority = new DeltaTargetAuthority(DeltaTargetAuthorityKind.LocalAspire,
            "aspire://legacy-postgres-main-local/disposable-full-schema-" + Guid.NewGuid().ToString("N"),
            systemHash);

        foreach (DatabaseSchemaPlan database in schema.Databases)
        {
            DatabaseSchemaPlan fixture = FixtureSchema(database);
            var builder = new NpgsqlConnectionStringBuilder(connectionString) { Database = database.Database };
            await using var connection = new NpgsqlConnection(builder.ConnectionString);
            await connection.OpenAsync();
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
            await using var writer = new PostgreSqlWholeDatabaseTransaction(connection, transaction,
                ownsResources: false);
            await writer.ApplySchemaAsync(fixture, CancellationToken.None);
            await writer.FinalizeSchemaAsync(fixture, CancellationToken.None);
            Assert.Equal(fixture.TargetSchemaSha256,
                await writer.InspectSchemaAsync(fixture, CancellationToken.None));
            await transaction.CommitAsync();
        }

        string runId = Guid.NewGuid().ToString("N");
        string targetConnectionPath = Path.Combine(proofDirectory, $"target-disposable-{runId}.connection");
        await File.WriteAllTextAsync(targetConnectionPath, connectionString);
        Assert.True(OwnerProtectedFilePolicy.IsOwnerOnly(targetConnectionPath));
        foreach (string databaseName in new[] { "Material", "QuotationRequest" })
        {
            DatabaseSchemaPlan database = schema.Databases.Single(item => item.Database == databaseName);
            string missing = TargetExtensionRepairAuthorizationProducer.ExpectedMissingSet(database);
            TargetSchemaGap gap = await TargetSchemaGapInspector.InspectDatabaseAsync(database,
                new NpgsqlConnectionStringBuilder(connectionString) { Database = databaseName }.ConnectionString,
                CancellationToken.None);
            Assert.Equal(missing, string.Join(';', gap.MissingApprovedTargetExtensions));
            Assert.Empty(gap.MissingTables);
            Assert.Empty(gap.MissingColumns);
            Assert.Empty(gap.TargetOnlyTables);
            Assert.Empty(gap.TargetOnlyColumns);

            string prefix = $"extension-{databaseName}-{runId}";
            string authorizationPath = Path.Combine(proofDirectory, prefix + "-authorization.json");
            string receiptPath = Path.Combine(proofDirectory, prefix + "-receipt.json");
            string authorizeConfigPath = Path.Combine(proofDirectory, prefix + "-authorize-config.json");
            string applyConfigPath = Path.Combine(proofDirectory, prefix + "-apply-config.json");
            await File.WriteAllTextAsync(authorizeConfigPath, Config(schemaPath, databaseName,
                targetConnectionPath, authority, missing, keyId, publicKeyPath, authorizationPath,
                null, authorize: true, execute: false));
            await File.WriteAllTextAsync(applyConfigPath, Config(schemaPath, databaseName,
                targetConnectionPath, authority, missing, keyId, publicKeyPath, receiptPath,
                authorizationPath, authorize: false, execute: true));
            Assert.True(OwnerProtectedFilePolicy.IsOwnerOnly(authorizeConfigPath));
            Assert.True(OwnerProtectedFilePolicy.IsOwnerOnly(applyConfigPath));

            using var authorizationError = new StringWriter();
            int authorized = await MigrationConsole.RunExtensionRepairForTestsAsync(
                ["authorize-target-extension-repair", "--config", authorizeConfigPath],
                TextWriter.Null, authorizationError,
                name => name switch
                {
                    "LEGACY_DEPLOY_ENABLED" => "false",
                    "LEGACY_MIGRATION_CALLER" => "owner",
                    "LEGACY_MIGRATION_EXTENSION_REPAIR_AUTHORIZATION_SIGNING_KEY_FILE" => privateKeyPath,
                    _ => null,
                }, CancellationToken.None);
            Assert.True(authorized == 0, authorizationError.ToString());

            using var applyError = new StringWriter();
            int applied = await MigrationConsole.RunExtensionRepairForTestsAsync(
                ["apply-target-extension-repair", "--config", applyConfigPath],
                TextWriter.Null, applyError,
                name => name switch
                {
                    "LEGACY_DEPLOY_ENABLED" => "false",
                    "LEGACY_MIGRATION_CALLER" => "owner",
                    _ => null,
                }, CancellationToken.None);
            Assert.True(applied == 0, applyError.ToString());
            using JsonDocument receipt = JsonDocument.Parse(await File.ReadAllTextAsync(receiptPath));
            Assert.Equal("created", receipt.RootElement.GetProperty("disposition").GetString());
            Assert.Equal(database.TargetSchemaSha256,
                receipt.RootElement.GetProperty("targetSchemaSha256").GetString());
            await ApprovedTargetExtensionRepair.VerifyPostCommitAsync(database,
                new NpgsqlConnectionStringBuilder(connectionString) { Database = databaseName }.ConnectionString,
                systemHash, CancellationToken.None);
        }
    }

    private static DatabaseSchemaPlan FixtureSchema(DatabaseSchemaPlan database)
    {
        DatabaseSchemaPlan fixture = database.Database == "Quotation"
            ? database with
            {
                Tables = ApprovedSourceDispositionManifest.TargetTablesFor(database),
                SourceDispositionProfile = null,
                SourceTableDispositions = [],
            }
            : database with { TargetExtensionProfile = null };
        return fixture with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(fixture) };
    }

    private static string Config(string schemaPath, string database, string targetConnectionPath,
        DeltaTargetAuthority authority, string missing, string keyId, string publicKeyPath,
        string outputPath, string? authorizationPath, bool authorize, bool execute)
    {
        return JsonSerializer.Serialize(new
        {
            targetExtensionRepair = new
            {
                schemaPlanPath = schemaPath,
                database,
                targetConnectionFile = targetConnectionPath,
                targetAuthority = authority,
                reviewedMissingTables = missing,
                authorizationKey = new { keyId, subjectPublicKeyInfoPath = publicKeyPath },
                outputPath,
                authorizationPath,
                authorizationExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                allowAuthorizationSigning = authorize,
                allowExecution = execute,
            },
        }, JsonOptions);
    }

    private static string Required(string name)
    {
        return Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException(name + " is required for the disposable proof.");
    }
}
