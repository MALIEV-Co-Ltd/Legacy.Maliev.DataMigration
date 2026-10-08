using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class LocalSchemaCatalogConsoleTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "legacy-local-catalog-tests", Guid.NewGuid().ToString("N"));

    public LocalSchemaCatalogConsoleTests()
    {
        OwnerProtectedDirectory.CreateNew(_directory);
    }

    [Theory]
    [InlineData("inspect-local-schema-catalog", DeltaTargetAuthorityKind.ProductionCloudNativePg)]
    [InlineData("inspect-production-schema-catalog", DeltaTargetAuthorityKind.LocalAspire)]
    public async Task Wrong_authority_is_rejected_before_target_access(string command, string kind)
    {
        string config = await ConfigureAsync(kind, FreshPlan(), null);
        (int code, string error) = await InvokeAsync(command, config);
        Assert.Equal(65, code);
        Assert.Equal("delta_schema_catalog_boundary_invalid" + Environment.NewLine, error);
    }

    [Fact]
    public async Task Stale_schema_is_rejected_before_target_access()
    {
        string config = await ConfigureAsync(DeltaTargetAuthorityKind.LocalAspire,
            FreshPlan() with { CapturedAtUtc = DateTimeOffset.UtcNow.AddHours(-3) }, null);
        (int code, string error) = await InvokeAsync("inspect-local-schema-catalog", config);
        Assert.Equal(70, code);
        Assert.Equal("delta_schema_catalog_boundary_invalid" + Environment.NewLine, error);
    }

    [Fact]
    public async Task Non_loopback_connection_is_rejected_without_echoing_credentials()
    {
        string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        string connection = new NpgsqlConnectionStringBuilder
        {
            Host = "remote.invalid",
            Database = "postgres",
            Username = "test",
            Password = password,
        }.ConnectionString;
        string config = await ConfigureAsync(DeltaTargetAuthorityKind.LocalAspire, FreshPlan(), connection);
        (int code, string error) = await InvokeAsync("inspect-local-schema-catalog", config);
        Assert.Equal(65, code);
        Assert.Equal("delta_schema_catalog_local_loopback_required" + Environment.NewLine, error);
        Assert.DoesNotContain(password, error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Disposable_exact23_catalog_reports_shape_without_rows_or_target_mutation()
    {
        await using var container = new PostgreSqlBuilder("postgres:18-alpine")
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 384L * 1024 * 1024;
                parameters.HostConfig.MemorySwap = 384L * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 500000000;
            })
            .WithDatabase("postgres").WithPassword(Convert.ToHexString(RandomNumberGenerator.GetBytes(24))).Build();
        await container.StartAsync();
        string connectionString = new NpgsqlConnectionStringBuilder(container.GetConnectionString())
        {
            Host = "127.0.0.1",
            Pooling = false,
        }.ConnectionString;
        await using (var admin = new NpgsqlConnection(connectionString))
        {
            await admin.OpenAsync();
            foreach (string database in DatabaseInventory.ActiveDatabases)
            {
                await using var create = new NpgsqlCommand($"CREATE DATABASE \"{database}\"", admin);
                _ = await create.ExecuteNonQueryAsync();
            }
        }
        var countryConnection = new NpgsqlConnectionStringBuilder(connectionString) { Database = "Country" };
        await using var country = new NpgsqlConnection(countryConnection.ConnectionString);
        await country.OpenAsync();
        await using (var seed = new NpgsqlCommand(
            "CREATE TABLE public.\"CatalogProbe\" (\"Id\" integer PRIMARY KEY, \"Value\" text DEFAULT 'private-default'); " +
            "INSERT INTO public.\"CatalogProbe\" VALUES (1, 'private-row-marker');", country))
        {
            _ = await seed.ExecuteNonQueryAsync();
        }
        string fingerprint;
        await using (var identity = new NpgsqlCommand("SELECT system_identifier::text FROM pg_control_system();", country))
        {
            string identifier = (string)(await identity.ExecuteScalarAsync())!;
            fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identifier))).ToLowerInvariant();
        }
        string config = await ConfigureAsync(DeltaTargetAuthorityKind.LocalAspire, FreshPlan(), connectionString, fingerprint);
        (int code, string error) = await InvokeAsync("inspect-local-schema-catalog", config);
        Assert.Equal(0, code);
        Assert.Equal(string.Empty, error);
        string json = await File.ReadAllTextAsync(Path.Combine(_directory, "catalog.json"));
        using JsonDocument result = JsonDocument.Parse(json);
        Assert.Equal("read-only-full-catalog-not-reconciliation", result.RootElement.GetProperty("inspectionKind").GetString());
        Assert.Equal(23, result.RootElement.GetProperty("databases").GetArrayLength());
        JsonElement observed = Assert.Single(result.RootElement.GetProperty("databases").EnumerateArray(),
            database => database.GetProperty("database").GetString() == "Country");
        JsonElement probe = Assert.Single(observed.GetProperty("tableDiagnostics").EnumerateArray(),
            table => table.GetProperty("table").GetString() == "CatalogProbe");
        Assert.Equal("target-only-table", probe.GetProperty("status").GetString());
        Assert.DoesNotContain("private-row-marker", json, StringComparison.Ordinal);
        Assert.DoesNotContain("private-default", json, StringComparison.Ordinal);
        Assert.DoesNotContain(new NpgsqlConnectionStringBuilder(connectionString).Password!, json, StringComparison.Ordinal);
        await using var readback = new NpgsqlCommand("SELECT \"Value\" FROM public.\"CatalogProbe\" WHERE \"Id\"=1", country);
        Assert.Equal("private-row-marker", await readback.ExecuteScalarAsync());
    }

    private async Task<string> ConfigureAsync(string kind, FreshSchemaPlan schema, string? target, string? fingerprint = null)
    {
        string schemaPath = Path.Combine(_directory, "schema.json");
        string targetPath = Path.Combine(_directory, "target.connection");
        await MigrationConsole.WriteNewJsonForTestsAsync(schemaPath, schema, CancellationToken.None);
        if (target is not null)
        {
            await File.WriteAllTextAsync(targetPath, target);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(targetPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }

        bool local = kind == DeltaTargetAuthorityKind.LocalAspire;
        var authority = new DeltaTargetAuthority(kind,
            local ? "aspire://legacy-postgres-main-local/disposable-catalog-test" : "gke://maliev-website/catalog-test",
            fingerprint ?? new string('a', 64));
        string config = Path.Combine(_directory, "config.json");
        await MigrationConsole.WriteNewJsonForTestsAsync(config, new
        {
            delta = new
            {
                schemaPlanPath = schemaPath,
                outputPath = Path.Combine(_directory, "catalog.json"),
                targetConnectionFile = targetPath,
                targetNamespace = local ? "local-aspire" : "maliev-legacy",
                targetCluster = local ? "legacy-postgres-main-local" : "legacy-postgres-main",
                targetAuthority = authority,
            },
        }, CancellationToken.None);
        return config;
    }

    private static FreshSchemaPlan FreshPlan()
    {
        return new("2.0", DateTimeOffset.UtcNow, new string('b', 40),
        [.. DatabaseInventory.ActiveDatabases.Select(name =>
        {
            var database = new DatabaseSchemaPlan(name, "1.0", new string('a', 64), string.Empty, []);
            return database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
        })]);
    }

    private static async Task<(int Code, string Error)> InvokeAsync(string command, string config)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        int code = await MigrationConsole.RunDeltaForTestsAsync([command, "--config", config], output, error,
            name => name switch
            {
                "LEGACY_DEPLOY_ENABLED" => "false",
                "LEGACY_MIGRATION_CALLER" => "owner",
                _ => throw new InvalidOperationException("Catalog inspection must not project signing keys."),
            }, new DefaultGuardedDeltaConsoleRuntime(), CancellationToken.None);
        return (code, error.ToString());
    }

    public void Dispose()
    {
        Directory.Delete(_directory, recursive: true);
    }
}
