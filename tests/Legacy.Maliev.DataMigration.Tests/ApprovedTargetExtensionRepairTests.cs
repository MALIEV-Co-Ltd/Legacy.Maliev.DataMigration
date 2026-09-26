using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class ApprovedTargetExtensionRepairTests(PostgreSqlAdapterFixture fixture)
{
    [Theory]
    [InlineData("Material", ApprovedTargetExtensionManifest.MaterialCatalogV1, "public.Country;public.Currency")]
    [InlineData("QuotationRequest", ApprovedTargetExtensionManifest.QuotationRequestIdempotencyV1,
        "public.RequestCreateIdempotency")]
    public async Task Repair_CreatesOnlyReviewedMissingExtensionsAndIsIdempotent(
        string database, string profile, string reviewedMissing)
    {
        (PostgreSqlShadowTarget target, ShadowDatabase shadow, DatabaseSchemaPlan plan, string connectionString) =
            await CreateSourceOnlyDatabaseAsync(database, profile);
        try
        {
            string systemIdentifier = await SystemIdentifierSha256Async(connectionString);
            string first = await ApprovedTargetExtensionRepair.ExecuteAsync(
                plan, connectionString, shadow.Name, systemIdentifier, reviewedMissing, CancellationToken.None);
            Assert.Equal("created", first);
            string second = await ApprovedTargetExtensionRepair.ExecuteAsync(
                plan, connectionString, shadow.Name, systemIdentifier, reviewedMissing, CancellationToken.None);
            Assert.Equal("already-current", second);

            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync();
            await using var transaction = await connection.BeginTransactionAsync();
            var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
            Assert.Equal(plan.TargetSchemaSha256, await inspector.InspectSchemaAsync(plan, CancellationToken.None));
            await transaction.RollbackAsync();
            Assert.Equal(1, await CountProbeRowsAsync(connectionString));
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task Repair_RejectsUnreviewedTableWithoutCreatingExtensions()
    {
        (PostgreSqlShadowTarget target, ShadowDatabase shadow, DatabaseSchemaPlan plan, string connectionString) =
            await CreateSourceOnlyDatabaseAsync("Material", ApprovedTargetExtensionManifest.MaterialCatalogV1);
        try
        {
            await ExecuteSqlAsync(connectionString, "CREATE TABLE public.\"Unexpected\" (\"ID\" integer);");
            string systemIdentifier = await SystemIdentifierSha256Async(connectionString);
            MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                ApprovedTargetExtensionRepair.ExecuteAsync(plan, connectionString, shadow.Name, systemIdentifier,
                    "public.Country;public.Currency", CancellationToken.None));
            Assert.Equal("target_extension_repair_schema_drift", failure.Code);
            Assert.Equal(0, await CountTablesAsync(connectionString, "Country", "Currency"));
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task Repair_RejectsPartiallyPresentApprovedSetWithoutCreatingAnotherTable()
    {
        (PostgreSqlShadowTarget target, ShadowDatabase shadow, DatabaseSchemaPlan plan, string connectionString) =
            await CreateSourceOnlyDatabaseAsync("Material", ApprovedTargetExtensionManifest.MaterialCatalogV1);
        try
        {
            await ExecuteSqlAsync(connectionString, "CREATE TABLE public.\"Country\" (\"ID\" integer);");
            string systemIdentifier = await SystemIdentifierSha256Async(connectionString);
            MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                ApprovedTargetExtensionRepair.ExecuteAsync(plan, connectionString, shadow.Name, systemIdentifier,
                    "public.Country;public.Currency", CancellationToken.None));
            Assert.Equal("target_extension_repair_missing_set_invalid", failure.Code);
            Assert.Equal(1, await CountTablesAsync(connectionString, "Country", "Currency"));
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    private async Task<(PostgreSqlShadowTarget, ShadowDatabase, DatabaseSchemaPlan, string)>
        CreateSourceOnlyDatabaseAsync(string database, string profile)
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(database,
            $"legacy_shadow_extension_repair_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), CancellationToken.None);
        DatabaseSchemaPlan sourceOnly = Plan(database, null);
        await using (IPostgreSqlWholeDatabaseTransaction transaction =
            await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None))
        {
            await transaction.ApplySchemaAsync(sourceOnly, CancellationToken.None);
            await transaction.FinalizeSchemaAsync(sourceOnly, CancellationToken.None);
            _ = await transaction.InspectSchemaAsync(sourceOnly, CancellationToken.None);
            _ = await transaction.InspectTableAsync(sourceOnly.Tables[0], CancellationToken.None);
            await transaction.CommitAsync(CancellationToken.None);
        }
        string connectionString = new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString)
        {
            Database = shadow.Name,
        }.ConnectionString;
        await ExecuteSqlAsync(connectionString, "INSERT INTO public.\"Probe\" (\"ID\") VALUES (7);");
        return (target, shadow, Plan(database, profile), connectionString);
    }

    private static DatabaseSchemaPlan Plan(string database, string? profile)
    {
        var table = new TableCopyPlan("dbo", "Probe", "public", "Probe", ["ID"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["ID"] = "integer" },
            PrimaryKey = new PrimaryKeyCopyPlan("PK_Probe", ["ID"]),
        };
        var draft = new DatabaseSchemaPlan(database, "1.0", new string('a', 64), new string('0', 64), [table])
        {
            TargetExtensionProfile = profile,
        };
        return draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
    }

    private static async Task<string> SystemIdentifierSha256Async(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT system_identifier::text FROM pg_control_system();", connection);
        string identifier = (string)(await command.ExecuteScalarAsync() ?? throw new InvalidOperationException());
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(identifier))).ToLowerInvariant();
    }

    private static async Task ExecuteSqlAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static async Task<long> CountTablesAsync(string connectionString, params string[] tables)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT COUNT(*) FROM pg_tables WHERE schemaname='public' AND tablename = ANY($1);", connection);
        _ = command.Parameters.AddWithValue(tables);
        return (long)(await command.ExecuteScalarAsync() ?? throw new InvalidOperationException());
    }

    private static async Task<long> CountProbeRowsAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT COUNT(*) FROM public.\"Probe\" WHERE \"ID\"=7;", connection);
        return (long)(await command.ExecuteScalarAsync() ?? throw new InvalidOperationException());
    }
}
