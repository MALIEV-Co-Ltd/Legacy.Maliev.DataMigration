using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class ApprovedTargetExtensionManifestTests(PostgreSqlAdapterFixture fixture)
{
    [Theory]
    [InlineData("Material", ApprovedTargetExtensionManifest.MaterialCatalogV1, "Country")]
    [InlineData("QuotationRequest", ApprovedTargetExtensionManifest.QuotationRequestIdempotencyV1, "RequestCreateIdempotency")]
    public async Task ApprovedExtension_IsFingerprintedAndUnexpectedChangesFailClosed(
        string database, string profile, string extensionTable)
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            database, $"legacy_shadow_extension_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), CancellationToken.None);
        try
        {
            DatabaseSchemaPlan plan = Plan(database, profile);
            ApprovedTargetExtensionState? originalExtensionState = null;
            await using (IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None))
            {
                await transaction.ApplySchemaAsync(plan, CancellationToken.None);
                await transaction.FinalizeSchemaAsync(plan, CancellationToken.None);
                Assert.Equal(plan.TargetSchemaSha256,
                    await transaction.InspectSchemaAsync(plan, CancellationToken.None));
                _ = await transaction.InspectTableAsync(plan.Tables[0], CancellationToken.None);
                await transaction.CommitAsync(CancellationToken.None);
            }

            await using (var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString)
            {
                Database = shadow.Name,
            }.ConnectionString))
            {
                await connection.OpenAsync();
                await using var stateTransaction = await connection.BeginTransactionAsync();
                ApprovedTargetExtensionState before = await ApprovedTargetExtensionStateInspector
                    .InspectAsync(connection, stateTransaction, plan, CancellationToken.None);
                originalExtensionState = before;
                ApprovedTargetExtensionStateInspector.Compare(plan, before, before);
                string insert = database == "Material"
                    ? "INSERT INTO public.\"Country\" (\"Name\") VALUES ('Synthetic');"
                    : $"INSERT INTO public.\"RequestCreateIdempotency\" (\"KeyHash\", \"Fingerprint\", \"RequestID\") VALUES ('{new string('a', 64)}', '{new string('b', 64)}', 1);";
                await using (var command = new NpgsqlCommand(insert, connection, stateTransaction))
                {
                    _ = await command.ExecuteNonQueryAsync();
                }
                ApprovedTargetExtensionState after = await ApprovedTargetExtensionStateInspector
                    .InspectAsync(connection, stateTransaction, plan, CancellationToken.None);
                _ = Assert.Throws<MigrationExecutionException>(() =>
                    ApprovedTargetExtensionStateInspector.Compare(plan, before, after));
                await stateTransaction.RollbackAsync();
            }
            if (database == "Material")
            {
                await using var sequenceConnection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString)
                {
                    Database = shadow.Name,
                }.ConnectionString);
                await sequenceConnection.OpenAsync();
                await using var sequenceTransaction = await sequenceConnection.BeginTransactionAsync();
                ApprovedTargetExtensionState sequenceAdvanced = await ApprovedTargetExtensionStateInspector
                    .InspectAsync(sequenceConnection, sequenceTransaction, plan, CancellationToken.None);
                _ = Assert.Throws<MigrationExecutionException>(() =>
                    ApprovedTargetExtensionStateInspector.Compare(plan, originalExtensionState, sequenceAdvanced));
                await sequenceTransaction.RollbackAsync();
            }

            await ExecuteAsync(shadow, $"ALTER TABLE public.\"{extensionTable}\" ADD COLUMN \"Unreviewed\" integer;");
            await using (IPostgreSqlWholeDatabaseTransaction modified =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None))
            {
                Assert.NotEqual(plan.TargetSchemaSha256,
                    await modified.InspectSchemaAsync(plan, CancellationToken.None));
            }

            await ExecuteAsync(shadow, $"ALTER TABLE public.\"{extensionTable}\" DROP COLUMN \"Unreviewed\";");
            await ExecuteAsync(shadow, "CREATE TABLE public.\"UnknownExtension\" (\"ID\" integer NOT NULL);");
            await using (IPostgreSqlWholeDatabaseTransaction unknown =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None))
            {
                Assert.NotEqual(plan.TargetSchemaSha256,
                    await unknown.InspectSchemaAsync(plan, CancellationToken.None));
            }

            await ExecuteAsync(shadow, "DROP TABLE public.\"UnknownExtension\"; DROP TABLE public.\"Probe\";");
            await using IPostgreSqlWholeDatabaseTransaction missingSource =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            Assert.NotEqual(plan.TargetSchemaSha256,
                await missingSource.InspectSchemaAsync(plan, CancellationToken.None));
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public void Manifest_IsBoundToSignedPlanAndCannotOverlapSourceTables()
    {
        DatabaseSchemaPlan withoutProfile = Plan("Material", null);
        DatabaseSchemaPlan withProfile = Plan("Material", ApprovedTargetExtensionManifest.MaterialCatalogV1);
        FreshSchemaPlan unsignedA = new("2.0", DateTimeOffset.UtcNow, new string('a', 40), [withoutProfile]);
        FreshSchemaPlan unsignedB = unsignedA with { Databases = [withProfile] };
        Assert.NotEqual(SchemaPlanCanonicalizer.ComputeSha256(unsignedA),
            SchemaPlanCanonicalizer.ComputeSha256(unsignedB));

        DatabaseSchemaPlan overlap = withProfile with
        {
            Tables = [withProfile.Tables[0] with { TargetTable = "Country" }],
        };
        MigrationExecutionException exception = Assert.Throws<MigrationExecutionException>(
            () => PostgreSqlSchemaFingerprint.ComputeExpected(overlap));
        Assert.Equal("target_extension_source_overlap", exception.Code);
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

    private async Task ExecuteAsync(ShadowDatabase shadow, string sql)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString)
        {
            Database = shadow.Name,
        }.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }
}
