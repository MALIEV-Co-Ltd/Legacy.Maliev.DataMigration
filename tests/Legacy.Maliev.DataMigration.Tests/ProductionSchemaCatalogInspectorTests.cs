using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ProductionSchemaCatalogPlanTests
{
    [Fact]
    public void ValidatePlan_RequiresFreshExact23AndConsistentTargetFingerprints()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DatabaseSchemaPlan[] databases = [.. DatabaseInventory.ActiveDatabases.Select(name =>
        {
            var plan = new DatabaseSchemaPlan(name, "1.0", new string('a', 64), string.Empty, []);
            return plan with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(plan) };
        })];
        var current = new FreshSchemaPlan("2.0", now.AddMinutes(-1), new string('b', 40), databases);
        ProductionSchemaCatalogInspector.ValidatePlan(current, now);

        Assert.Equal("delta_schema_catalog_boundary_invalid", Assert.Throws<MigrationExecutionException>(
            () => ProductionSchemaCatalogInspector.ValidatePlan(
                current with { CapturedAtUtc = now.AddHours(-3) }, now)).Code);
        Assert.Equal("delta_schema_catalog_boundary_invalid", Assert.Throws<MigrationExecutionException>(
            () => ProductionSchemaCatalogInspector.ValidatePlan(
                current with { Databases = databases[..^1] }, now)).Code);
        databases[0] = databases[0] with { TargetSchemaSha256 = new string('f', 64) };
        Assert.Equal("delta_schema_catalog_boundary_invalid", Assert.Throws<MigrationExecutionException>(
            () => ProductionSchemaCatalogInspector.ValidatePlan(
                current with { Databases = databases }, now)).Code);
    }
}

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class ProductionSchemaCatalogInspectorTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task InspectDatabaseAsync_DisposablePostgreSql_ClassifiesSafeFieldEvidenceWithoutLeakingSql()
    {
        var builder = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = fixture.CanonicalDatabase,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using (var setup = new NpgsqlCommand(
            "CREATE SCHEMA field_probe; " +
            "CREATE TABLE field_probe.\"Sample\" (\"Value\" text COLLATE \"C\" DEFAULT 'private-default', " +
            "\"Computed\" text GENERATED ALWAYS AS (\"Value\" || 'private-generated') STORED, " +
            "\"LockoutEnd\" timestamp with time zone);", connection))
        {
            _ = await setup.ExecuteNonQueryAsync();
        }

        try
        {
            var plan = new DatabaseSchemaPlan(fixture.CanonicalDatabase, "1.0", new string('a', 64),
                new string('b', 64),
                [new TableCopyPlan("dbo", "Sample", "field_probe", "Sample",
                    ["Value", "Computed", "LockoutEnd"], ["Value"])
                {
                    ColumnTypes = new Dictionary<string, string>
                    {
                        ["Value"] = "text", ["Computed"] = "text", ["LockoutEnd"] = "text",
                    },
                    NullableColumns = ["Value", "Computed", "LockoutEnd"],
                    DefaultExpressions = new Dictionary<string, string> { ["Value"] = "'expected-default'" },
                    GeneratedColumns = [new GeneratedColumnCopyPlan("Computed", "lower(\"Value\")")],
                }]);
            ProductionSchemaObservation observed = await ProductionSchemaCatalogInspector.InspectDatabaseAsync(
                plan, fixture.ConnectionString, CancellationToken.None);
            ProductionSchemaColumnDiagnostic value = Assert.Single(observed.ColumnDiagnostics,
                item => item.Schema == "field_probe" && item.Table == "Sample" && item.Column == "Value");
            Assert.Equal("text", value.ActualTypeCategory);
            Assert.Equal("explicit", value.ActualCollationMode);
            Assert.Equal("C", value.ActualCollationIdentity);
            Assert.Equal("present-different", value.DefaultState);
            ProductionSchemaColumnDiagnostic computed = Assert.Single(observed.ColumnDiagnostics,
                item => item.Schema == "field_probe" && item.Table == "Sample" && item.Column == "Computed");
            Assert.Equal("present-different", computed.GeneratedState);
            ProductionSchemaColumnDiagnostic lockout = Assert.Single(observed.ColumnDiagnostics,
                item => item.Schema == "field_probe" && item.Table == "Sample" && item.Column == "LockoutEnd");
            Assert.Equal("timestamp-with-time-zone", lockout.ActualTypeCategory);
            string json = System.Text.Json.JsonSerializer.Serialize(observed);
            Assert.DoesNotContain("private-default", json, StringComparison.Ordinal);
            Assert.DoesNotContain("private-generated", json, StringComparison.Ordinal);
            Assert.DoesNotContain("timestamp with time zone", json, StringComparison.Ordinal);
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand("DROP SCHEMA field_probe CASCADE;", connection);
            _ = await cleanup.ExecuteNonQueryAsync();
        }
    }

    [Fact]
    public async Task InspectDatabaseAsync_DisposablePostgreSql_ReportsFullShapeWithoutChangingRows()
    {
        var builder = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = fixture.CanonicalDatabase,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using (var setup = new NpgsqlCommand(
            "CREATE SCHEMA catalog_probe; " +
            "CREATE TABLE catalog_probe.\"Sample\" (\"ID\" integer PRIMARY KEY, \"Value\" text NOT NULL); " +
            "INSERT INTO catalog_probe.\"Sample\" VALUES (1, 'test-only');", connection))
        {
            _ = await setup.ExecuteNonQueryAsync();
        }

        try
        {
            var plan = new DatabaseSchemaPlan(fixture.CanonicalDatabase, "1.0", new string('a', 64),
                new string('b', 64),
                [new TableCopyPlan("dbo", "Sample", "catalog_probe", "Sample", ["ID", "Value"], ["ID"])
                {
                    ColumnTypes = new Dictionary<string, string> { ["ID"] = "integer", ["Value"] = "text" },
                }]);
            ProductionSchemaObservation first = await ProductionSchemaCatalogInspector.InspectDatabaseAsync(
                plan, fixture.ConnectionString, CancellationToken.None);
            Assert.Equal(fixture.CanonicalDatabase, first.Database);
            Assert.Contains(first.Tables, table => table.Schema == "catalog_probe" && table.Table == "Sample" &&
                table.Columns.SequenceEqual(["ID", "Value"], StringComparer.Ordinal));
            Assert.Matches("^[0-9a-f]{64}$", first.SchemaSha256);
            ProductionSchemaTableComponents before = Assert.Single(first.TableComponents,
                item => item.Schema == "catalog_probe" && item.Table == "Sample");
            Assert.Matches("^[0-9a-f]{64}$", before.WholeTableSha256);
            Assert.Contains(first.TableDiagnostics, item => item.Schema == "catalog_probe" &&
                item.Table == "Sample" && item.Status == "shape-drift");
            Assert.Contains(first.ColumnDiagnostics, item => item.Schema == "catalog_probe" &&
                item.Table == "Sample" && item.Column == "Value" && item.Status == "match");
            Assert.DoesNotContain("test-only", System.Text.Json.JsonSerializer.Serialize(first),
                StringComparison.Ordinal);
            var independent = new PostgreSqlDeltaReconciliationInspector(
                new PostgreSqlDeltaReconciliationInspectorOptions(fixture.ConnectionString));
            Assert.Equal(await independent.InspectSchemaAsync(plan, CancellationToken.None), first.SchemaSha256);

            await using (var change = new NpgsqlCommand(
                "CREATE INDEX \"IX_Sample_Value\" ON catalog_probe.\"Sample\" (\"Value\");", connection))
            {
                _ = await change.ExecuteNonQueryAsync();
            }
            ProductionSchemaObservation second = await ProductionSchemaCatalogInspector.InspectDatabaseAsync(
                plan, fixture.ConnectionString, CancellationToken.None);
            Assert.NotEqual(first.SchemaSha256, second.SchemaSha256);
            ProductionSchemaTableComponents after = Assert.Single(second.TableComponents,
                item => item.Schema == "catalog_probe" && item.Table == "Sample");
            Assert.Equal(before.ColumnsSha256, after.ColumnsSha256);
            Assert.Equal(before.ConstraintsSha256, after.ConstraintsSha256);
            Assert.NotEqual(before.IndexesSha256, after.IndexesSha256);
            Assert.Equal(before.ForeignKeysSha256, after.ForeignKeysSha256);
            Assert.NotEqual(before.WholeTableSha256, after.WholeTableSha256);
            Assert.Equal(first.ColumnDiagnostics, second.ColumnDiagnostics);
            await using var rows = new NpgsqlCommand("SELECT COUNT(*) FROM catalog_probe.\"Sample\";", connection);
            Assert.Equal(1L, await rows.ExecuteScalarAsync());
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand("DROP SCHEMA catalog_probe CASCADE;", connection);
            _ = await cleanup.ExecuteNonQueryAsync();
        }
    }
}
