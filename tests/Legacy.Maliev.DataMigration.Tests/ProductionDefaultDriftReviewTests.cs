using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ProductionDefaultDriftReviewBoundaryTests
{
    [Fact]
    public void Plan_RequiresFreshExact23ProductionAuthorityAndCompleteCatalog()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DatabaseSchemaPlan[] databases = [.. DatabaseInventory.ActiveDatabases.Select(name =>
        {
            var database = new DatabaseSchemaPlan(name, "1.0", new string('a', 64), "", []);
            return database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
        })];
        var source = new FreshSchemaPlan("2.0", now.AddMinutes(-1), new string('b', 40), databases);
        ProductionSchemaObservation[] observed = [.. databases.Select(database =>
            new ProductionSchemaObservation(database.Database, [], new string('c', 64)))];
        var authority = new DeltaTargetAuthority(DeltaTargetAuthorityKind.ProductionCloudNativePg,
            "gke://maliev-website/us-central1-a/maliev-legacy/legacy-postgres-main/uid-1", new string('d', 64));

        ProductionDefaultDriftReview review = ProductionDefaultDriftReviewPlanner.Plan(source, authority, observed, now);
        Assert.Equal(23, review.Databases.Length);
        Assert.All(review.Databases, database => Assert.Empty(database.Tables));
        Assert.Matches("^[0-9a-f]{64}$", review.ReviewSha256);
        Assert.Equal("delta_schema_catalog_boundary_invalid", Assert.Throws<MigrationExecutionException>(() =>
            ProductionDefaultDriftReviewPlanner.Plan(source with { CapturedAtUtc = now.AddHours(-3) },
                authority, observed, now)).Code);
        Assert.Equal("production_default_drift_review_invalid", Assert.Throws<MigrationExecutionException>(() =>
            ProductionDefaultDriftReviewPlanner.Plan(source, authority with
            {
                Kind = DeltaTargetAuthorityKind.LocalAspire,
            }, observed, now)).Code);
        Assert.Equal("production_default_drift_review_invalid", Assert.Throws<MigrationExecutionException>(() =>
            ProductionDefaultDriftReviewPlanner.Plan(source, authority, observed[..^1], now)).Code);
        Assert.Equal("production_default_drift_review_invalid", Assert.Throws<MigrationExecutionException>(() =>
            ProductionDefaultDriftReviewPlanner.Plan(source, authority,
                [observed[1], observed[0], .. observed[2..]], now)).Code);
        Assert.NotEqual(review.ReviewSha256, ProductionDefaultDriftReviewPlanner.Plan(source,
            authority with { SystemIdentifierSha256 = new string('e', 64) }, observed, now).ReviewSha256);
        Assert.NotEqual(review.ReviewSha256, ProductionDefaultDriftReviewPlanner.Plan(source,
            authority, [observed[0] with { SchemaSha256 = new string('e', 64) }, .. observed[1..]], now)
            .ReviewSha256);
    }
}

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class ProductionDefaultDriftReviewTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task PlanDatabase_DisposableCatalog_BindsDefaultPreimageWithoutExpressionLeak()
    {
        var builder = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = fixture.CanonicalDatabase,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using (var setup = new NpgsqlCommand(
            "CREATE SCHEMA default_review_probe; " +
            "CREATE TABLE default_review_probe.\"Sample\" (\"Value\" text COLLATE \"C\" DEFAULT 'private-actual');",
            connection))
        {
            _ = await setup.ExecuteNonQueryAsync();
        }
        try
        {
            var table = new TableCopyPlan("dbo", "Sample", "default_review_probe", "Sample",
                ["Value"], ["Value"])
            {
                ColumnTypes = new Dictionary<string, string> { ["Value"] = "text" },
                NullableColumns = ["Value"],
                DefaultExpressions = new Dictionary<string, string> { ["Value"] = "'private-expected'" },
            };
            var database = new DatabaseSchemaPlan(fixture.CanonicalDatabase, "1.0", new string('a', 64), "",
                [table]);
            database = database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
            ProductionSchemaObservation first = await ProductionSchemaCatalogInspector.InspectDatabaseAsync(
                database, fixture.ConnectionString, CancellationToken.None);
            ProductionDefaultDriftDatabaseReview review = ProductionDefaultDriftReviewPlanner.PlanDatabase(
                database, first);
            ProductionDefaultDriftTableReview target = Assert.Single(review.Tables);
            Assert.Equal("default_review_probe", target.Schema);
            Assert.True(target.Columns.SequenceEqual(["Value"], StringComparer.Ordinal));
            ProductionExpressionDriftColumnReview facet = Assert.Single(target.Expressions);
            Assert.Equal("default", facet.Kind);
            Assert.True(facet.OtherColumnShapeDriftPresent);
            Assert.True(target.OtherShapeDriftPresent);
            Assert.Equal(first.SchemaSha256, review.ObservedSchemaSha256);
            Assert.Equal(Assert.Single(first.TableComponents, item => item.Schema == target.Schema &&
                item.Table == target.Table).WholeTableSha256, target.ObservedWholeTableSha256);
            Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpectedComponents(table).WholeTableSha256,
                target.ExpectedFinalWholeTableSha256);
            string json = JsonSerializer.Serialize(review);
            Assert.DoesNotContain("private-actual", json, StringComparison.Ordinal);
            Assert.DoesNotContain("private-expected", json, StringComparison.Ordinal);
            Assert.DoesNotContain("DEFAULT", json, StringComparison.Ordinal);

            await using (var change = new NpgsqlCommand(
                "ALTER TABLE default_review_probe.\"Sample\" ALTER COLUMN \"Value\" SET DEFAULT 'private-second';",
                connection))
            {
                _ = await change.ExecuteNonQueryAsync();
            }
            ProductionSchemaObservation second = await ProductionSchemaCatalogInspector.InspectDatabaseAsync(
                database, fixture.ConnectionString, CancellationToken.None);
            ProductionDefaultDriftTableReview changed = Assert.Single(
                ProductionDefaultDriftReviewPlanner.PlanDatabase(database, second).Tables);
            Assert.NotEqual(target.ObservedWholeTableSha256, changed.ObservedWholeTableSha256);
            Assert.Equal(target.ExpectedFinalWholeTableSha256, changed.ExpectedFinalWholeTableSha256);

            ProductionSchemaObservation tampered = first with { ColumnDiagnostics = [] };
            Assert.Equal("production_default_drift_review_invalid", Assert.Throws<MigrationExecutionException>(() =>
                ProductionDefaultDriftReviewPlanner.PlanDatabase(database, tampered)).Code);
            tampered = first with { TableDiagnostics = [] };
            Assert.Equal("production_default_drift_review_invalid", Assert.Throws<MigrationExecutionException>(() =>
                ProductionDefaultDriftReviewPlanner.PlanDatabase(database, tampered)).Code);
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand("DROP SCHEMA default_review_probe CASCADE;", connection);
            _ = await cleanup.ExecuteNonQueryAsync();
        }
    }

    [Fact]
    public async Task PlanDatabase_DisposableGeneratedFacet_IsNonExecutableAndBoundToPreimage()
    {
        var builder = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = fixture.CanonicalDatabase,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using (var setup = new NpgsqlCommand(
            "CREATE SCHEMA generated_review_probe; " +
            "CREATE TABLE generated_review_probe.\"Sample\" (\"Value\" text, " +
            "\"Computed\" text GENERATED ALWAYS AS (\"Value\" || 'private-actual') STORED);",
            connection))
        {
            _ = await setup.ExecuteNonQueryAsync();
        }
        try
        {
            var table = new TableCopyPlan("dbo", "Sample", "generated_review_probe", "Sample",
                ["Value", "Computed"], ["Value"])
            {
                ColumnTypes = new Dictionary<string, string>
                {
                    ["Value"] = "text",
                    ["Computed"] = "text",
                },
                NullableColumns = ["Value", "Computed"],
                GeneratedColumns = [new GeneratedColumnCopyPlan("Computed", "lower(\"Value\")")],
            };
            var database = new DatabaseSchemaPlan(fixture.CanonicalDatabase, "1.0", new string('a', 64), "",
                [table]);
            database = database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
            ProductionSchemaObservation first = await ProductionSchemaCatalogInspector.InspectDatabaseAsync(
                database, fixture.ConnectionString, CancellationToken.None);
            ProductionDefaultDriftDatabaseReview review = ProductionDefaultDriftReviewPlanner.PlanDatabase(
                database, first);
            ProductionDefaultDriftTableReview target = Assert.Single(review.Tables);
            Assert.Empty(target.Columns);
            ProductionExpressionDriftColumnReview facet = Assert.Single(target.Expressions);
            Assert.Equal("Computed", facet.Column);
            Assert.Equal("generated", facet.Kind);
            Assert.False(facet.OtherColumnShapeDriftPresent);
            Assert.False(target.OtherShapeDriftPresent);
            Assert.Equal(Assert.Single(first.TableComponents).WholeTableSha256, target.ObservedWholeTableSha256);
            Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpectedComponents(table).WholeTableSha256,
                target.ExpectedFinalWholeTableSha256);
            string json = JsonSerializer.Serialize(review);
            Assert.DoesNotContain("private-actual", json, StringComparison.Ordinal);
            Assert.DoesNotContain("lower", json, StringComparison.Ordinal);
            Assert.DoesNotContain("GENERATED ALWAYS", json, StringComparison.Ordinal);

            await using (var change = new NpgsqlCommand(
                "ALTER TABLE generated_review_probe.\"Sample\" DROP COLUMN \"Computed\"; " +
                "ALTER TABLE generated_review_probe.\"Sample\" ADD COLUMN \"Computed\" text " +
                "GENERATED ALWAYS AS (\"Value\" || 'private-second') STORED;",
                connection))
            {
                _ = await change.ExecuteNonQueryAsync();
            }
            ProductionSchemaObservation second = await ProductionSchemaCatalogInspector.InspectDatabaseAsync(
                database, fixture.ConnectionString, CancellationToken.None);
            ProductionDefaultDriftTableReview changed = Assert.Single(
                ProductionDefaultDriftReviewPlanner.PlanDatabase(database, second).Tables);
            Assert.NotEqual(target.ObservedWholeTableSha256, changed.ObservedWholeTableSha256);
            Assert.Equal(target.ExpectedFinalWholeTableSha256, changed.ExpectedFinalWholeTableSha256);
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand("DROP SCHEMA generated_review_probe CASCADE;", connection);
            _ = await cleanup.ExecuteNonQueryAsync();
        }
    }
}
