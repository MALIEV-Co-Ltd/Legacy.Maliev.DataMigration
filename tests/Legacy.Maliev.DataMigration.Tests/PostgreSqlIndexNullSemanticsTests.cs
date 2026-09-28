using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class PostgreSqlIndexNullSemanticsTests
{
    [Theory]
    [InlineData("(\"NormalizedName\" IS NOT NULL)", false)]
    [InlineData("\"NormalizedName\" IS NOT NULL", false)]
    [InlineData("(\"Other\" IS NOT NULL)", true)]
    [InlineData(null, true)]
    public void NullableUniqueKey_OnlyExactNotNullFilterMakesNullsSettingRedundant(
        string? predicate, bool expected)
    {
        var table = new TableCopyPlan("dbo", "AspNetRoles", "public", "AspNetRoles",
            ["Id", "NormalizedName"], ["Id"])
        {
            NullableColumns = ["NormalizedName"],
        };
        var index = new IndexCopyPlan("RoleNameIndex", ["NormalizedName"], true)
        {
            FilterPredicate = predicate,
        };

        Assert.Equal(expected, PostgreSqlIndexNullSemantics.RequiresNullsNotDistinct(index, table));
    }

    [Fact]
    public void CompositeNullableUniqueKey_RetainsNullsNotDistinct()
    {
        var table = new TableCopyPlan("dbo", "Sample", "public", "Sample",
            ["Id", "Name", "Code"], ["Id"])
        {
            NullableColumns = ["Name", "Code"],
        };
        var index = new IndexCopyPlan("UX_Sample", ["Name", "Code"], true)
        {
            FilterPredicate = "(\"Name\" IS NOT NULL)",
        };

        Assert.True(PostgreSqlIndexNullSemantics.RequiresNullsNotDistinct(index, table));
    }
}

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlFilteredUniqueIndexCatalogTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task ExactNonNullFilter_MatchesExistingPostgreSqlIndexWithoutNullsNotDistinct()
    {
        string schema = "identity_index_probe_" + Guid.NewGuid().ToString("N");
        var builder = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = fixture.CanonicalDatabase,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using (var setup = new NpgsqlCommand($"""
            CREATE SCHEMA "{schema}";
            CREATE TABLE "{schema}"."AspNetRoles" ("Id" text NOT NULL, "NormalizedName" text);
            CREATE UNIQUE INDEX "RoleNameIndex" ON "{schema}"."AspNetRoles" ("NormalizedName")
                WHERE ("NormalizedName" IS NOT NULL);
            """, connection))
        {
            _ = await setup.ExecuteNonQueryAsync();
        }

        try
        {
            await using (var values = new NpgsqlCommand($"""
                INSERT INTO "{schema}"."AspNetRoles" ("Id", "NormalizedName")
                VALUES ('one', NULL), ('two', NULL), ('three', 'STAFF');
                """, connection))
            {
                Assert.Equal(3, await values.ExecuteNonQueryAsync());
            }
            await using (var duplicate = new NpgsqlCommand($"""
                INSERT INTO "{schema}"."AspNetRoles" ("Id", "NormalizedName")
                VALUES ('four', 'STAFF');
                """, connection))
            {
                PostgresException conflict = await Assert.ThrowsAsync<PostgresException>(
                    duplicate.ExecuteNonQueryAsync);
                Assert.Equal(PostgresErrorCodes.UniqueViolation, conflict.SqlState);
            }

            var table = new TableCopyPlan("dbo", "AspNetRoles", schema, "AspNetRoles",
                ["Id", "NormalizedName"], ["Id"])
            {
                ColumnTypes = new Dictionary<string, string>
                {
                    ["Id"] = "text",
                    ["NormalizedName"] = "text",
                },
                NullableColumns = ["NormalizedName"],
                Indexes = [new IndexCopyPlan("RoleNameIndex", ["NormalizedName"], true)
                {
                    FilterPredicate = "(\"NormalizedName\" IS NOT NULL)",
                }],
            };
            var plan = new DatabaseSchemaPlan(fixture.CanonicalDatabase, "1.0", new string('a', 64), "", [table]);
            plan = plan with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(plan) };
            ProductionSchemaObservation observed = await ProductionSchemaCatalogInspector.InspectDatabaseAsync(
                plan, fixture.ConnectionString, CancellationToken.None);
            ProductionSchemaTableComponents actual = Assert.Single(observed.TableComponents);

            Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpectedComponents(table).IndexesSha256,
                actual.IndexesSha256);
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand($"DROP SCHEMA \"{schema}\" CASCADE;", connection);
            _ = await cleanup.ExecuteNonQueryAsync();
        }
    }
}
