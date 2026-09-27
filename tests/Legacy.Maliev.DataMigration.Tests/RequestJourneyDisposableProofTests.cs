using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

/// <summary>Reduced, synthetic Request-table proof only; the production whole-schema gate remains authoritative.</summary>
[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class RequestJourneyDisposableProofTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task NullableJourneyAddition_DisposableRequest_PreservesRowsAndExactShapeOnRerun()
    {
        const string schema = "request_journey_proof";
        var builder = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = fixture.CanonicalDatabase,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using (var setup = new NpgsqlCommand(
            "CREATE SCHEMA request_journey_proof; " +
            "CREATE TABLE request_journey_proof.\"Request\" (\"ID\" integer NOT NULL, " +
            "CONSTRAINT \"PK_Request\" PRIMARY KEY (\"ID\")); " +
            "INSERT INTO request_journey_proof.\"Request\" (\"ID\") VALUES (1), (2);",
            connection))
        {
            _ = await setup.ExecuteNonQueryAsync();
        }

        try
        {
            var before = new TableCopyPlan("dbo", "Request", schema, "Request", ["ID"], ["ID"])
            {
                ColumnTypes = new Dictionary<string, string> { ["ID"] = "integer" },
                PrimaryKey = new PrimaryKeyCopyPlan("PK_Request", ["ID"]),
            };
            TableCopyPlan after = before with
            {
                OrderedColumns = ["ID", "JourneyId"],
                ColumnTypes = new Dictionary<string, string>(before.ColumnTypes, StringComparer.Ordinal)
                {
                    ["JourneyId"] = "uuid",
                },
                NullableColumns = ["JourneyId"],
                Indexes =
                [
                    new IndexCopyPlan("IX_Request_JourneyId", ["JourneyId"], false)
                    {
                        FilterPredicate = "\"JourneyId\" IS NOT NULL",
                    },
                ],
            };
            string expectedBefore = PostgreSqlSchemaFingerprint.ComputeExpectedComponents(before).WholeTableSha256;
            string expectedAfter = PostgreSqlSchemaFingerprint.ComputeExpectedComponents(after).WholeTableSha256;
            string preimage = await TableHashAsync(before, fixture.CanonicalDatabase, builder.ConnectionString);
            Assert.Equal(expectedBefore, preimage);
            Assert.NotEqual(expectedBefore, expectedAfter);
            Assert.Matches("^[0-9a-f]{64}$", preimage);

            await ApplyTestOnlyAdditionAsync(connection);
            string postimage = await TableHashAsync(after, fixture.CanonicalDatabase, builder.ConnectionString);
            Assert.Equal(expectedAfter, postimage);
            Assert.Matches("^[0-9a-f]{64}$", postimage);
            Assert.Equal((2L, 2L), await CountsAsync(connection));

            var journey = Guid.Parse("be9dbf90-7552-436b-a82f-0ca27a000001");
            await using (var insert = new NpgsqlCommand(
                "INSERT INTO request_journey_proof.\"Request\" (\"ID\", \"JourneyId\") " +
                "VALUES (3, @journey);", connection))
            {
                _ = insert.Parameters.AddWithValue("journey", journey);
                Assert.Equal(1, await insert.ExecuteNonQueryAsync());
            }
            await using (var read = new NpgsqlCommand(
                "SELECT \"JourneyId\" FROM request_journey_proof.\"Request\" WHERE \"ID\" = 3;",
                connection))
            {
                Assert.Equal(journey, (Guid)(await read.ExecuteScalarAsync())!);
            }

            await ApplyTestOnlyAdditionAsync(connection);
            Assert.Equal(postimage, await TableHashAsync(after, fixture.CanonicalDatabase,
                builder.ConnectionString));
            Assert.Equal((3L, 2L), await CountsAsync(connection));
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand("DROP SCHEMA request_journey_proof CASCADE;", connection);
            _ = await cleanup.ExecuteNonQueryAsync();
        }
    }

    private static async Task<string> TableHashAsync(TableCopyPlan table, string databaseName,
        string connectionString)
    {
        var database = new DatabaseSchemaPlan(databaseName, "1.0", new string('a', 64), "", [table]);
        database = database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
        ProductionSchemaObservation observation = await ProductionSchemaCatalogInspector.InspectDatabaseAsync(
            database, connectionString, CancellationToken.None);
        return Assert.Single(observation.TableComponents, item =>
            item.Schema == table.TargetSchema && item.Table == table.TargetTable).WholeTableSha256;
    }

    private static async Task ApplyTestOnlyAdditionAsync(NpgsqlConnection connection)
    {
        // Testcontainers-only DDL. No production plan, authorization, or apply path calls this method.
        await using var add = new NpgsqlCommand(
            "ALTER TABLE request_journey_proof.\"Request\" " +
            "ADD COLUMN IF NOT EXISTS \"JourneyId\" uuid NULL; " +
            "CREATE INDEX IF NOT EXISTS \"IX_Request_JourneyId\" " +
            "ON request_journey_proof.\"Request\" (\"JourneyId\") " +
            "WHERE \"JourneyId\" IS NOT NULL;",
            connection);
        _ = await add.ExecuteNonQueryAsync();
    }

    private static async Task<(long Rows, long PreviousRowsNull)> CountsAsync(NpgsqlConnection connection)
    {
        await using var count = new NpgsqlCommand(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE \"ID\" IN (1, 2) AND \"JourneyId\" IS NULL) " +
            "FROM request_journey_proof.\"Request\";", connection);
        await using NpgsqlDataReader reader = await count.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return (reader.GetInt64(0), reader.GetInt64(1));
    }
}
