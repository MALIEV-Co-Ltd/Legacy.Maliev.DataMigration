using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

/// <summary>
/// A synthetic one-table shape proof only. This does not authorize or implement production schema repair.
/// </summary>
[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class InvoiceAttributionDisposableProofTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task NullableAttributionAddition_DisposableTable_PreservesRowsAndIsIdempotent()
    {
        const string schema = "invoice_attribution_proof";
        var builder = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = fixture.CanonicalDatabase,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using (var setup = new NpgsqlCommand(
            "CREATE SCHEMA invoice_attribution_proof; " +
            "CREATE TABLE invoice_attribution_proof.\"Invoice\" (\"ID\" integer NOT NULL, " +
            "\"Number\" text NOT NULL, CONSTRAINT \"PK_Invoice\" PRIMARY KEY (\"ID\")); " +
            "INSERT INTO invoice_attribution_proof.\"Invoice\" (\"ID\", \"Number\") " +
            "VALUES (1, 'synthetic-one'), (2, 'synthetic-two');",
            connection))
        {
            _ = await setup.ExecuteNonQueryAsync();
        }

        try
        {
            TableCopyPlan before = InvoiceShape(schema);
            TableCopyPlan after = before with
            {
                OrderedColumns = ["ID", "Number", "SourceJourneyID", "SourceRequestID"],
                ColumnTypes = new Dictionary<string, string>(before.ColumnTypes, StringComparer.Ordinal)
                {
                    ["SourceJourneyID"] = "uuid",
                    ["SourceRequestID"] = "integer",
                },
                NullableColumns = ["SourceJourneyID", "SourceRequestID"],
                Indexes =
                [
                    new IndexCopyPlan("IX_Invoice_SourceJourneyID", ["SourceJourneyID"], false)
                    {
                        FilterPredicate = "\"SourceJourneyID\" IS NOT NULL",
                    },
                    new IndexCopyPlan("IX_Invoice_SourceRequestID", ["SourceRequestID"], false)
                    {
                        FilterPredicate = "\"SourceRequestID\" IS NOT NULL",
                    },
                ],
            };
            string expectedBefore = PostgreSqlSchemaFingerprint.ComputeExpectedComponents(before).WholeTableSha256;
            string expectedAfter = PostgreSqlSchemaFingerprint.ComputeExpectedComponents(after).WholeTableSha256;
            string preimage = await ObserveTableHashAsync(before, fixture.CanonicalDatabase,
                builder.ConnectionString);
            Assert.Equal(expectedBefore, preimage);
            Assert.NotEqual(expectedBefore, expectedAfter);
            Assert.Matches("^[0-9a-f]{64}$", preimage);

            await ApplyTestOnlyAdditionAsync(connection);
            string postimage = await ObserveTableHashAsync(after, fixture.CanonicalDatabase,
                builder.ConnectionString);
            Assert.Equal(expectedAfter, postimage);
            Assert.Matches("^[0-9a-f]{64}$", postimage);
            Assert.Equal((2L, 2L), await CountsAsync(connection));

            var journeyId = Guid.Parse("b1797761-c7ea-44e7-aedb-187fd0000001");
            await using (var insert = new NpgsqlCommand(
                "INSERT INTO invoice_attribution_proof.\"Invoice\" " +
                "(\"ID\", \"Number\", \"SourceJourneyID\", \"SourceRequestID\") " +
                "VALUES (3, 'synthetic-attributed', @journey, 91);",
                connection))
            {
                _ = insert.Parameters.AddWithValue("journey", journeyId);
                Assert.Equal(1, await insert.ExecuteNonQueryAsync());
            }
            await using (var read = new NpgsqlCommand(
                "SELECT \"SourceJourneyID\", \"SourceRequestID\" " +
                "FROM invoice_attribution_proof.\"Invoice\" WHERE \"ID\" = 3;", connection))
            await using (NpgsqlDataReader reader = await read.ExecuteReaderAsync())
            {
                Assert.True(await reader.ReadAsync());
                Assert.Equal(journeyId, reader.GetGuid(0));
                Assert.Equal(91, reader.GetInt32(1));
                Assert.False(await reader.ReadAsync());
            }

            await ApplyTestOnlyAdditionAsync(connection);
            Assert.Equal(postimage, await ObserveTableHashAsync(after, fixture.CanonicalDatabase,
                builder.ConnectionString));
            Assert.Equal((3L, 2L), await CountsAsync(connection));
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand(
                "DROP SCHEMA invoice_attribution_proof CASCADE;", connection);
            _ = await cleanup.ExecuteNonQueryAsync();
        }
    }

    private static TableCopyPlan InvoiceShape(string schema)
    {
        return new TableCopyPlan("dbo", "Invoice", schema, "Invoice", ["ID", "Number"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string>
            {
                ["ID"] = "integer",
                ["Number"] = "text",
            },
            PrimaryKey = new PrimaryKeyCopyPlan("PK_Invoice", ["ID"]),
        };
    }

    private static async Task<string> ObserveTableHashAsync(TableCopyPlan table, string databaseName,
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
        // Deliberately test-only SQL against a newly created Testcontainers table; no production executor calls this.
        await using var add = new NpgsqlCommand(
            "ALTER TABLE invoice_attribution_proof.\"Invoice\" " +
            "ADD COLUMN IF NOT EXISTS \"SourceJourneyID\" uuid NULL, " +
            "ADD COLUMN IF NOT EXISTS \"SourceRequestID\" integer NULL; " +
            "CREATE INDEX IF NOT EXISTS \"IX_Invoice_SourceJourneyID\" " +
            "ON invoice_attribution_proof.\"Invoice\" (\"SourceJourneyID\") " +
            "WHERE \"SourceJourneyID\" IS NOT NULL; " +
            "CREATE INDEX IF NOT EXISTS \"IX_Invoice_SourceRequestID\" " +
            "ON invoice_attribution_proof.\"Invoice\" (\"SourceRequestID\") " +
            "WHERE \"SourceRequestID\" IS NOT NULL;",
            connection);
        _ = await add.ExecuteNonQueryAsync();
    }

    private static async Task<(long Rows, long ExistingRowsWithoutAttribution)> CountsAsync(
        NpgsqlConnection connection)
    {
        await using var count = new NpgsqlCommand(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE " +
            "((\"ID\" = 1 AND \"Number\" = 'synthetic-one') OR " +
            "(\"ID\" = 2 AND \"Number\" = 'synthetic-two')) " +
            "AND \"SourceJourneyID\" IS NULL AND \"SourceRequestID\" IS NULL) " +
            "FROM invoice_attribution_proof.\"Invoice\";", connection);
        await using NpgsqlDataReader reader = await count.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return (reader.GetInt64(0), reader.GetInt64(1));
    }
}
