using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class DeltaOrderedRowSourcesTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task PostgreSql_source_streams_complete_rows_in_primary_key_order()
    {
        string database = fixture.CanonicalDatabase;
        string connectionString = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = database,
        }.ConnectionString;
        await using (var connection = new NpgsqlConnection(connectionString))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand("""
                DROP TABLE IF EXISTS public.delta_stream_rows;
                CREATE TABLE public.delta_stream_rows(id integer PRIMARY KEY, name text NULL, payload bytea NULL, amount numeric(18,4) NOT NULL);
                INSERT INTO public.delta_stream_rows VALUES
                    (3,'สาม',decode('000102ff', 'hex'),30.1250),
                    (1,'one',decode('aabb', 'hex'),10.5000),
                    (2,NULL,NULL,20.2500);
                """, connection);
            _ = await command.ExecuteNonQueryAsync();
        }
        TableCopyPlan table = new("dbo", "delta_stream_rows", "public", "delta_stream_rows",
            ["id", "name", "payload", "amount"], ["id"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["id"] = "integer",
                ["name"] = "text",
                ["payload"] = "bytea",
                ["amount"] = "numeric(18,4)",
            },
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["id"] = "int",
                ["name"] = "nvarchar(max)",
                ["payload"] = "varbinary(max)",
                ["amount"] = "decimal(18,4)",
            },
            PrimaryKey = new("pk_delta_stream_rows", ["id"]),
        };
        var source = new PostgreSqlDeltaRowSource(new(fixture.ConnectionString));

        List<MigrationRow> rows = await source.ReadOrderedAsync(database, table, CancellationToken.None).ToListAsync();

        Assert.Equal([1, 2, 3], rows.Select(row => row.Values["id"]));
        BufferedStreamingLob thaiText = Assert.IsType<BufferedStreamingLob>(rows[2].Values["name"]);
        await using (Stream thaiTextStream = thaiText.OpenRead())
        using (var reader = new StreamReader(thaiTextStream))
        {
            Assert.Equal("สาม", await reader.ReadToEndAsync());
        }
        BufferedStreamingLob binary = Assert.IsType<BufferedStreamingLob>(rows[2].Values["payload"]);
        await using (Stream binaryStream = binary.OpenRead())
        {
            using var buffer = new MemoryStream();
            await binaryStream.CopyToAsync(buffer);
            Assert.Equal(new byte[] { 0, 1, 2, 255 }, buffer.ToArray());
        }
        Assert.Null(rows[1].Values["name"]);
        Assert.Null(rows[1].Values["payload"]);
        Assert.Equal(10.5000m, rows[0].Values["amount"]);
    }

    [Fact]
    public void PostgreSql_source_rejects_incomplete_endpoint()
    {
        _ = Assert.Throws<ArgumentException>(() => new PostgreSqlDeltaRowSource(new("Username=test")));
    }
}
