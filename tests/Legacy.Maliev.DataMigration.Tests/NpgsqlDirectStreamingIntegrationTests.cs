using System.Text;
using Npgsql;
using NpgsqlTypes;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class NpgsqlDirectStreamingIntegrationTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task BinaryCopy_AcceptsDirectTextAndBinaryStreamsWithoutLargeObjectStaging()
    {
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using (var create = new NpgsqlCommand("CREATE TEMP TABLE direct_streaming(id integer, text_value text, binary_value bytea);", connection))
        {
            _ = await create.ExecuteNonQueryAsync();
        }

        string thai = new('ก', 3 * 1024 * 1024);
        byte[] binary = Enumerable.Range(0, 5 * 1024 * 1024).Select(index => (byte)(index % 251)).ToArray();
        await using (NpgsqlBinaryImporter importer = await connection.BeginBinaryImportAsync(
            "COPY direct_streaming (id, text_value, binary_value) FROM STDIN (FORMAT BINARY)"))
        {
            await importer.StartRowAsync();
            await importer.WriteAsync(1, NpgsqlDbType.Integer);
            await using var text = new MemoryStream(new UTF8Encoding(false, true).GetBytes(thai), writable: false);
            await importer.WriteAsync<Stream>(text, NpgsqlDbType.Text);
            await using var stream = new MemoryStream(binary, writable: false);
            await importer.WriteAsync<Stream>(stream, NpgsqlDbType.Bytea);
            _ = await importer.CompleteAsync();
        }

        await using var verify = new NpgsqlCommand(
            "SELECT octet_length(text_value), octet_length(binary_value), (SELECT count(*) FROM pg_largeobject_metadata) FROM direct_streaming;",
            connection);
        await using NpgsqlDataReader reader = await verify.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(9 * 1024 * 1024, reader.GetInt32(0));
        Assert.Equal(5 * 1024 * 1024, reader.GetInt32(1));
        Assert.Equal(0, reader.GetInt64(2));
    }
}
