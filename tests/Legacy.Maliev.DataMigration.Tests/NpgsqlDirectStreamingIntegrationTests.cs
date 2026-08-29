using System.Text;
using System.Reflection;
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

    [Fact]
    public async Task BinaryCopy_ProductionLengthKnownStream_DoesNotAllocateAWholeValueBuffer()
    {
        string version = typeof(NpgsqlConnection).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
        Assert.StartsWith("10.0.3", version, StringComparison.Ordinal);

        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using (var create = new NpgsqlCommand("CREATE TEMP TABLE production_streaming(id integer, binary_value bytea);", connection))
        {
            _ = await create.ExecuteNonQueryAsync();
        }

        const int payloadBytes = 32 * 1024 * 1024;
        var producerCompleted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var lob = new StreamingLob(StreamingLobKind.Binary, payloadBytes, async (destination, cancellationToken) =>
        {
            byte[] chunk = new byte[64 * 1024];
            for (var written = 0; written < payloadBytes; written += chunk.Length)
            {
                await destination.WriteAsync(chunk, cancellationToken);
            }
            producerCompleted.SetResult();
        });
        await using Stream productionStream = await lob.OpenReadAsync(CancellationToken.None);
        Assert.True(productionStream.CanSeek);
        Assert.Equal(payloadBytes, productionStream.Length);
        Assert.Equal(0, productionStream.Position);
        _ = Assert.Throws<NotSupportedException>(() => productionStream.Seek(0, SeekOrigin.Begin));
        long allocatedBefore = GC.GetTotalAllocatedBytes(precise: true);

        await using (NpgsqlBinaryImporter importer = await connection.BeginBinaryImportAsync(
            "COPY production_streaming (id, binary_value) FROM STDIN (FORMAT BINARY)"))
        {
            await importer.StartRowAsync();
            await importer.WriteAsync(1, NpgsqlDbType.Integer);
            await importer.WriteAsync(productionStream, NpgsqlDbType.Bytea);
            _ = await importer.CompleteAsync();
        }
        long allocatedBytes = GC.GetTotalAllocatedBytes(precise: true) - allocatedBefore;

        Assert.True(producerCompleted.Task.IsCompletedSuccessfully);
        Assert.True(lob.IsConsumed);
        Assert.True(allocatedBytes < 24L * 1024 * 1024, $"COPY allocated {allocatedBytes:N0} bytes for a {payloadBytes:N0}-byte stream.");
    }
}
