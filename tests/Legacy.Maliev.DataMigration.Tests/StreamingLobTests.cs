using System.Text;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class StreamingLobTests
{
    [Fact]
    public void ProductionStreamingPath_HasNoFilesystemOrPostgreSqlLargeObjectStaging()
    {
        string source = File.ReadAllText(SourcePath("StreamingLob.cs")) +
            File.ReadAllText(SourcePath("PostgreSqlShadowTarget.cs"));

        Assert.DoesNotContain("Path.GetTempPath", source, StringComparison.Ordinal);
        Assert.DoesNotContain("FileStream", source, StringComparison.Ordinal);
        Assert.DoesNotContain("lo_create", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("lowrite", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("lo_get", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("NpgsqlLargeObject", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsumeAsync_StreamsMoreThanFourMiBWithoutFilesystemSpooling()
    {
        byte[] payload = Encoding.UTF8.GetBytes(new string('ก', 3 * 1024 * 1024));
        var opened = false;
        var disposed = false;
        var lob = new StreamingLob(StreamingLobKind.Text, async (destination, cancellationToken) =>
        {
            opened = true;
            await using var source = new TrackingStream(payload, () => disposed = true);
            await source.CopyToAsync(destination, 64 * 1024, cancellationToken);
        });

        await lob.ConsumeAsync(Stream.Null, CancellationToken.None);

        Assert.True(opened);
        Assert.True(disposed);
        Assert.Equal(payload.LongLength, lob.CanonicalByteLength);
        Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(payload)).ToLowerInvariant(), lob.CanonicalSha256);
        Assert.DoesNotContain("Path.GetTempPath", File.ReadAllText(SourcePath("StreamingLob.cs")), StringComparison.Ordinal);
        Assert.DoesNotContain("FileStream", File.ReadAllText(SourcePath("StreamingLob.cs")), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsumeAsync_ProducerFailure_DisposesResourcesAndCannotBeReplayed()
    {
        var disposed = false;
        var lob = new StreamingLob(StreamingLobKind.Binary, async (destination, cancellationToken) =>
        {
            await using var source = new TrackingStream([1, 2, 3], () => disposed = true);
            await source.CopyToAsync(destination, cancellationToken);
            throw new InvalidOperationException("later column failed");
        });

        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => lob.ConsumeAsync(Stream.Null, CancellationToken.None));

        Assert.True(disposed);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => lob.ConsumeAsync(Stream.Null, CancellationToken.None));
    }

    private static string SourcePath(string file)
    {
        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../src/Legacy.Maliev.DataMigration", file));
    }

    private sealed class TrackingStream(byte[] payload, Action onDispose) : MemoryStream(payload)
    {
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing)
            {
                onDispose();
            }
        }
    }
}
