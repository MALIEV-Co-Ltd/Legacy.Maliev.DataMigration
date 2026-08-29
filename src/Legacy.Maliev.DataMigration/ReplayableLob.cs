using System.Text;

namespace Legacy.Maliev.DataMigration;

public enum ReplayableLobKind
{
    Text,
    Binary,
}

/// <summary>Disk-backed value used to keep large source fields outside managed memory.</summary>
public sealed class ReplayableLob : IAsyncDisposable
{
    private readonly string _path;

    private ReplayableLob(string path, ReplayableLobKind kind, long byteLength)
    {
        _path = path;
        Kind = kind;
        ByteLength = byteLength;
    }

    public ReplayableLobKind Kind { get; }

    public long ByteLength { get; }

    public Stream OpenRead()
    {
        return new FileStream(
        _path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
        FileOptions.Asynchronous | FileOptions.SequentialScan);
    }

    public static async Task<ReplayableLob> FromTextReaderAsync(TextReader reader, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reader);
        string path = Path.Combine(Path.GetTempPath(), $"maliev-lob-{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (var writer = new StreamWriter(output, new UTF8Encoding(false, true), 64 * 1024, leaveOpen: false))
            {
                char[] buffer = new char[32 * 1024];
                int read;
                while ((read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) != 0)
                {
                    await writer.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                }
            }

            return new ReplayableLob(path, ReplayableLobKind.Text, new FileInfo(path).Length);
        }
        catch
        {
            File.Delete(path);
            throw;
        }
    }

    public static async Task<ReplayableLob> FromStreamAsync(Stream input, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        string path = Path.Combine(Path.GetTempPath(), $"maliev-lob-{Guid.NewGuid():N}.tmp");
        try
        {
            await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            await input.CopyToAsync(output, 64 * 1024, cancellationToken).ConfigureAwait(false);
            return new ReplayableLob(path, ReplayableLobKind.Binary, output.Length);
        }
        catch
        {
            File.Delete(path);
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await Task.Yield();
        File.Delete(_path);
    }
}
