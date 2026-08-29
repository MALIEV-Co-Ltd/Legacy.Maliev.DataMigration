using System.IO.Pipelines;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration;

public enum StreamingLobKind
{
    Text,
    Binary,
}

/// <summary>A single-use large value exposed through a bounded in-memory producer/consumer pipe.</summary>
public sealed class StreamingLob
{
    private const int PipePauseBytes = 128 * 1024;
    private const int PipeResumeBytes = 64 * 1024;
    private readonly Func<Stream, CancellationToken, Task> _producer;
    private int _state;

    public StreamingLob(StreamingLobKind kind, Func<Stream, CancellationToken, Task> producer)
        : this(kind, null, producer)
    {
    }

    public StreamingLob(StreamingLobKind kind, long expectedByteLength, Func<Stream, CancellationToken, Task> producer)
        : this(kind, (long?)expectedByteLength, producer)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(expectedByteLength);
    }

    private StreamingLob(StreamingLobKind kind, long? expectedByteLength, Func<Stream, CancellationToken, Task> producer)
    {
        ArgumentNullException.ThrowIfNull(producer);
        Kind = kind;
        ExpectedByteLength = expectedByteLength;
        _producer = producer;
    }

    public StreamingLobKind Kind { get; }
    public long? ExpectedByteLength { get; }
    public long CanonicalByteLength { get; private set; }
    public string CanonicalSha256 { get; private set; } = string.Empty;
    public bool IsConsumed => Volatile.Read(ref _state) == 2;

    public Task<Stream> OpenReadAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
        {
            throw new InvalidOperationException("A streamed large value can be consumed exactly once.");
        }

        var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var pipe = new Pipe(new PipeOptions(
            pauseWriterThreshold: PipePauseBytes,
            resumeWriterThreshold: PipeResumeBytes,
            useSynchronizationContext: false));
        Task producer = ProduceAsync(pipe.Writer, linkedCancellation.Token);
        Stream reader = pipe.Reader.AsStream(leaveOpen: false);
        return Task.FromResult<Stream>(new HashingReadStream(reader, producer, linkedCancellation, ExpectedByteLength, Complete));
    }

    public async Task ConsumeAsync(Stream destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        await using Stream source = await OpenReadAsync(cancellationToken).ConfigureAwait(false);
        await source.CopyToAsync(destination, 64 * 1024, cancellationToken).ConfigureAwait(false);
    }

    private async Task ProduceAsync(PipeWriter writer, CancellationToken cancellationToken)
    {
        Exception? failure = null;
        try
        {
            await using Stream destination = writer.AsStream(leaveOpen: true);
            await _producer(destination, cancellationToken).ConfigureAwait(false);
            await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failure = exception;
        }
        finally
        {
            await writer.CompleteAsync(failure).ConfigureAwait(false);
        }
    }

    private void Complete(long byteLength, string sha256, bool success)
    {
        if (success)
        {
            CanonicalByteLength = byteLength;
            CanonicalSha256 = sha256;
            Volatile.Write(ref _state, 2);
        }
        else
        {
            Volatile.Write(ref _state, 3);
        }
    }

    private sealed class HashingReadStream(
        Stream inner,
        Task producer,
        CancellationTokenSource cancellation,
        long? expectedByteLength,
        Action<long, string, bool> complete) : Stream
    {
        private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private long _byteLength;
        private bool _completed;
        private bool _disposed;

        public override bool CanRead => !_disposed;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => expectedByteLength ?? throw new NotSupportedException("The exact streamed field length is required by this consumer.");
        public override long Position { get => _byteLength; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            int read = inner.Read(buffer, offset, count);
            Process(buffer.AsSpan(offset, read));
            return read;
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            int read = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            Process(buffer.Span[..read]);
            if (read == 0)
            {
                await producer.ConfigureAwait(false);
            }
            return read;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return await ReadAsync(buffer.AsMemory(offset, count), cancellationToken).ConfigureAwait(false);
        }

        public override async ValueTask DisposeAsync()
        {
            if (!_disposed)
            {
                _disposed = true;
                if (!_completed)
                {
                    await cancellation.CancelAsync().ConfigureAwait(false);
                    try
                    {
                        await producer.ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        // The consumer stopped before EOF; cancellation is the intended cleanup path.
                    }
                    Finish(success: false);
                }
                await inner.DisposeAsync().ConfigureAwait(false);
                cancellation.Dispose();
                _hash.Dispose();
            }
            await base.DisposeAsync().ConfigureAwait(false);
            GC.SuppressFinalize(this);
        }

        private void Finish(bool success)
        {
            if (_completed)
            {
                return;
            }
            _completed = true;
            if (success && expectedByteLength is not null && expectedByteLength != _byteLength)
            {
                complete(_byteLength, string.Empty, false);
                throw new MigrationExecutionException(
                    "streaming_lob_length_mismatch",
                    "The streamed field length differs from the source length observed inside the snapshot.");
            }
            string sha256 = success
                ? Convert.ToHexString(_hash.GetHashAndReset()).ToLowerInvariant()
                : string.Empty;
            complete(_byteLength, sha256, success);
        }

        private void Process(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length == 0)
            {
                producer.GetAwaiter().GetResult();
                Finish(success: true);
                return;
            }
            _hash.AppendData(buffer);
            _byteLength = checked(_byteLength + buffer.Length);
        }
    }
}
