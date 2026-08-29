using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration;

public enum StreamingLobKind
{
    Text,
    Binary,
}

/// <summary>A single-use large value streamed without filesystem persistence or whole-value materialization.</summary>
public sealed class StreamingLob
{
    private readonly Func<Stream, CancellationToken, Task> _producer;
    private int _state;

    public StreamingLob(StreamingLobKind kind, Func<Stream, CancellationToken, Task> producer)
    {
        ArgumentNullException.ThrowIfNull(producer);
        Kind = kind;
        _producer = producer;
    }

    public StreamingLobKind Kind { get; }

    public long CanonicalByteLength { get; private set; }

    public string CanonicalSha256 { get; private set; } = string.Empty;

    public bool IsConsumed => Volatile.Read(ref _state) == 2;

    public async Task ConsumeAsync(Stream destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
        {
            throw new InvalidOperationException("A streamed large value can be consumed exactly once.");
        }

        using var hashing = new HashingWriteStream(destination);
        try
        {
            await _producer(hashing, cancellationToken).ConfigureAwait(false);
            await hashing.FlushAsync(cancellationToken).ConfigureAwait(false);
            CanonicalByteLength = hashing.ByteLength;
            CanonicalSha256 = hashing.Finish();
            Volatile.Write(ref _state, 2);
        }
        catch
        {
            Volatile.Write(ref _state, 3);
            throw;
        }
    }

    private sealed class HashingWriteStream(Stream inner) : Stream
    {
        private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private bool _finished;

        public long ByteLength { get; private set; }
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush()
        {
            inner.Flush();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            return inner.FlushAsync(cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
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
            Write(buffer.AsSpan(offset, count));
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            inner.Write(buffer);
            _hash.AppendData(buffer);
            ByteLength = checked(ByteLength + buffer.Length);
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            _hash.AppendData(buffer.Span);
            ByteLength = checked(ByteLength + buffer.Length);
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            await WriteAsync(buffer.AsMemory(offset, count), cancellationToken).ConfigureAwait(false);
        }

        public string Finish()
        {
            if (_finished)
            {
                throw new InvalidOperationException("The streamed value hash was already finalized.");
            }
            _finished = true;
            return Convert.ToHexString(_hash.GetHashAndReset()).ToLowerInvariant();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _hash.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
