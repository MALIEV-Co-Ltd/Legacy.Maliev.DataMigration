using System.Runtime.ExceptionServices;

namespace Legacy.Maliev.DataMigration;

// Only this factory product is valid for the operator-host coordinator. Successful
// EOF is the acceptance gate: process exit and fresh endpoint identity precede it.
internal sealed class HostBoundPgDumpSource : IPostgreSqlDumpSource
{
    private readonly string _executable;
    private readonly RemotePostgreSqlHostBoundary _boundary;

    internal HostBoundPgDumpSource(string executable, RemotePostgreSqlHostBoundary boundary)
    {
        ArgumentNullException.ThrowIfNull(boundary);
        if (!Path.IsPathFullyQualified(executable) || !File.Exists(executable))
        { throw new MigrationExecutionException("host_dump_executable_missing", "An explicit existing native PostgreSQL dump executable is required."); }
        SecureSnapshotFileCreation.RejectLinkedAncestors(Path.GetDirectoryName(executable)!);
        if (!SecureLocalFile.IsRegularNonLink(new FileInfo(executable))) { throw HostRuntimeTrust.Invalid(); }
        _executable = executable;
        _boundary = boundary;
    }

    public async Task<Stream> OpenDumpAsync(string database, string shadowDatabase, CancellationToken cancellationToken)
    {
        await _boundary.VerifyEndpointAsync(shadowDatabase, cancellationToken).ConfigureAwait(false);
        var dump = new PgDumpSource(_executable, _boundary.ConnectionStringFor(shadowDatabase));
        Stream inner = await dump.OpenDumpAsync(database, shadowDatabase, cancellationToken).ConfigureAwait(false);
        return new AcceptanceStream(inner, token => _boundary.VerifyEndpointAsync(shadowDatabase, token), cancellationToken);
    }

    private sealed class AcceptanceStream(Stream inner, Func<CancellationToken, Task> verify, CancellationToken executionToken) : Stream
    {
        private bool _accepted;
        private bool _innerDisposed;
        private bool _disposed;
        private Exception? _primary;

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_primary is not null) { ExceptionDispatchInfo.Capture(_primary).Throw(); }
            if (buffer.Length == 0) { return 0; }
            if (_accepted) { return 0; }
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(executionToken, cancellationToken);
            try
            {
                int read = await inner.ReadAsync(buffer, linked.Token).ConfigureAwait(false);
                if (read != 0) { return read; }
                _innerDisposed = true;
                await inner.DisposeAsync().ConfigureAwait(false);
                linked.Token.ThrowIfCancellationRequested();
                await verify(linked.Token).ConfigureAwait(false);
                _accepted = true;
                return 0;
            }
            catch (Exception exception) { _primary = exception; throw; }
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        }

        public override async ValueTask DisposeAsync()
        {
            if (_disposed) { return; }
            _disposed = true;
            if (!_accepted && _primary is null)
            { _primary = new MigrationExecutionException("host_dump_incomplete", "Native export was not fully consumed and independently accepted."); }
            try
            {
                if (!_innerDisposed)
                {
                    _innerDisposed = true;
                    try { await inner.DisposeAsync().ConfigureAwait(false); }
                    catch (Exception secondary)
                    {
                        _primary!.Data["host_dump_cleanup_failure"] = secondary.GetType().Name;
                    }
                }
                if (_primary is not null) { ExceptionDispatchInfo.Capture(_primary).Throw(); }
            }
            finally { await base.DisposeAsync().ConfigureAwait(false); GC.SuppressFinalize(this); }
        }
        protected override void Dispose(bool disposing)
        {
            try { if (disposing && !_disposed) { DisposeAsync().AsTask().GetAwaiter().GetResult(); } }
            finally { base.Dispose(disposing); }
        }
        public override bool CanRead => !_disposed;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush()
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
            throw new NotSupportedException();
        }
    }
}
