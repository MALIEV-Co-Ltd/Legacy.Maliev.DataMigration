using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public sealed partial class PgDumpSource(string executablePath, string administrativeConnectionString) : IPostgreSqlDumpSource
{
    public Task<Stream> OpenDumpAsync(string database, string shadowDatabase, CancellationToken cancellationToken)
    {
        ProcessStartInfo startInfo = BuildStartInfo(executablePath, administrativeConnectionString, shadowDatabase);
        Process process = Process.Start(startInfo) ??
            throw new MigrationExecutionException("snapshot_dump_start_failed", "The PostgreSQL dump process could not start.");
        CancellationTokenRegistration cancellation = cancellationToken.Register(() =>
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
            }
            catch (InvalidOperationException)
            {
                // The process exited concurrently.
            }
        });
        return Task.FromResult<Stream>(new PgDumpProcessStream(process, cancellation));
    }

    internal static ProcessStartInfo BuildStartInfo(string executablePath, string connectionString, string shadowDatabase)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        if (!ShadowDatabaseName().IsMatch(shadowDatabase))
        {
            throw new MigrationExecutionException("snapshot_shadow_name_invalid", "Only a run-owned shadow database may be exported.");
        }
        var connection = new NpgsqlConnectionStringBuilder(connectionString);
        var start = new ProcessStartInfo(executablePath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        string restrictKey = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(shadowDatabase))).ToLowerInvariant()[..32];
        foreach (string argument in new[]
        {
            "--dbname", shadowDatabase,
            "--format=plain",
            "--encoding=UTF8",
            "--no-owner",
            "--no-privileges",
            "--no-comments",
            "--quote-all-identifiers",
            "--restrict-key", restrictKey,
        })
        {
            start.ArgumentList.Add(argument);
        }
        start.Environment["PGHOST"] = connection.Host;
        start.Environment["PGPORT"] = connection.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        start.Environment["PGUSER"] = connection.Username;
        start.Environment["PGPASSWORD"] = connection.Password;
        start.Environment["PGSSLMODE"] = connection.SslMode.ToString().ToLowerInvariant();
        return start;
    }

    [GeneratedRegex("^legacy_shadow_[a-z0-9_]+_[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex ShadowDatabaseName();

    private sealed class PgDumpProcessStream(Process process, CancellationTokenRegistration cancellation) : Stream
    {
        private readonly Stream _output = process.StandardOutput.BaseStream;
        private readonly Task _stderrDrain = process.StandardError.BaseStream.CopyToAsync(Null);
        private bool _disposed;

        public override bool CanRead => !_disposed;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush()
        {
            throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return _output.Read(buffer, offset, count);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return _output.ReadAsync(buffer, offset, count, cancellationToken);
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return _output.ReadAsync(buffer, cancellationToken);
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

        public override async ValueTask DisposeAsync()
        {
            if (!_disposed)
            {
                _disposed = true;
                try
                {
                    await _output.DisposeAsync().ConfigureAwait(false);
                    await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
                    await _stderrDrain.ConfigureAwait(false);
                    if (process.ExitCode != 0)
                    {
                        throw new MigrationExecutionException("snapshot_dump_failed", "The PostgreSQL dump process failed.");
                    }
                }
                finally
                {
                    cancellation.Dispose();
                    process.Dispose();
                    await base.DisposeAsync().ConfigureAwait(false);
                }
            }
            GC.SuppressFinalize(this);
        }
    }
}
