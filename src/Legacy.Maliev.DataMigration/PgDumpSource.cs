using System.Diagnostics;
using System.Text.RegularExpressions;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public sealed partial class PgDumpSource(string executablePath, string administrativeConnectionString) : IPostgreSqlDumpSource
{
    public static IPostgreSqlDumpSource CreateForHost(string executablePath, RemotePostgreSqlHostBoundary boundary)
    {
        return new HostBoundPgDumpSource(executablePath, boundary);
    }

    public Task<Stream> OpenDumpAsync(string database, string shadowDatabase, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ProcessStartInfo startInfo = BuildStartInfo(executablePath, administrativeConnectionString, shadowDatabase);
        Process process = Process.Start(startInfo) ??
            throw new MigrationExecutionException("snapshot_dump_start_failed", "The PostgreSQL dump process could not start.");
        return Task.FromResult<Stream>(new PgDumpProcessStream(process));
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
        ValidateConnectionOptions(connection);
        var start = new ProcessStartInfo(executablePath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (string name in start.Environment.Keys.Where(name => name.StartsWith("PG", StringComparison.OrdinalIgnoreCase)).ToArray())
        { _ = start.Environment.Remove(name); }
        start.Environment["PGPASSFILE"] = OperatingSystem.IsWindows() ? "NUL" : "/dev/null";
        start.Environment["PGGSSENCMODE"] = "disable";
        start.Environment["PGSSLCERTMODE"] = "disable";
        start.Environment["PGCONNECT_TIMEOUT"] = connection.Timeout.ToString(System.Globalization.CultureInfo.InvariantCulture);
        start.Environment["PGAPPNAME"] = connection.ApplicationName ?? string.Empty;
        foreach (string argument in new[]
        {
            "--dbname", shadowDatabase,
            "--format=custom",
            "--encoding=UTF8",
            "--no-owner",
            "--no-privileges",
            "--no-comments",
            "--no-password",
            "--quote-all-identifiers",
        })
        {
            start.ArgumentList.Add(argument);
        }
        start.Environment["PGHOST"] = connection.Host;
        start.Environment["PGPORT"] = connection.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        start.Environment["PGUSER"] = connection.Username;
        start.Environment["PGPASSWORD"] = connection.Password;
        start.Environment["PGSSLMODE"] = connection.SslMode switch
        {
            SslMode.VerifyFull => "verify-full",
            SslMode.VerifyCA => "verify-ca",
            SslMode.Disable => "disable",
            SslMode.Allow => "allow",
            SslMode.Prefer => "prefer",
            SslMode.Require => "require",
            _ => throw new MigrationExecutionException("host_postgres_options_unsupported", "The native SQL boundary requires a recognized SSL mode."),
        };
        if (!string.IsNullOrWhiteSpace(connection.RootCertificate))
        {
            start.Environment["PGSSLROOTCERT"] = connection.RootCertificate;
        }
        return start;
    }

    internal static void ValidateConnectionOptions(NpgsqlConnectionStringBuilder settings)
    {
        string[] supported = ["Host", "Port", "Database", "Username", "Password", "SSL Mode", "Root Certificate", "Pooling", "Timeout", "Application Name", "GSS Encryption Mode"];
        if (settings.Keys.Cast<string>().Where(settings.ShouldSerialize).Any(key => !supported.Contains(key, StringComparer.OrdinalIgnoreCase)) ||
            (settings.ShouldSerialize("GSS Encryption Mode") && settings.GssEncryptionMode != GssEncryptionMode.Disable))
        { throw new MigrationExecutionException("host_postgres_options_unsupported", "The native SQL boundary cannot safely preserve a configured connection option."); }
    }

    [GeneratedRegex("^legacy_shadow_[a-z0-9_]+_[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex ShadowDatabaseName();

    private sealed class PgDumpProcessStream(Process process) : Stream
    {
        private static readonly TimeSpan ShutdownTimeout = TimeSpan.FromSeconds(10);
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
                    Exception? primaryFailure = null;
                    try
                    {
                        await _output.DisposeAsync().ConfigureAwait(false);
                        await process.WaitForExitAsync(CancellationToken.None).WaitAsync(ShutdownTimeout).ConfigureAwait(false);
                        await _stderrDrain.WaitAsync(ShutdownTimeout).ConfigureAwait(false);
                        if (process.ExitCode != 0)
                        {
                            throw new MigrationExecutionException("snapshot_dump_failed", "The PostgreSQL dump process failed.");
                        }
                    }
                    catch (Exception exception) when (exception is not OutOfMemoryException and not AccessViolationException)
                    {
                        primaryFailure = exception;
                    }

                    Exception? cleanupFailure = null;
                    if (primaryFailure is not null)
                    {
                        try
                        {
                            await PgDumpProcessTermination.TerminateAndObserveAsync(process, ShutdownTimeout).ConfigureAwait(false);
                            await PgDumpProcessTermination.AwaitDrainAsync(_stderrDrain, ShutdownTimeout).ConfigureAwait(false);
                        }
                        catch (Exception exception) when (exception is not OutOfMemoryException and not AccessViolationException)
                        {
                            cleanupFailure = exception;
                        }
                    }

                    PgDumpProcessTermination.ThrowPrimaryOrAggregate(primaryFailure, cleanupFailure);
                }
                finally
                {
                    process.Dispose();
                    await base.DisposeAsync().ConfigureAwait(false);
                }

            }
            GC.SuppressFinalize(this);
        }
    }
}
