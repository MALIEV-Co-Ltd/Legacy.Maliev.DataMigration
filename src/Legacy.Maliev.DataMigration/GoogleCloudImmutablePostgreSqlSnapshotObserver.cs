using Google.Cloud.Storage.V1;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

internal sealed record ImmutablePostgreSqlSnapshotObjectState(
    long Generation, long ByteLength, IReadOnlyDictionary<string, string> Metadata);

internal interface IImmutablePostgreSqlSnapshotObjectGateway
{
    Task<ImmutablePostgreSqlSnapshotObjectState> ReadAsync(string bucket, string objectName, long generation, CancellationToken cancellationToken);
    Task DownloadAsync(string bucket, string objectName, long generation, Stream destination, CancellationToken cancellationToken);
}

public sealed partial class GoogleCloudImmutablePostgreSqlSnapshotObserver : IImmutablePostgreSqlSnapshotObserver
{
    private const string SnapshotIdMetadata = "maliev-snapshot-id";
    private const string Sha256Metadata = "maliev-sha256";
    private const string RecoveryPointMetadata = "maliev-recovery-point-utc";
    private readonly IImmutablePostgreSqlSnapshotObjectGateway gateway;

    internal GoogleCloudImmutablePostgreSqlSnapshotObserver(IImmutablePostgreSqlSnapshotObjectGateway gateway)
    {
        this.gateway = gateway ?? throw new ArgumentNullException(nameof(gateway));
    }

    public static async Task<GoogleCloudImmutablePostgreSqlSnapshotObserver> CreateWithApplicationDefaultCredentialsAsync()
    {
        return new(new GoogleCloudSnapshotObjectGateway(await StorageClient.CreateAsync().ConfigureAwait(false)));
    }

    public async Task<ImmutablePostgreSqlSnapshotObservation> ObserveAsync(
        string backupObjectUri,
        long backupObjectGeneration,
        CancellationToken cancellationToken)
    {
        (string bucket, string objectName) = Parse(backupObjectUri);
        if (backupObjectGeneration <= 0)
        {
            throw Invalid();
        }
        try
        {
            ImmutablePostgreSqlSnapshotObjectState value = await gateway.ReadAsync(
                bucket, objectName, backupObjectGeneration, cancellationToken).ConfigureAwait(false);
            if (!value.Metadata.TryGetValue(SnapshotIdMetadata, out string? snapshotId) ||
                !value.Metadata.TryGetValue(Sha256Metadata, out string? sha256) ||
                !value.Metadata.TryGetValue(RecoveryPointMetadata, out string? recoveryText) ||
                value.Generation != backupObjectGeneration || value.ByteLength <= 0 ||
                !Identifier().IsMatch(snapshotId) || !Sha256().IsMatch(sha256) ||
                !DateTimeOffset.TryParseExact(recoveryText, "O", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset recoveryPoint) ||
                recoveryPoint.Offset != TimeSpan.Zero)
            {
                throw Invalid();
            }

            await using var hashingSink = new HashingSink();
            await gateway.DownloadAsync(bucket, objectName, backupObjectGeneration, hashingSink, cancellationToken)
                .ConfigureAwait(false);
            string observedSha256 = hashingSink.GetHashAndSeal();
            return hashingSink.ByteLength != value.ByteLength ||
                !CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(observedSha256), Convert.FromHexString(sha256))
                ? throw Invalid()
                : new(snapshotId, backupObjectUri, backupObjectGeneration, value.ByteLength,
                observedSha256, recoveryPoint);
        }
        catch (MigrationExecutionException) { throw; }
        catch (Exception exception) when (exception is Google.GoogleApiException or InvalidOperationException or OverflowException or FormatException)
        {
            throw Invalid();
        }
    }

    private static (string Bucket, string ObjectName) Parse(string uriText)
    {
        return !Uri.TryCreate(uriText, UriKind.Absolute, out Uri? uri) || uri.Scheme != "gs" ||
            !Bucket().IsMatch(uri.Host) || !ObjectName().IsMatch(uri.AbsolutePath.TrimStart('/')) ||
            uri.AbsolutePath.Contains("..", StringComparison.Ordinal)
            ? throw Invalid()
            : ((string Bucket, string ObjectName))(uri.Host, uri.AbsolutePath.TrimStart('/'));
    }

    private static MigrationExecutionException Invalid()
    {
        return new("quotation_snapshot_object_observation_invalid", "The exact immutable PostgreSQL snapshot generation could not be observed securely.");
    }

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{1,221}[A-Za-z0-9]$", RegexOptions.CultureInvariant)] private static partial Regex Bucket();
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$", RegexOptions.CultureInvariant)] private static partial Regex ObjectName();
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", RegexOptions.CultureInvariant)] private static partial Regex Identifier();
    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)] private static partial Regex Sha256();

    private sealed class HashingSink : Stream
    {
        private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private bool sealedHash;

        public long ByteLength { get; private set; }
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => !sealedHash;
        public override long Length => ByteLength;
        public override long Position { get => ByteLength; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
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
            ArgumentNullException.ThrowIfNull(buffer);
            hash.AppendData(buffer, offset, count);
            ByteLength = checked(ByteLength + count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            hash.AppendData(buffer);
            ByteLength = checked(ByteLength + buffer.Length);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public string GetHashAndSeal()
        {
            if (sealedHash)
            {
                throw new InvalidOperationException();
            }
            sealedHash = true;
            return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                hash.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}

internal sealed class GoogleCloudSnapshotObjectGateway(StorageClient client) : IImmutablePostgreSqlSnapshotObjectGateway
{
    public async Task<ImmutablePostgreSqlSnapshotObjectState> ReadAsync(
        string bucket, string objectName, long generation, CancellationToken cancellationToken)
    {
        Google.Apis.Storage.v1.Data.Object value = await client.GetObjectAsync(
            bucket, objectName, new GetObjectOptions { Generation = generation }, cancellationToken).ConfigureAwait(false);
        return value.Generation is null || value.Generation > long.MaxValue || value.Size is null || value.Size > long.MaxValue || value.Metadata is null
            ? throw new MigrationExecutionException("quotation_snapshot_object_observation_invalid", "GCS omitted immutable snapshot metadata.")
            : new(checked(value.Generation.Value), checked((long)value.Size.Value),
                new Dictionary<string, string>(value.Metadata, StringComparer.Ordinal));
    }

    public Task DownloadAsync(
        string bucket, string objectName, long generation, Stream destination, CancellationToken cancellationToken)
    {
        return client.DownloadObjectAsync(
            bucket, objectName, destination, new DownloadObjectOptions { Generation = generation }, cancellationToken);
    }
}
