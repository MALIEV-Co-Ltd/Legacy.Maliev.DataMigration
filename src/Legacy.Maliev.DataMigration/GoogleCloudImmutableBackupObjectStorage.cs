using Google.Cloud.Storage.V1;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

internal sealed record GoogleCloudBackupUploadRequest(
    string Bucket,
    string ObjectName,
    string Sha256,
    long IfGenerationMatch);

internal sealed record GoogleCloudBackupObjectState(
    string Bucket,
    string ObjectName,
    long Generation,
    long ByteLength,
    string Sha256);

internal interface IGoogleCloudBackupGateway
{
    Task<GoogleCloudBackupObjectState> UploadNewAsync(
        GoogleCloudBackupUploadRequest request,
        Stream source,
        CancellationToken cancellationToken);

    Task<GoogleCloudBackupObjectState> ReadAsync(
        string bucket,
        string objectName,
        long generation,
        CancellationToken cancellationToken);
}

public sealed partial class GoogleCloudImmutableBackupObjectStorage : IImmutableBackupObjectStorage
{
    private readonly IGoogleCloudBackupGateway _gateway;

    internal GoogleCloudImmutableBackupObjectStorage(IGoogleCloudBackupGateway gateway)
    {
        ArgumentNullException.ThrowIfNull(gateway);
        _gateway = gateway;
    }

    public static async Task<GoogleCloudImmutableBackupObjectStorage> CreateWithApplicationDefaultCredentialsAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        StorageClient client = await StorageClient.CreateAsync().ConfigureAwait(false);
        return new(new GoogleCloudBackupGateway(client));
    }

    public async Task<ImmutableBackupObject> UploadNewAndReadBackAsync(
        string localPath,
        string objectUri,
        string sha256,
        CancellationToken cancellationToken)
    {
        string fullLocalPath = Path.GetFullPath(localPath);
        var file = new FileInfo(fullLocalPath);
        if (!file.Exists || file.Length <= 0 || !Sha256Value().IsMatch(sha256))
        {
            throw new Exact25FullBackupException("cloud_backup_request_invalid", "The immutable GCS upload request is incomplete.");
        }

        (string bucket, string objectName) = ParseObjectUri(objectUri);
        var request = new GoogleCloudBackupUploadRequest(bucket, objectName, sha256.ToLowerInvariant(), IfGenerationMatch: 0);
        await using FileStream source = new(fullLocalPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        GoogleCloudBackupObjectState uploaded = await _gateway
            .UploadNewAsync(request, source, cancellationToken).ConfigureAwait(false);
        ValidateState(uploaded, bucket, objectName, file.Length, sha256, requireGeneration: false);

        GoogleCloudBackupObjectState observed = await _gateway
            .ReadAsync(bucket, objectName, uploaded.Generation, cancellationToken).ConfigureAwait(false);
        ValidateState(observed, bucket, objectName, file.Length, sha256, requireGeneration: true);
        return observed.Generation != uploaded.Generation
            ? throw new Exact25FullBackupException("cloud_backup_parity_invalid", "The immutable GCS generation changed during readback.")
            : new(objectUri, observed.Generation, observed.ByteLength, observed.Sha256.ToLowerInvariant(), Immutable: true);
    }

    private static (string Bucket, string ObjectName) ParseObjectUri(string objectUri)
    {
        if (!Uri.TryCreate(objectUri, UriKind.Absolute, out Uri? uri) ||
            !string.Equals(uri.Scheme, "gs", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(uri.Host))
        {
            throw new Exact25FullBackupException("cloud_backup_request_invalid", "The immutable GCS object URI is invalid.");
        }

        string objectName = uri.AbsolutePath.TrimStart('/');
        return !SafeBucket().IsMatch(uri.Host) || !SafeObjectName().IsMatch(objectName) || objectName.Contains("..", StringComparison.Ordinal)
            ? throw new Exact25FullBackupException("cloud_backup_request_invalid", "The immutable GCS object URI is unsafe.")
            : ((string Bucket, string ObjectName))(uri.Host, objectName);
    }

    private static void ValidateState(
        GoogleCloudBackupObjectState state,
        string bucket,
        string objectName,
        long byteLength,
        string sha256,
        bool requireGeneration)
    {
        if (!string.Equals(state.Bucket, bucket, StringComparison.Ordinal) ||
            !string.Equals(state.ObjectName, objectName, StringComparison.Ordinal) ||
            state.Generation <= 0 || state.ByteLength != byteLength ||
            !Sha256Value().IsMatch(state.Sha256) ||
            !string.Equals(state.Sha256, sha256, StringComparison.OrdinalIgnoreCase) ||
            (requireGeneration && state.Generation <= 0))
        {
            throw new Exact25FullBackupException("cloud_backup_parity_invalid", "The immutable GCS object does not match the approved local backup.");
        }
    }

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{1,221}[A-Za-z0-9]$", RegexOptions.CultureInvariant)] private static partial Regex SafeBucket();
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$", RegexOptions.CultureInvariant)] private static partial Regex SafeObjectName();
    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)] private static partial Regex Sha256Value();
}

internal sealed class GoogleCloudBackupGateway(StorageClient client) : IGoogleCloudBackupGateway
{
    private const string Sha256MetadataKey = "maliev-sha256";
    private readonly StorageClient _client = client ?? throw new ArgumentNullException(nameof(client));

    public async Task<GoogleCloudBackupObjectState> UploadNewAsync(
        GoogleCloudBackupUploadRequest request,
        Stream source,
        CancellationToken cancellationToken)
    {
        var destination = new Google.Apis.Storage.v1.Data.Object
        {
            Bucket = request.Bucket,
            Name = request.ObjectName,
            Metadata = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [Sha256MetadataKey] = request.Sha256,
            },
        };
        var options = new UploadObjectOptions { IfGenerationMatch = request.IfGenerationMatch };
        Google.Apis.Storage.v1.Data.Object uploaded = await _client
            .UploadObjectAsync(destination, source, options, cancellationToken).ConfigureAwait(false);
        return ToState(uploaded);
    }

    public async Task<GoogleCloudBackupObjectState> ReadAsync(
        string bucket,
        string objectName,
        long generation,
        CancellationToken cancellationToken)
    {
        var options = new GetObjectOptions { Generation = generation };
        Google.Apis.Storage.v1.Data.Object observed = await _client
            .GetObjectAsync(bucket, objectName, options, cancellationToken).ConfigureAwait(false);
        return ToState(observed);
    }

    private static GoogleCloudBackupObjectState ToState(Google.Apis.Storage.v1.Data.Object value)
    {
        return value.Generation is null || value.Generation > long.MaxValue || value.Size is null || value.Size > long.MaxValue ||
            value.Metadata is null || !value.Metadata.TryGetValue(Sha256MetadataKey, out string? sha256)
            ? throw new Exact25FullBackupException("cloud_backup_parity_invalid", "GCS omitted required immutable object metadata.")
            : new(
            value.Bucket ?? string.Empty,
            value.Name ?? string.Empty,
            checked(value.Generation.Value),
            checked((long)value.Size.Value),
            sha256);
    }
}
