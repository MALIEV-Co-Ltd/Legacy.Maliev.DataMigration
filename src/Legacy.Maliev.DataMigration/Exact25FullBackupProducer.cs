using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public sealed record Exact25FullBackupRequest(
    string Namespace,
    string ExpectedPodName,
    string ExpectedPodUid,
    string ContainerName,
    string GcsPrefix,
    string LocalWorkingDirectory,
    string RunId,
    DateTimeOffset ApprovedRunUtc,
    int MaximumTransportAttempts);

public sealed class SecureSqlBackupCredential
{
    private readonly string _userName;
    private readonly string _password;

    public SecureSqlBackupCredential(string userName, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        if (userName.ContainsAny('\r', '\n', '\0') || password.ContainsAny('\r', '\n', '\0'))
        {
            throw new ArgumentException("SQL backup credentials contain forbidden control characters.");
        }

        _userName = userName;
        _password = password;
    }

    internal string CreateChildProcessStandardInput()
    {
        return $"{_userName}\n{_password}\n";
    }

    public override string ToString()
    {
        return "[REDACTED]";
    }
}

public sealed record SqlServerDatabaseState(string Name, string State);

public sealed record Exact25BackupSourceObservation(
    string Namespace,
    string PodName,
    string PodUid,
    string ContainerName,
    bool Ready,
    DateTimeOffset ObservedAtUtc,
    IReadOnlyList<SqlServerDatabaseState> UserDatabases);

public sealed record RemoteFullBackupArtifact(
    string Database,
    string RemoteRelativePath,
    long ByteLength,
    string Sha256,
    DateTimeOffset CompletedAtUtc);

public sealed record ImmutableBackupObject(
    string Uri,
    long Generation,
    long ByteLength,
    string Sha256,
    bool Immutable);

public interface IExact25FullBackupProcess
{
    Task<Exact25BackupSourceObservation> InspectSourceAsync(
        Exact25FullBackupRequest request,
        SecureSqlBackupCredential credential,
        CancellationToken cancellationToken);

    Task PrepareRunAsync(
        Exact25BackupSourceObservation source,
        string runId,
        CancellationToken cancellationToken);

    Task<RemoteFullBackupArtifact> CreateUniqueFullBackupAsync(
        Exact25BackupSourceObservation source,
        string database,
        string remoteRelativePath,
        SecureSqlBackupCredential credential,
        CancellationToken cancellationToken);

    Task VerifyRestoreAsync(
        Exact25BackupSourceObservation source,
        RemoteFullBackupArtifact artifact,
        SecureSqlBackupCredential credential,
        CancellationToken cancellationToken);

    Task CopyToLocalAsync(
        Exact25BackupSourceObservation source,
        RemoteFullBackupArtifact artifact,
        string localRelativePath,
        string workingDirectory,
        CancellationToken cancellationToken);
}

public interface IImmutableBackupObjectStorage
{
    Task<ImmutableBackupObject> UploadNewAndReadBackAsync(
        string localPath,
        string objectUri,
        string sha256,
        CancellationToken cancellationToken);
}

public interface IBackupReceiptPublisher
{
    Task PublishNewAsync(BackupReceipt receipt, CancellationToken cancellationToken);
}

public sealed class Exact25BackupTransportException(string code, string message, bool retryable) : Exception(message)
{
    public string Code { get; } = code;

    public bool Retryable { get; } = retryable;
}

public sealed class Exact25FullBackupException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public static partial class Exact25FullBackupProducer
{
    public static async Task<BackupReceipt> ProduceAsync(
        Exact25FullBackupRequest request,
        SecureSqlBackupCredential credential,
        IExact25FullBackupProcess process,
        IImmutableBackupObjectStorage storage,
        IBackupReceiptPublisher publisher,
        string receiptKeyId,
        ECDsa receiptSigningKey,
        CancellationToken cancellationToken)
    {
        ValidateRequest(request);
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(publisher);
        ArgumentException.ThrowIfNullOrWhiteSpace(receiptKeyId);
        ArgumentNullException.ThrowIfNull(receiptSigningKey);

        Exact25BackupSourceObservation source = await process
            .InspectSourceAsync(request, credential, cancellationToken).ConfigureAwait(false);
        ValidateSource(request, source);

        string workingDirectory = Path.GetFullPath(request.LocalWorkingDirectory);
        if (Directory.Exists(workingDirectory) || File.Exists(workingDirectory))
        {
            throw new Exact25FullBackupException("local_backup_destination_exists", "The unique backup working directory already exists.");
        }

        OwnerProtectedDirectory.CreateNew(workingDirectory);
        await process.PrepareRunAsync(source, request.RunId, cancellationToken).ConfigureAwait(false);
        var states = new List<VerifiedBackupStateArtifact>(DatabaseInventory.ActiveDatabases.Count);
        DateTimeOffset latestCompletionUtc = source.ObservedAtUtc;
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string fileName = $"Full_{database}_{request.RunId}.bak";
            string remoteRelativePath = $"maliev-backups/{request.RunId}/{fileName}";
            RemoteFullBackupArtifact remote = await process.CreateUniqueFullBackupAsync(
                source, database, remoteRelativePath, credential, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(remote.Database, database, StringComparison.Ordinal) ||
                !string.Equals(remote.RemoteRelativePath, remoteRelativePath, StringComparison.Ordinal) || remote.ByteLength <= 0 ||
                !Sha256Value().IsMatch(remote.Sha256))
            {
                throw new Exact25FullBackupException("remote_backup_artifact_invalid", "SQL Server returned an invalid full-backup artifact.");
            }
            if (remote.CompletedAtUtc.Offset != TimeSpan.Zero || remote.CompletedAtUtc < latestCompletionUtc)
            {
                throw new Exact25FullBackupException("backup_capture_time_invalid", "SQL Server returned invalid or non-monotonic backup completion evidence.");
            }
            latestCompletionUtc = remote.CompletedAtUtc;

            await process.VerifyRestoreAsync(source, remote, credential, cancellationToken).ConfigureAwait(false);
            await CopyWithBoundedTransportRetryAsync(
                request.MaximumTransportAttempts,
                () => process.CopyToLocalAsync(source, remote, fileName, workingDirectory, cancellationToken),
                cancellationToken).ConfigureAwait(false);

            string localPath = Path.Combine(workingDirectory, fileName);
            var local = new FileInfo(localPath);
            if (!IsRegularNonLink(local) || local.Length != remote.ByteLength)
            {
                throw new Exact25FullBackupException("local_backup_size_invalid", "The copied recovery backup does not match SQL Server metadata.");
            }

            string sha256 = await ComputeSha256Async(localPath, cancellationToken).ConfigureAwait(false);
            if (!IsRegularNonLink(local))
            {
                throw new Exact25FullBackupException("local_backup_type_invalid", "The recovery backup is not a regular non-link file.");
            }
            if (!FixedHashEquals(sha256, remote.Sha256))
            {
                throw new Exact25FullBackupException("local_backup_hash_invalid", "The copied recovery backup does not match the verified SQL Server artifact.");
            }

            string objectUri = request.GcsPrefix + fileName;
            if (!IsRegularNonLink(local))
            {
                throw new Exact25FullBackupException("local_backup_type_invalid", "The recovery backup changed before immutable upload.");
            }
            ImmutableBackupObject cloud = await storage
                .UploadNewAndReadBackAsync(localPath, objectUri, sha256, cancellationToken).ConfigureAwait(false);
            if (!cloud.Immutable || cloud.Generation <= 0 || cloud.ByteLength != local.Length ||
                !string.Equals(cloud.Uri, objectUri, StringComparison.Ordinal) ||
                !FixedHashEquals(cloud.Sha256, sha256))
            {
                throw new Exact25FullBackupException("cloud_backup_parity_invalid", "The immutable cloud object does not match the retained recovery backup.");
            }

            states.Add(new(database, localPath, ObjectName(objectUri), cloud.Generation, cloud.ByteLength, sha256)
            {
                CompletedAtUtc = remote.CompletedAtUtc,
            });
        }

        BackupReceipt receipt = await BackupReceiptProducer.ProduceAsync(
            states,
            receiptKeyId,
            receiptSigningKey,
            source.ObservedAtUtc,
            cancellationToken).ConfigureAwait(false);
        await publisher.PublishNewAsync(receipt, cancellationToken).ConfigureAwait(false);
        return receipt;
    }

    private static void ValidateRequest(Exact25FullBackupRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        Match prefix = FullBackupPrefix().Match(request.GcsPrefix ?? string.Empty);
        string expectedDate = request.ApprovedRunUtc.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        if (!KubernetesName().IsMatch(request.Namespace) || !KubernetesName().IsMatch(request.ExpectedPodName) ||
            !SafeIdentifier().IsMatch(request.ExpectedPodUid) || !KubernetesName().IsMatch(request.ContainerName) ||
            !SafeIdentifier().IsMatch(request.RunId) || !prefix.Success ||
            !string.Equals(prefix.Groups["date"].Value, expectedDate, StringComparison.Ordinal) ||
            !string.Equals(prefix.Groups["run"].Value, request.RunId, StringComparison.Ordinal) ||
            request.ApprovedRunUtc == default || request.ApprovedRunUtc.Offset != TimeSpan.Zero ||
            request.MaximumTransportAttempts is < 1 or > 3)
        {
            throw new Exact25FullBackupException("backup_request_invalid", "The full-backup request is not safe or policy compliant.");
        }
    }

    private static void ValidateSource(Exact25FullBackupRequest request, Exact25BackupSourceObservation source)
    {
        if (!string.Equals(source.Namespace, request.Namespace, StringComparison.Ordinal) ||
            !string.Equals(source.PodName, request.ExpectedPodName, StringComparison.Ordinal) ||
            !string.Equals(source.PodUid, request.ExpectedPodUid, StringComparison.Ordinal) ||
            !string.Equals(source.ContainerName, request.ContainerName, StringComparison.Ordinal) ||
            !source.Ready || source.ObservedAtUtc.Offset != TimeSpan.Zero || source.ObservedAtUtc < request.ApprovedRunUtc)
        {
            throw new Exact25FullBackupException("source_identity_invalid", "The observed SQL Server source identity or authoritative observation time is invalid.");
        }

        string[] observed = [.. source.UserDatabases.Select(database => database.Name)];
        string[] expected = [.. DatabaseInventory.Entries.Keys.Order(StringComparer.Ordinal)];
        if (source.UserDatabases.Any(database => !string.Equals(database.State, "ONLINE", StringComparison.Ordinal)) ||
            observed.Distinct(StringComparer.Ordinal).Count() != observed.Length ||
            !observed.Order(StringComparer.Ordinal).SequenceEqual(expected, StringComparer.Ordinal))
        {
            throw new Exact25FullBackupException("source_database_inventory_invalid", "The source must expose the exact approved 27-database ONLINE disposition inventory.");
        }
    }

    private static async Task CopyWithBoundedTransportRetryAsync(
        int maximumAttempts,
        Func<Task> copy,
        CancellationToken cancellationToken)
    {
        for (int attempt = 1; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                await copy().ConfigureAwait(false);
                return;
            }
            catch (Exact25BackupTransportException exception) when (exception.Retryable && attempt < maximumAttempts)
            {
                continue;
            }
        }
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false)).ToLowerInvariant();
    }

    private static bool FixedHashEquals(string left, string right)
    {
        return Sha256Value().IsMatch(left) && Sha256Value().IsMatch(right) &&
            CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(left.ToLowerInvariant()),
                Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    private static bool IsRegularNonLink(FileInfo file)
    {
        file.Refresh();
        return file.Exists && file.LinkTarget is null && (file.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) == 0;
    }

    private static string ObjectName(string uri)
    {
        int slash = uri.IndexOf('/', "gs://".Length);
        return slash < 0 ? throw new Exact25FullBackupException("backup_request_invalid", "The GCS URI has no object name.") : uri[(slash + 1)..];
    }

    [GeneratedRegex("^[a-z0-9](?:[-a-z0-9.]{0,61}[a-z0-9])?$", RegexOptions.CultureInvariant)] private static partial Regex KubernetesName();
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", RegexOptions.CultureInvariant)] private static partial Regex SafeIdentifier();
    [GeneratedRegex("^gs://[A-Za-z0-9._-]+/database/full/(?<date>[0-9]{4}-[0-9]{2}-[0-9]{2})/(?<run>[A-Za-z0-9][A-Za-z0-9._-]{0,127})/$", RegexOptions.CultureInvariant)] private static partial Regex FullBackupPrefix();
    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)] private static partial Regex Sha256Value();
}
