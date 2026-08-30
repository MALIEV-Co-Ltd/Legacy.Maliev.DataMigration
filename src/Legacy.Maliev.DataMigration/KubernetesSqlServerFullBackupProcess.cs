using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public sealed partial class KubernetesSqlServerFullBackupProcess : IExact25FullBackupProcess
{
    private const string InventorySql =
        "SET NOCOUNT ON; SELECT 'OBSERVED_AT_UTC', CONVERT(varchar(33), SYSUTCDATETIME(), 127) + '+00:00'; " +
        "SELECT name, state_desc FROM sys.databases WHERE database_id > 4 ORDER BY name;";

    private const string ValidateAndCreateRunScript =
        "root=$1; run=$2; test -d \"$root\"; test ! -L \"$root\"; root_real=$(realpath -e -- \"$root\"); test \"$root_real\" = \"$root\"; " +
        "parent=\"$root/maliev-backups\"; if test -e \"$parent\" || test -L \"$parent\"; then test -d \"$parent\"; test ! -L \"$parent\"; else umask 077; mkdir -- \"$parent\"; fi; " +
        "test \"$(stat -c %u -- \"$parent\")\" = \"$(id -u)\"; test \"$(stat -c %a -- \"$parent\")\" = 700; " +
        "parent_real=$(realpath -e -- \"$parent\"); test \"$parent_real\" = \"$root_real/maliev-backups\"; target=\"$parent/$run\"; " +
        "test ! -e \"$target\"; test ! -L \"$target\"; mkdir --mode=700 -- \"$target\"; test -d \"$target\"; test ! -L \"$target\"; " +
        "test \"$(stat -c %u -- \"$target\")\" = \"$(id -u)\"; test \"$(stat -c %a -- \"$target\")\" = 700; " +
        "target_real=$(realpath -e -- \"$target\"); test \"$target_real\" = \"$parent_real/$run\"";

    private const string ValidateRunScript =
        "root=$1; run=$2; test -d \"$root\"; test ! -L \"$root\"; root_real=$(realpath -e -- \"$root\"); test \"$root_real\" = \"$root\"; " +
        "parent=\"$root/maliev-backups\"; target=\"$parent/$run\"; test -d \"$parent\"; test ! -L \"$parent\"; " +
        "test -d \"$target\"; test ! -L \"$target\"; test \"$(stat -c %u -- \"$parent\")\" = \"$(id -u)\"; " +
        "test \"$(stat -c %a -- \"$parent\")\" = 700; test \"$(stat -c %u -- \"$target\")\" = \"$(id -u)\"; " +
        "test \"$(stat -c %a -- \"$target\")\" = 700; parent_real=$(realpath -e -- \"$parent\"); " +
        "target_real=$(realpath -e -- \"$target\"); test \"$parent_real\" = \"$root_real/maliev-backups\"; test \"$target_real\" = \"$parent_real/$run\"";

    private readonly IBackupProcessRunner _runner;
    private readonly string _backupRoot;

    public KubernetesSqlServerFullBackupProcess(
        IBackupProcessRunner runner,
        string backupRoot = "/var/opt/mssql/data")
    {
        ArgumentNullException.ThrowIfNull(runner);
        if (!AbsoluteContainerPath().IsMatch(backupRoot) || backupRoot.Contains("..", StringComparison.Ordinal))
        {
            throw new ArgumentException("The SQL Server backup root is unsafe.", nameof(backupRoot));
        }

        _runner = runner;
        _backupRoot = backupRoot.TrimEnd('/');
    }

    public async Task<Exact25BackupSourceObservation> InspectSourceAsync(
        Exact25FullBackupRequest request,
        SecureSqlBackupCredential credential,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(credential);
        ValidateKubernetesIdentifier(request.Namespace);
        ValidateKubernetesIdentifier(request.ExpectedPodName);
        ValidateKubernetesIdentifier(request.ContainerName);

        BackupProcessResult podResult = await RunRequiredAsync(
            Kubectl("get", "pod", request.ExpectedPodName, "-n", request.Namespace, "-o", "json"),
            "pod_inspection_failed",
            cancellationToken).ConfigureAwait(false);
        (string podNamespace, string podName, string podUid, bool ready, bool containerPresent) =
            ParsePod(podResult.StandardOutput, request.ContainerName);
        if (!ready || !containerPresent || !string.Equals(podNamespace, request.Namespace, StringComparison.Ordinal) ||
            !string.Equals(podName, request.ExpectedPodName, StringComparison.Ordinal) ||
            !string.Equals(podUid, request.ExpectedPodUid, StringComparison.Ordinal))
        {
            throw new Exact25FullBackupException("source_identity_invalid", "The approved SQL Server container is absent from the observed pod.");
        }

        BackupProcessResult inventoryResult = await RunRequiredAsync(
            SecureKubectlSqlCmdInvocation.Create(
                request.Namespace, request.ExpectedPodName, request.ContainerName, InventorySql, credential),
            "source_inventory_query_failed",
            cancellationToken).ConfigureAwait(false);

        (DateTimeOffset observedAtUtc, IReadOnlyList<SqlServerDatabaseState> databases) =
            ParseInventory(inventoryResult.StandardOutput);
        var source = new Exact25BackupSourceObservation(
            podNamespace,
            podName,
            podUid,
            request.ContainerName,
            ready,
            observedAtUtc,
            databases);
        await FenceSourceAsync(source, cancellationToken).ConfigureAwait(false);
        return source;
    }

    public async Task PrepareRunAsync(
        Exact25BackupSourceObservation source,
        string runId,
        CancellationToken cancellationToken)
    {
        ValidateSourceIdentifiers(source);
        ValidateSafeIdentifier(runId);
        await FenceSourceAsync(source, cancellationToken).ConfigureAwait(false);
        _ = await RunRequiredAsync(
            KubectlExec(source, "sh", "-ceu", ValidateAndCreateRunScript, "sh", _backupRoot, runId),
            "remote_backup_destination_exists_or_unavailable",
            cancellationToken).ConfigureAwait(false);
        await FenceSourceAsync(source, cancellationToken).ConfigureAwait(false);
    }

    public async Task<RemoteFullBackupArtifact> CreateUniqueFullBackupAsync(
        Exact25BackupSourceObservation source,
        string database,
        string remoteRelativePath,
        SecureSqlBackupCredential credential,
        CancellationToken cancellationToken)
    {
        ValidateSourceIdentifiers(source);
        ArgumentNullException.ThrowIfNull(credential);
        if (!DatabaseInventory.ActiveDatabases.Contains(database, StringComparer.Ordinal) ||
            !SafeRemoteBackupPath().IsMatch(remoteRelativePath))
        {
            throw new Exact25FullBackupException("remote_backup_path_invalid", "The requested SQL Server backup path is outside the approved run directory.");
        }

        string runId = remoteRelativePath.Split('/')[1];
        await FenceSourceAsync(source, cancellationToken).ConfigureAwait(false);
        await ValidateRunAsync(source, runId, cancellationToken).ConfigureAwait(false);

        string remotePath = $"{_backupRoot}/{remoteRelativePath}";
        string quotedDatabase = database.Replace("]", "]]", StringComparison.Ordinal);
        string sql = $"BACKUP DATABASE [{quotedDatabase}] TO DISK = N'{remotePath}' WITH COPY_ONLY, CHECKSUM, COMPRESSION, NOFORMAT, NOINIT, STATS = 10; " +
            "SELECT 'BACKUP_COMPLETED_AT_UTC', CONVERT(varchar(33), SYSUTCDATETIME(), 127) + '+00:00';";
        BackupProcessResult backup = await RunRequiredAsync(
            SecureKubectlSqlCmdInvocation.Create(source.Namespace, source.PodName, source.ContainerName, sql, credential),
            "backup_create_failed",
            cancellationToken).ConfigureAwait(false);
        DateTimeOffset completedAtUtc = ParseTimestampMarker(backup.StandardOutput, "BACKUP_COMPLETED_AT_UTC", "backup_completion_output_invalid");

        await FenceSourceAsync(source, cancellationToken).ConfigureAwait(false);
        await ValidateRunAsync(source, runId, cancellationToken).ConfigureAwait(false);
        const string metadataScript =
            "test -f \"$1\"; test ! -L \"$1\"; test \"$(stat -c %F -- \"$1\")\" = 'regular file'; " +
            "test \"$(realpath -e -- \"$1\")\" = \"$1\"; size=$(stat -c %s -- \"$1\"); " +
            "hash=$(sha256sum -- \"$1\"); hash=${hash%% *}; printf '%s|%s\\n' \"$size\" \"$hash\"";
        BackupProcessResult metadata = await RunRequiredAsync(
            KubectlExec(source, "sh", "-ceu", metadataScript, "sh", remotePath),
            "backup_metadata_failed",
            cancellationToken).ConfigureAwait(false);
        await FenceSourceAsync(source, cancellationToken).ConfigureAwait(false);
        string[] fields = metadata.StandardOutput.Trim().Split('|');
        return fields.Length != 2 || !long.TryParse(fields[0], System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out long byteLength) || byteLength <= 0 ||
            !Sha256Value().IsMatch(fields[1])
            ? throw new Exact25FullBackupException("backup_metadata_invalid", "SQL Server backup metadata is invalid.")
            : new(database, remoteRelativePath, byteLength, fields[1].ToLowerInvariant(), completedAtUtc);
    }

    public async Task VerifyRestoreAsync(
        Exact25BackupSourceObservation source,
        RemoteFullBackupArtifact artifact,
        SecureSqlBackupCredential credential,
        CancellationToken cancellationToken)
    {
        ValidateSourceIdentifiers(source);
        ValidateArtifact(artifact);
        ArgumentNullException.ThrowIfNull(credential);
        await FenceSourceAsync(source, cancellationToken).ConfigureAwait(false);
        string remotePath = $"{_backupRoot}/{artifact.RemoteRelativePath}";
        string sql = $"RESTORE VERIFYONLY FROM DISK = N'{remotePath}' WITH CHECKSUM;";
        _ = await RunRequiredAsync(
            SecureKubectlSqlCmdInvocation.Create(source.Namespace, source.PodName, source.ContainerName, sql, credential),
            "restore_verify_failed",
            cancellationToken).ConfigureAwait(false);
        await FenceSourceAsync(source, cancellationToken).ConfigureAwait(false);
    }

    public async Task CopyToLocalAsync(
        Exact25BackupSourceObservation source,
        RemoteFullBackupArtifact artifact,
        string localRelativePath,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        ValidateSourceIdentifiers(source);
        ValidateArtifact(artifact);
        await FenceSourceAsync(source, cancellationToken).ConfigureAwait(false);
        if (!SafeLocalFileName().IsMatch(localRelativePath) ||
            !string.Equals(localRelativePath, Path.GetFileName(localRelativePath), StringComparison.Ordinal))
        {
            throw new Exact25FullBackupException("local_backup_path_invalid", "The local backup destination must be one safe relative file name.");
        }

        string fullWorkingDirectory = Path.GetFullPath(workingDirectory);
        string target = Path.Combine(fullWorkingDirectory, localRelativePath);
        if (File.Exists(target) || Directory.Exists(target))
        {
            throw new Exact25FullBackupException("local_backup_destination_exists", "The local backup artifact destination already exists.");
        }

        string temporary = Path.Combine(fullWorkingDirectory, $".{localRelativePath}.{Guid.NewGuid():N}.tmp");
        try
        {
            string remotePath = $"{_backupRoot}/{artifact.RemoteRelativePath}";
            SecureBackupProcessInvocation invocation = Kubectl(
                "cp", $"{source.Namespace}/{source.PodName}:{remotePath}", temporary, "-c", source.ContainerName);
            BackupProcessResult result = await _runner.RunAsync(invocation, cancellationToken).ConfigureAwait(false);
            if (result.ExitCode != 0)
            {
                throw new Exact25BackupTransportException(
                    "copy_transport_failed",
                    "The kubectl backup copy failed.",
                    IsExplicitlyRetryableCopyFailure(result.StandardError));
            }

            await FenceSourceAsync(source, cancellationToken).ConfigureAwait(false);

            var copied = new FileInfo(temporary);
            if (!IsRegularNonLink(copied) || copied.Length != artifact.ByteLength ||
                !FixedHashEquals(await ComputeSha256Async(temporary, cancellationToken).ConfigureAwait(false), artifact.Sha256))
            {
                throw new Exact25FullBackupException("local_backup_hash_invalid", "The kubectl backup copy does not match the verified remote artifact.");
            }

            copied.Refresh();
            if (!IsRegularNonLink(copied))
            {
                throw new Exact25FullBackupException("local_backup_type_invalid", "The copied backup is not a regular non-link file.");
            }
            File.Move(temporary, target);
        }
        catch
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }

            throw;
        }
    }

    private async Task<BackupProcessResult> RunRequiredAsync(
        SecureBackupProcessInvocation invocation,
        string code,
        CancellationToken cancellationToken)
    {
        BackupProcessResult result = await _runner.RunAsync(invocation, cancellationToken).ConfigureAwait(false);
        return result.ExitCode != 0
            ? throw new Exact25FullBackupException(code, $"The required backup command failed: {invocation}.")
            : result;
    }

    private static SecureBackupProcessInvocation Kubectl(params string[] arguments)
    {
        return new("kubectl", arguments, string.Empty);
    }

    private static SecureBackupProcessInvocation KubectlExec(Exact25BackupSourceObservation source, params string[] command)
    {
        string[] arguments = [
            "exec", source.PodName, "-n", source.Namespace, "-c", source.ContainerName, "--", .. command,
        ];
        return Kubectl(arguments);
    }

    private static (string Namespace, string Name, string Uid, bool Ready, bool ContainerPresent) ParsePod(
        string json,
        string expectedContainer)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            JsonElement metadata = root.GetProperty("metadata");
            string podNamespace = metadata.GetProperty("namespace").GetString() ?? string.Empty;
            string name = metadata.GetProperty("name").GetString() ?? string.Empty;
            string uid = metadata.GetProperty("uid").GetString() ?? string.Empty;
            bool ready = root.GetProperty("status").GetProperty("conditions").EnumerateArray().Any(condition =>
                string.Equals(condition.GetProperty("type").GetString(), "Ready", StringComparison.Ordinal) &&
                string.Equals(condition.GetProperty("status").GetString(), "True", StringComparison.Ordinal));
            bool containerPresent = root.GetProperty("spec").GetProperty("containers").EnumerateArray().Any(container =>
                string.Equals(container.GetProperty("name").GetString(), expectedContainer, StringComparison.Ordinal));
            return (podNamespace, name, uid, ready, containerPresent);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or KeyNotFoundException)
        {
            throw new Exact25FullBackupException("pod_observation_invalid", "The Kubernetes pod observation is incomplete or malformed.");
        }
    }

    private static (DateTimeOffset ObservedAtUtc, IReadOnlyList<SqlServerDatabaseState> Databases) ParseInventory(string output)
    {
        DateTimeOffset? observedAtUtc = null;
        var databases = new List<SqlServerDatabaseState>();
        foreach (string line in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string[] fields = line.Split('|', StringSplitOptions.TrimEntries);
            if (fields.Length == 2 && string.Equals(fields[0], "OBSERVED_AT_UTC", StringComparison.Ordinal))
            {
                if (observedAtUtc is not null || !TryParseUtc(fields[1], out DateTimeOffset parsed))
                {
                    throw new Exact25FullBackupException("source_inventory_output_invalid", "The SQL Server observation time is malformed.");
                }
                observedAtUtc = parsed;
                continue;
            }
            if (fields.Length != 2 || !DatabaseName().IsMatch(fields[0]) || !DatabaseState().IsMatch(fields[1]))
            {
                throw new Exact25FullBackupException("source_inventory_output_invalid", "The SQL Server inventory output is malformed.");
            }

            databases.Add(new(fields[0], fields[1]));
        }

        return observedAtUtc is null
            ? throw new Exact25FullBackupException("source_inventory_output_invalid", "The SQL Server observation time is missing.")
            : (observedAtUtc.Value, databases);
    }

    private async Task FenceSourceAsync(Exact25BackupSourceObservation source, CancellationToken cancellationToken)
    {
        BackupProcessResult result = await RunRequiredAsync(
            Kubectl("get", "pod", source.PodName, "-n", source.Namespace, "-o", "json"),
            "source_identity_changed",
            cancellationToken).ConfigureAwait(false);
        (string ns, string name, string uid, bool ready, bool containerPresent) = ParsePod(result.StandardOutput, source.ContainerName);
        if (!ready || !containerPresent || !string.Equals(ns, source.Namespace, StringComparison.Ordinal) ||
            !string.Equals(name, source.PodName, StringComparison.Ordinal) || !string.Equals(uid, source.PodUid, StringComparison.Ordinal))
        {
            throw new Exact25FullBackupException("source_identity_changed", "The SQL Server pod identity changed during backup production.");
        }
    }

    private async Task ValidateRunAsync(Exact25BackupSourceObservation source, string runId, CancellationToken cancellationToken)
    {
        _ = await RunRequiredAsync(
            KubectlExec(source, "sh", "-ceu", ValidateRunScript, "sh", _backupRoot, runId),
            "remote_backup_directory_invalid",
            cancellationToken).ConfigureAwait(false);
    }

    private static DateTimeOffset ParseTimestampMarker(string output, string marker, string code)
    {
        string prefix = marker + "|";
        string[] matches = output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => line.StartsWith(prefix, StringComparison.Ordinal)).ToArray();
        return matches.Length == 1 && TryParseUtc(matches[0][prefix.Length..], out DateTimeOffset parsed)
            ? parsed
            : throw new Exact25FullBackupException(code, "SQL Server did not return one authoritative UTC timestamp.");
    }

    private static bool TryParseUtc(string value, out DateTimeOffset parsed)
    {
        return DateTimeOffset.TryParseExact(value, "O", System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.None, out parsed) && parsed.Offset == TimeSpan.Zero;
    }

    private static bool IsRegularNonLink(FileInfo file)
    {
        file.Refresh();
        return file.Exists && file.LinkTarget is null && (file.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) == 0;
    }

    private static void ValidateSourceIdentifiers(Exact25BackupSourceObservation source)
    {
        ArgumentNullException.ThrowIfNull(source);
        ValidateKubernetesIdentifier(source.Namespace);
        ValidateKubernetesIdentifier(source.PodName);
        ValidateKubernetesIdentifier(source.ContainerName);
        ValidateSafeIdentifier(source.PodUid);
    }

    private static void ValidateArtifact(RemoteFullBackupArtifact artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        if (!DatabaseInventory.ActiveDatabases.Contains(artifact.Database, StringComparer.Ordinal) ||
            !SafeRemoteBackupPath().IsMatch(artifact.RemoteRelativePath) || artifact.ByteLength <= 0 ||
            !Sha256Value().IsMatch(artifact.Sha256) || artifact.CompletedAtUtc == default || artifact.CompletedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new Exact25FullBackupException("remote_backup_artifact_invalid", "The remote backup artifact is unsafe or incomplete.");
        }
    }

    private static void ValidateKubernetesIdentifier(string value)
    {
        if (!KubernetesIdentifier().IsMatch(value))
        {
            throw new Exact25FullBackupException("source_identity_invalid", "A Kubernetes source identifier is unsafe.");
        }
    }

    private static void ValidateSafeIdentifier(string value)
    {
        if (!SafeIdentifier().IsMatch(value))
        {
            throw new Exact25FullBackupException("source_identity_invalid", "A source identifier is unsafe.");
        }
    }

    private static bool IsExplicitlyRetryableCopyFailure(string stderr)
    {
        string normalized = stderr.ToLowerInvariant();
        return normalized.Contains("unexpected eof", StringComparison.Ordinal) ||
            normalized.Contains("connection reset", StringComparison.Ordinal) ||
            normalized.Contains("i/o timeout", StringComparison.Ordinal) ||
            normalized.Contains("transport is closing", StringComparison.Ordinal) ||
            normalized.Contains("error dialing backend", StringComparison.Ordinal) ||
            normalized.Contains("tls handshake timeout", StringComparison.Ordinal);
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

    [GeneratedRegex("^/[A-Za-z0-9._/-]+$", RegexOptions.CultureInvariant)] private static partial Regex AbsoluteContainerPath();
    [GeneratedRegex("^[A-Za-z][A-Za-z0-9_]{0,127}$", RegexOptions.CultureInvariant)] private static partial Regex DatabaseName();
    [GeneratedRegex("^[A-Z_]+$", RegexOptions.CultureInvariant)] private static partial Regex DatabaseState();
    [GeneratedRegex("^[a-z0-9](?:[-a-z0-9.]{0,61}[a-z0-9])?$", RegexOptions.CultureInvariant)] private static partial Regex KubernetesIdentifier();
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", RegexOptions.CultureInvariant)] private static partial Regex SafeIdentifier();
    [GeneratedRegex("^maliev-backups/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/Full_[A-Za-z][A-Za-z0-9_]{0,127}_[A-Za-z0-9][A-Za-z0-9._-]{0,127}\\.bak$", RegexOptions.CultureInvariant)] private static partial Regex SafeRemoteBackupPath();
    [GeneratedRegex("^Full_[A-Za-z][A-Za-z0-9_]{0,127}_[A-Za-z0-9][A-Za-z0-9._-]{0,127}\\.bak$", RegexOptions.CultureInvariant)] private static partial Regex SafeLocalFileName();
    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)] private static partial Regex Sha256Value();
}
