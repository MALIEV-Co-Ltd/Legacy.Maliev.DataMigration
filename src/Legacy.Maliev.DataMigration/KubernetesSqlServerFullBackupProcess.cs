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
        "root=$1; run=$2; test -d \"$root\"; test ! -L \"$root\"; test \"$(stat -c %u -- \"$root\")\" = \"$(id -u)\"; test \"$((0$(stat -c %a -- \"$root\") & 022))\" = 0; root_real=$(realpath -e -- \"$root\"); test \"$root_real\" = \"$root\"; " +
        "parent=\"$root/maliev-backups\"; if test -e \"$parent\" || test -L \"$parent\"; then test -d \"$parent\"; test ! -L \"$parent\"; else umask 077; mkdir -- \"$parent\"; fi; " +
        "test \"$(stat -c %u -- \"$parent\")\" = \"$(id -u)\"; test \"$(stat -c %a -- \"$parent\")\" = 700; " +
        "parent_real=$(realpath -e -- \"$parent\"); test \"$parent_real\" = \"$root_real/maliev-backups\"; target=\"$parent/$run\"; " +
        "test ! -e \"$target\"; test ! -L \"$target\"; mkdir --mode=700 -- \"$target\"; test -d \"$target\"; test ! -L \"$target\"; " +
        "test \"$(stat -c %u -- \"$target\")\" = \"$(id -u)\"; test \"$(stat -c %a -- \"$target\")\" = 700; " +
        "target_real=$(realpath -e -- \"$target\"); test \"$target_real\" = \"$parent_real/$run\"";

    private const string ValidateRunScript =
        "root=$1; run=$2; test -d \"$root\"; test ! -L \"$root\"; test \"$(stat -c %u -- \"$root\")\" = \"$(id -u)\"; test \"$((0$(stat -c %a -- \"$root\") & 022))\" = 0; root_real=$(realpath -e -- \"$root\"); test \"$root_real\" = \"$root\"; " +
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
        (string podNamespace, string podName, string podUid, bool ready, string containerId, string imageId) =
            ParsePod(podResult.StandardOutput, request.ContainerName);
        if (!ready || string.IsNullOrWhiteSpace(containerId) || string.IsNullOrWhiteSpace(imageId) || !string.Equals(podNamespace, request.Namespace, StringComparison.Ordinal) ||
            !string.Equals(podName, request.ExpectedPodName, StringComparison.Ordinal) ||
            !string.Equals(podUid, request.ExpectedPodUid, StringComparison.Ordinal))
        {
            throw new Exact25FullBackupException("source_identity_invalid", "The approved SQL Server container is absent from the observed pod.");
        }

        string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        string marker = SessionMarker(nonce);
        const string establishScript = "marker=$1; test ! -e \"$marker\"; test ! -L \"$marker\"; umask 077; (set -C; : > \"$marker\"); test -f \"$marker\"; test ! -L \"$marker\"; test \"$(stat -c %u -- \"$marker\")\" = \"$(id -u)\"; test \"$(stat -c %a -- \"$marker\")\" = 600";
        _ = await RunRequiredAsync(Kubectl("exec", podName, "-n", podNamespace, "-c", request.ContainerName, "--", "sh", "-ceu", establishScript, "sh", marker),
            "source_session_fence_failed", cancellationToken).ConfigureAwait(false);
        var fencedSource = new Exact25BackupSourceObservation(podNamespace, podName, podUid, request.ContainerName, ready,
            default, [])
        { ContainerId = containerId, ImageId = imageId, SessionNonce = nonce };
        await FenceSourceAsync(fencedSource, cancellationToken).ConfigureAwait(false);

        BackupProcessResult inventoryResult = await RunRequiredAsync(
            SecureKubectlSqlCmdInvocation.Create(
                request.Namespace, request.ExpectedPodName, request.ContainerName, InventorySql, credential, marker),
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
            databases)
        { ContainerId = containerId, ImageId = imageId, SessionNonce = nonce };
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
            KubectlExecFenced(source, "sh", "-ceu", ValidateAndCreateRunScript, "sh", _backupRoot, runId),
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
            SecureKubectlSqlCmdInvocation.Create(source.Namespace, source.PodName, source.ContainerName, sql, credential, SessionMarker(source.SessionNonce!)),
            "backup_create_failed",
            cancellationToken).ConfigureAwait(false);
        DateTimeOffset completedAtUtc = ParseTimestampMarker(backup.StandardOutput, "BACKUP_COMPLETED_AT_UTC", "backup_completion_output_invalid");

        await FenceSourceAsync(source, cancellationToken).ConfigureAwait(false);
        await ValidateRunAsync(source, runId, cancellationToken).ConfigureAwait(false);
        const string metadataScript =
            "root=$1; run=$2; file=$3; test -d \"$root\"; test ! -L \"$root\"; test \"$(stat -c %u -- \"$root\")\" = \"$(id -u)\"; test \"$((0$(stat -c %a -- \"$root\") & 022))\" = 0; " +
            "root_real=$(realpath -e -- \"$root\"); test \"$root_real\" = \"$root\"; run_path=\"$root/maliev-backups/$run\"; test -d \"$run_path\"; test ! -L \"$run_path\"; " +
            "test \"$(stat -c %u -- \"$run_path\")\" = \"$(id -u)\"; test \"$(stat -c %a -- \"$run_path\")\" = 700; run_real=$(realpath -e -- \"$run_path\"); test \"$run_real\" = \"$root_real/maliev-backups/$run\"; " +
            "test -f \"$file\"; test ! -L \"$file\"; chmod 600 -- \"$file\"; test \"$(stat -c %F -- \"$file\")\" = 'regular file'; test \"$(stat -c %u -- \"$file\")\" = \"$(id -u)\"; test \"$(stat -c %a -- \"$file\")\" = 600; " +
            "test \"$(realpath -e -- \"$file\")\" = \"$run_real/${file##*/}\"; size=$(stat -c %s -- \"$file\"); " +
            "hash=$(sha256sum -- \"$file\"); hash=${hash%% *}; printf '%s|%s\\n' \"$size\" \"$hash\"";
        BackupProcessResult metadata = await RunRequiredAsync(
            KubectlExecFenced(source, "sh", "-ceu", metadataScript, "sh", _backupRoot, runId, remotePath),
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
            SecureKubectlSqlCmdInvocation.Create(source.Namespace, source.PodName, source.ContainerName, sql, credential, SessionMarker(source.SessionNonce!)),
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
        SecureLocalFile.EnsureOwnerOnlyDirectory(fullWorkingDirectory);
        string target = Path.Combine(fullWorkingDirectory, localRelativePath);
        SecureLocalFile.EnsurePathWithin(fullWorkingDirectory, target);
        if (File.Exists(target) || Directory.Exists(target))
        {
            throw new Exact25FullBackupException("local_backup_destination_exists", "The local backup artifact destination already exists.");
        }

        string temporary = Path.Combine(fullWorkingDirectory, $".{localRelativePath}.{Guid.NewGuid():N}.tmp");
        try
        {
            string remotePath = $"{_backupRoot}/{artifact.RemoteRelativePath}";
            const string streamScript = "root=$1; run=$2; file=$3; test -d \"$root\"; test ! -L \"$root\"; test \"$(stat -c %u -- \"$root\")\" = \"$(id -u)\"; test \"$((0$(stat -c %a -- \"$root\") & 022))\" = 0; root_real=$(realpath -e -- \"$root\"); run_path=\"$root/maliev-backups/$run\"; test -d \"$run_path\"; test ! -L \"$run_path\"; test \"$(stat -c %u -- \"$run_path\")\" = \"$(id -u)\"; test \"$(stat -c %a -- \"$run_path\")\" = 700; run_real=$(realpath -e -- \"$run_path\"); test \"$run_real\" = \"$root_real/maliev-backups/$run\"; test -f \"$file\"; test ! -L \"$file\"; test \"$(stat -c %u -- \"$file\")\" = \"$(id -u)\"; test \"$(stat -c %a -- \"$file\")\" = 600; test \"$(realpath -e -- \"$file\")\" = \"$run_real/${file##*/}\"; exec cat -- \"$file\"";
            string runId = artifact.RemoteRelativePath.Split('/')[1];
            SecureBackupProcessInvocation invocation = KubectlExecFenced(source, "sh", "-ceu", streamScript, "sh", _backupRoot, runId, remotePath);
            BackupProcessResult result = await _runner.RunToNewFileAsync(invocation, temporary, cancellationToken).ConfigureAwait(false);
            if (result.ExitCode != 0)
            {
                throw new Exact25BackupTransportException(
                    "copy_transport_failed",
                    "The kubectl backup copy failed.",
                    IsExplicitlyRetryableCopyFailure(result.StandardError));
            }

            await FenceSourceAsync(source, cancellationToken).ConfigureAwait(false);
            SecureLocalFile.EnsureOwnerOnlyDirectory(fullWorkingDirectory);
            SecureLocalFile.EnsurePathWithin(fullWorkingDirectory, temporary);

            var copied = new FileInfo(temporary);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            if (!SecureLocalFile.IsOwnerOnlyFile(copied) || copied.Length != artifact.ByteLength)
            {
                throw new Exact25FullBackupException("local_backup_hash_invalid", "The kubectl backup copy does not match the verified remote artifact.");
            }

            string copiedSha256;
            await using (FileStream copiedRead = SecureLocalFile.OpenRead(temporary))
            {
                copiedSha256 = await SecureLocalFile.ComputeSha256Async(copiedRead, cancellationToken).ConfigureAwait(false);
            }
            if (!FixedHashEquals(copiedSha256, artifact.Sha256))
            {
                throw new Exact25FullBackupException("local_backup_hash_invalid", "The kubectl backup copy does not match the verified remote artifact.");
            }

            copied.Refresh();
            SecureLocalFile.EnsureOwnerOnlyDirectory(fullWorkingDirectory);
            if (!SecureLocalFile.IsOwnerOnlyFile(copied))
            {
                throw new Exact25FullBackupException("local_backup_type_invalid", "The copied backup is not a regular non-link file.");
            }
            File.Move(temporary, target);
            SecureLocalFile.EnsureOwnerOnlyDirectory(fullWorkingDirectory);
            SecureLocalFile.EnsurePathWithin(fullWorkingDirectory, target);
            if (!SecureLocalFile.IsOwnerOnlyFile(new FileInfo(target)))
            {
                throw new Exact25FullBackupException("local_backup_type_invalid", "The finalized backup is not an owner-only regular file.");
            }
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

    private static SecureBackupProcessInvocation KubectlExecFenced(Exact25BackupSourceObservation source, params string[] command)
    {
        string marker = SessionMarker(source.SessionNonce!);
        const string fenceScript = "marker=$1; shift; test -f \"$marker\"; test ! -L \"$marker\"; test \"$(stat -c %u -- \"$marker\")\" = \"$(id -u)\"; test \"$(stat -c %a -- \"$marker\")\" = 600; exec \"$@\"";
        string[] arguments = [
            "exec", source.PodName, "-n", source.Namespace, "-c", source.ContainerName, "--",
            "sh", "-ceu", fenceScript, "sh", marker, .. command,
        ];
        return Kubectl(arguments);
    }

    private static (string Namespace, string Name, string Uid, bool Ready, string ContainerId, string ImageId) ParsePod(
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
            JsonElement status = root.GetProperty("status").GetProperty("containerStatuses").EnumerateArray().Single(container =>
                string.Equals(container.GetProperty("name").GetString(), expectedContainer, StringComparison.Ordinal));
            bool containerReady = status.GetProperty("ready").GetBoolean() && status.GetProperty("state").TryGetProperty("running", out _);
            return (podNamespace, name, uid, ready && containerReady,
                status.GetProperty("containerID").GetString() ?? string.Empty,
                status.GetProperty("imageID").GetString() ?? string.Empty);
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
        (string ns, string name, string uid, bool ready, string containerId, string imageId) = ParsePod(result.StandardOutput, source.ContainerName);
        if (!ready || !string.Equals(ns, source.Namespace, StringComparison.Ordinal) ||
            !string.Equals(name, source.PodName, StringComparison.Ordinal) || !string.Equals(uid, source.PodUid, StringComparison.Ordinal) ||
            !string.Equals(containerId, source.ContainerId, StringComparison.Ordinal) || !string.Equals(imageId, source.ImageId, StringComparison.Ordinal))
        {
            throw new Exact25FullBackupException("source_identity_changed", "The SQL Server pod identity changed during backup production.");
        }
    }

    private async Task ValidateRunAsync(Exact25BackupSourceObservation source, string runId, CancellationToken cancellationToken)
    {
        _ = await RunRequiredAsync(
            KubectlExecFenced(source, "sh", "-ceu", ValidateRunScript, "sh", _backupRoot, runId),
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

    private static void ValidateSourceIdentifiers(Exact25BackupSourceObservation source)
    {
        ArgumentNullException.ThrowIfNull(source);
        ValidateKubernetesIdentifier(source.Namespace);
        ValidateKubernetesIdentifier(source.PodName);
        ValidateKubernetesIdentifier(source.ContainerName);
        ValidateSafeIdentifier(source.PodUid);
        ValidateSafeIdentifier(source.SessionNonce ?? string.Empty);
        if (string.IsNullOrWhiteSpace(source.ContainerId) || string.IsNullOrWhiteSpace(source.ImageId))
        {
            throw new Exact25FullBackupException("source_identity_invalid", "Container runtime identity is missing.");
        }
    }

    private static string SessionMarker(string nonce)
    {
        return $"/dev/shm/maliev-backup-session-{nonce}";
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
