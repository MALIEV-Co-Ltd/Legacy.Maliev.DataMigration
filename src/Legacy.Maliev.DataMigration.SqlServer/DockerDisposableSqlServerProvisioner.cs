using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

namespace Legacy.Maliev.DataMigration;

public sealed record DockerRestoreResources(
    string ContainerId,
    string ContainerName,
    string VolumeId,
    string VolumeName,
    string VolumeBinding,
    string VolumeFingerprint,
    string RunBinding,
    string SqlServerImage,
    string SqlServerImageId,
    string StagingImage,
    string MountPath,
    bool MountReadOnly,
    string SqlServerProductMajorVersion);

/// <summary>Explicit limits applied before a disposable SQL Server container starts.</summary>
public sealed class DockerRestoreResourceLimits
{
    public DockerRestoreResourceLimits(long memoryBytes, long memorySwapBytes, decimal cpus)
    {
        if (memoryBytes < 6L * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(memoryBytes), "Docker memory limits must be at least six MiB.");
        }
        if (memorySwapBytes < memoryBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(memorySwapBytes), "The memory-plus-swap limit must cover the memory limit.");
        }
        if (cpus <= 0 || cpus > long.MaxValue / 1_000_000_000m ||
            decimal.Truncate(cpus * 1_000_000_000m) != cpus * 1_000_000_000m)
        {
            throw new ArgumentOutOfRangeException(nameof(cpus), "The CPU limit must be positive and representable in whole nano CPUs.");
        }
        MemoryBytes = memoryBytes;
        MemorySwapBytes = memorySwapBytes;
        Cpus = cpus;
    }

    public DockerRestoreResourceLimits(long memoryBytes, long memorySwapBytes, decimal cpus, int sqlServerMemoryLimitMb)
        : this(memoryBytes, memorySwapBytes, cpus)
    {
        if (sqlServerMemoryLimitMb <= 0 || sqlServerMemoryLimitMb >= memoryBytes / (1024 * 1024))
        {
            throw new ArgumentOutOfRangeException(nameof(sqlServerMemoryLimitMb), "The SQL Server process limit must be positive and below the container memory limit in MiB.");
        }
        SqlServerMemoryLimitMb = sqlServerMemoryLimitMb;
    }

    public int? SqlServerMemoryLimitMb { get; }
    public long MemoryBytes { get; }
    public long MemorySwapBytes { get; }
    public decimal Cpus { get; }
}

public sealed partial class DockerDisposableSqlServerProvisioner
{
    public static Task<DockerRestoreResources> ProvisionAsync(
        string adminConnectionString,
        string volumeName,
        string containerName,
        string sqlServerMountPath,
        string sqlServerImage,
        string expectedSqlServerImageId,
        string stagingImage,
        string runBinding,
        CancellationToken cancellationToken)
    {
        return ProvisionAsync(
            adminConnectionString, volumeName, containerName, sqlServerMountPath, sqlServerImage,
            expectedSqlServerImageId, stagingImage, runBinding, resourceLimits: null, cancellationToken);
    }

    public static async Task<DockerRestoreResources> ProvisionAsync(
        string adminConnectionString,
        string volumeName,
        string containerName,
        string sqlServerMountPath,
        string sqlServerImage,
        string expectedSqlServerImageId,
        string stagingImage,
        string runBinding,
        DockerRestoreResourceLimits? resourceLimits,
        CancellationToken cancellationToken)
    {
        ValidateName(volumeName, nameof(volumeName));
        ValidateName(containerName, nameof(containerName));
        ValidateName(runBinding, nameof(runBinding));
        sqlServerImage = RestoreImagePolicy.ValidateSqlServer2022(sqlServerImage);
        stagingImage = RestoreImagePolicy.ValidateStagingHelper(stagingImage);
        string volumeBinding = volumeName;
        string volumeFingerprint = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        expectedSqlServerImageId = ImageId().IsMatch(expectedSqlServerImageId ?? string.Empty)
            ? expectedSqlServerImageId!
            : throw new ArgumentException("The approved SQL Server image ID is invalid.", nameof(expectedSqlServerImageId));
        if (string.IsNullOrWhiteSpace(sqlServerMountPath) || sqlServerMountPath[0] != '/' ||
            sqlServerMountPath.Contains("..", StringComparison.Ordinal))
        {
            throw new ArgumentException("The SQL Server backup mount path is invalid.", nameof(sqlServerMountPath));
        }

        var connection = new SqlConnectionStringBuilder(adminConnectionString);
        Match endpoint = LoopbackEndpoint().Match(connection.DataSource);
        if (!endpoint.Success || string.IsNullOrWhiteSpace(connection.Password) ||
            !string.Equals(connection.UserID, "sa", StringComparison.OrdinalIgnoreCase))
        {
            throw new Exact25FullBackupException(
                "restore_target_connection_invalid",
                "The disposable SQL Server connection must use sa on an explicit loopback TCP port.");
        }

        if (await ExistsAsync("container", containerName, cancellationToken).ConfigureAwait(false))
        {
            throw new Exact25FullBackupException("restore_target_exists", "The run-owned disposable restore target already exists.");
        }

        DockerResourceIdentity? volume = null;
        DockerResourceIdentity? container = null;
        try
        {
            DockerResult volumeCreate = await RunDockerAsync(
                ["volume", "create",
                    "--label", $"com.maliev.legacy.restore-run={runBinding}",
                    "--label", $"com.maliev.legacy.restore-volume-binding={volumeBinding}",
                    "--label", $"com.maliev.legacy.restore-volume-fingerprint={volumeFingerprint}"],
                null, cancellationToken).ConfigureAwait(false);
            EnsureSuccess(volumeCreate, "restore_volume_create_failed");
            string generatedVolumeName = volumeCreate.StandardOutput.Trim();
            ValidateName(generatedVolumeName, "generatedVolumeName");
            volume = OwnedOrNull(
                await InspectAsync("volume", generatedVolumeName, cancellationToken).ConfigureAwait(false),
                runBinding,
                volumeFingerprint,
                volumeBinding) ?? throw new Exact25FullBackupException("restore_volume_identity_invalid", "The created restore volume has no matching immutable run identity.");
            var environment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["MSSQL_SA_PASSWORD"] = connection.Password!,
            };
            DockerResult containerCreate = await RunDockerAsync(
                CreateRunArguments(containerName, runBinding, volume.Name, sqlServerMountPath,
                    endpoint.Groups["port"].Value, sqlServerImage, resourceLimits),
                environment, cancellationToken).ConfigureAwait(false);
            container = OwnedOrNull(await InspectAsync("container", containerName, cancellationToken).ConfigureAwait(false), runBinding);
            EnsureSuccess(containerCreate, "restore_container_create_failed");
            if (container is null)
            {
                throw new Exact25FullBackupException("restore_container_identity_invalid", "The created restore container has no matching immutable run identity.");
            }
            if (!string.Equals(container.ImageId, expectedSqlServerImageId, StringComparison.Ordinal))
            {
                throw new Exact25FullBackupException("restore_container_image_invalid", "The restore container image does not match the approved immutable image ID.");
            }
            string productMajorVersion = await WaitUntilReadyAsync(connection.ConnectionString, cancellationToken).ConfigureAwait(false);
            return new(container.Id, containerName, volume.Id, volume.Name, volumeBinding, volumeFingerprint, runBinding,
                sqlServerImage, expectedSqlServerImageId, stagingImage, sqlServerMountPath, MountReadOnly: true,
                productMajorVersion);
        }
        catch (Exception provisionException)
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var cleanupFailures = new List<Exception>();
            if (volume is null)
            {
                try
                {
                    volume = await FindOwnedVolumeAsync(
                        runBinding, volumeBinding, volumeFingerprint, cleanup.Token).ConfigureAwait(false);
                }
                catch (Exception reconciliationException)
                {
                    cleanupFailures.Add(reconciliationException);
                }
            }
            try
            {
                // Empty IDs intentionally trigger label-bound daemon reconciliation after ambiguous client failures.
                await CleanupCreatedResourcesAsync(
                    container ?? new(string.Empty, containerName, runBinding, null, null, null),
                    volume,
                    runBinding,
                    cleanup.Token).ConfigureAwait(false);
            }
            catch (Exception cleanupException)
            {
                cleanupFailures.Add(cleanupException);
            }
            if (cleanupFailures.Count > 0)
            {
                throw new AggregateException(
                    "Disposable SQL Server provisioning failed and its run-owned Docker resources could not be fully removed.",
                    [provisionException, .. cleanupFailures]);
            }

            throw;
        }
    }

    internal static string[] CreateRunArguments(string containerName, string runBinding, string volumeName,
        string mountPath, string port, string image, DockerRestoreResourceLimits? limits)
    {
        string[] limitArguments = limits is null ? [] :
            ["--memory", limits.MemoryBytes.ToString(CultureInfo.InvariantCulture),
             "--memory-swap", limits.MemorySwapBytes.ToString(CultureInfo.InvariantCulture),
             "--cpus", limits.Cpus.ToString("0.#########", CultureInfo.InvariantCulture)];
        string[] processLimitArguments = limits?.SqlServerMemoryLimitMb is { } memoryLimitMb
            ? ["--env", "MSSQL_MEMORY_LIMIT_MB=" + memoryLimitMb.ToString(CultureInfo.InvariantCulture)] : [];
        return ["run", "-d", "--name", containerName, .. limitArguments,
            "--label", $"com.maliev.legacy.restore-run={runBinding}",
            "--mount", $"type=volume,source={volumeName},target={mountPath},readonly",
            "--publish", $"127.0.0.1:{port}:1433",
            "--env", "ACCEPT_EULA=Y", "--env", "MSSQL_SA_PASSWORD", .. processLimitArguments, image];
    }

    public static async Task CleanupAsync(DockerRestoreResources resources, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resources);
        ValidateName(resources.ContainerName, nameof(resources));
        ValidateName(resources.VolumeName, nameof(resources));
        ValidateName(resources.RunBinding, nameof(resources));
        await CleanupCreatedResourcesAsync(
            new(resources.ContainerId, resources.ContainerName, resources.RunBinding, null, null, resources.SqlServerImageId),
            new(resources.VolumeId, resources.VolumeName, resources.RunBinding,
                resources.VolumeBinding, resources.VolumeFingerprint, null),
            resources.RunBinding,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task CleanupCreatedResourcesAsync(
        DockerResourceIdentity? container,
        DockerResourceIdentity? volume,
        string runBinding,
        CancellationToken cancellationToken)
    {
        var failures = new List<Exception>();
        if (container is not null)
        {
            await TryRemoveOwnedResourceAsync(
                failures,
                "container",
                container,
                runBinding,
                "restore_container_cleanup_failed",
                cancellationToken).ConfigureAwait(false);
        }

        if (volume is not null)
        {
            await TryRemoveOwnedResourceAsync(
                failures,
                "volume",
                volume,
                runBinding,
                "restore_volume_cleanup_failed",
                cancellationToken).ConfigureAwait(false);
        }

        if (failures.Count == 1)
        {
            throw failures[0];
        }

        if (failures.Count > 1)
        {
            throw new AggregateException(
                "The run-owned disposable SQL Server container and volume could not be fully removed.",
                failures);
        }
    }

    private static async Task TryRemoveOwnedResourceAsync(
        List<Exception> failures,
        string kind,
        DockerResourceIdentity expected,
        string runBinding,
        string code,
        CancellationToken cancellationToken)
    {
        try
        {
            DockerResourceIdentity? observed = await InspectForCleanupAsync(kind, expected.Name, cancellationToken).ConfigureAwait(false);
            if (observed is null)
            {
                return;
            }
            string? removalId = kind == "volume"
                ? string.Equals(expected.VolumeBinding, observed.VolumeBinding, StringComparison.Ordinal) &&
                  IsOwnedVolumeEvidence(
                    expected.Name,
                    runBinding,
                    expected.Fingerprint ?? string.Empty,
                    observed.Name,
                    observed.RunBinding,
                    observed.Fingerprint ?? string.Empty)
                    ? observed.Name
                    : null
                : SelectOwnedResourceId(expected.Id, runBinding, observed.Id, observed.RunBinding);
            if (removalId is null)
            {
                failures.Add(new Exact25FullBackupException(code, "A same-name Docker resource no longer belongs to this restore run."));
                return;
            }
            IReadOnlyList<string> arguments = kind == "container"
                ? ["rm", "-f", removalId]
                : ["volume", "rm", "-f", removalId];
            DockerResult result = await RunDockerAsync(arguments, null, cancellationToken).ConfigureAwait(false);
            if (result.ExitCode != 0)
            {
                AddCleanupFailure(failures, result, code);
                return;
            }
            DockerResourceIdentity? observedAfterRemoval = await InspectForCleanupAsync(
                kind, expected.Name, cancellationToken).ConfigureAwait(false);
            if (!IsRemovalConfirmed(result.ExitCode, observedAfterRemoval is not null))
            {
                failures.Add(new Exact25FullBackupException(code, "Docker did not prove that the run-owned restore resource was removed."));
            }
        }
        catch (Exception exception)
        {
            failures.Add(new AggregateException(
                "A run-owned disposable Docker restore resource cleanup command did not complete.",
                new Exact25FullBackupException(code, "A run-owned disposable Docker restore resource could not be removed."),
                exception));
        }
    }

    internal static bool IsOwnedResourceEvidence(
        string expectedId,
        string expectedRunBinding,
        string observedId,
        string observedRunBinding)
    {
        return !string.IsNullOrWhiteSpace(expectedId) &&
            string.Equals(expectedId, observedId, StringComparison.Ordinal) &&
            string.Equals(expectedRunBinding, observedRunBinding, StringComparison.Ordinal);
    }

    internal static bool IsOwnedVolumeEvidence(
        string expectedName,
        string expectedRunBinding,
        string expectedFingerprint,
        string observedName,
        string observedRunBinding,
        string observedFingerprint)
    {
        string normalizedExpectedFingerprint = expectedFingerprint ?? string.Empty;
        string normalizedObservedFingerprint = observedFingerprint ?? string.Empty;
        return !string.IsNullOrWhiteSpace(expectedName) &&
            Fingerprint().IsMatch(normalizedExpectedFingerprint) &&
            string.Equals(expectedName, observedName, StringComparison.Ordinal) &&
            string.Equals(expectedRunBinding, observedRunBinding, StringComparison.Ordinal) &&
            CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(normalizedExpectedFingerprint),
                System.Text.Encoding.ASCII.GetBytes(normalizedObservedFingerprint));
    }

    internal static bool IsSqlServer2022(string productMajorVersion)
    {
        return string.Equals(productMajorVersion, "16", StringComparison.Ordinal);
    }

    internal static string? SelectOwnedResourceId(
        string expectedId,
        string expectedRunBinding,
        string observedId,
        string observedRunBinding)
    {
        return !string.Equals(expectedRunBinding, observedRunBinding, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(observedId)
            ? null
            : string.IsNullOrEmpty(expectedId) || string.Equals(expectedId, observedId, StringComparison.Ordinal)
            ? observedId
            : null;
    }

    internal static bool IsConfirmedAbsent(int inspectExitCode, int listExitCode, string listing)
    {
        return inspectExitCode != 0 && listExitCode == 0 && string.IsNullOrWhiteSpace(listing);
    }

    internal static bool IsRemovalConfirmed(int removalExitCode, bool resourceStillExists)
    {
        return removalExitCode == 0 && !resourceStillExists;
    }

    private static DockerResourceIdentity? OwnedOrNull(
        DockerResourceIdentity? observed,
        string runBinding,
        string? volumeFingerprint = null,
        string? volumeBinding = null)
    {
        return observed is not null && string.Equals(observed.RunBinding, runBinding, StringComparison.Ordinal) &&
            (volumeFingerprint is null ||
             (string.Equals(volumeBinding, observed.VolumeBinding, StringComparison.Ordinal) &&
             IsOwnedVolumeEvidence(observed.Name, runBinding, volumeFingerprint,
                 observed.Name, observed.RunBinding, observed.Fingerprint ?? string.Empty)))
            ? observed
            : null;
    }

    private static async Task<DockerResourceIdentity?> FindOwnedVolumeAsync(
        string runBinding,
        string volumeBinding,
        string volumeFingerprint,
        CancellationToken cancellationToken)
    {
        DockerResult listing = await RunDockerAsync(
            ["volume", "ls",
                "--filter", $"label=com.maliev.legacy.restore-run={runBinding}",
                "--filter", $"label=com.maliev.legacy.restore-volume-binding={volumeBinding}",
                "--filter", $"label=com.maliev.legacy.restore-volume-fingerprint={volumeFingerprint}",
                "--format", "{{.Name}}"],
            null,
            cancellationToken).ConfigureAwait(false);
        if (listing.ExitCode != 0)
        {
            throw new Exact25FullBackupException(
                "restore_volume_reconciliation_failed",
                "Docker could not reconcile the daemon-generated restore volume after an ambiguous create result.");
        }
        string[] names = listing.StandardOutput
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return names.Length == 0
            ? null
            : names.Length != 1 || !SafeName().IsMatch(names[0])
            ? throw new Exact25FullBackupException(
                "restore_volume_reconciliation_ambiguous",
                "Docker returned ambiguous daemon-generated restore volume ownership evidence.")
            : OwnedOrNull(
            await InspectAsync("volume", names[0], cancellationToken).ConfigureAwait(false),
            runBinding,
            volumeFingerprint,
            volumeBinding) ?? throw new Exact25FullBackupException(
            "restore_volume_reconciliation_invalid",
            "The reconciled restore volume does not match its cryptographic ownership fingerprint.");
    }

    private static async Task<DockerResourceIdentity?> InspectAsync(
        string kind,
        string name,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<string> arguments = kind == "container"
            ? ["inspect", "--format", "{{.Id}}|{{index .Config.Labels \"com.maliev.legacy.restore-run\"}}|{{.Image}}", name]
            : ["volume", "inspect", "--format", "{{.Name}}|{{index .Labels \"com.maliev.legacy.restore-run\"}}|{{index .Labels \"com.maliev.legacy.restore-volume-binding\"}}|{{index .Labels \"com.maliev.legacy.restore-volume-fingerprint\"}}", name];
        DockerResult result = await RunDockerAsync(arguments, null, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            return null;
        }
        string[] parts = result.StandardOutput.Trim().Split('|');
        int expectedParts = kind == "container" ? 3 : 4;
        return parts.Length == expectedParts && !string.IsNullOrWhiteSpace(parts[0])
            ? kind == "container"
                ? new(parts[0], name, parts[1], null, null, parts[2])
                : new(parts[0], name, parts[1], parts[2], parts[3], null)
            : null;
    }

    private static async Task<DockerResourceIdentity?> InspectForCleanupAsync(
        string kind,
        string name,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<string> inspectArguments = kind == "container"
            ? ["inspect", "--format", "{{.Id}}|{{index .Config.Labels \"com.maliev.legacy.restore-run\"}}|{{.Image}}", name]
            : ["volume", "inspect", "--format", "{{.Name}}|{{index .Labels \"com.maliev.legacy.restore-run\"}}|{{index .Labels \"com.maliev.legacy.restore-volume-binding\"}}|{{index .Labels \"com.maliev.legacy.restore-volume-fingerprint\"}}", name];
        DockerResult inspection = await RunDockerAsync(inspectArguments, null, cancellationToken).ConfigureAwait(false);
        if (inspection.ExitCode == 0)
        {
            string[] parts = inspection.StandardOutput.Trim().Split('|');
            int expectedParts = kind == "container" ? 3 : 4;
            return parts.Length == expectedParts && !string.IsNullOrWhiteSpace(parts[0])
                ? kind == "container"
                    ? new(parts[0], name, parts[1], null, null, parts[2])
                    : new(parts[0], name, parts[1], parts[2], parts[3], null)
                : throw new Exact25FullBackupException(
                    "restore_cleanup_identity_invalid",
                    "Docker returned malformed immutable restore resource identity evidence.");
        }

        IReadOnlyList<string> listArguments = kind == "container"
            ? ["container", "ls", "--all", "--filter", $"name=^/{name}$", "--format", "{{.ID}}"]
            : ["volume", "ls", "--filter", $"name=^{name}$", "--format", "{{.Name}}"];
        DockerResult listing = await RunDockerAsync(listArguments, null, cancellationToken).ConfigureAwait(false);
        return IsConfirmedAbsent(inspection.ExitCode, listing.ExitCode, listing.StandardOutput)
            ? null
            : throw new Exact25FullBackupException(
            "restore_cleanup_inspection_failed",
            "Docker could not prove that the run-owned restore resource is absent.");
    }

    internal static void AddCleanupFailure(
        List<Exception> failures,
        int exitCode,
        string code)
    {
        AddCleanupFailure(failures, new DockerResult(exitCode, string.Empty, string.Empty), code);
    }

    private static void AddCleanupFailure(
        List<Exception> failures,
        DockerResult result,
        string code)
    {
        if (result.ExitCode != 0)
        {
            failures.Add(new Exact25FullBackupException(
                code,
                "A run-owned disposable Docker restore resource could not be removed."));
        }
    }

    private static async Task<string> WaitUntilReadyAsync(string connectionString, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(2));
        Exception? last = null;
        while (!timeout.IsCancellationRequested)
        {
            try
            {
                await using var connection = new SqlConnection(connectionString);
                await connection.OpenAsync(timeout.Token).ConfigureAwait(false);
                await using var version = new SqlCommand(
                    "SELECT CONVERT(varchar(10), SERVERPROPERTY('ProductMajorVersion'));",
                    connection)
                { CommandTimeout = 0 };
                string productMajorVersion = Convert.ToString(
                    await version.ExecuteScalarAsync(timeout.Token).ConfigureAwait(false),
                    CultureInfo.InvariantCulture) ?? string.Empty;
                return !IsSqlServer2022(productMajorVersion)
                    ? throw new Exact25FullBackupException(
                        "restore_sqlserver_version_invalid",
                        "The disposable restore runtime is not Microsoft SQL Server 2022 major version 16.")
                    : productMajorVersion;
            }
            catch (Exception exception) when (exception is SqlException or InvalidOperationException)
            {
                last = exception;
                await Task.Delay(TimeSpan.FromSeconds(1), timeout.Token).ConfigureAwait(false);
            }
        }
        throw new Exact25FullBackupException(
            "restore_container_unavailable",
            $"The disposable SQL Server did not become ready ({last?.GetType().Name ?? "timeout"}).");
    }

    private static async Task<bool> ExistsAsync(string kind, string name, CancellationToken cancellationToken)
    {
        DockerResult result = await RunDockerAsync([kind, "inspect", name], null, cancellationToken).ConfigureAwait(false);
        return result.ExitCode == 0;
    }

    private static async Task<DockerResult> RunDockerAsync(
        IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string>? environment,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo("docker")
        {
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        if (environment is not null)
        {
            foreach ((string key, string value) in environment)
            {
                startInfo.Environment[key] = value;
            }
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
            {
                throw new Exact25FullBackupException("docker_start_failed", "Docker could not start.");
            }
            Task<string> stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
            Task<string> stderr = process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            return new(process.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
        }
        catch
        {
            try { process.Kill(entireProcessTree: true); } catch (Exception) { }
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try { await process.WaitForExitAsync(cleanup.Token).ConfigureAwait(false); } catch (Exception) { }
            throw;
        }
    }

    private static void EnsureSuccess(DockerResult result, string code)
    {
        if (result.ExitCode != 0)
        {
            throw new Exact25FullBackupException(code, "The disposable Docker restore target could not be provisioned.");
        }
    }

    private static void ValidateName(string value, string parameterName)
    {
        if (!SafeName().IsMatch(value ?? string.Empty))
        {
            throw new ArgumentException("The Docker run-owned name is invalid.", parameterName);
        }
    }

    private sealed record DockerResult(int ExitCode, string StandardOutput, string StandardError);
    private sealed record DockerResourceIdentity(
        string Id,
        string Name,
        string RunBinding,
        string? VolumeBinding,
        string? Fingerprint,
        string? ImageId);

    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeName();

    [GeneratedRegex("^(?:127\\.0\\.0\\.1|localhost),(?<port>[1-9][0-9]{0,4})$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex LoopbackEndpoint();

    [GeneratedRegex("^sha256:[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex ImageId();

    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Fingerprint();
}
