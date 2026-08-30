using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

namespace Legacy.Maliev.DataMigration;

public sealed record DockerRestoreResources(
    string ContainerId,
    string ContainerName,
    string VolumeId,
    string VolumeName,
    string RunBinding,
    string SqlServerImage,
    string SqlServerImageId,
    string StagingImage,
    string MountPath,
    bool MountReadOnly);

public sealed partial class DockerDisposableSqlServerProvisioner
{
    public static async Task<DockerRestoreResources> ProvisionAsync(
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
        ValidateName(volumeName, nameof(volumeName));
        ValidateName(containerName, nameof(containerName));
        ValidateName(runBinding, nameof(runBinding));
        sqlServerImage = RestoreImagePolicy.ValidateSqlServer2022(sqlServerImage);
        stagingImage = RestoreImagePolicy.ValidateStagingHelper(stagingImage);
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

        if (await ExistsAsync("volume", volumeName, cancellationToken).ConfigureAwait(false) ||
            await ExistsAsync("container", containerName, cancellationToken).ConfigureAwait(false))
        {
            throw new Exact25FullBackupException("restore_target_exists", "The run-owned disposable restore target already exists.");
        }

        DockerResourceIdentity? volume = null;
        DockerResourceIdentity? container = null;
        try
        {
            DockerResult volumeCreate = await RunDockerAsync(
                ["volume", "create", "--label", $"com.maliev.legacy.restore-run={runBinding}", volumeName],
                null, cancellationToken).ConfigureAwait(false);
            volume = OwnedOrNull(await InspectAsync("volume", volumeName, cancellationToken).ConfigureAwait(false), runBinding);
            EnsureSuccess(volumeCreate, "restore_volume_create_failed");
            if (volume is null)
            {
                throw new Exact25FullBackupException("restore_volume_identity_invalid", "The created restore volume has no matching immutable run identity.");
            }
            var environment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["MSSQL_SA_PASSWORD"] = connection.Password!,
            };
            DockerResult containerCreate = await RunDockerAsync(
                ["run", "-d", "--name", containerName,
                    "--label", $"com.maliev.legacy.restore-run={runBinding}",
                    "--mount", $"type=volume,source={volumeName},target={sqlServerMountPath},readonly",
                    "--publish", $"127.0.0.1:{endpoint.Groups["port"].Value}:1433",
                    "--env", "ACCEPT_EULA=Y", "--env", "MSSQL_SA_PASSWORD", sqlServerImage!],
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
            await WaitUntilReadyAsync(connection.ConnectionString, cancellationToken).ConfigureAwait(false);
            return new(container.Id, containerName, volume.Id, volumeName, runBinding,
                sqlServerImage, expectedSqlServerImageId, stagingImage, sqlServerMountPath, MountReadOnly: true);
        }
        catch (Exception provisionException)
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try
            {
                // Empty IDs intentionally trigger label-bound daemon reconciliation after ambiguous client failures.
                await CleanupCreatedResourcesAsync(
                    container ?? new(string.Empty, containerName, runBinding, null),
                    volume ?? new(string.Empty, volumeName, runBinding, null),
                    runBinding,
                    cleanup.Token).ConfigureAwait(false);
            }
            catch (Exception cleanupException)
            {
                throw new AggregateException(
                    "Disposable SQL Server provisioning failed and its run-owned Docker resources could not be fully removed.",
                    provisionException,
                    cleanupException);
            }

            throw;
        }
    }

    public static async Task CleanupAsync(DockerRestoreResources resources, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resources);
        ValidateName(resources.ContainerName, nameof(resources));
        ValidateName(resources.VolumeName, nameof(resources));
        ValidateName(resources.RunBinding, nameof(resources));
        await CleanupCreatedResourcesAsync(
            new(resources.ContainerId, resources.ContainerName, resources.RunBinding, resources.SqlServerImageId),
            new(resources.VolumeId, resources.VolumeName, resources.RunBinding, null),
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
            string? removalId = SelectOwnedResourceId(expected.Id, runBinding, observed.Id, observed.RunBinding);
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

    private static DockerResourceIdentity? OwnedOrNull(DockerResourceIdentity? observed, string runBinding)
    {
        return observed is not null && string.Equals(observed.RunBinding, runBinding, StringComparison.Ordinal)
            ? observed
            : null;
    }

    private static async Task<DockerResourceIdentity?> InspectAsync(
        string kind,
        string name,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<string> arguments = kind == "container"
            ? ["inspect", "--format", "{{.Id}}|{{index .Config.Labels \"com.maliev.legacy.restore-run\"}}|{{.Image}}", name]
            : ["volume", "inspect", "--format", "{{.Name}}|{{index .Labels \"com.maliev.legacy.restore-run\"}}", name];
        DockerResult result = await RunDockerAsync(arguments, null, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            return null;
        }
        string[] parts = result.StandardOutput.Trim().Split('|');
        int expectedParts = kind == "container" ? 3 : 2;
        return parts.Length == expectedParts && !string.IsNullOrWhiteSpace(parts[0])
            ? new(parts[0], name, parts[1], kind == "container" ? parts[2] : null)
            : null;
    }

    private static async Task<DockerResourceIdentity?> InspectForCleanupAsync(
        string kind,
        string name,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<string> inspectArguments = kind == "container"
            ? ["inspect", "--format", "{{.Id}}|{{index .Config.Labels \"com.maliev.legacy.restore-run\"}}|{{.Image}}", name]
            : ["volume", "inspect", "--format", "{{.Name}}|{{index .Labels \"com.maliev.legacy.restore-run\"}}", name];
        DockerResult inspection = await RunDockerAsync(inspectArguments, null, cancellationToken).ConfigureAwait(false);
        if (inspection.ExitCode == 0)
        {
            string[] parts = inspection.StandardOutput.Trim().Split('|');
            int expectedParts = kind == "container" ? 3 : 2;
            return parts.Length == expectedParts && !string.IsNullOrWhiteSpace(parts[0])
                ? new(parts[0], name, parts[1], kind == "container" ? parts[2] : null)
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

    private static async Task WaitUntilReadyAsync(string connectionString, CancellationToken cancellationToken)
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
                return;
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
    private sealed record DockerResourceIdentity(string Id, string Name, string RunBinding, string? ImageId);

    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeName();

    [GeneratedRegex("^(?:127\\.0\\.0\\.1|localhost),(?<port>[1-9][0-9]{0,4})$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex LoopbackEndpoint();

    [GeneratedRegex("^sha256:[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex ImageId();
}
