using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

namespace Legacy.Maliev.DataMigration;

public sealed partial class DockerDisposableSqlServerProvisioner
{
    public static async Task ProvisionAsync(
        string adminConnectionString,
        string volumeName,
        string containerName,
        string sqlServerMountPath,
        string sqlServerImage,
        string runBinding,
        CancellationToken cancellationToken)
    {
        ValidateName(volumeName, nameof(volumeName));
        ValidateName(containerName, nameof(containerName));
        ValidateName(runBinding, nameof(runBinding));
        if (!PinnedImage().IsMatch(sqlServerImage ?? string.Empty))
        {
            throw new ArgumentException("The SQL Server image must be pinned by sha256 digest.", nameof(sqlServerImage));
        }
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

        bool volumeCreated = false;
        bool containerCreated = false;
        try
        {
            EnsureSuccess(await RunDockerAsync(
                ["volume", "create", "--label", $"com.maliev.legacy.restore-run={runBinding}", volumeName],
                null, cancellationToken).ConfigureAwait(false), "restore_volume_create_failed");
            volumeCreated = true;
            var environment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["MSSQL_SA_PASSWORD"] = connection.Password!,
            };
            EnsureSuccess(await RunDockerAsync(
                ["run", "-d", "--name", containerName,
                    "--label", $"com.maliev.legacy.restore-run={runBinding}",
                    "--mount", $"type=volume,source={volumeName},target={sqlServerMountPath},readonly",
                    "--publish", $"127.0.0.1:{endpoint.Groups["port"].Value}:1433",
                    "--env", "ACCEPT_EULA=Y", "--env", "MSSQL_SA_PASSWORD", sqlServerImage!],
                environment, cancellationToken).ConfigureAwait(false), "restore_container_create_failed");
            containerCreated = true;
            await WaitUntilReadyAsync(connection.ConnectionString, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            if (containerCreated)
            {
                _ = await RunDockerAsync(["rm", "-f", containerName], null, cleanup.Token).ConfigureAwait(false);
            }
            if (volumeCreated)
            {
                _ = await RunDockerAsync(["volume", "rm", "-f", volumeName], null, cleanup.Token).ConfigureAwait(false);
            }
            throw;
        }
    }

    public static async Task CleanupAsync(string containerName, string volumeName, CancellationToken cancellationToken)
    {
        ValidateName(containerName, nameof(containerName));
        ValidateName(volumeName, nameof(volumeName));
        _ = await RunDockerAsync(["rm", "-f", containerName], null, cancellationToken).ConfigureAwait(false);
        _ = await RunDockerAsync(["volume", "rm", "-f", volumeName], null, cancellationToken).ConfigureAwait(false);
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

    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeName();

    [GeneratedRegex("^[a-z0-9./:_-]+@sha256:[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex PinnedImage();

    [GeneratedRegex("^(?:127\\.0\\.0\\.1|localhost),(?<port>[1-9][0-9]{0,4})$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex LoopbackEndpoint();
}
