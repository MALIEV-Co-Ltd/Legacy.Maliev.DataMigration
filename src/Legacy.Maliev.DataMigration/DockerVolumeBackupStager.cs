using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public sealed record SqlServerStagedBackup(string SqlServerPath, long ByteLength, string Sha256);

public interface ISqlServerBackupStager
{
    Task<SqlServerStagedBackup> StageAsync(VerifiedBackupRestoreArtifact artifact, CancellationToken cancellationToken);
}

/// <summary>
/// Copies verified backup bytes into a Docker-managed volume which is mounted read-only by the disposable SQL Server.
/// The source pathname is never exposed to SQL Server and the staged object is independently hashed before use.
/// </summary>
public sealed partial class DockerVolumeBackupStager(
    string volumeName,
    string sqlServerMountPath,
    string stagingImage,
    string sqlServerContainerName,
    string sqlServerImageId) : ISqlServerBackupStager
{
    private static readonly JsonSerializerOptions DockerJson = new() { PropertyNameCaseInsensitive = true };
    private readonly string _volumeName = SafeName().IsMatch(volumeName ?? string.Empty)
        ? volumeName!
        : throw new ArgumentException("The staging volume name is invalid.", nameof(volumeName));
    private readonly string _sqlServerMountPath = ValidateMountPath(sqlServerMountPath);
    private readonly string _stagingImage = RestoreImagePolicy.ValidateStagingHelper(stagingImage);
    private readonly string _sqlServerContainerName = SafeName().IsMatch(sqlServerContainerName ?? string.Empty)
        ? sqlServerContainerName!
        : throw new ArgumentException("The disposable SQL Server container name is invalid.", nameof(sqlServerContainerName));
    private readonly string _sqlServerImageId = ImageId().IsMatch(sqlServerImageId ?? string.Empty)
        ? sqlServerImageId!
        : throw new ArgumentException("The disposable SQL Server image ID is invalid.", nameof(sqlServerImageId));

    public async Task<SqlServerStagedBackup> StageAsync(
        VerifiedBackupRestoreArtifact artifact,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        string fileName = Path.GetFileName(artifact.LocalPath);
        if (!SafeFileName().IsMatch(fileName))
        {
            throw new Exact25FullBackupException("restore_stage_path_invalid", "The staged backup filename is unsafe.");
        }

        await VerifyReadOnlySqlMountAsync(cancellationToken).ConfigureAwait(false);

        artifact.RetainedHandle.Position = 0;
        string script = "set -eu; umask 077; test ! -e /staging/$1; trap 'rm -f /staging/.$1.partial' EXIT; " +
            "cat > /staging/.$1.partial; test $(wc -c < /staging/.$1.partial) -eq $2; " +
            "chown 10001:0 /staging/.$1.partial; chmod 0400 /staging/.$1.partial; " +
            "mv /staging/.$1.partial /staging/$1; trap - EXIT; sha256sum /staging/$1";
        ProcessResult staged;
        try
        {
            staged = await RunAsync(
                ["run", "--rm", "-i", "--user", "0:0", "--mount", $"type=volume,source={_volumeName},target=/staging",
                    "--entrypoint", "sh", _stagingImage, "-ceu", script, "sh", fileName,
                    artifact.ByteLength.ToString(System.Globalization.CultureInfo.InvariantCulture)],
                artifact.RetainedHandle,
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await RemoveStagedFileAsync(fileName).ConfigureAwait(false);
            throw;
        }
        if (staged.ExitCode != 0)
        {
            await RemoveStagedFileAsync(fileName).ConfigureAwait(false);
            throw new Exact25FullBackupException("restore_stage_failed", "The verified backup could not be staged.");
        }

        string observed = staged.StandardOutput.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
        if (!Sha256().IsMatch(observed) || !CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(observed.ToLowerInvariant()),
            System.Text.Encoding.ASCII.GetBytes(artifact.Sha256.ToLowerInvariant())))
        {
            await RemoveStagedFileAsync(fileName).ConfigureAwait(false);
            throw new Exact25FullBackupException("restore_stage_hash_invalid", "The staged backup does not match the signed artifact hash.");
        }

        return new($"{_sqlServerMountPath}/{fileName}", artifact.ByteLength, observed.ToLowerInvariant());
    }

    private async Task VerifyReadOnlySqlMountAsync(CancellationToken cancellationToken)
    {
        await using var empty = new MemoryStream();
        ProcessResult inspection = await RunAsync(
            ["inspect", "--format", "{\"image\":\"{{.Image}}\",\"mounts\":{{json .Mounts}}}", _sqlServerContainerName], empty, cancellationToken)
            .ConfigureAwait(false);
        if (inspection.ExitCode != 0)
        {
            throw new Exact25FullBackupException("restore_stage_mount_invalid", "The disposable SQL Server mount could not be inspected.");
        }
        try
        {
            DockerContainerEvidence evidence = JsonSerializer.Deserialize<DockerContainerEvidence>(
                inspection.StandardOutput, DockerJson) ??
                throw new JsonException();
            if (!string.Equals(evidence.Image, _sqlServerImageId, StringComparison.Ordinal) ||
                evidence.Mounts is null ||
                !evidence.Mounts.Any(mount => string.Equals(mount.Name, _volumeName, StringComparison.Ordinal) &&
                string.Equals(mount.Destination, _sqlServerMountPath, StringComparison.Ordinal) && !mount.RW))
            {
                throw new Exact25FullBackupException("restore_stage_mount_invalid", "SQL Server must mount the verified staging volume read-only.");
            }
        }
        catch (JsonException)
        {
            throw new Exact25FullBackupException("restore_stage_mount_invalid", "The disposable SQL Server mount evidence is invalid.");
        }
    }

    private async Task RemoveStagedFileAsync(string fileName)
    {
        await using var empty = new MemoryStream();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            _ = await RunAsync(
                ["run", "--rm", "--user", "0:0", "--mount", $"type=volume,source={_volumeName},target=/staging",
                    "--entrypoint", "sh", _stagingImage, "-ceu", "rm -f /staging/$1 /staging/.$1.partial", "sh", fileName],
                empty, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
        }
    }

    private static async Task<ProcessResult> RunAsync(
        IReadOnlyList<string> arguments,
        Stream standardInput,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo("docker")
        {
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
            {
                throw new Exact25FullBackupException("restore_stage_start_failed", "The Docker staging helper could not start.");
            }
            Task<string> stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
            Task<string> stderr = process.StandardError.ReadToEndAsync(cancellationToken);
            await standardInput.CopyToAsync(process.StandardInput.BaseStream, cancellationToken).ConfigureAwait(false);
            await process.StandardInput.DisposeAsync().ConfigureAwait(false);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            return new(process.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
        }
        catch
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception)
            {
            }
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                await process.WaitForExitAsync(cleanup.Token).ConfigureAwait(false);
            }
            catch (Exception)
            {
            }
            throw;
        }
    }

    private static string ValidateMountPath(string value)
    {
        return string.IsNullOrWhiteSpace(value) || value[0] != '/' || value.Contains("..", StringComparison.Ordinal)
            ? throw new ArgumentException("The SQL Server staging mount path is invalid.", nameof(value))
            : value.TrimEnd('/');
    }

    private sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);
    private sealed record DockerContainerEvidence(string? Image, DockerMount[]? Mounts);
    private sealed record DockerMount(string? Name, string? Destination, bool RW);

    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeName();

    [GeneratedRegex("^Full_[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9][A-Za-z0-9._-]{0,127}\\.bak$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeFileName();

    [GeneratedRegex("^sha256:[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex ImageId();

    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256();
}
