using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed class DefaultPairedLocalTemplateObserver : IPairedLocalTemplateObserver
{
    public async Task<ObservedPairedLocalTarget> ObserveAsync(PairedLocalTemplateTarget candidate,
        string connectionString, FreshSchemaPlan schema, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows() || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_HOST")) ||
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_CONTEXT")))
        {
            throw Invalid("delta_paired_template_local_docker_required");
        }
        if (candidate.DockerContainerId.Length != 64 || !candidate.DockerContainerId.All(char.IsAsciiHexDigit) ||
            (candidate.DockerVolumeName != "legacy-maliev-exact23-postgres-data" &&
             !candidate.DockerVolumeName.StartsWith("legacy-delta-proof-", StringComparison.Ordinal)) ||
            candidate.DockerVolumeName.Length > 128 ||
            !candidate.DockerVolumeName.All(value => char.IsAsciiLetterOrDigit(value) || value is '-'))
        {
            throw Invalid("delta_paired_template_docker_claim_invalid");
        }
        var settings = new NpgsqlConnectionStringBuilder(connectionString);
        if (settings.Host != "127.0.0.1" || settings.Port is < 1 or > 65535 ||
            string.IsNullOrWhiteSpace(settings.Username) || string.IsNullOrWhiteSpace(settings.Password) ||
            !string.IsNullOrEmpty(settings.Options) || settings.Database != "postgres")
        {
            throw Invalid("delta_paired_template_connection_invalid");
        }
        string containerJson = await RunDockerAsync(["inspect", "--type", "container", candidate.DockerContainerId],
            cancellationToken).ConfigureAwait(false);
        string volumeJson = await RunDockerAsync(["inspect", "--type", "volume", candidate.DockerVolumeName],
            cancellationToken).ConfigureAwait(false);
        DockerLocalTargetObservation runtime = DockerLocalTargetObservation.Parse(containerJson, volumeJson,
            candidate.DockerContainerId, candidate.DockerVolumeName, settings.Port);
        string capacityOutput = await RunDockerAsync(["exec", candidate.DockerContainerId,
            "df", "-Pk", runtime.PgData], cancellationToken).ConfigureAwait(false);
        DockerLocalTargetObservation.RequireCapacity(capacityOutput);
        settings.Options = "-c default_transaction_read_only=on";
        settings.Pooling = false;
        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var systemCommand = new NpgsqlCommand("SELECT system_identifier::text FROM pg_control_system();", connection);
        string identifier = Convert.ToString(await systemCommand.ExecuteScalarAsync(cancellationToken)
            .ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
        if (identifier.Length == 0 || !identifier.All(char.IsAsciiDigit))
        {
            throw Invalid("delta_paired_template_system_identifier_invalid");
        }
        string systemHash = Hash(identifier);
        string label = candidate.DockerVolumeName == "legacy-maliev-exact23-postgres-data" ?
            "persistent-" : "disposable-";
        var authority = new DeltaTargetAuthority(DeltaTargetAuthorityKind.LocalAspire,
            "aspire://legacy-postgres-main-local/" + label + candidate.DockerContainerId[..12], systemHash);
        await DefaultGuardedDeltaConsoleRuntime.VerifyTargetAuthorityAsync(settings.ConnectionString,
            authority, cancellationToken).ConfigureAwait(false);
        var inspector = new PostgreSqlDeltaReconciliationInspector(new(settings.ConnectionString));
        foreach (DatabaseSchemaPlan database in schema.Databases)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (database.Database == "Quotation")
            {
                await inspector.ValidateQuotationTransitionSchemaAsync(database, cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                await inspector.ValidateSchemaAsync(database, cancellationToken).ConfigureAwait(false);
            }
        }
        string containerAfter = await RunDockerAsync(["inspect", "--type", "container", candidate.DockerContainerId],
            cancellationToken).ConfigureAwait(false);
        string volumeAfter = await RunDockerAsync(["inspect", "--type", "volume", candidate.DockerVolumeName],
            cancellationToken).ConfigureAwait(false);
        DockerLocalTargetObservation observedAfter = DockerLocalTargetObservation.Parse(containerAfter, volumeAfter,
            candidate.DockerContainerId, candidate.DockerVolumeName, settings.Port);
        if (runtime != observedAfter)
        {
            throw Invalid("delta_paired_template_runtime_drift");
        }
        DockerLocalTargetObservation.RequireCapacity(await RunDockerAsync(["exec", candidate.DockerContainerId,
            "df", "-Pk", runtime.PgData], cancellationToken).ConfigureAwait(false));
        await DefaultGuardedDeltaConsoleRuntime.VerifyTargetAuthorityAsync(settings.ConnectionString,
            authority, cancellationToken).ConfigureAwait(false);
        DateTimeOffset observedAt = DateTimeOffset.UtcNow;
        string observation = string.Join('\n', "paired-local-template-observation-v1", runtime.ContainerId,
            runtime.ContainerCreatedAtUtc.ToString("O"), runtime.ContainerStartedAtUtc.ToString("O"),
            runtime.VolumeName, runtime.VolumeCreatedAtUtc.ToString("O"), runtime.VolumeDestination,
            settings.Port.ToString(System.Globalization.CultureInfo.InvariantCulture), systemHash,
            SchemaPlanCanonicalizer.ComputeSha256(schema), observedAt.ToString("O"));
        return new(runtime.ContainerId, runtime.VolumeName, settings.Port,
            LocalDockerGenerationGuard.ComposeGeneration(runtime), Hash(observation), authority, observedAt);
    }

    internal static async Task<string> RunDockerAsync(IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo("docker")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };
        process.StartInfo.ArgumentList.Add("--context");
        process.StartInfo.ArgumentList.Add("default");
        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }
        using (process)
        {
            if (!process.Start())
            {
                throw Invalid("delta_paired_template_docker_unavailable");
            }
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            Task<string> stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
            Task<string> stderr = process.StandardError.ReadToEndAsync(timeout.Token);
            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
                string content = await stdout.ConfigureAwait(false);
                _ = await stderr.ConfigureAwait(false);
                return process.ExitCode != 0 || content.Length is 0 or > 2_000_000
                    ? throw Invalid("delta_paired_template_docker_inspect_failed")
                    : content;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                process.Kill(entireProcessTree: true);
                throw Invalid("delta_paired_template_docker_timeout");
            }
        }
    }

    private static string Hash(string value)
    {
        return Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    private static MigrationConsoleException Invalid(string code)
    {
        return new(code,
        "The independently observed LOCAL Docker/PostgreSQL target does not match the paired template claim.");
    }
}

internal sealed partial record DockerLocalTargetObservation(string ContainerId, string VolumeName,
    string VolumeDestination, string PgData, DateTimeOffset ContainerCreatedAtUtc, DateTimeOffset ContainerStartedAtUtc,
    DateTimeOffset VolumeCreatedAtUtc)
{
    internal static void RequireCapacity(string dfOutput)
    {
        string[] lines = dfOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        string[] fields = lines.Length >= 2 ? MyRegex().Split(lines[^1].Trim()) : [];
        // Match the reviewed production preflight's 10 GiB available-space floor.
        if (fields.Length < 6 ||
            !long.TryParse(fields[3], System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out long availableKiB) ||
            availableKiB < 10_485_760)
        {
            throw new MigrationConsoleException("delta_paired_template_capacity_insufficient",
                "The LOCAL target does not have the reviewed minimum free capacity.");
        }
    }

    internal static DockerLocalTargetObservation Parse(string containerJson, string volumeJson,
        string claimedContainerId, string claimedVolumeName, int claimedLoopbackPort)
    {
        try
        {
            using JsonDocument containers = JsonDocument.Parse(containerJson);
            using JsonDocument volumes = JsonDocument.Parse(volumeJson);
            if (containers.RootElement.ValueKind != JsonValueKind.Array ||
                containers.RootElement.GetArrayLength() != 1 ||
                volumes.RootElement.ValueKind != JsonValueKind.Array ||
                volumes.RootElement.GetArrayLength() != 1)
            {
                throw Invalid();
            }
            JsonElement container = containers.RootElement[0];
            JsonElement volume = volumes.RootElement[0];
            string id = container.GetProperty("Id").GetString() ?? string.Empty;
            string name = volume.GetProperty("Name").GetString() ?? string.Empty;
            if (id != claimedContainerId || name != claimedVolumeName ||
                !container.GetProperty("State").GetProperty("Running").GetBoolean() ||
                volume.GetProperty("Driver").GetString() != "local")
            {
                throw Invalid();
            }
            string? pgData = container.GetProperty("Config").GetProperty("Env").EnumerateArray()
                .Select(item => item.GetString()).SingleOrDefault(item => item?.StartsWith("PGDATA=", StringComparison.Ordinal) == true)?[7..];
            JsonElement[] mounts = [.. container.GetProperty("Mounts").EnumerateArray()
                .Where(item => item.GetProperty("Type").GetString() == "volume" &&
                    item.GetProperty("Name").GetString() == name)];
            if (mounts.Length != 1 || string.IsNullOrWhiteSpace(pgData))
            {
                throw Invalid();
            }
            string destination = mounts[0].GetProperty("Destination").GetString() ?? string.Empty;
            if (!mounts[0].GetProperty("RW").GetBoolean() ||
                (!pgData.StartsWith(destination.TrimEnd('/') + "/", StringComparison.Ordinal) &&
                pgData != destination))
            {
                throw Invalid();
            }
            if (name.StartsWith("legacy-delta-proof-", StringComparison.Ordinal) &&
                container.GetProperty("Name").GetString() != "/" + name)
            {
                throw Invalid();
            }
            if (name == "legacy-maliev-exact23-postgres-data" &&
                !(container.GetProperty("Name").GetString() ?? string.Empty)
                    .StartsWith("/legacy-postgres-main-", StringComparison.Ordinal))
            {
                throw Invalid();
            }
            JsonElement ports = container.GetProperty("NetworkSettings").GetProperty("Ports")
                .GetProperty("5432/tcp");
            if (ports.ValueKind != JsonValueKind.Array || ports.GetArrayLength() != 1 ||
                ports[0].GetProperty("HostIp").GetString() != "127.0.0.1" ||
                ports[0].GetProperty("HostPort").GetString() !=
                    claimedLoopbackPort.ToString(System.Globalization.CultureInfo.InvariantCulture))
            {
                throw Invalid();
            }
            DateTimeOffset created = DateTimeOffset.Parse(container.GetProperty("Created").GetString()!,
                System.Globalization.CultureInfo.InvariantCulture);
            DateTimeOffset started = DateTimeOffset.Parse(container.GetProperty("State").GetProperty("StartedAt")
                .GetString()!, System.Globalization.CultureInfo.InvariantCulture);
            DateTimeOffset volumeCreated = DateTimeOffset.Parse(volume.GetProperty("CreatedAt").GetString()!,
                System.Globalization.CultureInfo.InvariantCulture);
            return created > started || volumeCreated > started || started > DateTimeOffset.UtcNow.AddMinutes(1)
                ? throw Invalid()
                : new(id, name, destination, pgData, created.ToUniversalTime(), started.ToUniversalTime(),
                volumeCreated.ToUniversalTime());
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or
            KeyNotFoundException or ArgumentException or FormatException)
        {
            throw Invalid();
        }
    }

    private static MigrationConsoleException Invalid()
    {
        return new("delta_paired_template_docker_observation_invalid",
        "The independently observed Docker container, named volume, or loopback binding is invalid.");
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"\s+")]
    private static partial System.Text.RegularExpressions.Regex MyRegex();
}
