using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Re-observes the projected persistent LOCAL container before each atomic database transaction.</summary>
internal static class LocalDockerGenerationGuard
{
    private const string PersistentVolume = "legacy-maliev-exact23-postgres-data";

    internal static string ComposeGeneration(DockerLocalTargetObservation observed)
    {
        return string.Join(':', "docker", observed.ContainerId,
            observed.ContainerCreatedAtUtc.ToUnixTimeMilliseconds(),
            observed.ContainerStartedAtUtc.ToUnixTimeMilliseconds(),
            observed.VolumeCreatedAtUtc.ToUnixTimeMilliseconds());
    }

    internal static bool IsGenerationFor(string? generation, string id)
    {
        string[] parts = generation?.Split(':') ?? [];
        return parts.Length == 5 && parts[0] == "docker" && parts[1] == id &&
            parts.Skip(2).All(part => long.TryParse(part,
                System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture,
                out long milliseconds) && milliseconds > 0);
    }

    internal static string RequireContainerId(DeltaSynchronizationPlan plan)
    {
        DeltaTargetAuthority authority = plan.TargetAuthority ??
            throw Invalid("delta_paired_local_docker_generation_required");
        if (plan.SchemaVersion != "1.4" ||
            !DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(authority) ||
            plan.TargetGeneration is null ||
            !plan.TargetGeneration.StartsWith("docker:", StringComparison.Ordinal))
        {
            throw Invalid("delta_paired_local_docker_generation_required");
        }
        string id = plan.TargetGeneration.Split(':').ElementAtOrDefault(1) ?? string.Empty;
        return id.Length != 64 || !id.All(char.IsAsciiHexDigit) ||
            !IsGenerationFor(plan.TargetGeneration, id) ||
            authority.AuthorityId !=
                "aspire://legacy-postgres-main-local/persistent-" + id[..12]
            ? throw Invalid("delta_paired_local_docker_generation_invalid")
            : id;
    }

    internal static async Task VerifyAsync(DeltaSynchronizationPlan plan, string connectionString,
        CancellationToken cancellationToken)
    {
        string id = RequireContainerId(plan);
        DeltaTargetAuthority authority = plan.TargetAuthority!;
        if (!OperatingSystem.IsWindows() ||
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_HOST")) ||
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_CONTEXT")))
        {
            throw Invalid("delta_paired_local_docker_runtime_unavailable");
        }
        var settings = new NpgsqlConnectionStringBuilder(connectionString);
        if (settings.Host != "127.0.0.1" || settings.Port is < 1 or > 65535 ||
            settings.Database != "postgres" || string.IsNullOrEmpty(settings.Username) ||
            string.IsNullOrEmpty(settings.Password) || !string.IsNullOrEmpty(settings.Options))
        {
            throw Invalid("delta_paired_local_docker_connection_invalid");
        }
        string containerJson = await DefaultPairedLocalTemplateObserver.RunDockerAsync(
            ["inspect", "--type", "container", id], cancellationToken).ConfigureAwait(false);
        string volumeJson = await DefaultPairedLocalTemplateObserver.RunDockerAsync(
            ["inspect", "--type", "volume", PersistentVolume], cancellationToken).ConfigureAwait(false);
        DockerLocalTargetObservation observed = DockerLocalTargetObservation.Parse(containerJson, volumeJson,
            id, PersistentVolume, settings.Port);
        if (ComposeGeneration(observed) != plan.TargetGeneration)
        {
            throw Invalid("delta_paired_local_docker_generation_drift");
        }
        string capacity = await DefaultPairedLocalTemplateObserver.RunDockerAsync(
            ["exec", id, "df", "-Pk", observed.PgData], cancellationToken).ConfigureAwait(false);
        DockerLocalTargetObservation.RequireCapacity(capacity);
        settings.Options = "-c default_transaction_read_only=on";
        settings.Pooling = false;
        await DefaultGuardedDeltaConsoleRuntime.VerifyTargetAuthorityAsync(settings.ConnectionString,
            authority, cancellationToken).ConfigureAwait(false);
    }

    private static DeltaExecutionException Invalid(string code)
    {
        return new(code, "The signed LOCAL transition plan is not bound to the current Docker generation.");
    }
}
