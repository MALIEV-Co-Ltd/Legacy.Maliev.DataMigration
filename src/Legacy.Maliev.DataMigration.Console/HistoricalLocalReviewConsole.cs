using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record HistoricalLocalReviewCommandConfiguration(
    string HistoricalPlanPath,
    string HistoricalReceiptPath,
    string HistoricalSchemaPath,
    string TargetConnectionFile,
    string CurrentContainerId,
    int LoopbackPort,
    DeltaTrustedKeyReference HistoricalPlanKey,
    DeltaTrustedKeyReference HistoricalEvidenceKey,
    string OutputPath);

internal interface IHistoricalLocalReviewRuntime
{
    Task<HistoricalCurrentLocalObservation> ObserveAsync(HistoricalLocalReviewCommandConfiguration request,
        string connectionString, DeltaSynchronizationPlan historicalPlan, CancellationToken cancellationToken);

    IDeltaReconciliationInspector CreateInspector(string connectionString, DeltaSynchronizationPlan historicalPlan,
        Exact23DeltaReconciliationResult historicalReceipt, FreshSchemaPlan historicalSchema,
        ReceiptAttestationTrustStore trust, DateTimeOffset nowUtc);
}

internal sealed class DefaultHistoricalLocalReviewRuntime : IHistoricalLocalReviewRuntime
{
    public async Task<HistoricalCurrentLocalObservation> ObserveAsync(HistoricalLocalReviewCommandConfiguration request,
        string connectionString, DeltaSynchronizationPlan historicalPlan, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows() || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_HOST")) ||
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_CONTEXT")) ||
            request.CurrentContainerId.Length != 64 || !request.CurrentContainerId.All(char.IsAsciiHexDigit))
        {
            throw Invalid("delta_historical_local_docker_invalid");
        }
        var settings = new NpgsqlConnectionStringBuilder(connectionString);
        if (settings.Host != "127.0.0.1" || settings.Port != request.LoopbackPort ||
            settings.Database != "postgres" || string.IsNullOrWhiteSpace(settings.Username) ||
            string.IsNullOrWhiteSpace(settings.Password) || !string.IsNullOrWhiteSpace(settings.Options))
        {
            throw Invalid("delta_historical_local_connection_invalid");
        }
        string[] oldGeneration = historicalPlan.TargetGeneration.Split(':');
        if (oldGeneration.Length != 5 || oldGeneration[1].Length != 64 ||
            !oldGeneration[1].All(char.IsAsciiHexDigit) || oldGeneration[1] == request.CurrentContainerId)
        {
            throw Invalid("delta_historical_local_docker_invalid");
        }
        const string volumeName = "legacy-maliev-exact23-postgres-data";
        string activeContainers = await DefaultPairedLocalTemplateObserver.RunDockerAsync(
            ["ps", "-a", "--no-trunc", "--format", "{{.ID}}"], cancellationToken).ConfigureAwait(false);
        RequireContainerInventory(activeContainers, oldGeneration[1], request.CurrentContainerId);
        string containerJson = await DefaultPairedLocalTemplateObserver.RunDockerAsync(
            ["inspect", "--type", "container", request.CurrentContainerId], cancellationToken).ConfigureAwait(false);
        string volumeJson = await DefaultPairedLocalTemplateObserver.RunDockerAsync(
            ["inspect", "--type", "volume", volumeName], cancellationToken).ConfigureAwait(false);
        DockerLocalTargetObservation observed = DockerLocalTargetObservation.Parse(containerJson, volumeJson,
            request.CurrentContainerId, volumeName, request.LoopbackPort, persistent: true);
        string mountpoint = ReadMountpoint(volumeJson);
        RequireMountSource(containerJson, volumeName, mountpoint);
        if (string.IsNullOrWhiteSpace(mountpoint) ||
            observed.VolumeCreatedAtUtc.ToUnixTimeMilliseconds().ToString(
                System.Globalization.CultureInfo.InvariantCulture) != oldGeneration[4])
        {
            throw Invalid("delta_historical_local_volume_invalid");
        }
        settings.Options = "-c default_transaction_read_only=on";
        settings.Pooling = false;
        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand("SELECT system_identifier::text FROM pg_control_system();", connection);
        string identifier = Convert.ToString(await command.ExecuteScalarAsync(cancellationToken)
            .ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
        if (identifier.Length == 0 || !identifier.All(char.IsAsciiDigit))
        {
            throw Invalid("delta_historical_local_system_identifier_invalid");
        }
        string systemHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identifier))).ToLowerInvariant();
        return new(observed.ContainerId, LocalDockerGenerationGuard.ComposeGeneration(observed),
            observed.VolumeName, observed.VolumeCreatedAtUtc, mountpoint, observed.VolumeDestination,
            observed.PgData, systemHash);
    }

    public IDeltaReconciliationInspector CreateInspector(string connectionString,
        DeltaSynchronizationPlan historicalPlan, Exact23DeltaReconciliationResult historicalReceipt,
        FreshSchemaPlan historicalSchema, ReceiptAttestationTrustStore trust, DateTimeOffset nowUtc)
    {
        return new HistoricalPostgreSqlDeltaReconciliationInspector(connectionString, historicalPlan,
            historicalReceipt, historicalSchema, trust, nowUtc);
    }

    private static MigrationConsoleException Invalid(string code)
    {
        return new(code, "The historical LOCAL read-only target observation is invalid.");
    }

    internal static void RequireContainerInventory(string output, string oldId, string currentId)
    {
        string[] ids = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (ids.Length == 0 || ids.Any(id => id.Length != 64 || !id.All(char.IsAsciiHexDigit)) ||
            !ids.Contains(currentId, StringComparer.Ordinal))
        {
            throw Invalid("delta_historical_local_docker_invalid");
        }
        if (ids.Contains(oldId, StringComparer.Ordinal))
        {
            throw Invalid("delta_historical_local_old_container_present");
        }
    }

    internal static string ReadMountpoint(string volumeJson)
    {
        try
        {
            using JsonDocument volumes = JsonDocument.Parse(volumeJson);
            string? mountpoint = volumes.RootElement[0].GetProperty("Mountpoint").GetString();
            return string.IsNullOrWhiteSpace(mountpoint)
                ? throw Invalid("delta_historical_local_volume_invalid")
                : mountpoint;
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or
            IndexOutOfRangeException or KeyNotFoundException)
        {
            throw Invalid("delta_historical_local_volume_invalid");
        }
    }

    internal static void RequireMountSource(string containerJson, string volumeName, string mountpoint)
    {
        try
        {
            using JsonDocument containers = JsonDocument.Parse(containerJson);
            JsonElement[] matching = [.. containers.RootElement[0].GetProperty("Mounts").EnumerateArray()
                .Where(mount => mount.GetProperty("Type").GetString() == "volume" &&
                    mount.GetProperty("Name").GetString() == volumeName)];
            if (matching.Length != 1 || matching[0].GetProperty("Source").GetString() != mountpoint)
            {
                throw Invalid("delta_historical_local_volume_invalid");
            }
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or
            IndexOutOfRangeException or KeyNotFoundException)
        {
            throw Invalid("delta_historical_local_volume_invalid");
        }
    }
}

public static partial class MigrationConsole
{
    internal static Task<int> RunHistoricalLocalReviewForTestsAsync(IReadOnlyList<string> arguments,
        TextWriter output, TextWriter error, Func<string, string?> environment,
        IHistoricalLocalReviewRuntime runtime, CancellationToken cancellationToken)
    {
        ConsoleInvocation invocation = ConsoleInvocation.Parse(arguments);
        return invocation.Command == "review-historical-local-target"
            ? RunHistoricalLocalReviewBoundaryAsync(invocation.ConfigPath, environment, output, error, runtime,
                cancellationToken)
            : Task.FromResult(65);
    }

    private static async Task<int> RunHistoricalLocalReviewBoundaryAsync(string configPath,
        Func<string, string?> environment, TextWriter output, TextWriter error,
        IHistoricalLocalReviewRuntime runtime, CancellationToken cancellationToken)
    {
        try
        {
            if (!string.Equals(environment(DeployEnabledEnvironmentVariable), "false",
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new MigrationConsoleException("delta_deploy_gate_invalid", "Deployment must be disabled.");
            }
            GuardedDeltaCommandPolicy.ValidateCaller("review-historical-local-target",
                environment("LEGACY_MIGRATION_CALLER"));
            MigrationConsoleConfiguration root = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
                configPath, "delta_config_unprotected", cancellationToken).ConfigureAwait(false);
            HistoricalLocalReviewCommandConfiguration request = root.HistoricalLocalReview ??
                throw new MigrationConsoleException("delta_historical_local_config_missing",
                    "A protected historical LOCAL review configuration is required.");
            DeltaSynchronizationPlan plan = await ReadProtectedJsonAsync<DeltaSynchronizationPlan>(
                request.HistoricalPlanPath, "delta_historical_local_plan_unprotected", cancellationToken)
                .ConfigureAwait(false);
            Exact23DeltaReconciliationResult receipt = await ReadProtectedJsonAsync<Exact23DeltaReconciliationResult>(
                request.HistoricalReceiptPath, "delta_historical_local_receipt_unprotected", cancellationToken)
                .ConfigureAwait(false);
            FreshSchemaPlan schema = await ReadProtectedJsonAsync<FreshSchemaPlan>(
                request.HistoricalSchemaPath, "delta_historical_local_schema_unprotected", cancellationToken)
                .ConfigureAwait(false);
            ReceiptAttestationTrustStore trust = await ReadTrustStoreAsync(
                [new(request.HistoricalPlanKey.KeyId, request.HistoricalPlanKey.SubjectPublicKeyInfoPath),
                    new(request.HistoricalEvidenceKey.KeyId, request.HistoricalEvidenceKey.SubjectPublicKeyInfoPath)],
                cancellationToken).ConfigureAwait(false);
            _ = HistoricalPairedLocalEvidenceReviewer.Verify(plan, receipt, trust, DateTimeOffset.UtcNow);
            string connectionString = (await ReadProtectedTextAsync(request.TargetConnectionFile,
                "delta_historical_local_connection_unprotected", cancellationToken).ConfigureAwait(false)).Trim();
            IDeltaReconciliationInspector inspector = runtime.CreateInspector(connectionString, plan, receipt,
                schema, trust, DateTimeOffset.UtcNow);
            HistoricalPairedLocalCurrentTargetReview review = await HistoricalPairedLocalCurrentTargetReviewer
                .CompareAsync(plan, receipt, schema, trust,
                    token => runtime.ObserveAsync(request, connectionString, plan, token), inspector,
                    TimeProvider.System, cancellationToken).ConfigureAwait(false);
            await WriteNewJsonAsync(request.OutputPath, review, cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync("review_historical_local_target_complete").ConfigureAwait(false);
            return 0;
        }
        catch (Exception failure)
        {
            string code = ClassifyDeltaFailure(failure);
            await error.WriteLineAsync(code).ConfigureAwait(false);
            return failure is OperationCanceledException ? 130 : 65;
        }
    }
}
