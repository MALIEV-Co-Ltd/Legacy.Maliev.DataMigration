using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record DualTargetCapturedDeltaEndpoint(DualTargetCapturedDeltaPurpose Purpose, string ConnectionFile,
    string? DockerContainerId, string? DockerVolumeName, string MaintenancePinsPath, DeltaTrustedKeyReference PlanKey,
    DeltaTrustedKeyReference AuthorizationKey, DeltaTrustedKeyReference EvidenceKey);

// The production transport is a finite owned Console child, never an adopted listener or configured executable.
internal sealed class DualTargetCapturedDeltaObservation : IAsyncDisposable
{
    private readonly CnpgExecTunnelConfiguration _production;
    private readonly DualTargetCapturedDeltaRelay _relay;
    private readonly DualTargetCapturedToolLease _tools;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly string _tunnelPath;
    private readonly string _tunnelHash;
    private bool _disposed;
    private DualTargetCapturedDeltaObservation(CnpgExecTunnelConfiguration production, DualTargetCapturedDeltaRelay relay,
        DualTargetCapturedToolLease tools, CurrentAppOwnedRepairCustody files, string tunnelPath, string tunnelHash)
    { _production = production; _relay = relay; _tools = tools; _files = files; _tunnelPath = tunnelPath; _tunnelHash = tunnelHash; }

    internal static async Task<DualTargetCapturedDeltaObservation> OpenAsync(CurrentAppOwnedRepairCustody files,
        string root, string tunnelPath, string acceptedMain, DateTimeOffset expiry, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || expiry <= DateTimeOffset.UtcNow || expiry - DateTimeOffset.UtcNow > TimeSpan.FromMinutes(15) ||
            Environment.GetEnvironmentVariable("LEGACY_DEPLOY_ENABLED") != "false") { throw Invalid(); }
        CurrentAuthArchiveCapacity.Require(admission: true);
        byte[] bytes = files.Read(tunnelPath, sharedReader: true, maximumBytes: 65536);
        CnpgExecTunnelConfiguration config = MigrationConsole.DecodeV3<CnpgExecTunnelConfiguration>(bytes); CnpgExecTunnel.Validate(config);
        DualTargetCapturedToolLease tools = DualTargetCapturedToolLease.AcquireForFixedObserver();
        try
        {
            DualTargetCapturedDeltaRelay relay = await DualTargetCapturedDeltaRelay.OpenAsync(files, root, tunnelPath, acceptedMain, expiry, ct).ConfigureAwait(false);
            return new(config, relay, tools, files, tunnelPath, Hash(bytes));
        }
        catch { tools.Dispose(); throw; }
    }
    internal Task<DualTargetCapturedTargetObservation> ObserveAsync(DualTargetCapturedDeltaEndpoint endpoint,
        string connectionString, FreshSchemaPlan schema, CancellationToken ct)
    {
        return ObserveAsync(endpoint, connectionString, schema, null, ct);
    }

    internal async Task<DualTargetCapturedTargetObservation> ObserveAsync(DualTargetCapturedDeltaEndpoint endpoint,
        string connectionString, FreshSchemaPlan schema, DualTargetNativeProofClone.ProofLease? proofLease, CancellationToken ct)
    {
        await DualTargetNativeProofClone.ProofLease.RequireEndpointAsync(endpoint, connectionString, schema.SourceCommitSha, proofLease, ct).ConfigureAwait(false);
        if (_disposed || Hash(_files.Read(_tunnelPath, sharedReader: true, maximumBytes: 65536)) != _tunnelHash)
        { throw Invalid(); }
        _relay.RequireLive();
        CurrentAuthArchiveCapacity.Require(admission: false);
        var settings = new NpgsqlConnectionStringBuilder(connectionString);
        if (settings.Host != "127.0.0.1" || settings.Database != "postgres" || string.IsNullOrEmpty(settings.Username) ||
            string.IsNullOrEmpty(settings.Password) || !string.IsNullOrEmpty(settings.Options) || settings.Multiplexing)
        { throw Invalid(); }
        settings.Pooling = false; settings.Options = "-c default_transaction_read_only=on";
        string runtime, generation, id;
        if (endpoint.Purpose == DualTargetCapturedDeltaPurpose.Production)
        {
            if (settings.Port != _production.ListenPort || endpoint.DockerContainerId is not null || endpoint.DockerVolumeName is not null) { throw Invalid(); }
            _relay.RequireLive();
            runtime = JsonSerializer.Serialize(_production);
            generation = "cnpg:" + _production.ClusterUid + ":" + _production.ClusterGeneration.ToString(CultureInfo.InvariantCulture) + ":" + _production.PrimaryPodUid;
            id = "gke://maliev-website/us-central1-a/maliev-legacy/legacy-postgres-main/" + _production.ClusterUid;
        }
        else
        {
            if (endpoint.DockerContainerId is null || endpoint.DockerVolumeName is null ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_HOST")) || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_CONTEXT")))
            { throw Invalid(); }
            bool persistent = endpoint.Purpose == DualTargetCapturedDeltaPurpose.PersistentLocal;
            if (!persistent && endpoint.Purpose is not (DualTargetCapturedDeltaPurpose.ProductionProof or DualTargetCapturedDeltaPurpose.LocalProof)) { throw Invalid(); }
            string container = await _tools.RunDockerAsync(["inspect", "--type", "container", endpoint.DockerContainerId], ct).ConfigureAwait(false);
            string volume = await _tools.RunDockerAsync(["inspect", "--type", "volume", endpoint.DockerVolumeName], ct).ConfigureAwait(false);
            DockerLocalTargetObservation observed = DockerLocalTargetObservation.Parse(container, volume, endpoint.DockerContainerId, endpoint.DockerVolumeName, settings.Port, persistent);
            string consumers = await _tools.RunDockerAsync(["ps", "-aq", "--no-trunc", "--filter", "volume=" + endpoint.DockerVolumeName], ct).ConfigureAwait(false);
            if (!consumers.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).SequenceEqual([endpoint.DockerContainerId], StringComparer.Ordinal)) { throw Invalid(); }
            DockerLocalTargetObservation.RequireCapacity(await _tools.RunDockerAsync(["exec", endpoint.DockerContainerId, "df", "-Pk", observed.PgData], ct).ConfigureAwait(false));
            using JsonDocument inspect = JsonDocument.Parse(container);
            string image = inspect.RootElement[0].GetProperty("Image").GetString() ?? throw Invalid();
            runtime = JsonSerializer.Serialize(new { observed, Image = image, Consumers = new[] { endpoint.DockerContainerId } });
            generation = LocalDockerGenerationGuard.ComposeGeneration(observed);
            id = "aspire://legacy-postgres-main-local/" + (persistent ? "persistent-" : "disposable-") + observed.ContainerId[..12];
        }
        string system, version;
        await using (var connection = new NpgsqlConnection(settings.ConnectionString))
        {
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var query = new NpgsqlCommand("SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),current_setting('server_version_num') FROM pg_control_system();", connection);
            await using var reader = await query.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw Invalid(); }
            system = reader.GetString(0); version = reader.GetString(1);
        }
        var authority = new DeltaTargetAuthority(endpoint.Purpose == DualTargetCapturedDeltaPurpose.Production ?
            DeltaTargetAuthorityKind.ProductionCloudNativePg : DeltaTargetAuthorityKind.LocalAspire, id, system);
        CurrentAppOwnedMaintenancePin maintenance = MigrationConsole.DecodeV3<CurrentAppOwnedMaintenancePin>(
            _files.Read(endpoint.MaintenancePinsPath, sharedReader: true, maximumBytes: 65536));
        await DefaultGuardedDeltaConsoleRuntime.VerifyTargetAuthorityAsync(settings.ConnectionString, authority, ct).ConfigureAwait(false);
        var physical = new PostgreSqlDeltaReconciliationInspector(new(settings.ConnectionString));
        foreach (DatabaseSchemaPlan database in schema.Databases)
        { await physical.ValidateSchemaAsync(database, ct).ConfigureAwait(false); }
        var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
        string inventoryKind = endpoint.Purpose is DualTargetCapturedDeltaPurpose.Production or DualTargetCapturedDeltaPurpose.ProductionProof ?
            DeltaTargetAuthorityKind.ProductionCloudNativePg : DeltaTargetAuthorityKind.LocalAspire;
        string[] names = inventoryKind == DeltaTargetAuthorityKind.ProductionCloudNativePg ? [.. ReviewedProductionRepairInventory.ExportProductionNames()] :
            [.. DatabaseInventory.ActiveDatabases, "Auth", "postgres", "legacy_local"];
        settings.Database = "postgres";
        await using (var inventoryConnection = new NpgsqlConnection(settings.ConnectionString))
        {
            await inventoryConnection.OpenAsync(ct).ConfigureAwait(false);
            await using var inventoryTransaction = await inventoryConnection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ReviewedProductionRepairInventoryObservation.RequireAsync(inventoryConnection, inventoryTransaction, inventoryKind, system, names, ct).ConfigureAwait(false);
            await inventoryTransaction.RollbackAsync(ct).ConfigureAwait(false);
        }
        foreach (string database in names.Order(StringComparer.Ordinal))
        {
            settings.Database = database;
            await using var connection = new NpgsqlConnection(settings.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await DualTargetCapturedDeltaMaintenance.RequireInstalledAsync(connection, tx, authority, maintenance, ct).ConfigureAwait(false);
            hashes.Add(database, await DualTargetCapturedDeltaNativeGuard.CapturePreimageAsync(connection, tx, ct).ConfigureAwait(false));
            await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        _relay.RequireLive();
        settings.Database = "postgres";
        await DefaultGuardedDeltaConsoleRuntime.VerifyTargetAuthorityAsync(settings.ConnectionString, authority, ct).ConfigureAwait(false);
        if (endpoint.Purpose != DualTargetCapturedDeltaPurpose.Production)
        {
            string container = await _tools.RunDockerAsync(["inspect", "--type", "container", endpoint.DockerContainerId!], ct).ConfigureAwait(false);
            string volume = await _tools.RunDockerAsync(["inspect", "--type", "volume", endpoint.DockerVolumeName!], ct).ConfigureAwait(false);
            var observed = DockerLocalTargetObservation.Parse(container, volume, endpoint.DockerContainerId!, endpoint.DockerVolumeName!, settings.Port,
                endpoint.Purpose == DualTargetCapturedDeltaPurpose.PersistentLocal);
            string consumers = await _tools.RunDockerAsync(["ps", "-aq", "--no-trunc", "--filter", "volume=" + endpoint.DockerVolumeName], ct).ConfigureAwait(false);
            if (!consumers.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).SequenceEqual([endpoint.DockerContainerId!], StringComparer.Ordinal)) { throw Invalid(); }
            using JsonDocument inspect = JsonDocument.Parse(container);
            string image = inspect.RootElement[0].GetProperty("Image").GetString() ?? throw Invalid();
            if (runtime != JsonSerializer.Serialize(new { observed, Image = image, Consumers = new[] { endpoint.DockerContainerId } })) { throw Invalid(); }
        }
        await DualTargetNativeProofClone.ProofLease.RequireEndpointAsync(endpoint, connectionString, schema.SourceCommitSha, proofLease, ct).ConfigureAwait(false);
        _files.Require();
        return new(Hash(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { endpoint.Purpose, runtime, system, version, maintenance }))), authority, generation, maintenance, hashes);
    }

    internal IReadOnlyList<CurrentAuthTypedProcessFrame> ToolFrames => _tools.Frames;
    internal CancellationToken OperationToken => _relay.OperationToken;
    internal void RequireLive() { _relay.RequireLive(); _files.Require(); }
    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true;
        try { await _relay.DisposeAsync().ConfigureAwait(false); }
        finally { _tools.Dispose(); }
    }
    private static string Hash(byte[] value)
    {
        return Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
    }

    private static MigrationConsoleException Invalid()
    {
        return new("dual_target_native_observation_invalid", "The fixed target runtime could not be independently observed.");
    }
}
