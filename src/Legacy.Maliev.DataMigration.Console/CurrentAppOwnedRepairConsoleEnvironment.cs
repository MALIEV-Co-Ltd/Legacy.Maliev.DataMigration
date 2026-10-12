using System.Data;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAppOwnedRepairTargetPins(string? DockerContainerId, string? DockerVolume,
    string? DockerImageId, string? DockerImageReference, string HbaPath, string? HbaStatSha256,
    CloudNativePgTargetObserverOptions? CloudOptions, CloudNativePgTargetObservation? CloudObservation);
internal sealed record CurrentAppOwnedRepairArtifact(string Path, string Sha256);
internal sealed record CurrentAppOwnedRepairConfiguration(string BeforeSchemaPath, string AfterSchemaPath,
    string ReviewPath, string AuthorizationPath, string SigningPinsPath, string RunBindingPath,
    string OperatorConnectionPath, string RejectedOrdinaryConnectionPath, string GlobalBeforePath,
    string TargetPinsPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    string ReceiptPrivateKeyPath, CurrentAppOwnedRepairArtifact NativeProof,
    CurrentAppOwnedRepairArtifact RecoveryReview, CurrentAppOwnedRepairArtifact ExactRoleTransitionReview,
    string? AuthorizationPrivateKeyPath = null, string? AuthorizationOutputPath = null);

/// <summary>Closed actual Console composition. Never provisions an operator or rewrites policy.</summary>
internal sealed class CurrentAppOwnedRepairConsoleEnvironment : ICurrentAppOwnedRepairEnvironment, IDisposable
{
    private readonly WindowsLocalRunAuthority _authority;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly CurrentAppOwnedRepairTargetPins _target;
    private readonly string _connection;
    private readonly string _ordinary;
    private readonly CurrentAppOwnedDatabaseSnapshot[] _baseline;
    private readonly FreshSchemaPlan _before;
    private readonly FreshSchemaPlan _after;
    private readonly CurrentAppOwnedRepairScope _scope;
    private readonly CloudNativePgTargetObserver? _cloud;

    internal CurrentAppOwnedRepairConsoleEnvironment(WindowsLocalRunAuthority authority,
        CurrentAppOwnedRepairCustody files, CurrentAppOwnedRepairTargetPins target,
        string connection, string ordinary, CurrentAppOwnedDatabaseSnapshot[] baseline,
        FreshSchemaPlan before, FreshSchemaPlan after, CurrentAppOwnedRepairScope scope)
    {
        _authority = authority; _files = files; _target = target; _connection = connection; _ordinary = ordinary;
        _baseline = baseline; _before = before; _after = after; _scope = scope;
        if (target.CloudOptions is not null)
        {
            _ = files.Read(target.CloudOptions.ServiceAccountTokenFile, sharedReader: true);
            _ = files.Read(target.CloudOptions.ServiceAccountCaFile, sharedReader: true);
            _cloud = CloudNativePgTargetObserver.CreateForCurrentAppOwnedRepair(target.CloudOptions);
        }
        if (baseline.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != baseline.Length ||
            !DatabaseInventory.ActiveDatabases.All(name => baseline.Any(x => x.Database == name)) ||
            CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(baseline)) != scope.GlobalPreservationSha256)
        { throw CurrentAppOwnedRepairPermit.Invalid(); }
    }

    public async Task RequireSourceAsync(string sourceCommitSha, CancellationToken ct)
    {
        _files.Require();
        string actual = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        if (actual != sourceCommitSha) { throw CurrentAppOwnedRepairPermit.Invalid(); }
        _files.Require();
    }

    public async Task RequireResourceAndCustodyAsync(CurrentAppOwnedRepairScope scope, CancellationToken ct)
    {
        _files.Require();
        if (_authority.Binding.ComputeSha256() != scope.RunBindingSha256 || _target.HbaPath != scope.Maintenance.HbaPath ||
            JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(_scope) ||
            CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(_target)) != scope.TargetObservationSha256)
        { throw CurrentAppOwnedRepairPermit.Invalid(); }
        var endpoint = new NpgsqlConnectionStringBuilder(_connection);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 ||
            endpoint.Username != scope.Maintenance.Role || string.IsNullOrWhiteSpace(endpoint.Password) ||
            !string.IsNullOrEmpty(endpoint.Options)) { throw CurrentAppOwnedRepairPermit.Invalid(); }
        if (scope.Target.Kind == DeltaTargetAuthorityKind.LocalAspire)
        {
            if (!OperatingSystem.IsWindows() || _target.CloudOptions is not null || _target.CloudObservation is not null ||
                _target.DockerVolume != "legacy-maliev-exact23-postgres-data" ||
                _target.DockerContainerId is not { Length: 64 } || _target.HbaStatSha256 is null ||
                !CurrentAppOwnedRepairPermit.HashShape(_target.HbaStatSha256) ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_HOST")) ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_CONTEXT")) ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_CONFIG")) ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_TLS_VERIFY")) ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_CERT_PATH")))
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
            string container = await DefaultPairedLocalTemplateObserver.RunDockerAsync(
                ["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "container", _target.DockerContainerId], ct).ConfigureAwait(false);
            string volume = await DefaultPairedLocalTemplateObserver.RunDockerAsync(
                ["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "volume", _target.DockerVolume], ct).ConfigureAwait(false);
            DockerLocalTargetObservation actual = DockerLocalTargetObservation.Parse(container, volume,
                _target.DockerContainerId, _target.DockerVolume, endpoint.Port, persistent: true);
            using JsonDocument metadata = JsonDocument.Parse(container);
            JsonElement item = metadata.RootElement[0];
            if (item.GetProperty("Image").GetString() != _target.DockerImageId ||
                item.GetProperty("Config").GetProperty("Image").GetString() != _target.DockerImageReference ||
                LocalDockerGenerationGuard.ComposeGeneration(actual) != scope.TargetGeneration)
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
            string writers = await DefaultPairedLocalTemplateObserver.RunDockerAsync(
                ["--host", "npipe:////./pipe/docker_engine", "ps", "--no-trunc", "--filter", "volume=" + _target.DockerVolume, "--format", "{{.ID}}"], ct).ConfigureAwait(false);
            string stat = await DefaultPairedLocalTemplateObserver.RunDockerAsync(
                ["--host", "npipe:////./pipe/docker_engine", "exec", _target.DockerContainerId, "env", "TZ=UTC", "LC_ALL=C",
                    "stat", "--printf=%d|%i|%f|%u|%g|%h|%s|%y|%z", "--", _target.HbaPath], ct).ConfigureAwait(false);
            if (writers.Trim() != _target.DockerContainerId ||
                CurrentAppOwnedRepairPermit.Hash(Encoding.UTF8.GetBytes(stat)) != _target.HbaStatSha256)
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
        }
        else
        {
            if (scope.Target.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg || scope.TargetNamespace != "maliev-legacy" ||
                scope.TargetCluster != "legacy-postgres-main" || _cloud is null || _target.CloudObservation is null ||
                _target.DockerContainerId is not null || _target.DockerVolume is not null)
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
            CloudNativePgTargetObservation actual = await _cloud.ObserveAsync("maliev-legacy", "legacy-postgres-main", ct).ConfigureAwait(false);
            if (actual != _target.CloudObservation || "cnpg:" + actual.Uid + ":" + actual.Generation.ToString(CultureInfo.InvariantCulture) != scope.TargetGeneration ||
                !actual.Ready || actual.ReadyInstances != 2 || actual.Instances != 2 ||
                !actual.ConsistentSystemId || !actual.ContinuousArchiving || !actual.LastBackupSucceeded)
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
        }
        var ordinary = new NpgsqlConnectionStringBuilder(_ordinary);
        if (ordinary.Host != endpoint.Host || ordinary.Port != endpoint.Port || ordinary.Username == endpoint.Username ||
            string.IsNullOrWhiteSpace(ordinary.Password) || !string.IsNullOrEmpty(ordinary.Options))
        { throw CurrentAppOwnedRepairPermit.Invalid(); }
        foreach (string name in _baseline.Select(x => x.Database))
        {
            ordinary.Database = name; ordinary.Pooling = false; ordinary.Timeout = 5; ordinary.IncludeErrorDetail = false;
            bool rejected = false;
            try { await using var probe = new NpgsqlConnection(ordinary.ConnectionString); await probe.OpenAsync(ct).ConfigureAwait(false); }
            catch (PostgresException failure) when (failure.SqlState == "28000") { rejected = true; }
            if (!rejected) { throw CurrentAppOwnedRepairPermit.Invalid(); }
        }
        _files.Require();
    }

    public async Task<string> InspectGlobalPreservationAsync(CancellationToken ct)
    {
        _files.Require();
        await using (var inventoryConnection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_connection)
        { Database = "postgres", Pooling = false, IncludeErrorDetail = false, Options = "-c default_transaction_read_only=on" }.ConnectionString))
        {
            await inventoryConnection.OpenAsync(ct).ConfigureAwait(false);
            await using var inventory = new NpgsqlCommand("SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname COLLATE \"C\";", inventoryConnection);
            var names = new List<string>();
            await using NpgsqlDataReader r = await inventory.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false)) { names.Add(r.GetString(0)); }
            if (!names.SequenceEqual(_baseline.Select(x => x.Database).Order(StringComparer.Ordinal), StringComparer.Ordinal))
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
        }
        foreach (CurrentAppOwnedDatabaseSnapshot expected in _baseline)
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_connection)
            { Database = expected.Database, Pooling = false, IncludeErrorDetail = false }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx))
            { _ = await readOnly.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
            await PostgreSqlCurrentAppOwnedEightRepair.RequireInstalledPolicyAsync(connection, tx, _scope, ct).ConfigureAwait(false);
            CurrentAppOwnedDatabaseSnapshot actual = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false);
            IReadOnlySet<string> closure = new HashSet<string>(StringComparer.Ordinal);
            string[] added = [];
            if (CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.CreateEightTables).Contains(expected.Database, StringComparer.Ordinal))
            {
                string[] names = CurrentAppOwnedRepairManifest.NewTables(expected.Database);
                string[] present = [.. actual.Relations.Where(x => x.Schema == "public" && names.Contains(x.Name, StringComparer.Ordinal)).Select(x => x.Name)];
                CurrentAppOwnedCreationState state = CurrentAppOwnedRepairPreflight.ClassifyInventory(expected.Database, present);
                DatabaseSchemaPlan schema = (state == CurrentAppOwnedCreationState.MissingExactSet ? _before : _after)
                    .Databases.Single(x => x.Database == expected.Database);
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                if (await inspector.InspectSchemaAsync(schema, ct).ConfigureAwait(false) != schema.TargetSchemaSha256)
                { throw CurrentAppOwnedRepairPermit.Invalid(); }
                if (state == CurrentAppOwnedCreationState.AlreadyCurrent)
                {
                    closure = await CurrentAppOwnedRepairPreservation.ObserveNewObjectClosureAsync(connection, tx, expected.Database,
                        _scope.Target.Kind == DeltaTargetAuthorityKind.LocalAspire ? "legacy_local" : "postgres", ct).ConfigureAwait(false);
                    added = [.. names.Where(name => !expected.Relations.Any(x => x.Schema == "public" && x.Name == name))];
                }
            }
            CurrentAppOwnedRepairPreservation.RequirePreserved(expected, actual, closure, added);
            await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        _files.Require();
        return _scope.GlobalPreservationSha256;
    }

    public Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken ct)
    {
        return name != Path.GetFileName(name) || !name.EndsWith(".json", StringComparison.Ordinal)
            ? throw CurrentAppOwnedRepairPermit.Invalid()
            : _files.WriteNewAsync(Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, name), payload, ct);
    }
    public void Dispose() { _cloud?.Dispose(); }
}
