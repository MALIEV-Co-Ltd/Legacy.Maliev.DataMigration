using System.Data;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Closed actual Console composition. Never provisions an operator or rewrites policy.</summary>
internal sealed class CurrentAppOwnedRetained31ConsoleEnvironment : ICurrentAppOwnedRetained31Environment, IDisposable
{
    private readonly WindowsLocalRunAuthority _authority;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly CurrentAppOwnedRepairTargetPins _target;
    private readonly string _connection;
    private readonly string _ordinary;
    private readonly CurrentAppOwnedDatabaseSnapshot[] _baseline;
    private readonly FreshSchemaPlan _before;
    private readonly FreshSchemaPlan _after;
    private readonly CurrentAppOwnedRetained31Scope _scope;
    private readonly CloudNativePgTargetObserver? _cloud;
    private readonly CurrentAppOwnedRetained31Contract _contract;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly CurrentAppOwnedRetained31SigningPins _pins;
    private readonly string _authorizationSha256;
    private readonly Dictionary<string, byte[]> _retainedEvidence = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _expectedHashes;
    private readonly Dictionary<string, CurrentAppOwnedRetained31Observation> _nativeBefore = new(StringComparer.Ordinal);
    private readonly HashSet<string> _completed = new(StringComparer.Ordinal);
    private bool _reserved;

    internal CurrentAppOwnedRetained31ConsoleEnvironment(WindowsLocalRunAuthority authority,
        CurrentAppOwnedRepairCustody files, CurrentAppOwnedRepairTargetPins target,
        string connection, string ordinary, CurrentAppOwnedDatabaseSnapshot[] baseline,
        FreshSchemaPlan before, FreshSchemaPlan after, CurrentAppOwnedRetained31Scope scope,
        IReceiptAttestationTrustStore trust, CurrentAppOwnedRetained31SigningPins pins, string authorizationSha256)
    {
        _authority = authority; _files = files; _target = target; _connection = connection; _ordinary = ordinary;
        _baseline = baseline.Select(x => x with { Catalog = x.Catalog.ToArray(), Relations = x.Relations.ToArray(), Sequences = x.Sequences.ToArray() }).ToArray();
        _before = JsonSerializer.Deserialize<FreshSchemaPlan>(JsonSerializer.SerializeToUtf8Bytes(before))!;
        _after = JsonSerializer.Deserialize<FreshSchemaPlan>(JsonSerializer.SerializeToUtf8Bytes(after))!;
        _scope = scope with { BeforeDatabaseSha256 = new Dictionary<string, string>(scope.BeforeDatabaseSha256, StringComparer.Ordinal) };
        _contract = CurrentAppOwnedRetained31Contract.Create(_before, _after, scope.SourceCommitSha, DateTimeOffset.UtcNow);
        _trust = trust; _pins = pins; _authorizationSha256 = authorizationSha256;
        _expectedHashes = new Dictionary<string, string>(scope.BeforeDatabaseSha256, StringComparer.Ordinal);
        if (target.CloudOptions is not null)
        {
            _ = files.Read(target.CloudOptions.ServiceAccountTokenFile, sharedReader: true);
            _ = files.Read(target.CloudOptions.ServiceAccountCaFile, sharedReader: true);
            _cloud = CloudNativePgTargetObserver.CreateForCurrentAppOwnedRepair(target.CloudOptions);
        }
        if (baseline.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != baseline.Length ||
            !DatabaseInventory.ActiveDatabases.All(name => baseline.Any(x => x.Database == name)) ||
            CurrentAppOwnedSnapshotSerialization.Sha256(_baseline) != scope.GlobalPreservationSha256 ||
            !CurrentAppOwnedRepairPermit.HashShape(authorizationSha256) ||
            !baseline.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(_expectedHashes.Keys.Order(StringComparer.Ordinal)) ||
            baseline.Any(x => x.Sha256 != _expectedHashes[x.Database]))
        { throw CurrentAppOwnedRetained31Permit.Invalid(); }
    }

    public async Task RequireSourceAsync(string sourceCommitSha, CancellationToken ct)
    {
        _files.Require();
        RequireEvidenceInventory();
        string actual = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        if (actual != sourceCommitSha) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        _files.Require();
    }

    public async Task RequireResourceAndCustodyAsync(CurrentAppOwnedRetained31Scope scope, CancellationToken ct)
    {
        _files.Require();
        RequireEvidenceInventory();
        if (_authority.Binding.ComputeSha256() != scope.RunBindingSha256 || _target.HbaPath != scope.Maintenance.HbaPath ||
            JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(_scope) ||
            CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(_target)) != scope.TargetObservationSha256)
        { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        var endpoint = new NpgsqlConnectionStringBuilder(_connection);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 ||
            endpoint.Username != scope.Maintenance.Role || string.IsNullOrWhiteSpace(endpoint.Password) ||
            !string.IsNullOrEmpty(endpoint.Options)) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        if (scope.Target.Kind == DeltaTargetAuthorityKind.LocalAspire)
        {
            if (!OperatingSystem.IsWindows() || _target.CloudOptions is not null || _target.CloudObservation is not null ||
                _target.DockerContainerId is not { Length: 64 } || _target.HbaStatSha256 is null ||
                !CurrentAppOwnedRepairPermit.HashShape(_target.HbaStatSha256) ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_HOST")) ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_CONTEXT")) ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_CONFIG")) ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_TLS_VERIFY")) ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_CERT_PATH")))
            { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            bool persistent = CurrentAppOwnedRetained31LocalTarget.RequireClaim(scope.Target, scope.OperationId,
                scope.RunBindingSha256, _target);
            string volumeName = _target.DockerVolume ?? throw CurrentAppOwnedRetained31Permit.Invalid();
            string container = await ObserveDockerAsync(
                ["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "container", _target.DockerContainerId], ct).ConfigureAwait(false);
            string volume = await ObserveDockerAsync(
                ["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "volume", volumeName], ct).ConfigureAwait(false);
            DockerLocalTargetObservation actual = DockerLocalTargetObservation.Parse(container, volume,
                _target.DockerContainerId, volumeName, endpoint.Port, persistent);
            using JsonDocument metadata = JsonDocument.Parse(container);
            JsonElement item = metadata.RootElement[0];
            if (!persistent)
            {
                using JsonDocument volumeMetadata = JsonDocument.Parse(volume);
                CurrentAppOwnedRetained31LocalTarget.RequireDisposableMetadata(item, volumeMetadata.RootElement[0],
                    scope.OperationId, scope.RunBindingSha256, DateTimeOffset.UtcNow);
            }
            if (item.GetProperty("Image").GetString() != _target.DockerImageId ||
                item.GetProperty("Config").GetProperty("Image").GetString() != _target.DockerImageReference ||
                LocalDockerGenerationGuard.ComposeGeneration(actual) != scope.TargetGeneration)
            { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            string[] inventoryArguments = persistent
                ? ["--host", "npipe:////./pipe/docker_engine", "ps", "--no-trunc", "--filter", "volume=" + _target.DockerVolume, "--format", "{{.ID}}"]
                : ["--host", "npipe:////./pipe/docker_engine", "ps", "--all", "--no-trunc", "--filter", "volume=" + _target.DockerVolume, "--format", "{{.ID}}"];
            string writers = await ObserveDockerAsync(inventoryArguments, ct).ConfigureAwait(false);
            if (!persistent) { CurrentAppOwnedRetained31LocalTarget.RequireVolumeConsumers(writers, _target.DockerContainerId); }
            string stat = await ObserveDockerAsync(
                ["--host", "npipe:////./pipe/docker_engine", "exec", _target.DockerContainerId, "env", "TZ=UTC", "LC_ALL=C",
                    "stat", "--printf=%d|%i|%f|%u|%g|%h|%s|%y|%z", "--", _target.HbaPath], ct).ConfigureAwait(false);
            if (writers.Trim() != _target.DockerContainerId ||
                CurrentAppOwnedRepairPermit.Hash(Encoding.UTF8.GetBytes(stat)) != _target.HbaStatSha256)
            { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        }
        else
        {
            if (scope.Target.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg || scope.TargetNamespace != "maliev-legacy" ||
                scope.TargetCluster != "legacy-postgres-main" || _cloud is null || _target.CloudObservation is null ||
                _target.DockerContainerId is not null || _target.DockerVolume is not null)
            { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            CloudNativePgTargetObservation actual = await _cloud.ObserveAsync("maliev-legacy", "legacy-postgres-main", ct).ConfigureAwait(false);
            if (!actual.SameRuntimeTarget(_target.CloudObservation) || "cnpg:" + actual.Uid + ":" + actual.Generation.ToString(CultureInfo.InvariantCulture) != scope.TargetGeneration ||
                !actual.Ready || actual.ReadyInstances != 2 || actual.Instances != 2 ||
                !actual.ConsistentSystemId || !actual.ContinuousArchiving || !actual.LastBackupSucceeded)
            { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        }
        var ordinary = new NpgsqlConnectionStringBuilder(_ordinary);
        if (ordinary.Host != endpoint.Host || ordinary.Port != endpoint.Port || ordinary.Username == endpoint.Username ||
            string.IsNullOrWhiteSpace(ordinary.Password) || !string.IsNullOrEmpty(ordinary.Options))
        { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        foreach (string name in _baseline.Select(x => x.Database))
        {
            ordinary.Database = name; ordinary.Pooling = false; ordinary.Timeout = 5; ordinary.IncludeErrorDetail = false;
            bool rejected = false;
            try { await using var probe = new NpgsqlConnection(ordinary.ConnectionString); await probe.OpenAsync(ct).ConfigureAwait(false); }
            catch (PostgresException failure) when (failure.SqlState == "28000") { rejected = true; }
            if (!rejected) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        }
        _files.Require();
        RequireEvidenceInventory();
    }

    public async Task<string> InspectGlobalPreservationAsync(CancellationToken ct)
    {
        _files.Require(); RequireEvidenceInventory();
        await using (var inventoryConnection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_connection)
        { Database = "postgres", Pooling = false, IncludeErrorDetail = false, Options = "-c default_transaction_read_only=on" }.ConnectionString))
        {
            await inventoryConnection.OpenAsync(ct).ConfigureAwait(false);
            await using var inventory = new NpgsqlCommand("SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname COLLATE \"C\";", inventoryConnection);
            var names = new List<string>();
            await using NpgsqlDataReader reader = await inventory.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false)) { names.Add(reader.GetString(0)); }
            if (!names.SequenceEqual(_expectedHashes.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal))
            { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        }
        var pool = new CurrentAppOwnedSnapshotInternPool();
        foreach (CurrentAppOwnedDatabaseSnapshot expected in _baseline)
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_connection)
            { Database = expected.Database, Pooling = false, IncludeErrorDetail = false, Timeout = 5, CommandTimeout = 30 }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await SetReadOnlyAsync(connection, tx, ct).ConfigureAwait(false);
            await PostgreSqlCurrentAppOwnedRetained31Repair.RequireInstalledPolicyAsync(connection, tx, _scope, ct).ConfigureAwait(false);
            bool affected = CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations)
                .Contains(expected.Database, StringComparer.Ordinal);
            CurrentAppOwnedDatabaseSnapshot actual;
            if (affected)
            {
                CurrentAppOwnedRetained31Observation observed = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false);
                actual = pool.Intern(observed.Snapshot);
                observed = observed with { Snapshot = actual };
                if (_completed.Contains(expected.Database))
                {
                    if (!_nativeBefore.TryGetValue(expected.Database, out CurrentAppOwnedRetained31Observation? original))
                    { throw CurrentAppOwnedRetained31Permit.Invalid(); }
                    CurrentAppOwnedRetained31Preservation.RequirePreserved(original, observed, _before, _after, DateTimeOffset.UtcNow);
                }
                else
                {
                    CurrentAppOwnedRetained31Preservation.RequireBefore(observed, _before, _after, DateTimeOffset.UtcNow);
                    if (actual.Sha256 != expected.Sha256) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
                    _nativeBefore.TryAdd(expected.Database, observed);
                }
            }
            else { actual = pool.Intern(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false)); }
            if (actual.Sha256 != _expectedHashes[expected.Database]) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            if (DatabaseInventory.ActiveDatabases.Contains(expected.Database, StringComparer.Ordinal))
            {
                DatabaseSchemaPlan physical = _completed.Contains(expected.Database)
                    ? _contract.AfterForDatabase(expected.Database) : _contract.BeforeForDatabase(expected.Database);
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                if (await inspector.InspectSchemaAsync(physical, ct).ConfigureAwait(false) != physical.TargetSchemaSha256)
                { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            }
            await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        _files.Require(); RequireEvidenceInventory();
        return _scope.GlobalPreservationSha256;
    }

    public Task RequireFreshOperationAsync(CurrentAppOwnedRetained31Scope scope, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); _files.Require();
        if (_reserved || JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(_scope) || ObserveOperationNames().Length != 0)
        { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        return Task.CompletedTask;
    }

    public async Task ReserveFreshOperationAsync(CurrentAppOwnedRetained31Scope scope, string authorizationSha256, CancellationToken ct)
    {
        await RequireFreshOperationAsync(scope, ct).ConfigureAwait(false);
        if (authorizationSha256 != _authorizationSha256) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        string name = $"{scope.OperationId:D}-retained31-operation-start.json";
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new { Kind = "current-app-owned-retained31-operation-start-v1",
            scope.OperationId, ScopeSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(scope), AuthorizationSha256 = authorizationSha256 });
        await RetainNewEvidenceAsync(name, bytes, ct).ConfigureAwait(false);
        RequireEvidenceInventory(); _reserved = true;
    }

    public async Task ObserveCommittedDatabaseAsync(CurrentAppOwnedRetained31Receipt prepared, CancellationToken ct)
    {
        _files.Require(); RequireEvidenceInventory();
        PostgreSqlCurrentAppOwnedRetained31Repair.RequireReceipt(prepared, _scope, _authorizationSha256, _trust, _pins);
        string name = $"{prepared.OperationId:D}-{prepared.Database}-prepared.json";
        if (!_reserved || prepared.Classification != CurrentAppOwnedCommitClassification.Prepared || prepared.AfterSha256 is null ||
            _completed.Contains(prepared.Database) || !_nativeBefore.TryGetValue(prepared.Database, out CurrentAppOwnedRetained31Observation? before) ||
            !_retainedEvidence.TryGetValue(name, out byte[]? held) || !held.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(prepared)))
        { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_connection)
        { Database = prepared.Database, Pooling = false, IncludeErrorDetail = false, Timeout = 5, CommandTimeout = 30 }.ConnectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
        await SetReadOnlyAsync(connection, tx, ct).ConfigureAwait(false);
        await PostgreSqlCurrentAppOwnedRetained31Repair.RequireInstalledPolicyAsync(connection, tx, _scope, ct).ConfigureAwait(false);
        CurrentAppOwnedRetained31Observation actual = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false);
        CurrentAppOwnedRetained31Preservation.RequirePreserved(before, actual, _before, _after, DateTimeOffset.UtcNow);
        if (actual.Snapshot.Sha256 != prepared.AfterSha256) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
        DatabaseSchemaPlan physical = _contract.AfterForDatabase(prepared.Database);
        if (await inspector.InspectSchemaAsync(physical, ct).ConfigureAwait(false) != physical.TargetSchemaSha256)
        { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        await tx.RollbackAsync(ct).ConfigureAwait(false);
        _files.Require(); RequireEvidenceInventory();
        _expectedHashes[prepared.Database] = prepared.AfterSha256;
        if (!_completed.Add(prepared.Database)) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
    }

    private static async Task SetReadOnlyAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken ct)
    {
        await using var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx);
        _ = await readOnly.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private string[] ObserveOperationNames()
    {
        string prefix = $"{_scope.OperationId:D}-";
        return Directory.EnumerateFileSystemEntries(_authority.Binding.ArtifactRootCanonicalPath)
            .Select(Path.GetFileName).Where(name => name is not null && name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            .Select(name => name!).Order(StringComparer.Ordinal).ToArray();
    }

    private void RequireEvidenceInventory()
    {
        if (!ObserveOperationNames().SequenceEqual(_retainedEvidence.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal))
        { throw CurrentAppOwnedRetained31Permit.Invalid(); }
    }
    public async Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken ct)
    {
        string reservation = $"{_scope.OperationId:D}-retained31-operation-start.json";
        string[] allowed = CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations)
            .SelectMany(database => new[] { "prepared", "committed-readback", "failed-or-uncertain" }
                .Select(suffix => $"{_scope.OperationId:D}-{database}-{suffix}.json")).Append(reservation).ToArray();
        if (name != Path.GetFileName(name) || !allowed.Contains(name, StringComparer.Ordinal) || payload.Length > 65536 ||
            _retainedEvidence.ContainsKey(name)) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        if (name != reservation)
        {
            CurrentAppOwnedRetained31Receipt receipt = JsonSerializer.Deserialize<CurrentAppOwnedRetained31Receipt>(payload)
                ?? throw CurrentAppOwnedRetained31Permit.Invalid();
            PostgreSqlCurrentAppOwnedRetained31Repair.RequireReceipt(receipt, _scope, _authorizationSha256, _trust, _pins);
            string suffix = receipt.Classification switch
            {
                CurrentAppOwnedCommitClassification.Prepared => "prepared",
                CurrentAppOwnedCommitClassification.CommittedAndReadback => "committed-readback",
                _ => "failed-or-uncertain",
            };
            if (name != $"{receipt.OperationId:D}-{receipt.Database}-{suffix}.json")
            { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        }
        else
        {
            byte[] expected = JsonSerializer.SerializeToUtf8Bytes(new
            {
                Kind = "current-app-owned-retained31-operation-start-v1",
                _scope.OperationId,
                ScopeSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(_scope),
                AuthorizationSha256 = _authorizationSha256,
            });
            if (_reserved || !payload.AsSpan().SequenceEqual(expected))
            { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        }
        string path = Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, name);
        await _files.WriteNewAsync(path, payload, ct).ConfigureAwait(false);
        byte[] held = _files.Read(path, maximumBytes: 65536);
        if (!held.AsSpan().SequenceEqual(payload)) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        _retainedEvidence.Add(name, held);
    }
    private Task<string> ObserveDockerAsync(IReadOnlyList<string> arguments, CancellationToken ct)
    {
        return CurrentAppOwnedRepairDockerProcess.RunDockerAsync(arguments, ct, RetainResourceFrameAsync);
    }

    private async Task RetainResourceFrameAsync(CurrentAppOwnedDockerResource resource)
    {
        string name = $"resource-{resource.RunId:N}-{Guid.NewGuid():N}.json";
        string path = Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, name);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new { _scope.OperationId, Resource = resource });
        await _files.WriteNewAsync(path, bytes, CancellationToken.None).ConfigureAwait(false);
        byte[] held = _files.Read(path, maximumBytes: 65536);
        if (!held.AsSpan().SequenceEqual(bytes)) { throw CurrentAppOwnedRepairPermit.Invalid(); }
    }
    public void Dispose() { _cloud?.Dispose(); }
}
