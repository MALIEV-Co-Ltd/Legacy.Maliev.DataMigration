using System.Data;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Closed actual Console composition. Never provisions an operator or rewrites policy.</summary>
internal sealed class CurrentAppOwnedV3RepairConsoleEnvironment : ICurrentAppOwnedV3RepairEnvironment, IDisposable
{
    internal static string ReceiptSuffix(CurrentAppOwnedCommitClassification classification)
    {
        return classification switch
        {
            CurrentAppOwnedCommitClassification.Prepared => "prepared",
            CurrentAppOwnedCommitClassification.CommittedAndReadback => "committed-readback",
            CurrentAppOwnedCommitClassification.RolledBackBeforeCommit => "failed-or-uncertain",
            CurrentAppOwnedCommitClassification.FailedBeforeCommit => "failed-or-uncertain",
            CurrentAppOwnedCommitClassification.Uncertain => "failed-or-uncertain",
            _ => throw CurrentAppOwnedV3RepairPermit.Invalid(),
        };
    }
    private static readonly string[] EvidenceSuffixes = ["prepared", "committed-readback", "failed-or-uncertain"];
    private readonly WindowsLocalRunAuthority _authority;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly CurrentAppOwnedRepairTargetPins _target;
    private readonly string _connection;
    private readonly string _ordinary;
    private readonly CurrentAppOwnedDatabaseSnapshot[] _baseline;
    private readonly FreshSchemaPlan _before;
    private readonly FreshSchemaPlan _after;
    private readonly CurrentAppOwnedV3RepairScope _scope;
    private readonly CloudNativePgTargetObserver? _cloud;
    private readonly CurrentAppOwnedV3AdditiveContract _contract;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly CurrentAppOwnedRepairSigningPins _pins;
    private readonly string _authorizationSha256;
    private readonly Dictionary<string, byte[]> _retainedEvidence = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _expectedHashes;
    private readonly Dictionary<string, V3AdditiveObservation> _nativeBefore = new(StringComparer.Ordinal);
    private readonly HashSet<string> _completed = new(StringComparer.Ordinal);
    private static readonly string[] RepairDatabases = ["Invoice", "PurchaseOrder", "Quotation"];
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private CurrentAppOwnedV3RepairReceipt? _prepared;
    private string? _preparedHash;
    private string? _pendingAfterObserved;
    private string _previousTerminal = new('0', 64);
    private int _nextDatabase;
    private bool _failed;
    private bool _reserved;

    internal CurrentAppOwnedV3RepairConsoleEnvironment(WindowsLocalRunAuthority authority,
        CurrentAppOwnedRepairCustody files, CurrentAppOwnedRepairTargetPins target,
        string connection, string ordinary, CurrentAppOwnedDatabaseSnapshot[] baseline,
        FreshSchemaPlan before, FreshSchemaPlan after, CurrentAppOwnedV3RepairScope scope,
        IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins, string authorizationSha256)
    {
        _authority = authority; _files = files; _target = target; _connection = connection; _ordinary = ordinary;
        _baseline = baseline.Select(CurrentAppOwnedV3RepairPermit.CopySnapshot).ToArray();
        _before = JsonSerializer.Deserialize<FreshSchemaPlan>(JsonSerializer.SerializeToUtf8Bytes(before))!;
        _after = JsonSerializer.Deserialize<FreshSchemaPlan>(JsonSerializer.SerializeToUtf8Bytes(after))!;
        _scope = scope with { BeforeDatabaseSha256 = new Dictionary<string, string>(scope.BeforeDatabaseSha256, StringComparer.Ordinal) };
        _contract = CurrentAppOwnedV3AdditiveContract.Create(_before, _after, scope.SourceCommitSha, DateTimeOffset.UtcNow);
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
            CurrentAppOwnedV3RepairPermit.FleetSha256(_expectedHashes) != scope.GlobalPreservationSha256 ||
            !CurrentAppOwnedRepairPermit.HashShape(authorizationSha256) ||
            !baseline.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(_expectedHashes.Keys.Order(StringComparer.Ordinal)) ||
            baseline.Any(x => CurrentAppOwnedSnapshotSerialization.Sha256(x) != _expectedHashes[x.Database]))
        { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
    }

    public async Task RequireSourceAsync(string sourceCommitSha, CancellationToken ct)
    {
        _files.Require();
        RequireEvidenceInventory();
        if (_failed) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        string actual = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        if (actual != sourceCommitSha) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        _files.Require();
    }

    public async Task RequireResourceAndCustodyAsync(CurrentAppOwnedV3RepairScope scope, CancellationToken ct)
    {
        _files.Require();
        RequireEvidenceInventory();
        if (_failed || _authority.Binding.ComputeSha256() != scope.RunBindingSha256 || _target.HbaPath != scope.Maintenance.HbaPath ||
            JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(_scope) ||
            CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(_target)) != scope.TargetObservationSha256)
        { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        var endpoint = new NpgsqlConnectionStringBuilder(_connection);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 ||
            endpoint.Username != scope.Maintenance.Role || string.IsNullOrWhiteSpace(endpoint.Password) ||
            !string.IsNullOrEmpty(endpoint.Options)) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
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
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            bool persistent = CurrentAppOwnedV3RepairLocalTarget.RequireClaim(scope.Target, scope.OperationId,
                scope.RunBindingSha256, _target);
            string volumeName = _target.DockerVolume ?? throw CurrentAppOwnedV3RepairPermit.Invalid();
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
                CurrentAppOwnedV3RepairLocalTarget.RequireDisposableMetadata(item, volumeMetadata.RootElement[0],
                    scope.OperationId, scope.RunBindingSha256, DateTimeOffset.UtcNow);
            }
            if (item.GetProperty("Image").GetString() != _target.DockerImageId ||
                item.GetProperty("Config").GetProperty("Image").GetString() != _target.DockerImageReference ||
                LocalDockerGenerationGuard.ComposeGeneration(actual) != scope.TargetGeneration)
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            string[] inventoryArguments = persistent
                ? ["--host", "npipe:////./pipe/docker_engine", "ps", "--no-trunc", "--filter", "volume=" + _target.DockerVolume, "--format", "{{.ID}}"]
                : ["--host", "npipe:////./pipe/docker_engine", "ps", "--all", "--no-trunc", "--filter", "volume=" + _target.DockerVolume, "--format", "{{.ID}}"];
            string writers = await ObserveDockerAsync(inventoryArguments, ct).ConfigureAwait(false);
            if (!persistent) { CurrentAppOwnedV3RepairLocalTarget.RequireVolumeConsumers(writers, _target.DockerContainerId); }
            string stat = await ObserveDockerAsync(
                ["--host", "npipe:////./pipe/docker_engine", "exec", _target.DockerContainerId, "env", "TZ=UTC", "LC_ALL=C",
                    "stat", "--printf=%d|%i|%f|%u|%g|%h|%s|%y|%z", "--", _target.HbaPath], ct).ConfigureAwait(false);
            if (writers.Trim() != _target.DockerContainerId ||
                CurrentAppOwnedRepairPermit.Hash(Encoding.UTF8.GetBytes(stat)) != _target.HbaStatSha256)
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        }
        else
        {
            if (scope.Target.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg || scope.TargetNamespace != "maliev-legacy" ||
                scope.TargetCluster != "legacy-postgres-main" || _cloud is null || _target.CloudObservation is null ||
                _target.DockerContainerId is not null || _target.DockerVolume is not null)
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            CloudNativePgTargetObservation actual = await _cloud.ObserveAsync("maliev-legacy", "legacy-postgres-main", ct).ConfigureAwait(false);
            if (!actual.SameRuntimeTarget(_target.CloudObservation) || "cnpg:" + actual.Uid + ":" + actual.Generation.ToString(CultureInfo.InvariantCulture) != scope.TargetGeneration ||
                !actual.Ready || actual.ReadyInstances != 2 || actual.Instances != 2 ||
                !actual.ConsistentSystemId || !actual.ContinuousArchiving || !actual.LastBackupSucceeded)
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        }
        var ordinary = new NpgsqlConnectionStringBuilder(_ordinary);
        if (ordinary.Host != endpoint.Host || ordinary.Port != endpoint.Port || ordinary.Username == endpoint.Username ||
            string.IsNullOrWhiteSpace(ordinary.Password) || !string.IsNullOrEmpty(ordinary.Options))
        { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        foreach (string name in _baseline.Select(x => x.Database))
        {
            ordinary.Database = name; ordinary.Pooling = false; ordinary.Timeout = 5; ordinary.IncludeErrorDetail = false;
            bool rejected = false;
            try { await using var probe = new NpgsqlConnection(ordinary.ConnectionString); await probe.OpenAsync(ct).ConfigureAwait(false); }
            catch (PostgresException failure) when (failure.SqlState == "28000") { rejected = true; }
            if (!rejected) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        }
        _files.Require();
        RequireEvidenceInventory();
    }

    public async Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CurrentAppOwnedV3RepairScope scope, CancellationToken ct)
    {
        _files.Require(); RequireEvidenceInventory();
        if (_failed || JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(_scope))
        { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        await ObserveApprovedFleetAsync(ct).ConfigureAwait(false);
        var pool = new CurrentAppOwnedSnapshotInternPool();
        var results = new List<CurrentAppOwnedDatabaseSnapshot>();
        string? observedPending = null;
        _pendingAfterObserved = null;
        foreach (CurrentAppOwnedDatabaseSnapshot expected in _baseline)
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_connection)
            { Database = expected.Database, Pooling = false, IncludeErrorDetail = false, Timeout = 5, CommandTimeout = 30 }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await SetReadOnlyAsync(connection, tx, ct).ConfigureAwait(false);
            await PostgreSqlCurrentAppOwnedV3Repair.RequireInstalledPolicyAsync(connection, tx, _scope, ct).ConfigureAwait(false);
            CurrentAppOwnedDatabaseSnapshot raw = pool.Intern(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false));
            string rawHash = CurrentAppOwnedSnapshotSerialization.Sha256(raw);
            bool pendingAfter = _prepared?.Database == expected.Database && rawHash == _prepared.AfterSha256;
            bool isAfter = _completed.Contains(expected.Database) || pendingAfter;
            if (rawHash != (pendingAfter ? _prepared!.AfterSha256 : _expectedHashes[expected.Database]))
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            if (RepairDatabases.Contains(expected.Database, StringComparer.Ordinal))
            {
                V3AdditiveObservation observed = await CurrentAppOwnedV3AdditivePreservation.CaptureAsync(connection, tx,
                    _before, _after, _scope.SourceCommitSha, isAfter, DateTimeOffset.UtcNow, ct,
                    _scope.Target.Kind == DeltaTargetAuthorityKind.LocalAspire ? "legacy_local" : "postgres").ConfigureAwait(false);
                if (CurrentAppOwnedSnapshotSerialization.Sha256(observed.Snapshot) != rawHash)
                { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
                observed = observed with { Snapshot = raw };
                if (isAfter)
                {
                    if (!_nativeBefore.TryGetValue(expected.Database, out V3AdditiveObservation? original))
                    { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
                    CurrentAppOwnedV3AdditivePreservation.RequirePreserved(original, observed);
                    if (pendingAfter) { observedPending = rawHash; }
                }
                else { _ = _nativeBefore.TryAdd(expected.Database, observed); }
            }
            if (DatabaseInventory.ActiveDatabases.Contains(expected.Database, StringComparer.Ordinal))
            {
                DatabaseSchemaPlan physical = isAfter ? _contract.AfterForDatabase(expected.Database) : _contract.BeforeForDatabase(expected.Database);
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                if (await inspector.InspectSchemaAsync(physical, ct).ConfigureAwait(false) != physical.TargetSchemaSha256)
                { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            }
            await tx.RollbackAsync(ct).ConfigureAwait(false);
            results.Add(raw);
        }
        await ObserveApprovedFleetAsync(ct).ConfigureAwait(false);
        _files.Require(); RequireEvidenceInventory();
        _pendingAfterObserved = observedPending;
        return results.AsReadOnly();
    }

    internal async Task<IReadOnlyList<V3AdditiveObservation>> GetRepairPreimagesAsync(CancellationToken ct)
    {
        _ = await InspectFleetAsync(_scope, ct).ConfigureAwait(false);
        return _reserved || _completed.Count != 0 || _nativeBefore.Count != RepairDatabases.Length
            ? throw CurrentAppOwnedV3RepairPermit.Invalid()
            : (IReadOnlyList<V3AdditiveObservation>)RepairDatabases.Select(name => _nativeBefore[name] with
            {
                Snapshot = CurrentAppOwnedV3RepairPermit.CopySnapshot(_nativeBefore[name].Snapshot),
                AddedCatalogKeys = new HashSet<string>(_nativeBefore[name].AddedCatalogKeys, StringComparer.Ordinal),
                NewObjectClosure = new HashSet<string>(_nativeBefore[name].NewObjectClosure, StringComparer.Ordinal),
            }).ToArray();
    }

    private async Task ObserveApprovedFleetAsync(CancellationToken ct)
    {
        // Same held signed scope binds original target artifact/topology/system/run; no new authority contract.
        await RequireResourceAndCustodyAsync(_scope, ct).ConfigureAwait(false);
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_connection)
        {
            Database = "postgres",
            Pooling = false,
            Timeout = 5,
            CommandTimeout = 30,
            IncludeErrorDetail = false,
            Options = "-c default_transaction_read_only=on"
        }.ConnectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
        await SetReadOnlyAsync(connection, transaction, ct).ConfigureAwait(false);
        await PostgreSqlCurrentAppOwnedV3Repair.RequireInstalledPolicyAsync(connection, transaction, _scope, ct).ConfigureAwait(false);
        await ReviewedProductionRepairInventoryObservation.RequireAsync(connection, transaction, _scope.Target.Kind,
            _scope.Target.SystemIdentifierSha256, _expectedHashes.Keys, ct).ConfigureAwait(false);
        await transaction.RollbackAsync(ct).ConfigureAwait(false);
        _files.Require(); RequireEvidenceInventory();
    }

    public Task RequireFreshOperationAsync(CurrentAppOwnedV3RepairScope scope, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); _files.Require();
        return _failed || _reserved || JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(_scope) || ObserveOperationNames().Length != 0
            ? throw CurrentAppOwnedV3RepairPermit.Invalid()
            : Task.CompletedTask;
    }

    public async Task ReserveFreshOperationAsync(CurrentAppOwnedV3RepairScope scope, string authorizationSha256, CancellationToken ct)
    {
        await _operationGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await RequireFreshOperationAsync(scope, ct).ConfigureAwait(false);
            if (authorizationSha256 != _authorizationSha256) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            string name = $"{scope.OperationId:D}-v3-operation-start.json";
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new
            {
                Kind = "current-app-owned-v3-operation-start-v1",
                scope.OperationId,
                ScopeSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(scope),
                AuthorizationSha256 = authorizationSha256
            });
            await RetainEvidenceCoreAsync(name, bytes, ct).ConfigureAwait(false);
            RequireEvidenceInventory(); _reserved = true;
        }
        catch { _failed = true; throw; }
        finally { _ = _operationGate.Release(); }
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
        { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
    }
    public async Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken ct)
    {
        await _operationGate.WaitAsync(ct).ConfigureAwait(false);
        try { await RetainEvidenceCoreAsync(name, payload, ct).ConfigureAwait(false); }
        catch { _failed = true; throw; }
        finally { _ = _operationGate.Release(); }
    }

    private async Task RetainEvidenceCoreAsync(string name, byte[] payload, CancellationToken ct)
    {
        _files.Require(); RequireEvidenceInventory();
        string reservation = $"{_scope.OperationId:D}-v3-operation-start.json";
        string[] allowed = RepairDatabases
            .SelectMany(database => EvidenceSuffixes
                .Select(suffix => $"{_scope.OperationId:D}-{database}-{suffix}.json")).Append(reservation).ToArray();
        if (name != Path.GetFileName(name) || !allowed.Contains(name, StringComparer.Ordinal) || payload.Length > 65536 ||
            _retainedEvidence.ContainsKey(name)) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        CurrentAppOwnedV3RepairReceipt? effect = null;
        if (name != reservation)
        {
            CurrentAppOwnedV3RepairReceipt receipt = JsonSerializer.Deserialize<CurrentAppOwnedV3RepairReceipt>(payload)
                ?? throw CurrentAppOwnedV3RepairPermit.Invalid();
            PostgreSqlCurrentAppOwnedV3Repair.RequireReceipt(receipt, _scope, _authorizationSha256, _trust, _pins);
            effect = receipt;
            bool failure = receipt.Classification is not (CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback);
            if (!_reserved || (_failed && !failure) || _nextDatabase >= RepairDatabases.Length || receipt.Database != RepairDatabases[_nextDatabase])
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            if (receipt.Classification == CurrentAppOwnedCommitClassification.Prepared)
            {
                if (_prepared is not null || receipt.PreviousReceiptSha256 != _previousTerminal || !_nativeBefore.ContainsKey(receipt.Database))
                { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            }
            else if (receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback)
            {
                if (_prepared is null || receipt.PreviousReceiptSha256 != _preparedHash ||
                    receipt.BeforeSha256 != _prepared.BeforeSha256 || receipt.AfterSha256 != _prepared.AfterSha256 ||
                    _pendingAfterObserved != receipt.AfterSha256)
                { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            }
            else if (receipt.PreviousReceiptSha256 != (_preparedHash ?? _previousTerminal))
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            string suffix = ReceiptSuffix(receipt.Classification);
            if (name != $"{receipt.OperationId:D}-{receipt.Database}-{suffix}.json")
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        }
        else
        {
            byte[] expected = JsonSerializer.SerializeToUtf8Bytes(new
            {
                Kind = "current-app-owned-v3-operation-start-v1",
                _scope.OperationId,
                ScopeSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(_scope),
                AuthorizationSha256 = _authorizationSha256,
            });
            if (_reserved || !payload.AsSpan().SequenceEqual(expected))
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        }
        string path = Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, name);
        await _files.WriteNewAsync(path, payload, ct).ConfigureAwait(false);
        byte[] held = _files.Read(path, maximumBytes: 65536);
        if (!held.AsSpan().SequenceEqual(payload)) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        _retainedEvidence.Add(name, held);
        RequireEvidenceInventory(); _files.Require();
        if (effect?.Classification == CurrentAppOwnedCommitClassification.Prepared)
        {
            _prepared = effect; _preparedHash = CurrentAppOwnedRepairPermit.Hash(held); _pendingAfterObserved = null;
        }
        else if (effect?.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback)
        {
            _ = _completed.Add(effect.Database); _expectedHashes[effect.Database] = effect.AfterSha256!;
            _previousTerminal = CurrentAppOwnedRepairPermit.Hash(held); _nextDatabase++;
            _prepared = null; _preparedHash = null; _pendingAfterObserved = null;
        }
        else if (effect is not null) { _failed = true; }
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
    public void Dispose() { _cloud?.Dispose(); _operationGate.Dispose(); }
}
