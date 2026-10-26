using System.Data;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Closed fixed two-database ISO boundary; no configured callbacks or role/policy provisioning.</summary>
internal sealed class CurrentOwnerIsoRepairConsoleEnvironment : ICurrentOwnerIsoRepairEnvironment, IDisposable
{
    private readonly WindowsLocalRunAuthority _authority;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly CurrentAppOwnedRepairTargetPins _target;
    private readonly string _connection, _ordinary, _authorizationSha256;
    private readonly CurrentAppOwnedDatabaseSnapshot[] _baseline;
    private readonly FreshSchemaPlan _source;
    private readonly CurrentOwnerIsoRepairScope _scope;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly CurrentOwnerIsoRepairSigningPins _pins;
    private readonly CloudNativePgTargetObserver? _cloud;
    private readonly CurrentOwnerIsoRepairSourceObservation _sourceObserver;
    private readonly CurrentAppOwnedRepairArtifact _nativeProof, _maintenanceProof;
    private bool _capacityAdmitted, _publicationFaultUsed;
    private readonly IsoClosedBootstrapInputs? _closedBootstrap;
    private readonly IsoExternalClosedEvidence? _externalClosed;
    private int _closedObservationOrdinal;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, byte[]> _retainedEvidence = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _expectedHashes;
    private readonly Dictionary<string, string> _operandOwnerClosures = new(StringComparer.Ordinal);
    private readonly Dictionary<string, CurrentOwnerIsoNativeObservation> _nativeBefore = new(StringComparer.Ordinal);
    private readonly IReadOnlyList<CurrentOwnerIsoSourceObservation> _owners;
    private readonly ApprovedCurrentOwnerIsoOverlay _contract;
    private readonly Dictionary<string, CurrentOwnerIsoRepairReceipt> _prepared = new(StringComparer.Ordinal);
    private string _latestReceipt = new('0', 64);
    private readonly Dictionary<string, string> _pendingAfterObserved = new(StringComparer.Ordinal);
    private readonly HashSet<string> _completed = new(StringComparer.Ordinal);
    private bool _failed, _reserved;
    internal CurrentOwnerIsoRepairConsoleEnvironment(WindowsLocalRunAuthority authority, CurrentAppOwnedRepairCustody files,
        CurrentAppOwnedRepairTargetPins target, string connection, string ordinary, CurrentAppOwnedDatabaseSnapshot[] baseline,
        FreshSchemaPlan source, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners, CurrentOwnerIsoRepairScope scope, IReceiptAttestationTrustStore trust,
        CurrentOwnerIsoRepairSigningPins pins, string authorizationSha256, CurrentOwnerIsoRepairSourceInputs sourceInputs,
        CurrentAppOwnedRepairArtifact nativeProof, CurrentAppOwnedRepairArtifact maintenanceProof, IsoClosedBootstrapInputs? closedBootstrap = null, IsoExternalClosedEvidence? externalClosed = null)
    {
        _authority = authority; _files = files; _target = target; _connection = connection; _ordinary = ordinary; _source = source;
        _baseline = baseline.Select(x => x with { Catalog = x.Catalog.ToArray(), Relations = x.Relations.ToArray(), Sequences = x.Sequences.ToArray() }).ToArray();
        _scope = JsonSerializer.Deserialize<CurrentOwnerIsoRepairScope>(JsonSerializer.SerializeToUtf8Bytes(scope))!;
        _trust = trust; _pins = pins; _authorizationSha256 = authorizationSha256; _owners = owners; _nativeProof = nativeProof; _maintenanceProof = maintenanceProof;
        _closedBootstrap = closedBootstrap; _externalClosed = externalClosed;
        if (externalClosed is not null && (scope.ProofAdmission != CurrentOwnerIsoProofAdmission.PersistentWithClosedConsoleProof || scope.BootstrapSubject is not null || scope.Target.Kind != DeltaTargetAuthorityKind.LocalAspire || target.CloudOptions is not null || target.CloudObservation is not null)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        if (scope.ProofAdmission == CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap != (closedBootstrap is not null)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        if (closedBootstrap is not null && (target.CloudOptions is not null || target.CloudObservation is not null)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        _contract = ApprovedCurrentOwnerIsoOverlay.Create(source, scope.SourceCommitSha, scope.Operation, owners, DateTimeOffset.UtcNow);
        if (source.Databases.Any(x => x.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(x.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3)))
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        if (scope.Target.Kind == DeltaTargetAuthorityKind.LocalAspire && !scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal).SequenceEqual(
            DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]).Order(StringComparer.Ordinal))) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        _expectedHashes = new(scope.BeforeDatabaseSha256, StringComparer.Ordinal);
        if (baseline.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != baseline.Length ||
            !baseline.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(_expectedHashes.Keys.Order(StringComparer.Ordinal)) ||
            baseline.Any(x => x.Sha256 != _expectedHashes[x.Database]) || !CurrentAppOwnedRepairPermit.HashShape(authorizationSha256))
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        _sourceObserver = new(files, scope, sourceInputs, source, RetainResourceFrameAsync);
        if (target.CloudOptions is not null)
        {
            _ = files.Read(target.CloudOptions.ServiceAccountTokenFile, sharedReader: true);
            _ = files.Read(target.CloudOptions.ServiceAccountCaFile, sharedReader: true);
            _cloud = CloudNativePgTargetObserver.CreateForCurrentAppOwnedRepair(target.CloudOptions);
        }
    }
    public async Task RequireSourceAsync(string sha, CancellationToken ct)
    {
        RequireOpen();
        if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != sha) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        _ = await _sourceObserver.ObserveCatalogAsync(sha, ct).ConfigureAwait(false);
        RequireOpen();
    }
    public async Task RequireOwnerSourcesAsync(string evidenceSha256, CancellationToken ct)
    {
        RequireOpen();
        var observed = await _sourceObserver.ObserveOwnersAsync(_owners, ct).ConfigureAwait(false);
        // Observe timestamps may refresh, but signed owner timestamps and exact heads/pins remain held.
        if (observed.Length != _owners.Count || observed.Zip(_owners).Any(pair => pair.First.Repository != pair.Second.Repository ||
            pair.First.Head != pair.Second.Head || !pair.First.Clean ||
            JsonSerializer.Serialize(pair.First.Files) != JsonSerializer.Serialize(pair.Second.Files)) ||
            evidenceSha256 != CurrentAppOwnedSnapshotSerialization.Sha256(_owners)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        _ = ApprovedCurrentOwnerIsoOverlay.Create(_source, _scope.SourceCommitSha, _scope.Operation, _owners, DateTimeOffset.UtcNow);
    }
    public async Task RequireResourceAndCustodyAsync(CurrentOwnerIsoRepairScope scope, CancellationToken ct)
    {
        _files.Require();
        RequireEvidenceInventory();
        if (_failed || _authority.Binding.ComputeSha256() != scope.RunBindingSha256 || _target.HbaPath != scope.Maintenance.HbaPath ||
            JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(_scope) ||
            CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(_target)) != scope.TargetObservationSha256)
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        var endpoint = new NpgsqlConnectionStringBuilder(_connection);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 ||
            endpoint.Username != scope.Maintenance.Role || string.IsNullOrWhiteSpace(endpoint.Password) ||
            !string.IsNullOrEmpty(endpoint.Options)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
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
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            bool namedClosed = scope.ProofAdmission == CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap;
            bool persistent = !namedClosed && CurrentOwnerIsoRepairLocalTarget.RequireClaim(scope.Target, scope.OperationId,
                scope.RunBindingSha256, _target);
            string volumeName = _target.DockerVolume ?? throw CurrentOwnerIsoRepairPermit.Invalid();
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
                if (namedClosed)
                {
                    string pgData = actual.PgData;
                    var sanitized = System.Text.Json.Nodes.JsonNode.Parse(item.GetRawText())!.AsObject();
                    var config = sanitized["Config"]!.AsObject(); _ = config.Remove("Env"); config["PgData"] = pgData;
                    CurrentOwnerIsoNamedClosedTarget.Require(scope, _target, JsonSerializer.SerializeToElement(sanitized), volumeMetadata.RootElement[0], endpoint.Port, DateTimeOffset.UtcNow);
                }
                else
                {
                    CurrentOwnerIsoRepairLocalTarget.RequireDisposableMetadata(item, volumeMetadata.RootElement[0],
                    scope.OperationId, scope.RunBindingSha256, DateTimeOffset.UtcNow);
                }
            }
            if (item.GetProperty("Image").GetString() != _target.DockerImageId ||
                item.GetProperty("Config").GetProperty("Image").GetString() != _target.DockerImageReference ||
                LocalDockerGenerationGuard.ComposeGeneration(actual) != scope.TargetGeneration)
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            string[] inventoryArguments = persistent
                ? ["--host", "npipe:////./pipe/docker_engine", "ps", "--no-trunc", "--filter", "volume=" + _target.DockerVolume, "--format", "{{.ID}}"]
                : ["--host", "npipe:////./pipe/docker_engine", "ps", "--all", "--no-trunc", "--filter", "volume=" + _target.DockerVolume, "--format", "{{.ID}}"];
            string writers = await ObserveDockerAsync(inventoryArguments, ct).ConfigureAwait(false);
            if (!persistent) { CurrentOwnerIsoRepairLocalTarget.RequireVolumeConsumers(writers, _target.DockerContainerId); }
            string stat = await ObserveDockerAsync(
                ["--host", "npipe:////./pipe/docker_engine", "exec", _target.DockerContainerId, "env", "TZ=UTC", "LC_ALL=C",
                    "stat", "--printf=%d|%i|%f|%u|%g|%h|%s|%y|%z", "--", _target.HbaPath], ct).ConfigureAwait(false);
            if (writers.Trim() != _target.DockerContainerId ||
                CurrentAppOwnedRepairPermit.Hash(Encoding.UTF8.GetBytes(stat)) != _target.HbaStatSha256)
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        }
        else
        {
            if (scope.Target.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg || scope.TargetNamespace != "maliev-legacy" ||
                scope.TargetCluster != "legacy-postgres-main" || _cloud is null || _target.CloudObservation is null ||
                _target.DockerContainerId is not null || _target.DockerVolume is not null)
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            CloudNativePgTargetObservation actual = await _cloud.ObserveAsync("maliev-legacy", "legacy-postgres-main", ct).ConfigureAwait(false);
            if (!actual.SameRuntimeTarget(_target.CloudObservation) || "cnpg:" + actual.Uid + ":" + actual.Generation.ToString(CultureInfo.InvariantCulture) != scope.TargetGeneration ||
                !actual.Ready || actual.ReadyInstances != 2 || actual.Instances != 2 ||
                !actual.ConsistentSystemId || !actual.ContinuousArchiving || !actual.LastBackupSucceeded)
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        }
        await RequireActualNativeProofAndCapacityAsync(ct).ConfigureAwait(false);
        var ordinary = new NpgsqlConnectionStringBuilder(_ordinary);
        if (ordinary.Host != endpoint.Host || ordinary.Port != endpoint.Port || ordinary.Username == endpoint.Username ||
            string.IsNullOrWhiteSpace(ordinary.Password) || !string.IsNullOrEmpty(ordinary.Options))
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        var actualRejected = new List<string>();
        foreach (string name in _baseline.Select(x => x.Database))
        {
            ordinary.Database = name; ordinary.Pooling = false; ordinary.Timeout = 5; ordinary.IncludeErrorDetail = false;
            bool rejected = false;
            try { await using var probe = new NpgsqlConnection(ordinary.ConnectionString); await probe.OpenAsync(ct).ConfigureAwait(false); }
            catch (PostgresException failure) when (failure.SqlState == "28000") { rejected = true; }
            if (!rejected) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            actualRejected.Add(name);
        }
        if (_scope.ProofAdmission == CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap)
        {
            await _files.WriteNewAsync(Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, $"iso-closed-ordinary-{_scope.OperationId:N}-{Guid.NewGuid():N}.json"), JsonSerializer.SerializeToUtf8Bytes(new { _scope.OperationId, databases = actualRejected.Order(StringComparer.Ordinal).ToArray(), observedAtUtc = DateTimeOffset.UtcNow }), ct).ConfigureAwait(false);
        }
        _files.Require();
        RequireEvidenceInventory();
    }

    private async Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CurrentOwnerIsoRepairScope scope, CancellationToken ct)
    {
        RequireOpen();
        if (JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(_scope)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        await ObserveApprovedFleetAsync(ct).ConfigureAwait(false);
        var pool = new CurrentAppOwnedSnapshotInternPool(); var results = new List<CurrentAppOwnedDatabaseSnapshot>();
        var pending = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var expected in _baseline)
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_connection)
            { Database = expected.Database, Pooling = false, Timeout = 5, CommandTimeout = 30, IncludeErrorDetail = false }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await SetReadOnlyAsync(connection, tx, ct).ConfigureAwait(false);
            await PostgreSqlCurrentOwnerIsoRepair.RequireInstalledPolicyAsync(connection, tx, _scope, ct).ConfigureAwait(false);
            CurrentAppOwnedDatabaseSnapshot raw = pool.Intern(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false));
            string hash = raw.Sha256;
            bool affected = PostgreSqlCurrentOwnerIsoRepair.Databases().Contains(expected.Database, StringComparer.Ordinal);
            bool pendingAfter = affected && _prepared.TryGetValue(expected.Database, out var prepared) && hash == prepared.AfterSha256;
            if (hash != (pendingAfter ? _prepared[expected.Database].AfterSha256 : _expectedHashes[expected.Database])) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            if (affected)
            {
                bool selected = _completed.Contains(expected.Database) || pendingAfter;
                var observed = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, _contract, selected, ct).ConfigureAwait(false);
                if (observed.Snapshot.Sha256 != hash) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                string closure = await CurrentOwnerIsoNativePreservation.RequireOperandOwnerAsync(connection, tx, _scope, observed, ct).ConfigureAwait(false);
                if (_operandOwnerClosures.TryGetValue(expected.Database, out string? priorClosure) && priorClosure != closure) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                if (selected && !_operandOwnerClosures.ContainsKey(expected.Database)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                _ = _operandOwnerClosures.TryAdd(expected.Database, closure);
                if (selected)
                {
                    if (!_nativeBefore.TryGetValue(expected.Database, out var before)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                    CurrentOwnerIsoNativePreservation.RequirePreserved(before, observed, _contract);
                    if (pendingAfter) { pending.Add(expected.Database, hash); }
                }
                else
                {
                    CurrentOwnerIsoNativePreservation.RequireBefore(observed, _contract);
                    _ = _nativeBefore.TryAdd(expected.Database, observed);
                }
            }
            if (DatabaseInventory.ActiveDatabases.Contains(expected.Database, StringComparer.Ordinal))
            {
                DatabaseSchemaPlan physical = _source.Databases.Single(x => x.Database == expected.Database);
                if (_completed.Contains(expected.Database) || pendingAfter)
                {
                    physical = physical with { TargetExtensionProfile = ApprovedConsumerOverlaySelection.ProfileForDatabase(expected.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3Iso) };
                    physical = physical with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(physical) };
                }
                // Schema fingerprint plus exact typed native ISO phase; no omitted field/catalog family.
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                if (await inspector.InspectSchemaAsync(physical, ct).ConfigureAwait(false) != physical.TargetSchemaSha256)
                { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            }
            await tx.RollbackAsync(ct).ConfigureAwait(false); results.Add(raw);
        }
        await ObserveApprovedFleetAsync(ct).ConfigureAwait(false);
        RequireOpen(); _pendingAfterObserved.Clear(); foreach (var pair in pending) { _pendingAfterObserved.Add(pair.Key, pair.Value); }
        return results.AsReadOnly();
    }
    private async Task ObserveApprovedFleetAsync(CancellationToken ct)
    {
        // Recheck the held signed topology/custody/run before each independent catalog boundary.
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
        await PostgreSqlCurrentOwnerIsoRepair.RequireInstalledPolicyAsync(connection, transaction, _scope, ct).ConfigureAwait(false);
        await ReviewedProductionRepairInventoryObservation.RequireAsync(connection, transaction, _scope.Target.Kind,
            _scope.Target.SystemIdentifierSha256, _expectedHashes.Keys, ct).ConfigureAwait(false);
        await transaction.RollbackAsync(ct).ConfigureAwait(false);
        RequireOpen();
    }
    public async Task<string> InspectGlobalPreservationAsync(CancellationToken ct)
    {
        _ = await InspectFleetAsync(_scope, ct).ConfigureAwait(false);
        return _scope.GlobalPreservationSha256;
    }
    public async Task ObserveCommittedDatabaseAsync(CurrentOwnerIsoRepairReceipt prepared, CancellationToken ct)
    {
        RequireOpen();
        if (!_prepared.TryGetValue(prepared.Database, out var retained) || JsonSerializer.Serialize(prepared) != JsonSerializer.Serialize(retained))
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        _ = await InspectFleetAsync(_scope, ct).ConfigureAwait(false);
        if (!_pendingAfterObserved.TryGetValue(prepared.Database, out string? after) || after != prepared.AfterSha256)
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
    }
    public Task RequireFreshOperationAsync(CurrentOwnerIsoRepairScope scope, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); RequireOpen();
        return _reserved || JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(_scope) || ObserveOperationNames().Length != 0
            ? throw CurrentOwnerIsoRepairPermit.Invalid()
            : Task.CompletedTask;
    }
    public async Task ReserveFreshOperationAsync(CurrentOwnerIsoRepairScope scope, string authorizationSha256, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await RequireFreshOperationAsync(scope, ct).ConfigureAwait(false);
            if (authorizationSha256 != _authorizationSha256) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            await RetainCoreAsync(ReservationName(scope.OperationId), ReservationBytes(), ct).ConfigureAwait(false);
            _reserved = true; RequireEvidenceInventory();
        }
        catch { _failed = true; throw; }
        finally { _ = _gate.Release(); }
    }
    internal static string ReceiptSuffix(CurrentAppOwnedCommitClassification value)
    {
        return value switch
        {
            CurrentAppOwnedCommitClassification.Prepared => "prepared",
            CurrentAppOwnedCommitClassification.CommittedAndReadback => "committed-readback",
            CurrentAppOwnedCommitClassification.FailedBeforeCommit or CurrentAppOwnedCommitClassification.RolledBackBeforeCommit or
                CurrentAppOwnedCommitClassification.Uncertain => "failed-or-uncertain",
            _ => throw CurrentOwnerIsoRepairPermit.Invalid(),
        };
    }

    public async Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try { await RetainCoreAsync(name, payload, ct).ConfigureAwait(false); }
        catch { _failed = true; throw; }
        finally { _ = _gate.Release(); }
    }
    private async Task RetainCoreAsync(string name, byte[] payload, CancellationToken ct)
    {
        _files.Require(); RequireEvidenceInventory();
        string reservation = ReservationName(_scope.OperationId);
        if (name != Path.GetFileName(name) || payload.Length > 65536 || _retainedEvidence.ContainsKey(name)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        CurrentOwnerIsoRepairReceipt? effect = null;
        if (name == reservation)
        {
            if (_reserved || _failed || !payload.AsSpan().SequenceEqual(ReservationBytes())) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        }
        else
        {
            effect = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairReceipt>(payload);
            PostgreSqlCurrentOwnerIsoRepair.RequireReceipt(effect, _scope, _authorizationSha256, _trust, _pins);
            if (effect.PreviousReceiptSha256 != _latestReceipt || effect.ObservedAtUtc > DateTimeOffset.UtcNow ||
                DateTimeOffset.UtcNow - effect.ObservedAtUtc > TimeSpan.FromMinutes(5) || effect.ObservedAtUtc > _scope.Maintenance.ExpiresAtUtc)
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            bool failure = effect.Classification is not (CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback);
            if (!_reserved || (_failed && !failure) || !PostgreSqlCurrentOwnerIsoRepair.Databases().Contains(effect.Database, StringComparer.Ordinal) ||
                name != $"{_scope.OperationId:D}-{effect.Database}-{ReceiptSuffix(effect.Classification)}.json") { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            if (effect.Classification == CurrentAppOwnedCommitClassification.Prepared && (_prepared.ContainsKey(effect.Database) || _completed.Contains(effect.Database) || !_nativeBefore.ContainsKey(effect.Database)))
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            if (effect.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback &&
                (!_prepared.TryGetValue(effect.Database, out var pending) || _completed.Contains(effect.Database) ||
                 effect.AfterSha256 != pending.AfterSha256 || !_pendingAfterObserved.TryGetValue(effect.Database, out string? after) || effect.AfterSha256 != after))
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        }
        string path = Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, name);
        await _files.WriteNewAsync(path, payload, ct).ConfigureAwait(false);
        byte[] held = _files.Read(path, maximumBytes: 65536);
        if (!held.AsSpan().SequenceEqual(payload)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        _retainedEvidence.Add(name, held); RequireEvidenceInventory(); _files.Require();
        if (_scope.ProofAdmission == CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap && effect is not null)
        {
            string caseId = _scope.BootstrapSubject!.CaseId;
            bool loseAck = !_publicationFaultUsed && effect.Database == "Country" &&
                ((caseId == "prepared-publication" && effect.Classification == CurrentAppOwnedCommitClassification.Prepared) ||
                 (caseId == "terminal-publication" && effect.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback));
            await RetainClosedPublicationAsync(name, held, !loseAck, ct).ConfigureAwait(false);
            if (loseAck) { _publicationFaultUsed = true; _failed = true; throw new MigrationExecutionException("iso_closed_publication_ack_lost", "The owned disposable publisher retained the slot without acknowledging it."); }
        }
        if (effect is not null)
        {
            _latestReceipt = CurrentAppOwnedRepairPermit.Hash(held);
            if (effect.Classification == CurrentAppOwnedCommitClassification.Prepared) { _prepared.Add(effect.Database, effect); _ = _pendingAfterObserved.Remove(effect.Database); }
            else if (effect.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback)
            { _ = _completed.Add(effect.Database); _expectedHashes[effect.Database] = effect.AfterSha256!; _ = _pendingAfterObserved.Remove(effect.Database); }
            else { _failed = true; }
        }
    }
    private byte[] ReservationBytes()
    {
        return JsonSerializer.SerializeToUtf8Bytes(new
        { Kind = "current-owner-iso-operation-start-v1", _scope.OperationId, ScopeSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(_scope), AuthorizationSha256 = _authorizationSha256 });
    }

    private string[] ObserveOperationNames()
    {
        return Directory.EnumerateFileSystemEntries(_authority.Binding.ArtifactRootCanonicalPath)
            .Select(Path.GetFileName).Where(x => x is not null && x.StartsWith(_scope.OperationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase))
            .Select(x => x!).Order(StringComparer.Ordinal).ToArray();
    }

    private void RequireEvidenceInventory()
    {
        RequireSlotInventory(ObserveOperationNames(), _retainedEvidence.Keys);
    }

    internal static string ReservationName(Guid operation)
    {
        return $"{operation:D}-owner-iso-operation-start.json";
    }

    internal static void RequireSlotInventory(IEnumerable<string> observed, IEnumerable<string> acknowledged)
    { if (!observed.Order(StringComparer.Ordinal).SequenceEqual(acknowledged.Order(StringComparer.Ordinal))) { throw CurrentOwnerIsoRepairPermit.Invalid(); } }
    private void RequireOpen() { _files.Require(); RequireEvidenceInventory(); if (_failed) { throw CurrentOwnerIsoRepairPermit.Invalid(); } }
    private static async Task SetReadOnlyAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken ct)
    { await using var command = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx); _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
    private Task<string> ObserveDockerAsync(IReadOnlyList<string> arguments, CancellationToken ct)
    {
        return CurrentAppOwnedRepairDockerProcess.RunDockerAsync(arguments, ct, RetainResourceFrameAsync);
    }

    private async Task RetainResourceFrameAsync(CurrentAppOwnedDockerResource resource)
    {
        string path = Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, $"resource-{resource.RunId:N}-{Guid.NewGuid():N}.json");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new { _scope.OperationId, Resource = resource });
        await _files.WriteNewAsync(path, bytes, CancellationToken.None).ConfigureAwait(false);
        if (!_files.Read(path, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
    }
    private async Task RequireActualNativeProofAndCapacityAsync(CancellationToken ct)
    {
        CurrentOwnerIsoCapacity.Require(!_capacityAdmitted);
        if (_scope.ProofAdmission == CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap)
        {
            await IsoClosedBootstrapReadback.RequireAsync(_files, _authority.Binding, _scope, _closedBootstrap ?? throw CurrentOwnerIsoRepairPermit.Invalid(), ct).ConfigureAwait(false);
            CurrentOwnerIsoCapacity.Require(admission: false); _capacityAdmitted = true; return;
        }
        if (_externalClosed is not null)
        {
            await IsoExternalClosedReader.RequireAllAsync(_files, _authority.Binding, _scope, _pins, _source, _owners, _nativeProof, _maintenanceProof, _externalClosed, ct).ConfigureAwait(false);
            CurrentOwnerIsoCapacity.Require(admission: false); _capacityAdmitted = true; return;
        }
        bool bootstrap = _scope.ProofAdmission == CurrentOwnerIsoProofAdmission.DisposableNativeBootstrap;
        if (bootstrap && (_scope.Target.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(_scope.Target) ||
            CurrentOwnerIsoRepairLocalTarget.RequireClaim(_scope.Target, _scope.OperationId, _scope.RunBindingSha256, _target)))
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        CurrentOwnerIsoClosedProofReader.Require(_files, _nativeProof, _scope.NativeProofSha256, bootstrap ? "native-component" : "native", _scope, _trust, _pins, _source, _owners);
        CurrentOwnerIsoClosedProofReader.Require(_files, _maintenanceProof, _scope.MaintenanceProofSha256, bootstrap ? "maintenance-component" : "maintenance", _scope, _trust, _pins, _source, _owners);
        CurrentOwnerIsoCapacity.Require(admission: false);
        _capacityAdmitted = true;
    }
    private Task RetainClosedPublicationAsync(string name, byte[] held, bool acknowledged, CancellationToken ct)
    {
        string path = Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, $"iso-closed-publication-{_scope.OperationId:N}-{Interlocked.Increment(ref _closedObservationOrdinal):D5}.json");
        return _files.WriteNewAsync(path, JsonSerializer.SerializeToUtf8Bytes(new { _scope.OperationId, name, payloadSha256 = CurrentAppOwnedRepairPermit.Hash(held), acknowledged, observedAtUtc = DateTimeOffset.UtcNow }), ct);
    }
    public void Dispose() { _sourceObserver.Dispose(); _cloud?.Dispose(); _gate.Dispose(); }
}
