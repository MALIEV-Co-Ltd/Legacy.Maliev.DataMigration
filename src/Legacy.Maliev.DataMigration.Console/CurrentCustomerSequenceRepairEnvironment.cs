using System.Data;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Closed fixed Customer definition boundary; no configured callbacks or role/policy provisioning.</summary>
internal sealed class CurrentCustomerSequenceRepairConsoleEnvironment : ICurrentCustomerSequenceRepairEnvironment, IDisposable
{
    private readonly WindowsLocalRunAuthority _authority;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly CurrentAppOwnedRepairTargetPins _target;
    private readonly string _connection, _ordinary, _authorizationSha256;
    private readonly CurrentAppOwnedDatabaseSnapshot[] _baseline;
    private readonly FreshSchemaPlan _source;
    private readonly CurrentCustomerSequenceRepairScope _scope;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly CurrentCustomerSequenceRepairSigningPins _pins;
    private readonly CloudNativePgTargetObserver? _cloud;
    private readonly CurrentCustomerSequenceRepairSourceObservation _sourceObserver;
    private readonly CurrentAppOwnedRepairArtifact _definitionProof, _nativeProof, _maintenanceProof;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, byte[]> _retainedEvidence = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _expectedHashes;
    private CurrentCustomerSequenceObservation? _nativeBefore;
    private CurrentCustomerSequenceRepairReceipt? _prepared;
    private string _latestReceipt = new('0', 64);
    private string? _pendingAfterObserved, _operandOwnerClosure;
    private bool _failed, _reserved, _completed, _closedDropUsed;
    private readonly CustomerClosedSeedEvidence? _closedSeedEvidence;
    private readonly CustomerClosedEightEvidence? _closedEight;
    internal CurrentCustomerSequenceRepairConsoleEnvironment(WindowsLocalRunAuthority authority, CurrentAppOwnedRepairCustody files,
        CurrentAppOwnedRepairTargetPins target, string connection, string ordinary, CurrentAppOwnedDatabaseSnapshot[] baseline,
        FreshSchemaPlan source, CurrentCustomerSequenceRepairScope scope, IReceiptAttestationTrustStore trust,
        CurrentCustomerSequenceRepairSigningPins pins, string authorizationSha256, CurrentCustomerSequenceRepairSourceInputs sourceInputs,
        CurrentAppOwnedRepairArtifact definitionProof, CurrentAppOwnedRepairArtifact nativeProof, CurrentAppOwnedRepairArtifact maintenanceProof, CustomerClosedSeedEvidence? closedSeedEvidence = null, CustomerClosedEightEvidence? closedEight = null)
    {
        _authority = authority; _files = files; _target = target; _connection = connection; _ordinary = ordinary; _source = source;
        _baseline = baseline.Select(CurrentCustomerSequenceRepairPermit.CopySnapshot).ToArray();
        _scope = JsonSerializer.Deserialize<CurrentCustomerSequenceRepairScope>(JsonSerializer.SerializeToUtf8Bytes(scope))!;
        _trust = trust; _pins = pins; _authorizationSha256 = authorizationSha256;
        _definitionProof = definitionProof; _nativeProof = nativeProof; _maintenanceProof = maintenanceProof; _closedSeedEvidence = closedSeedEvidence; _closedEight = closedEight;
        if (closedEight is not null && (closedSeedEvidence is not null || scope.ProofAdmission != CurrentCustomerSequenceProofAdmission.PersistentWithClosedConsoleProof))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        _expectedHashes = new(scope.BeforeDatabaseSha256, StringComparer.Ordinal);
        if (baseline.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != baseline.Length ||
            !baseline.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(_expectedHashes.Keys.Order(StringComparer.Ordinal)) ||
            baseline.Any(x => x.Sha256 != _expectedHashes[x.Database]) || !CurrentCustomerSequenceRepairPermit.HashShape(authorizationSha256))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
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
        if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != sha) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        RequireOpen();
    }
    public async Task<CurrentCustomerSequenceSource> ObserveCurrentCatalogAsync(string sha, CancellationToken ct)
    { RequireOpen(); var observed = await _sourceObserver.ObserveCatalogAsync(sha, ct).ConfigureAwait(false); RequireOpen(); return observed; }
    public async Task<CurrentCustomerSequenceOwner> ObserveOwnerAsync(CancellationToken ct)
    { RequireOpen(); var observed = await _sourceObserver.ObserveOwnerAsync(ct).ConfigureAwait(false); RequireOpen(); return observed; }
    public async Task RequireSource23PhysicalBaselineAsync(FreshSchemaPlan source, CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
    {
        RequireOpen();
        if (SchemaPlanCanonicalizer.ComputeSha256(source) != scope.SourceSchemaPlanSha256 ||
            SchemaPlanCanonicalizer.ComputeSha256(source) != SchemaPlanCanonicalizer.ComputeSha256(_source))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        // Each required database is actually observed below. Customer native phase derives only from authentic retained receipts.
        if (!_reserved) { _ = await InspectFleetAsync(scope, ct).ConfigureAwait(false); }
        else if (_nativeBefore is null) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        // During the serializable writer transaction, provider checks actual native state under locks.
        // A concurrent fleet backend would violate global client isolation; full fleet readback follows writer closure.
    }
    public async Task<CurrentCustomerSequenceObservation> ObserveNativeBeforeAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
    {
        _ = await InspectFleetAsync(scope, ct).ConfigureAwait(false);
        return _completed || _prepared is not null || _nativeBefore is null
            ? throw CurrentCustomerSequenceRepairPermit.Invalid()
            : new(_nativeBefore.State with { }, CurrentCustomerSequenceRepairPermit.CopySnapshot(_nativeBefore.Snapshot));
    }
    public async Task RequireResourceAndCustodyAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        _files.Require();
        RequireEvidenceInventory();
        if (_failed || _authority.Binding.ComputeSha256() != scope.RunBindingSha256 || _target.HbaPath != scope.Maintenance.HbaPath ||
            JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(_scope) ||
            CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(_target)) != scope.TargetObservationSha256)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        if (_closedEight is not null)
        {
            await CurrentCustomerClosedEightConsumer.RequireAsync(_closedEight, _scope, _trust, _pins, DateTimeOffset.UtcNow, ct, initialAdmission: false).ConfigureAwait(false);
        }
        var endpoint = new NpgsqlConnectionStringBuilder(_connection);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 ||
            endpoint.Username != scope.Maintenance.Role || string.IsNullOrWhiteSpace(endpoint.Password) ||
            !string.IsNullOrEmpty(endpoint.Options)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
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
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            bool persistent = CurrentCustomerSequenceRepairLocalTarget.RequireClaim(scope.Target, scope.OperationId,
                scope.RunBindingSha256, _target);
            string volumeName = _target.DockerVolume ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
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
                CurrentCustomerSequenceRepairLocalTarget.RequireDisposableMetadata(item, volumeMetadata.RootElement[0],
                    scope.OperationId, scope.RunBindingSha256, DateTimeOffset.UtcNow);
            }
            if (item.GetProperty("Image").GetString() != _target.DockerImageId ||
                item.GetProperty("Config").GetProperty("Image").GetString() != _target.DockerImageReference ||
                LocalDockerGenerationGuard.ComposeGeneration(actual) != scope.TargetGeneration)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            string[] inventoryArguments = persistent
                ? ["--host", "npipe:////./pipe/docker_engine", "ps", "--no-trunc", "--filter", "volume=" + _target.DockerVolume, "--format", "{{.ID}}"]
                : ["--host", "npipe:////./pipe/docker_engine", "ps", "--all", "--no-trunc", "--filter", "volume=" + _target.DockerVolume, "--format", "{{.ID}}"];
            string writers = await ObserveDockerAsync(inventoryArguments, ct).ConfigureAwait(false);
            if (!persistent) { CurrentCustomerSequenceRepairLocalTarget.RequireVolumeConsumers(writers, _target.DockerContainerId); }
            string stat = await ObserveDockerAsync(
                ["--host", "npipe:////./pipe/docker_engine", "exec", _target.DockerContainerId, "env", "TZ=UTC", "LC_ALL=C",
                    "stat", "--printf=%d|%i|%f|%u|%g|%h|%s|%y|%z", "--", _target.HbaPath], ct).ConfigureAwait(false);
            if (writers.Trim() != _target.DockerContainerId ||
                CurrentAppOwnedRepairPermit.Hash(Encoding.UTF8.GetBytes(stat)) != _target.HbaStatSha256)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        else
        {
            if (scope.Target.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg || scope.TargetNamespace != "maliev-legacy" ||
                scope.TargetCluster != "legacy-postgres-main" || _cloud is null || _target.CloudObservation is null ||
                _target.DockerContainerId is not null || _target.DockerVolume is not null)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            CloudNativePgTargetObservation actual = await _cloud.ObserveAsync("maliev-legacy", "legacy-postgres-main", ct).ConfigureAwait(false);
            if (!actual.SameRuntimeTarget(_target.CloudObservation) || "cnpg:" + actual.Uid + ":" + actual.Generation.ToString(CultureInfo.InvariantCulture) != scope.TargetGeneration ||
                !actual.Ready || actual.ReadyInstances != 2 || actual.Instances != 2 ||
                !actual.ConsistentSystemId || !actual.ContinuousArchiving || !actual.LastBackupSucceeded)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        bool bootstrap = _scope.ProofAdmission == CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap;
        if (bootstrap && CurrentCustomerSequenceRepairLocalTarget.RequireClaim(_scope.Target, _scope.OperationId, _scope.RunBindingSha256, _target))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        if (_closedEight is not null)
        {
            if (_closedSeedEvidence is not null) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        else if (_scope.ProofAdmission == CurrentCustomerSequenceProofAdmission.DisposableClosedConsoleBootstrap)
        {
            if (_closedSeedEvidence is null || CurrentCustomerSequenceRepairLocalTarget.RequireClaim(_scope.Target, _scope.OperationId, _scope.RunBindingSha256, _target))
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            await CurrentCustomerSequenceClosedSeedReadback.RequireAsync(_closedSeedEvidence, _scope, _source, _trust, _pins, ct).ConfigureAwait(false);
        }
        else
        {
            if (_closedSeedEvidence is not null) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            CurrentCustomerSequenceClosedProofReader.Require(_files, _definitionProof, _scope.DefinitionProofSha256, "definition", _scope, _trust, _pins, _source);
            CurrentCustomerSequenceClosedProofReader.Require(_files, _nativeProof, _scope.NativeProofSha256, bootstrap ? "native-component" : "native", _scope, _trust, _pins, _source);
            CurrentCustomerSequenceClosedProofReader.Require(_files, _maintenanceProof, _scope.MaintenanceProofSha256, bootstrap ? "maintenance-component" : "maintenance", _scope, _trust, _pins, _source);
        }
        CurrentCustomerSequenceCapacity.Require(admission: false);
        var ordinary = new NpgsqlConnectionStringBuilder(_ordinary);
        if (ordinary.Host != endpoint.Host || ordinary.Port != endpoint.Port || ordinary.Username == endpoint.Username ||
            string.IsNullOrWhiteSpace(ordinary.Password) || !string.IsNullOrEmpty(ordinary.Options))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        foreach (string name in _baseline.Select(x => x.Database))
        {
            ordinary.Database = name; ordinary.Pooling = false; ordinary.Timeout = 5; ordinary.IncludeErrorDetail = false;
            bool rejected = false;
            try { await using var probe = new NpgsqlConnection(ordinary.ConnectionString); await probe.OpenAsync(ct).ConfigureAwait(false); }
            catch (PostgresException failure) when (failure.SqlState == "28000") { rejected = true; }
            if (!rejected) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        CurrentCustomerSequenceCapacity.Require(admission: false);
        _files.Require();
        RequireEvidenceInventory();
    }

    public async Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
    {
        RequireOpen();
        if (JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(_scope)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        await ObserveApprovedFleetAsync(ct).ConfigureAwait(false);
        var pool = new CurrentAppOwnedSnapshotInternPool(); var results = new List<CurrentAppOwnedDatabaseSnapshot>();
        string? pending = null;
        foreach (var expected in _baseline)
        {
            CurrentCustomerSequenceCapacity.Require(admission: false);
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_connection)
            { Database = expected.Database, Pooling = false, Timeout = 5, CommandTimeout = 30, IncludeErrorDetail = false }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await SetReadOnlyAsync(connection, tx, ct).ConfigureAwait(false);
            await PostgreSqlCurrentCustomerSequenceRepair.RequireInstalledPolicyAsync(connection, tx, _scope, ct).ConfigureAwait(false);
            CurrentAppOwnedDatabaseSnapshot raw = pool.Intern(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false));
            string hash = raw.Sha256;
            bool pendingAfter = expected.Database == "Customer" && _prepared is not null && hash == _prepared.AfterSha256;
            if (hash != (pendingAfter ? _prepared!.AfterSha256 : _expectedHashes[expected.Database])) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            if (expected.Database == "Customer")
            {
                var observed = await CurrentCustomerSequenceNativeObservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false);
                if (observed.Snapshot.Sha256 != hash) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                observed = observed with { Snapshot = raw };
                string closure = await CurrentCustomerSequenceNativeObservation.RequireOperandOwnerAsync(connection, tx, _scope, observed, ct).ConfigureAwait(false);
                if (_operandOwnerClosure is not null && _operandOwnerClosure != closure) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                if ((_completed || pendingAfter) && _operandOwnerClosure is null) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                _operandOwnerClosure ??= closure;
                if (_completed || pendingAfter)
                {
                    if (_nativeBefore is null) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                    _ = ApprovedCurrentCustomerSequenceDefinition.Create(_scope.SourceObservation, _scope.OwnerObservation, _scope.SourceCommitSha,
                        _scope.CatalogReportSha256, DateTimeOffset.UtcNow);
                    ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(_nativeBefore, observed,
                        CurrentRepairOperandOwnerProfile.ExpectedOwnerName(CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, _scope.Target));
                    if (pendingAfter) { pending = hash; }
                }
                else
                {
                    CurrentCustomerSequenceRepairPermit.RequireNativePreimage(observed, _scope, DateTimeOffset.UtcNow);
                    _nativeBefore ??= observed;
                }
            }
            if (DatabaseInventory.ActiveDatabases.Contains(expected.Database, StringComparer.Ordinal))
            {
                DatabaseSchemaPlan physical = _source.Databases.Single(x => x.Database == expected.Database);
                // Schema fingerprint plus exact native Customer sequence phase; no omitted field/catalog family.
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                if (await inspector.InspectSchemaAsync(physical, ct).ConfigureAwait(false) != physical.TargetSchemaSha256)
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
            await tx.RollbackAsync(ct).ConfigureAwait(false); results.Add(raw);
        }
        await ObserveApprovedFleetAsync(ct).ConfigureAwait(false);
        RequireOpen(); _pendingAfterObserved = pending; return results.AsReadOnly();
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
        await PostgreSqlCurrentCustomerSequenceRepair.RequireInstalledPolicyAsync(connection, transaction, _scope, ct).ConfigureAwait(false);
        await ReviewedProductionRepairInventoryObservation.RequireAsync(connection, transaction, _scope.Target.Kind,
            _scope.Target.SystemIdentifierSha256, _expectedHashes.Keys, ct).ConfigureAwait(false);
        await transaction.RollbackAsync(ct).ConfigureAwait(false);
        RequireOpen();
    }
    public Task RequireFreshOperationAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); RequireOpen();
        return _reserved || JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(_scope) || ObserveOperationNames().Length != 0
            ? throw CurrentCustomerSequenceRepairPermit.Invalid()
            : Task.CompletedTask;
    }
    public async Task ReserveFreshOperationAsync(CurrentCustomerSequenceRepairScope scope, string authorizationSha256, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await RequireFreshOperationAsync(scope, ct).ConfigureAwait(false);
            if (authorizationSha256 != _authorizationSha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            await RetainCoreAsync($"{scope.OperationId:D}-customer-sequence-operation-start.json", ReservationBytes(), ct).ConfigureAwait(false);
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
            _ => throw CurrentCustomerSequenceRepairPermit.Invalid(),
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
        string reservation = $"{_scope.OperationId:D}-customer-sequence-operation-start.json";
        if (name != Path.GetFileName(name) || payload.Length > 65536 || _retainedEvidence.ContainsKey(name)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        CurrentCustomerSequenceRepairReceipt? effect = null;
        if (name == reservation)
        {
            if (_reserved || _failed || !payload.AsSpan().SequenceEqual(ReservationBytes())) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        else
        {
            effect = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceRepairReceipt>(payload);
            PostgreSqlCurrentCustomerSequenceRepair.RequireReceipt(effect, _scope, _authorizationSha256, _trust, _pins, _latestReceipt, DateTimeOffset.UtcNow);
            bool failure = effect.Classification is not (CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback);
            if (!_reserved || (_failed && !failure) || effect.Database != "Customer" ||
                name != $"{_scope.OperationId:D}-Customer-{ReceiptSuffix(effect.Classification)}.json") { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            if (effect.Classification == CurrentAppOwnedCommitClassification.Prepared && (_prepared is not null || _completed || _nativeBefore is null))
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            if (effect.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback && (_prepared is null || _completed ||
                effect.AfterSha256 != _prepared.AfterSha256 || effect.AfterSha256 != _pendingAfterObserved)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        string path = Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, name);
        await _files.WriteNewAsync(path, payload, ct).ConfigureAwait(false);
        byte[] held = _files.Read(path, maximumBytes: 65536);
        if (!held.AsSpan().SequenceEqual(payload)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        _retainedEvidence.Add(name, held); RequireEvidenceInventory(); _files.Require();
        if (effect is not null)
        {
            if (!_closedDropUsed && _scope.ProofAdmission == CurrentCustomerSequenceProofAdmission.DisposableClosedConsoleBootstrap &&
                ((_scope.ClosedConsoleSeed!.CaseId == "prepared-publication" && effect.Classification == CurrentAppOwnedCommitClassification.Prepared) ||
                 (_scope.ClosedConsoleSeed!.CaseId == "terminal-publication" && effect.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback)))
            {
                _closedDropUsed = true;
                // Physical publication has completed, but caller has not received ACK.
                // Preserve the last acknowledged predecessor for the genuine catch receipt.
                await _files.WriteNewAsync(Path.Combine(_authority.Binding.ArtifactRootCanonicalPath,
                    $"customer-closed-publication-unack-{_scope.OperationId:N}.json"), JsonSerializer.SerializeToUtf8Bytes(new
                    {
                        Slot = name,
                        Sha256 = CurrentCustomerSequenceRepairPermit.Hash(held),
                        Acknowledged = false,
                        PreviousAcknowledgedSha256 = _latestReceipt,
                        ObservedAtUtc = DateTimeOffset.UtcNow
                    }), ct).ConfigureAwait(false);
                throw new IOException("Owned disposable Customer publication acknowledgment dropped.");
            }
            _latestReceipt = CurrentCustomerSequenceRepairPermit.Hash(held);
            if (effect.Classification == CurrentAppOwnedCommitClassification.Prepared) { _prepared = effect; _pendingAfterObserved = null; }
            else if (effect.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback)
            { _completed = true; _expectedHashes["Customer"] = effect.AfterSha256!; _pendingAfterObserved = null; }
            else { _failed = true; }
        }
    }
    private byte[] ReservationBytes()
    {
        return JsonSerializer.SerializeToUtf8Bytes(new
        { Kind = "current-customer-sequence-operation-start-v1", _scope.OperationId, ScopeSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(_scope), AuthorizationSha256 = _authorizationSha256 });
    }

    private string[] ObserveOperationNames()
    {
        return Directory.EnumerateFileSystemEntries(_authority.Binding.ArtifactRootCanonicalPath)
            .Select(Path.GetFileName).Where(x => x is not null && x.StartsWith(_scope.OperationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase))
            .Select(x => x!).Order(StringComparer.Ordinal).ToArray();
    }

    private void RequireEvidenceInventory()
    { if (!ObserveOperationNames().SequenceEqual(_retainedEvidence.Keys.Order(StringComparer.Ordinal))) { throw CurrentCustomerSequenceRepairPermit.Invalid(); } }
    private void RequireOpen() { CurrentCustomerSequenceCapacity.Require(admission: false); _files.Require(); RequireEvidenceInventory(); if (_failed) { throw CurrentCustomerSequenceRepairPermit.Invalid(); } }
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
        if (!_files.Read(path, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    public void Dispose() { _sourceObserver.Dispose(); _cloud?.Dispose(); _gate.Dispose(); }
}
