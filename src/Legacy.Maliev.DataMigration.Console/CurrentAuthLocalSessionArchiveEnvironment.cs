using System.Data;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed class CurrentAuthLocalSessionArchiveEnvironment : ICurrentAuthLocalSessionArchiveEnvironment, IDisposable
{
    private static readonly string[] DockerOverrides = ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"];
    private readonly CurrentAppOwnedRepairCustody _localFiles, _productionFiles;
    private readonly WindowsLocalRunAuthority _localAuthority;
    private readonly CurrentAuthArchiveScope _scope;
    private readonly FreshSchemaPlan _source;
    private readonly CurrentAppOwnedRepairTargetPins _localTarget, _productionTarget;
    private readonly string _localConnection, _productionConnection, _localOrdinary, _productionOrdinary, _authorization;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly CurrentAuthArchivePins _pins;
    private readonly CloudNativePgTargetObserver? _cloud;
    private readonly CurrentAuthLocalSessionArchiveRecoveryStorage _storage;
    private readonly CurrentAuthLocalSessionArchivePublication _publication;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CurrentAppOwnedSnapshotInternPool _pool = new();
    private string _previous = new('0', 64);
    private CurrentAuthArchiveReceipt? _prepared;
    private bool _reserved, _terminal, _failed;
    public ICurrentAuthLocalSessionArchiveStorage RecoveryStorage => _storage;
    internal CurrentAuthLocalSessionArchiveEnvironment(CurrentAppOwnedRepairCustody localFiles, CurrentAppOwnedRepairCustody productionFiles,
        WindowsLocalRunAuthority localAuthority, WindowsLocalRunAuthority productionAuthority, CurrentAuthArchiveScope scope,
        FreshSchemaPlan source, CurrentAppOwnedRepairTargetPins localTarget, CurrentAppOwnedRepairTargetPins productionTarget,
        string localConnection, string productionConnection, string localOrdinary, string productionOrdinary,
        CurrentAuthArchiveDeviceProof devices, IReceiptAttestationTrustStore trust, CurrentAuthArchivePins pins, string authorization)
    {
        _localFiles = localFiles; _productionFiles = productionFiles; _localAuthority = localAuthority;
        _scope = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveScope>(JsonSerializer.SerializeToUtf8Bytes(scope));
        _source = MigrationConsole.DecodeAuthRepair<FreshSchemaPlan>(JsonSerializer.SerializeToUtf8Bytes(source));
        _localTarget = localTarget; _productionTarget = productionTarget; _localConnection = localConnection; _productionConnection = productionConnection;
        _localOrdinary = localOrdinary; _productionOrdinary = productionOrdinary; _trust = trust; _pins = pins; _authorization = authorization;
        RequireObservationPolicies(scope, DateTimeOffset.UtcNow);
        bool bootstrap = scope.ProofAdmission == CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap;
        if ((!bootstrap && (productionTarget.CloudOptions is null || productionTarget.CloudObservation is null)) ||
            (bootstrap && (productionTarget.CloudOptions is not null || productionTarget.CloudObservation is not null)) || localAuthority.Binding.ComputeSha256() != scope.LocalObservationPolicy.RunBindingSha256 ||
            productionAuthority.Binding.ComputeSha256() != scope.ProductionObservationPolicy.RunBindingSha256 ||
            !CurrentAuthRepairPermit.HashShape(authorization)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        if (!bootstrap)
        {
            _ = productionFiles.Read(productionTarget.CloudOptions!.ServiceAccountTokenFile, sharedReader: true, maximumBytes: 65536);
            _ = productionFiles.Read(productionTarget.CloudOptions.ServiceAccountCaFile, sharedReader: true, maximumBytes: 65536);
        }
        _publication = new(localFiles, localAuthority, productionAuthority, scope.OperationId);
        _storage = new(localFiles, productionFiles, localAuthority, productionAuthority, _scope, devices);
        try { if (!bootstrap) { _cloud = CloudNativePgTargetObserver.CreateForCurrentAppOwnedRepair(productionTarget.CloudOptions!); } RequireHealthy(); }
        catch { _publication.Dispose(); _storage.Dispose(); _cloud?.Dispose(); _gate.Dispose(); throw; }
    }
    public async Task RequireAcceptedSourceOwnerCustodyAndTargetsAsync(CurrentAuthArchiveScope scope, CancellationToken ct)
    {
        RequireHealthy(); Match(scope);
        CurrentAuthLocalSessionArchivePolicy.RequireScope(scope, DateTimeOffset.UtcNow);
        RequireObservationPolicies(scope, DateTimeOffset.UtcNow);
        ProductionSchemaCatalogInspector.ValidatePlan(_source, DateTimeOffset.UtcNow);
        if (!ApprovedConsumerOverlaySelection.IsApproved(_source) ||
            _source.Databases.Any(x => x.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(x.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3)) ||
            _source.Databases.Single(x => x.Database == "Quotation").SourceDispositionProfile != ApprovedSourceDispositionManifest.QuotationOutboxesV1)
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != scope.LocalObservationPolicy.SourceCommitSha ||
            _source.SourceCommitSha != scope.LocalObservationPolicy.SourceCommitSha || SchemaPlanCanonicalizer.ComputeSha256(_source) != scope.LocalObservationPolicy.SourceSchemaPlanSha256 ||
            _source.CapturedAtUtc.Offset != TimeSpan.Zero || _source.CapturedAtUtc > scope.CapturedAtUtc || DateTimeOffset.UtcNow - _source.CapturedAtUtc > TimeSpan.FromMinutes(5) ||
            !_source.Databases.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases.Order(StringComparer.Ordinal)) ||
            _source.Databases.Sum(x => x.Tables.Count) != 100 || scope.LocalObservationPolicy.MaintenanceValidatorSha256 != CurrentAuthRepairEnvironment.IntegratedMaintenanceValidatorSha256 ||
            scope.ProductionObservationPolicy.MaintenanceValidatorSha256 != CurrentAuthRepairEnvironment.IntegratedMaintenanceValidatorSha256)
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        await CurrentAuthOwnerSourceReader.RequireAsync(resource => FrameAsync("git", resource), ct).ConfigureAwait(false);
        await RequireTargetsAsync(ct).ConfigureAwait(false);
        await _storage.RequireCustodyAsync(ct).ConfigureAwait(false);
        // During the exact writer transaction, these temporary readers claim no zero
        // clients; provider policy checks zero others before/after each callback.
        foreach (bool local in new[] { true, false })
        {
            foreach (DatabaseSchemaPlan database in _source.Databases)
            {
                CurrentAuthArchiveCapacity.Require(admission: false);
                await using var connection = Connection(local, database.Database); await connection.OpenAsync(ct).ConfigureAwait(false);
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
                await ReadOnlyAsync(connection, tx, ct).ConfigureAwait(false);
                await RequireReadPolicyAsync(connection, tx, local ? _scope.LocalObservationPolicy : _scope.ProductionObservationPolicy, ct).ConfigureAwait(false);
                await RequirePhysicalAsync(connection, tx, database, ct).ConfigureAwait(false); await tx.RollbackAsync(ct).ConfigureAwait(false);
            }
        }

        RequireHealthy();
    }
    public Task<CurrentAuthArchiveFleet> CaptureLocalFleetAsync(CurrentAuthArchiveScope scope, CancellationToken ct)
    {
        return CaptureAsync(scope, true, ct);
    }

    public Task<CurrentAuthArchiveFleet> CaptureProductionFleetAsync(CurrentAuthArchiveScope scope, CancellationToken ct)
    {
        return CaptureAsync(scope, false, ct);
    }

    private async Task<CurrentAuthArchiveFleet> CaptureAsync(CurrentAuthArchiveScope scope, bool local, CancellationToken ct)
    {
        RequireHealthy(); Match(scope);
        CurrentAuthRepairScope policy = local ? scope.LocalObservationPolicy : scope.ProductionObservationPolicy;
        CurrentAuthArchiveCatalogObservation before = await CaptureCatalogAsync(local, policy, ct).ConfigureAwait(false);
        DateTimeOffset began = DateTimeOffset.UtcNow;
        var results = new List<CurrentAppOwnedDatabaseSnapshot>();
        CurrentAuthLocalSessionArchiveObservation? auth = null;
        foreach (string database in policy.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))
        {
            CurrentAuthArchiveCapacity.Require(admission: false);
            await using var connection = Connection(local, database); await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ReadOnlyAsync(connection, tx, ct).ConfigureAwait(false);
            await PostgreSqlCurrentAuthRepair.RequireInstalledPolicyAsync(connection, tx, policy, ct).ConfigureAwait(false);
            CurrentAppOwnedDatabaseSnapshot raw;
            if (database == "Auth")
            { auth = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, policy.RunBindingSha256, ct).ConfigureAwait(false); raw = auth.Native.Snapshot; }
            else { raw = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false); }
            if (DatabaseInventory.ActiveDatabases.Contains(database, StringComparer.Ordinal))
            { await RequirePhysicalAsync(connection, tx, _source.Databases.Single(x => x.Database == database), ct).ConfigureAwait(false); }
            await tx.RollbackAsync(ct).ConfigureAwait(false); results.Add(_pool.Intern(raw));
        }
        DateTimeOffset ended = DateTimeOffset.UtcNow;
        CurrentAuthArchiveCatalogObservation after = await CaptureCatalogAsync(local, policy, ct).ConfigureAwait(false);
        var catalogs = new CurrentAuthArchiveFleetCatalogs(before, after, began, ended);
        CurrentAuthLocalSessionArchivePolicy.RequireCatalogs(catalogs, policy, !local, results.Select(x => x.Database), before.BeganAtUtc, DateTimeOffset.UtcNow);
        RequireHealthy(); return new(auth ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid(), results.AsReadOnly(), began, ended, catalogs);
    }
    private async Task<CurrentAuthArchiveCatalogObservation> CaptureCatalogAsync(bool local, CurrentAuthRepairScope policy, CancellationToken ct)
    {
        RequireHealthy();
        await _storage.RequireCustodyAsync(ct).ConfigureAwait(false);
        await RequireTargetsAsync(ct).ConfigureAwait(false);
        await using var connection = Connection(local, "postgres"); await connection.OpenAsync(ct).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
        await ReadOnlyAsync(connection, tx, ct).ConfigureAwait(false);
        await PostgreSqlCurrentAuthRepair.RequireInstalledPolicyAsync(connection, tx, policy, ct).ConfigureAwait(false);
        DateTimeOffset began = DateTimeOffset.UtcNow;
        var flags = new List<ReviewedRepairDatabaseFlag>();
        string? system = null; bool readOnly = false;
        const string sql = """
            SELECT d.datname,d.datistemplate,d.datallowconn,
              encode(sha256(convert_to(c.system_identifier::text,'UTF8')),'hex'),
              current_setting('transaction_read_only')='on'
            FROM pg_database d CROSS JOIN pg_control_system() c ORDER BY d.datname COLLATE "C";
            """;
        await using (var command = new NpgsqlCommand(sql, connection, tx) { CommandTimeout = 30 })
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                string observed = reader.GetString(3); bool observedReadOnly = reader.GetBoolean(4);
                ReviewedProductionRepairInventoryObservation.RequireSystemBinding(observed, policy.Target.SystemIdentifierSha256, observedReadOnly);
                if (system is not null && (system != observed || readOnly != observedReadOnly)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                system = observed; readOnly = observedReadOnly;
                flags.Add(new(reader.GetString(0), reader.GetBoolean(1), reader.GetBoolean(2)));
            }
        }
        ReviewedProductionRepairInventory.RequireComplete(CurrentAuthLocalSessionArchivePolicy.InventoryProfile(!local), flags, policy.BeforeDatabaseSha256.Keys);
        var result = new CurrentAuthArchiveCatalogObservation(policy.RunBindingSha256, policy.TargetObservationSha256,
            system ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid(), readOnly, flags.AsReadOnly(), began, DateTimeOffset.UtcNow);
        await tx.RollbackAsync(ct).ConfigureAwait(false);
        RequireHealthy(); return result;
    }
    public async Task ReserveCreateNewAsync(Guid operationId, string authorizationSha256, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            RequireHealthy();
            if (_reserved || operationId != _scope.OperationId || authorizationSha256 != _authorization || Names().Length != 0 ||
                new[] { _scope.Paths.FirstCiphertext, _scope.Paths.SecondCiphertext, _scope.Paths.RecoveryPrivateKey, _scope.Paths.SecondRecoveryPrivateKey }.Any(path => File.Exists(path) || Directory.Exists(path)))
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new
            {
                Domain = "current-auth-session-archive-reservation-v1",
                OperationId = operationId,
                AuthorizationSha256 = authorizationSha256,
                ScopeSha256 = CurrentAuthLocalSessionArchivePolicy.Hash(_scope)
            });
            await WriteAndRetainAsync($"{operationId:D}-Auth-session-archive-operation-start.json", bytes, ct).ConfigureAwait(false); _reserved = true;
        }
        catch { _failed = true; throw; }
        finally { _ = _gate.Release(); }
    }
    public async Task RetainCreateNewAsync(string name, byte[] canonicalSignedBytes, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            _localFiles.Require(); _productionFiles.Require(); RequireInventory();
            if (!_reserved || canonicalSignedBytes.Length > 65536) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            CurrentAuthArchiveClaim claim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(canonicalSignedBytes);
            if (!JsonSerializer.SerializeToUtf8Bytes(claim).AsSpan().SequenceEqual(canonicalSignedBytes)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            CurrentAuthArchiveReceipt receipt = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveReceipt>(claim,
                CurrentAuthLocalSessionArchivePolicy.ReceiptDomain, _pins.EvidenceKeyId, _pins.EvidenceFingerprint, _trust);
            bool success = receipt.Classification is CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback;
            if ((_failed && success) || receipt.OperationId != _scope.OperationId || receipt.AuthorizationSha256 != _authorization || receipt.PreviousSha256 != _previous ||
                receipt.BeforeAuthSha256 != _scope.LocalObservationPolicy.BeforeDatabaseSha256["Auth"] || receipt.ObservedAtUtc.Offset != TimeSpan.Zero ||
                receipt.ObservedAtUtc > DateTimeOffset.UtcNow || DateTimeOffset.UtcNow - receipt.ObservedAtUtc > TimeSpan.FromMinutes(5) ||
                !CurrentAuthRepairPermit.HashShape(receipt.RecoveryManifestSha256)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            string suffix = receipt.Classification switch
            {
                CurrentAppOwnedCommitClassification.Prepared => "prepared",
                CurrentAppOwnedCommitClassification.CommittedAndReadback => "committed-readback",
                CurrentAppOwnedCommitClassification.Uncertain or CurrentAppOwnedCommitClassification.RolledBackBeforeCommit or CurrentAppOwnedCommitClassification.FailedBeforeCommit => "failed-or-uncertain",
                _ => throw CurrentAuthLocalSessionArchivePolicy.Invalid(),
            };
            if (name != $"{_scope.OperationId:D}-Auth-session-archive-{suffix}.json" ||
                (receipt.Classification == CurrentAppOwnedCommitClassification.Prepared && (_prepared is not null || _terminal || !CurrentAuthRepairPermit.HashShape(receipt.AfterAuthSha256 ?? ""))) ||
                (receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback && (_prepared is null || _terminal || receipt.AfterAuthSha256 != _prepared.AfterAuthSha256)))
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            await WriteAndRetainAsync(name, canonicalSignedBytes, ct).ConfigureAwait(false);
            _previous = CurrentAuthLocalSessionArchivePolicy.Hash(claim);
            if (receipt.Classification == CurrentAppOwnedCommitClassification.Prepared) { _prepared = receipt; }
            else if (receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback) { _terminal = true; }
            else { _failed = true; }
        }
        catch { _failed = true; throw; }
        finally { _ = _gate.Release(); }
    }
    public async Task RetainRecoveryManifestAsync(byte[] canonicalSignedBytes, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            RequireHealthy();
            var claim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(canonicalSignedBytes);
            if (!_reserved || !JsonSerializer.SerializeToUtf8Bytes(claim).AsSpan().SequenceEqual(canonicalSignedBytes)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            var manifest = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveRecoveryManifest>(claim, CurrentAuthLocalSessionArchivePolicy.RecoveryDomain,
                _pins.EvidenceKeyId, _pins.EvidenceFingerprint, _trust);
            if (manifest.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(_scope) || manifest.AuthorizationSha256 != _authorization ||
                !CurrentAuthRepairPermit.HashShape(manifest.RecoveryPublicKeySha256) || !CurrentAuthRepairPermit.HashShape(manifest.FirstCiphertextSha256) ||
                !CurrentAuthRepairPermit.HashShape(manifest.SecondCiphertextSha256) || manifest.FirstCiphertextSha256 == manifest.SecondCiphertextSha256)
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            await WriteAndRetainAsync($"{_scope.OperationId:D}-Auth-session-archive-recovery-manifest.json", canonicalSignedBytes, ct).ConfigureAwait(false);
        }
        catch { _failed = true; throw; }
        finally { _ = _gate.Release(); }
    }
    private Task WriteAndRetainAsync(string name, byte[] bytes, CancellationToken ct)
    {
        return _publication.WriteAndRetainAsync(name, bytes, ct);
    }
    internal void RequireTerminal(CurrentAuthArchiveReceipt receipt)
    { RequireHealthy(); if (!_terminal || receipt.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback || _prepared?.AfterAuthSha256 != receipt.AfterAuthSha256) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); } }
    private string[] Names()
    {
        return _publication.Names();
    }
    private void RequireInventory()
    {
        _publication.RequireInventory();
    }
    private void RequireHealthy() { CurrentAuthArchiveCapacity.Require(admission: false); _localFiles.Require(); _productionFiles.Require(); RequireInventory(); if (_failed) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); } }
    private void Match(CurrentAuthArchiveScope scope) { if (CurrentAuthLocalSessionArchivePolicy.Hash(scope) != CurrentAuthLocalSessionArchivePolicy.Hash(_scope)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); } }
    private NpgsqlConnection Connection(bool local, string database)
    {
        return new(new NpgsqlConnectionStringBuilder(local ? _localConnection : _productionConnection)
        { Database = database, Pooling = false, Options = "", IncludeErrorDetail = false, Timeout = 5, CommandTimeout = 30 }.ConnectionString);
    }

    private static async Task ReadOnlyAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken ct)
    { await using var command = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx); _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
    private static async Task RequirePhysicalAsync(NpgsqlConnection connection, NpgsqlTransaction tx, DatabaseSchemaPlan plan, CancellationToken ct)
    { await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false); if (await inspector.InspectSchemaAsync(plan, ct).ConfigureAwait(false) != plan.TargetSchemaSha256) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); } }
    private async Task FrameAsync<T>(string kind, T resource)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        string path = Path.Combine(_localAuthority.Binding.ArtifactRootCanonicalPath, $"resource-auth-archive-{kind}-{Guid.NewGuid():N}.json");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new { _scope.OperationId, Resource = resource });
        await _localFiles.WriteNewAsync(path, bytes, timeout.Token).ConfigureAwait(false);
        if (!_localFiles.Read(path, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
    }
    private Task<string> DockerAsync(IReadOnlyList<string> arguments, CancellationToken ct)
    {
        return CurrentAppOwnedRepairDockerProcess.RunDockerAsync(arguments, ct, resource => FrameAsync("docker", resource));
    }

    private async Task RequireTargetsAsync(CancellationToken ct)
    {
        CurrentAuthRepairScope local = _scope.LocalObservationPolicy, production = _scope.ProductionObservationPolicy;
        var endpoint = RequireEndpoint(_localConnection, local); var productionEndpoint = RequireEndpoint(_productionConnection, production);
        if (_localTarget.CloudOptions is not null || _localTarget.CloudObservation is not null || DockerOverrides.Any(name => !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(name))) ||
            _localTarget.HbaPath != local.Maintenance.HbaPath || _productionTarget.HbaPath != production.Maintenance.HbaPath ||
            CurrentAuthLocalSessionArchivePolicy.Hash(_localTarget) != local.TargetObservationSha256 || CurrentAuthLocalSessionArchivePolicy.Hash(_productionTarget) != production.TargetObservationSha256)
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        bool persistent = CurrentAppOwnedRepairLocalTarget.RequireClaim(local.Target, _scope.OperationId, local.RunBindingSha256, _localTarget);
        string id = _localTarget.DockerContainerId ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid(); string volumeName = _localTarget.DockerVolume ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid();
        string container = await DockerAsync(["inspect", "--type", "container", id], ct).ConfigureAwait(false);
        string volume = await DockerAsync(["inspect", "--type", "volume", volumeName], ct).ConfigureAwait(false);
        DockerLocalTargetObservation actual = DockerLocalTargetObservation.Parse(container, volume, id, volumeName, endpoint.Port, persistent);
        using JsonDocument c = JsonDocument.Parse(container); using JsonDocument v = JsonDocument.Parse(volume);
        JsonElement item = c.RootElement[0];
        if (!persistent) { CurrentAuthLocalSessionArchiveTarget.RequireDisposable(item, v.RootElement[0], _scope.OperationId, local.RunBindingSha256, DateTimeOffset.UtcNow); }
        if (LocalDockerGenerationGuard.ComposeGeneration(actual) != local.TargetGeneration || item.GetProperty("Image").GetString() != _localTarget.DockerImageId ||
            item.GetProperty("Config").GetProperty("Image").GetString() != _localTarget.DockerImageReference) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        CurrentAppOwnedRepairLocalTarget.RequireVolumeConsumers(await DockerAsync(["ps", "--all", "--no-trunc", "--filter", "volume=" + volumeName, "--format", "{{.ID}}"], ct).ConfigureAwait(false), id);
        string stat = await DockerAsync(["exec", id, "env", "TZ=UTC", "LC_ALL=C", "stat", "--printf=%d|%i|%f|%u|%g|%h|%s|%y|%z", "--", _localTarget.HbaPath], ct).ConfigureAwait(false);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(Encoding.UTF8.GetBytes(stat)) != _localTarget.HbaStatSha256) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        if (_scope.ProofAdmission == CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap)
        {
            await RequireComparisonDisposableAsync(production, productionEndpoint, ct).ConfigureAwait(false);
        }
        else
        {
            if (_productionTarget.DockerContainerId is not null || _productionTarget.DockerVolume is not null || _productionTarget.CloudObservation is null) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            CloudNativePgTargetObservation cloud = await _cloud!.ObserveAsync("maliev-legacy", "legacy-postgres-main", ct).ConfigureAwait(false);
            if (!cloud.SameRuntimeTarget(_productionTarget.CloudObservation) || "cnpg:" + cloud.Uid + ":" + cloud.Generation.ToString(CultureInfo.InvariantCulture) != production.TargetGeneration ||
                !cloud.Ready || cloud.ReadyInstances != 2 || cloud.Instances != 2 || !cloud.ConsistentSystemId || !cloud.ContinuousArchiving || !cloud.LastBackupSucceeded)
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
        await RequireOrdinaryRejectedAsync(endpoint, _localOrdinary, local, ct).ConfigureAwait(false);
        await RequireOrdinaryRejectedAsync(productionEndpoint, _productionOrdinary, production, ct).ConfigureAwait(false);
    }
    private async Task RequireComparisonDisposableAsync(CurrentAuthRepairScope policy, NpgsqlConnectionStringBuilder endpoint, CancellationToken ct)
    {
        CurrentAppOwnedRepairTargetPins target = _productionTarget;
        string id = target.DockerContainerId ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid();
        string name = "legacy-delta-proof-" + _scope.OperationId.ToString("N") + "-comparison";
        if (id.Length != 64 || !id.All(char.IsAsciiHexDigitLower) || target.DockerVolume != name ||
            policy.Target.Kind != DeltaTargetAuthorityKind.LocalAspire || !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(policy.Target) ||
            policy.Target.AuthorityId != "aspire://legacy-postgres-main-local/disposable-" + id[..12] ||
            endpoint.Port == new NpgsqlConnectionStringBuilder(_localConnection).Port || target.CloudOptions is not null || target.CloudObservation is not null)
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        string container = await DockerAsync(["inspect", "--type", "container", id], ct).ConfigureAwait(false);
        string volume = await DockerAsync(["inspect", "--type", "volume", name], ct).ConfigureAwait(false);
        DockerLocalTargetObservation actual = DockerLocalTargetObservation.Parse(container, volume, id, name, endpoint.Port, false);
        using JsonDocument c = JsonDocument.Parse(container); using JsonDocument v = JsonDocument.Parse(volume); JsonElement item = c.RootElement[0];
        CurrentAuthLocalSessionArchiveTarget.RequireDisposable(item, v.RootElement[0], _scope.OperationId, policy.RunBindingSha256, DateTimeOffset.UtcNow, comparison: true);
        if (LocalDockerGenerationGuard.ComposeGeneration(actual) != policy.TargetGeneration || item.GetProperty("Image").GetString() != target.DockerImageId ||
            item.GetProperty("Config").GetProperty("Image").GetString() != target.DockerImageReference || target.HbaPath != actual.PgData.TrimEnd('/') + "/pg_hba.conf")
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        CurrentAppOwnedRepairLocalTarget.RequireVolumeConsumers(await DockerAsync(["ps", "--all", "--no-trunc", "--filter", "volume=" + name, "--format", "{{.ID}}"], ct).ConfigureAwait(false), id);
        string stat = await DockerAsync(["exec", id, "env", "TZ=UTC", "LC_ALL=C", "stat", "--printf=%d|%i|%f|%u|%g|%h|%s|%y|%z", "--", target.HbaPath], ct).ConfigureAwait(false);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(Encoding.UTF8.GetBytes(stat)) != target.HbaStatSha256) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
    }
    private static NpgsqlConnectionStringBuilder RequireEndpoint(string text, CurrentAuthRepairScope policy)
    {
        var endpoint = new NpgsqlConnectionStringBuilder(text);
        return endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 || endpoint.Username != policy.Maintenance.Role || string.IsNullOrWhiteSpace(endpoint.Password) || !string.IsNullOrEmpty(endpoint.Options)
            ? throw CurrentAuthLocalSessionArchivePolicy.Invalid()
            : endpoint;
    }
    internal static void RequireObservationPolicies(CurrentAuthArchiveScope scope, DateTimeOffset now)
    {
        foreach (CurrentAuthRepairScope policy in new[] { scope.LocalObservationPolicy, scope.ProductionObservationPolicy })
        {
            bool local = policy.Target.Kind == DeltaTargetAuthorityKind.LocalAspire;
            string space = local ? "local-aspire" : "maliev-legacy", cluster = local ? "legacy-postgres-main-local" : "legacy-postgres-main";
            CurrentAppOwnedMaintenancePin m = policy.Maintenance;
            if (!DeltaSynchronizationPlanProducer.ValidAuthority(policy.Target, space, cluster) || policy.TargetNamespace != space || policy.TargetCluster != cluster ||
                policy.AuthBeforeSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(true) || policy.AuthAfterSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(true) ||
                !CurrentAuthRepairPermit.HashShape(policy.TargetObservationSha256) || !CurrentAuthRepairPermit.HashShape(policy.RunBindingSha256) ||
                string.IsNullOrWhiteSpace(policy.TargetGeneration) || string.IsNullOrWhiteSpace(m.Role) ||
                m.RoleComment != "legacy-maliev-current-auth-session-archive-v1:" + policy.RunBindingSha256 ||
                m.IssuedAtUtc.Offset != TimeSpan.Zero || m.ExpiresAtUtc.Offset != TimeSpan.Zero || m.Postmaster.Offset != TimeSpan.Zero || m.ConfigLoaded.Offset != TimeSpan.Zero ||
                m.IssuedAtUtc > now || m.ExpiresAtUtc <= scope.ExpiresAtUtc || m.ExpiresAtUtc - m.IssuedAtUtc > TimeSpan.FromHours(4) ||
                m.ExpiresAtUtc <= m.IssuedAtUtc || m.Postmaster > now || m.ConfigLoaded > now || !CurrentAuthRepairPermit.HashShape(m.HbaSha256) ||
                !CurrentAuthRepairPermit.HashShape(m.HbaRulesSha256) || string.IsNullOrWhiteSpace(m.HbaPath)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
    }
    private static async Task RequireOrdinaryRejectedAsync(NpgsqlConnectionStringBuilder endpoint, string text, CurrentAuthRepairScope policy, CancellationToken ct)
    {
        var ordinary = new NpgsqlConnectionStringBuilder(text);
        if (ordinary.Host != endpoint.Host || ordinary.Port != endpoint.Port || ordinary.Username == endpoint.Username || string.IsNullOrWhiteSpace(ordinary.Password) || !string.IsNullOrEmpty(ordinary.Options))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        foreach (string database in policy.BeforeDatabaseSha256.Keys)
        {
            ordinary.Database = database; ordinary.Pooling = false; ordinary.Timeout = 5; ordinary.IncludeErrorDetail = false; bool rejected = false;
            try { await using var connection = new NpgsqlConnection(ordinary.ConnectionString); await connection.OpenAsync(ct).ConfigureAwait(false); }
            catch (PostgresException failure) when (failure.SqlState == "28000") { rejected = true; }
            if (!rejected) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
    }
    private static async Task RequireReadPolicyAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CurrentAuthRepairScope policy, CancellationToken ct)
    {
        const string sql = """
            SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),pg_postmaster_start_time(),pg_conf_load_time(),current_user,
              encode(sha256(convert_to(pg_read_file(current_setting('hba_file')),'UTF8')),'hex'),
              (SELECT encode(sha256(convert_to(jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text,'UTF8')),'hex') FROM pg_hba_file_rules h),
              rolvaliduntil,shobj_description(r.oid,'pg_authid'),rolsuper,rolcanlogin,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,
              (SELECT count(*) FROM pg_auth_members WHERE member=r.oid),(SELECT rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE oid=r.oid),
              (SELECT count(*) FROM pg_default_acl WHERE defaclrole=r.oid),current_setting('hba_file'),NOT pg_is_in_recovery(),
              (SELECT count(*) FROM pg_prepared_xacts),(SELECT count(*) FROM pg_event_trigger WHERE evtenabled<>'D')
            FROM pg_control_system(),pg_roles r WHERE rolname=current_user;
            """;
        await using var command = new NpgsqlCommand(sql, connection, tx); await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        CurrentAppOwnedMaintenancePin m = policy.Maintenance;
        if (!await reader.ReadAsync(ct).ConfigureAwait(false) || reader.GetString(0) != policy.Target.SystemIdentifierSha256 || reader.GetFieldValue<DateTimeOffset>(1) != m.Postmaster ||
            reader.GetFieldValue<DateTimeOffset>(2) != m.ConfigLoaded || reader.GetString(3) != m.Role || reader.GetString(4) != m.HbaSha256 || reader.GetString(5) != m.HbaRulesSha256 ||
            reader.GetFieldValue<DateTimeOffset>(6) != m.ExpiresAtUtc || reader.GetString(7) != m.RoleComment || !reader.GetBoolean(8) || !reader.GetBoolean(9) ||
            reader.GetBoolean(10) || reader.GetBoolean(11) || reader.GetBoolean(12) || reader.GetBoolean(13) || reader.GetInt64(14) != 0 || !reader.GetBoolean(15) || reader.GetInt64(16) != 0 ||
            reader.GetString(17) != m.HbaPath || !reader.GetBoolean(18) || reader.GetInt64(19) != 0 || reader.GetInt64(20) != 0 || DateTimeOffset.UtcNow >= m.ExpiresAtUtc || await reader.ReadAsync(ct).ConfigureAwait(false))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        await reader.DisposeAsync().ConfigureAwait(false);
        await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, tx, m.Role, policy.Target.Kind, ct).ConfigureAwait(false);
    }
    public void Dispose() { _publication.Dispose(); _storage.Dispose(); _cloud?.Dispose(); _gate.Dispose(); }
}
