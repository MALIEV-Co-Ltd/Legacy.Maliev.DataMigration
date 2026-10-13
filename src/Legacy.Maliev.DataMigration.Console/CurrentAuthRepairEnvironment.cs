using System.Data;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Actual fixed Auth composition; never provisions roles, policy, archives or histories.</summary>
internal sealed class CurrentAuthRepairEnvironment : ICurrentAuthRepairEnvironment, IDisposable
{
    internal const string IntegratedMaintenanceValidatorSha256 = "5fc4d018d7ecfec6517db497d1bc8e06dc204be91d1ae2a421f5d41f34d72324";
    private static readonly string[] DockerOverrideNames = ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"];
    private readonly WindowsLocalRunAuthority _authority;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly CurrentAppOwnedRepairTargetPins _target;
    private readonly string _connection, _ordinary, _authorization;
    private readonly FreshSchemaPlan _source;
    private readonly CurrentAuthRepairScope _scope;
    private readonly CurrentAppOwnedDatabaseSnapshot[] _baseline;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly CurrentAuthRepairSigningPins _pins;
    private readonly CloudNativePgTargetObserver? _cloud;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, byte[]> _retained = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _expected;
    private readonly CurrentAuthRetainedReceiptChain _chain = new();
    private CurrentAuthNativeObservation? _nativeBefore;
    private CurrentAuthRepairReceipt? _prepared, _terminal;
    private string? _pendingAfter;
    private bool _reserved, _failed;
    private bool _closedAckFaultUsed;

    internal CurrentAuthRepairEnvironment(WindowsLocalRunAuthority authority, CurrentAppOwnedRepairCustody files,
        CurrentAppOwnedRepairTargetPins target, string connection, string ordinary, CurrentAppOwnedDatabaseSnapshot[] baseline,
        FreshSchemaPlan source, CurrentAuthRepairScope scope, IReceiptAttestationTrustStore trust,
        CurrentAuthRepairSigningPins pins, string authorization)
    {
        _authority = authority; _files = files; _target = target; _connection = connection; _ordinary = ordinary;
        _source = JsonSerializer.Deserialize<FreshSchemaPlan>(JsonSerializer.SerializeToUtf8Bytes(source))!;
        _scope = scope with { BeforeDatabaseSha256 = new Dictionary<string, string>(scope.BeforeDatabaseSha256, StringComparer.Ordinal) };
        _baseline = baseline.Select(CurrentAuthRepairPermit.CopySnapshot).ToArray(); _trust = trust; _pins = pins; _authorization = authorization;
        _expected = new(scope.BeforeDatabaseSha256, StringComparer.Ordinal);
        if (scope.MaintenanceValidatorSha256 != IntegratedMaintenanceValidatorSha256 || baseline.Length != _expected.Count || baseline.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != baseline.Length ||
            !baseline.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(_expected.Keys.Order(StringComparer.Ordinal)) ||
            baseline.Any(x => CurrentAppOwnedSnapshotSerialization.Sha256(x) != _expected[x.Database]) ||
            CurrentAuthRepairPermit.FleetSha256(_expected) != scope.GlobalPreservationSha256 || !CurrentAuthRepairPermit.HashShape(authorization))
        { throw CurrentAuthRepairPermit.Invalid(); }
        if (target.CloudOptions is not null)
        {
            _ = files.Read(target.CloudOptions.ServiceAccountTokenFile, sharedReader: true, maximumBytes: 65536);
            _ = files.Read(target.CloudOptions.ServiceAccountCaFile, sharedReader: true, maximumBytes: 65536);
            _cloud = CloudNativePgTargetObserver.CreateForCurrentAppOwnedRepair(target.CloudOptions);
        }
    }

    public async Task RequireSourceAsync(string sourceCommitSha, CancellationToken ct)
    {
        RequireHealthy();
        if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != sourceCommitSha)
        { throw CurrentAuthRepairPermit.Invalid(); }
        RequireHealthy();
    }
    public async Task RequireAuthOwnerSourceAsync(CurrentAuthRepairScope scope, CancellationToken ct)
    {
        RequireHealthy(); MatchScope(scope);
        await CurrentAuthOwnerSourceReader.RequireAsync(RetainGitFrameAsync, ct).ConfigureAwait(false);
        RequireHealthy();
    }
    public async Task RequireSource23PhysicalBaselineAsync(FreshSchemaPlan source, CancellationToken ct)
    {
        RequireHealthy();
        if (SchemaPlanCanonicalizer.ComputeSha256(source) != _scope.SourceSchemaPlanSha256 || source.SourceCommitSha != _scope.SourceCommitSha ||
            !source.Databases.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases.Order(StringComparer.Ordinal)) ||
            source.Databases.Sum(x => x.Tables.Count) != 100) { throw CurrentAuthRepairPermit.Invalid(); }
        foreach (DatabaseSchemaPlan database in source.Databases)
        {
            CurrentAuthRepairCapacity.Require(admission: false);
            await using var connection = Connection(database.Database);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ReadOnlyAsync(connection, tx, ct).ConfigureAwait(false);
            await RequireSourceReadPolicyAsync(connection, tx, ct).ConfigureAwait(false);
            await RequirePhysicalAsync(connection, tx, database, ct).ConfigureAwait(false);
            await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        RequireHealthy();
    }
    public async Task RequireResourceAndCustodyAsync(CurrentAuthRepairScope scope, CancellationToken ct)
    {
        RequireHealthy(); MatchScope(scope);
        if (_authority.Binding.ComputeSha256() != scope.RunBindingSha256 || _target.HbaPath != scope.Maintenance.HbaPath ||
            CurrentAppOwnedSnapshotSerialization.Sha256(_target) != scope.TargetObservationSha256) { throw CurrentAuthRepairPermit.Invalid(); }
        var endpoint = new NpgsqlConnectionStringBuilder(_connection);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 || endpoint.Username != scope.Maintenance.Role ||
            string.IsNullOrWhiteSpace(endpoint.Password) || !string.IsNullOrEmpty(endpoint.Options)) { throw CurrentAuthRepairPermit.Invalid(); }
        if (scope.Target.Kind == DeltaTargetAuthorityKind.LocalAspire)
        {
            if (!OperatingSystem.IsWindows() || _target.CloudOptions is not null || _target.CloudObservation is not null ||
                _target.DockerContainerId is not { Length: 64 } || !CurrentAuthRepairPermit.HashShape(_target.HbaStatSha256 ?? "") ||
                DockerOverrideNames
                    .Any(name => !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(name)))) { throw CurrentAuthRepairPermit.Invalid(); }
            bool persistent = CurrentAppOwnedRepairLocalTarget.RequireClaim(scope.Target, scope.OperationId, scope.RunBindingSha256, _target);
            string volumeName = _target.DockerVolume ?? throw CurrentAuthRepairPermit.Invalid();
            string container = await DockerAsync(["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "container", _target.DockerContainerId], ct).ConfigureAwait(false);
            string volume = await DockerAsync(["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "volume", volumeName], ct).ConfigureAwait(false);
            DockerLocalTargetObservation actual = DockerLocalTargetObservation.Parse(container, volume, _target.DockerContainerId, volumeName, endpoint.Port, persistent);
            using JsonDocument metadata = JsonDocument.Parse(container); JsonElement item = metadata.RootElement[0];
            using JsonDocument volumeMetadata = JsonDocument.Parse(volume);
            if (!persistent) { RequireAuthDisposable(item, volumeMetadata.RootElement[0], scope.OperationId, scope.RunBindingSha256, DateTimeOffset.UtcNow); }
            if (item.GetProperty("Image").GetString() != _target.DockerImageId || item.GetProperty("Config").GetProperty("Image").GetString() != _target.DockerImageReference ||
                LocalDockerGenerationGuard.ComposeGeneration(actual) != scope.TargetGeneration) { throw CurrentAuthRepairPermit.Invalid(); }
            string writers = await DockerAsync(["--host", "npipe:////./pipe/docker_engine", "ps", "--all", "--no-trunc", "--filter", "volume=" + volumeName, "--format", "{{.ID}}"], ct).ConfigureAwait(false);
            CurrentAppOwnedRepairLocalTarget.RequireVolumeConsumers(writers, _target.DockerContainerId);
            string stat = await DockerAsync(["--host", "npipe:////./pipe/docker_engine", "exec", _target.DockerContainerId,
                "env", "TZ=UTC", "LC_ALL=C", "stat", "--printf=%d|%i|%f|%u|%g|%h|%s|%y|%z", "--", _target.HbaPath], ct).ConfigureAwait(false);
            if (CurrentAuthRepairPermit.Hash(Encoding.UTF8.GetBytes(stat)) != _target.HbaStatSha256) { throw CurrentAuthRepairPermit.Invalid(); }
        }
        else
        {
            if (scope.Target.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg || _cloud is null || _target.CloudObservation is null ||
                _target.DockerContainerId is not null || _target.DockerVolume is not null) { throw CurrentAuthRepairPermit.Invalid(); }
            CloudNativePgTargetObservation actual = await _cloud.ObserveAsync("maliev-legacy", "legacy-postgres-main", ct).ConfigureAwait(false);
            if (!actual.SameRuntimeTarget(_target.CloudObservation) || "cnpg:" + actual.Uid + ":" + actual.Generation.ToString(CultureInfo.InvariantCulture) != scope.TargetGeneration ||
                !actual.Ready || actual.ReadyInstances != 2 || actual.Instances != 2 || !actual.ConsistentSystemId || !actual.ContinuousArchiving || !actual.LastBackupSucceeded)
            { throw CurrentAuthRepairPermit.Invalid(); }
        }
        var ordinary = new NpgsqlConnectionStringBuilder(_ordinary);
        if (ordinary.Host != endpoint.Host || ordinary.Port != endpoint.Port || ordinary.Username == endpoint.Username ||
            string.IsNullOrWhiteSpace(ordinary.Password) || !string.IsNullOrEmpty(ordinary.Options)) { throw CurrentAuthRepairPermit.Invalid(); }
        foreach (string database in _expected.Keys)
        {
            ordinary.Database = database; ordinary.Pooling = false; ordinary.Timeout = 5; ordinary.IncludeErrorDetail = false;
            bool rejected = false;
            try { await using var connection = new NpgsqlConnection(ordinary.ConnectionString); await connection.OpenAsync(ct).ConfigureAwait(false); }
            catch (PostgresException failure) when (failure.SqlState == "28000") { rejected = true; }
            if (!rejected) { throw CurrentAuthRepairPermit.Invalid(); }
        }
        RequireHealthy();
    }

    public async Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CurrentAuthRepairScope scope, CancellationToken ct)
    {
        RequireHealthy(); MatchScope(scope);
        await using (var inventory = Connection("postgres"))
        {
            await inventory.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await inventory.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ReadOnlyAsync(inventory, tx, ct).ConfigureAwait(false);
            await PostgreSqlCurrentAuthRepair.RequireInstalledPolicyAsync(inventory, tx, _scope, ct).ConfigureAwait(false);
            await using var command = new NpgsqlCommand("SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY datname COLLATE \"C\";", inventory, tx);
            var names = new List<string>();
            await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
            { while (await reader.ReadAsync(ct).ConfigureAwait(false)) { names.Add(reader.GetString(0)); } }
            if (!names.SequenceEqual(_expected.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal)) { throw CurrentAuthRepairPermit.Invalid(); }
            await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        var results = new List<CurrentAppOwnedDatabaseSnapshot>(); var pool = new CurrentAppOwnedSnapshotInternPool(); _pendingAfter = null;
        string? pending = null;
        foreach (CurrentAppOwnedDatabaseSnapshot expected in _baseline)
        {
            CurrentAuthRepairCapacity.Require(admission: false);
            await using var connection = Connection(expected.Database); await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ReadOnlyAsync(connection, tx, ct).ConfigureAwait(false);
            await PostgreSqlCurrentAuthRepair.RequireInstalledPolicyAsync(connection, tx, _scope, ct).ConfigureAwait(false);
            CurrentAuthNativeObservation? auth = expected.Database == "Auth" ? await CurrentAuthNativePreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false) : null;
            CurrentAppOwnedDatabaseSnapshot raw = pool.Intern(auth?.Snapshot ?? await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false));
            string hash = CurrentAppOwnedSnapshotSerialization.Sha256(raw);
            bool pendingAfter = expected.Database == "Auth" && _prepared?.AfterSha256 == hash;
            if (hash != (pendingAfter ? _prepared!.AfterSha256 : _expected[expected.Database])) { throw CurrentAuthRepairPermit.Invalid(); }
            if (auth is not null)
            {
                bool after = _terminal is not null || pendingAfter;
                if (after)
                {
                    if (_nativeBefore is null) { throw CurrentAuthRepairPermit.Invalid(); }
                    CurrentAuthNativePreservation.RequirePreserved(_nativeBefore, auth);
                    if (pendingAfter) { pending = hash; }
                }
                else { CurrentAuthNativePreservation.RequireBefore(auth); _nativeBefore ??= auth; }
            }
            if (DatabaseInventory.ActiveDatabases.Contains(expected.Database, StringComparer.Ordinal))
            { await RequirePhysicalAsync(connection, tx, _source.Databases.Single(x => x.Database == expected.Database), ct).ConfigureAwait(false); }
            await tx.RollbackAsync(ct).ConfigureAwait(false); results.Add(raw);
        }
        RequireHealthy(); _pendingAfter = pending; return results.AsReadOnly();
    }
    internal async Task<CurrentAuthNativeObservation> GetAuthPreimageAsync(CancellationToken ct)
    {
        _ = await InspectFleetAsync(_scope, ct).ConfigureAwait(false);
        return _reserved || _nativeBefore is null || _prepared is not null || _terminal is not null
            ? throw CurrentAuthRepairPermit.Invalid()
            : new(CurrentAuthRepairPermit.CopySnapshot(_nativeBefore.Snapshot), _nativeBefore.CopyTuples(), _nativeBefore.CopyStorage(), _nativeBefore.CopyExpressions());
    }
    public Task RequireFreshOperationAsync(CurrentAuthRepairScope scope, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); RequireHealthy(); MatchScope(scope);
        return _reserved || OperationNames().Length != 0 ? throw CurrentAuthRepairPermit.Invalid() : Task.CompletedTask;
    }
    public async Task ReserveFreshOperationAsync(CurrentAuthRepairScope scope, string authorizationSha256, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await RequireFreshOperationAsync(scope, ct).ConfigureAwait(false);
            if (authorizationSha256 != _authorization) { throw CurrentAuthRepairPermit.Invalid(); }
            await RetainCoreAsync(ReservationName, ReservationBytes(), ct).ConfigureAwait(false); _reserved = true;
        }
        catch { _failed = true; throw; }
        finally { _ = _gate.Release(); }
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
        _files.Require(); RequireInventory();
        if (name != Path.GetFileName(name) || payload.Length > 65536 || _retained.ContainsKey(name)) { throw CurrentAuthRepairPermit.Invalid(); }
        CurrentAuthRepairReceipt? receipt = null;
        if (name == ReservationName)
        {
            if (_reserved || _failed || !payload.AsSpan().SequenceEqual(ReservationBytes())) { throw CurrentAuthRepairPermit.Invalid(); }
        }
        else
        {
            receipt = MigrationConsole.DecodeAuthRepair<CurrentAuthRepairReceipt>(payload);
            PostgreSqlCurrentAuthRepair.RequireReceipt(receipt, _scope, _authorization, _trust, _pins, _chain.PreviousSha256, DateTimeOffset.UtcNow);
            bool failure = receipt.Classification is not (CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback);
            if (!_reserved || (_failed && !failure) || name != $"{_scope.OperationId:D}-Auth-{Suffix(receipt.Classification)}.json") { throw CurrentAuthRepairPermit.Invalid(); }
            if (receipt.Classification == CurrentAppOwnedCommitClassification.Prepared && (_prepared is not null || _terminal is not null || _nativeBefore is null))
            { throw CurrentAuthRepairPermit.Invalid(); }
            if (receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback &&
                (_prepared is null || _terminal is not null || receipt.AfterSha256 != _prepared.AfterSha256 || _pendingAfter != receipt.AfterSha256))
            { throw CurrentAuthRepairPermit.Invalid(); }
        }
        string path = Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, name);
        await _files.WriteNewAsync(path, payload, ct).ConfigureAwait(false);
        byte[] held = _files.Read(path, maximumBytes: 65536);
        if (!held.AsSpan().SequenceEqual(payload)) { throw CurrentAuthRepairPermit.Invalid(); }
        _retained.Add(name, held); RequireInventory(); _files.Require();
        if (receipt is not null && _scope.ProofAdmission == CurrentAuthProofAdmission.DisposableClosedConsoleBootstrap)
        {
            var seed = _scope.ClosedBootstrapSubject ?? throw CurrentAuthRepairPermit.Invalid();
            if (!DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(_scope.Target)) { throw CurrentAuthRepairPermit.Invalid(); }
            bool drop = !_closedAckFaultUsed &&
                ((seed.CaseId == "prepared-publication" && receipt.Classification == CurrentAppOwnedCommitClassification.Prepared) ||
                 (seed.CaseId == "terminal-publication" && receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback));
            if (drop)
            {
                _closedAckFaultUsed = true;
                // The bytes are durable, but neither publisher nor provider advances its
                // acknowledged predecessor. A later failure receipt is a genuine sibling.
                await _files.WriteNewAsync(Path.Combine(_authority.Binding.ArtifactRootCanonicalPath,
                    $"auth-closed-unacknowledged-{_scope.OperationId:N}-{Suffix(receipt.Classification)}.json"),
                    JsonSerializer.SerializeToUtf8Bytes(new { name, sha256 = CurrentAuthRepairPermit.Hash(held),
                        acknowledged = false, classification = receipt.Classification, observedAtUtc = DateTimeOffset.UtcNow }), ct).ConfigureAwait(false);
                _files.Require();
                throw new IOException("owned_disposable_auth_publication_ack_dropped");
            }
        }
        if (receipt is not null)
        {
            if (receipt.Classification is CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback)
            { _chain.RecordRetained(receipt, _scope, _authorization, _trust, _pins, DateTimeOffset.UtcNow); }
            if (receipt.Classification == CurrentAppOwnedCommitClassification.Prepared) { _prepared = receipt; _pendingAfter = null; }
            else if (receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback)
            { _terminal = receipt; _expected["Auth"] = receipt.AfterSha256!; _pendingAfter = null; }
            else { _failed = true; }
        }
    }
    internal void RequireTerminal(CurrentAuthRepairReceipt receipt)
    {
        RequireHealthy();
        if (_terminal != receipt || receipt.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback ||
            _retained.Keys.Any(x => x.EndsWith("failed-or-uncertain.json", StringComparison.Ordinal))) { throw CurrentAuthRepairPermit.Invalid(); }
    }
    internal static string Suffix(CurrentAppOwnedCommitClassification value)
    {
        return value switch
        {
            CurrentAppOwnedCommitClassification.Prepared => "prepared",
            CurrentAppOwnedCommitClassification.CommittedAndReadback => "committed-readback",
            CurrentAppOwnedCommitClassification.RolledBackBeforeCommit or CurrentAppOwnedCommitClassification.FailedBeforeCommit or CurrentAppOwnedCommitClassification.Uncertain => "failed-or-uncertain",
            _ => throw CurrentAuthRepairPermit.Invalid(),
        };
    }

    private string ReservationName => $"{_scope.OperationId:D}-auth-operation-start.json";
    private byte[] ReservationBytes()
    {
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            Kind = "current-auth-operation-start-v1",
            _scope.OperationId,
            ScopeSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(_scope),
            AuthorizationSha256 = _authorization
        });
    }

    private string[] OperationNames()
    {
        return Directory.EnumerateFileSystemEntries(_authority.Binding.ArtifactRootCanonicalPath)
            .Select(Path.GetFileName).Where(x => x is not null && x.StartsWith(_scope.OperationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase))
            .Select(x => x!).Order(StringComparer.Ordinal).ToArray();
    }

    private void RequireInventory()
    {
        if (!OperationNames().SequenceEqual(_retained.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal)) { throw CurrentAuthRepairPermit.Invalid(); }
    }
    private void RequireHealthy() { CurrentAuthRepairCapacity.Require(admission: false); _files.Require(); RequireInventory(); if (_failed) { throw CurrentAuthRepairPermit.Invalid(); } }
    private void MatchScope(CurrentAuthRepairScope scope)
    { if (JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(_scope)) { throw CurrentAuthRepairPermit.Invalid(); } }
    private NpgsqlConnection Connection(string database)
    {
        return new(new NpgsqlConnectionStringBuilder(_connection)
        { Database = database, Pooling = false, IncludeErrorDetail = false, Timeout = 5, CommandTimeout = 30, Options = "" }.ConnectionString);
    }

    private static async Task ReadOnlyAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken ct)
    { await using var command = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx); _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
    private static async Task RequirePhysicalAsync(NpgsqlConnection connection, NpgsqlTransaction tx, DatabaseSchemaPlan plan, CancellationToken ct)
    {
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
        if (await inspector.InspectSchemaAsync(plan, ct).ConfigureAwait(false) != plan.TargetSchemaSha256) { throw CurrentAuthRepairPermit.Invalid(); }
    }
    private async Task RequireSourceReadPolicyAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken ct)
    {
        // RequireAsync also runs while the exact provider writer is open. These readers
        // claim no zero-client observation; the writer checks zero other clients before
        // and after RequireAsync, and fleet capture checks it after writer retirement.
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
        await using var command = new NpgsqlCommand(sql, connection, tx);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        CurrentAppOwnedMaintenancePin m = _scope.Maintenance;
        if (!await reader.ReadAsync(ct).ConfigureAwait(false) || reader.GetString(0) != _scope.Target.SystemIdentifierSha256 ||
            reader.GetFieldValue<DateTimeOffset>(1) != m.Postmaster || reader.GetFieldValue<DateTimeOffset>(2) != m.ConfigLoaded ||
            reader.GetString(3) != m.Role || reader.GetString(4) != m.HbaSha256 || reader.GetString(5) != m.HbaRulesSha256 ||
            reader.GetFieldValue<DateTimeOffset>(6) != m.ExpiresAtUtc || reader.GetString(7) != m.RoleComment ||
            !reader.GetBoolean(8) || !reader.GetBoolean(9) || reader.GetBoolean(10) || reader.GetBoolean(11) || reader.GetBoolean(12) || reader.GetBoolean(13) ||
            reader.GetInt64(14) != 0 || !reader.GetBoolean(15) || reader.GetInt64(16) != 0 || reader.GetString(17) != m.HbaPath ||
            !reader.GetBoolean(18) || reader.GetInt64(19) != 0 || reader.GetInt64(20) != 0 || DateTimeOffset.UtcNow >= m.ExpiresAtUtc ||
            await reader.ReadAsync(ct).ConfigureAwait(false)) { throw CurrentAuthRepairPermit.Invalid(); }
        await reader.DisposeAsync().ConfigureAwait(false);
        await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, tx, m.Role, _scope.Target.Kind, ct).ConfigureAwait(false);
    }
    private Task<string> DockerAsync(IReadOnlyList<string> arguments, CancellationToken ct)
    {
        return CurrentAppOwnedRepairDockerProcess.RunDockerAsync(arguments, ct, RetainDockerFrameAsync);
    }

    private Task RetainDockerFrameAsync(CurrentAppOwnedDockerResource resource)
    {
        return FrameAsync("docker", resource);
    }

    private Task RetainGitFrameAsync(CurrentAuthGitResource resource)
    {
        return FrameAsync("git", resource);
    }

    private async Task FrameAsync<T>(string kind, T resource)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        string path = Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, $"resource-auth-{kind}-{Guid.NewGuid():N}.json");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new { _scope.OperationId, Resource = resource });
        await _files.WriteNewAsync(path, bytes, timeout.Token).ConfigureAwait(false);
        if (!_files.Read(path, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw CurrentAuthRepairPermit.Invalid(); }
    }
    internal static void RequireAuthDisposable(JsonElement container, JsonElement volume, Guid operation, string binding, DateTimeOffset now)
    {
        try
        {
            string name = "legacy-delta-proof-" + operation.ToString("N");
            JsonElement[] mounts = [.. container.GetProperty("Mounts").EnumerateArray()];
            DateTimeOffset created = container.GetProperty("Created").GetDateTimeOffset(), volumeCreated = volume.GetProperty("CreatedAt").GetDateTimeOffset();
            JsonElement options = volume.GetProperty("Options");
            if (operation == Guid.Empty || !CurrentAuthRepairPermit.HashShape(binding) || container.GetProperty("Name").GetString() != "/" + name ||
                mounts.Length != 1 || mounts[0].GetProperty("Type").GetString() != "volume" || mounts[0].GetProperty("Name").GetString() != name || !mounts[0].GetProperty("RW").GetBoolean() ||
                volume.GetProperty("Name").GetString() != name || (options.ValueKind != JsonValueKind.Null && (options.ValueKind != JsonValueKind.Object || options.EnumerateObject().Any())) ||
                created > now || volumeCreated > created || created < now.AddHours(-4) || volumeCreated < now.AddHours(-4)) { throw CurrentAuthRepairPermit.Invalid(); }
            Labels(container.GetProperty("Config").GetProperty("Labels")); Labels(volume.GetProperty("Labels"));
            void Labels(JsonElement labels)
            {
                if (labels.GetProperty("codex.repair.purpose").GetString() != "current-auth-repair-proof" ||
                    labels.GetProperty("codex.repair.operation").GetString() != operation.ToString("D") || labels.GetProperty("codex.repair.run-binding").GetString() != binding)
                { throw CurrentAuthRepairPermit.Invalid(); }
            }
        }
        catch (Exception failure) when (failure is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        { throw CurrentAuthRepairPermit.Invalid(); }
    }
    public void Dispose() { _cloud?.Dispose(); _gate.Dispose(); }
}

internal enum CurrentAuthGitCommand { Head = 1, Status = 2 }
internal sealed record CurrentAuthGitResource(Guid RunId, string Executable, string ExecutableSha256, int? ProcessId,
    long? StartUtcTicks, DateTimeOffset ExpiresAtUtc, bool Exited, bool ReadersSettled, bool CleanupFailed);

/// <summary>Fixed read-only owner checkout observation; no configured command, repo or executable.</summary>
internal static class CurrentAuthOwnerSourceReader
{
    private const string OwnerRoot = @"B:\maliev-legacy\Legacy.Maliev.AuthService";
    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(20), Cleanup = TimeSpan.FromSeconds(5);
    private const int OutputLimit = 1_000_000;
    internal static async Task RequireAsync(Func<CurrentAuthGitResource, Task> observe, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || File.Exists(Path.Combine(OwnerRoot, ".gitmodules"))) { throw CurrentAuthRepairPermit.Invalid(); }
        DateTimeOffset began = DateTimeOffset.UtcNow;
        string head = (await RunReadOnlyAsync(CurrentAuthGitCommand.Head, observe, ct).ConfigureAwait(false)).Trim();
        if (head != ApprovedCurrentAuthSchema.AuthServiceCommit || !string.IsNullOrWhiteSpace(
            await RunReadOnlyAsync(CurrentAuthGitCommand.Status, observe, ct).ConfigureAwait(false))) { throw CurrentAuthRepairPermit.Invalid(); }
        var held = new List<FileStream>();
        try
        {
            var actual = new List<CurrentAuthSourcePin>();
            foreach (CurrentAuthSourcePin pin in ApprovedCurrentAuthSchema.SourcePins())
            {
                string path = Path.GetFullPath(Path.Combine(OwnerRoot, pin.RelativePath));
                if (!path.StartsWith(OwnerRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) { throw CurrentAuthRepairPermit.Invalid(); }
                NoLinks(path);
                var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); held.Add(stream);
                if (stream.Length is < 1 or > 8 * 1024 * 1024) { throw CurrentAuthRepairPermit.Invalid(); }
                actual.Add(new(pin.RelativePath, Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false))));
            }
            ApprovedCurrentAuthSchema.RequireSourceObservation(head, true, actual, began, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(2));
            if ((await RunReadOnlyAsync(CurrentAuthGitCommand.Head, observe, ct).ConfigureAwait(false)).Trim() != head ||
                !string.IsNullOrWhiteSpace(await RunReadOnlyAsync(CurrentAuthGitCommand.Status, observe, ct).ConfigureAwait(false)))
            { throw CurrentAuthRepairPermit.Invalid(); }
            foreach (CurrentAuthSourcePin pin in ApprovedCurrentAuthSchema.SourcePins()) { NoLinks(Path.Combine(OwnerRoot, pin.RelativePath)); }
        }
        finally { foreach (FileStream stream in held) { stream.Dispose(); } }
    }
    private static void NoLinks(string path)
    {
        FileSystemInfo? current = new FileInfo(path);
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0) { throw CurrentAuthRepairPermit.Invalid(); }
            current = current is FileInfo file ? file.Directory : ((DirectoryInfo)current).Parent;
        }
    }
    internal static ProcessStartInfo StartInfo(CurrentAuthGitCommand command)
    {
        if (command is not (CurrentAuthGitCommand.Head or CurrentAuthGitCommand.Status)) { throw CurrentAuthRepairPermit.Invalid(); }
        string executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "cmd", "git.exe");
        var start = new ProcessStartInfo(executable)
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        start.Environment.Clear(); string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        start.Environment["SystemRoot"] = windows; start.Environment["WINDIR"] = windows;
        start.Environment["TEMP"] = Path.GetTempPath(); start.Environment["TMP"] = Path.GetTempPath();
        start.Environment["GIT_CONFIG_NOSYSTEM"] = "1"; start.Environment["GIT_CONFIG_GLOBAL"] = "NUL";
        start.Environment["GIT_TERMINAL_PROMPT"] = "0"; start.Environment["GIT_OPTIONAL_LOCKS"] = "0";
        foreach (string argument in new[] { "--no-optional-locks", "-C", OwnerRoot, "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false" })
        { start.ArgumentList.Add(argument); }
        foreach (string argument in command == CurrentAuthGitCommand.Head ? new[] { "rev-parse", "HEAD" } :
            ["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"]) { start.ArgumentList.Add(argument); }
        return start;
    }
    // Source tests exercise the exact fixed executable/repository/operations, not a generic command seam.
    internal static async Task<string> RunReadOnlyAsync(CurrentAuthGitCommand command, Func<CurrentAuthGitResource, Task> observe, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows()) { throw CurrentAuthRepairPermit.Invalid(); }
        ProcessStartInfo start = StartInfo(command); NoLinks(start.FileName); NoLinks(Path.Combine(OwnerRoot, ".git"));
        using var image = new FileStream(start.FileName, FileMode.Open, FileAccess.Read, FileShare.Read);
        string executableHash = Convert.ToHexStringLower(await SHA256.HashDataAsync(image, ct).ConfigureAwait(false));
        using var process = new Process { StartInfo = start };
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(Lifetime);
        using var readers = new CancellationTokenSource();
        CurrentAuthGitResource resource = new(Guid.NewGuid(), start.FileName, executableHash, null, null,
            DateTimeOffset.UtcNow.Add(Lifetime + Cleanup + Cleanup + TimeSpan.FromSeconds(20)), false, false, false);
        Task<string>? stdout = null, stderr = null; bool started = false;
        try
        {
            ct.ThrowIfCancellationRequested();
            if (!process.Start()) { throw CurrentAuthRepairPermit.Invalid(); }
            started = true; _ = process.SafeHandle;
            resource = resource with { ProcessId = process.Id };
            resource = resource with { StartUtcTicks = process.StartTime.ToUniversalTime().Ticks };
            await observe(resource).ConfigureAwait(false); ct.ThrowIfCancellationRequested();
            process.StandardInput.Close();
            stdout = ReadBoundedAsync(process.StandardOutput, readers.Token); stderr = ReadBoundedAsync(process.StandardError, readers.Token);
            Task exited = process.WaitForExitAsync(deadline.Token);
            var pending = new List<Task> { exited, stdout, stderr };
            while (pending.Count != 0)
            {
                Task completed = await Task.WhenAny(pending).WaitAsync(deadline.Token).ConfigureAwait(false);
                _ = pending.Remove(completed); await completed.ConfigureAwait(false);
            }
            string text = await stdout.ConfigureAwait(false);
            return process.ExitCode != 0 || (command == CurrentAuthGitCommand.Head && text.Length == 0)
                ? throw CurrentAuthRepairPermit.Invalid()
                : text;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw CurrentAuthRepairPermit.Invalid(); }
        finally
        {
            await CompleteCleanupAsync().ConfigureAwait(false);
        }

        async Task CompleteCleanupAsync()
        {
            Exception? failure = null;
            if (started)
            {
                try
                {
                    process.Refresh();
                    if ((resource.ProcessId is { } processId && process.Id != processId) ||
                        (resource.StartUtcTicks is { } startTicks && process.StartTime.ToUniversalTime().Ticks != startTicks))
                    { throw CurrentAuthRepairPermit.Invalid(); }
                    if (!process.HasExited)
                    {
                        try { process.Kill(); } catch (InvalidOperationException) when (process.HasExited) { }
                    }
                    await process.WaitForExitAsync(CancellationToken.None).WaitAsync(Cleanup, CancellationToken.None).ConfigureAwait(false);
                    if (!process.HasExited) { throw CurrentAuthRepairPermit.Invalid(); }
                    resource = resource with { Exited = true };
                }
                catch (Exception problem) when (problem is InvalidOperationException or System.ComponentModel.Win32Exception or TimeoutException or MigrationExecutionException)
                { failure = problem; }
            }
            await readers.CancelAsync().ConfigureAwait(false);
            if (started)
            {
                try { process.StandardInput.Dispose(); }
                catch (IOException problem) { failure ??= problem; }
                try { process.StandardOutput.Dispose(); }
                catch (IOException problem) { failure ??= problem; }
                try { process.StandardError.Dispose(); }
                catch (IOException problem) { failure ??= problem; }
            }
            try { await SettleAsync(stdout, stderr).WaitAsync(Cleanup, CancellationToken.None).ConfigureAwait(false); resource = resource with { ReadersSettled = true }; }
            catch (TimeoutException problem) { failure ??= problem; }
            resource = resource with { CleanupFailed = failure is not null };
            // A failed final immutable frame prevents success; cleanup already ran before this callback.
            await observe(resource).ConfigureAwait(false);
            if (failure is not null) { throw CurrentAuthRepairPermit.Invalid(); }
        }
    }
    private static async Task<string> ReadBoundedAsync(StreamReader reader, CancellationToken ct)
    {
        var text = new StringBuilder(4096); char[] buffer = new char[4096];
        while (true)
        {
            int count = await reader.ReadAsync(buffer.AsMemory(), ct).ConfigureAwait(false);
            if (count == 0) { return text.ToString(); }
            if (count > OutputLimit - text.Length) { throw CurrentAuthRepairPermit.Invalid(); }
            _ = text.Append(buffer, 0, count);
        }
    }
    private static async Task SettleAsync(params Task<string>?[] tasks)
    {
        foreach (Task<string>? task in tasks)
        {
            if (task is null) { continue; }
            try { _ = await task.ConfigureAwait(false); }
            catch (Exception failure) when (failure is OperationCanceledException or IOException or ObjectDisposedException or InvalidOperationException or MigrationExecutionException) { }
        }
    }
}
