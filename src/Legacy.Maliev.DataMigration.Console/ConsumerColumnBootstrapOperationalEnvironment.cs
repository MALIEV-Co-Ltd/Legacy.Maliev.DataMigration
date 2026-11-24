using System.Data;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Closed Console composition; observes resources and policy without provisioning persistent resources.</summary>
internal sealed class ConsumerColumnBootstrapOperationalEnvironment : IConsumerColumnBootstrapOperationalEnvironment, IDisposable
{
    private readonly WindowsLocalRunAuthority _authority;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly ConsumerColumnBootstrapOperationalScope _scope;
    private readonly FreshSchemaPlan _source;
    private readonly CurrentAppOwnedRepairTargetPins _target;
    private readonly string _ordinary;
    private readonly ConsumerColumnBootstrapOperationalConfiguration _config;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly CurrentAppOwnedRepairSigningPins _pins;
    private readonly ConsumerColumnBootstrapProofFixture? _fixture;
    private readonly ConsumerColumnBootstrapPersistentTarget? _persistent;
    private readonly ConsumerColumnBootstrapRehearsalAcceptance? _rehearsal;
    private readonly string? _sourceConnection;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, string> _committed = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _preparedAfter = new(StringComparer.Ordinal);
    private string _previous = new('0', 64);
    private string? _pending;
    private int _next;
    private bool _failed, _disposed;
    public string ConnectionString { get; }

    private ConsumerColumnBootstrapOperationalEnvironment(WindowsLocalRunAuthority authority, CurrentAppOwnedRepairCustody files,
        ConsumerColumnBootstrapOperationalScope scope, FreshSchemaPlan source, CurrentAppOwnedRepairTargetPins target, string connection,
        string ordinary, ConsumerColumnBootstrapOperationalConfiguration config, IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins,
        ConsumerColumnBootstrapProofFixture? fixture, ConsumerColumnBootstrapPersistentTarget? persistent = null,
        ConsumerColumnBootstrapRehearsalAcceptance? rehearsal = null, string? sourceConnection = null)
    {
        _authority = authority; _files = files; _scope = ConsumerColumnBootstrapOperationalContract.Copy(scope); _source = ConsumerColumnBootstrapOperationalContract.Copy(source);
        _target = ConsumerColumnBootstrapOperationalContract.Copy(target); ConnectionString = fixture?.FaultControl?.Route(connection) ?? connection; _ordinary = ordinary; _config = config; _trust = trust; _pins = pins;
        _fixture = fixture; _persistent = persistent; _rehearsal = rehearsal; _sourceConnection = sourceConnection;
    }

    internal static async Task<ConsumerColumnBootstrapOperationalEnvironment> CreateAsync(WindowsLocalRunAuthority authority, CurrentAppOwnedRepairCustody files,
        ConsumerColumnBootstrapOperationalScope scope, FreshSchemaPlan source, CurrentAppOwnedRepairTargetPins target, string connection,
        string ordinary, ConsumerColumnBootstrapOperationalConfiguration config, IReceiptAttestationTrustStore trust,
        CurrentAppOwnedRepairSigningPins pins, ConsumerColumnBootstrapProofFixture fixture, CancellationToken ct)
    {
        // No environment can be adopted from an arbitrary interface implementation or unprobed SDK host.
        // This authenticates the actual compiled Console bundle and protected-main/CI custody first.
        if (System.Reflection.Assembly.GetEntryAssembly() != typeof(ConsumerColumnBootstrapOperationalEnvironment).Assembly ||
            await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != scope.SourceCommitSha)
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        authority.ValidateHeld(); files.Require();
        fixture.Require(scope.OperationId, scope.RunBindingSha256, target.DockerContainerId!, target.DockerVolume!, target.DockerImageReference!);
        return fixture.SourceIdentitySha256 != scope.SourceIdentitySha256
            ? throw ConsumerColumnBootstrapOperationalContract.Invalid()
            : new(authority, files, scope, source, target, connection, ordinary, config, trust, pins, fixture);
    }

    internal static async Task<ConsumerColumnBootstrapOperationalEnvironment> CreatePersistentAsync(WindowsLocalRunAuthority authority, CurrentAppOwnedRepairCustody files,
        ConsumerColumnBootstrapOperationalScope scope, ConsumerColumnBootstrapSourceCapture capture, CurrentAppOwnedRepairTargetPins target,
        string connection, string ordinary, string sourceConnection, ConsumerColumnBootstrapOperationalConfiguration config,
        IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins, ConsumerColumnBootstrapRehearsalAcceptance rehearsal, CancellationToken ct)
    {
        if (System.Reflection.Assembly.GetEntryAssembly() != typeof(ConsumerColumnBootstrapOperationalEnvironment).Assembly ||
            scope.Mode != ConsumerColumnBootstrapOperationalMode.PersistentReviewed ||
            await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != scope.SourceCommitSha) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        capture.Require(scope.SourceCommitSha, scope.SourceIdentitySha256, DateTimeOffset.UtcNow);
        if (capture.FullPlanSha256 != scope.LogicalSourcePlanSha256 ||
            await ConsumerColumnBootstrapProofSourceCapture.ObserveIdentityAsync(sourceConnection, ct).ConfigureAwait(false) != scope.SourceIdentitySha256)
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        rehearsal.Require(scope, capture.Plan, pins, DateTimeOffset.UtcNow); authority.ValidateHeld(); files.Require();
        var persistent = new ConsumerColumnBootstrapPersistentTarget(target, files, authority.Binding.ArtifactRootCanonicalPath);
        return new(authority, files, scope, capture.Plan, target, connection, ordinary, config, trust, pins, null, persistent, rehearsal, sourceConnection);
    }

    internal static async Task<ConsumerColumnBootstrapOperationalEnvironment> CreateReviewObserverAsync(WindowsLocalRunAuthority authority,
        CurrentAppOwnedRepairCustody files, ConsumerColumnBootstrapOperationalScope scope, FreshSchemaPlan source, CurrentAppOwnedRepairTargetPins target,
        string connection, string ordinary, ConsumerColumnBootstrapOperationalConfiguration config, CancellationToken ct)
    {
        if (System.Reflection.Assembly.GetEntryAssembly() != typeof(ConsumerColumnBootstrapOperationalEnvironment).Assembly ||
            await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != scope.SourceCommitSha)
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        authority.ValidateHeld(); files.Require();
        // No creation lease, persistent observer, token or source credential is attached. Thus
        // RequireScopeAsync/operational admission always rejects this read-only policy observer.
        return new(authority, files, scope, source, target, connection, ordinary, config, new ReceiptAttestationTrustStore([]),
            new CurrentAppOwnedRepairSigningPins(string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty), null);
    }

    public async Task RequireScopeAsync(ConsumerColumnBootstrapOperationalScope scope, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this); ct.ThrowIfCancellationRequested();
        if (scope.Mode == ConsumerColumnBootstrapOperationalMode.OwnedForwardRecoveryCharacterization && (_fixture is null || !_fixture.AcceptsRecovery(scope)))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        if (_fixture is not null) { _fixture.Require(scope.OperationId, scope.RunBindingSha256, _target.DockerContainerId!, _target.DockerVolume!, _target.DockerImageReference!); }
        else
        {
            if (_persistent is null || _rehearsal is null || _sourceConnection is null) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            _rehearsal.Require(scope, _source, _pins, DateTimeOffset.UtcNow);
            if (await ConsumerColumnBootstrapProofSourceCapture.ObserveIdentityAsync(_sourceConnection, ct).ConfigureAwait(false) != scope.SourceIdentitySha256)
            { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        }
        ConsumerColumnBootstrapOperationalContract.RequireScope(scope, _source, DateTimeOffset.UtcNow);
        if (_failed || (_fixture is not null && scope.SourceIdentitySha256 != _fixture.SourceIdentitySha256) || JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(_scope) || _authority.Binding.ComputeSha256() != scope.RunBindingSha256 ||
            !filesEqualSource() || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != scope.SourceCommitSha)
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        _authority.ValidateHeld(); _files.Require();
        var endpoint = new NpgsqlConnectionStringBuilder(ConnectionString); var ordinary = new NpgsqlConnectionStringBuilder(_ordinary);
        int targetPort = _fixture?.RequireDataPort(endpoint.Port) ?? endpoint.Port;
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 || endpoint.Username != scope.Maintenance.Role ||
            string.IsNullOrWhiteSpace(endpoint.Password) || !string.IsNullOrEmpty(endpoint.Options) || ordinary.Host != endpoint.Host || ordinary.Port != targetPort ||
            string.IsNullOrWhiteSpace(ordinary.Username) || ordinary.Username == endpoint.Username || string.IsNullOrWhiteSpace(ordinary.Password) || !string.IsNullOrEmpty(ordinary.Options))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        ConsumerColumnBootstrapOperationalProof.Require(_files, scope, _config.NativePreparation, _config.RecoveryPreparation, _config.RolePreparation, ordinary.Username, DateTimeOffset.UtcNow, _rehearsal);
        if (_persistent is not null) { await _persistent.RequireAsync(scope, endpoint.Port, ct).ConfigureAwait(false); }
        else { await RequireTargetAsync(scope, targetPort, ct).ConfigureAwait(false); }
        try
        {
            await using var rejected = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_ordinary) { Database = "postgres", Pooling = false, Timeout = 3 }.ConnectionString);
            await rejected.OpenAsync(ct).ConfigureAwait(false);
            throw ConsumerColumnBootstrapOperationalContract.Invalid();
        }
        catch (PostgresException failure) when (failure.SqlState == PostgresErrorCodes.InvalidAuthorizationSpecification) { }

        bool filesEqualSource()
        {
            return SchemaPlanCanonicalizer.ComputeSha256(MigrationConsole.DecodeAuthRepair<FreshSchemaPlan>(
            _files.Read(_config.SourcePath, sharedReader: true, maximumBytes: 12 * 1024 * 1024))) == scope.LogicalSourcePlanSha256;
        }
    }

    public async Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> ObserveFleetAsync(ConsumerColumnBootstrapOperationalScope scope, CancellationToken ct)
    {
        await RequireScopeAsync(scope, ct).ConfigureAwait(false);
        if (_fixture?.FaultControl is { } fault) { await fault.BeforeFleetAsync(scope, ct).ConfigureAwait(false); }
        var result = new List<CurrentAppOwnedDatabaseSnapshot>();
        foreach (string database in scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(ConnectionString) { Database = database, Pooling = false }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction)) { _ = await readOnly.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
            await RequirePolicyAsync(connection, transaction, scope, ct).ConfigureAwait(false);
            if (scope.PreviouslyCompletedDatabaseSha256.ContainsKey(database))
            {
                var contract = ConsumerColumnBootstrapContract.Create(_source, scope.SourceCommitSha, DateTimeOffset.UtcNow);
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                if (await inspector.InspectSchemaAsync(contract.After(database), ct).ConfigureAwait(false) != contract.After(database).TargetSchemaSha256)
                { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            }
            var snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
            if (scope.PreviouslyCompletedDatabaseSha256.TryGetValue(database, out string? retained) && snapshot.Sha256 != retained)
            { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            result.Add(snapshot);
            await transaction.RollbackAsync(ct).ConfigureAwait(false);
        }
        // Actual catalog inventory: no unknown or missing database is silently left outside preservation.
        await using (var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(ConnectionString) { Database = "postgres", Pooling = false }.ConnectionString))
        {
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var command = new NpgsqlCommand("SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY datname COLLATE \"C\";", connection);
            var names = new List<string>(); await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false)) { names.Add(reader.GetString(0)); }
            if (!names.SequenceEqual(scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        }
        _fixture?.RecordFleet(result); return result.AsReadOnly();
    }

    public async Task ReserveExecutionAsync(ConsumerColumnBootstrapOperationalScope scope, string authorizationSha256, CancellationToken ct)
    {
        await RequireScopeAsync(scope, ct).ConfigureAwait(false);
        if (!ConsumerColumnBootstrapOperationalContract.IsHash(authorizationSha256)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        string path = Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, $"consumer-bootstrap-{scope.OperationId:N}-execution-reservation.json");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new
        { Kind = "consumer-column-bootstrap-disposable-reservation-v1", scope.OperationId, scope.ContractSha256, scope.RunBindingSha256, AuthorizationSha256 = authorizationSha256, ReservedAtUtc = DateTimeOffset.UtcNow });
        // CreateNew custody makes reservation survive process exit. Never erase or reuse this marker after failure or rollback.
        try { await _files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false); }
        catch (IOException failure)
        {
            _fixture?.FaultControl?.ReservationDenied(scope.OperationId, path, failure.HResult); throw;
        }
        if (!_files.Read(path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }

    public async Task RequirePolicyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, ConsumerColumnBootstrapOperationalScope scope, CancellationToken ct)
    {
        if (transaction.IsolationLevel is not (IsolationLevel.RepeatableRead or IsolationLevel.Serializable) || transaction.Connection != connection)
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        const string sql = """
            SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),pg_postmaster_start_time(),pg_conf_load_time(),current_user,
             encode(sha256(convert_to(pg_read_file(current_setting('hba_file')),'UTF8')),'hex'),
             (SELECT encode(sha256(convert_to(jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text,'UTF8')),'hex') FROM pg_hba_file_rules h),
             rolvaliduntil,shobj_description(r.oid,'pg_authid'),rolsuper,rolcanlogin,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,
             (SELECT count(*) FROM pg_auth_members WHERE member=r.oid),(SELECT rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE oid=r.oid),
             (SELECT count(*) FROM pg_default_acl WHERE defaclrole=r.oid),current_setting('hba_file'),NOT pg_is_in_recovery(),
             (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid()),
             (SELECT count(*) FROM pg_prepared_xacts),(SELECT count(*) FROM pg_event_trigger WHERE evtenabled<>'D'),
             current_setting('server_version_num')::int=$1,
             CASE WHEN $1=180007 THEN current_setting('composite_type_mismatch',true)='error'
                  WHEN $1=180004 THEN current_setting('composite_type_mismatch',true) IS NULL ELSE false END,
             ($2 OR current_setting('autovacuum')='off')
            FROM pg_control_system(),pg_roles r WHERE rolname=current_user;
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 30 };
        _ = command.Parameters.AddWithValue(_fixture?.Cohort.ServerVersion ?? _scope.NativePreimages[0].ProviderVersion);
        _ = command.Parameters.AddWithValue(_scope.Mode == ConsumerColumnBootstrapOperationalMode.PersistentReviewed);
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false); var m = scope.Maintenance;
        if (!await reader.ReadAsync(ct).ConfigureAwait(false) || reader.GetString(0) != scope.Target.SystemIdentifierSha256 ||
            reader.GetFieldValue<DateTimeOffset>(1) != m.Postmaster || reader.GetFieldValue<DateTimeOffset>(2) != m.ConfigLoaded || reader.GetString(3) != m.Role ||
            reader.GetString(4) != m.HbaSha256 || reader.GetString(5) != m.HbaRulesSha256 || reader.GetFieldValue<DateTimeOffset>(6) != m.ExpiresAtUtc || reader.GetString(7) != m.RoleComment ||
            !reader.GetBoolean(8) || !reader.GetBoolean(9) || reader.GetBoolean(10) || reader.GetBoolean(11) || reader.GetBoolean(12) || reader.GetBoolean(13) ||
            reader.GetInt64(14) != 0 || !reader.GetBoolean(15) || reader.GetInt64(16) != 0 || reader.GetString(17) != m.HbaPath || !reader.GetBoolean(18) ||
            reader.GetInt64(19) != 0 || reader.GetInt64(20) != 0 || reader.GetInt64(21) != 0 || !reader.GetBoolean(22) || !reader.GetBoolean(23) || !reader.GetBoolean(24) ||
            DateTimeOffset.UtcNow >= m.ExpiresAtUtc || await reader.ReadAsync(ct).ConfigureAwait(false)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        await reader.DisposeAsync().ConfigureAwait(false);
        await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, transaction, m.Role, scope.Target.Kind, ct).ConfigureAwait(false);
        await using var ordinary = new NpgsqlCommand("SELECT count(*)=1 FROM pg_roles WHERE rolname=$1 AND rolcanlogin AND NOT rolsuper;", connection, transaction);
        _ = ordinary.Parameters.AddWithValue(new NpgsqlConnectionStringBuilder(_ordinary).Username!);
        if (await ordinary.ExecuteScalarAsync(ct).ConfigureAwait(false) is not true) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }

    public Task<ConsumerColumnBootstrapProviderObservation> ObserveProviderAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    {
        return ConsumerColumnBootstrapProviderCapture.CaptureAsync(connection, transaction, ct);
    }

    public async Task RetainNativeWitnessAsync(ConsumerColumnBootstrapNativePhase phase, ConsumerColumnBootstrapPreservationObservation observation, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (_fixture is null)
        {
            if (_persistent is null || _rehearsal is null || observation.ContractSha256 != _scope.ContractSha256 ||
                !_scope.PendingDatabases.Contains(observation.LogicalDatabase, StringComparer.Ordinal)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(ConsumerColumnBootstrapNativeWitness.Capture(phase, observation));
            string path = Path.Combine(_authority.Binding.ArtifactRootCanonicalPath,
                $"consumer-bootstrap-{_scope.OperationId:N}-{observation.LogicalDatabase}-native-{(int)phase}.json");
            await _files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
            if (!_files.Read(path, sharedReader: true, maximumBytes: 64 * 1024 * 1024).AsSpan().SequenceEqual(bytes))
            { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            return;
        }
        _fixture.Require(_scope.OperationId, _scope.RunBindingSha256,
            _target.DockerContainerId!, _target.DockerVolume!, _target.DockerImageReference!);
        if (_fixture.FaultControl is { } fault) { fault.RecordNative(_scope, phase, observation); }
        else { _fixture.RecordNative(phase, observation); }
    }

    private async Task RequireTargetAsync(ConsumerColumnBootstrapOperationalScope scope, int port, CancellationToken ct)
    {
        string image = Cohort().ImageReference;
        string id = _target.DockerContainerId ?? throw ConsumerColumnBootstrapOperationalContract.Invalid();
        string volume = _fixture?.VolumeName ?? throw ConsumerColumnBootstrapOperationalContract.Invalid();
        if (id.Length != 64 || !id.All(char.IsAsciiHexDigitLower) || _target.CloudOptions is not null || _target.CloudObservation is not null ||
            _target.DockerVolume != volume || _target.DockerImageReference != image || _target.HbaPath != scope.Maintenance.HbaPath ||
            scope.Target.AuthorityId != "aspire://legacy-postgres-main-local/disposable-" + id[..12]) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        using var containers = JsonDocument.Parse(await DockerAsync(["inspect", id], ct).ConfigureAwait(false));
        using var volumes = JsonDocument.Parse(await DockerAsync(["volume", "inspect", volume], ct).ConfigureAwait(false));
        JsonElement container = containers.RootElement.EnumerateArray().Single(), disk = volumes.RootElement.EnumerateArray().Single();
        if (container.GetProperty("Name").GetString() != "/" + volume) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        string generation = ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(new
        { ContainerId = id, StartedAt = container.GetProperty("State").GetProperty("StartedAt").GetString(), ImageId = container.GetProperty("Image").GetString() }));
        JsonElement mount = container.GetProperty("Mounts").EnumerateArray().Single();
        if (container.GetProperty("Id").GetString() != id || container.GetProperty("Image").GetString() != _target.DockerImageId ||
            container.GetProperty("Config").GetProperty("Image").GetString() != image || !container.GetProperty("State").GetProperty("Running").GetBoolean() ||
            container.GetProperty("State").GetProperty("Restarting").GetBoolean() || container.GetProperty("State").GetProperty("OOMKilled").GetBoolean() ||
            disk.GetProperty("Name").GetString() != volume || mount.GetProperty("Name").GetString() != volume || mount.GetProperty("Type").GetString() != "volume" ||
            !mount.GetProperty("RW").GetBoolean() || mount.GetProperty("Destination").GetString() != "/var/lib/postgresql" ||
            disk.GetProperty("Driver").GetString() != "local" || disk.GetProperty("Scope").GetString() != "local" ||
            (disk.TryGetProperty("Options", out JsonElement options) && options.ValueKind != JsonValueKind.Null &&
                (options.ValueKind != JsonValueKind.Object || options.EnumerateObject().Any())) ||
            !DateTimeOffset.TryParse(disk.GetProperty("CreatedAt").GetString(), System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.RoundtripKind, out DateTimeOffset created) ||
            created > scope.Maintenance.IssuedAtUtc || created < scope.Maintenance.IssuedAtUtc.Subtract(TimeSpan.FromHours(2)) ||
            created > DateTimeOffset.UtcNow || DateTimeOffset.UtcNow - created > TimeSpan.FromHours(2))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        RequireLabels(container.GetProperty("Config").GetProperty("Labels")); RequireLabels(disk.GetProperty("Labels"));
        var host = container.GetProperty("HostConfig");
        if (host.GetProperty("Privileged").GetBoolean() || host.GetProperty("Memory").GetInt64() != 384L * 1024 * 1024 ||
            host.GetProperty("MemorySwap").GetInt64() != 384L * 1024 * 1024 || host.GetProperty("NanoCpus").GetInt64() != 500000000)
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        var binding = container.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp").EnumerateArray().Single();
        if (binding.GetProperty("HostIp").GetString() != "127.0.0.1" || binding.GetProperty("HostPort").GetString() != port.ToString(System.Globalization.CultureInfo.InvariantCulture))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        string consumers = await DockerAsync(["ps", "-a", "--filter", "volume=" + volume, "--format", "{{.ID}}", "--no-trunc"], ct).ConfigureAwait(false);
        CurrentAppOwnedRepairLocalTarget.RequireVolumeConsumers(consumers, id);
        var sanitized = JsonNode.Parse(container.GetRawText())!.AsObject(); _ = sanitized["Config"]!.AsObject().Remove("Env");
        string observed = ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(new { Container = sanitized, Volume = disk }));
        if (observed != scope.TargetObservationSha256 || generation != scope.TargetGeneration) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }

        void RequireLabels(JsonElement labels)
        {
            if (labels.GetProperty("codex.repair.purpose").GetString() != ConsumerColumnBootstrapOperationalContract.Purpose ||
                labels.GetProperty("codex.repair.operation").GetString() != _fixture!.OperationId.ToString("D") ||
                labels.GetProperty("codex.repair.run-binding").GetString() != scope.RunBindingSha256) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        }
    }

    private ConsumerColumnBootstrapProofCohort Cohort()
    {
        return _target.DockerImageReference switch
        {
            var image when image == ConsumerColumnBootstrapProofCohort.PostgreSql184.ImageReference => ConsumerColumnBootstrapProofCohort.PostgreSql184,
            var image when image == ConsumerColumnBootstrapProofCohort.PostgreSql187.ImageReference => ConsumerColumnBootstrapProofCohort.PostgreSql187,
            _ => throw ConsumerColumnBootstrapOperationalContract.Invalid(),
        };
    }

    private Task<string> DockerAsync(IReadOnlyList<string> args, CancellationToken ct)
    {
        return CurrentAppOwnedRepairDockerProcess.RunDockerAsync(args, ct, async resource =>
    {
        await _files.WriteNewAsync(Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, $"consumer-bootstrap-{_scope.OperationId:N}-process-{resource.RunId:N}-{Guid.NewGuid():N}.json"),
            JsonSerializer.SerializeToUtf8Bytes(resource), CancellationToken.None).ConfigureAwait(false);
        if (resource.CleanupFailed) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    });
    }

    public async Task RetainReceiptAsync(ConsumerColumnBootstrapOperationalReceipt receipt, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this); _files.Require();
            byte[] authorization = _files.Read(_config.AuthorizationPath, sharedReader: true, maximumBytes: 65536);
            if (_failed || _next >= _scope.PendingDatabases.Count || receipt.Kind != "consumer-column-bootstrap-receipt-v1" || receipt.OperationId != _scope.OperationId ||
                receipt.Database != _scope.PendingDatabases[_next] || receipt.ContractSha256 != _scope.ContractSha256 ||
                receipt.AuthorizationSha256 != ConsumerColumnBootstrapOperationalContract.Hash(authorization) || receipt.BeforeSha256 != _scope.BeforeDatabaseSha256[receipt.Database] ||
                receipt.PreviousReceiptSha256 != _previous || receipt.KeyId != _pins.ReceiptKeyId || receipt.Signature is null ||
                !_trust.TryGetPublicKeyFingerprintSha256(receipt.KeyId, out string fingerprint) || fingerprint != _pins.ReceiptFingerprint ||
                !_trust.Verify(receipt.KeyId, PostgreSqlConsumerColumnBootstrapRepair.ReceiptPayload(receipt), Convert.FromBase64String(receipt.Signature)))
            { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            bool prepared = receipt.Classification == CurrentAppOwnedCommitClassification.Prepared;
            bool committed = receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback;
            if (!Enum.IsDefined(receipt.Classification) || (prepared && _pending is not null) ||
                ((prepared || committed) && !ConsumerColumnBootstrapOperationalContract.IsHash(receipt.AfterSha256)) ||
                (committed && (_pending is null || receipt.AfterSha256 != _pending))) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            string phase = prepared ? "prepared" : committed ? "committed-readback" : "failed-or-uncertain";
            string path = Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, $"consumer-bootstrap-{_scope.OperationId:N}-{receipt.Database}-{phase}.json");
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(receipt);
            try { await _files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false); }
            catch (IOException failure) { _fixture?.FaultControl?.PublicationDenied(_scope.OperationId, failure.HResult); throw; }
            if (!_files.Read(path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            _previous = ConsumerColumnBootstrapOperationalContract.Hash(bytes);
            if (prepared) { _preparedAfter.Add(receipt.Database, receipt.AfterSha256!); _pending = receipt.AfterSha256; }
            else if (committed) { _committed.Add(receipt.Database, receipt.AfterSha256!); _pending = null; _next++; }
            else { _failed = true; }
            _fixture?.FaultControl?.ReceiptRetained(_scope, receipt);
        }
        finally { _ = _gate.Release(); }
    }

    public void Dispose() { if (_disposed) { return; } _disposed = true; _persistent?.Dispose(); _gate.Dispose(); }

    public async Task RetainRunReceiptAsync(ConsumerColumnBootstrapOperationalRunReceipt receipt, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this); _authority.ValidateHeld(); _files.Require();
            if (receipt.Kind != "consumer-column-bootstrap-run-receipt-v1" || receipt.OperationId != _scope.OperationId ||
                receipt.ContractSha256 != _scope.ContractSha256 || receipt.LogicalSourcePlanSha256 != _scope.LogicalSourcePlanSha256 ||
                receipt.AuthorizationSha256 != ConsumerColumnBootstrapOperationalContract.Hash(_files.Read(_config.AuthorizationPath, sharedReader: true, maximumBytes: 65536)) ||
                receipt.KeyId != _pins.ReceiptKeyId || receipt.Signature is null ||
                receipt.CommittedDatabaseSha256.Count != _committed.Count ||
                receipt.CommittedDatabaseSha256.Any(item => !_committed.TryGetValue(item.Key, out string? hash) || hash != item.Value) ||
                receipt.IndependentlyVerifiedReadbackSha256.Any(item => !_preparedAfter.TryGetValue(item.Key, out string? preparedHash) || preparedHash != item.Value) ||
                receipt.CommittedDatabaseSha256.Any(item => !receipt.IndependentlyVerifiedReadbackSha256.TryGetValue(item.Key, out string? readbackHash) || readbackHash != item.Value) ||
                !_trust.TryGetPublicKeyFingerprintSha256(receipt.KeyId, out string fingerprint) || fingerprint != _pins.ReceiptFingerprint ||
                !_trust.Verify(receipt.KeyId, PostgreSqlConsumerColumnBootstrapRepair.RunReceiptPayload(receipt), Convert.FromBase64String(receipt.Signature)) ||
                (receipt.Completed && (_failed || _pending is not null || _next != _scope.PendingDatabases.Count || receipt.LastDatabaseReceiptSha256 != _previous ||
                    receipt.CommittedDatabaseSha256.Count != _scope.PendingDatabases.Count || receipt.IndependentlyVerifiedReadbackSha256.Count != _scope.PendingDatabases.Count || !ConsumerColumnBootstrapOperationalContract.IsHash(receipt.FinalFleetSha256))) ||
                (!receipt.Completed && receipt.FinalFleetSha256 is not null))
            { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            string phase = receipt.Completed ? "run-completed" : "run-unfinished";
            string path = Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, $"consumer-bootstrap-{_scope.OperationId:N}-{phase}.json");
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(receipt);
            await _files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
            if (!_files.Read(path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            if (!receipt.Completed) { _failed = true; }
        }
        finally { _ = _gate.Release(); }
    }
}
