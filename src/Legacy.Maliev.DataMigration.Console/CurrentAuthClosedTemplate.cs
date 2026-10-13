using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthClosedTemplateState(Guid OperationId, string BindingSha256,
    string SourceCommitSha, string Role, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc,
    string ContainerId, string Volume, string TargetGeneration, string HbaPath);

internal sealed record CurrentAuthClosedTemplateCapture(CurrentAuthClosedTemplateState State,
    DeltaTargetAuthority Target, CurrentAppOwnedRepairTargetPins TargetPins,
    CurrentAppOwnedMaintenancePin Maintenance, IReadOnlyDictionary<string, string> BeforeDatabaseSha256,
    string FleetSha256, string BaselinePath, string NativeBeforePath);

// Named disposable fixture preparation only; this class issues no Auth review, authorization or permit.
internal static class CurrentAuthClosedTemplate
{
    private const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";
    internal static async Task<CurrentAuthClosedTemplateState> PrepareAsync(CurrentAppOwnedRepairCustody files,
        LocalExecutionBinding binding, Guid operation, string containerId, FreshSchemaPlan source,
        string adminConnection, CancellationToken ct)
    {
        CurrentAuthRepairCapacity.Require(admission: true); files.Require();
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        if (operation == Guid.Empty || !CurrentAuthRepairPermit.HashShape(containerId) || source.SourceCommitSha != accepted ||
            source.Databases.Count != 23 || source.Databases.Sum(x => x.Tables.Count) != 100 || !ApprovedConsumerOverlaySelection.IsApproved(source) ||
            source.Databases.Any(x => x.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(x.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3)))
        { throw CurrentAuthRepairPermit.Invalid(); }
        ProductionSchemaCatalogInspector.ValidatePlan(source, DateTimeOffset.UtcNow);
        string root = binding.ArtifactRootCanonicalPath, volumeName = "legacy-delta-proof-" + operation.ToString("N");
        int frame = 0;
        Task ObserveDocker(CurrentAppOwnedDockerResource value) => files.WriteNewAsync(Path.Combine(root,
            $"auth-template-docker-{value.RunId:N}-{Interlocked.Increment(ref frame):D5}.json"), JsonSerializer.SerializeToUtf8Bytes(value), CancellationToken.None);
        Task ObserveOwner(CurrentAuthGitResource value) => files.WriteNewAsync(Path.Combine(root,
            $"auth-template-owner-{value.RunId:N}-{Interlocked.Increment(ref frame):D5}.json"), JsonSerializer.SerializeToUtf8Bytes(value), CancellationToken.None);
        await CurrentAuthOwnerSourceReader.RequireAsync(ObserveOwner, ct).ConfigureAwait(false);
        string containerText = await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(
            ["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "container", containerId], ct, ObserveDocker).ConfigureAwait(false);
        string volumeText = await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(
            ["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "volume", volumeName], ct, ObserveDocker).ConfigureAwait(false);
        using var containerDocument = JsonDocument.Parse(containerText); using var volumeDocument = JsonDocument.Parse(volumeText);
        JsonElement container = containerDocument.RootElement.EnumerateArray().Single(), volume = volumeDocument.RootElement.EnumerateArray().Single();
        var endpoint = new NpgsqlConnectionStringBuilder(adminConnection);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 || endpoint.Database != "postgres" || endpoint.Username != "postgres" ||
            string.IsNullOrEmpty(endpoint.Password) || !string.IsNullOrEmpty(endpoint.Options) || endpoint.Pooling)
        { throw CurrentAuthRepairPermit.Invalid(); }
        var observed = DockerLocalTargetObservation.Parse(containerText, volumeText, containerId, volumeName, endpoint.Port, persistent: false);
        CurrentAuthRepairEnvironment.RequireAuthDisposable(container, volume, operation, binding.ComputeSha256(), DateTimeOffset.UtcNow);
        string consumers = await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(
            ["--host", "npipe:////./pipe/docker_engine", "ps", "--all", "--filter", "volume=" + volumeName, "--format", "{{.ID}}", "--no-trunc"], ct, ObserveDocker).ConfigureAwait(false);
        CurrentAppOwnedRepairLocalTarget.RequireVolumeConsumers(consumers, containerId);
        JsonElement host = container.GetProperty("HostConfig"); DateTimeOffset created = container.GetProperty("Created").GetDateTimeOffset();
        if (container.GetProperty("Id").GetString() != containerId || container.GetProperty("Name").GetString() != "/" + volumeName ||
            container.GetProperty("Config").GetProperty("Image").GetString() != Image ||
            !container.GetProperty("State").GetProperty("Running").GetBoolean() || created < DateTimeOffset.UtcNow.AddMinutes(-2) ||
            host.GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 || host.GetProperty("MemorySwap").GetInt64() != 512L * 1024 * 1024 ||
            host.GetProperty("NanoCpus").GetInt64() != 750_000_000 || observed.PgData != "/var/lib/postgresql/18/docker")
        { throw CurrentAuthRepairPermit.Invalid(); }
        string role = "auth_closed_" + operation.ToString("N");
        DateTimeOffset issued = DateTimeOffset.UtcNow, expires = created.AddMinutes(8);
        expires = new(expires.Ticks - expires.Ticks % 10, TimeSpan.Zero);
        if (expires <= issued) { throw CurrentAuthRepairPermit.Invalid(); }
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct); lease.CancelAfter(expires - issued);
        var state = new CurrentAuthClosedTemplateState(operation, binding.ComputeSha256(), accepted, role, issued, expires,
            containerId, volumeName, LocalDockerGenerationGuard.ComposeGeneration(observed), observed.PgData + "/pg_hba.conf");
        // Create-new state before effects prevents resuming/replaying partial seeding.
        await files.WriteNewAsync(Path.Combine(root, "auth-template-state.json"), JsonSerializer.SerializeToUtf8Bytes(state), lease.Token).ConfigureAwait(false);
        string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        string ordinaryPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        endpoint.Timeout = 5; endpoint.CommandTimeout = 30; endpoint.IncludeErrorDetail = false;
        await using (var connection = new NpgsqlConnection(endpoint.ConnectionString))
        {
            await connection.OpenAsync(lease.Token).ConfigureAwait(false);
            if (await ScalarAsync<string>(connection, "SHOW server_version;", lease.Token).ConfigureAwait(false) != "18.4" ||
                await ScalarAsync<string>(connection, "SHOW autovacuum;", lease.Token).ConfigureAwait(false) != "off" ||
                await ScalarAsync<long>(connection, "SELECT count(*) FROM pg_database WHERE NOT datistemplate;", lease.Token).ConfigureAwait(false) != 1 ||
                await ScalarAsync<long>(connection, "SELECT count(*) FROM pg_roles WHERE rolname IN ('legacy_local','auth_closed_rejected');", lease.Token).ConfigureAwait(false) != 0)
            { throw CurrentAuthRepairPermit.Invalid(); }
            await SqlAsync(connection, null, "SET password_encryption='scram-sha-256'; CREATE ROLE legacy_local NOLOGIN; CREATE ROLE " + Q(role) +
                " LOGIN SUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD '" + password + "' VALID UNTIL '" + expires.ToString("O", CultureInfo.InvariantCulture) +
                "'; COMMENT ON ROLE " + Q(role) + " IS 'legacy-maliev-current-auth-v1:" + binding.ComputeSha256() +
                "'; CREATE ROLE auth_closed_rejected LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD '" + ordinaryPassword + "';", lease.Token).ConfigureAwait(false);
            foreach (string database in DatabaseInventory.ActiveDatabases.Concat(["Auth", "legacy_local"]))
            { await SqlAsync(connection, null, "CREATE DATABASE " + Q(database) + " TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C';", lease.Token).ConfigureAwait(false); }
        }
        foreach (DatabaseSchemaPlan plan in source.Databases)
        {
            CurrentAuthRepairCapacity.Require(admission: false);
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(endpoint.ConnectionString) { Database = plan.Database }.ConnectionString);
            await connection.OpenAsync(lease.Token).ConfigureAwait(false); await using var tx = await connection.BeginTransactionAsync(lease.Token).ConfigureAwait(false);
            var physical = plan with { Tables = ApprovedConsumerColumnOverlayManifest.ComposePhysical(plan), TargetExtensionProfile = null, SourceDispositionProfile = null, SourceTableDispositions = [] };
            await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
            await inspector.ApplySchemaAsync(physical, lease.Token).ConfigureAwait(false); await inspector.FinalizeSchemaAsync(physical, lease.Token).ConfigureAwait(false);
            await tx.CommitAsync(lease.Token).ConfigureAwait(false);
        }
        foreach (string database in DatabaseInventory.ActiveDatabases.Concat(["postgres", "legacy_local"]))
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(endpoint.ConnectionString) { Database = database }.ConnectionString);
            await connection.OpenAsync(lease.Token).ConfigureAwait(false);
            await SqlAsync(connection, null, "CREATE SCHEMA private; CREATE TABLE private.auth_closed_sentinel(id integer PRIMARY KEY,evidence text NOT NULL); INSERT INTO private.auth_closed_sentinel VALUES(1,'unchanged'); CREATE SEQUENCE private.auth_closed_allocation START WITH 77; SELECT nextval('private.auth_closed_allocation');", lease.Token).ConfigureAwait(false);
        }
        await CreateAuthAsync(new NpgsqlConnectionStringBuilder(endpoint.ConnectionString) { Database = "Auth" }.ConnectionString, lease.Token).ConfigureAwait(false);
        await files.WriteNewAsync(Path.Combine(root, "operator.txt"), Encoding.UTF8.GetBytes(new NpgsqlConnectionStringBuilder(endpoint.ConnectionString) { Username = role, Password = password }.ConnectionString), lease.Token).ConfigureAwait(false);
        await files.WriteNewAsync(Path.Combine(root, "ordinary.txt"), Encoding.UTF8.GetBytes(new NpgsqlConnectionStringBuilder(endpoint.ConnectionString) { Username = "auth_closed_rejected", Password = ordinaryPassword }.ConnectionString), lease.Token).ConfigureAwait(false);
        // Docker's host-port forwarding reaches PostgreSQL through the bridge. The exact
        // temporary role is allowed; the externally published port remains loopback only.
        string hba = "local all " + role + " scram-sha-256\nhost all " + role + " 0.0.0.0/0 scram-sha-256\nhost all " + role + " ::/0 scram-sha-256\nlocal all all reject\nhost all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n";
        await files.WriteNewAsync(Path.Combine(root, "exclusive-hba.conf"), Encoding.UTF8.GetBytes(hba), lease.Token).ConfigureAwait(false);
        await CurrentAuthOwnerSourceReader.RequireAsync(ObserveOwner, lease.Token).ConfigureAwait(false);
        if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(lease.Token).ConfigureAwait(false) != accepted) { throw CurrentAuthRepairPermit.Invalid(); }
        files.Require(); return state;
    }

    internal static async Task InstallPolicyAsync(CurrentAppOwnedRepairCustody files, LocalExecutionBinding binding,
        CurrentAuthClosedTemplateState state, string adminConnection, string caseId, CancellationToken ct)
    {
        RequireState(files, binding, state);
        if (caseId is not ("success" or "prepared-publication" or "lost-commit-ack" or "terminal-publication" or
            "host-unprobed-sdk" or "local-ordinary-trust" or "final-fleet" or "replay")) { throw CurrentAuthRepairPermit.Invalid(); }
        string hba = Encoding.UTF8.GetString(files.Read(Path.Combine(binding.ArtifactRootCanonicalPath, "exclusive-hba.conf"), maximumBytes: 65536));
        if (caseId == "host-unprobed-sdk") { hba = "host all auth_closed_rejected 0.0.0.0/0 trust\n" + hba; }
        if (caseId == "local-ordinary-trust") { hba = "local all all trust\n" + hba; }
        var endpoint = new NpgsqlConnectionStringBuilder(adminConnection);
        if (endpoint.Host != "127.0.0.1" || endpoint.Database != "postgres" || endpoint.Username != "postgres" ||
            endpoint.Pooling || !string.IsNullOrEmpty(endpoint.Options)) { throw CurrentAuthRepairPermit.Invalid(); }
        await RequireTargetAsync(files, binding, state, endpoint.Port, ct).ConfigureAwait(false);
        // Retain the admin connection only across the policy rewrite/reload. No admin
        // handle survives this method or enters the Console configuration.
        await using var connection = new NpgsqlConnection(endpoint.ConnectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);
        if (await ScalarAsync<string>(connection, "SHOW hba_file;", ct).ConfigureAwait(false) != state.HbaPath ||
            await ScalarAsync<string>(connection, "SHOW autovacuum;", ct).ConfigureAwait(false) != "off") { throw CurrentAuthRepairPermit.Invalid(); }
        // hba consists only of the fixed grammar above and a generated identifier.
        // COPY TEXT escapes backslashes; each fixed physical rule is one actual row.
        string values = string.Join(',', hba.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => "('" + line.Replace("'", "''", StringComparison.Ordinal) + "')"));
        await SqlAsync(connection, null, "COPY (SELECT * FROM (VALUES " + values + ") AS h(line)) TO '" + state.HbaPath + "';", ct).ConfigureAwait(false);
        if (!await ScalarAsync<bool>(connection, "SELECT pg_reload_conf();", ct).ConfigureAwait(false)) { throw CurrentAuthRepairPermit.Invalid(); }
        await files.WriteNewAsync(Path.Combine(binding.ArtifactRootCanonicalPath, "installed-hba.conf"), Encoding.UTF8.GetBytes(hba), ct).ConfigureAwait(false);
        RequireState(files, binding, state);
    }

    internal static async Task<CurrentAuthClosedTemplateCapture> CaptureAsync(CurrentAppOwnedRepairCustody files,
        LocalExecutionBinding binding, CurrentAuthClosedTemplateState state, FreshSchemaPlan source,
        bool unsafePolicyFixture, CancellationToken ct)
    {
        RequireState(files, binding, state); CurrentAuthRepairCapacity.Require(admission: true);
        if (source.SourceCommitSha != state.SourceCommitSha || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != state.SourceCommitSha)
        { throw CurrentAuthRepairPermit.Invalid(); }
        string root = binding.ArtifactRootCanonicalPath;
        string text = Encoding.UTF8.GetString(files.Read(Path.Combine(root, "operator.txt"), maximumBytes: 65536));
        var endpoint = new NpgsqlConnectionStringBuilder(text);
        if (endpoint.Host != "127.0.0.1" || endpoint.Username != state.Role || endpoint.Database != "postgres" || endpoint.Pooling || !string.IsNullOrEmpty(endpoint.Options))
        { throw CurrentAuthRepairPermit.Invalid(); }
        CurrentAppOwnedRepairTargetPins pins = await RequireTargetAsync(files, binding, state, endpoint.Port, ct).ConfigureAwait(false);
        CurrentAppOwnedMaintenancePin maintenance; string system;
        await using (var connection = new NpgsqlConnection(text))
        {
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await SqlAsync(connection, tx, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
            const string query = """
                SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),pg_postmaster_start_time(),pg_conf_load_time(),
                  encode(sha256(convert_to(pg_read_file(current_setting('hba_file')),'UTF8')),'hex'),
                  (SELECT encode(sha256(convert_to(jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text,'UTF8')),'hex') FROM pg_hba_file_rules h),
                  rolvaliduntil,shobj_description(r.oid,'pg_authid'),rolsuper,rolcanlogin,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,
                  (SELECT count(*) FROM pg_auth_members WHERE member=r.oid),(SELECT rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE oid=r.oid),
                  (SELECT count(*) FROM pg_default_acl WHERE defaclrole=r.oid),current_setting('hba_file'),NOT pg_is_in_recovery(),
                  (SELECT count(*) FROM pg_prepared_xacts),(SELECT count(*) FROM pg_event_trigger WHERE evtenabled<>'D'),
                  (SELECT count(*) FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND backend_type='client backend')
                FROM pg_control_system(),pg_roles r WHERE rolname=current_user;
                """;
            await using var command = new NpgsqlCommand(query, connection, tx);
            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw CurrentAuthRepairPermit.Invalid(); }
            system = reader.GetString(0);
            maintenance = new(state.Role, reader.GetString(6), state.IssuedAtUtc, reader.GetFieldValue<DateTimeOffset>(5),
                reader.GetFieldValue<DateTimeOffset>(1), reader.GetFieldValue<DateTimeOffset>(2), reader.GetString(3), reader.GetString(4), reader.GetString(16));
            if (maintenance.ExpiresAtUtc != state.ExpiresAtUtc || maintenance.RoleComment != "legacy-maliev-current-auth-v1:" + binding.ComputeSha256() ||
                maintenance.HbaPath != state.HbaPath || !reader.GetBoolean(7) || !reader.GetBoolean(8) || reader.GetBoolean(9) || reader.GetBoolean(10) ||
                reader.GetBoolean(11) || reader.GetBoolean(12) || reader.GetInt64(13) != 0 || !reader.GetBoolean(14) || reader.GetInt64(15) != 0 ||
                !reader.GetBoolean(17) || reader.GetInt64(18) != 0 || reader.GetInt64(19) != 0 || reader.GetInt64(20) != 0 || await reader.ReadAsync(ct).ConfigureAwait(false))
            { throw CurrentAuthRepairPermit.Invalid(); }
            await reader.DisposeAsync().ConfigureAwait(false);
            byte[] actualHba = Encoding.UTF8.GetBytes(await ScalarAsync<string>(connection, "SELECT pg_read_file(current_setting('hba_file'));", ct).ConfigureAwait(false));
            if (!actualHba.AsSpan().SequenceEqual(files.Read(Path.Combine(root, "installed-hba.conf"), maximumBytes: 65536))) { throw CurrentAuthRepairPermit.Invalid(); }
            if (!unsafePolicyFixture) { await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, tx, state.Role, DeltaTargetAuthorityKind.LocalAspire, ct).ConfigureAwait(false); }
            await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        string[] expected = [.. DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]).Order(StringComparer.Ordinal)];
        await using (var connection = new NpgsqlConnection(text))
        {
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var command = new NpgsqlCommand("SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY datname COLLATE \"C\";", connection);
            var actual = new List<string>(); await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false)) { actual.Add(reader.GetString(0)); }
            if (!actual.SequenceEqual(expected, StringComparer.Ordinal)) { throw CurrentAuthRepairPermit.Invalid(); }
        }
        var baseline = new List<CurrentAppOwnedDatabaseSnapshot>(); var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
        var pool = new CurrentAppOwnedSnapshotInternPool(); string nativePath = Path.Combine(root, "auth-template-native-before.json");
        foreach (string database in expected)
        {
            RequireState(files, binding, state); CurrentAuthRepairCapacity.Require(admission: false);
            DateTimeOffset began = DateTimeOffset.UtcNow;
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(text) { Database = database }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await SqlAsync(connection, tx, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
            CurrentAppOwnedDatabaseSnapshot snapshot;
            if (database == "Auth")
            {
                var native = await CurrentAuthNativePreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false);
                CurrentAuthNativePreservation.RequireBefore(native); snapshot = native.Snapshot;
                var artifact = new CurrentAuthProofNative(snapshot, native.CopyTuples(), native.CopyStorage().ToDictionary(x => x.Key,
                    x => new CurrentAuthProofStorage(x.Value.FileNode, x.Value.Blocks), StringComparer.Ordinal), native.CopyExpressions());
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(artifact);
                if (bytes.Length > 32 * 1024 * 1024) { throw CurrentAuthRepairPermit.Invalid(); }
                await files.WriteNewAsync(nativePath, bytes, ct).ConfigureAwait(false);
            }
            else { snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false); }
            DatabaseSchemaPlan? schema = source.Databases.SingleOrDefault(x => x.Database == database);
            if (schema is not null)
            {
                var physical = schema with { Tables = ApprovedConsumerColumnOverlayManifest.ComposePhysical(schema), TargetExtensionProfile = null, SourceDispositionProfile = null, SourceTableDispositions = [] };
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                if (await inspector.InspectSchemaAsync(physical, ct).ConfigureAwait(false) != physical.TargetSchemaSha256) { throw CurrentAuthRepairPermit.Invalid(); }
            }
            snapshot = pool.Intern(snapshot); baseline.Add(snapshot); hashes.Add(database, CurrentAppOwnedSnapshotSerialization.Sha256(snapshot));
            await tx.RollbackAsync(ct).ConfigureAwait(false);
            await files.WriteNewAsync(Path.Combine(root, "auth-template-capture-" + database + ".json"),
                JsonSerializer.SerializeToUtf8Bytes(new { database, StartedAtUtc = began, CompletedAtUtc = DateTimeOffset.UtcNow, Sha256 = hashes[database] }), ct).ConfigureAwait(false);
        }
        string baselinePath = Path.Combine(root, "auth-template-global-before.json");
        await files.WriteBaselineNewAsync(baselinePath, [.. baseline], ct).ConfigureAwait(false);
        var result = new CurrentAuthClosedTemplateCapture(state, new(DeltaTargetAuthorityKind.LocalAspire,
            "aspire://legacy-postgres-main-local/disposable-" + state.ContainerId[..12], system), pins, maintenance, hashes,
            CurrentAuthRepairPermit.FleetSha256(hashes), baselinePath, nativePath);
        await files.WriteNewAsync(Path.Combine(root, "auth-template-capture.json"), JsonSerializer.SerializeToUtf8Bytes(result), ct).ConfigureAwait(false);
        RequireState(files, binding, state); return result;
    }

    private static void RequireState(CurrentAppOwnedRepairCustody files, LocalExecutionBinding binding, CurrentAuthClosedTemplateState state)
    {
        files.Require();
        if (state.OperationId == Guid.Empty || state.BindingSha256 != binding.ComputeSha256() || DateTimeOffset.UtcNow >= state.ExpiresAtUtc ||
            state.Volume != "legacy-delta-proof-" + state.OperationId.ToString("N") || state.HbaPath != "/var/lib/postgresql/18/docker/pg_hba.conf" ||
            !files.Read(Path.Combine(binding.ArtifactRootCanonicalPath, "auth-template-state.json"), sharedReader: true, maximumBytes: 65536).AsSpan()
                .SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(state))) { throw CurrentAuthRepairPermit.Invalid(); }
    }

    private static async Task<CurrentAppOwnedRepairTargetPins> RequireTargetAsync(CurrentAppOwnedRepairCustody files,
        LocalExecutionBinding binding, CurrentAuthClosedTemplateState state, int port, CancellationToken ct)
    {
        RequireState(files, binding, state); int frame = 0;
        Task Observe(CurrentAppOwnedDockerResource value) => files.WriteNewAsync(Path.Combine(binding.ArtifactRootCanonicalPath,
            $"auth-template-contact-{value.RunId:N}-{Interlocked.Increment(ref frame):D5}.json"), JsonSerializer.SerializeToUtf8Bytes(value), CancellationToken.None);
        Task<string> Docker(string[] args) => CurrentAppOwnedRepairDockerProcess.RunDockerAsync(args, ct, Observe);
        string containerText = await Docker(["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "container", state.ContainerId]).ConfigureAwait(false);
        string volumeText = await Docker(["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "volume", state.Volume]).ConfigureAwait(false);
        using var containers = JsonDocument.Parse(containerText); using var volumes = JsonDocument.Parse(volumeText);
        JsonElement container = containers.RootElement.EnumerateArray().Single(), volume = volumes.RootElement.EnumerateArray().Single();
        CurrentAuthRepairEnvironment.RequireAuthDisposable(container, volume, state.OperationId, binding.ComputeSha256(), DateTimeOffset.UtcNow);
        var actual = DockerLocalTargetObservation.Parse(containerText, volumeText, state.ContainerId, state.Volume, port, persistent: false);
        if (container.GetProperty("Config").GetProperty("Image").GetString() != Image || LocalDockerGenerationGuard.ComposeGeneration(actual) != state.TargetGeneration)
        { throw CurrentAuthRepairPermit.Invalid(); }
        CurrentAppOwnedRepairLocalTarget.RequireVolumeConsumers(await Docker(["--host", "npipe:////./pipe/docker_engine", "ps", "--all", "--filter", "volume=" + state.Volume,
            "--format", "{{.ID}}", "--no-trunc"]).ConfigureAwait(false), state.ContainerId);
        string stat = await Docker(["--host", "npipe:////./pipe/docker_engine", "exec", state.ContainerId, "env", "TZ=UTC", "LC_ALL=C", "stat",
            "--printf=%d|%i|%f|%u|%g|%h|%s|%y|%z", "--", state.HbaPath]).ConfigureAwait(false);
        return new(state.ContainerId, state.Volume, container.GetProperty("Image").GetString(), Image, state.HbaPath,
            CurrentAuthRepairPermit.Hash(Encoding.UTF8.GetBytes(stat)), null, null);
    }

    private static async Task CreateAuthAsync(string connectionText, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(connectionText); await connection.OpenAsync(ct).ConfigureAwait(false);
        foreach (TableCopyPlan table in ApprovedCurrentAuthSchema.Tables(false))
        {
            var key = table.PrimaryKey ?? throw CurrentAuthRepairPermit.Invalid();
            string[] columns = [.. table.OrderedColumns.Select(name => Q(name) + " " + table.ColumnTypes[name] + (table.NullableColumns.Contains(name, StringComparer.Ordinal) ? "" : " NOT NULL"))];
            string[] checks = [.. table.CheckConstraints.Select(check => "CONSTRAINT " + Q(check.Name) + " CHECK (" + (check.Name == "CK_identity_action_tokens_employee_binding" ?
                "\"RecoveryVersion\" IS NULL OR (\"RecoveryVersion\" = 1 AND \"Purpose\" IN ('employee-password-reset', 'employee-email-confirmation') AND \"OriginalTokenSha256\" IS NOT NULL AND length(\"OriginalTokenSha256\") = 64 AND \"OwnerSubject\" IS NOT NULL AND length(\"OwnerSubject\") > 0 AND \"BoundNormalizedEmail\" IS NOT NULL AND length(\"BoundNormalizedEmail\") > 0 AND \"BoundSecurityStamp\" IS NOT NULL AND length(\"BoundSecurityStamp\") > 0)" : check.Expression) + ")")];
            await SqlAsync(connection, null, "CREATE TABLE public." + Q(table.TargetTable) + " (" + string.Join(',', columns.Append("CONSTRAINT " + Q(key.Name) + " PRIMARY KEY(" + string.Join(',', key.Columns.Select(Q)) + ")").Concat(checks)) + ");", ct).ConfigureAwait(false);
            foreach (IndexCopyPlan index in table.Indexes)
            { await SqlAsync(connection, null, "CREATE " + (index.Unique ? "UNIQUE " : "") + "INDEX " + Q(index.Name) + " ON public." + Q(table.TargetTable) + "(" + string.Join(',', index.Columns.Select(Q)) + ");", ct).ConfigureAwait(false); }
        }
        foreach (string migration in new[] { "20260715104357_InitialRefreshSessions", "20260715140429_AddIdentityActionTokens", "20260726184305_AddGoogleIdentityNonces", "20260727193121_AddIdentityActionTokenTargetEmail", "20260930125706_AddEmployeeRecoveryBinding" })
        {
            await using var command = new NpgsqlCommand("INSERT INTO public.\"__EFMigrationsHistory\" VALUES($1,$2);", connection);
            _ = command.Parameters.AddWithValue(migration); _ = command.Parameters.AddWithValue("10.0.12"); _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        await SqlAsync(connection, null, """
            CREATE SCHEMA private; CREATE TABLE private.journal(id integer PRIMARY KEY,evidence text NOT NULL);
            INSERT INTO private.journal VALUES(1,'synthetic immutable journal'); CREATE SEQUENCE private.allocation START WITH 77; SELECT nextval('private.allocation');
            INSERT INTO public.refresh_sessions VALUES
            ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000010','ไทย '' \\',1,NULL,'session-one',
            timestamptz '2000-01-01 01:02:03.123456+00',timestamptz '2000-01-02 01:02:03+00',NULL,NULL,NULL),
            ('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000020','synthetic-two',2,'ไทย stamp','session-two',
            timestamptz '2001-01-01 01:02:03+00',timestamptz '2001-01-02 01:02:03+00',timestamptz '2001-01-01 02:02:03+00',timestamptz '2001-01-01 03:02:03+00','00000000-0000-0000-0000-000000000003');
            INSERT INTO public.google_identity_nonces VALUES ('00000000-0000-0000-0000-000000000030','nonce-one','ไทย service','synthetic',now(),now());
            INSERT INTO public.identity_action_tokens("Id","IdentityId","TokenHash","Purpose","CreatedAt","ExpiresAt") VALUES
              ('00000000-0000-0000-0000-000000000040','ไทย','action-one','synthetic',now(),now()),
              ('00000000-0000-0000-0000-000000000041','ไทย','action-two','synthetic',now(),now());
            INSERT INTO public.identity_action_tokens("Id","IdentityId","TokenHash","Purpose","CreatedAt","ExpiresAt",
              "ConsumedAt","TargetEmail","BoundNormalizedEmail","BoundSecurityStamp","EffectActionId","FinalizedAt",
              "OriginalTokenSha256","OwnerSubject","RecoveryVersion") VALUES
              ('00000000-0000-0000-0000-000000000046','synthetic-employee','action-bound','employee-password-reset',now(),now(),
               now(),'synthetic@example.invalid','SYNTHETIC@EXAMPLE.INVALID','ไทย stamp','00000000-0000-0000-0000-000000000046',now(),
               repeat('a',64),'ไทย synthetic owner',1);
            """, ct).ConfigureAwait(false);
    }
    private static string Q(string text) => "\"" + text.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    private static async Task SqlAsync(NpgsqlConnection connection, NpgsqlTransaction? tx, string text, CancellationToken ct)
    { await using var command = new NpgsqlCommand(text, connection, tx); _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string text, CancellationToken ct)
    { await using var command = new NpgsqlCommand(text, connection); return (T)(await command.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? throw CurrentAuthRepairPermit.Invalid()); }
}
