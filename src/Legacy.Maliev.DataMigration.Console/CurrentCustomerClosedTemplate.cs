using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentCustomerClosedTemplateState(Guid OperationId, string BindingSha256,
    string SourceCommitSha, string Role, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc,
    string ContainerId, string Volume, string TargetGeneration, string HbaPath);

internal sealed record CurrentCustomerClosedTemplateCapture(CurrentCustomerClosedTemplateState State,
    DeltaTargetAuthority Target, CurrentAppOwnedRepairTargetPins TargetPins,
    CurrentAppOwnedMaintenancePin Maintenance, IReadOnlyDictionary<string, string> BeforeDatabaseSha256,
    string FleetSha256, string BaselinePath, string NativeBeforePath);

// Named disposable fixture preparation only; this class issues no Customer review, authorization or permit.
internal static class CurrentCustomerClosedTemplate
{
    private const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";
    internal static async Task<CurrentCustomerClosedTemplateState> PrepareAsync(CurrentAppOwnedRepairCustody files,
        LocalExecutionBinding binding, Guid operation, string containerId, FreshSchemaPlan source,
        string adminConnection, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: true); files.Require();
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        if (operation == Guid.Empty || !CurrentCustomerSequenceRepairPermit.HashShape(containerId) || source.SourceCommitSha != accepted ||
            source.Databases.Count != 23 || source.Databases.Sum(x => x.Tables.Count) != 100 || !ApprovedConsumerOverlaySelection.IsApproved(source) ||
            source.Databases.Any(x => x.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(x.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3)))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        ProductionSchemaCatalogInspector.ValidatePlan(source, DateTimeOffset.UtcNow);
        string root = binding.ArtifactRootCanonicalPath, volumeName = "legacy-delta-proof-" + operation.ToString("N");
        int frame = 0;
        Task ObserveDocker(CurrentAppOwnedDockerResource value)
        {
            return files.WriteNewAsync(Path.Combine(root,
            $"customer-template-docker-{value.RunId:N}-{Interlocked.Increment(ref frame):D5}.json"), JsonSerializer.SerializeToUtf8Bytes(value), CancellationToken.None);
        }

        string containerText = await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(
            ["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "container", containerId], ct, ObserveDocker).ConfigureAwait(false);
        string volumeText = await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(
            ["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "volume", volumeName], ct, ObserveDocker).ConfigureAwait(false);
        using var containerDocument = JsonDocument.Parse(containerText); using var volumeDocument = JsonDocument.Parse(volumeText);
        JsonElement container = containerDocument.RootElement.EnumerateArray().Single(), volume = volumeDocument.RootElement.EnumerateArray().Single();
        var endpoint = new NpgsqlConnectionStringBuilder(adminConnection);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 || endpoint.Database != "postgres" || endpoint.Username != "postgres" ||
            string.IsNullOrEmpty(endpoint.Password) || !string.IsNullOrEmpty(endpoint.Options) || endpoint.Pooling)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var observed = DockerLocalTargetObservation.Parse(containerText, volumeText, containerId, volumeName, endpoint.Port, persistent: false);
        CurrentCustomerSequenceRepairLocalTarget.RequireDisposableMetadata(container, volume, operation, binding.ComputeSha256(), DateTimeOffset.UtcNow);
        string consumers = await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(
            ["--host", "npipe:////./pipe/docker_engine", "ps", "--all", "--filter", "volume=" + volumeName, "--format", "{{.ID}}", "--no-trunc"], ct, ObserveDocker).ConfigureAwait(false);
        CurrentAppOwnedRepairLocalTarget.RequireVolumeConsumers(consumers, containerId);
        JsonElement host = container.GetProperty("HostConfig"); DateTimeOffset created = container.GetProperty("Created").GetDateTimeOffset();
        if (container.GetProperty("Id").GetString() != containerId || container.GetProperty("Name").GetString() != "/" + volumeName ||
            container.GetProperty("Config").GetProperty("Image").GetString() != Image ||
            !container.GetProperty("State").GetProperty("Running").GetBoolean() || created < DateTimeOffset.UtcNow.AddMinutes(-2) ||
            host.GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 || host.GetProperty("MemorySwap").GetInt64() != 512L * 1024 * 1024 ||
            host.GetProperty("NanoCpus").GetInt64() != 750_000_000 || observed.PgData != "/var/lib/postgresql/18/docker")
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        string role = "customer_closed_" + operation.ToString("N");
        DateTimeOffset issued = DateTimeOffset.UtcNow, expires = created.AddMinutes(8);
        expires = new(expires.Ticks - (expires.Ticks % 10), TimeSpan.Zero);
        if (expires <= issued) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct); lease.CancelAfter(expires - issued);
        var state = new CurrentCustomerClosedTemplateState(operation, binding.ComputeSha256(), accepted, role, issued, expires,
            containerId, volumeName, LocalDockerGenerationGuard.ComposeGeneration(observed), observed.PgData + "/pg_hba.conf");
        // Create-new state before effects prevents resuming/replaying partial seeding.
        await files.WriteNewAsync(Path.Combine(root, "customer-template-state.json"), JsonSerializer.SerializeToUtf8Bytes(state), lease.Token).ConfigureAwait(false);
        string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        string ordinaryPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        endpoint.Timeout = 5; endpoint.CommandTimeout = 30; endpoint.IncludeErrorDetail = false;
        await using (var connection = new NpgsqlConnection(endpoint.ConnectionString))
        {
            await connection.OpenAsync(lease.Token).ConfigureAwait(false);
            if (await ScalarAsync<string>(connection, "SHOW server_version;", lease.Token).ConfigureAwait(false) != "18.4" ||
                await ScalarAsync<string>(connection, "SHOW autovacuum;", lease.Token).ConfigureAwait(false) != "off" ||
                await ScalarAsync<long>(connection, "SELECT count(*) FROM pg_database WHERE NOT datistemplate;", lease.Token).ConfigureAwait(false) != 1 ||
                await ScalarAsync<long>(connection, "SELECT count(*) FROM pg_roles WHERE rolname IN ('legacy_local','customer_closed_rejected');", lease.Token).ConfigureAwait(false) != 0)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            await SqlAsync(connection, null, "SET password_encryption='scram-sha-256'; CREATE ROLE legacy_local NOLOGIN; CREATE ROLE " + Q(role) +
                " LOGIN SUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD '" + password + "' VALID UNTIL '" + expires.ToString("O", CultureInfo.InvariantCulture) +
                "'; COMMENT ON ROLE " + Q(role) + " IS 'legacy-maliev-current-customer-sequence-v1:" + binding.ComputeSha256() +
                "'; CREATE ROLE customer_closed_rejected LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD '" + ordinaryPassword + "';", lease.Token).ConfigureAwait(false);
            await SqlAsync(connection, null, "CREATE ROLE customer_closed_sdk LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;", lease.Token).ConfigureAwait(false);
            foreach (string database in DatabaseInventory.ActiveDatabases.Concat(["Auth", "legacy_local"]))
            { await SqlAsync(connection, null, "CREATE DATABASE " + Q(database) + " TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C';", lease.Token).ConfigureAwait(false); }
        }
        foreach (DatabaseSchemaPlan plan in source.Databases)
        {
            CurrentCustomerSequenceCapacity.Require(admission: false);
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(endpoint.ConnectionString) { Database = plan.Database }.ConnectionString);
            await connection.OpenAsync(lease.Token).ConfigureAwait(false); await using var tx = await connection.BeginTransactionAsync(lease.Token).ConfigureAwait(false);
            var physical = plan with { Tables = ApprovedConsumerColumnOverlayManifest.ComposePhysical(plan), TargetExtensionProfile = null, SourceDispositionProfile = null, SourceTableDispositions = [] };
            await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
            await inspector.ApplySchemaAsync(physical, lease.Token).ConfigureAwait(false); await inspector.FinalizeSchemaAsync(physical, lease.Token).ConfigureAwait(false);
            foreach (TableCopyPlan table in physical.Tables)
            { await SqlAsync(connection, tx, "ALTER TABLE " + Q(table.TargetSchema) + "." + Q(table.TargetTable) + " OWNER TO legacy_local;", lease.Token).ConfigureAwait(false); }
            if (plan.Database == "Customer")
            {
                // Fixture setup only, prior to baseline. The reviewed provider performs START1000.
                await SqlAsync(connection, tx, "ALTER SEQUENCE public.\"Customer_ID_seq\" START WITH 1; SELECT nextval('public.\"Customer_ID_seq\"');", lease.Token).ConfigureAwait(false);
            }
            await tx.CommitAsync(lease.Token).ConfigureAwait(false);
        }
        foreach (string database in DatabaseInventory.ActiveDatabases.Concat(["postgres", "legacy_local"]))
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(endpoint.ConnectionString) { Database = database }.ConnectionString);
            await connection.OpenAsync(lease.Token).ConfigureAwait(false);
            await SqlAsync(connection, null, "CREATE SCHEMA private; CREATE TABLE private.customer_closed_sentinel(id integer PRIMARY KEY,evidence text NOT NULL); INSERT INTO private.customer_closed_sentinel VALUES(1,'unchanged'); CREATE SEQUENCE private.customer_closed_allocation START WITH 77; SELECT nextval('private.customer_closed_allocation');", lease.Token).ConfigureAwait(false);
        }
        await CreateAuthAsync(new NpgsqlConnectionStringBuilder(endpoint.ConnectionString) { Database = "Auth" }.ConnectionString, lease.Token).ConfigureAwait(false);
        await files.WriteNewAsync(Path.Combine(root, "operator.txt"), Encoding.UTF8.GetBytes(new NpgsqlConnectionStringBuilder(endpoint.ConnectionString) { Username = role, Password = password }.ConnectionString), lease.Token).ConfigureAwait(false);
        await files.WriteNewAsync(Path.Combine(root, "ordinary.txt"), Encoding.UTF8.GetBytes(new NpgsqlConnectionStringBuilder(endpoint.ConnectionString) { Username = "customer_closed_rejected", Password = ordinaryPassword }.ConnectionString), lease.Token).ConfigureAwait(false);
        // Docker's host-port forwarding reaches PostgreSQL through the bridge. The exact
        // temporary role is allowed; the externally published port remains loopback only.
        string hba = "local all " + role + " scram-sha-256\nhost all " + role + " 0.0.0.0/0 scram-sha-256\nhost all " + role + " ::/0 scram-sha-256\nlocal all all reject\nhost all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n";
        await files.WriteNewAsync(Path.Combine(root, "exclusive-hba.conf"), Encoding.UTF8.GetBytes(hba), lease.Token).ConfigureAwait(false);
        // Actual Customer owner/source observation is mandatory in the public closed route before review.
        if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(lease.Token).ConfigureAwait(false) != accepted) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        files.Require(); return state;
    }

    internal static async Task InstallPolicyAsync(CurrentAppOwnedRepairCustody files, LocalExecutionBinding binding,
        CurrentCustomerClosedTemplateState state, string adminConnection, string caseId, CancellationToken ct)
    {
        RequireState(files, binding, state);
        if (caseId is not ("success" or "prepared-publication" or "lost-commit-ack" or "terminal-publication" or
            "host-unprobed-sdk" or "local-ordinary-trust" or "final-fleet" or "replay")) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        string hba = Encoding.UTF8.GetString(files.Read(Path.Combine(binding.ArtifactRootCanonicalPath, "exclusive-hba.conf"), sharedReader: true, maximumBytes: 65536));
        if (caseId == "host-unprobed-sdk") { hba = "host all customer_closed_sdk 0.0.0.0/0 trust\n" + hba; }
        if (caseId == "local-ordinary-trust") { hba = "local all all trust\n" + hba; }
        var endpoint = new NpgsqlConnectionStringBuilder(adminConnection);
        if (endpoint.Host != "127.0.0.1" || endpoint.Database != "postgres" || endpoint.Username != "postgres" ||
            endpoint.Pooling || !string.IsNullOrEmpty(endpoint.Options)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        _ = await RequireTargetAsync(files, binding, state, endpoint.Port, ct).ConfigureAwait(false);
        // Retain the admin connection only across the policy rewrite/reload. No admin
        // handle survives this method or enters the Console configuration.
        await using var connection = new NpgsqlConnection(endpoint.ConnectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);
        if (await ScalarAsync<string>(connection, "SHOW hba_file;", ct).ConfigureAwait(false) != state.HbaPath ||
            await ScalarAsync<string>(connection, "SHOW autovacuum;", ct).ConfigureAwait(false) != "off") { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        // hba consists only of the fixed grammar above and a generated identifier.
        // COPY TEXT escapes backslashes; each fixed physical rule is one actual row.
        string values = string.Join(',', hba.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => "('" + line.Replace("'", "''", StringComparison.Ordinal) + "')"));
        await SqlAsync(connection, null, "COPY (SELECT * FROM (VALUES " + values + ") AS h(line)) TO '" + state.HbaPath + "';", ct).ConfigureAwait(false);
        if (!await ScalarAsync<bool>(connection, "SELECT pg_reload_conf();", ct).ConfigureAwait(false)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        await files.WriteNewAsync(Path.Combine(binding.ArtifactRootCanonicalPath, "installed-hba.conf"), Encoding.UTF8.GetBytes(hba), ct).ConfigureAwait(false);
        RequireState(files, binding, state);
    }

    internal static async Task<CurrentCustomerClosedTemplateCapture> CaptureAsync(CurrentAppOwnedRepairCustody files,
        LocalExecutionBinding binding, CurrentCustomerClosedTemplateState state, FreshSchemaPlan source,
        bool unsafePolicyFixture, CancellationToken ct)
    {
        RequireState(files, binding, state); CurrentCustomerSequenceCapacity.Require(admission: true);
        if (source.SourceCommitSha != state.SourceCommitSha || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != state.SourceCommitSha)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        string root = binding.ArtifactRootCanonicalPath;
        string text = Encoding.UTF8.GetString(files.Read(Path.Combine(root, "operator.txt"), sharedReader: true, maximumBytes: 65536));
        var endpoint = new NpgsqlConnectionStringBuilder(text);
        if (endpoint.Host != "127.0.0.1" || endpoint.Username != state.Role || endpoint.Database != "postgres" || endpoint.Pooling || !string.IsNullOrEmpty(endpoint.Options))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
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
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            system = reader.GetString(0);
            maintenance = new(state.Role, reader.GetString(6), state.IssuedAtUtc, reader.GetFieldValue<DateTimeOffset>(5),
                reader.GetFieldValue<DateTimeOffset>(1), reader.GetFieldValue<DateTimeOffset>(2), reader.GetString(3), reader.GetString(4), reader.GetString(16));
            if (maintenance.ExpiresAtUtc != state.ExpiresAtUtc || maintenance.RoleComment != "legacy-maliev-current-customer-sequence-v1:" + binding.ComputeSha256() ||
                maintenance.HbaPath != state.HbaPath || !reader.GetBoolean(7) || !reader.GetBoolean(8) || reader.GetBoolean(9) || reader.GetBoolean(10) ||
                reader.GetBoolean(11) || reader.GetBoolean(12) || reader.GetInt64(13) != 0 || !reader.GetBoolean(14) || reader.GetInt64(15) != 0 ||
                !reader.GetBoolean(17) || reader.GetInt64(18) != 0 || reader.GetInt64(19) != 0 || reader.GetInt64(20) != 0 || await reader.ReadAsync(ct).ConfigureAwait(false))
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            await reader.DisposeAsync().ConfigureAwait(false);
            byte[] actualHba = Encoding.UTF8.GetBytes(await ScalarAsync<string>(connection, "SELECT pg_read_file(current_setting('hba_file'));", ct).ConfigureAwait(false));
            if (!actualHba.AsSpan().SequenceEqual(files.Read(Path.Combine(root, "installed-hba.conf"), sharedReader: true, maximumBytes: 65536))) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
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
            if (!actual.SequenceEqual(expected, StringComparer.Ordinal)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        var baseline = new List<CurrentAppOwnedDatabaseSnapshot>(); var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
        var pool = new CurrentAppOwnedSnapshotInternPool(); string nativePath = Path.Combine(root, "customer-template-native-before.json");
        foreach (string database in expected)
        {
            RequireState(files, binding, state); CurrentCustomerSequenceCapacity.Require(admission: false);
            DateTimeOffset began = DateTimeOffset.UtcNow;
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(text) { Database = database }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await SqlAsync(connection, tx, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
            CurrentAppOwnedDatabaseSnapshot snapshot;
            if (database == "Customer")
            {
                var native = await CurrentCustomerSequenceNativeObservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false);
                ApprovedCurrentCustomerSequenceDefinition.RequireBefore(native, "legacy_local"); snapshot = native.Snapshot;
                await files.WriteNewAsync(nativePath, JsonSerializer.SerializeToUtf8Bytes(native), ct).ConfigureAwait(false);
            }
            else { snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false); }
            DatabaseSchemaPlan? schema = source.Databases.SingleOrDefault(x => x.Database == database);
            if (schema is not null)
            {
                var physical = schema with { Tables = ApprovedConsumerColumnOverlayManifest.ComposePhysical(schema), TargetExtensionProfile = null, SourceDispositionProfile = null, SourceTableDispositions = [] };
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                if (await inspector.InspectSchemaAsync(physical, ct).ConfigureAwait(false) != physical.TargetSchemaSha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
            snapshot = pool.Intern(snapshot); baseline.Add(snapshot); hashes.Add(database, CurrentAppOwnedSnapshotSerialization.Sha256(snapshot));
            await tx.RollbackAsync(ct).ConfigureAwait(false);
            await files.WriteNewAsync(Path.Combine(root, "customer-template-capture-" + database + ".json"),
                JsonSerializer.SerializeToUtf8Bytes(new { database, StartedAtUtc = began, CompletedAtUtc = DateTimeOffset.UtcNow, Sha256 = hashes[database] }), ct).ConfigureAwait(false);
        }
        string baselinePath = Path.Combine(root, "customer-template-global-before.json");
        await files.WriteBaselineNewAsync(baselinePath, [.. baseline], ct).ConfigureAwait(false);
        var result = new CurrentCustomerClosedTemplateCapture(state, new(DeltaTargetAuthorityKind.LocalAspire,
            "aspire://legacy-postgres-main-local/disposable-" + state.ContainerId[..12], system), pins, maintenance, hashes,
            CurrentCustomerSequenceRepairPermit.FleetSha256(hashes), baselinePath, nativePath);
        await files.WriteNewAsync(Path.Combine(root, "customer-template-capture.json"), JsonSerializer.SerializeToUtf8Bytes(result), ct).ConfigureAwait(false);
        RequireState(files, binding, state); return result;
    }

    private static void RequireState(CurrentAppOwnedRepairCustody files, LocalExecutionBinding binding, CurrentCustomerClosedTemplateState state)
    {
        files.Require();
        if (state.OperationId == Guid.Empty || state.BindingSha256 != binding.ComputeSha256() || DateTimeOffset.UtcNow >= state.ExpiresAtUtc ||
            state.Volume != "legacy-delta-proof-" + state.OperationId.ToString("N") || state.HbaPath != "/var/lib/postgresql/18/docker/pg_hba.conf" ||
            !files.Read(Path.Combine(binding.ArtifactRootCanonicalPath, "customer-template-state.json"), sharedReader: true, maximumBytes: 65536).AsSpan()
                .SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(state))) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }

    private static async Task<CurrentAppOwnedRepairTargetPins> RequireTargetAsync(CurrentAppOwnedRepairCustody files,
        LocalExecutionBinding binding, CurrentCustomerClosedTemplateState state, int port, CancellationToken ct)
    {
        RequireState(files, binding, state); int frame = 0;
        Task Observe(CurrentAppOwnedDockerResource value)
        {
            return files.WriteNewAsync(Path.Combine(binding.ArtifactRootCanonicalPath,
            $"customer-template-contact-{value.RunId:N}-{Interlocked.Increment(ref frame):D5}.json"), JsonSerializer.SerializeToUtf8Bytes(value), CancellationToken.None);
        }

        Task<string> Docker(string[] args)
        {
            return CurrentAppOwnedRepairDockerProcess.RunDockerAsync(args, ct, Observe);
        }

        string containerText = await Docker(["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "container", state.ContainerId]).ConfigureAwait(false);
        string volumeText = await Docker(["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "volume", state.Volume]).ConfigureAwait(false);
        using var containers = JsonDocument.Parse(containerText); using var volumes = JsonDocument.Parse(volumeText);
        JsonElement container = containers.RootElement.EnumerateArray().Single(), volume = volumes.RootElement.EnumerateArray().Single();
        CurrentCustomerSequenceRepairLocalTarget.RequireDisposableMetadata(container, volume, state.OperationId, binding.ComputeSha256(), DateTimeOffset.UtcNow);
        var actual = DockerLocalTargetObservation.Parse(containerText, volumeText, state.ContainerId, state.Volume, port, persistent: false);
        if (container.GetProperty("Config").GetProperty("Image").GetString() != Image || LocalDockerGenerationGuard.ComposeGeneration(actual) != state.TargetGeneration)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        CurrentAppOwnedRepairLocalTarget.RequireVolumeConsumers(await Docker(["--host", "npipe:////./pipe/docker_engine", "ps", "--all", "--filter", "volume=" + state.Volume,
            "--format", "{{.ID}}", "--no-trunc"]).ConfigureAwait(false), state.ContainerId);
        string stat = await Docker(["--host", "npipe:////./pipe/docker_engine", "exec", state.ContainerId, "env", "TZ=UTC", "LC_ALL=C", "stat",
            "--printf=%d|%i|%f|%u|%g|%h|%s|%y|%z", "--", state.HbaPath]).ConfigureAwait(false);
        return new(state.ContainerId, state.Volume, container.GetProperty("Image").GetString(), Image, state.HbaPath,
            CurrentCustomerSequenceRepairPermit.Hash(Encoding.UTF8.GetBytes(stat)), null, null);
    }

    private static async Task CreateAuthAsync(string connectionText, CancellationToken ct)
    {
        // Retained unrelated Auth data is a fixture sentinel; this is not Auth closure proof.
        await using var connection = new NpgsqlConnection(connectionText); await connection.OpenAsync(ct).ConfigureAwait(false);
        await SqlAsync(connection, null, "CREATE SCHEMA private; CREATE TABLE private.retained_auth_sessions(id integer PRIMARY KEY,evidence text NOT NULL); INSERT INTO private.retained_auth_sessions VALUES(1,'unchanged'); CREATE SEQUENCE private.retained_auth_allocation START WITH 77; SELECT nextval('private.retained_auth_allocation');", ct).ConfigureAwait(false);
    }
    private static string Q(string text)
    {
        return "\"" + text.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    private static async Task SqlAsync(NpgsqlConnection connection, NpgsqlTransaction? tx, string text, CancellationToken ct)
    { await using var command = new NpgsqlCommand(text, connection, tx); _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string text, CancellationToken ct)
    { await using var command = new NpgsqlCommand(text, connection); return (T)(await command.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? throw CurrentCustomerSequenceRepairPermit.Invalid()); }
}
