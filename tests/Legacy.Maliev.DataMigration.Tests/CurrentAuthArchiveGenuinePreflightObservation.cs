using System.Data;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair
{
    private async Task RequireOwnedPreflightAsync(CancellationToken ct)
    {
        if (_disposed || _first is null || _second is null || _firstAuthority is null || _secondAuthority is null ||
            _firstFiles is null || _secondFiles is null || _firstPolicy is null || _secondPolicy is null || DateTimeOffset.UtcNow >= Scope.ExpiresAtUtc) { throw Invalid(); }
        _bundle.Require(); await _inputs.RequireAsync(ct);
        await _first.RequireHealthyHeldAsync(_firstAuthority, ct); await _second.RequireHealthyHeldAsync(_secondAuthority, ct);
        await CurrentAuthOwnerSourceReader.RequireAsync(resource => _inputs.ParentFiles.WriteNewAsync(Path.Combine(
            _inputs.ParentAuthority.Binding.ArtifactRootCanonicalPath, "preflight-owner-resource-" + Guid.NewGuid().ToString("N") + ".json"),
            JsonSerializer.SerializeToUtf8Bytes(resource), CancellationToken.None), ct);
        _firstFiles.Require(); _secondFiles.Require(); _bundle.Require();
    }

    private NpgsqlConnection PreflightConnection(bool comparison, string database)
    {
        var files = comparison ? _secondFiles : _firstFiles; var policy = comparison ? _secondPolicy : _firstPolicy;
        if (files is null || policy is null) { throw Invalid(); }
        var endpoint = new NpgsqlConnectionStringBuilder(Encoding.UTF8.GetString(files.Read(policy.OperatorConnectionPath, maximumBytes: 65536)))
        { Database = database, Pooling = false, Options = "", IncludeErrorDetail = false, Timeout = 5, CommandTimeout = 30 };
        return endpoint.Host != "127.0.0.1" || endpoint.Username != policy.Maintenance.Role || endpoint.Port is < 1 or > 65535 || string.IsNullOrWhiteSpace(endpoint.Password)
            ? throw Invalid()
            : new(endpoint.ConnectionString);
    }

    private async Task<CurrentAuthArchiveGenuinePreflightPolicy> ObservePreflightPolicyAsync(bool comparison, Guid operation, CancellationToken ct)
    {
        var policy = comparison ? Scope.ProductionObservationPolicy : Scope.LocalObservationPolicy;
        await using var connection = PreflightConnection(comparison, "Auth"); await connection.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await PreflightReadOnlyAsync(connection, transaction, ct);
        const string sql = """
            SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),pg_postmaster_start_time(),pg_conf_load_time(),
              current_setting('hba_file'),pg_read_file(current_setting('hba_file')),
              (SELECT jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text FROM pg_hba_file_rules h),
              NOT pg_is_in_recovery(),current_setting('transaction_read_only')='on',
              (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid()),
              (SELECT count(*) FROM pg_prepared_xacts),(SELECT count(*) FROM pg_event_trigger WHERE evtenabled<>'D'),
              current_setting('server_version_num')='180004',current_setting('server_encoding')='UTF8',current_user
            FROM pg_control_system();
            """;
        string system, path, hba, rules; DateTimeOffset postmaster, loaded; bool primary, readOnly; long clients, prepared, events;
        await using (var command = new NpgsqlCommand(sql, connection, transaction))
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            if (!await reader.ReadAsync(ct) || !reader.GetBoolean(11) || !reader.GetBoolean(12) || reader.GetString(13) != policy.Maintenance.Role) { throw Invalid(); }
            system = reader.GetString(0); postmaster = reader.GetFieldValue<DateTimeOffset>(1); loaded = reader.GetFieldValue<DateTimeOffset>(2);
            path = reader.GetString(3); hba = reader.GetString(4); rules = reader.GetString(5); primary = reader.GetBoolean(6); readOnly = reader.GetBoolean(7);
            clients = reader.GetInt64(8); prepared = reader.GetInt64(9); events = reader.GetInt64(10);
            if (await reader.ReadAsync(ct) || system != policy.Target.SystemIdentifierSha256 || path != policy.Maintenance.HbaPath || !readOnly || !primary || clients != 0 || prepared != 0 || events != 0) { throw Invalid(); }
        }
        var op = await RoleAsync(policy.Maintenance.Role); var ordinary = await RoleAsync("archive_denied_" + operation.ToString("N"));
        var unprobed = await RoleAsync(CurrentAuthArchiveGenuinePreflight.UnprobedRole(operation));
        await transaction.RollbackAsync(ct);
        return new(policy.Maintenance, system, postmaster, loaded, path, hba, rules, op ?? throw Invalid(), ordinary ?? throw Invalid(), unprobed,
            readOnly, primary, clients, prepared, events, DateTimeOffset.UtcNow);

        async Task<CurrentAuthArchiveGenuinePreflightRole?> RoleAsync(string name)
        {
            await using var command = new NpgsqlCommand("""
                SELECT r.oid,r.rolname,r.rolcanlogin,r.rolsuper,r.rolcreaterole,r.rolcreatedb,r.rolreplication,r.rolbypassrls,r.rolvaliduntil,
                  (SELECT count(*) FROM pg_auth_members WHERE member=r.oid),(SELECT count(*) FROM pg_default_acl WHERE defaclrole=r.oid),
                  a.rolpassword IS NOT NULL,coalesce(a.rolpassword LIKE 'SCRAM-SHA-256$%',false),encode(sha256(convert_to(to_jsonb(a)::text,'UTF8')),'hex')
                FROM pg_roles r JOIN pg_authid a ON a.oid=r.oid WHERE r.rolname=$1;
                """, connection, transaction);
            _ = command.Parameters.AddWithValue(name); await using var reader = await command.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) { return null; }
            var result = new CurrentAuthArchiveGenuinePreflightRole(reader.GetFieldValue<uint>(0), reader.GetString(1), reader.GetBoolean(2), reader.GetBoolean(3), reader.GetBoolean(4),
                reader.GetBoolean(5), reader.GetBoolean(6), reader.GetBoolean(7), reader.IsDBNull(8) ? null : reader.GetFieldValue<DateTimeOffset>(8), reader.GetInt64(9), reader.GetInt64(10),
                reader.GetBoolean(11), reader.GetBoolean(12), reader.GetString(13));
            return await reader.ReadAsync(ct) ? throw Invalid() : result;
        }
    }

    private async Task<CurrentAuthArchiveFleet> CapturePreflightFleetAsync(bool comparison, CancellationToken ct)
    {
        var policy = comparison ? Scope.ProductionObservationPolicy : Scope.LocalObservationPolicy;
        var before = await CatalogAsync(); DateTimeOffset began = DateTimeOffset.UtcNow;
        var snapshots = new List<CurrentAppOwnedDatabaseSnapshot>(); CurrentAuthLocalSessionArchiveObservation? auth = null;
        foreach (string database in policy.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))
        {
            CurrentAuthArchiveCapacity.Require(admission: false);
            await using var connection = PreflightConnection(comparison, database); await connection.OpenAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await PreflightReadOnlyAsync(connection, transaction, ct);
            if (database == "Auth")
            { auth = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, transaction, policy.RunBindingSha256, ct); snapshots.Add(auth.Native.Snapshot); }
            else { snapshots.Add(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, ct)); }
            var source = _inputs.Source.Databases.SingleOrDefault(item => item.Database == database);
            if (source is not null)
            {
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                if (await inspector.InspectSchemaAsync(source, ct) != source.TargetSchemaSha256) { throw Invalid(); }
            }
            await transaction.RollbackAsync(ct);
        }
        DateTimeOffset ended = DateTimeOffset.UtcNow; var after = await CatalogAsync();
        var catalogs = new CurrentAuthArchiveFleetCatalogs(before, after, began, ended);
        CurrentAuthLocalSessionArchivePolicy.RequireCatalogs(catalogs, policy, comparison, snapshots.Select(item => item.Database), before.BeganAtUtc, DateTimeOffset.UtcNow);
        return new(auth ?? throw Invalid(), snapshots.AsReadOnly(), began, ended, catalogs);

        async Task<CurrentAuthArchiveCatalogObservation> CatalogAsync()
        {
            await RequireOwnedPreflightAsync(ct);
            await using var connection = PreflightConnection(comparison, "postgres"); await connection.OpenAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct); await PreflightReadOnlyAsync(connection, transaction, ct);
            DateTimeOffset started = DateTimeOffset.UtcNow;
            await using var command = new NpgsqlCommand("SELECT d.datname,d.datistemplate,d.datallowconn,encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),current_setting('transaction_read_only')='on' FROM pg_database d CROSS JOIN pg_control_system() ORDER BY d.datname COLLATE \"C\";", connection, transaction);
            var flags = new List<ReviewedRepairDatabaseFlag>();
            await using (var reader = await command.ExecuteReaderAsync(ct))
            {
                while (await reader.ReadAsync(ct))
                { if (reader.GetString(3) != policy.Target.SystemIdentifierSha256 || !reader.GetBoolean(4)) { throw Invalid(); } flags.Add(new(reader.GetString(0), reader.GetBoolean(1), reader.GetBoolean(2))); }
            }
            ReviewedProductionRepairInventory.RequireComplete(CurrentAuthLocalSessionArchivePolicy.InventoryProfile(comparison), flags, policy.BeforeDatabaseSha256.Keys);
            await transaction.RollbackAsync(ct);
            return new(policy.RunBindingSha256, policy.TargetObservationSha256, policy.Target.SystemIdentifierSha256, true, flags.AsReadOnly(), started, DateTimeOffset.UtcNow);
        }
    }
    private static async Task PreflightReadOnlyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SET TRANSACTION READ ONLY; SET LOCAL timezone='UTC'; SET LOCAL datestyle='ISO, YMD'; SET LOCAL extra_float_digits=3;", connection, transaction); _ = await command.ExecuteNonQueryAsync(ct);
    }
}
