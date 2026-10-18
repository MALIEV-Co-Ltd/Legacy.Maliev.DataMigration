using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

internal static class IsoNamedClosedMaintenance
{
    internal static async Task<IsoInstalledFixturePolicy> InstallAsync(string admin, string bindingHash, string fault, DateTimeOffset fixtureExpires, CancellationToken ct)
    {
        const string role = "legacy_iso_native"; string password = Guid.NewGuid().ToString("N");
        DateTimeOffset issued = DateTimeOffset.UtcNow; DateTimeOffset expires = issued.AddMinutes(7) < fixtureExpires ? issued.AddMinutes(7) : fixtureExpires;
        expires = new DateTimeOffset(expires.UtcTicks - (expires.UtcTicks % 10), TimeSpan.Zero);
        if (expires <= issued) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        string comment = "legacy-maliev-current-owner-iso-v1:" + bindingHash;
        await using (var setup = new NpgsqlConnection(admin))
        {
            await setup.OpenAsync(ct);
            await IsoGuardedFleetFixture.Sql(setup, null, $"CREATE ROLE {role} LOGIN SUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{password}' VALID UNTIL '{expires:O}'; COMMENT ON ROLE {role} IS '{comment}';", ct);
            if (fault == "unsafe-host") { await IsoGuardedFleetFixture.Sql(setup, null, "CREATE ROLE iso_unprobed_sdk LOGIN;", ct); }
            await using var pathQuery = new NpgsqlCommand("SELECT current_setting('hba_file');", setup);
            string path = (string)(await pathQuery.ExecuteScalarAsync(ct) ?? throw CurrentOwnerIsoRepairPermit.Invalid());
            string local = fault == "local-trust" ? "trust" : "reject";
            string unsafeRule = fault == "unsafe-host" ? "('host all iso_unprobed_sdk 0.0.0.0/0 trust')," : string.Empty;
            await IsoGuardedFleetFixture.Sql(setup, null, $"COPY (VALUES ('host all {role} 0.0.0.0/0 scram-sha-256'),('host all {role} ::/0 scram-sha-256'),{unsafeRule}('local all all {local}'),('host all all 0.0.0.0/0 reject'),('host all all ::/0 reject')) TO '{path.Replace("'", "''", StringComparison.Ordinal)}'; SELECT pg_reload_conf();", ct);
        }
        bool ordinaryDenied = false;
        for (int attempt = 0; attempt < 40 && !ordinaryDenied; attempt++)
        {
            try { await using var probe = new NpgsqlConnection(admin); await probe.OpenAsync(ct); }
            catch (PostgresException error) when (error.SqlState == "28000") { ordinaryDenied = true; }
            if (!ordinaryDenied) { await Task.Delay(TimeSpan.FromMilliseconds(50), ct); }
        }
        if (!ordinaryDenied) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        string endpoint = new NpgsqlConnectionStringBuilder(admin) { Username = role, Password = password, Pooling = false }.ConnectionString;
        await using var observation = new NpgsqlConnection(endpoint); await observation.OpenAsync(ct);
        await using var query = new NpgsqlCommand("""
            SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),pg_postmaster_start_time(),pg_conf_load_time(),
              encode(sha256(convert_to(pg_read_file(current_setting('hba_file')),'UTF8')),'hex'),
              (SELECT encode(sha256(convert_to(jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text,'UTF8')),'hex') FROM pg_hba_file_rules h),
              current_setting('hba_file'),rolvaliduntil,pg_read_file(current_setting('hba_file')),
              (SELECT jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text FROM pg_hba_file_rules h)
            FROM pg_control_system(),pg_roles WHERE rolname=current_user;
            """, observation);
        await using var reader = await query.ExecuteReaderAsync(ct);
        return !await reader.ReadAsync(ct)
            ? throw CurrentOwnerIsoRepairPermit.Invalid()
            : new(endpoint, new(role, comment, issued, reader.GetFieldValue<DateTimeOffset>(6), reader.GetFieldValue<DateTimeOffset>(1),
            reader.GetFieldValue<DateTimeOffset>(2), reader.GetString(3), reader.GetString(4), reader.GetString(5)), reader.GetString(0), reader.GetString(7), reader.GetString(8));
    }
}
