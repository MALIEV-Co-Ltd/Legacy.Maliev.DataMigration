using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal static class DualTargetNativeProofPolicy
{
    internal static async Task<CurrentAppOwnedMaintenancePin> InstallAsync(DualTargetNativeProofClone clone, DateTimeOffset expires, CancellationToken ct)
    {
        await clone.RequireOwnedAsync(ct).ConfigureAwait(false);
        string role = "delta_proof_" + clone.Operation.ToString("N"), password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        DateTimeOffset issued = new(DateTimeOffset.UtcNow.Ticks / 10 * 10, TimeSpan.Zero);
        expires = new(expires.Ticks / 10 * 10, TimeSpan.Zero);
        if (expires <= issued || expires - issued > TimeSpan.FromMinutes(8)) { throw DualTargetNativeProofPreimage.Invalid(); }
        string comment = "legacy-maliev-dual-target-native-proof-v1:" + clone.Binding.ComputeSha256();
        string hba = "local all " + role + " scram-sha-256\nhost all " + role + " 0.0.0.0/0 scram-sha-256\nhost all " + role +
            " ::/0 scram-sha-256\nlocal all all reject\nhost all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n";
        string path;
        await using (var admin = new NpgsqlConnection(clone.AdminConnection))
        {
            await admin.OpenAsync(ct).ConfigureAwait(false);
            path = await DualTargetNativeProofLogicalCapture.ScalarAsync(admin, null, "SHOW hba_file;", ct).ConfigureAwait(false);
            if (path != "/var/lib/postgresql/18/docker/pg_hba.conf") { throw DualTargetNativeProofPreimage.Invalid(); }
            string sql = "SET password_encryption='scram-sha-256'; CREATE ROLE " + role +
                " LOGIN SUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + password +
                "' VALID UNTIL '" + expires.ToString("O", CultureInfo.InvariantCulture) + "'; COMMENT ON ROLE " + role + " IS '" + comment + "';";
            await DualTargetNativeProofLogicalCapture.ExecuteAsync(admin, null, sql, ct).ConfigureAwait(false);
            string values = string.Join(',', hba.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(x => "('" + x + "')"));
            await DualTargetNativeProofLogicalCapture.ExecuteAsync(admin, null, "COPY (SELECT * FROM (VALUES " + values + ") h(line)) TO '" + path + "';", ct).ConfigureAwait(false);
            if (await DualTargetNativeProofLogicalCapture.ScalarAsync(admin, null, "SELECT pg_reload_conf();", ct).ConfigureAwait(false) != "True") { throw DualTargetNativeProofPreimage.Invalid(); }
        }
        bool retired = false;
        for (int attempt = 0; attempt < 40 && !retired; attempt++)
        {
            try { await using var old = new NpgsqlConnection(clone.AdminConnection); await old.OpenAsync(ct).ConfigureAwait(false); }
            catch (PostgresException rejected) when (rejected.SqlState == "28000") { retired = true; }
            if (!retired) { await Task.Delay(50, ct).ConfigureAwait(false); }
        }
        if (!retired) { throw DualTargetNativeProofPreimage.Invalid(); }
        string operationConnection = new NpgsqlConnectionStringBuilder(clone.AdminConnection) { Username = role, Password = password }.ConnectionString;
        clone.RetireAdministrator(operationConnection);
        await using var connection = new NpgsqlConnection(operationConnection); await connection.OpenAsync(ct).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
        await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, tx, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
        CurrentAppOwnedMaintenancePin pin;
        await using (var query = new NpgsqlCommand("""
            SELECT pg_postmaster_start_time(),pg_conf_load_time(),pg_read_file(current_setting('hba_file')),
              (SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY rule_number),'[]')::text FROM pg_hba_file_rules r);
            """, connection, tx))
        await using (var reader = await query.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(ct).ConfigureAwait(false) || reader.GetString(2) != hba) { throw DualTargetNativeProofPreimage.Invalid(); }
            pin = new(role, comment, issued, expires, reader.GetFieldValue<DateTimeOffset>(0), reader.GetFieldValue<DateTimeOffset>(1),
                DualTargetNativeProofPreimage.HashBytes(Encoding.UTF8.GetBytes(hba)), DualTargetNativeProofPreimage.HashBytes(Encoding.UTF8.GetBytes(reader.GetString(3))), path);
        }
        string system = await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, tx,
            "SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex') FROM pg_control_system();", ct).ConfigureAwait(false);
        await DualTargetCapturedDeltaMaintenance.RequireInstalledAsync(connection, tx,
            new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/disposable-" + clone.ContainerId[..12], system), pin, ct).ConfigureAwait(false);
        await tx.RollbackAsync(ct).ConfigureAwait(false);
        return pin;
    }
}
