using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record IsoMaintenanceNativeObservation(string SystemIdentifierSha256, DateTimeOffset Postmaster,
    DateTimeOffset ConfigLoaded, string Role, bool Superuser, bool Login, bool CreateRole, bool CreateDatabase,
    bool Replication, bool BypassRls, DateTimeOffset ValidUntil, string Comment, bool Scram,
    long Memberships, long DefaultAcls, long OtherClients, long PreparedTransactions, long EventTriggers, bool Recovery,
    DateTimeOffset ObservedAtUtc);
internal static class IsoMaintenanceNativeObserver
{
    internal static async Task<IsoMaintenanceNativeObservation> CaptureAsync(string endpoint, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(endpoint) { Database = "postgres", Pooling = false }.ConnectionString);
        await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await using (var mode = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx)) { _ = await mode.ExecuteNonQueryAsync(ct); }
        await using var query = new NpgsqlCommand("""
            SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),pg_postmaster_start_time(),pg_conf_load_time(),
              current_user,rolsuper,rolcanlogin,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,rolvaliduntil,
              shobj_description(oid,'pg_authid'),rolpassword LIKE 'SCRAM-SHA-256$%',
              (SELECT count(*) FROM pg_auth_members WHERE roleid=r.oid OR member=r.oid),
              (SELECT count(*) FROM pg_default_acl WHERE defaclrole=r.oid),
              (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid()),
              (SELECT count(*) FROM pg_prepared_xacts),(SELECT count(*) FROM pg_event_trigger),pg_is_in_recovery()
            FROM pg_control_system(),pg_authid r WHERE rolname=current_user;
            """, connection, tx);
        IsoMaintenanceNativeObservation result;
        await using (var reader = await query.ExecuteReaderAsync(ct))
        {
            if (!await reader.ReadAsync(ct)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            result = new(reader.GetString(0), reader.GetFieldValue<DateTimeOffset>(1), reader.GetFieldValue<DateTimeOffset>(2), reader.GetString(3),
                reader.GetBoolean(4), reader.GetBoolean(5), reader.GetBoolean(6), reader.GetBoolean(7), reader.GetBoolean(8), reader.GetBoolean(9),
                reader.GetFieldValue<DateTimeOffset>(10), reader.GetString(11), reader.GetBoolean(12), reader.GetInt64(13), reader.GetInt64(14), reader.GetInt64(15), reader.GetInt64(16), reader.GetInt64(17), reader.GetBoolean(18), DateTimeOffset.UtcNow);
            if (await reader.ReadAsync(ct)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        }
        await tx.RollbackAsync(ct); return result;
    }
    internal static void Require(IsoMaintenanceNativeObservation actual, CurrentOwnerIsoRepairScope scope)
    {
        var pin = scope.Maintenance;
        if (actual.SystemIdentifierSha256 != scope.Target.SystemIdentifierSha256 || actual.Postmaster != pin.Postmaster || actual.ConfigLoaded != pin.ConfigLoaded || actual.Role != pin.Role ||
            !actual.Superuser || !actual.Login || actual.CreateRole || actual.CreateDatabase || actual.Replication || actual.BypassRls || actual.ValidUntil != pin.ExpiresAtUtc || actual.Comment != pin.RoleComment || !actual.Scram ||
            actual.Memberships != 0 || actual.DefaultAcls != 0 || actual.OtherClients != 0 || actual.PreparedTransactions != 0 || actual.EventTriggers != 0 || actual.Recovery || actual.ObservedAtUtc < pin.IssuedAtUtc || actual.ObservedAtUtc > pin.ExpiresAtUtc) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
    }
}
