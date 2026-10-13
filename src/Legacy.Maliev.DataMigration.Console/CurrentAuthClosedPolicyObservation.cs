using System.Data;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

// Observation only. This records the real installed policy; it grants no admission.
internal static class CurrentAuthClosedPolicyObservation
{
    internal static async Task CaptureAsync(CurrentAppOwnedRepairCustody files,
        CurrentAuthRepairConfiguration config, CurrentAuthRepairScope scope, string caseId, CancellationToken ct)
    {
        string root = Path.GetDirectoryName(config.ScopePath)!;
        string text = Encoding.UTF8.GetString(files.Read(config.OperatorConnectionPath, sharedReader: true, maximumBytes: 65536));
        var settings = new NpgsqlConnectionStringBuilder(text);
        if (settings.Host != "127.0.0.1" || settings.Username != scope.Maintenance.Role || settings.Pooling ||
            scope.ProofAdmission != CurrentAuthProofAdmission.DisposableClosedConsoleBootstrap ||
            scope.ClosedBootstrapSubject?.CaseId != caseId) { throw CurrentAuthRepairPermit.Invalid(); }
        DateTimeOffset observed;
        CurrentAuthProofPolicy policy;
        await using (var connection = new NpgsqlConnection(text))
        {
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await using (var readOnlyCommand = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx))
            { _ = await readOnlyCommand.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
            const string query = """
                SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),pg_postmaster_start_time(),pg_conf_load_time(),
                  rolvaliduntil,shobj_description(r.oid,'pg_authid'),rolsuper,rolcanlogin,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,
                  (SELECT rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE oid=r.oid),
                  (SELECT count(*) FROM pg_auth_members WHERE member=r.oid),(SELECT count(*) FROM pg_default_acl WHERE defaclrole=r.oid),
                  (SELECT count(*) FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND backend_type='client backend'),
                  (SELECT count(*) FROM pg_prepared_xacts),(SELECT count(*) FROM pg_event_trigger WHERE evtenabled<>'D'),
                  current_setting('hba_file'),NOT pg_is_in_recovery(),pg_read_file(current_setting('hba_file')),
                  (SELECT jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text FROM pg_hba_file_rules h)
                FROM pg_control_system(),pg_roles r WHERE rolname=current_user;
                """;
            await using var command = new NpgsqlCommand(query, connection, tx);
            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw CurrentAuthRepairPermit.Invalid(); }
            byte[] hba = Encoding.UTF8.GetBytes(reader.GetString(19)), rulesBytes = Encoding.UTF8.GetBytes(reader.GetString(20));
            if (hba.Length > 65536 || rulesBytes.Length > 65536) { throw CurrentAuthRepairPermit.Invalid(); }
            string hbaPath = Path.Combine(root, "closed-policy-hba.conf"), rulesPath = Path.Combine(root, "closed-policy-rules.json");
            using var document = JsonDocument.Parse(rulesBytes);
            CurrentAppOwnedMaintenanceHbaRule[] rules = [.. document.RootElement.EnumerateArray().Select(row => new CurrentAppOwnedMaintenanceHbaRule(
                row.GetProperty("rule_number").GetInt32(), row.GetProperty("type").GetString()!, Strings(row, "database"), Strings(row, "user_name"),
                Text(row, "address"), Text(row, "netmask"), row.GetProperty("auth_method").GetString()!, Strings(row, "options"), Text(row, "error")))];
            observed = DateTimeOffset.UtcNow;
            policy = new(scope, observed, reader.GetString(0), reader.GetFieldValue<DateTimeOffset>(1), reader.GetFieldValue<DateTimeOffset>(2),
                settings.Username!, reader.GetFieldValue<DateTimeOffset>(3), reader.GetString(4), reader.GetString(17),
                new(hbaPath, CurrentAuthRepairPermit.Hash(hba)), new(rulesPath, CurrentAuthRepairPermit.Hash(rulesBytes)), reader.GetBoolean(18),
                reader.GetBoolean(5), reader.GetBoolean(6), reader.GetBoolean(7), reader.GetBoolean(8), reader.GetBoolean(9), reader.GetBoolean(10),
                reader.GetBoolean(11), reader.GetInt64(12), reader.GetInt64(13), reader.GetInt64(14), reader.GetInt64(15), reader.GetInt64(16), rules);
            if (await reader.ReadAsync(ct).ConfigureAwait(false)) { throw CurrentAuthRepairPermit.Invalid(); }
            await reader.DisposeAsync().ConfigureAwait(false); await tx.RollbackAsync(ct).ConfigureAwait(false);
            await files.WriteNewAsync(hbaPath, hba, ct).ConfigureAwait(false);
            await files.WriteNewAsync(rulesPath, rulesBytes, ct).ConfigureAwait(false);
        }
        var attempts = new List<object>();
        string ordinary = Encoding.UTF8.GetString(files.Read(config.RejectedOrdinaryConnectionPath, sharedReader: true, maximumBytes: 65536));
        foreach (string database in scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))
        {
            CurrentAuthRepairCapacity.Require(admission: false); ct.ThrowIfCancellationRequested();
            var endpoint = new NpgsqlConnectionStringBuilder(ordinary) { Database = database, Pooling = false, Timeout = 3, CommandTimeout = 3, IncludeErrorDetail = false };
            if (endpoint.Host != settings.Host || endpoint.Port != settings.Port || endpoint.Username != "auth_closed_rejected" || !string.IsNullOrEmpty(endpoint.Options))
            { throw CurrentAuthRepairPermit.Invalid(); }
            DateTimeOffset began = DateTimeOffset.UtcNow; string? sqlState = null; bool admitted = false;
            await using (var connection = new NpgsqlConnection(endpoint.ConnectionString))
            {
                try { await connection.OpenAsync(ct).ConfigureAwait(false); admitted = true; }
                catch (PostgresException rejected) when (rejected.SqlState == "28000") { sqlState = rejected.SqlState; }
            }
            if (caseId != "host-unprobed-sdk" && (admitted || sqlState != "28000")) { throw CurrentAuthRepairPermit.Invalid(); }
            if (caseId == "host-unprobed-sdk" && !admitted) { throw CurrentAuthRepairPermit.Invalid(); }
            attempts.Add(new { database, beganAtUtc = began, observedAtUtc = DateTimeOffset.UtcNow, admitted, sqlState });
        }
        await files.WriteNewAsync(Path.Combine(root, "closed-policy.json"), JsonSerializer.SerializeToUtf8Bytes(policy), ct).ConfigureAwait(false);
        await files.WriteNewAsync(Path.Combine(root, "closed-ordinary-attempts.json"), JsonSerializer.SerializeToUtf8Bytes(attempts), ct).ConfigureAwait(false);
        files.Require();
    }
    private static string? Text(JsonElement row, string name) => row.GetProperty(name).ValueKind == JsonValueKind.Null ? null : row.GetProperty(name).GetString();
    private static string[] Strings(JsonElement row, string name) => row.GetProperty(name).ValueKind == JsonValueKind.Null ? [] : [.. row.GetProperty(name).EnumerateArray().Select(x => x.GetString()!)];
}
