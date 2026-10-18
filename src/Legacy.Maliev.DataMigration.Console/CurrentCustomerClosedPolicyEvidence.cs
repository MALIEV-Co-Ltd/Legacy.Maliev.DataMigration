using System.Data;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CustomerClosedPolicy(CurrentCustomerSequenceProofPolicy Native,
    IReadOnlyList<string> RejectedOrdinaryDatabases, bool SemanticPolicyAccepted, bool SdkHostAllowed, DateTimeOffset CompletedAtUtc);

internal static class CurrentCustomerClosedPolicyEvidence
{
    internal static async Task CaptureAsync(LocalExecutionBinding binding, CurrentCustomerSequenceRepairConfiguration config,
        CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
    {
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        string text = Encoding.UTF8.GetString(files.Read(config.OperatorConnectionPath, sharedReader: true, maximumBytes: 65536));
        var endpoint = new NpgsqlConnectionStringBuilder(text) { Database = "postgres" };
        CurrentCustomerSequenceProofPolicy policy; bool semantic = true;
        string hbaPath = Path.Combine(binding.ArtifactRootCanonicalPath, "closed-policy-hba.conf"), rulesPath = Path.Combine(binding.ArtifactRootCanonicalPath, "closed-policy-rules.json");
        await using (var connection = new NpgsqlConnection(endpoint.ConnectionString))
        {
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx)) { _ = await readOnly.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
            const string sql = """
                SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),pg_postmaster_start_time(),pg_conf_load_time(),
                pg_read_file(current_setting('hba_file')),(SELECT jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text FROM pg_hba_file_rules h),
                rolvaliduntil,shobj_description(r.oid,'pg_authid'),rolsuper,rolcanlogin,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,
                (SELECT count(*) FROM pg_auth_members WHERE member=r.oid),(SELECT rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE oid=r.oid),
                (SELECT count(*) FROM pg_default_acl WHERE defaclrole=r.oid),current_setting('hba_file'),NOT pg_is_in_recovery(),
                (SELECT count(*) FROM pg_prepared_xacts),(SELECT count(*) FROM pg_event_trigger WHERE evtenabled<>'D'),
                (SELECT count(*) FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND backend_type='client backend')
                FROM pg_control_system(),pg_roles r WHERE rolname=current_user;
                """;
            await using var command = new NpgsqlCommand(sql, connection, tx);
            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            byte[] hba = Encoding.UTF8.GetBytes(reader.GetString(3)), rules = Encoding.UTF8.GetBytes(reader.GetString(4));
            policy = new(reader.GetString(0), reader.GetFieldValue<DateTimeOffset>(1), reader.GetFieldValue<DateTimeOffset>(2), scope.Maintenance.Role,
                reader.GetFieldValue<DateTimeOffset>(5), reader.GetString(6), reader.GetString(16),
                new(hbaPath, CurrentCustomerSequenceRepairPermit.Hash(hba)), new(rulesPath, CurrentCustomerSequenceRepairPermit.Hash(rules)),
                reader.GetBoolean(7), reader.GetBoolean(8), reader.GetBoolean(9), reader.GetBoolean(10), reader.GetBoolean(11), reader.GetBoolean(12),
                reader.GetInt64(13), reader.GetBoolean(14), reader.GetInt64(15), reader.GetInt64(20), reader.GetInt64(18), reader.GetInt64(19), reader.GetBoolean(17), DateTimeOffset.UtcNow);
            if (await reader.ReadAsync(ct).ConfigureAwait(false)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            await reader.DisposeAsync().ConfigureAwait(false);
            try { await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, tx, scope.Maintenance.Role, scope.Target.Kind, ct).ConfigureAwait(false); }
            catch (MigrationExecutionException failure) when (failure.Code == "current_app_owned_maintenance_hba_not_exclusive") { semantic = false; }
            await tx.RollbackAsync(ct).ConfigureAwait(false);
            await files.WriteNewAsync(hbaPath, hba, ct).ConfigureAwait(false); await files.WriteNewAsync(rulesPath, rules, ct).ConfigureAwait(false);
        }
        string ordinary = Encoding.UTF8.GetString(files.Read(config.RejectedOrdinaryConnectionPath, sharedReader: true, maximumBytes: 65536));
        var rejected = new List<string>();
        foreach (string database in scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))
        {
            CurrentCustomerSequenceCapacity.Require(admission: false);
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(ordinary) { Database = database, Pooling = false, Timeout = 3 }.ConnectionString);
            try { await connection.OpenAsync(ct).ConfigureAwait(false); throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            catch (PostgresException failure) when (failure.SqlState == "28000") { rejected.Add(database); }
        }
        bool sdkAllowed = false;
        await using (var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(text) { Database = "Customer", Username = "customer_closed_sdk", Password = "", Pooling = false, Timeout = 3 }.ConnectionString))
        {
            try { await connection.OpenAsync(ct).ConfigureAwait(false); sdkAllowed = true; }
            catch (PostgresException failure) when (failure.SqlState == "28000") { }
        }
        await files.WriteNewAsync(Path.Combine(binding.ArtifactRootCanonicalPath, "closed-installed-policy.json"),
            JsonSerializer.SerializeToUtf8Bytes(new CustomerClosedPolicy(policy, rejected, semantic, sdkAllowed, DateTimeOffset.UtcNow)), ct).ConfigureAwait(false);
        files.Require();
    }
    internal static CurrentAppOwnedMaintenanceHbaRule[] ParseRules(byte[] bytes)
    {
        using var document = JsonDocument.Parse(bytes);
        return document.RootElement.EnumerateArray().Select(x => new CurrentAppOwnedMaintenanceHbaRule(
            x.GetProperty("rule_number").GetInt32(), x.GetProperty("type").GetString()!, Strings(x, "database"), Strings(x, "user_name"),
            Nullable(x, "address"), Nullable(x, "netmask"), x.GetProperty("auth_method").GetString()!, Strings(x, "options"), Nullable(x, "error"))).ToArray();
        static string[] Strings(JsonElement x, string name)
        {
            return x.GetProperty(name).ValueKind == JsonValueKind.Null ? [] : x.GetProperty(name).EnumerateArray().Select(v => v.GetString() ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).ToArray();
        }

        static string? Nullable(JsonElement x, string name)
        {
            return x.GetProperty(name).ValueKind == JsonValueKind.Null ? null : x.GetProperty(name).GetString();
        }
    }
}
