using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAppOwnedMaintenanceHbaRule(int Number, string Type, string[] Databases,
    string[] Users, string? Address, string? Netmask, string Method, string[] Options, string? Error);

/// <summary>Closed complete application maintenance policy; a pinned hash alone proves no exclusivity.</summary>
internal static class CurrentAppOwnedMaintenanceHba
{
    internal static async Task RequireInstalledAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string operatorRole, string targetKind, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT rule_number,type,database,user_name,address,netmask,auth_method,options,error
            FROM pg_hba_file_rules ORDER BY rule_number;
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var rules = new List<CurrentAppOwnedMaintenanceHbaRule>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rules.Add(new(reader.IsDBNull(0) ? 0 : reader.GetInt32(0), reader.IsDBNull(1) ? string.Empty : reader.GetString(1),
                reader.IsDBNull(2) ? [] : reader.GetFieldValue<string[]>(2), reader.IsDBNull(3) ? [] : reader.GetFieldValue<string[]>(3),
                reader.IsDBNull(4) ? null : reader.GetString(4), reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.IsDBNull(6) ? string.Empty : reader.GetString(6), reader.IsDBNull(7) ? [] : reader.GetFieldValue<string[]>(7),
                reader.IsDBNull(8) ? null : reader.GetString(8)));
        }
        Require(rules, operatorRole, targetKind);
        await reader.DisposeAsync().ConfigureAwait(false);
        if (rules.Any(rule => rule.Method == "cert"))
        {
            await using var role = new NpgsqlCommand("""
                SELECT count(*) FROM pg_roles WHERE rolname='streaming_replica' AND rolcanlogin AND rolreplication
                  AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolbypassrls;
                """, connection, transaction);
            if (Convert.ToInt64(await role.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
                System.Globalization.CultureInfo.InvariantCulture) != 1) { throw Invalid(); }
        }
    }

    internal static void Require(IReadOnlyList<CurrentAppOwnedMaintenanceHbaRule> rules, string operatorRole,
        string targetKind)
    {
        if (string.IsNullOrWhiteSpace(operatorRole) || operatorRole is "all" or "sameuser" or "samerole" or "samegroup" or "replication" or "postgres" or "streaming_replica" ||
            operatorRole.StartsWith("pg_", StringComparison.Ordinal) || operatorRole.Length > 63 ||
            operatorRole.Any(value => !char.IsAsciiLetterOrDigit(value) && value != '_') ||
            targetKind is not (DeltaTargetAuthorityKind.LocalAspire or DeltaTargetAuthorityKind.ProductionCloudNativePg) ||
            rules.Count is 0 or > 256)
        { throw Invalid(); }
        bool localRejected = false, ipv4Rejected = false, ipv6Rejected = false, operatorAllowed = false;
        bool rejectionStarted = false;
        int previous = 0;
        foreach (CurrentAppOwnedMaintenanceHbaRule rule in rules)
        {
            if (rule.Number <= previous || rule.Error is not null ||
                rule.Type is not ("local" or "host" or "hostssl" or "hostnossl"))
            { throw Invalid(); }
            previous = rule.Number;
            bool local = rule.Type == "local";
            if (targetKind == DeltaTargetAuthorityKind.ProductionCloudNativePg && rule.Type == "hostssl" &&
                rule.Method == "cert" && rule.Address == "all" && rule.Netmask is null &&
                rule.Databases.Length == 1 && (rule.Databases[0] is "replication" or "postgres") &&
                rule.Options.SequenceEqual(["clientcert=verify-full"], StringComparer.Ordinal) &&
                rule.Users.SequenceEqual(["streaming_replica"], StringComparer.Ordinal))
            {
                if (rejectionStarted) { throw Invalid(); }
                continue;
            }
            if (rule.Options.Length != 0) { throw Invalid(); }
            if ((local && (rule.Address is not null || rule.Netmask is not null)) ||
                (!local && (string.IsNullOrEmpty(rule.Address) || string.IsNullOrEmpty(rule.Netmask))))
            { throw Invalid(); }
            if (targetKind == DeltaTargetAuthorityKind.ProductionCloudNativePg && local && rule.Method == "peer" &&
                rule.Databases.SequenceEqual(["postgres"], StringComparer.Ordinal) &&
                rule.Users.SequenceEqual(["postgres"], StringComparer.Ordinal))
            {
                if (rejectionStarted) { throw Invalid(); }
                continue;
            }
            if (!rule.Databases.SequenceEqual(["all"], StringComparer.Ordinal)) { throw Invalid(); }
            if (rule.Method == "scram-sha-256" && rule.Users.SequenceEqual([operatorRole], StringComparer.Ordinal))
            {
                if (rejectionStarted) { throw Invalid(); }
                operatorAllowed = true;
                continue;
            }
            if (rule.Method != "reject" || !rule.Users.SequenceEqual(["all"], StringComparer.Ordinal))
            { throw Invalid(); }
            rejectionStarted = true;
            localRejected |= local;
            ipv4Rejected |= rule.Type == "host" && rule.Address == "0.0.0.0" && rule.Netmask == "0.0.0.0";
            ipv6Rejected |= rule.Type == "host" && rule.Address == "::" && rule.Netmask == "::";
        }
        if (!operatorAllowed || !localRejected || !ipv4Rejected || !ipv6Rejected) { throw Invalid(); }
    }

    private static MigrationExecutionException Invalid()
    {
        return new("current_app_owned_maintenance_hba_not_exclusive", "The installed policy does not establish complete ordinary-role maintenance exclusion.");
    }
}
