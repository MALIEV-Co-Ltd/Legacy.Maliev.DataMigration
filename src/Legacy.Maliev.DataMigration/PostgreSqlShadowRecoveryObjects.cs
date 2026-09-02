using Npgsql;

namespace Legacy.Maliev.DataMigration;

// This is a fail-closed object-surface guard, not another schema/content comparator.
// The existing inspectors/fingerprints compare supported tables, columns, keys and indexes.
internal static class PostgreSqlShadowRecoveryObjects
{
    internal static async Task<bool> InspectAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, DatabaseSchemaPlan plan, CancellationToken cancellationToken)
    {
        const string sql = """
            WITH user_namespaces AS (
                SELECT oid FROM pg_namespace
                WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
                  AND nspname NOT LIKE 'pg!_temp!_%' ESCAPE '!' AND nspname NOT LIKE 'pg!_toast!_temp!_%' ESCAPE '!')
            SELECT
                EXISTS (SELECT 1 FROM pg_class c JOIN user_namespaces n ON n.oid=c.relnamespace
                    WHERE c.relkind NOT IN ('r', 'i', 'S') OR c.relrowsecurity OR c.relforcerowsecurity
                       OR c.relispartition OR c.relpersistence <> 'p')
                OR EXISTS (SELECT 1 FROM pg_type t JOIN user_namespaces n ON n.oid=t.typnamespace
                    WHERE NOT EXISTS (SELECT 1 FROM pg_class c
                        WHERE c.relkind='r' AND (c.reltype=t.oid OR
                            (t.typelem=c.reltype AND t.typlen=-1 AND t.typcategory='A'))))
                OR EXISTS (SELECT 1 FROM pg_depend d JOIN user_namespaces n ON n.oid=d.refobjid
                    WHERE d.refclassid='pg_namespace'::regclass
                      AND d.classid NOT IN ('pg_class'::regclass, 'pg_type'::regclass, 'pg_constraint'::regclass))
                OR EXISTS (SELECT 1 FROM pg_constraint c JOIN user_namespaces n ON n.oid=c.connamespace
                    WHERE c.contype NOT IN ('p','u','c','f','n'))
                OR EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
                    JOIN user_namespaces n ON n.oid=c.relnamespace WHERE NOT t.tgisinternal)
                OR EXISTS (SELECT 1 FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class
                    JOIN user_namespaces n ON n.oid=c.relnamespace)
                OR EXISTS (SELECT 1 FROM pg_inherits)
                OR EXISTS (SELECT 1 FROM pg_policy)
                OR EXISTS (SELECT 1 FROM pg_default_acl)
                OR EXISTS (SELECT 1 FROM pg_extension WHERE extname <> 'plpgsql')
                OR EXISTS (SELECT 1 FROM pg_event_trigger)
                OR EXISTS (SELECT 1 FROM pg_foreign_data_wrapper)
                OR EXISTS (SELECT 1 FROM pg_foreign_server)
                OR EXISTS (SELECT 1 FROM pg_publication)
                OR EXISTS (SELECT 1 FROM pg_subscription WHERE subdbid=(SELECT oid FROM pg_database WHERE datname=current_database()))
                OR EXISTS (SELECT 1 FROM pg_largeobject_metadata);
            """;
        await using (var command = new NpgsqlCommand(sql, connection, transaction))
        {
            if (true.Equals(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false))) { throw InvalidObjects(); }
        }

        HashSet<string> allowedSchemas = new(plan.Tables.Select(table => table.TargetSchema), StringComparer.Ordinal) { "public" };
        List<string> observedSchemas = [];
        const string schemasSql = """
            SELECT nspname FROM pg_namespace
            WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
                AND nspname NOT LIKE 'pg!_temp!_%' ESCAPE '!' AND nspname NOT LIKE 'pg!_toast!_temp!_%' ESCAPE '!';
            """;
        await using (var command = new NpgsqlCommand(schemasSql, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                string schema = reader.GetString(0);
                if (!allowedSchemas.Contains(schema)) { throw InvalidObjects(); }
                observedSchemas.Add(schema);
            }
        }

        var identities = plan.Tables.SelectMany(table => table.Identities.Select(identity =>
            new { Table = table, Identity = identity })).ToDictionary(
                item => (item.Table.TargetSchema, item.Table.TargetTable, item.Identity.Column));
        HashSet<(string, string, string)> observedIdentities = [];
        const string relationsSql = """
            SELECT c.relkind, owner_ns.nspname, owner_table.relname, a.attname, s.seqstart, s.seqincrement,
                pg_catalog.format_type(s.seqtypid, NULL), s.seqmin, s.seqmax, s.seqcycle, s.seqcache
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            LEFT JOIN pg_sequence s ON s.seqrelid=c.oid
            LEFT JOIN pg_depend d ON d.classid='pg_class'::regclass AND d.objid=c.oid AND d.objsubid=0
                AND d.refclassid='pg_class'::regclass AND d.deptype='i' AND c.relkind='S'
            LEFT JOIN pg_class owner_table ON owner_table.oid=d.refobjid
            LEFT JOIN pg_namespace owner_ns ON owner_ns.oid=owner_table.relnamespace
            LEFT JOIN pg_attribute a ON a.attrelid=d.refobjid AND a.attnum=d.refobjsubid
            WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
                AND n.nspname NOT LIKE 'pg!_temp!_%' ESCAPE '!' AND n.nspname NOT LIKE 'pg!_toast!_temp!_%' ESCAPE '!';
            """;
        bool hasRelations = false;
        await using (var command = new NpgsqlCommand(relationsSql, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                hasRelations = true;
                if (reader.GetChar(0) != 'S') { continue; }
                if (reader.IsDBNull(1) || reader.IsDBNull(2) || reader.IsDBNull(3)) { throw InvalidObjects(); }
                var key = (reader.GetString(1), reader.GetString(2), reader.GetString(3));
                if (!identities.TryGetValue(key, out var expected) || !observedIdentities.Add(key) ||
                    reader.GetInt64(4) != expected.Identity.SeedValue || reader.GetInt64(5) != expected.Identity.IncrementValue ||
                    !HasSupportedSequenceConfiguration(reader, expected.Table, expected.Identity))
                {
                    throw InvalidObjects();
                }
            }
        }
        return !hasRelations && observedSchemas.Any(schema => !string.Equals(schema, "public", StringComparison.Ordinal))
            ? throw InvalidObjects()
            : !hasRelations;
    }

    private static bool HasSupportedSequenceConfiguration(NpgsqlDataReader reader, TableCopyPlan table, IdentityCopyPlan identity)
    {
        string type = table.ColumnTypes[identity.Column];
        (long minimum, long maximum) = type switch
        {
            "smallint" => (short.MinValue, short.MaxValue),
            "integer" => (int.MinValue, int.MaxValue),
            "bigint" => (long.MinValue, long.MaxValue),
            _ => throw InvalidObjects(),
        };
        // ApplySchema specifies only START/INCREMENT. Require the same type-dependent
        // default limits, NO CYCLE and CACHE 1 so the reused last_value inspector is sound.
        return string.Equals(reader.GetString(6), type, StringComparison.Ordinal) &&
            reader.GetInt64(7) == (identity.IncrementValue > 0 ? 1 : minimum) &&
            reader.GetInt64(8) == (identity.IncrementValue > 0 ? maximum : -1) &&
            !reader.GetBoolean(9) && reader.GetInt64(10) == 1;
    }

    private static MigrationExecutionException InvalidObjects()
    {
        return new(
        "shadow_recovery_objects_invalid", "The target contains unexpected or unsupported user objects; preserve it for review.");
    }
}
