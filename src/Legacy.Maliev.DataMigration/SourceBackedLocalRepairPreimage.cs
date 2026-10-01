using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record SourceRepairRelationPreimage(string Schema, string Table,
    long Rows, string RowMultisetSha256, string CatalogSha256);
internal sealed record SourceRepairSequencePreimage(string Schema, string Name,
    string Type, long Start, long Increment, long Minimum, long Maximum,
    long Cache, bool Cycle, long LastValue, bool IsCalled, string CatalogSha256);
internal sealed record SourceBackedLocalRepairDatabasePreimage(string Database,
    string ObservedPhysicalSchemaSha256, string CatalogObjectsSha256, IReadOnlyList<SourceRepairRelationPreimage> Relations,
    IReadOnlyList<SourceRepairSequencePreimage> Sequences)
{
    internal static bool AuthorizesExecution => false;
}

internal static class SourceBackedLocalRepairPreimage
{
    internal static void RequireMatches(SourceBackedLocalRepairDatabasePreimage expected,
        SourceBackedLocalRepairDatabasePreimage observed)
    {
        if (expected.Database != observed.Database || !CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(ComputeSha256(expected)), Convert.FromHexString(ComputeSha256(observed))))
        {
            throw Invalid("delta_source_repair_preimage_changed");
        }
    }

    internal static string ComputeSha256(SourceBackedLocalRepairDatabasePreimage value)
    {
        return Convert.ToHexString(SHA256.HashData([.. "legacy-maliev-source-repair-database-preimage-v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(value)])).ToLowerInvariant();
    }

    internal static async Task<SourceBackedLocalRepairDatabasePreimage> InspectAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, DatabaseSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(schema);
        if (connection.Database != schema.Database ||
            !DatabaseInventory.ActiveDatabases.Contains(schema.Database, StringComparer.Ordinal) ||
            transaction.Connection != connection || transaction.IsolationLevel is not
                (IsolationLevel.RepeatableRead or IsolationLevel.Serializable))
        {
            throw Invalid("delta_source_repair_preimage_binding_invalid");
        }
        await using (var settings = new NpgsqlCommand("SET LOCAL timezone='UTC'; SET LOCAL datestyle='ISO,YMD'; SET LOCAL extra_float_digits=3;", connection, transaction))
        {
            _ = await settings.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        await using (var journal = new NpgsqlCommand("SELECT count(*) FROM legacy_migration_internal.delta_journal WHERE reconciliation_sha256 IS NULL;", connection, transaction))
        {
            if (Convert.ToInt64(await journal.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) != 0)
            {
                throw Invalid("delta_source_repair_preimage_unsettled");
            }
        }
        await using (var fence = new NpgsqlCommand("SELECT count(*) FROM legacy_migration_internal.delta_fence;", connection, transaction))
        {
            if (Convert.ToInt64(await fence.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) != 1)
            {
                throw Invalid("delta_source_repair_preimage_fence_invalid");
            }
        }
        await using var physicalInspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
        string physical = await physicalInspector.InspectSchemaAsync(schema, cancellationToken).ConfigureAwait(false);
        var catalog = new List<(string Schema, string Table, string Hash)>();
        const string sql = """
            SELECT n.nspname,c.relname,c.relkind::text,
              jsonb_build_object('owner',pg_get_userbyid(c.relowner),'acl',c.relacl,
                'persistence',c.relpersistence,'rowSecurity',c.relrowsecurity,
                'forceRowSecurity',c.relforcerowsecurity,'options',c.reloptions,
                'columns',(SELECT jsonb_agg(jsonb_build_object('name',a.attname,
                   'type',format_type(a.atttypid,a.atttypmod),'nullable',NOT a.attnotnull,
                   'identity',a.attidentity,'generated',a.attgenerated,
                   'default',pg_get_expr(d.adbin,d.adrelid),'collation',co.collname,
                   'collationVersion',co.collversion,'actualCollationVersion',pg_collation_actual_version(co.oid)) ORDER BY a.attnum)
                   FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
                   LEFT JOIN pg_collation co ON co.oid=a.attcollation
                   WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),
                'constraints',(SELECT jsonb_agg(jsonb_build_object('name',conname,'definition',pg_get_constraintdef(oid),'validated',convalidated)
                   ORDER BY conname COLLATE "C") FROM pg_constraint WHERE conrelid=c.oid),
                'indexes',(SELECT jsonb_agg(pg_get_indexdef(indexrelid) ORDER BY pg_get_indexdef(indexrelid) COLLATE "C") FROM pg_index WHERE indrelid=c.oid),
                'triggers',(SELECT jsonb_agg(pg_get_triggerdef(oid) ORDER BY tgname COLLATE "C") FROM pg_trigger WHERE tgrelid=c.oid AND NOT tgisinternal))::text
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND c.relkind IN ('r','p','v','m','f')
            ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C";
            """;
        await using (var command = new NpgsqlCommand(sql, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (reader.GetString(2) != "r") { throw Invalid("delta_source_repair_preimage_relation_unsupported"); }
                catalog.Add((reader.GetString(0), reader.GetString(1), HashText(reader.GetString(3))));
            }
        }
        var relations = new List<SourceRepairRelationPreimage>();
        foreach ((string ns, string name, string hash) in catalog)
        {
            string tableSql = $"SELECT count(*),encode(sha256(convert_to(coalesce(string_agg(h,'' ORDER BY h COLLATE \"C\"),''),'UTF8')),'hex') FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') h FROM {Qualified(ns, name)} t) rows;";
            await using var command = new NpgsqlCommand(tableSql, connection, transaction);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw Invalid("delta_source_repair_preimage_rows_invalid"); }
            relations.Add(new(ns, name, reader.GetInt64(0), reader.GetString(1), hash));
        }
        var definitions = new List<(string Schema, string Name, string Type, long Start, long Increment, long Minimum, long Maximum, long Cache, bool Cycle, string CatalogSha256)>();
        const string sequenceSql = """
            SELECT n.nspname,c.relname,s.seqtypid::regtype::text,s.seqstart,s.seqincrement,s.seqmin,s.seqmax,s.seqcache,s.seqcycle,
              jsonb_build_object('owner',pg_get_userbyid(c.relowner),'acl',c.relacl,
                'persistence',c.relpersistence,'options',c.reloptions,
                'dependencies',(SELECT jsonb_agg(jsonb_build_object('type',d.deptype,
                  'tableSchema',rn.nspname,'table',rc.relname,'column',a.attname)
                  ORDER BY rn.nspname COLLATE "C",rc.relname COLLATE "C",a.attname COLLATE "C",d.deptype)
                  FROM pg_depend d JOIN pg_class rc ON rc.oid=d.refobjid
                  JOIN pg_namespace rn ON rn.oid=rc.relnamespace
                  LEFT JOIN pg_attribute a ON a.attrelid=rc.oid AND a.attnum=d.refobjsubid
                  WHERE d.classid='pg_class'::regclass AND d.objid=c.oid
                    AND d.refclassid='pg_class'::regclass AND d.deptype IN ('a','i')))::text
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_sequence s ON s.seqrelid=c.oid
            WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'
            ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C";
            """;
        await using (var command = new NpgsqlCommand(sequenceSql, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                definitions.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetInt64(3), reader.GetInt64(4), reader.GetInt64(5), reader.GetInt64(6), reader.GetInt64(7), reader.GetBoolean(8), HashText(reader.GetString(9))));
            }
        }
        var sequences = new List<SourceRepairSequencePreimage>();
        foreach (var item in definitions)
        {
            await using var command = new NpgsqlCommand($"SELECT last_value,is_called FROM {Qualified(item.Schema, item.Name)};", connection, transaction);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw Invalid("delta_source_repair_preimage_sequence_invalid"); }
            sequences.Add(new(item.Schema, item.Name, item.Type, item.Start, item.Increment, item.Minimum, item.Maximum,
                item.Cache, item.Cycle, reader.GetInt64(0), reader.GetBoolean(1), item.CatalogSha256));
        }
        const string objectsSql = """
            SELECT jsonb_build_object(
              'schemas',(SELECT jsonb_agg(jsonb_build_object('name',nspname,
                'owner',pg_get_userbyid(nspowner),'acl',nspacl) ORDER BY nspname COLLATE "C")
                FROM pg_namespace WHERE nspname NOT LIKE 'pg_%' AND nspname<>'information_schema'),
              'defaultPrivileges',(SELECT jsonb_agg(jsonb_build_object('owner',pg_get_userbyid(d.defaclrole),
                'schema',n.nspname,'objectType',d.defaclobjtype,'acl',d.defaclacl)
                ORDER BY pg_get_userbyid(d.defaclrole) COLLATE "C",n.nspname COLLATE "C",d.defaclobjtype)
                FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace),
              'database',(SELECT jsonb_build_object('owner',pg_get_userbyid(datdba),'encoding',encoding,
                'localeProvider',datlocprovider,'collate',datcollate,'ctype',datctype,'locale',datlocale,
                'icuRules',daticurules,'collationVersion',datcollversion,'acl',datacl,
                'allowConnections',datallowconn,'connectionLimit',datconnlimit)
                FROM pg_database WHERE datname=current_database()),
              'functions',(SELECT jsonb_agg(jsonb_build_object('schema',n.nspname,'name',p.proname,
                'arguments',pg_get_function_identity_arguments(p.oid),'owner',pg_get_userbyid(p.proowner),
                'acl',p.proacl,'definition',CASE WHEN p.prokind IN ('f','p') THEN pg_get_functiondef(p.oid)
                  ELSE to_jsonb(p)::text END) ORDER BY n.nspname COLLATE "C",p.proname COLLATE "C",pg_get_function_identity_arguments(p.oid) COLLATE "C")
                FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'),
              'collations',(SELECT jsonb_agg(jsonb_build_object('schema',n.nspname,'owner',pg_get_userbyid(co.collowner),
                'definition',to_jsonb(co)-'oid'-'collnamespace'-'collowner',
                'actualVersion',pg_collation_actual_version(co.oid)) ORDER BY n.nspname COLLATE "C",co.collname COLLATE "C")
                FROM pg_collation co JOIN pg_namespace n ON n.oid=co.collnamespace
                WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'),
              'types',(SELECT jsonb_agg(jsonb_build_object('schema',n.nspname,'name',t.typname,
                'kind',t.typtype,'baseType',format_type(t.typbasetype,t.typtypmod),
                'notNull',t.typnotnull,'default',t.typdefault,'owner',pg_get_userbyid(t.typowner),'acl',t.typacl,
                'attributes',(SELECT jsonb_agg(jsonb_build_object('name',a.attname,'type',format_type(a.atttypid,a.atttypmod),
                  'collation',co.collname) ORDER BY a.attnum) FROM pg_attribute a
                  LEFT JOIN pg_collation co ON co.oid=a.attcollation
                  WHERE a.attrelid=t.typrelid AND a.attnum>0 AND NOT a.attisdropped),
                'enumLabels',(SELECT jsonb_agg(enumlabel ORDER BY enumsortorder) FROM pg_enum WHERE enumtypid=t.oid),
                'constraints',(SELECT jsonb_agg(pg_get_constraintdef(oid) ORDER BY conname COLLATE "C") FROM pg_constraint WHERE contypid=t.oid))
                ORDER BY n.nspname COLLATE "C",t.typname COLLATE "C")
                FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'),
              'extensions',(SELECT jsonb_agg(jsonb_build_object('name',e.extname,'version',e.extversion,
                'schema',n.nspname,'owner',pg_get_userbyid(e.extowner)) ORDER BY e.extname COLLATE "C")
                FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace))::text;
            """;
        await using var objects = new NpgsqlCommand(objectsSql, connection, transaction);
        string objectsJson = await objects.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string
            ?? throw Invalid("delta_source_repair_preimage_catalog_invalid");
        return new(schema.Database, physical, HashText(objectsJson), relations, sequences);
    }
    private static string Qualified(string ns, string table)
    {
        return PostgreSqlShadowTarget.QuoteIdentifier(ns) + "." + PostgreSqlShadowTarget.QuoteIdentifier(table);
    }

    private static string HashText(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    private static DeltaExecutionException Invalid(string code)
    {
        return new(code, "The complete source repair preimage is absent, changed or unsupported.");
    }
}
