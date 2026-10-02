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
    public string? FenceAuxiliarySha256 { get; init; }
    public string? TargetExtensionStateSha256 { get; init; }
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
                'indexes',(SELECT jsonb_agg(jsonb_build_object('definition',pg_get_indexdef(indexrelid),
                   'valid',indisvalid,'ready',indisready,'live',indislive,'replicaIdentity',indisreplident,
                   'clustered',indisclustered) ORDER BY pg_get_indexdef(indexrelid) COLLATE "C") FROM pg_index WHERE indrelid=c.oid),
                'triggers',(SELECT jsonb_agg(jsonb_build_object('definition',pg_get_triggerdef(oid),
                   'enabled',tgenabled,'internal',tgisinternal) ORDER BY tgname COLLATE "C") FROM pg_trigger WHERE tgrelid=c.oid),
                'policies',(SELECT jsonb_agg(jsonb_build_object('name',polname,'command',polcmd,
                   'permissive',polpermissive,'roles',(SELECT jsonb_agg(CASE WHEN role_oid=0 THEN 'PUBLIC' ELSE pg_get_userbyid(role_oid) END
                     ORDER BY role_oid) FROM unnest(polroles) role_oid),
                   'using',pg_get_expr(polqual,polrelid),'check',pg_get_expr(polwithcheck,polrelid))
                   ORDER BY polname COLLATE "C") FROM pg_policy WHERE polrelid=c.oid))::text
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
              'eventTriggers',(SELECT jsonb_agg(jsonb_build_object('name',evtname,'event',evtevent,
                'enabled',evtenabled,'owner',pg_get_userbyid(evtowner),'function',evtfoid::regprocedure::text,
                'tags',evttags) ORDER BY evtname COLLATE "C") FROM pg_event_trigger),
              'operators',(SELECT jsonb_agg(to_jsonb(o)-'oid' ORDER BY n.nspname COLLATE "C",o.oprname COLLATE "C",o.oid)
                FROM pg_operator o JOIN pg_namespace n ON n.oid=o.oprnamespace
                WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'),
              'operatorClasses',(SELECT jsonb_agg(to_jsonb(o)-'oid' ORDER BY n.nspname COLLATE "C",o.opcname COLLATE "C",o.oid)
                FROM pg_opclass o JOIN pg_namespace n ON n.oid=o.opcnamespace
                WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'),
              'operatorFamilies',(SELECT jsonb_agg(jsonb_build_object('definition',to_jsonb(o)-'oid',
                'operators',(SELECT jsonb_agg(to_jsonb(m)-'oid' ORDER BY m.oid) FROM pg_amop m WHERE m.amopfamily=o.oid),
                'functions',(SELECT jsonb_agg(to_jsonb(m)-'oid' ORDER BY m.oid) FROM pg_amproc m WHERE m.amprocfamily=o.oid))
                ORDER BY n.nspname COLLATE "C",o.opfname COLLATE "C",o.oid)
                FROM pg_opfamily o JOIN pg_namespace n ON n.oid=o.opfnamespace
                WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'),
              'ranges',(SELECT jsonb_agg(to_jsonb(r) ORDER BY n.nspname COLLATE "C",t.typname COLLATE "C")
                FROM pg_range r JOIN pg_type t ON t.oid=r.rngtypid JOIN pg_namespace n ON n.oid=t.typnamespace
                WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'),
              'casts',(SELECT jsonb_agg(to_jsonb(c)-'oid' ORDER BY c.castsource,c.casttarget)
                FROM pg_cast c JOIN pg_type s ON s.oid=c.castsource JOIN pg_type t ON t.oid=c.casttarget
                JOIN pg_namespace sn ON sn.oid=s.typnamespace JOIN pg_namespace tn ON tn.oid=t.typnamespace
                WHERE (sn.nspname NOT LIKE 'pg_%' AND sn.nspname<>'information_schema')
                  OR (tn.nspname NOT LIKE 'pg_%' AND tn.nspname<>'information_schema')),
              'foreignDataWrappers',(SELECT jsonb_agg(to_jsonb(f)-'oid' ORDER BY fdwname COLLATE "C") FROM pg_foreign_data_wrapper f),
              'foreignServers',(SELECT jsonb_agg(to_jsonb(s)-'oid' ORDER BY srvname COLLATE "C") FROM pg_foreign_server s),
              'userMappings',(SELECT jsonb_agg(to_jsonb(m)-'oid' ORDER BY umuser,umserver) FROM pg_user_mapping m),
              'publications',(SELECT jsonb_agg(jsonb_build_object('definition',to_jsonb(p)-'oid',
                'tables',(SELECT jsonb_agg(to_jsonb(r)-'oid' ORDER BY prrelid) FROM pg_publication_rel r WHERE r.prpubid=p.oid),
                'schemas',(SELECT jsonb_agg(to_jsonb(s)-'oid' ORDER BY pnnspid) FROM pg_publication_namespace s WHERE s.pnpubid=p.oid))
                ORDER BY pubname COLLATE "C") FROM pg_publication p),
              'subscriptions',(SELECT jsonb_agg(to_jsonb(s)-'oid' ORDER BY subname COLLATE "C") FROM pg_subscription s
                WHERE s.subdbid=(SELECT oid FROM pg_database WHERE datname=current_database())),
              'roles',(SELECT jsonb_agg(jsonb_build_object('name',rolname,
                'superuser',rolsuper,'inherit',rolinherit,'createRole',rolcreaterole,
                'createDatabase',rolcreatedb,'login',rolcanlogin,'replication',rolreplication,
                'bypassRls',rolbypassrls,'connectionLimit',rolconnlimit,'validUntil',rolvaliduntil,
                'comment',shobj_description(oid,'pg_authid'))
                ORDER BY rolname COLLATE "C") FROM pg_roles),
              'roleMemberships',(SELECT jsonb_agg(jsonb_build_object('role',pg_get_userbyid(roleid),
                'member',pg_get_userbyid(member),'grantor',pg_get_userbyid(grantor),
                'admin',admin_option,'inherit',inherit_option,'set',set_option)
                ORDER BY pg_get_userbyid(roleid) COLLATE "C",pg_get_userbyid(member) COLLATE "C",
                  pg_get_userbyid(grantor) COLLATE "C") FROM pg_auth_members),
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
              'databaseRoleSettings',(SELECT jsonb_agg(jsonb_build_object('database',CASE WHEN s.setdatabase=0 THEN '*' ELSE d.datname END,
                'role',CASE WHEN s.setrole=0 THEN '*' ELSE pg_get_userbyid(s.setrole) END,
                'settings',(SELECT jsonb_agg(setting ORDER BY setting COLLATE "C") FROM unnest(s.setconfig) setting))
                ORDER BY s.setdatabase,s.setrole) FROM pg_db_role_setting s
                LEFT JOIN pg_database d ON d.oid=s.setdatabase
                WHERE s.setdatabase=0 OR d.datname=current_database()),
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
        await using var auxiliary = new NpgsqlCommand("""
            SELECT encode(sha256(convert_to((to_jsonb(f)-ARRAY['schema_plan_sha256',
              'target_schema_sha256','target_generation','target_observation_sha256']::text[])::text,'UTF8')),'hex')
            FROM legacy_migration_internal.delta_fence f;
            """, connection, transaction);
        // Hash the PostgreSQL JSONB representation, never return private values in evidence.
        string auxiliaryHash = await auxiliary.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string
            ?? throw Invalid("delta_source_repair_preimage_fence_invalid");
        string? extensionHash = null;
        // Generic preimages also describe nonconforming databases during diagnosis. They are
        // nonexecuting evidence; only a conforming declared physical schema can bind the
        // approved owner state. The mixed reader rejects any nonconforming physical hash.
        if (ApprovedConsumerColumnOverlayManifest.HasState(schema) &&
            (physical == schema.TargetSchemaSha256 || schema.SourceDispositionProfile is not null &&
                physical == PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(schema, true)))
        {
            ApprovedTargetExtensionState extensions = await ApprovedTargetExtensionStateInspector
                .InspectAsync(connection, transaction, schema, cancellationToken).ConfigureAwait(false);
            extensionHash = ApprovedTargetExtensionStateInspector.ComputeSha256(schema, extensions);
        }
        return new(schema.Database, physical, HashText(objectsJson), relations, sequences)
        {
            FenceAuxiliarySha256 = auxiliaryHash,
            TargetExtensionStateSha256 = extensionHash,
        };
    }
    internal static async Task RequireMarkerCatalogAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, long expectedRows, CancellationToken cancellationToken)
    {
        if (expectedRows is not (0 or 1) || transaction.Connection != connection)
        {
            throw Invalid("delta_source_repair_marker_catalog_invalid");
        }
        const string sql = """
            SELECT c.reltype,t.typarray,
              c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity
              AND NOT c.relforcerowsecurity AND c.reloptions IS NULL AND c.relacl IS NULL
              AND c.relowner=j.relowner AND t.typowner=c.relowner AND t.typacl IS NULL
              AND t.typtype='c' AND t.typrelid=c.oid AND a.typelem=t.oid
              AND a.typowner=c.relowner AND a.typacl IS NULL AND a.typrelid=0
              AND (SELECT count(*) FROM pg_type WHERE typrelid=c.oid)=1
              AND (SELECT count(*) FROM pg_type WHERE typelem=t.oid)=1
              AND (SELECT jsonb_agg(jsonb_build_array(attname,format_type(atttypid,atttypmod),attnotnull)
                ORDER BY attnum) FROM pg_attribute WHERE attrelid=c.oid AND attnum>0 AND NOT attisdropped)
                = '[ ["database_name","text",true],["admission_sha256","text",true],
                  ["claim_id","uuid",true],["preimage_sha256","text",true],
                  ["source_capture_sha256","text",true],["future_plan_sha256","text",true],
                  ["continuation_ordinal","bigint",true],["continuation_sha256","text",true],
                  ["authorization_sha256","text",true],["prior_internal_sha256","text",true],
                  ["checkpoint_sha256","text",true],["reconciliation_sha256","text",true]]'::jsonb
              AND NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=c.oid AND attnum>0
                AND (attisdropped OR attidentity<>'' OR attgenerated<>''))
              AND NOT EXISTS(SELECT 1 FROM pg_attrdef WHERE adrelid=c.oid)
              AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=c.oid)
              AND NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=c.oid)
              AND NOT EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class=c.oid)
              AND NOT EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid)
              AND (SELECT count(*) FROM pg_constraint WHERE conrelid=c.oid AND contype='p')=1
              AND (SELECT count(*) FROM pg_constraint WHERE conrelid=c.oid AND contype='n')=12
              AND NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=c.oid
                AND (contype NOT IN ('p','n') OR NOT convalidated OR NOT conenforced))
              AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=c.oid AND contype='p'
                AND conkey=ARRAY[1]::smallint[] AND convalidated AND NOT condeferrable AND NOT condeferred)
              AND (SELECT count(*) FROM pg_index WHERE indrelid=c.oid)=1
              AND EXISTS(SELECT 1 FROM pg_index i JOIN pg_class ix ON ix.oid=i.indexrelid
                JOIN pg_am am ON am.oid=ix.relam WHERE i.indrelid=c.oid
                AND i.indisprimary AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
                AND NOT i.indisclustered AND NOT i.indisreplident AND i.indnkeyatts=1 AND i.indnatts=1
                AND i.indkey::text='1' AND i.indexprs IS NULL AND i.indpred IS NULL
                AND ix.reloptions IS NULL AND am.amname='btree')
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            JOIN pg_type t ON t.oid=c.reltype JOIN pg_type a ON a.oid=t.typarray
            JOIN pg_class j ON j.oid='legacy_migration_internal.delta_journal'::regclass
            WHERE n.nspname='legacy_migration_internal' AND c.relname='delta_source_backed_repair';
            """;
        await using (var command = new NpgsqlCommand(sql, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.IsDBNull(2) || !reader.GetBoolean(2))
            {
                throw Invalid("delta_source_repair_marker_catalog_invalid");
            }
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw Invalid("delta_source_repair_marker_catalog_invalid"); }
        }
        await using var rows = new NpgsqlCommand("SELECT count(*) FROM legacy_migration_internal.delta_source_backed_repair;", connection, transaction);
        if (Convert.ToInt64(await rows.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) != expectedRows)
        {
            throw Invalid("delta_source_repair_marker_catalog_invalid");
        }
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
