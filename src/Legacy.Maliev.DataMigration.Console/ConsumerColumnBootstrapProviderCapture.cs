using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal static class ConsumerColumnBootstrapProviderCapture
{
    internal static async Task<ConsumerColumnBootstrapProviderObservation> CaptureAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken ct)
    {
        if (transaction.Connection != connection || transaction.IsolationLevel is not (System.Data.IsolationLevel.RepeatableRead or System.Data.IsolationLevel.Serializable))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        const string sql = """
            WITH types AS (
              SELECT t.oid,t.typname,n.nspname,t.typlen,t.typbyval,t.typtype,t.typcategory,t.typispreferred,
                t.typisdefined,t.typrelid,t.typsubscript,t.typelem,t.typarray,t.typinput,t.typoutput,
                t.typreceive,t.typsend,t.typmodin,t.typmodout,t.typanalyze,t.typalign,t.typstorage,
                t.typnotnull,t.typbasetype,t.typtypmod,t.typndims,t.typcollation
              FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE t.oid IN (16,1114)
            ), functions AS (
              SELECT p.oid,l.lanname,p.prokind,p.prosecdef,p.proleakproof,p.proisstrict,p.proretset,
                p.provolatile,p.proparallel,p.pronargs,p.pronargdefaults,p.prorettype,p.proargtypes::text,
                p.proallargtypes,p.proargmodes,p.proargnames,p.proargdefaults::text,p.prosrc,p.probin,p.prosqlbody::text,p.proconfig
              FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid IN
                (SELECT function_oid FROM types t CROSS JOIN LATERAL unnest(ARRAY[t.typinput,t.typoutput,t.typreceive,t.typsend,t.typmodin,t.typmodout,t.typanalyze,t.typsubscript]) function_oid WHERE function_oid<>0)
            )
            SELECT current_setting('server_version_num')::integer,catalog_version_no::bigint,
              current_setting('server_encoding'),current_setting('block_size')::integer,
              coalesce(current_setting('composite_type_mismatch',true),''),
              encode(sha256(convert_to(jsonb_build_object('Types',(SELECT jsonb_agg(to_jsonb(t) ORDER BY oid) FROM types t),
                'Functions',(SELECT jsonb_agg(to_jsonb(p) ORDER BY oid) FROM functions p))::text,'UTF8')),'hex'),
              (SELECT encode(sha256(convert_to(jsonb_build_object('Provider',d.datlocprovider,'Collation',d.datcollate,
                'Ctype',d.datctype,'Locale',d.datlocale,'IcuRules',d.daticurules,'RecordedVersion',d.datcollversion,
                'ActualVersion',pg_database_collation_actual_version(d.oid))::text,'UTF8')),'hex') FROM pg_database d WHERE d.datname=current_database()),
              (SELECT encode(sha256(convert_to(jsonb_object_agg(name,setting ORDER BY name)::text,'UTF8')),'hex') FROM pg_settings
                WHERE name IN ('DateStyle','IntervalStyle','TimeZone','lc_numeric','lc_monetary','standard_conforming_strings',
                  'default_table_access_method','default_tablespace','temp_tablespaces','shared_preload_libraries','session_preload_libraries',
                  'local_preload_libraries','default_toast_compression','search_path','default_transaction_isolation','row_security','session_replication_role')),
              (SELECT count(*)=2 AND bool_and(nspname='pg_catalog' AND typcollation=0 AND typtype='b' AND typisdefined AND NOT typnotnull
                 AND typbasetype=0 AND typtypmod=-1 AND typndims=0 AND typelem=0 AND typbyval AND typstorage='p'
                 AND ((oid=16 AND typname='bool' AND typlen=1 AND typcategory='B') OR
                      (oid=1114 AND typname='timestamp' AND typlen=8 AND typcategory='D'))) FROM types),
              current_setting('standard_conforming_strings')='on' AND current_setting('default_table_access_method')='heap'
                AND current_setting('session_replication_role')='origin' AND current_setting('row_security')='on'
                AND (current_schemas(true))[1]='pg_catalog'
            FROM pg_control_system();
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 30 };
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false) || !reader.GetBoolean(8) || !reader.GetBoolean(9))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        var result = new ConsumerColumnBootstrapProviderObservation(reader.GetInt32(0), reader.GetInt64(1), reader.GetString(2), reader.GetInt32(3),
            reader.GetString(4), reader.GetString(5), reader.GetString(6), reader.GetString(7));
        if (await reader.ReadAsync(ct).ConfigureAwait(false)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        ConsumerColumnBootstrapProviderCompatibility.RequireObservation(result); return result;
    }
}
