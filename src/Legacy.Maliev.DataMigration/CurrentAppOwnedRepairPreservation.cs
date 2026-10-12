using System.Globalization;
using Npgsql;
using NpgsqlTypes;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAppOwnedCatalogFact(string Catalog, string Key, string Sha256, string ObjectClass, string ObjectId);
internal sealed record CurrentAppOwnedRelationFact(string Schema, string Name, long Rows, string RowSha256);
internal sealed record CurrentAppOwnedSequenceFact(string Schema, string Name, string Owner, string TupleSha256);
internal sealed record CurrentAppOwnedDatabaseSnapshot(string Database, IReadOnlyList<CurrentAppOwnedCatalogFact> Catalog,
    IReadOnlyList<CurrentAppOwnedRelationFact> Relations, IReadOnlyList<CurrentAppOwnedSequenceFact> Sequences)
{
    internal string Sha256 => CurrentAppOwnedSnapshotSerialization.Sha256(this);
}

/// <summary>Complete raw catalog tuples + user/private rows + physical sequence tuples; no source projection filtering.</summary>
internal static class CurrentAppOwnedRepairPreservation
{
    private static readonly string[] OidCatalogs =
        ["pg_class", "pg_type", "pg_namespace", "pg_constraint", "pg_attrdef", "pg_trigger", "pg_proc",
         "pg_collation", "pg_policy", "pg_rewrite", "pg_extension", "pg_event_trigger",
         "pg_authid", "pg_database", "pg_tablespace", "pg_language", "pg_operator", "pg_cast",
         "pg_opclass", "pg_opfamily", "pg_am", "pg_conversion"];
    private static readonly string[] TupleCatalogs =
        ["pg_attribute", "pg_index", "pg_depend", "pg_shdepend", "pg_description", "pg_shdescription",
         "pg_auth_members", "pg_default_acl", "pg_init_privs", "pg_inherits", "pg_partitioned_table",
         "pg_sequence", "pg_statistic", "pg_statistic_ext", "pg_statistic_ext_data", "pg_amop", "pg_amproc",
         "pg_range", "pg_transform", "pg_seclabel", "pg_shseclabel"];

    internal static async Task<CurrentAppOwnedDatabaseSnapshot> CaptureAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        if (transaction.Connection != connection ||
            transaction.IsolationLevel is not (System.Data.IsolationLevel.Serializable or System.Data.IsolationLevel.RepeatableRead))
        { throw CurrentAppOwnedRepairPermit.Invalid(); }
        await using (var settings = new NpgsqlCommand("SET LOCAL timezone='UTC'; SET LOCAL datestyle='ISO,YMD'; SET LOCAL extra_float_digits=3;",
            connection, transaction)) { _ = await settings.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false); }
        var catalog = new List<CurrentAppOwnedCatalogFact>();
        foreach (string name in OidCatalogs.Concat(TupleCatalogs))
        {
            bool hasOid = OidCatalogs.Contains(name, StringComparer.Ordinal);
            // Statistics/descriptions may contain private values. Some non-OID
            // catalogs also legally contain identical tuples. A digest plus an
            // occurrence ordinal retains their full multiplicity without values
            // or unstable physical tuple addresses in evidence.
            string oidKey = hasOid ? "x.oid::text" : "NULL::text";
            string key = hasOid ? "oid_key" :
                "digest || '/' || row_number() OVER (PARTITION BY digest COLLATE \"C\" ORDER BY digest COLLATE \"C\")::text";
            string objectClass = name switch
            {
                "pg_attribute" => "'pg_class'::regclass::oid::text",
                "pg_index" => "'pg_class'::regclass::oid::text",
                "pg_depend" or "pg_shdepend" => "x.classid::text",
                _ => $"'{name}'::regclass::oid::text",
            };
            string objectId = name switch
            {
                "pg_attribute" => "x.attrelid::text",
                "pg_index" => "x.indexrelid::text",
                "pg_depend" or "pg_shdepend" => "x.objid::text",
                "pg_sequence" => "x.seqrelid::text",
                "pg_description" or "pg_seclabel" => "x.objoid::text",
                _ => OidCatalogs.Contains(name, StringComparer.Ordinal) ? "x.oid::text" : "''",
            };
            string filter = name == "pg_shdepend" ? "WHERE x.dbid=0 OR x.dbid=(SELECT oid FROM pg_database WHERE datname=current_database())" : string.Empty;
            await using var command = new NpgsqlCommand(
                $"WITH tuples AS (SELECT {oidKey} oid_key,encode(sha256(convert_to(to_jsonb(x)::text,'UTF8')),'hex') digest," +
                $"{objectClass} object_class,{objectId} object_id FROM pg_catalog.{name} x {filter})," +
                $"identified AS (SELECT {key} row_key,digest,object_class,object_id FROM tuples) " +
                "SELECT row_key,digest,object_class,object_id FROM identified ORDER BY row_key COLLATE \"C\";",
                connection, transaction);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            { catalog.Add(new(name, reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3))); }
        }
        var relationNames = new List<(string Schema, string Name)>();
        var sequenceNames = new List<(string Schema, string Name, string Owner)>();
        await using (var command = new NpgsqlCommand("""
            SELECT n.nspname,c.relname,c.relkind::text,pg_get_userbyid(c.relowner)::text
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'
            AND c.relkind IN ('r','p','S','v','m','f')
            ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C";
            """, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                string kind = reader.GetString(2);
                if (kind == "r") { relationNames.Add((reader.GetString(0), reader.GetString(1))); }
                else if (kind == "S") { sequenceNames.Add((reader.GetString(0), reader.GetString(1), reader.GetString(3))); }
                else { throw CurrentAppOwnedRepairPermit.Invalid(); }
            }
        }
        var relations = new List<CurrentAppOwnedRelationFact>();
        foreach ((string schema, string name) in relationNames)
        {
            await using var command = new NpgsqlCommand(
                $"SELECT count(*),encode(sha256(convert_to(coalesce(string_agg(h,'' ORDER BY h COLLATE \"C\"),''),'UTF8')),'hex') FROM " +
                $"(SELECT encode(sha256(convert_to(to_jsonb(x)::text,'UTF8')),'hex') h FROM {Qualified(schema, name)} x) rows;",
                connection, transaction);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw CurrentAppOwnedRepairPermit.Invalid(); }
            relations.Add(new(schema, name, reader.GetInt64(0), reader.GetString(1)));
        }
        var sequences = new List<CurrentAppOwnedSequenceFact>();
        foreach ((string schema, string name, string owner) in sequenceNames)
        {
            await using var command = new NpgsqlCommand(
                $"SELECT encode(sha256(convert_to(jsonb_build_object('last_value',s.last_value,'log_cnt',s.log_cnt,'is_called',s.is_called)::text,'UTF8')),'hex') FROM {Qualified(schema, name)} s;",
                connection, transaction);
            string tuple = Convert.ToString(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture)
                ?? throw CurrentAppOwnedRepairPermit.Invalid();
            sequences.Add(new(schema, name, owner, tuple));
        }
        return new(connection.Database, catalog, relations, sequences);
    }

    internal static void RequirePreserved(CurrentAppOwnedDatabaseSnapshot before, CurrentAppOwnedDatabaseSnapshot after,
        IReadOnlySet<string> reviewedNewObjectKeys, string[] newTables)
    {
        if (before.Database != after.Database) { throw CurrentAppOwnedRepairPermit.Invalid(); }
        var oldCatalog = before.Catalog.ToDictionary(x => x.Catalog + "/" + x.Key, StringComparer.Ordinal);
        var newCatalog = after.Catalog.ToDictionary(x => x.Catalog + "/" + x.Key, StringComparer.Ordinal);
        foreach ((string key, CurrentAppOwnedCatalogFact fact) in oldCatalog)
        { if (!newCatalog.TryGetValue(key, out CurrentAppOwnedCatalogFact? observed) || observed != fact) { throw CurrentAppOwnedRepairPermit.Invalid(); } }
        foreach ((string key, CurrentAppOwnedCatalogFact fact) in newCatalog)
        {
            if (oldCatalog.ContainsKey(key)) { continue; }
            if (fact.Catalog is not ("pg_class" or "pg_type" or "pg_attribute" or "pg_index" or "pg_constraint" or "pg_attrdef" or "pg_trigger" or "pg_depend" or "pg_shdepend") ||
                !reviewedNewObjectKeys.Contains(fact.ObjectClass + "/" + fact.ObjectId))
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
        }
        var expectedRelations = before.Relations.ToDictionary(x => x.Schema + "/" + x.Name, StringComparer.Ordinal);
        foreach (CurrentAppOwnedRelationFact relation in after.Relations)
        {
            if (expectedRelations.Remove(relation.Schema + "/" + relation.Name, out CurrentAppOwnedRelationFact? old))
            { if (old != relation) { throw CurrentAppOwnedRepairPermit.Invalid(); } }
            else if (relation.Schema != "public" || !newTables.Contains(relation.Name, StringComparer.Ordinal) || relation.Rows != 0)
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
        }
        if (expectedRelations.Count != 0 || !before.Sequences.SequenceEqual(after.Sequences))
        { throw CurrentAppOwnedRepairPermit.Invalid(); }
    }

    internal static async Task LockAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CurrentAppOwnedDatabaseSnapshot before, CancellationToken cancellationToken)
    {
        // Signed complete names, not a discovery SELECT before lock acquisition.
        foreach (CurrentAppOwnedRelationFact relation in before.Relations)
        {
            await using var command = new NpgsqlCommand($"LOCK TABLE ONLY {Qualified(relation.Schema, relation.Name)} IN ACCESS EXCLUSIVE MODE NOWAIT;",
                connection, transaction);
            _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        foreach (CurrentAppOwnedSequenceFact sequence in before.Sequences)
        {
            await using var command = new NpgsqlCommand($"ALTER SEQUENCE {Qualified(sequence.Schema, sequence.Name)} OWNER TO {PostgreSqlShadowTarget.QuoteIdentifier(sequence.Owner)};",
                connection, transaction);
            _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        foreach (string name in OidCatalogs.Concat(TupleCatalogs))
        {
            await using var command = new NpgsqlCommand($"LOCK TABLE pg_catalog.{name} IN SHARE MODE NOWAIT;", connection, transaction);
            _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    internal static async Task<IReadOnlySet<string>> ObserveNewObjectClosureAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, string database, string owner,
        CancellationToken cancellationToken)
    {
        string[] names = CurrentAppOwnedRepairManifest.NewTables(database);
        TableCopyPlan[] expected = [.. ApprovedCurrentConsumerTargetShapes.ForDatabase(database)];
        string[] expectedIndexes = [.. expected.SelectMany(x => x.Indexes.Select(i => i.Name)
            .Concat(x.PrimaryKey is null ? [] : [x.PrimaryKey.Name])).Order(StringComparer.Ordinal)];
        var relationIds = new List<uint>();
        var tableIds = new List<uint>();
        await using (var command = new NpgsqlCommand("""
            SELECT c.oid,c.relkind::text,pg_get_userbyid(c.relowner)::text,c.relacl IS NULL,
                c.relpersistence::text,c.relrowsecurity,c.relforcerowsecurity,c.reloptions IS NULL
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname=ANY($1) ORDER BY c.relname COLLATE "C";
            """, connection, transaction))
        {
            _ = command.Parameters.AddWithValue(names);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (reader.GetString(1) != "r" || reader.GetString(2) != owner || !reader.GetBoolean(3) ||
                    reader.GetString(4) != "p" || reader.GetBoolean(5) || reader.GetBoolean(6) || !reader.GetBoolean(7))
                { throw CurrentAppOwnedRepairPermit.Invalid(); }
                tableIds.Add(reader.GetFieldValue<uint>(0));
            }
        }
        if (tableIds.Count != names.Length) { throw CurrentAppOwnedRepairPermit.Invalid(); }
        relationIds.AddRange(tableIds);
        var actualIndexes = new List<string>();
        await using (var command = new NpgsqlCommand("""
            SELECT c.oid,c.relname,i.indisvalid AND i.indisready AND i.indislive,c.relacl IS NULL,
                pg_get_userbyid(c.relowner)::text
            FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid=ANY($1)
            ORDER BY c.relname COLLATE "C";
            """, connection, transaction))
        {
            _ = command.Parameters.AddWithValue(NpgsqlDbType.Array | NpgsqlDbType.Oid, tableIds.ToArray());
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (!reader.GetBoolean(2) || !reader.GetBoolean(3) || reader.GetString(4) != owner)
                { throw CurrentAppOwnedRepairPermit.Invalid(); }
                relationIds.Add(reader.GetFieldValue<uint>(0)); actualIndexes.Add(reader.GetString(1));
            }
        }
        if (!actualIndexes.SequenceEqual(expectedIndexes, StringComparer.Ordinal)) { throw CurrentAppOwnedRepairPermit.Invalid(); }
        await using (var command = new NpgsqlCommand("""
            SELECT c.reltoastrelid FROM pg_class c WHERE c.oid=ANY($1) AND c.reltoastrelid<>0
            UNION SELECT i.indexrelid FROM pg_class c JOIN pg_index i ON i.indrelid=c.reltoastrelid WHERE c.oid=ANY($1);
            """, connection, transaction))
        {
            _ = command.Parameters.AddWithValue(NpgsqlDbType.Array | NpgsqlDbType.Oid, tableIds.ToArray());
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { relationIds.Add(reader.GetFieldValue<uint>(0)); }
        }
        await using (var command = new NpgsqlCommand("""
            SELECT
                (SELECT count(*) FROM pg_policy WHERE polrelid=ANY($1))=0 AND
                NOT EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
                    JOIN pg_namespace n ON n.oid=p.pronamespace WHERE t.tgrelid=ANY($1) AND
                    (NOT t.tgisinternal OR t.tgenabled<>'O' OR n.nspname<>'pg_catalog'
                    OR p.proname NOT IN ('RI_FKey_check_ins','RI_FKey_check_upd','RI_FKey_cascade_del','RI_FKey_noaction_upd'))) AND
                NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=ANY($1) AND
                    (NOT convalidated OR NOT conenforced OR contype NOT IN ('n','p','c','f'))) AND
                (SELECT count(*) FROM pg_trigger WHERE tgrelid=ANY($1))=$2 AND
                (SELECT count(*) FROM pg_constraint WHERE conrelid=ANY($1) AND contype='n')=$3 AND
                (SELECT count(*) FROM pg_constraint WHERE conrelid=ANY($1) AND contype='p')=$4 AND
                (SELECT count(*) FROM pg_constraint WHERE conrelid=ANY($1) AND contype='c')=$5 AND
                (SELECT count(*) FROM pg_constraint WHERE conrelid=ANY($1) AND contype='f')=$6;
            """, connection, transaction))
        {
            _ = command.Parameters.AddWithValue(NpgsqlDbType.Array | NpgsqlDbType.Oid, tableIds.ToArray());
            _ = command.Parameters.AddWithValue(expected.Sum(x => x.ForeignKeys.Count) * 4);
            _ = command.Parameters.AddWithValue(expected.Sum(x => x.OrderedColumns.Count - x.NullableColumns.Count));
            _ = command.Parameters.AddWithValue(expected.Count(x => x.PrimaryKey is not null));
            _ = command.Parameters.AddWithValue(expected.Sum(x => x.CheckConstraints.Count));
            _ = command.Parameters.AddWithValue(expected.Sum(x => x.ForeignKeys.Count));
            if (await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is not true)
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
        }
        var result = new HashSet<string>(StringComparer.Ordinal);
        const string closureSql = """
            WITH rowtypes AS (SELECT oid FROM pg_type WHERE typrelid=ANY($1)),
            objects AS (
              SELECT 'pg_class'::regclass::oid classid,unnest($1::oid[]) objid
              UNION SELECT 'pg_type'::regclass::oid,oid FROM pg_type WHERE oid IN (SELECT oid FROM rowtypes) OR typelem IN (SELECT oid FROM rowtypes)
              UNION SELECT 'pg_constraint'::regclass::oid,oid FROM pg_constraint WHERE conrelid=ANY($2)
              UNION SELECT 'pg_attrdef'::regclass::oid,oid FROM pg_attrdef WHERE adrelid=ANY($2)
              UNION SELECT 'pg_trigger'::regclass::oid,oid FROM pg_trigger WHERE tgrelid=ANY($2))
            SELECT classid::text,objid::text FROM objects ORDER BY 1,2;
            """;
        await using (var command = new NpgsqlCommand(closureSql, connection, transaction))
        {
            _ = command.Parameters.AddWithValue(NpgsqlDbType.Array | NpgsqlDbType.Oid, relationIds.ToArray());
            _ = command.Parameters.AddWithValue(NpgsqlDbType.Array | NpgsqlDbType.Oid, tableIds.ToArray());
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            { if (!result.Add(reader.GetString(0) + "/" + reader.GetString(1))) { throw CurrentAppOwnedRepairPermit.Invalid(); } }
        }
        return result;
    }
    private static string Qualified(string schema, string name)
    {
        return $"{PostgreSqlShadowTarget.QuoteIdentifier(schema)}.{PostgreSqlShadowTarget.QuoteIdentifier(name)}";
    }
}
