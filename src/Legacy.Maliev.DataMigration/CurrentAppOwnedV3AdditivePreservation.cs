using System.Globalization;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;

namespace Legacy.Maliev.DataMigration;

internal sealed record V3AdditiveObservation(CurrentAppOwnedDatabaseSnapshot Snapshot,
    CurrentAppOwnedRelationFact? InvoiceProjection, string? InvoiceClassKey,
    string? InvoiceClassNormalizedSha256, IReadOnlySet<string> AddedCatalogKeys,
    IReadOnlySet<string> NewObjectClosure);

/// <summary>Exact V3 additive native preservation observation. Does not issue execution authority.</summary>
internal static class CurrentAppOwnedV3AdditivePreservation
{
    private static readonly string[] Added = ["OriginIssuer", "FinancialResultJson", "FinancialOwnershipJson", "EmployeeCompletionJson"];
    private static readonly string[] Databases = ["Invoice", "PurchaseOrder", "Quotation"];

    internal static async Task<V3AdditiveObservation> CaptureAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, FreshSchemaPlan before, FreshSchemaPlan after,
        string expectedSourceSha, bool isAfter, DateTimeOffset now, CancellationToken ct, string? expectedOwner = null)
    {
        if (expectedOwner is not null && expectedOwner is not ("legacy_local" or "postgres")) { throw Invalid(); }
        RequirePair(before, after, expectedSourceSha, now);
        if (!Databases.Contains(connection.Database, StringComparer.Ordinal)) { throw Invalid(); }
        DatabaseSchemaPlan plan = (isAfter ? after : before).Databases.Single(x => x.Database == connection.Database);
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
        if (await inspector.InspectSchemaAsync(plan, ct).ConfigureAwait(false) != plan.TargetSchemaSha256) { throw Invalid(); }
        CurrentAppOwnedDatabaseSnapshot snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
        if (connection.Database != "Invoice")
        {
            string[] newNames = NewTables(connection.Database);
            if (!isAfter && snapshot.Relations.Any(x => x.Schema == "public" && newNames.Contains(x.Name, StringComparer.Ordinal))) { throw Invalid(); }
            IReadOnlySet<string> closure = isAfter
                ? await ObserveNewClosureAsync(connection, transaction, plan, ct, expectedOwner).ConfigureAwait(false)
                : new HashSet<string>(StringComparer.Ordinal);
            return new(snapshot, null, null, null, new HashSet<string>(StringComparer.Ordinal), closure);
        }
        CurrentAppOwnedRelationFact projection;
        string remove = isAfter ? " - ARRAY['OriginIssuer','FinancialResultJson','FinancialOwnershipJson','EmployeeCompletionJson']" : string.Empty;
        await using (var command = new NpgsqlCommand(
            "SELECT count(*),encode(sha256(convert_to(coalesce(string_agg(h,'' ORDER BY h COLLATE \"C\"),''),'UTF8')),'hex') FROM " +
            $"(SELECT encode(sha256(convert_to((to_jsonb(x){remove})::text,'UTF8')),'hex') h FROM public.\"InvoiceCreationAdmission\" x) rows;", connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw Invalid(); }
            projection = new("public", "InvoiceCreationAdmission", reader.GetInt64(0), reader.GetString(1));
        }
        if (isAfter)
        {
            await using var command = new NpgsqlCommand("SELECT NOT EXISTS(SELECT 1 FROM public.\"InvoiceCreationAdmission\" WHERE " +
                string.Join(" OR ", Added.Select(x => PostgreSqlShadowTarget.QuoteIdentifier(x) + " IS NOT NULL")) + ");", connection, transaction);
            if (await command.ExecuteScalarAsync(ct).ConfigureAwait(false) is not true) { throw Invalid(); }
        }
        string tableId;
        string normalizedClass;
        await using (var command = new NpgsqlCommand("""
            SELECT c.oid::text,encode(sha256(convert_to((to_jsonb(c)||jsonb_build_object('relnatts',9))::text,'UTF8')),'hex')
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname='InvoiceCreationAdmission' AND c.relkind='r' AND c.relnatts=$1;
            """, connection, transaction))
        {
            _ = command.Parameters.AddWithValue(isAfter ? 13 : 9);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw Invalid(); }
            tableId = reader.GetString(0); normalizedClass = reader.GetString(1);
        }
        var additions = new HashSet<string>(StringComparer.Ordinal);
        if (isAfter)
        {
            await using (var command = new NpgsqlCommand("""
                SELECT a.attnum,a.attname,encode(sha256(convert_to(to_jsonb(a)::text,'UTF8')),'hex')
                FROM pg_attribute a JOIN pg_type t ON t.oid=a.atttypid JOIN pg_namespace tn ON tn.oid=t.typnamespace
                JOIN pg_collation c ON c.oid=a.attcollation JOIN pg_namespace cn ON cn.oid=c.collnamespace
                WHERE a.attrelid=$1 AND a.attnum BETWEEN 10 AND 13 AND NOT a.attisdropped AND NOT a.attnotnull
                  AND NOT a.atthasdef AND a.attidentity='' AND a.attgenerated='' AND NOT a.atthasmissing AND a.attmissingval IS NULL
                  AND a.attacl IS NULL AND a.attoptions IS NULL AND a.attfdwoptions IS NULL AND a.attstattarget IS NULL
                  AND a.attndims=0 AND a.attlen=t.typlen AND a.attbyval=t.typbyval
                  AND a.attalign=t.typalign AND a.attstorage=t.typstorage AND a.attcompression=''
                  AND a.attislocal AND a.attinhcount=0 AND tn.nspname='pg_catalog' AND cn.nspname='pg_catalog' AND c.collname='C'
                  AND ((a.attnum=10 AND t.typname='varchar' AND a.atttypmod=516) OR
                       (a.attnum BETWEEN 11 AND 13 AND t.typname='text' AND a.atttypmod=-1)) ORDER BY a.attnum;
                """, connection, transaction))
            {
                _ = command.Parameters.AddWithValue(NpgsqlDbType.Oid, uint.Parse(tableId, CultureInfo.InvariantCulture));
                await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
                int index = 0;
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    if (index >= 4 || reader.GetInt16(0) != index + 10 || reader.GetString(1) != Added[index++]) { throw Invalid(); }
                    AddExactDigest("pg_attribute", reader.GetString(2));
                }
                if (index != 4) { throw Invalid(); }
            }
            await using (var command = new NpgsqlCommand("""
                SELECT encode(sha256(convert_to(to_jsonb(d)::text,'UTF8')),'hex') FROM pg_depend d
                JOIN pg_collation c ON c.oid=d.refobjid JOIN pg_namespace n ON n.oid=c.collnamespace
                WHERE d.classid='pg_class'::regclass AND d.objid=$1 AND d.objsubid BETWEEN 10 AND 13
                    AND d.refclassid='pg_collation'::regclass AND d.refobjsubid=0 AND d.deptype='n'
                    AND c.collname='C' AND n.nspname='pg_catalog';
                """, connection, transaction))
            {
                _ = command.Parameters.AddWithValue(NpgsqlDbType.Oid, uint.Parse(tableId, CultureInfo.InvariantCulture));
                await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
                while (await reader.ReadAsync(ct).ConfigureAwait(false)) { AddExactDigest("pg_depend", reader.GetString(0)); }
            }
        }
        return new(snapshot, projection, tableId, normalizedClass, additions, new HashSet<string>(StringComparer.Ordinal));

        void AddExactDigest(string catalog, string digest)
        {
            CurrentAppOwnedCatalogFact[] facts = [.. snapshot.Catalog.Where(x => x.Catalog == catalog && x.Sha256 == digest)];
            if (facts.Length != 1 || !additions.Add(catalog + "/" + facts[0].Key)) { throw Invalid(); }
        }
    }

    internal static void RequirePreserved(V3AdditiveObservation before, V3AdditiveObservation after)
    {
        string database = before.Snapshot.Database;
        if (database != after.Snapshot.Database || !Databases.Contains(database, StringComparer.Ordinal) ||
            !before.Snapshot.Sequences.SequenceEqual(after.Snapshot.Sequences)) { throw Invalid(); }
        string[] newTables = NewTables(database);
        var retained = before.Snapshot.Relations.ToDictionary(x => x.Schema + "/" + x.Name, StringComparer.Ordinal);
        foreach (CurrentAppOwnedRelationFact observed in after.Snapshot.Relations)
        {
            if (retained.Remove(observed.Schema + "/" + observed.Name, out CurrentAppOwnedRelationFact? original))
            {
                if (database == "Invoice" && observed.Schema == "public" && observed.Name == "InvoiceCreationAdmission")
                { if (original != before.InvoiceProjection || original != after.InvoiceProjection) { throw Invalid(); } }
                else if (original != observed) { throw Invalid(); }
            }
            else if (observed.Schema != "public" || !newTables.Contains(observed.Name, StringComparer.Ordinal) || observed.Rows != 0) { throw Invalid(); }
        }
        if (retained.Count != 0 || after.Snapshot.Relations.Count != before.Snapshot.Relations.Count + newTables.Length) { throw Invalid(); }
        var oldCatalog = before.Snapshot.Catalog.ToDictionary(x => x.Catalog + "/" + x.Key, StringComparer.Ordinal);
        var currentCatalog = after.Snapshot.Catalog.ToDictionary(x => x.Catalog + "/" + x.Key, StringComparer.Ordinal);
        foreach ((string key, CurrentAppOwnedCatalogFact original) in oldCatalog)
        {
            if (!currentCatalog.TryGetValue(key, out CurrentAppOwnedCatalogFact? actual)) { throw Invalid(); }
            if (database == "Invoice" && original.Catalog == "pg_class" && original.Key == before.InvoiceClassKey)
            {
                if (before.InvoiceClassKey != after.InvoiceClassKey || before.InvoiceClassNormalizedSha256 != original.Sha256 ||
                    before.InvoiceClassNormalizedSha256 != after.InvoiceClassNormalizedSha256 ||
                    (original with { Sha256 = actual.Sha256 }) != actual) { throw Invalid(); }
            }
            else if (original != actual) { throw Invalid(); }
        }
        foreach ((string key, CurrentAppOwnedCatalogFact actual) in currentCatalog)
        {
            if (oldCatalog.ContainsKey(key)) { continue; }
            if (database == "Invoice") { if (!after.AddedCatalogKeys.Contains(key)) { throw Invalid(); } }
            else if (actual.Catalog is not ("pg_class" or "pg_type" or "pg_attribute" or "pg_index" or "pg_constraint" or "pg_depend" or "pg_shdepend") ||
                !after.NewObjectClosure.Contains(actual.ObjectClass + "/" + actual.ObjectId)) { throw Invalid(); }
        }
        if (database == "Invoice" && after.AddedCatalogKeys.Any(oldCatalog.ContainsKey)) { throw Invalid(); }
    }

    private static void RequirePair(FreshSchemaPlan before, FreshSchemaPlan after, string source, DateTimeOffset now)
    {
        ProductionSchemaCatalogInspector.ValidatePlan(before, now); ProductionSchemaCatalogInspector.ValidatePlan(after, now);
        if (source.Length != 40 || !source.All(x => x is (>= '0' and <= '9') or (>= 'a' and <= 'f')) ||
            before.SourceCommitSha != source || after.SourceCommitSha != source ||
            !ApprovedConsumerOverlaySelection.IsApproved(before) || !ApprovedConsumerOverlaySelection.IsApproved(after) ||
            before.Databases.Sum(x => x.Tables.Count) != 100 || after.Databases.Sum(x => x.Tables.Count) != 100 ||
            after.Databases.Single(x => x.Database == "Quotation").SourceDispositionProfile != ApprovedSourceDispositionManifest.QuotationOutboxesV1)
        { throw Invalid(); }
        foreach ((DatabaseSchemaPlan left, DatabaseSchemaPlan right) in before.Databases.Zip(after.Databases))
        {
            if (left.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(left.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV2) ||
                right.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(right.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3) ||
                JsonSerializer.Serialize(left with { TargetExtensionProfile = right.TargetExtensionProfile, TargetSchemaSha256 = right.TargetSchemaSha256 }) != JsonSerializer.Serialize(right)) { throw Invalid(); }
        }
    }

    private static string[] NewTables(string database)
    {
        return database switch
        {
            "PurchaseOrder" => ["OrderItemCreateReceipt", "PurchaseOrderFileCreateReceipt"],
            "Quotation" => ["QuotationInvoiceCompletionOperation"],
            "Invoice" => [],
            _ => throw Invalid(),
        };
    }

    private static MigrationExecutionException Invalid()
    {
        return new("v3_additive_native_preservation_invalid", "The fixed V3 additive native preservation contract failed.");
    }

    private static async Task<IReadOnlySet<string>> ObserveNewClosureAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, DatabaseSchemaPlan plan,
        CancellationToken cancellationToken, string? expectedOwner)
    {
        string[] names = NewTables(plan.Database);
        string owner = expectedOwner ?? new NpgsqlConnectionStringBuilder(connection.ConnectionString).Username ?? throw Invalid();
        TableCopyPlan[] expected = [.. ApprovedTargetExtensionManifest.TablesFor(plan).Where(x => names.Contains(x.TargetTable, StringComparer.Ordinal))];
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
                { throw Invalid(); }
                tableIds.Add(reader.GetFieldValue<uint>(0));
            }
        }
        if (tableIds.Count != names.Length) { throw Invalid(); }
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
                { throw Invalid(); }
                relationIds.Add(reader.GetFieldValue<uint>(0)); actualIndexes.Add(reader.GetString(1));
            }
        }
        if (!actualIndexes.SequenceEqual(expectedIndexes, StringComparer.Ordinal)) { throw Invalid(); }
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
            { throw Invalid(); }
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
            { if (!result.Add(reader.GetString(0) + "/" + reader.GetString(1))) { throw Invalid(); } }
        }
        return result;
    }
}
