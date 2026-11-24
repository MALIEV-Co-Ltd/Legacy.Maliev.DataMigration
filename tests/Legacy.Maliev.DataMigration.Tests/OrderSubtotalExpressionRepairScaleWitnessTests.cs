using System.Data;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;
using Xunit.Abstractions;

namespace Legacy.Maliev.DataMigration.Tests;

// Synthetic full HistoricalDefaults Order database, not source freshness or persistent execution authority.
public abstract class OrderSubtotalExpressionRepairScaleWitnessBase(OrderSubtotalExpressionRepairScaleFixture fixture, ITestOutputHelper output)
{
    private sealed record Observation(CurrentAppOwnedRetained31Observation Native, string OriginalProjection,
        string ExpectedCorrectedRows, string ActualRows, string ObjectDefinitions, uint TableOid,
        IReadOnlyDictionary<string, StorageFact> Storage)
    {
        internal int ProviderVersion { get; init; }
        internal string CompositeDefense { get; init; } = string.Empty;
        internal ulong WalLower { get; init; }
        internal ulong WalUpper { get; init; }
        internal IReadOnlyDictionary<string, StorageFact> AllStorage { get; init; } = new Dictionary<string, StorageFact>(StringComparer.Ordinal);
    }
    private sealed record StorageFact(string Relation, uint FileNode, long Blocks, bool OrderClosure);
    private static readonly string[] StructuralWitnessCatalogs =
        ["pg_class", "pg_attribute", "pg_attrdef", "pg_depend", "pg_type", "pg_index", "pg_constraint", "pg_statistic_ext", "pg_description", "pg_shdepend"];

    private static readonly string[] SeedTableOrder = ["Category", "Process", "FileFormat", "sysdiagrams", "Order", "OrderFile"];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Full_historical_Order_13008_rows_reports_exact_rewrite_closure(bool alphabetical)
    {
        FreshSchemaPlan logical = ConsumerColumnBootstrapTestData.WithCorrectedOrder(ConsumerColumnBootstrapTestData.Logical());
        string original = JsonSerializer.Serialize(logical);
        var initial = OrderSubtotalExpressionRepairContract.Create(logical, logical.SourceCommitSha,
            OrderSubtotalExpressionRepairContract.HistoricalExpression, ConsumerColumnBootstrapTestData.Now);
        DatabaseSchemaPlan physical = initial.BeforePhysical();
        Assert.Equal(6, physical.Tables.Count);
        Assert.Equal(27, physical.Tables.Single(x => x.TargetTable == "Order").OrderedColumns.Count);
        Assert.DoesNotContain(physical.Tables, x => x.TargetTable == "OrderDeletionIntent");
        if (alphabetical)
        {
            // Detached physical fixture only; original source and contract views remain unchanged.
            physical = physical with
            {
                Tables = [.. physical.Tables.Select(x => x with
                { OrderedColumns = [.. x.OrderedColumns.Order(StringComparer.Ordinal)] })]
            };
            physical = physical with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(physical) };
        }
        output.WriteLine("ORDER_SCALE_WITNESS_INPUT " + JsonSerializer.Serialize(new
        {
            Rows = 13008,
            alphabetical,
            fixture.ExpectedVersion,
            LogicalSha256 = initial.LogicalSourcePlanSha256,
            PhysicalSchemaSha256 = physical.TargetSchemaSha256,
            SyntheticNonLive = true,
            NoExecutionAuthority = true,
            Tables = physical.Tables.Select(x => new { x.TargetSchema, x.TargetTable, x.OrderedColumns }).ToArray()
        }));
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        CancellationToken ct = deadline.Token;
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync("Order", $"legacy_shadow_order_scale_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), ct);
        ExceptionDispatchInfo? primary = null; Exception? cleanupFailure = null;
        try
        {
            string settings = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = shadow.Name, Pooling = false }.ConnectionString;
            await using var connection = new NpgsqlConnection(settings);
            await connection.OpenAsync(ct);
            OrderSubtotalExpressionRepairContract contract;
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct))
            {
                await using var schema = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                await schema.ApplySchemaAsync(physical, ct);
                await schema.FinalizeSchemaAsync(physical, ct);
                Assert.Equal(physical.TargetSchemaSha256, await schema.InspectSchemaAsync(physical, ct));
                foreach (string table in SeedTableOrder)
                {
                    TableCopyPlan model = physical.Tables.Single(x => x.TargetTable == table);
                    await SeedModelAsync(connection, transaction, model, table == "Order" ? 13008 : 3, ct);
                }
                await ExecuteAsync(connection, transaction, """
                    CREATE SCHEMA legacy_migration_internal;
                    CREATE TABLE legacy_migration_internal."Journal" ("ID" integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"Effect" text NOT NULL);
                    INSERT INTO legacy_migration_internal."Journal" ("Effect") VALUES ('synthetic retained effect ไทย  ');
                    CREATE FUNCTION public."ObserveOrderMutation"() RETURNS trigger LANGUAGE plpgsql AS $$
                    BEGIN INSERT INTO legacy_migration_internal."Journal" ("Effect") VALUES (TG_OP); RETURN NULL; END $$;
                    CREATE TRIGGER "ObserveOrderMutation" AFTER INSERT OR UPDATE OR DELETE ON public."Order"
                    FOR EACH ROW EXECUTE FUNCTION public."ObserveOrderMutation"();
                    CREATE INDEX "IX_Order_Scale_Subtotal" ON public."Order" ("Subtotal");
                    ALTER TABLE public."Order" ADD CONSTRAINT "CK_Order_Scale_Subtotal" CHECK ("Subtotal" IS NULL OR "Subtotal">=-9999999999999999.99);
                    ANALYZE public."Order";
                    """, ct);
                string observed = await ReadExpressionAsync(connection, transaction, ct);
                contract = OrderSubtotalExpressionRepairContract.Create(logical, logical.SourceCommitSha, observed, ConsumerColumnBootstrapTestData.Now);
                await transaction.CommitAsync(ct);
            }
            Observation baseline;
            OrderSubtotalExpressionRepairNativeObservation guardBaseline;
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct))
            {
                baseline = await CaptureAsync(connection, transaction, ct);
                guardBaseline = await OrderSubtotalExpressionRepairNativePreservation.CaptureAsync(connection, transaction, contract, after: false, ct);
                Assert.Equal(fixture.ExpectedVersion, baseline.ProviderVersion);
                Assert.Equal(13008L, baseline.Native.Snapshot.Relations.Single(x => x.Schema == "public" && x.Name == "Order").Rows);
                await ExecuteAsync(connection, transaction, OrderSubtotalExpressionRepairContract.CandidateSql(), ct);
                Observation changed = await CaptureAsync(connection, transaction, ct);
                RequirePreserved(baseline, changed);
                var guardChanged = await OrderSubtotalExpressionRepairNativePreservation.CaptureAsync(connection, transaction, contract, after: true, ct);
                OrderSubtotalExpressionRepairNativePreservation.RequirePreserved(guardBaseline, guardChanged, contract);
                OrderSubtotalExpressionRepairNativeMutationTests.RequireRejectedMutations(guardBaseline, guardChanged, contract);
                Report(baseline, changed, "scale-rollback-preparation");
                await RequireExpressionAsync(connection, transaction, OrderSubtotalExpressionRepairContract.CorrectedExpression, ct);
                await transaction.RollbackAsync(ct);
            }
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct))
            {
                Observation rolledBack = await CaptureAsync(connection, transaction, ct);
                Assert.Equal(baseline.Native.Snapshot.Sha256, rolledBack.Native.Snapshot.Sha256);
                Assert.Equal(baseline.ActualRows, rolledBack.ActualRows);
                await RequireExpressionAsync(connection, transaction, contract.ObservedHistoricalExpression, ct);
                await transaction.RollbackAsync(ct);
            }
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct))
            {
                Assert.Equal(baseline.Native.Snapshot.Sha256, (await CaptureAsync(connection, transaction, ct)).Native.Snapshot.Sha256);
                await ExecuteAsync(connection, transaction, OrderSubtotalExpressionRepairContract.CandidateSql(), ct);
                Observation changed = await CaptureAsync(connection, transaction, ct);
                RequirePreserved(baseline, changed);
                var guardChanged = await OrderSubtotalExpressionRepairNativePreservation.CaptureAsync(connection, transaction, contract, after: true, ct);
                OrderSubtotalExpressionRepairNativePreservation.RequirePreserved(guardBaseline, guardChanged, contract);
                OrderSubtotalExpressionRepairNativeMutationTests.RequireRejectedMutations(guardBaseline, guardChanged, contract);
                Report(baseline, changed, "scale-prepared-commit");
                await transaction.CommitAsync(ct);
            }
            await connection.CloseAsync();
            await using var independent = new NpgsqlConnection(settings);
            await independent.OpenAsync(ct);
            await using (var transaction = await independent.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct))
            {
                Observation committed = await CaptureAsync(independent, transaction, ct);
                RequirePreserved(baseline, committed);
                var guardCommitted = await OrderSubtotalExpressionRepairNativePreservation.CaptureAsync(independent, transaction, contract, after: true, ct);
                OrderSubtotalExpressionRepairNativePreservation.RequirePreserved(guardBaseline, guardCommitted, contract);
                Report(baseline, committed, "scale-independent-commit-readback");
                await RequireExpressionAsync(independent, transaction, OrderSubtotalExpressionRepairContract.CorrectedExpression, ct);
                await transaction.RollbackAsync(ct);
            }
            Assert.Equal(original, JsonSerializer.Serialize(logical));
            Assert.Equal(SchemaPlanCanonicalizer.ComputeSha256(logical), contract.LogicalSourcePlanSha256);
        }
        catch (Exception failure) { primary = ExceptionDispatchInfo.Capture(failure); }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            try { await target.DeleteRunOwnedShadowAsync(shadow, cleanup.Token); }
            catch (Exception failure) { cleanupFailure = failure; }
        }
        if (cleanupFailure is not null)
        {
            if (primary is not null) { throw new AggregateException("Scale witness and cleanup failed.", primary.SourceException, cleanupFailure); }
            ExceptionDispatchInfo.Capture(cleanupFailure).Throw();
        }
        primary?.Throw();
    }

    private static Task SeedModelAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, TableCopyPlan table, int count, CancellationToken ct)
    {
        string[] columns = [.. table.OrderedColumns.Where(column => !table.GeneratedColumns.Any(generated => generated.Column == column))];
        string values = string.Join(',', columns.Select(column => SyntheticValue(table, column)));
        return ExecuteAsync(connection, transaction, "INSERT INTO " + PostgreSqlShadowTarget.QuoteIdentifier(table.TargetSchema) + "." +
            PostgreSqlShadowTarget.QuoteIdentifier(table.TargetTable) + " (" + string.Join(',', columns.Select(PostgreSqlShadowTarget.QuoteIdentifier)) +
            ") SELECT " + values + " FROM generate_series(1," + count.ToString(System.Globalization.CultureInfo.InvariantCulture) + ") AS seed(g);", ct);
    }

    private static string SyntheticValue(TableCopyPlan table, string column)
    {
        if (table.IdentityColumns.Contains(column, StringComparer.Ordinal)) { return "g"; }
        if (column is "ID" or "diagram_id") { return "g"; }
        if (table.TargetTable == "Order")
        {
            if (column == "UnitPrice") { return "CASE g%8 WHEN 0 THEN 9999999999990024.76 WHEN 1 THEN -9999999999990024.76 WHEN 2 THEN 0.15 WHEN 3 THEN -0.15 WHEN 4 THEN NULL WHEN 6 THEN 9999999999999999.99 ELSE 1 END"; }
            if (column == "Quantity") { return "CASE g%8 WHEN 0 THEN 2 WHEN 1 THEN 2 WHEN 6 THEN 1 WHEN 7 THEN 0 ELSE 1 END"; }
            if (column == "DiscountPercent") { return "CASE g%8 WHEN 0 THEN 99.99 WHEN 1 THEN 99.99 WHEN 2 THEN 10 WHEN 3 THEN 10 WHEN 5 THEN NULL ELSE 0 END"; }
            if (column == "Manufactured") { return "g%2"; }
            if (column == "Comment") { return "CASE WHEN g%7=0 THEN NULL WHEN g%13=0 THEN 'ไทย  '||(SELECT string_agg(md5(g::text||':'||s::text),'' ORDER BY s) FROM generate_series(1,300) AS wide(s))||'  ' ELSE 'synthetic ไทย  ' END"; }
        }
        string type = table.ColumnTypes[column];
        string value = type switch
        {
            "integer" => "1",
            "boolean" => "(g%2=0)",
            "bytea" => "decode('00ff0102','hex')",
            "date" => "DATE '2026-01-01'+(g%30)",
            "timestamp without time zone" => "TIMESTAMP '2026-01-01 01:02:03.123456'+g*INTERVAL '1 microsecond'",
            "text" => "('synthetic ไทย '||g::text||'  ')",
            _ when type.StartsWith("character varying(", StringComparison.Ordinal) => "('synthetic ไทย '||g::text||'  ')",
            _ => throw new InvalidOperationException("Uncharacterized synthetic scale type: " + table.TargetTable + "." + column + ":" + type),
        };
        // Required foreign-key values stay present; optional values deliberately alternate NULL.
        return table.NullableColumns.Contains(column, StringComparer.Ordinal) && !table.ForeignKeys.Any(key => key.Columns.Contains(column, StringComparer.Ordinal))
            ? "CASE WHEN g%7=0 THEN NULL ELSE " + value + " END" : value;
    }
    private static async Task<Observation> CaptureAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    {
        int version; string defense; ulong lower;
        await using (var provider = new NpgsqlCommand("SELECT current_setting('server_version_num')::integer,coalesce(current_setting('composite_type_mismatch',true),''),pg_current_wal_insert_lsn()::text;", connection, transaction))
        await using (var reader = await provider.ExecuteReaderAsync(ct))
        {
            Assert.True(await reader.ReadAsync(ct)); version = reader.GetInt32(0); defense = reader.GetString(1); lower = ParseWal(reader.GetString(2));
        }
        CurrentAppOwnedRetained31Observation native = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, ct);
        string projection = await RowsAsync(connection, transaction, "to_jsonb(x)-'Subtotal'", ct);
        string expected = await RowsAsync(connection, transaction, "(to_jsonb(x)-'Subtotal')||jsonb_build_object('Subtotal'," +
            OrderSubtotalExpressionRepairContract.CorrectedExpression + ")", ct);
        string actual = await RowsAsync(connection, transaction, "to_jsonb(x)", ct);
        const string objects = """
            SELECT coalesce(jsonb_agg(v ORDER BY v::text)::text,'[]') FROM (
              SELECT jsonb_build_array('index',c.relname,pg_get_indexdef(c.oid)) v FROM pg_class c JOIN pg_index i ON i.indexrelid=c.oid
                WHERE i.indrelid='public."Order"'::regclass
              UNION ALL SELECT jsonb_build_array('constraint',conname,pg_get_constraintdef(oid)) FROM pg_constraint WHERE conrelid='public."Order"'::regclass
              UNION ALL SELECT jsonb_build_array('trigger',tgname,pg_get_triggerdef(oid)) FROM pg_trigger WHERE tgrelid='public."Order"'::regclass
            ) objects;
            """;
        await using var command = new NpgsqlCommand(objects, connection, transaction) { CommandTimeout = 120 };
        string definitions = (string)(await command.ExecuteScalarAsync(ct))!;
        await using var oid = new NpgsqlCommand("SELECT 'public.\"Order\"'::regclass::oid;", connection, transaction) { CommandTimeout = 120 };
        uint tableOid = (uint)(await oid.ExecuteScalarAsync(ct))!;
        var storage = new Dictionary<string, StorageFact>(StringComparer.Ordinal);
        await using var physical = new NpgsqlCommand("""
            WITH roots AS (
              SELECT c.oid,c.reltoastrelid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE c.relkind='r' AND n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'
            ), operand AS (SELECT oid,reltoastrelid FROM pg_class WHERE oid='public."Order"'::regclass)
            SELECT c.oid::text,n.nspname||'.'||c.relname,pg_relation_filenode(c.oid),
              pg_relation_size(c.oid)/current_setting('block_size')::bigint,
              c.oid IN (SELECT oid FROM operand UNION ALL SELECT reltoastrelid FROM operand) OR
                coalesce(i.indrelid IN (SELECT oid FROM operand UNION ALL SELECT reltoastrelid FROM operand),false)
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_index i ON i.indexrelid=c.oid
            WHERE c.relkind IN ('r','i','t') AND
              ((n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema') OR
               c.oid IN (SELECT reltoastrelid FROM roots) OR i.indrelid IN (SELECT reltoastrelid FROM roots));
            """, connection, transaction) { CommandTimeout = 120 };
        await using (NpgsqlDataReader reader = await physical.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            { storage.Add(reader.GetString(0), new(reader.GetString(1), reader.GetFieldValue<uint>(2), reader.GetInt64(3), reader.GetBoolean(4))); }
        }
        var allStorage = new Dictionary<string, StorageFact>(StringComparer.Ordinal);
        await using (var all = new NpgsqlCommand("""
            WITH operand AS (SELECT oid,reltoastrelid FROM pg_class WHERE oid='public."Order"'::regclass)
            SELECT c.oid::text,n.nspname||'.'||c.relname,coalesce(pg_relation_filenode(c.oid),0::oid),
              pg_relation_size(c.oid)/current_setting('block_size')::bigint,
              c.oid IN (SELECT oid FROM operand UNION ALL SELECT reltoastrelid FROM operand) OR
                coalesce(i.indrelid IN (SELECT oid FROM operand UNION ALL SELECT reltoastrelid FROM operand),false)
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_index i ON i.indexrelid=c.oid
            WHERE c.relkind IN ('r','i','t') ORDER BY c.oid;
            """, connection, transaction) { CommandTimeout = 120 })
        await using (var reader = await all.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            { allStorage.Add(reader.GetString(0), new(reader.GetString(1), reader.GetFieldValue<uint>(2), reader.GetInt64(3), reader.GetBoolean(4))); }
        }
        await using var wal = new NpgsqlCommand("SELECT pg_current_wal_insert_lsn()::text;", connection, transaction);
        ulong upper = ParseWal((string)(await wal.ExecuteScalarAsync(ct))!);
        return new(native, projection, expected, actual, definitions, tableOid, storage)
        { ProviderVersion = version, CompositeDefense = defense, WalLower = lower, WalUpper = upper, AllStorage = allStorage };
    }

    private static ulong ParseWal(string value)
    {
        string[] parts = value.Split('/');
        Assert.Equal(2, parts.Length);
        return ((ulong)uint.Parse(parts[0], System.Globalization.NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture) << 32) |
            uint.Parse(parts[1], System.Globalization.NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static void RequirePreserved(Observation before, Observation after)
    {
        Assert.Equal(before.TableOid, after.TableOid);
        // Only these catalog families had a rewrite delta in the retained small fixture.
        // New scale effects outside them fail; raw deltas inside them remain characterization, not admission.
        foreach (string catalog in before.Native.Snapshot.Catalog.Select(x => x.Catalog)
            .Concat(after.Native.Snapshot.Catalog.Select(x => x.Catalog)).Distinct(StringComparer.Ordinal))
        {
            if (catalog is "pg_class" or "pg_attribute" or "pg_attrdef" or "pg_depend" or "pg_index" or "pg_constraint" or "pg_statistic") { continue; }
            Assert.Equal(before.Native.Read(catalog).Select(x => x.ToJsonString()).Order(StringComparer.Ordinal),
                after.Native.Read(catalog).Select(x => x.ToJsonString()).Order(StringComparer.Ordinal));
        }
        Assert.Equal(before.Native.Read("pg_statistic").Where(x => x["starelid"]?.ToString() != before.TableOid.ToString(System.Globalization.CultureInfo.InvariantCulture)).Select(x => x.ToJsonString()).Order(StringComparer.Ordinal),
            after.Native.Read("pg_statistic").Where(x => x["starelid"]?.ToString() != after.TableOid.ToString(System.Globalization.CultureInfo.InvariantCulture)).Select(x => x.ToJsonString()).Order(StringComparer.Ordinal));
        Assert.Equal(before.OriginalProjection, after.OriginalProjection);
        Assert.Equal(before.ExpectedCorrectedRows, after.ActualRows);
        Assert.Equal(before.ObjectDefinitions, after.ObjectDefinitions);
        Assert.Equal(before.Native.Snapshot.Sequences, after.Native.Snapshot.Sequences);
        Assert.Equal(before.Native.Snapshot.Relations.Where(x => x.Schema != "public" || x.Name != "Order"),
            after.Native.Snapshot.Relations.Where(x => x.Schema != "public" || x.Name != "Order"));
        Assert.Equal(before.Storage.Where(x => !x.Value.OrderClosure).OrderBy(x => x.Key, StringComparer.Ordinal),
            after.Storage.Where(x => !x.Value.OrderClosure).OrderBy(x => x.Key, StringComparer.Ordinal));
        // All generated rewrite/dependency/OID/storage effects are reported below, not admitted by a generic guard.
    }

    private void Report(Observation before, Observation after, string phase)
    {
        output.WriteLine("ORDER_REWRITE_WITNESS_PROVIDER " + JsonSerializer.Serialize(new
        {
            phase,
            Before = new { before.ProviderVersion, before.CompositeDefense, before.WalLower, before.WalUpper, before.TableOid },
            After = new { after.ProviderVersion, after.CompositeDefense, after.WalLower, after.WalUpper, after.TableOid }
        }));
        output.WriteLine("ORDER_REWRITE_WITNESS_STORAGE " + JsonSerializer.Serialize(new
        {
            phase,
            Before = before.AllStorage.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { Oid = pair.Key, Fact = pair.Value }).ToArray(),
            After = after.AllStorage.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { Oid = pair.Key, Fact = pair.Value }).ToArray()
        }));
        foreach (string catalog in StructuralWitnessCatalogs)
        {
            string[] oldTuples = before.Native.Read(catalog).Select(row => row.ToJsonString()).ToArray();
            string[] newTuples = after.Native.Read(catalog).Select(row => row.ToJsonString()).ToArray();
            foreach (string tuple in oldTuples.Concat(newTuples).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
            {
                int oldCount = oldTuples.Count(value => value == tuple), newCount = newTuples.Count(value => value == tuple);
                if (oldCount != newCount)
                { output.WriteLine("ORDER_REWRITE_WITNESS_CATALOG " + JsonSerializer.Serialize(new { phase, Catalog = catalog, BeforeCount = oldCount, AfterCount = newCount, Tuple = tuple })); }
            }
        }
        // Statistics may contain raw sampled table values. Retain only their safe structural
        // locator/version fields here; complete before/after tuple hashes remain below.
        foreach (var (Side, Value) in new[] { (Side: "before", Value: before), (Side: "after", Value: after) })
        {
            foreach (var row in Value.Native.Read("pg_statistic").Where(row => row["starelid"]?.ToString() == Value.TableOid.ToString(System.Globalization.CultureInfo.InvariantCulture)))
            {
                output.WriteLine("ORDER_REWRITE_WITNESS_STATISTIC_METADATA " + JsonSerializer.Serialize(new
                {
                    phase,
                    Side,
                    RelationOid = row["starelid"]?.ToString(),
                    Attribute = row["staattnum"]?.ToString(),
                    Inherited = row["stainherit"]?.ToString(),
                    NullFraction = row["stanullfrac"]?.ToString(),
                    Width = row["stawidth"]?.ToString(),
                    Distinct = row["stadistinct"]?.ToString()
                }));
            }
        }

        foreach (string oid in before.Storage.Keys.Concat(after.Storage.Keys).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            StorageFact? old = before.Storage.GetValueOrDefault(oid), current = after.Storage.GetValueOrDefault(oid);
            if (old != current) { output.WriteLine($"{phase} storage oid={oid}; before={old}; after={current}"); }
        }
        foreach (var fact in before.Native.Snapshot.Catalog.Concat(after.Native.Snapshot.Catalog).Distinct()
            .Where(x => before.Native.Snapshot.Catalog.Contains(x) != after.Native.Snapshot.Catalog.Contains(x)))
        { output.WriteLine($"{phase} catalog={fact.Catalog}; key={fact.Key}; tupleSha256={fact.Sha256}; presentAfter={after.Native.Snapshot.Catalog.Contains(fact)}"); }
        foreach (var row in before.Native.Read("pg_class").Concat(after.Native.Read("pg_class")).Where(x => x["relkind"]?.ToString() is "r" or "i" or "t")
            .GroupBy(x => x["oid"]!.ToString(), StringComparer.Ordinal))
        {
            string[] values = [.. row.Select(x => x.ToJsonString()).Distinct(StringComparer.Ordinal)];
            if (values.Length != 1 || row.Count() != 2)
            { output.WriteLine($"{phase} pg_class oid={row.Key}; beforeAfterTupleDigests={string.Join(',', values.Select(Hash))}"); }
        }
    }

    private static async Task<string> RowsAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string expression, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SELECT encode(sha256(convert_to(coalesce(string_agg(v,'' ORDER BY v COLLATE \"C\"),''),'UTF8')),'hex') FROM " +
            "(SELECT encode(sha256(convert_to((" + expression + ")::text,'UTF8')),'hex') v FROM public.\"Order\" x) rows;", connection, transaction)
        { CommandTimeout = 120 };
        return (string)(await command.ExecuteScalarAsync(ct))!;
    }

    private static async Task RequireExpressionAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string expected, CancellationToken ct)
    {
        Assert.Equal(PostgreSqlGeneratedExpressionCanonicalizer.Canonicalize(expected),
            PostgreSqlGeneratedExpressionCanonicalizer.Canonicalize(await ReadExpressionAsync(connection, transaction, ct)));
    }

    private static async Task<string> ReadExpressionAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            SELECT pg_get_expr(d.adbin,d.adrelid) FROM pg_attribute a JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
            WHERE a.attrelid='public."Order"'::regclass AND a.attname='Subtotal' AND a.attgenerated='s' AND NOT a.attisdropped;
            """, connection, transaction) { CommandTimeout = 120 };
        return (string)(await command.ExecuteScalarAsync(ct))!;
    }

    private static string Hash(string value)
    {
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 120 };
        _ = await command.ExecuteNonQueryAsync(ct);
    }
}

[Collection(OrderSubtotalExpressionRepairScale184Group.Name)]
public sealed class OrderSubtotalExpressionRepairScale184Tests(OrderSubtotalExpressionRepairScale184Fixture fixture, ITestOutputHelper output)
    : OrderSubtotalExpressionRepairScaleWitnessBase(fixture, output);

[Collection(OrderSubtotalExpressionRepairScale187Group.Name)]
public sealed class OrderSubtotalExpressionRepairScale187Tests(OrderSubtotalExpressionRepairScale187Fixture fixture, ITestOutputHelper output)
    : OrderSubtotalExpressionRepairScaleWitnessBase(fixture, output);
