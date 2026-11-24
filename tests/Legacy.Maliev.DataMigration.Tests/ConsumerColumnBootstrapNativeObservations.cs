using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Xunit.Abstractions;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed record ConsumerColumnBootstrapNativeObservation(CurrentAppOwnedRetained31Observation Native,
    CurrentAppOwnedRelationFact OriginalColumnProjection, IReadOnlyDictionary<string, (uint File, long Blocks)> HeapStorage);

// Disposable measurements only. Deliberately no allowed catalog-transition set or operational preservation admission.
internal static class ConsumerColumnBootstrapNativeObservations
{
    private static readonly string[] PreservedCatalogs = ["pg_attribute", "pg_constraint"];
    private static readonly string[] AddedObjectCatalogs = ["pg_attrdef", "pg_constraint"];
    internal static async Task<ConsumerColumnBootstrapNativeObservation> CaptureAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ConsumerColumnBootstrapOperand operand, bool after, CancellationToken ct)
    {
        var native = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, ct);
        string remove = after ? " - '" + operand.Column + "'" : string.Empty;
        string relation = PostgreSqlShadowTarget.QuoteIdentifier(operand.Schema) + "." + PostgreSqlShadowTarget.QuoteIdentifier(operand.Table);
        await using var command = new NpgsqlCommand($$"""
            SELECT count(*), encode(sha256(convert_to(coalesce(string_agg(h,'' ORDER BY h COLLATE "C"),''),'UTF8')),'hex')
            FROM (SELECT encode(sha256(convert_to((to_jsonb(x){{remove}})::text,'UTF8')),'hex') h FROM {{relation}} x) rows;
            """, connection, transaction) { CommandTimeout = 30 };
        CurrentAppOwnedRelationFact projection;
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            Assert.True(await reader.ReadAsync(ct));
            projection = new(operand.Schema, operand.Table, reader.GetInt64(0), reader.GetString(1));
        }
        var storage = new Dictionary<string, (uint, long)>(StringComparer.Ordinal);
        await using var heaps = new NpgsqlCommand("""
            SELECT c.oid::text, pg_relation_filenode(c.oid), pg_relation_size(c.oid)/current_setting('block_size')::bigint
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE c.relkind='r' AND ((n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema') OR c.oid IN
                (SELECT u.reltoastrelid FROM pg_class u JOIN pg_namespace un ON un.oid=u.relnamespace
                 WHERE u.relkind='r' AND un.nspname NOT LIKE 'pg_%' AND un.nspname<>'information_schema'));
            """, connection, transaction) { CommandTimeout = 30 };
        await using (var reader = await heaps.ExecuteReaderAsync(ct))
        { while (await reader.ReadAsync(ct)) { storage.Add(reader.GetString(0), (reader.GetFieldValue<uint>(1), reader.GetInt64(2))); } }
        return new(native, projection, storage);
    }

    internal static void RequireOriginalDataAndObjects(ConsumerColumnBootstrapNativeObservation before,
        ConsumerColumnBootstrapNativeObservation after, ConsumerColumnBootstrapOperand operand)
    {
        Assert.Equal(before.OriginalColumnProjection, after.OriginalColumnProjection);
        Assert.Equal(before.Native.Snapshot.Sequences, after.Native.Snapshot.Sequences);
        Assert.Equal(before.Native.Snapshot.Relations.Count, after.Native.Snapshot.Relations.Count);
        Assert.Equal(before.Native.Snapshot.Relations.Where(x => x.Schema != operand.Schema || x.Name != operand.Table),
            after.Native.Snapshot.Relations.Where(x => x.Schema != operand.Schema || x.Name != operand.Table));
        Assert.Equal(before.HeapStorage.OrderBy(x => x.Key, StringComparer.Ordinal), after.HeapStorage.OrderBy(x => x.Key, StringComparer.Ordinal));
        foreach (string catalog in PreservedCatalogs)
        {
            var current = after.Native.Read(catalog).Select(Canonical).ToHashSet(StringComparer.Ordinal);
            Assert.All(before.Native.Read(catalog), row => Assert.Contains(Canonical(row), current));
        }
        Assert.Equal(before.Native.Read("pg_index").Select(Canonical).Order(StringComparer.Ordinal),
            after.Native.Read("pg_index").Select(Canonical).Order(StringComparer.Ordinal));
        string[] userNamespaces = [.. before.Native.Read("pg_namespace").Where(x => !Value(x, "nspname").StartsWith("pg_", StringComparison.Ordinal) &&
            Value(x, "nspname") != "information_schema").Select(x => Value(x, "oid"))];
        string[] toastRelations = [.. before.Native.Read("pg_class").Where(x => Value(x, "relkind") == "r" &&
            userNamespaces.Contains(Value(x, "relnamespace"), StringComparer.Ordinal)).Select(x => Value(x, "reltoastrelid"))];
        string[] toastIndexes = [.. before.Native.Read("pg_index").Where(x => toastRelations.Contains(Value(x, "indrelid"), StringComparer.Ordinal))
            .Select(x => Value(x, "indexrelid"))];
        foreach (JsonObject index in before.Native.Read("pg_class").Where(x => Value(x, "relkind") == "i" &&
            (userNamespaces.Contains(Value(x, "relnamespace"), StringComparer.Ordinal) || toastIndexes.Contains(Value(x, "oid"), StringComparer.Ordinal))))
        {
            string id = Value(index, "oid");
            Assert.Equal(Canonical(index), Canonical(after.Native.Read("pg_class").Single(x => Value(x, "oid") == id)));
            Assert.Equal(before.Native.Storage(id), after.Native.Storage(id));
        }
    }

    internal static async Task RequireNewColumnValuesAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        ConsumerColumnBootstrapOperand operand, CancellationToken ct)
    {
        string column = PostgreSqlShadowTarget.QuoteIdentifier(operand.Column);
        string relation = PostgreSqlShadowTarget.QuoteIdentifier(operand.Schema) + "." + PostgreSqlShadowTarget.QuoteIdentifier(operand.Table);
        string unexpected = operand.Nullable ? column + " IS NOT NULL" : column + " IS DISTINCT FROM false";
        await using var command = new NpgsqlCommand($"SELECT NOT EXISTS(SELECT 1 FROM {relation} WHERE {unexpected});",
            connection, transaction)
        { CommandTimeout = 30 };
        Assert.Equal(true, await command.ExecuteScalarAsync(ct));
    }

    internal static void Report(ITestOutputHelper output, ConsumerColumnBootstrapNativeObservation before,
        ConsumerColumnBootstrapNativeObservation after, ConsumerColumnBootstrapOperand operand, string phase)
    {
        output.WriteLine($"BOOTSTRAP phase={phase}; database={operand.Database}; column={operand.Column}; originalRows={before.OriginalColumnProjection.Rows}");
        foreach (string catalog in before.Native.Snapshot.Catalog.Concat(after.Native.Snapshot.Catalog)
            .Select(x => x.Catalog).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            var oldRows = before.Native.Read(catalog).Select(Canonical).GroupBy(x => x, StringComparer.Ordinal).ToDictionary(x => x.Key, x => x.Count(), StringComparer.Ordinal);
            var newRows = after.Native.Read(catalog).Select(Canonical).GroupBy(x => x, StringComparer.Ordinal).ToDictionary(x => x.Key, x => x.Count(), StringComparer.Ordinal);
            foreach (string row in oldRows.Keys.Concat(newRows.Keys).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
            {
                int delta = newRows.GetValueOrDefault(row) - oldRows.GetValueOrDefault(row);
                if (delta != 0) { output.WriteLine($"CATALOG catalog={catalog}; tupleSha256={Digest(row)}; multiplicityDelta={delta}"); }
            }
        }
        var oldClasses = before.Native.Read("pg_class").ToDictionary(x => Value(x, "oid"), StringComparer.Ordinal);
        foreach (JsonObject index in before.Native.Read("pg_index"))
        {
            string id = Value(index, "indexrelid");
            var oldStorage = before.Native.Storage(id); var newStorage = after.Native.Storage(id);
            if (oldStorage != newStorage)
            { output.WriteLine($"INDEX-STORAGE index={oldClasses[id]["relname"]}; oid={id}; before={oldStorage}; after={newStorage}"); }
        }
        string table = Value(after.Native.Read("pg_class").Single(x => Value(x, "relname") == operand.Table && Value(x, "relkind") == "r"), "oid");
        var oldAttributes = before.Native.Read("pg_attribute").Where(x => Value(x, "attrelid") == table).Select(Canonical).ToHashSet(StringComparer.Ordinal);
        foreach (JsonObject row in after.Native.Read("pg_attribute").Where(x => Value(x, "attrelid") == table && !oldAttributes.Contains(Canonical(x))))
        { output.WriteLine("OPERAND-ATTRIBUTE " + Canonical(row)); }
        var addedObjects = new HashSet<string>(StringComparer.Ordinal);
        foreach (string catalog in AddedObjectCatalogs)
        {
            string tableKey = catalog == "pg_attrdef" ? "adrelid" : "conrelid";
            var old = before.Native.Read(catalog).Select(Canonical).ToHashSet(StringComparer.Ordinal);
            foreach (JsonObject row in after.Native.Read(catalog).Where(x => Value(x, tableKey) == table && !old.Contains(Canonical(x))))
            {
                _ = addedObjects.Add(Value(row, "oid"));
                output.WriteLine("OPERAND-" + catalog + " " + Canonical(row));
            }
        }
        var oldDependencies = before.Native.Read("pg_depend").Select(Canonical).ToHashSet(StringComparer.Ordinal);
        foreach (JsonObject row in after.Native.Read("pg_depend").Where(x => !oldDependencies.Contains(Canonical(x)) &&
            (Value(x, "objid") == table || addedObjects.Contains(Value(x, "objid")))))
        { output.WriteLine("OPERAND-DEPENDENCY " + Canonical(row)); }
    }

    private static string Value(JsonObject row, string field)
    {
        return row[field]!.ToString();
    }

    private static string Canonical(JsonObject row)
    {
        return new JsonObject([.. row.OrderBy(x => x.Key, StringComparer.Ordinal)
        .Select(x => new KeyValuePair<string, JsonNode?>(x.Key, x.Value?.DeepClone()))]).ToJsonString();
    }

    private static string Digest(string value)
    {
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }
}
