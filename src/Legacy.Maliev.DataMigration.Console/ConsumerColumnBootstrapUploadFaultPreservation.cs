using System.Data;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record ConsumerColumnBootstrapUploadProbeRow(int Id, string Payload);
internal sealed record ConsumerColumnBootstrapUploadFaultWitness(CurrentAppOwnedDatabaseSnapshot Snapshot,
    IReadOnlyList<string> CapturedCatalogs, IReadOnlyList<ConsumerColumnBootstrapUploadProbeRow> ProbeRows,
    IReadOnlyList<ConsumerColumnBootstrapHeapWitness> Heaps, IReadOnlyList<ConsumerColumnBootstrapIndexWitness> Indexes);

/// <summary>Exact synthetic Upload probe delta only. Grants no execution authority.</summary>
internal static class ConsumerColumnBootstrapUploadFaultPreservation
{
    internal const string Schema = "legacy_migration_internal";
    internal const string Table = "BootstrapFleetProbe";
    private static readonly ConsumerColumnBootstrapUploadProbeRow[] BeforeRows = [new(1, "before-one"), new(2, "before-two")];
    private static readonly ConsumerColumnBootstrapUploadProbeRow[] AfterRows = [new(1, "owned final fleet fault"), new(2, "before-two")];
    private static readonly string[] BeforeJson = [/*lang=json,strict*/ "{\"ID\": 1, \"Payload\": \"before-one\"}", /*lang=json,strict*/ "{\"ID\": 2, \"Payload\": \"before-two\"}"];
    private static readonly string[] AfterJson = [/*lang=json,strict*/ "{\"ID\": 1, \"Payload\": \"owned final fleet fault\"}", /*lang=json,strict*/ "{\"ID\": 2, \"Payload\": \"before-two\"}"];
    internal const string CreateSql = """
        CREATE TABLE legacy_migration_internal."BootstrapFleetProbe" ("ID" integer PRIMARY KEY,"Payload" text NOT NULL);
        INSERT INTO legacy_migration_internal."BootstrapFleetProbe" VALUES (1,'before-one'),(2,'before-two');
        """;
    internal const string MutationSql = """
        UPDATE legacy_migration_internal."BootstrapFleetProbe" SET "Payload"='owned final fleet fault'
        WHERE "ID"=1 AND "Payload"='before-one';
        """;

    internal static CurrentAppOwnedRelationFact ExpectedProbe(bool after)
    {
        return new(Schema, Table, 2,
        ConsumerColumnBootstrapOperationalContract.Hash(Encoding.UTF8.GetBytes(string.Concat((after ? AfterJson : BeforeJson)
            .Select(row => ConsumerColumnBootstrapOperationalContract.Hash(Encoding.UTF8.GetBytes(row))).Order(StringComparer.Ordinal)))));
    }

    internal static void Require(ConsumerColumnBootstrapUploadFaultWitness before, ConsumerColumnBootstrapUploadFaultWitness after, int affectedRows)
    {
        if (affectedRows != 1 || before.Snapshot.Database != "Upload" || after.Snapshot.Database != "Upload" ||
            !before.CapturedCatalogs.SequenceEqual(ConsumerColumnBootstrapNativePreservation.CatalogNames, StringComparer.Ordinal) ||
            !after.CapturedCatalogs.SequenceEqual(before.CapturedCatalogs, StringComparer.Ordinal) ||
            !before.ProbeRows.SequenceEqual(BeforeRows) || !after.ProbeRows.SequenceEqual(AfterRows) ||
            !before.Snapshot.Catalog.SequenceEqual(after.Snapshot.Catalog) || !before.Snapshot.Sequences.SequenceEqual(after.Snapshot.Sequences) ||
            !before.Heaps.SequenceEqual(after.Heaps) || !before.Indexes.SequenceEqual(after.Indexes) ||
            before.Snapshot.Relations.Count(relation => relation.Schema == Schema && relation.Name == Table) != 1 ||
            after.Snapshot.Relations.Count(relation => relation.Schema == Schema && relation.Name == Table) != 1 ||
            before.Snapshot.Relations.Single(relation => relation.Schema == Schema && relation.Name == Table) != ExpectedProbe(false) ||
            after.Snapshot.Relations.Single(relation => relation.Schema == Schema && relation.Name == Table) != ExpectedProbe(true) ||
            !before.Snapshot.Relations.Where(relation => relation.Schema != Schema || relation.Name != Table)
                .SequenceEqual(after.Snapshot.Relations.Where(relation => relation.Schema != Schema || relation.Name != Table)) ||
            before.Snapshot.Catalog.Select(fact => fact.Catalog + "/" + fact.Key).Distinct(StringComparer.Ordinal).Count() != before.Snapshot.Catalog.Count ||
            before.Snapshot.Relations.Select(relation => relation.Schema + "/" + relation.Name).Distinct(StringComparer.Ordinal).Count() != before.Snapshot.Relations.Count)
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }

    internal static async Task<ConsumerColumnBootstrapUploadFaultWitness> CaptureAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    {
        if (connection.Database != "Upload" || transaction.Connection != connection || transaction.IsolationLevel is not (IsolationLevel.RepeatableRead or IsolationLevel.Serializable))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        var native = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
        var rows = new List<ConsumerColumnBootstrapUploadProbeRow>();
        await using (var command = new NpgsqlCommand("SELECT \"ID\",\"Payload\" FROM legacy_migration_internal.\"BootstrapFleetProbe\" ORDER BY \"ID\";", connection, transaction))
        await using (var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        { while (await reader.ReadAsync(ct).ConfigureAwait(false)) { rows.Add(new(reader.GetInt32(0), reader.GetString(1))); } }
        var heaps = new List<ConsumerColumnBootstrapHeapWitness>();
        await using (var command = new NpgsqlCommand("""
            SELECT c.oid::text,pg_relation_filenode(c.oid),pg_relation_size(c.oid)/current_setting('block_size')::bigint
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','t') AND
             ((n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema') OR c.oid IN
              (SELECT u.reltoastrelid FROM pg_class u JOIN pg_namespace un ON un.oid=u.relnamespace
               WHERE u.relkind='r' AND un.nspname NOT LIKE 'pg_%' AND un.nspname<>'information_schema')) ORDER BY c.oid::text COLLATE "C";
            """, connection, transaction))
        await using (var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        { while (await reader.ReadAsync(ct).ConfigureAwait(false)) { heaps.Add(new(reader.GetString(0), reader.GetFieldValue<uint>(1), reader.GetInt64(2))); } }
        var indexes = native.Read("pg_class").Where(row => row["relkind"]?.ToString() == "i").Select(row => row["oid"]!.ToString()).Order(StringComparer.Ordinal)
            .Select(oid => new ConsumerColumnBootstrapIndexWitness(oid, native.Storage(oid).FileNode, native.Storage(oid).Blocks)).ToArray();
        return new(native.Snapshot, ConsumerColumnBootstrapNativePreservation.CatalogNames, rows, heaps, indexes);
    }
}
