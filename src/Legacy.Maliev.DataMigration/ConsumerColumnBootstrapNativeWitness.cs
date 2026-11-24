using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal enum ConsumerColumnBootstrapNativePhase { LockedBefore = 1, TransactionalAfter = 2, IndependentReadback = 3 }
internal sealed record ConsumerColumnBootstrapHeapWitness(string Relation, uint File, long Blocks);
internal sealed record ConsumerColumnBootstrapIndexWitness(string Oid, uint FileNode, long Blocks);

/// <summary>PII-free replay facts from an owned synthetic rehearsal; pg_authid values are never retained.</summary>
internal sealed record ConsumerColumnBootstrapNativeWitness(ConsumerColumnBootstrapNativePhase Phase,
    string Database, string ContractSha256, bool After, CurrentAppOwnedDatabaseSnapshot Snapshot,
    CurrentAppOwnedRelationFact OriginalRows, IReadOnlyList<ConsumerColumnBootstrapHeapWitness> Heaps,
    IReadOnlyList<ConsumerColumnBootstrapIndexWitness> Indexes, int ProviderVersion, string CompositeDefense, ulong WalUpper,
    IReadOnlyDictionary<string, string[]> RawChangedCatalogs)
{
    private static readonly string[] RawNames = ["pg_class", "pg_namespace", "pg_attribute", "pg_attrdef", "pg_constraint", "pg_depend", "pg_index"];

    internal static ConsumerColumnBootstrapNativeWitness Capture(ConsumerColumnBootstrapNativePhase phase, ConsumerColumnBootstrapPreservationObservation observation)
    {
        if (!Enum.IsDefined(phase) || observation.After != (phase != ConsumerColumnBootstrapNativePhase.LockedBefore))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        var raw = RawNames.ToDictionary(name => name, name => observation.Native.Read(name).Select(row => row.ToJsonString()).ToArray(), StringComparer.Ordinal);
        var indexes = observation.Native.Read("pg_class").Where(row => row["relkind"]?.ToString() == "i")
            .Select(row => row["oid"]?.ToString() ?? throw ConsumerColumnBootstrapOperationalContract.Invalid()).Order(StringComparer.Ordinal)
            .Select(oid => { var (FileNode, Blocks) = observation.Native.Storage(oid); return new ConsumerColumnBootstrapIndexWitness(oid, FileNode, Blocks); }).ToArray();
        return new(phase, observation.LogicalDatabase, observation.ContractSha256, observation.After,
            ConsumerColumnBootstrapOperationalContract.Copy(observation.Native.Snapshot), observation.OriginalRows,
            observation.HeapStorage.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new ConsumerColumnBootstrapHeapWitness(pair.Key, pair.Value.File, pair.Value.Blocks)).ToArray(),
            indexes, observation.ProviderVersion, observation.CompositeDefense, observation.WalUpper, raw);
    }

    internal ConsumerColumnBootstrapPreservationObservation Rehydrate()
    {
        if (!RawChangedCatalogs.Keys.Order(StringComparer.Ordinal).SequenceEqual(RawNames.Order(StringComparer.Ordinal)) ||
            Heaps.Select(heap => heap.Relation).Distinct(StringComparer.Ordinal).Count() != Heaps.Count ||
            Indexes.Select(index => index.Oid).Distinct(StringComparer.Ordinal).Count() != Indexes.Count)
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        var tuples = new Dictionary<string, string[]>(StringComparer.Ordinal);
        foreach (string catalog in ConsumerColumnBootstrapNativePreservation.CatalogNames)
        {
            // Unchanged catalogs are represented by their complete tuple multiset, already hashed
            // by the database capture. The native guard compares these wrappers exactly. Only the
            // seven catalogs needed to validate the permitted transition retain actual metadata.
            tuples.Add(catalog, RawChangedCatalogs.TryGetValue(catalog, out string[]? raw) ? raw.ToArray() :
                Snapshot.Catalog.Where(fact => fact.Catalog == catalog).Select(fact => JsonSerializer.Serialize(new
                { fact.Key, fact.Sha256, fact.ObjectClass, fact.ObjectId })).ToArray());
        }
        var native = new CurrentAppOwnedRetained31Observation(Snapshot, tuples,
            Indexes.ToDictionary(index => index.Oid, index => (index.FileNode, index.Blocks), StringComparer.Ordinal));
        return new(native, Database, ContractSha256, After, OriginalRows,
            Heaps.ToDictionary(heap => heap.Relation, heap => (heap.File, heap.Blocks), StringComparer.Ordinal), ProviderVersion, CompositeDefense, WalUpper);
    }
}
