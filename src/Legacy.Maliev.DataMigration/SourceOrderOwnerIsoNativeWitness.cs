using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record SourceOrderOwnerIsoPhysical(string Oid, uint FileNode, long Blocks);
internal sealed record SourceOrderOwnerIsoNativeWitness(CurrentOwnerIsoNativeObservation Native, IReadOnlyList<SourceOrderOwnerIsoPhysical> Physical)
{
    internal string Sha256 => SourceOrderOwnerIsoProtocol.Hash(new
    { Kind = "source-order-owner-iso-full-native-v1", Native = SourceOrderOwnerIsoProtocol.NativeSha(Native), Physical });
    internal static async Task<SourceOrderOwnerIsoNativeWitness> CaptureAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        SourceOrderOwnerIsoContract contract, bool selected, CancellationToken ct)
    {
        var native = await SourceOrderOwnerIsoNativePreservation.CaptureAsync(connection, transaction, contract, selected, ct);
        SourceOrderOwnerIsoNativePreservation.RequireObserved(native, contract);
        var physical = new List<SourceOrderOwnerIsoPhysical>();
        await using var command = new NpgsqlCommand("""
            WITH roots AS (SELECT c.oid,c.reltoastrelid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE c.relkind='r' AND n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema')
            SELECT c.oid::text,pg_relation_filenode(c.oid),pg_relation_size(c.oid)/current_setting('block_size')::bigint
            FROM pg_class c WHERE c.relkind='i' OR c.oid IN (SELECT oid FROM roots UNION ALL SELECT reltoastrelid FROM roots)
            ORDER BY c.oid::text COLLATE "C";
            """, connection, transaction);
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) { physical.Add(new(reader.GetString(0), reader.GetFieldValue<uint>(1), reader.GetInt64(2))); }
        return new(native, physical);
    }
    internal static void RequirePreserved(SourceOrderOwnerIsoNativeWitness before, SourceOrderOwnerIsoNativeWitness after, SourceOrderOwnerIsoContract contract)
    {
        SourceOrderOwnerIsoNativePreservation.RequirePreserved(before.Native, after.Native, contract);
        var selected = before.Native.CopyStorage().Keys.ToHashSet(StringComparer.Ordinal);
        if (!before.Physical.Select(x => x.Oid).SequenceEqual(after.Physical.Select(x => x.Oid), StringComparer.Ordinal) ||
            before.Physical.Any(left => !selected.Contains(left.Oid) && left != after.Physical.Single(x => x.Oid == left.Oid)))
        { throw new MigrationExecutionException("source_order_owner_iso_uncharacterized_other_storage", "Unrelated native storage changed; no unobserved growth exception is admitted."); }
    }
}
