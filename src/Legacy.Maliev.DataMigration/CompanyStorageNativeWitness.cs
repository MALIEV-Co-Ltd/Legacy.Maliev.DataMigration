using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record CompanyStorageHeap(uint FileNode, long Blocks);
internal sealed record CompanyStorageNativeWitness(CustomerCompanyStorageNativePreservation.Observation Observation,
    string OwnerName, IReadOnlyDictionary<string, CompanyStorageHeap> Heaps)
{
    internal string Sha256 => CompanyStorageRepairProtocol.Hash(new
    {
        Native = CompanyStorageRepairProtocol.NativeSha(Observation),
        OwnerName,
        Heaps = Heaps.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new { x.Key, x.Value.FileNode, x.Value.Blocks }),
    });
    internal static async Task<CompanyStorageNativeWitness> CaptureAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        ApprovedCustomerCompanyStorageRepair contract, bool after, CancellationToken ct)
    {
        var native = await CustomerCompanyStorageNativePreservation.CaptureAsync(connection, transaction, contract, after, ct);
        string owner;
        await using (var command = new NpgsqlCommand("""
            SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid='public."Company"'::regclass;
            """, connection, transaction)) { owner = (string)(await command.ExecuteScalarAsync(ct))!; }
        var heaps = new Dictionary<string, CompanyStorageHeap>(StringComparer.Ordinal);
        await using (var command = new NpgsqlCommand("""
            WITH roots AS (SELECT c.oid,c.reltoastrelid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE c.relkind='r' AND n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema')
            SELECT c.oid::text,pg_relation_filenode(c.oid),pg_relation_size(c.oid)/current_setting('block_size')::bigint
            FROM pg_class c WHERE c.oid IN (SELECT oid FROM roots UNION ALL SELECT reltoastrelid FROM roots);
            """, connection, transaction))
        await using (var reader = await command.ExecuteReaderAsync(ct))
        { while (await reader.ReadAsync(ct)) { heaps.Add(reader.GetString(0), new(reader.GetFieldValue<uint>(1), reader.GetInt64(2))); } }
        return new(native, owner, heaps);
    }
    internal static void RequirePreserved(CompanyStorageNativeWitness before, CompanyStorageNativeWitness after, ApprovedCustomerCompanyStorageRepair contract)
    {
        CustomerCompanyStorageNativePreservation.RequirePreserved(before.Observation, after.Observation, contract);
        if (before.OwnerName != after.OwnerName || !before.Heaps.OrderBy(x => x.Key, StringComparer.Ordinal).SequenceEqual(after.Heaps.OrderBy(x => x.Key, StringComparer.Ordinal)))
        { throw CompanyStorageRepairProtocol.Invalid(); }
    }
}
