using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration;

public static class DeltaReconciliationEvidenceCanonicalizer
{
    private static ReadOnlySpan<byte> Domain => "legacy-maliev-exact23-delta-reconciliation-v1\0"u8;

    public static string ComputeSha256(DatabaseReconciliationEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        using var stream = new MemoryStream();
        stream.Write(Domain);
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            Write(writer, evidence.Database);
            Write(writer, evidence.SourceSchemaSha256.ToLowerInvariant());
            Write(writer, evidence.TargetSchemaSha256.ToLowerInvariant());
            foreach (TableReconciliationEvidence table in evidence.Tables.OrderBy(item => item.Table, StringComparer.Ordinal))
            {
                Write(writer, table.Table);
                writer.Write(table.RowCount);
                Write(writer, table.ContentSha256.ToLowerInvariant());
                Write(writer, table.AggregateSha256.ToLowerInvariant());
                WriteCounts(writer, table.NullCounts);
                WriteCounts(writer, table.ForeignKeyOrphanCounts);
                WriteCounts(writer, table.ForeignKeyRelationshipCounts);
            }
            WriteCounts(writer, evidence.SequenceNextValues);
        }

        return Convert.ToHexString(SHA256.HashData(stream.ToArray())).ToLowerInvariant();
    }

    private static void WriteCounts(BinaryWriter writer, IReadOnlyDictionary<string, long> values)
    {
        writer.Write(values.Count);
        foreach ((string key, long value) in values.OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            Write(writer, key);
            writer.Write(value);
        }
    }

    private static void Write(BinaryWriter writer, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value.Normalize(NormalizationForm.FormC));
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }
}
