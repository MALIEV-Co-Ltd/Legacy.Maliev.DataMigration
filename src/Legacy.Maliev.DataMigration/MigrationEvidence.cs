using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

public static class MigrationEvidenceAttestation
{
    public static byte[] CreatePayload(DatabaseMigrationCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        return [.. "legacy-maliev-database-checkpoint-v1\0"u8,
            .. SerializeCheckpoint(checkpoint with { AttestationSignature = null })];
    }

    internal static byte[] SerializeCheckpoint(DatabaseMigrationCheckpoint checkpoint)
    {
        // Unlike historical receipts, checkpoints have canonical object ordering, including dictionaries.
        JsonElement json = JsonSerializer.SerializeToElement(checkpoint);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            WriteCanonical(writer, json);
        }
        return stream.ToArray();
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            writer.WriteStartObject();
            foreach (JsonProperty property in element.EnumerateObject().OrderBy(item => item.Name, StringComparer.Ordinal))
            {
                writer.WritePropertyName(property.Name);
                WriteCanonical(writer, property.Value);
            }
            writer.WriteEndObject();
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            writer.WriteStartArray();
            foreach (JsonElement item in element.EnumerateArray())
            {
                WriteCanonical(writer, item);
            }
            writer.WriteEndArray();
        }
        else
        {
            element.WriteTo(writer);
        }
    }

    public static byte[] CreatePayload(MigrationExecutionReceipt receipt)
    {
        return Create("legacy-maliev-migration-success-v1", receipt with { AttestationSignature = null });
    }

    public static byte[] CreatePayload(MigrationFailureReceipt receipt)
    {
        return Create("legacy-maliev-migration-failure-v1", receipt with { AttestationSignature = null });
    }

    public static byte[] CreatePayload(PostExportShadowCleanupReceipt receipt)
    {
        return Create("legacy-maliev-post-export-shadow-cleanup-v1", receipt with { AttestationSignature = null });
    }

    private static byte[] Create<T>(string domain, T value)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(value);
        return [.. Encoding.UTF8.GetBytes(domain), 0, .. json];
    }
}

internal sealed class TableEvidenceCollector(TableCopyPlan table) : IDisposable
{
    private readonly IncrementalHash _ordered = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private readonly byte[] _multisetSum = new byte[SHA256.HashSizeInBytes];
    private readonly Dictionary<string, long> _nullCounts = table.OrderedColumns
        .ToDictionary(column => column, _ => 0L, StringComparer.Ordinal);
    private long _rowCount;

    public void Append(MigrationRow row)
    {
        ArgumentNullException.ThrowIfNull(row);
        string fingerprint = CanonicalRowFingerprint.Compute(table, [row]);
        byte[] fingerprintBytes = Convert.FromHexString(fingerprint);
        if (_rowCount > 0)
        {
            _ordered.AppendData("\n"u8);
        }

        _ordered.AppendData(Encoding.ASCII.GetBytes(fingerprint));
        AddModulo256(_multisetSum, fingerprintBytes);
        _rowCount++;
        foreach (string column in table.OrderedColumns)
        {
            if (row.Values.GetValueOrDefault(column) is null or DBNull)
            {
                _nullCounts[column]++;
            }
        }
    }

    public TableReconciliationEvidence Finish()
    {
        string content = Convert.ToHexString(_ordered.GetHashAndReset()).ToLowerInvariant();
        string aggregate = Convert.ToHexString(SHA256.HashData(_multisetSum)).ToLowerInvariant();
        return new(
            $"{table.TargetSchema}.{table.TargetTable}",
            _rowCount,
            content,
            aggregate,
            new System.Collections.ObjectModel.ReadOnlyDictionary<string, long>(_nullCounts),
            new System.Collections.ObjectModel.ReadOnlyDictionary<string, long>(
                table.ForeignKeys.ToDictionary(
                    foreignKey => foreignKey.Name,
                    _ => 0L,
                    StringComparer.Ordinal)));
    }

    public void Dispose()
    {
        _ordered.Dispose();
    }

    private static void AddModulo256(Span<byte> accumulator, ReadOnlySpan<byte> value)
    {
        int carry = 0;
        for (int index = accumulator.Length - 1; index >= 0; index--)
        {
            int sum = accumulator[index] + value[index] + carry;
            accumulator[index] = (byte)sum;
            carry = sum >> 8;
        }
    }
}
