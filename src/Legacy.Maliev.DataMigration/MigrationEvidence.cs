using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

public static class MigrationEvidenceAttestation
{
    public static byte[] CreatePayload(MigrationExecutionReceipt receipt)
    {
        return Create("legacy-maliev-migration-success-v1", receipt with { AttestationSignature = null });
    }

    public static byte[] CreatePayload(MigrationFailureReceipt receipt)
    {
        return Create("legacy-maliev-migration-failure-v1", receipt with { AttestationSignature = null });
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
