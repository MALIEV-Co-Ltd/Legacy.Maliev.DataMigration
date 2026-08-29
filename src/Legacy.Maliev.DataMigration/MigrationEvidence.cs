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

internal sealed class TableEvidenceCollector(TableCopyPlan table)
{
    private readonly List<string> _rowFingerprints = [];
    private readonly Dictionary<string, long> _nullCounts = table.OrderedColumns
        .ToDictionary(column => column, _ => 0L, StringComparer.Ordinal);

    public async IAsyncEnumerable<MigrationRow> ObserveAsync(
        IAsyncEnumerable<MigrationRow> rows,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (MigrationRow row in rows.WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            string fingerprint = CanonicalRowFingerprint.Compute(table, [row]);
            _rowFingerprints.Add(fingerprint);
            foreach (string column in table.OrderedColumns)
            {
                if (row.Values.GetValueOrDefault(column) is null or DBNull)
                {
                    _nullCounts[column]++;
                }
            }

            yield return row;
        }
    }

    public TableReconciliationEvidence Finish()
    {
        string content = Hash(string.Join('\n', _rowFingerprints));
        string aggregate = Hash(string.Join('\n', _rowFingerprints.Order(StringComparer.Ordinal)));
        return new(
            $"{table.TargetSchema}.{table.TargetTable}",
            _rowFingerprints.Count,
            content,
            aggregate,
            new System.Collections.ObjectModel.ReadOnlyDictionary<string, long>(_nullCounts),
            new System.Collections.ObjectModel.ReadOnlyDictionary<string, long>(
                table.ForeignKeys.ToDictionary(
                    foreignKey => foreignKey.Name,
                    _ => 0L,
                    StringComparer.Ordinal)));
    }

    private static string Hash(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }
}
