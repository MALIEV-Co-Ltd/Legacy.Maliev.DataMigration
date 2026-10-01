using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record ConsumerColumnOverlayState(TableReconciliationEvidence All, TableReconciliationEvidence Existing, long InsertedCount);

/// <summary>Streaming keyed state; only signed insertion hashes are retained, never a dictionary of owner rows.</summary>
internal static class ConsumerColumnOverlayStateInspector
{
    internal static async Task<ConsumerColumnOverlayState?> InspectAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        DatabaseSchemaPlan schema, IReadOnlySet<string>? insertKeys, bool afterApply, CancellationToken cancellationToken)
    {
        var overlay = ApprovedConsumerColumnOverlayManifest.For(schema);
        if (overlay is null) { return null; }
        string key = overlay.Root.PrimaryKey!.Columns[0];
        var projection = overlay.Root with
        {
            OrderedColumns = [key, overlay.Column],
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { [key] = overlay.Root.ColumnTypes[key], [overlay.Column] = overlay.Type },
            NullableColumns = overlay.Nullable ? [overlay.Column] : [],
            ForeignKeys = [],
        };
        var keyPlan = projection with { OrderedColumns = [key] };
        using var all = new TableEvidenceCollector(projection);
        using var existing = new TableEvidenceCollector(projection);
        long inserted = 0;
        string order = PostgreSqlShadowTarget.QuoteIdentifier(key) + (overlay.Root.ColumnTypes[key] == "integer" ? "" : " COLLATE \"C\"");
        await using var command = new NpgsqlCommand($"SELECT {PostgreSqlShadowTarget.QuoteIdentifier(key)}, {PostgreSqlShadowTarget.QuoteIdentifier(overlay.Column)} FROM {PostgreSqlDeltaCanonicalTarget.Qualified(overlay.Root.TargetSchema, overlay.Root.TargetTable)} ORDER BY {order};", connection, transaction);
        await using var reader = await command.ExecuteReaderAsync(System.Data.CommandBehavior.SequentialAccess, cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            object id = reader.GetValue(0);
            object value = reader.GetValue(1);
            var row = new MigrationRow(new Dictionary<string, object?>(StringComparer.Ordinal) { [key] = id, [overlay.Column] = value });
            string keyHash = CanonicalDeltaPlanner.ComputeKeySha256(keyPlan, new(new Dictionary<string, object?> { [key] = id }));
            all.Append(row);
            if (insertKeys?.Contains(keyHash) == true)
            {
                if (!afterApply || (overlay.Nullable ? value is not DBNull : value is not false))
                { throw ApprovedConsumerColumnOverlayManifest.Invalid("target_extension_overlay_state_invalid"); }
                inserted++;
            }
            else { existing.Append(row); }
        }
        return afterApply && inserted != (insertKeys?.Count ?? 0)
            ? throw ApprovedConsumerColumnOverlayManifest.Invalid("target_extension_overlay_state_invalid")
            : new(all.Finish(), existing.Finish(), inserted);
    }

    internal static void Compare(DatabaseSchemaPlan schema, ConsumerColumnOverlayState? before, ConsumerColumnOverlayState? after)
    {
        if (ApprovedConsumerColumnOverlayManifest.For(schema) is null)
        {
            if (before is not null || after is not null) { throw ApprovedConsumerColumnOverlayManifest.Invalid("target_extension_overlay_state_invalid"); }
            return;
        }
        if (before is null || after is null) { throw ApprovedConsumerColumnOverlayManifest.Invalid("target_extension_overlay_state_invalid"); }
        ReconciliationDiagnostics.CompareTable(schema.Database, before.All, after.Existing);
    }

    internal static string ComputeSha256(DatabaseSchemaPlan schema, ConsumerColumnOverlayState state, string? receiptDigest)
    {
        using var stream = new MemoryStream();
        stream.Write("consumer-column-overlay-state-v1\0"u8);
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(schema.Database);
            writer.Write(schema.TargetExtensionProfile!);
            writer.Write(schema.SourceSchemaSha256);
            writer.Write(schema.TargetSchemaSha256);
            writer.Write(receiptDigest is not null);
            if (receiptDigest is not null) { writer.Write(receiptDigest); }
            writer.Write(DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(new(schema.Database,
                schema.SourceSchemaSha256, schema.TargetSchemaSha256, [state.All])));
        }
        return Convert.ToHexString(SHA256.HashData(stream.ToArray())).ToLowerInvariant();
    }
}
