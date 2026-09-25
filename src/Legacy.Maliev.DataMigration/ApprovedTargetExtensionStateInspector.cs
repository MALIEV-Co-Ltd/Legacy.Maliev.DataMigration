using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record ApprovedTargetExtensionState(
    IReadOnlyList<TableReconciliationEvidence> Tables,
    IReadOnlyDictionary<string, long> SequenceNextValues);

internal static class ApprovedTargetExtensionStateInspector
{
    internal static async Task<ApprovedTargetExtensionState> InspectAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        DatabaseSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<TableCopyPlan> extensions = ApprovedTargetExtensionManifest.TablesFor(schema);
        await using var inspection = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
        var tables = new List<TableReconciliationEvidence>(extensions.Count);
        foreach (TableCopyPlan table in extensions)
        {
            tables.Add(await inspection.InspectTableAsync(table, cancellationToken).ConfigureAwait(false));
        }

        DatabaseSchemaPlan extensionPlan = schema with { Tables = extensions };
        IReadOnlyDictionary<string, long> sequences = await inspection
            .InspectSequenceNextValuesAsync(extensionPlan, cancellationToken).ConfigureAwait(false);
        return new(tables, sequences);
    }

    internal static void Compare(
        DatabaseSchemaPlan schema,
        ApprovedTargetExtensionState expected,
        ApprovedTargetExtensionState observed)
    {
        IReadOnlyList<TableCopyPlan> extensions = ApprovedTargetExtensionManifest.TablesFor(schema);
        if (expected.Tables.Count != extensions.Count || observed.Tables.Count != extensions.Count)
        {
            throw new MigrationExecutionException("target_extension_state_invalid",
                "The approved target extension inventory changed during the guarded transaction.");
        }

        for (int index = 0; index < extensions.Count; index++)
        {
            string tableName = $"{extensions[index].TargetSchema}.{extensions[index].TargetTable}";
            if (!string.Equals(expected.Tables[index].Table, tableName, StringComparison.Ordinal) ||
                !string.Equals(observed.Tables[index].Table, tableName, StringComparison.Ordinal))
            {
                throw new MigrationExecutionException("target_extension_state_invalid",
                    "The approved target extension inventory changed during the guarded transaction.");
            }

            ReconciliationDiagnostics.CompareTable(schema.Database, expected.Tables[index], observed.Tables[index]);
        }

        ReconciliationDiagnostics.CompareSequences(schema with { Tables = extensions },
            expected.SequenceNextValues, observed.SequenceNextValues);
    }
}
