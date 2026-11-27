using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class OrderSubtotalRuntime
{
    internal async Task<IReadOnlyDictionary<string, string>> NativeFleetAsync(CancellationToken ct)
    {
        var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string database in Inputs.Intent.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))
        {
            await using var connection = Connect(database); await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ReadOnlyAsync(connection, tx, ct).ConfigureAwait(false); await RequirePolicyAsync(connection, tx, Inputs.Intent.Maintenance, Inputs.Intent.Target, ct).ConfigureAwait(false);
            hashes.Add(database, await DualTargetCapturedDeltaNativeGuard.CapturePreimageAsync(connection, tx, ct).ConfigureAwait(false));
            await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        return hashes;
    }
    // The actual writer checks zero other clients before/after this fixed read-only cohort; each reader closes before the next.
    private async Task RequireOtherNativeBeforeCommitAsync(NpgsqlConnection writer, NpgsqlTransaction writerTx, CancellationToken ct)
    {
        await RequirePolicyAsync(writer, writerTx, Inputs.Intent.Maintenance, Inputs.Intent.Target, ct).ConfigureAwait(false);
        foreach (var expected in Inputs.Intent.BeforeNativeDatabaseSha256.Where(x => x.Key != "Order").OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            await using var connection = Connect(expected.Key); await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ReadOnlyAsync(connection, tx, ct).ConfigureAwait(false);
            const string sql = """
                SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex')=$1 AND current_user=$2
                  AND pg_postmaster_start_time()=$3 AND pg_conf_load_time()=$4 AND NOT pg_is_in_recovery()
                  AND encode(sha256(convert_to(pg_read_file(current_setting('hba_file')),'UTF8')),'hex')=$5
                  AND (SELECT encode(sha256(convert_to(jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text,'UTF8')),'hex') FROM pg_hba_file_rules h)=$6
                FROM pg_control_system();
                """;
            await using (var guard = new NpgsqlCommand(sql, connection, tx))
            {
                var maintenance = Inputs.Intent.Maintenance;
                _ = guard.Parameters.AddWithValue(Inputs.Intent.Target.SystemIdentifierSha256); _ = guard.Parameters.AddWithValue(maintenance.Role);
                _ = guard.Parameters.AddWithValue(maintenance.Postmaster); _ = guard.Parameters.AddWithValue(maintenance.ConfigLoaded);
                _ = guard.Parameters.AddWithValue(maintenance.HbaSha256); _ = guard.Parameters.AddWithValue(maintenance.HbaRulesSha256);
                if (await guard.ExecuteScalarAsync(ct).ConfigureAwait(false) is not true) { throw Invalid(); }
            }
            if (await DualTargetCapturedDeltaNativeGuard.CapturePreimageAsync(connection, tx, ct).ConfigureAwait(false) != expected.Value) { throw Invalid(); }
            await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        await RequirePolicyAsync(writer, writerTx, Inputs.Intent.Maintenance, Inputs.Intent.Target, ct).ConfigureAwait(false);
    }
    private void RequireNativeFleetAfter(IReadOnlyDictionary<string, string> actual, string afterOrder)
    {
        if (actual.Count != Inputs.Intent.BeforeNativeDatabaseSha256.Count || actual.Any(x =>
            !Inputs.Intent.BeforeNativeDatabaseSha256.TryGetValue(x.Key, out string? before) || x.Value != (x.Key == "Order" ? afterOrder : before))) { throw Invalid(); }
    }
    private static async Task<string> SequenceStorageAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken ct)
    {
        string value = await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, tx, """
            SELECT coalesce(jsonb_agg(jsonb_build_array(oid::text,pg_relation_filenode(oid)::text,pg_relation_size(oid)) ORDER BY oid),'[]')::text
            FROM pg_class WHERE relkind='S';
            """, ct).ConfigureAwait(false);
        return OrderSubtotalRepairProtocol.Hash(System.Text.Encoding.UTF8.GetBytes(value));
    }
}
