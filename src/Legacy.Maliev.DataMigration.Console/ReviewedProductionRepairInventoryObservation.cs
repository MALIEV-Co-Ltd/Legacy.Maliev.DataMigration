using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

// Native read-only observation only. Existing caller must first validate its actual signed
// topology/custody/run and installed maintenance policy; this grants no permit or authority token.
internal static class ReviewedProductionRepairInventoryObservation
{
    internal static async Task RequireAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string targetKind,
        string pinnedSystemIdentifierSha256, IEnumerable<string> baselineKeys, CancellationToken ct)
    {
        if (connection.Database != "postgres" || transaction.Connection != connection ||
            !CurrentAppOwnedRepairPermit.HashShape(pinnedSystemIdentifierSha256)) { throw Invalid(); }
        var flags = new List<ReviewedRepairDatabaseFlag>();
        const string sql = """
            SELECT d.datname,d.datistemplate,d.datallowconn,
              encode(sha256(convert_to(c.system_identifier::text,'UTF8')),'hex'),
              current_setting('transaction_read_only')='on'
            FROM pg_database d CROSS JOIN pg_control_system() c
            ORDER BY d.datname COLLATE "C";
            """;
        await using (var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 30 })
        await using (var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                RequireSystemBinding(reader.GetString(3), pinnedSystemIdentifierSha256, reader.GetBoolean(4));
                flags.Add(new(reader.GetString(0), reader.GetBoolean(1), reader.GetBoolean(2)));
            }
        }
        ReviewedProductionRepairInventory.RequireComplete(targetKind, flags, baselineKeys);
    }

    internal static void RequireSystemBinding(string observed, string pinned, bool readOnly)
    {
        if (!readOnly || !CurrentAppOwnedRepairPermit.HashShape(observed) ||
            !CurrentAppOwnedRepairPermit.HashShape(pinned) || observed != pinned) { throw Invalid(); }
    }

    private static MigrationExecutionException Invalid()
    {
        return new("reviewed_inventory_observation_unbound",
            "Fresh read-only complete catalog from the pinned actual PostgreSQL system required.");
    }
}
