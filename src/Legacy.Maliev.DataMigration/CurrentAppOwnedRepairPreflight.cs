using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal enum CurrentAppOwnedCreationState { MissingExactSet, AlreadyCurrent }
internal sealed record CurrentAppOwnedCreationObservation(
    string Database, CurrentAppOwnedCreationState State, string ActualSchemaSha256,
    string BeforeSchemaPlanSha256, string AfterSchemaPlanSha256);

/// <summary>Read-only classification only: no DDL admission, mutation, or preservation attestation.</summary>
internal static class CurrentAppOwnedRepairPreflight
{
    internal static async Task<CurrentAppOwnedCreationObservation> InspectCreationStateAsync(
        FreshSchemaPlan before, FreshSchemaPlan after, string database,
        NpgsqlConnection connection, NpgsqlTransaction transaction, DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        CurrentAppOwnedRepairManifest.RequireSchemaPair(before, after, now);
        string[] fixedNames = CurrentAppOwnedRepairManifest.NewTables(database);
        if (!ReferenceEquals(transaction.Connection, connection) ||
            transaction.IsolationLevel is not (System.Data.IsolationLevel.RepeatableRead or System.Data.IsolationLevel.Serializable))
        { throw Invalid(); }

        await using (var identity = new NpgsqlCommand(
            "SELECT current_database(),current_setting('transaction_read_only');", connection, transaction))
        await using (NpgsqlDataReader reader = await identity.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
                reader.GetString(0) != database || reader.GetString(1) != "on")
            { throw Invalid(); }
        }

        string[] present;
        await using (var inventory = new NpgsqlCommand("""
            SELECT c.relname
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname=ANY($1)
            ORDER BY c.relname COLLATE "C";
            """, connection, transaction))
        {
            _ = inventory.Parameters.AddWithValue(fixedNames);
            var names = new List<string>();
            await using NpgsqlDataReader reader = await inventory.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { names.Add(reader.GetString(0)); }
            present = [.. names];
        }

        CurrentAppOwnedCreationState state = ClassifyInventory(database, present);
        DatabaseSchemaPlan expected = (state == CurrentAppOwnedCreationState.MissingExactSet ? before : after)
            .Databases.Single(x => x.Database == database);
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
        string actual = await inspector.InspectSchemaAsync(expected, cancellationToken).ConfigureAwait(false);
        return !string.Equals(actual, expected.TargetSchemaSha256, StringComparison.Ordinal)
            ? throw Invalid()
            : new(database, state, actual, SchemaPlanCanonicalizer.ComputeSha256(before),
            SchemaPlanCanonicalizer.ComputeSha256(after));
    }

    internal static CurrentAppOwnedCreationState ClassifyInventory(string database, IReadOnlyList<string> present)
    {
        string[] expected = CurrentAppOwnedRepairManifest.NewTables(database);
        return present.Count == 0 ? CurrentAppOwnedCreationState.MissingExactSet
            : !present.Order(StringComparer.Ordinal).SequenceEqual(expected.Order(StringComparer.Ordinal), StringComparer.Ordinal)
                ? throw Invalid()
                : CurrentAppOwnedCreationState.AlreadyCurrent;
    }

    private static MigrationExecutionException Invalid()
    {
        return new("current_app_owned_repair_preimage_invalid", "The exact additive repair preimage is not established.");
    }
}