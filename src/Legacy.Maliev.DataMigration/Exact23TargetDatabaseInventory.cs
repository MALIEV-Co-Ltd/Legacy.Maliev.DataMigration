namespace Legacy.Maliev.DataMigration;

/// <summary>Validates that a PostgreSQL target contains exactly the active migration databases plus approved runtime infrastructure.</summary>
public static class Exact23TargetDatabaseInventory
{
    private static readonly HashSet<string> ApprovedExtras = new(StringComparer.Ordinal)
    {
        "Auth",
        "legacy_migration_control",
    };

    /// <summary>Rejects missing, duplicate, retired, or unknown target databases before delta planning or execution.</summary>
    public static void Validate(IReadOnlyCollection<string> databases)
    {
        ArgumentNullException.ThrowIfNull(databases);
        string[] observed = [.. databases];
        bool duplicates = observed.Distinct(StringComparer.Ordinal).Count() != observed.Length;
        bool missing = DatabaseInventory.ActiveDatabases.Any(database => !observed.Contains(database, StringComparer.Ordinal));
        bool unexpected = observed.Any(database =>
            !DatabaseInventory.ActiveDatabases.Contains(database, StringComparer.Ordinal) &&
            !ApprovedExtras.Contains(database) &&
            !database.StartsWith("legacy_shadow_", StringComparison.Ordinal));
        if (duplicates || missing || unexpected)
        {
            throw new DeltaExecutionException(
                "delta_target_database_inventory_invalid",
                "The PostgreSQL target database inventory does not match the exact-23 migration contract.");
        }
    }
}
