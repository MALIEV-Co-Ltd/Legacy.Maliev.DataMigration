namespace Legacy.Maliev.DataMigration;

public interface IDatabaseSchemaPlanSource
{
    Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken);

    Task<DatabaseSchemaPlan> GenerateDatabasePlanAsync(string database, CancellationToken cancellationToken);

    Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken);

    Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken);
}

public static class FreshSchemaPlanProducer
{
    public static async Task<FreshSchemaPlan> ProduceAsync(
        IDatabaseSchemaPlanSource source,
        string sourceCommitSha,
        DateTimeOffset capturedAtUtc,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        var databases = new List<DatabaseSchemaPlan>(DatabaseInventory.ActiveDatabases.Count);
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            await source.BeginDatabaseSnapshotAsync(database, cancellationToken).ConfigureAwait(false);
            try
            {
                databases.Add(await source.GenerateDatabasePlanAsync(database, cancellationToken).ConfigureAwait(false));
                await source.CompleteDatabaseSnapshotAsync(database, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await source.RollbackDatabaseSnapshotAsync(database, CancellationToken.None).ConfigureAwait(false);
                throw;
            }
        }

        return new FreshSchemaPlan("2.0", capturedAtUtc.ToUniversalTime(), sourceCommitSha, databases);
    }
}
