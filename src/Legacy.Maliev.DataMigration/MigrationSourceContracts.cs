namespace Legacy.Maliev.DataMigration;

/// <summary>Provider-neutral, read-only source snapshot used by migration coordinators.</summary>
public interface IReadOnlyMigrationSource
{
    Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken);
    Task<SourceSchemaEvidence> InspectSchemaAsync(string database, CancellationToken cancellationToken);
    IAsyncEnumerable<MigrationRow> ReadTableAsync(string database, TableCopyPlan table, CancellationToken cancellationToken);
    IAsyncEnumerable<MigrationRow> ReadTableImmediatelyAsync(
        string database,
        TableCopyPlan table,
        CancellationToken cancellationToken)
    {
        return ReadTableAsync(database, table, cancellationToken);
    }
    Task<IReadOnlyDictionary<string, long>> InspectForeignKeyOrphansAsync(
        string database, TableCopyPlan table, CancellationToken cancellationToken);
    Task<IReadOnlyDictionary<string, long>> InspectForeignKeyRelationshipsAsync(
        string database, TableCopyPlan table, CancellationToken cancellationToken);
    Task<IReadOnlyDictionary<string, long>> InspectSequenceNextValuesAsync(
        string database, DatabaseSchemaPlan plan, CancellationToken cancellationToken);
    Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken);
    Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken);
}

/// <summary>Provider-neutral migration source lifetime returned by host composition.</summary>
public interface IMigrationSourceSession : IReadOnlyMigrationSource, IAsyncDisposable;

/// <summary>Creates a migration-source session without exposing a provider type to coordinators.</summary>
public interface IMigrationSourceFactory
{
    IMigrationSourceSession Create(string protectedConnectionReference);
}

/// <summary>Compatibility contract retained while the SQL Server adapter moves to its dedicated assembly.</summary>
public interface IReadOnlySqlServerMigrationSource : IReadOnlyMigrationSource;

public interface IRestoredMigrationSourceObserver
{
    Task<RestoredSourceObservation> ObserveAsync(string connectionString, VerifiedRestoreReceipt receipt,
        FreshSchemaPlan plan, CancellationToken cancellationToken);
}
