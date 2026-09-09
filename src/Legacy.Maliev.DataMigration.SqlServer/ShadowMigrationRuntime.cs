namespace Legacy.Maliev.DataMigration;

public sealed record ShadowMigrationRuntimeOptions(
    SqlServerMigrationSourceOptions Source,
    PostgreSqlShadowTargetOptions ShadowTarget,
    PostgreSqlMigrationRunJournalOptions Journal);

public sealed record ShadowMigrationRuntime(
    SqlServerMigrationSource Source,
    PostgreSqlShadowTarget ShadowTarget,
    PostgreSqlMigrationRunJournal Journal) : IAsyncDisposable
{
    public static ShadowMigrationRuntime Create(ShadowMigrationRuntimeOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return new(
            new SqlServerMigrationSource(options.Source),
            new PostgreSqlShadowTarget(options.ShadowTarget),
            new PostgreSqlMigrationRunJournal(options.Journal));
    }

    public ValueTask DisposeAsync()
    {
        return Source.DisposeAsync();
    }
}
