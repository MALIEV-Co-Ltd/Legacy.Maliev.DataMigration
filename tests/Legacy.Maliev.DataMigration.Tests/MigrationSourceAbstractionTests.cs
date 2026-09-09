namespace Legacy.Maliev.DataMigration.Tests;

public sealed class MigrationSourceAbstractionTests
{
    [Fact]
    public async Task Factory_contract_returns_provider_neutral_disposable_session()
    {
        var session = new Session();
        IMigrationSourceFactory factory = new Factory(session);

        await using (IMigrationSourceSession opened = factory.Create("protected-source-reference"))
        {
            Assert.Same(session, opened);
        }
        Assert.True(session.DisposeCalled);
    }

    [Theory]
    [InlineData("AdmittedSequentialMigrationCoordinator.cs")]
    [InlineData("Exact23DeltaExecutionCoordinator.cs")]
    [InlineData("GuardedShadowMigrationRunner.cs")]
    public void Provider_neutral_coordinators_do_not_depend_on_SQL_Server_named_source_contract(string file)
    {
        string source = File.ReadAllText(Path.Combine(Repository(), "src", "Legacy.Maliev.DataMigration", file));

        Assert.DoesNotContain("IReadOnlySqlServerMigrationSource", source, StringComparison.Ordinal);
    }

    [Fact]
    public void Host_composition_uses_injected_factory_instead_of_constructing_SQL_source()
    {
        string source = File.ReadAllText(Path.Combine(Repository(), "src", "Legacy.Maliev.DataMigration", "AdmittedCoordinatorHost.cs"));

        Assert.Contains("IMigrationSourceFactory sourceFactory", source, StringComparison.Ordinal);
        Assert.DoesNotContain("new SqlServerMigrationSource(new", source, StringComparison.Ordinal);
    }

    private static string Repository()
    {
        for (DirectoryInfo? directory = new(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Legacy.Maliev.DataMigration.slnx")))
            {
                return directory.FullName;
            }
        }
        throw new InvalidOperationException("Repository root not found.");
    }

    private sealed class Factory(IMigrationSourceSession session) : IMigrationSourceFactory
    {
        public IMigrationSourceSession Create(string protectedConnectionReference)
        {
            return session;
        }
    }

    private sealed class Session : IMigrationSourceSession
    {
        internal bool DisposeCalled { get; private set; }
        public ValueTask DisposeAsync()
        {
            DisposeCalled = true;
            return ValueTask.CompletedTask;
        }
        public Task BeginDatabaseSnapshotAsync(string database, CancellationToken token)
        {
            return Task.CompletedTask;
        }

        public Task<SourceSchemaEvidence> InspectSchemaAsync(string database, CancellationToken token)
        {
            throw new NotSupportedException();
        }

        public async IAsyncEnumerable<MigrationRow> ReadTableAsync(string database, TableCopyPlan table,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken token)
        { await Task.CompletedTask; yield break; }
        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyOrphansAsync(string database, TableCopyPlan table, CancellationToken token)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyRelationshipsAsync(string database, TableCopyPlan table, CancellationToken token)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyDictionary<string, long>> InspectSequenceNextValuesAsync(string database, DatabaseSchemaPlan plan, CancellationToken token)
        {
            throw new NotSupportedException();
        }

        public Task CompleteDatabaseSnapshotAsync(string database, CancellationToken token)
        {
            return Task.CompletedTask;
        }

        public Task RollbackDatabaseSnapshotAsync(string database, CancellationToken token)
        {
            return Task.CompletedTask;
        }
    }
}
