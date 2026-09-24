using System.Runtime.CompilerServices;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SqlServerDeltaExecutionRowSourceTests
{
    [Fact]
    public async Task Execution_dispatches_to_provider_safe_read_path()
    {
        var provider = new RecordingSource();
        var adapter = new SqlServerSnapshotDeltaExecutionRowSource(provider);
        var table = new TableCopyPlan("dbo", "Source", "public", "Target", ["ID"], ["ID"]);

        List<MigrationRow> rows = await adapter.ReadOrderedAsync("CustomerIdentity", table, CancellationToken.None)
            .ToListAsync();

        Assert.True(provider.ExecutionReadCalled);
        _ = Assert.Single(rows);
    }

    private sealed class RecordingSource : IReadOnlyMigrationSource
    {
        public bool ExecutionReadCalled { get; private set; }

        public async IAsyncEnumerable<MigrationRow> ReadTableForDeltaExecutionAsync(
            string database, TableCopyPlan table, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            ExecutionReadCalled = true;
            await Task.Yield();
            yield return new MigrationRow(new Dictionary<string, object?> { ["ID"] = 1 });
        }

        public IAsyncEnumerable<MigrationRow> ReadTableAsync(
            string database, TableCopyPlan table, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("The deferred source path was selected unexpectedly.");
        }

        public Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task<SourceSchemaEvidence> InspectSchemaAsync(string database, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyOrphansAsync(
            string database, TableCopyPlan table, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyRelationshipsAsync(
            string database, TableCopyPlan table, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyDictionary<string, long>> InspectSequenceNextValuesAsync(
            string database, DatabaseSchemaPlan plan, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
