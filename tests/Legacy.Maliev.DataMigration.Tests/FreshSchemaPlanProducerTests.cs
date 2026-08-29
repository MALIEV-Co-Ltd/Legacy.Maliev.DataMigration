namespace Legacy.Maliev.DataMigration.Tests;

public sealed class FreshSchemaPlanProducerTests
{
    [Fact]
    public async Task ProduceAsync_InspectsExactlyTwentyFiveReadOnlySnapshotsDeterministically()
    {
        var source = new FakePlanSource();
        DateTimeOffset captured = DateTimeOffset.Parse("2026-08-30T08:00:00Z", System.Globalization.CultureInfo.InvariantCulture);

        FreshSchemaPlan plan = await FreshSchemaPlanProducer.ProduceAsync(
            source, new string('a', 40), captured, CancellationToken.None);

        Assert.Equal(DatabaseInventory.ActiveDatabases, plan.Databases.Select(database => database.Database).ToArray());
        Assert.Equal(DatabaseInventory.ActiveDatabases, source.Begun);
        Assert.Equal(DatabaseInventory.ActiveDatabases, source.Completed);
        Assert.Empty(source.RolledBack);
        Assert.Equal(captured, plan.CapturedAtUtc);
    }

    [Fact]
    public async Task ProduceAsync_FailureRollsBackCurrentSnapshotAndStops()
    {
        string failed = DatabaseInventory.ActiveDatabases[2];
        var source = new FakePlanSource(failed);

        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => FreshSchemaPlanProducer.ProduceAsync(
            source, new string('a', 40), DateTimeOffset.UtcNow, CancellationToken.None));

        Assert.Equal([failed], source.RolledBack);
        Assert.DoesNotContain(failed, source.Completed);
    }

    private sealed class FakePlanSource(string? failDatabase = null) : IDatabaseSchemaPlanSource
    {
        public List<string> Begun { get; } = [];
        public List<string> Completed { get; } = [];
        public List<string> RolledBack { get; } = [];

        public Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            Begun.Add(database);
            return Task.CompletedTask;
        }

        public Task<DatabaseSchemaPlan> GenerateDatabasePlanAsync(string database, CancellationToken cancellationToken)
        {
            if (database == failDatabase)
            {
                throw new InvalidOperationException("planned failure");
            }
            var table = new TableCopyPlan("dbo", "T", "public", "T", ["Id"], ["Id"])
            {
                SourceColumnTypes = new Dictionary<string, string> { ["Id"] = "int" },
                ColumnTypes = new Dictionary<string, string> { ["Id"] = "integer" },
                SourceColumns = [new("Id", "int", new string('b', 64), null)],
                PrimaryKey = new("PK_T", ["Id"]),
            };
            var draft = new DatabaseSchemaPlan(database, "1.0", new string('c', 64), new string('d', 64), [table]);
            return Task.FromResult(draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) });
        }

        public Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            Completed.Add(database);
            return Task.CompletedTask;
        }

        public Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            RolledBack.Add(database);
            return Task.CompletedTask;
        }
    }
}
