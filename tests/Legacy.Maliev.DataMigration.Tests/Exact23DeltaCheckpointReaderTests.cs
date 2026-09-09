namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Exact23DeltaCheckpointReaderTests
{
    [Fact]
    public async Task Incomplete_schema_inventory_fails_before_any_database_connection()
    {
        var reader = new PostgreSqlExact23DeltaCheckpointReader(new(
            "Host=127.0.0.1;Port=1;Username=unused;Password=unused;Timeout=1"));
        DateTimeOffset now = new(2026, 9, 8, 8, 0, 0, TimeSpan.Zero);
        var schema = new FreshSchemaPlan("2.0", now, new string('1', 40), []);
        var plan = new DeltaSynchronizationPlan("1.1", Guid.NewGuid(), schema.SourceCommitSha,
            now.AddMinutes(-1), Hash('a'), Hash('b'), Hash('c'), "local-aspire",
            "legacy-postgres-main-local", "generation-1", Hash('d'), Hash('e'), Hash('f'), now,
            [.. DatabaseInventory.ActiveDatabases.Select(database => new DeltaDatabasePlan(database,
                [new("public.items", 0, 0, 0, 0,
                    DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256([]), [])]))],
            "plan", "signature");

        DeltaExecutionException error = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            reader.ReadAsync(plan, schema, CancellationToken.None));

        Assert.Equal("delta_reconciliation_checkpoint_invalid", error.Code);
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }
}
