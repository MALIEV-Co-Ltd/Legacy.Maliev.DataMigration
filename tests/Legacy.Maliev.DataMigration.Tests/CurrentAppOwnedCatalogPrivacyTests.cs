using System.Data;
using System.Text.Json;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAppOwnedCatalogPrivacyTests
{
    [Fact]
    public async Task Native_preservation_evidence_does_not_publish_statistics_values()
    {
        const string privateValue = "synthetic-private-statistics-value-9d84a7";
        await using var postgres = new PostgreSqlBuilder(
            "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382")
            .WithDatabase("catalog_privacy_" + Guid.NewGuid().ToString("N"))
            .WithUsername("postgres").WithPassword(Guid.NewGuid().ToString("N"))
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 384 * 1024 * 1024;
                parameters.HostConfig.MemorySwap = 384 * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 500_000_000;
            }).Build();
        await postgres.StartAsync();
        await using var connection = new NpgsqlConnection(postgres.GetConnectionString());
        await connection.OpenAsync();
        await using (var fixture = new NpgsqlCommand(
            "CREATE TABLE public.privacy_fixture (value text NOT NULL);", connection))
        { _ = await fixture.ExecuteNonQueryAsync(); }
        await using (var insert = new NpgsqlCommand(
            "INSERT INTO public.privacy_fixture SELECT $1::text FROM generate_series(1,100);", connection))
        {
            _ = insert.Parameters.AddWithValue(privateValue);
            _ = await insert.ExecuteNonQueryAsync();
        }
        await using (var analyze = new NpgsqlCommand("ANALYZE public.privacy_fixture;", connection))
        { _ = await analyze.ExecuteNonQueryAsync(); }
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction))
        { _ = await readOnly.ExecuteNonQueryAsync(); }
        await using (var statistics = new NpgsqlCommand("""
            SELECT EXISTS(SELECT 1 FROM pg_statistic s
              WHERE starelid='public.privacy_fixture'::regclass
              AND strpos(to_jsonb(s)::text,$1)>0);
            """, connection, transaction))
        {
            _ = statistics.Parameters.AddWithValue(privateValue);
            Assert.True(await statistics.ExecuteScalarAsync() is true);
        }
        CurrentAppOwnedDatabaseSnapshot snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(
            connection, transaction, CancellationToken.None);
        Assert.DoesNotContain(privateValue, JsonSerializer.Serialize(snapshot));
        Assert.Equal(snapshot.Catalog.Count, snapshot.Catalog.Select(fact => fact.Catalog + "/" + fact.Key).Distinct().Count());
        var repeatedDependency = snapshot.Catalog.Where(fact => fact.Catalog == "pg_depend")
            .GroupBy(fact => fact.Sha256).First(group => group.Count() > 1);
        CurrentAppOwnedCatalogFact removed = repeatedDependency.Last();
        var missingOccurrence = snapshot with
        { Catalog = [.. snapshot.Catalog.Where(fact => fact != removed)] };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairPreservation.RequirePreserved(
            snapshot, missingOccurrence, new HashSet<string>(), []));
        var extraOccurrence = snapshot with
        { Catalog = [.. snapshot.Catalog, removed with { Key = removed.Sha256 + "/" + (repeatedDependency.Count() + 1) }] };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairPreservation.RequirePreserved(
            snapshot, extraOccurrence, new HashSet<string>(), []));
        CurrentAppOwnedDatabaseSnapshot repeated = await CurrentAppOwnedRepairPreservation.CaptureAsync(
            connection, transaction, CancellationToken.None);
        Assert.Equal(snapshot.Sha256, repeated.Sha256);
        CurrentAppOwnedRepairPreservation.RequirePreserved(snapshot, repeated, new HashSet<string>(), []);
    }
}
