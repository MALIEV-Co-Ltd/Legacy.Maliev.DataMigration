using System.Globalization;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Exact23DeltaPlanCoordinatorTests : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public async Task Produces_signed_exact_inventory_plan_from_ordered_streams()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-09-08T06:00:00Z", CultureInfo.InvariantCulture);
        FreshSchemaPlan schema = Schema(now);
        var source = new Rows(name => name == DatabaseInventory.ActiveDatabases[0] ? [Row(1, "new"), Row(2, "insert")] : [Row(1, "same")]);
        var target = new Rows(name => name == DatabaseInventory.ActiveDatabases[0] ? [Row(1, "old"), Row(3, "delete")] : [Row(1, "same")]);
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var coordinator = new Exact23DeltaPlanCoordinator(source, target, signer, new FixedTime(now));

        DeltaSynchronizationPlan plan = await coordinator.ProduceAsync(Request(schema, signer, now), CancellationToken.None);

        Assert.Equal(DatabaseInventory.ActiveDatabases, plan.Databases.Select(item => item.Database));
        DeltaTablePlan first = Assert.Single(plan.Databases[0].Tables);
        Assert.Equal((1, 1, 1), (first.InsertCount, first.UpdateCount, first.DeleteCount));
        Assert.All(plan.Databases.Skip(1), database => Assert.Equal(1, Assert.Single(database.Tables).UnchangedCount));
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(plan, trust, now));
    }

    [Fact]
    public async Task Rejects_inventory_missing_one_database_before_reading_rows()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-09-08T06:00:00Z", CultureInfo.InvariantCulture);
        FreshSchemaPlan schema = Schema(now) with { Databases = Schema(now).Databases.Skip(1).ToArray() };
        var rows = new Rows(_ => []);
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var coordinator = new Exact23DeltaPlanCoordinator(rows, rows, signer, new FixedTime(now));

        DeltaPlanException error = await Assert.ThrowsAsync<DeltaPlanException>(() =>
            coordinator.ProduceAsync(Request(schema, signer, now), CancellationToken.None));

        Assert.Equal("delta_plan_inventory_invalid", error.Code);
        Assert.Equal(0, rows.Reads);
    }

    private static Exact23DeltaPlanRequest Request(FreshSchemaPlan schema, P256MigrationEvidenceSigner signer, DateTimeOffset now)
    {
        string distinct = string.Equals(signer.PublicKeyFingerprintSha256, Hash('e'), StringComparison.OrdinalIgnoreCase) ? Hash('1') : Hash('e');
        string authorization = string.Equals(signer.PublicKeyFingerprintSha256, Hash('f'), StringComparison.OrdinalIgnoreCase) ? Hash('2') : Hash('f');
        return new(schema, now.AddMinutes(-1), Hash('a'), Hash('d'), "maliev-legacy", "legacy-postgres-main",
            "generation-1", Hash('c'), distinct, authorization)
        {
            TargetAuthority = new(DeltaTargetAuthorityKind.ProductionCloudNativePg,
                "gke://maliev-website/us-central1-a/maliev-legacy/legacy-postgres-main/uid-1", Hash('8')),
        };
    }

    private static FreshSchemaPlan Schema(DateTimeOffset now)
    {
        return new("2.0", now, new string('1', 40), [.. DatabaseInventory.ActiveDatabases.Select(name =>
            new DatabaseSchemaPlan(name, "1.0", Hash('a'), Hash('b'), [Table()]))]);
    }

    private static TableCopyPlan Table()
    {
        return new("dbo", "items", "public", "items", ["id", "value"], ["id"])
        {
            ColumnTypes = new Dictionary<string, string> { ["id"] = "integer", ["value"] = "text" },
            PrimaryKey = new("pk_items", ["id"]),
        };
    }

    private static MigrationRow Row(int id, string value)
    {
        return new(new Dictionary<string, object?> { ["id"] = id, ["value"] = value });
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    public void Dispose()
    {
        _key.Dispose();
    }

    private sealed class Rows(Func<string, IReadOnlyList<MigrationRow>> rows) : IDeltaOrderedRowSource
    {
        internal int Reads { get; private set; }
        public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(string database, TableCopyPlan table,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            Reads++;
            foreach (MigrationRow row in rows(database))
            {
                cancellationToken.ThrowIfCancellationRequested();
                await Task.Yield();
                yield return row;
            }
        }
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
}
