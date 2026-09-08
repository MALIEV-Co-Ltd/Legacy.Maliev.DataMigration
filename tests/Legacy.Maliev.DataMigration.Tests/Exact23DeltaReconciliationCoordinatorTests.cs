namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Exact23DeltaReconciliationCoordinatorTests : IDisposable
{
    private readonly System.Security.Cryptography.ECDsa _key = System.Security.Cryptography.ECDsa.Create(
        System.Security.Cryptography.ECCurve.NamedCurves.nistP256);

    [Fact]
    public async Task Exact_matching_evidence_produces_complete_same_cutoff_result()
    {
        DateTimeOffset now = new(2026, 9, 8, 8, 0, 0, TimeSpan.Zero);
        FreshSchemaPlan schemas = Schemas(now);
        var inspector = new Inspector(Evidence);
        using var signer = Signer();
        var coordinator = new Exact23DeltaReconciliationCoordinator(inspector, inspector, new FixedTime(now), signer);
        DeltaSynchronizationPlan plan = Plan(schemas, now);

        Exact23DeltaReconciliationResult result = await coordinator.ReconcileAsync(plan, schemas, CancellationToken.None);

        Assert.Equal(DatabaseInventory.ActiveDatabases, result.Databases.Select(item => item.Database));
        Assert.Equal(plan.SourceCutoffUtc, result.SourceCutoffUtc);
        Assert.Equal(now, result.ReconciledAtUtc);
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        Assert.True(Exact23DeltaReconciliationCoordinator.Verify(result, trust));
    }

    [Theory]
    [InlineData("row")]
    [InlineData("content")]
    [InlineData("orphan")]
    [InlineData("sequence")]
    [InlineData("schema")]
    public async Task Any_parity_drift_fails_without_partial_success(string field)
    {
        DateTimeOffset now = new(2026, 9, 8, 8, 0, 0, TimeSpan.Zero);
        FreshSchemaPlan schemas = Schemas(now);
        var source = new Inspector(Evidence);
        var target = new Inspector(schema => Change(Evidence(schema), field));
        using var signer = Signer();
        var coordinator = new Exact23DeltaReconciliationCoordinator(source, target, new FixedTime(now), signer);

        MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            coordinator.ReconcileAsync(Plan(schemas, now), schemas, CancellationToken.None));

        Assert.Equal("shadow_reconciliation_failed", error.Code);
    }

    private static DatabaseReconciliationEvidence Change(DatabaseReconciliationEvidence value, string field)
    {
        TableReconciliationEvidence table = value.Tables[0];
        return field switch
        {
            "row" => value with { Tables = [table with { RowCount = 2 }] },
            "content" => value with { Tables = [table with { ContentSha256 = Hash('9') }] },
            "orphan" => value with { Tables = [table with { ForeignKeyOrphanCounts = new Dictionary<string, long> { ["fk"] = 1 } }] },
            "sequence" => value with { SequenceNextValues = new Dictionary<string, long> { ["public.items.id"] = 3 } },
            "schema" => value with { TargetSchemaSha256 = Hash('8') },
            _ => value,
        };
    }

    private static DatabaseReconciliationEvidence Evidence(DatabaseSchemaPlan schema)
    {
        var table = new TableReconciliationEvidence("public.items", 1, Hash('c'), Hash('d'),
            new Dictionary<string, long> { ["value"] = 0 }, new Dictionary<string, long>());
        return new(schema.Database, schema.SourceSchemaSha256, schema.TargetSchemaSha256, [table])
        {
            SequenceNextValues = new Dictionary<string, long> { ["public.items.id"] = 2 },
        };
    }

    private static FreshSchemaPlan Schemas(DateTimeOffset now)
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
            Identities = [new("id", 1, 1, 1, true)],
        };
    }

    private static DeltaSynchronizationPlan Plan(FreshSchemaPlan schemas, DateTimeOffset now)
    {
        string operations = DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256([]);
        return new("1.0", Guid.NewGuid(), schemas.SourceCommitSha, now.AddMinutes(-1), Hash('a'),
            SchemaPlanCanonicalizer.ComputeSha256(schemas), Hash('c'), "maliev-legacy", "legacy-postgres-main",
            "generation-1", Hash('d'), Hash('e'), Hash('f'), now,
            [.. DatabaseInventory.ActiveDatabases.Select(name => new DeltaDatabasePlan(name,
                [new("public.items", 0, 0, 0, 1, operations, [])]))], "plan", "signature");
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    private P256MigrationEvidenceSigner Signer()
    {
        return new("reconciliation", _key.ExportECPrivateKeyPem());
    }

    public void Dispose()
    {
        _key.Dispose();
    }

    private sealed class Inspector(Func<DatabaseSchemaPlan, DatabaseReconciliationEvidence> inspect) : IDeltaReconciliationInspector
    {
        public Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(inspect(schema));
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
