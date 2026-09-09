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
        DeltaSynchronizationPlan plan = Plan(schemas, now);
        var coordinator = new Exact23DeltaReconciliationCoordinator(inspector, inspector,
            new Checkpoints(plan, schemas), new FixedTime(now), signer);

        Exact23DeltaReconciliationResult result = await coordinator.ReconcileAsync(plan, schemas, CancellationToken.None);

        Assert.Equal(DatabaseInventory.ActiveDatabases, result.Databases.Select(item => item.Database));
        Assert.Equal(plan.SourceCutoffUtc, result.SourceCutoffUtc);
        Assert.Equal(now, result.ReconciledAtUtc);
        Assert.Equal(DatabaseInventory.ActiveDatabases, result.Checkpoints.Select(item => item.Database));
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
        DeltaSynchronizationPlan plan = Plan(schemas, now);
        var coordinator = new Exact23DeltaReconciliationCoordinator(source, target,
            new Checkpoints(plan, schemas), new FixedTime(now), signer);

        MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            coordinator.ReconcileAsync(plan, schemas, CancellationToken.None));

        Assert.Equal("shadow_reconciliation_failed", error.Code);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("foreign")]
    [InlineData("plan")]
    [InlineData("cutoff")]
    [InlineData("target")]
    [InlineData("operations")]
    [InlineData("reconciliation")]
    public async Task Invalid_or_incomplete_checkpoint_inventory_cannot_emit_signed_success(string field)
    {
        DateTimeOffset now = new(2026, 9, 8, 8, 0, 0, TimeSpan.Zero);
        FreshSchemaPlan schemas = Schemas(now);
        DeltaSynchronizationPlan plan = Plan(schemas, now);
        var inspector = new Inspector(Evidence);
        using var signer = Signer();
        var coordinator = new Exact23DeltaReconciliationCoordinator(inspector, inspector,
            new Checkpoints(plan, schemas, field), new FixedTime(now), signer);

        DeltaExecutionException error = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            coordinator.ReconcileAsync(plan, schemas, CancellationToken.None));

        Assert.Equal("delta_reconciliation_checkpoint_invalid", error.Code);
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

    private sealed class Checkpoints(
        DeltaSynchronizationPlan plan,
        FreshSchemaPlan schemas,
        string? fault = null) : IExact23DeltaCheckpointReader
    {
        public Task<IReadOnlyList<DeltaDatabaseCheckpointEvidence>> ReadAsync(
            DeltaSynchronizationPlan requestedPlan,
            FreshSchemaPlan schemaPlan,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string planSha256 = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
            var values = DatabaseInventory.ActiveDatabases.Select(database =>
            {
                DeltaDatabasePlan databasePlan = plan.Databases.Single(item => item.Database == database);
                DatabaseSchemaPlan schema = schemas.Databases.Single(item => item.Database == database);
                string operations = DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(databasePlan);
                string reconciliation = DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(Evidence(schema));
                return new DeltaDatabaseCheckpointEvidence(database, plan.PlanId, planSha256, plan.SourceCutoffUtc,
                    plan.TargetObservationSha256, operations, reconciliation, plan.SourceCutoffUtc.AddSeconds(1));
            }).ToArray();
            IReadOnlyList<DeltaDatabaseCheckpointEvidence> result = fault switch
            {
                "missing" => values.Skip(1).ToArray(),
                "foreign" => Replace(values, values[0] with { Database = "Unapproved" }),
                "plan" => Replace(values, values[0] with { PlanId = Guid.NewGuid() }),
                "cutoff" => Replace(values, values[0] with { SourceCutoffUtc = plan.SourceCutoffUtc.AddSeconds(1) }),
                "target" => Replace(values, values[0] with { TargetObservationSha256 = Hash('9') }),
                "operations" => Replace(values, values[0] with { OperationsSha256 = Hash('9') }),
                "reconciliation" => Replace(values, values[0] with { ReconciliationSha256 = Hash('9') }),
                _ => values,
            };
            return Task.FromResult(result);
        }

        private static IReadOnlyList<DeltaDatabaseCheckpointEvidence> Replace(
            DeltaDatabaseCheckpointEvidence[] values,
            DeltaDatabaseCheckpointEvidence replacement)
        {
            return [replacement, .. values.Skip(1)];
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
