using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentConsumerSchemaV3IsoReconciliationTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("country-invented-state")]
    [InlineData("material-missing-state")]
    public async Task Actual_coordinator_requires_state_by_inventory_not_physical_profile_marker(string fault)
    {
        FreshSchemaPlan before = ApprovedCurrentOwnerIsoOverlayTests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
        FreshSchemaPlan schema = before with
        {
            Databases = [.. before.Databases.Select(database =>
            {
                DatabaseSchemaPlan selected = database with { TargetExtensionProfile =
                    ApprovedConsumerOverlaySelection.ProfileForDatabase(database.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3Iso) };
                return selected with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(selected) };
            })],
        };
        DatabaseSchemaPlan country = schema.Databases.Single(database => database.Database == "Country");
        DatabaseSchemaPlan material = schema.Databases.Single(database => database.Database == "Material");
        Assert.NotNull(country.TargetExtensionProfile);
        Assert.False(ApprovedConsumerColumnOverlayManifest.HasState(country));
        Assert.True(ApprovedConsumerColumnOverlayManifest.HasState(material));
        DateTimeOffset now = ApprovedCurrentOwnerIsoOverlayTests.Now;
        var plan = new DeltaSynchronizationPlan("1.0", Guid.NewGuid(), schema.SourceCommitSha,
            now.AddMinutes(-1), Hash('a'), SchemaPlanCanonicalizer.ComputeSha256(schema), Hash('c'),
            "maliev-legacy", "legacy-postgres-main", "component-generation", Hash('d'), Hash('e'), Hash('f'), now,
            [.. schema.Databases.Select(database => new DeltaDatabasePlan(database.Database,
                [.. new QuotationDeltaExecutionMapping(database).TargetSchema.Tables.Select(table =>
                    new DeltaTablePlan($"{table.TargetSchema}.{table.TargetTable}", 0, 0, 0, 0,
                        DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256([]), []))]))], "component-plan", null);
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("iso-reconciliation-component", key.ExportECPrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        var source = new Inspector("none");
        var target = new Inspector(fault);
        var coordinator = new Exact23DeltaReconciliationCoordinator(source, target,
            new Checkpoints(plan, schema, now), new Clock(now), signer);
        if (fault != "none")
        {
            DeltaExecutionException error = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                coordinator.ReconcileAsync(plan, schema, default));
            Assert.Equal("delta_reconciliation_shape_invalid", error.Code);
            return;
        }
        Exact23DeltaReconciliationResult receipt = await coordinator.ReconcileAsync(plan, schema, default);
        Assert.Null(receipt.Databases.Single(database => database.Database == "Country").TargetExtensionStateSha256);
        Assert.NotNull(receipt.Databases.Single(database => database.Database == "Material").TargetExtensionStateSha256);
        Assert.Equal(country.TargetSchemaSha256, receipt.Databases.Single(database => database.Database == "Country").TargetSchemaSha256);
        Assert.Equal(material.TargetSchemaSha256, receipt.Databases.Single(database => database.Database == "Material").TargetSchemaSha256);
        Assert.True(Exact23DeltaReconciliationCoordinator.Verify(receipt, plan, schema, trust));
    }

    private static DatabaseReconciliationEvidence Evidence(DatabaseSchemaPlan schema, string fault)
    {
        DatabaseSchemaPlan mapped = new QuotationDeltaExecutionMapping(schema).TargetSchema;
        string? state = ApprovedConsumerColumnOverlayManifest.HasState(schema) ? Hash('e') : null;
        if (schema.Database == "Country" && fault == "country-invented-state") { state = Hash('e'); }
        if (schema.Database == "Material" && fault == "material-missing-state") { state = null; }
        return new(schema.Database, schema.SourceSchemaSha256, schema.TargetSchemaSha256,
            [.. mapped.Tables.Select(table => new TableReconciliationEvidence($"{table.TargetSchema}.{table.TargetTable}",
                0, Hash('c'), Hash('d'), table.OrderedColumns.ToDictionary(column => column, _ => 0L, StringComparer.Ordinal),
                table.ForeignKeys.ToDictionary(key => key.Name, _ => 0L, StringComparer.Ordinal))
            {
                ForeignKeyRelationshipCounts = table.ForeignKeys.ToDictionary(key => key.Name, _ => 0L, StringComparer.Ordinal),
            })])
        {
            SequenceNextValues = mapped.Tables.SelectMany(table => table.Identities.Select(identity =>
                $"{table.TargetSchema}.{table.TargetTable}.{identity.Column}")).ToDictionary(column => column, _ => 1L, StringComparer.Ordinal),
            TargetExtensionStateSha256 = state,
        };
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
    private sealed class Inspector(string fault) : IDeltaReconciliationInspector
    {
        public Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema, CancellationToken cancellationToken)
        {
            return Task.FromResult(Evidence(schema, fault));
        }
    }
    private sealed class Checkpoints(DeltaSynchronizationPlan plan, FreshSchemaPlan schema, DateTimeOffset now) : IExact23DeltaCheckpointReader
    {
        public Task<IReadOnlyList<DeltaDatabaseCheckpointEvidence>> ReadAsync(DeltaSynchronizationPlan requestedPlan,
            FreshSchemaPlan schemaPlan, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<DeltaDatabaseCheckpointEvidence>>(
            [.. schema.Databases.Select(database => new DeltaDatabaseCheckpointEvidence(database.Database, plan.PlanId,
                DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan), plan.SourceCutoffUtc, plan.TargetObservationSha256,
                DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(plan.Databases.Single(item => item.Database == database.Database)),
                DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(Evidence(database, "none")), now.AddSeconds(-1)))]);
        }
    }
}
