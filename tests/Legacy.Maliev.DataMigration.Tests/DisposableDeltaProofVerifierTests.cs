using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DisposableDeltaProofVerifierTests : IDisposable
{
    private readonly ECDsa _planKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public async Task Fresh_signed_disposable_reconciliation_admits_distinct_local_target()
    {
        Fixture fixture = await CreateAsync();

        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.ProofPlan, fixture.Trust, fixture.Now));
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.LocalPlan, fixture.Trust, fixture.Now));
        Assert.True(Exact23DeltaReconciliationCoordinator.Verify(fixture.ProofResult, fixture.Trust));
        Assert.Equal(fixture.ProofPlan.SchemaPlanSha256, SchemaPlanCanonicalizer.ComputeSha256(fixture.Schema));

        DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
            fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now);
    }

    [Fact]
    public async Task Rejects_same_target_or_tampered_reconciliation()
    {
        Fixture fixture = await CreateAsync();

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.ProofPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan,
                fixture.ProofResult with { PlanSha256 = Hash('9') }, fixture.LocalPlan,
                fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Fact]
    public async Task Rejects_expired_proof_and_changed_source_observation()
    {
        Fixture fixture = await CreateAsync();

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now.AddHours(13))).Code);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan with { SourceObservationSha256 = Hash('9') },
                fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    private async Task<Fixture> CreateAsync()
    {
        DateTimeOffset now = new(2026, 9, 25, 8, 0, 0, TimeSpan.Zero);
        FreshSchemaPlan schema = new("2.0", now.AddMinutes(-10), new string('a', 40),
            [.. DatabaseInventory.ActiveDatabases.Select(name => new DatabaseSchemaPlan(name, "1.0",
                Hash('a'), Hash('b'), [new TableCopyPlan("dbo", "items", "public", "items", ["id"], ["id"])
                {
                    ColumnTypes = new Dictionary<string, string> { ["id"] = "integer" },
                    PrimaryKey = new("pk_items", ["id"]),
                }]))]);
        using var planSigner = new P256MigrationEvidenceSigner("proof-plan", _planKey.ExportECPrivateKeyPem());
        using var evidenceSigner = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore(
            [new(planSigner.KeyId, planSigner.ExportSubjectPublicKeyInfo()),
                new(evidenceSigner.KeyId, evidenceSigner.ExportSubjectPublicKeyInfo())]);
        DeltaSynchronizationPlan proofPlan = MakePlan("disposable-proof", Hash('1'), now.AddMinutes(-3));
        DeltaSynchronizationPlan localPlan = MakePlan("persistent-main", Hash('2'), now.AddMinutes(-1));
        var inspector = new Inspector();
        var coordinator = new Exact23DeltaReconciliationCoordinator(inspector, inspector,
            new Checkpoints(proofPlan, schema), new FixedTime(now.AddMinutes(-2)), evidenceSigner);
        Exact23DeltaReconciliationResult result = await coordinator.ReconcileAsync(proofPlan, schema,
            CancellationToken.None);
        return new(proofPlan, result, localPlan, schema, trust, now);

        DeltaSynchronizationPlan MakePlan(string id, string systemHash, DateTimeOffset created)
        {
            var request = new DeltaPlanSigningRequest(schema.SourceCommitSha, now.AddMinutes(-5), Hash('3'),
                SchemaPlanCanonicalizer.ComputeSha256(schema), Hash('4'), "local-aspire",
                "legacy-postgres-main-local", "generation-1", Hash('5'), Hash('6'), Hash('7'),
                [.. DatabaseInventory.ActiveDatabases.Select(name => new DeltaDatabasePlan(name,
                    [new DeltaTablePlan("public.items", 0, 0, 0, 1,
                        DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256([]), [])]))])
            {
                TargetAuthority = new(DeltaTargetAuthorityKind.LocalAspire,
                    $"aspire://legacy-postgres-main-local/{id}", systemHash),
                SourceMode = DeltaSourceMode.LiveReadOnly,
                SourceObservationSha256 = Hash('8'),
                SourceCaptureCompletedAtUtc = now.AddMinutes(-4),
            };
            return DeltaSynchronizationPlanProducer.Produce(request, planSigner, created);
        }
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    public void Dispose()
    {
        _planKey.Dispose();
        _evidenceKey.Dispose();
    }

    private sealed record Fixture(DeltaSynchronizationPlan ProofPlan,
        Exact23DeltaReconciliationResult ProofResult, DeltaSynchronizationPlan LocalPlan,
        FreshSchemaPlan Schema, ReceiptAttestationTrustStore Trust, DateTimeOffset Now);

    private sealed class Inspector : IDeltaReconciliationInspector
    {
        public Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema,
            CancellationToken cancellationToken)
        {
            var table = new TableReconciliationEvidence("public.items", 1, Hash('c'), Hash('d'),
                new Dictionary<string, long>(), new Dictionary<string, long>());
            return Task.FromResult(new DatabaseReconciliationEvidence(schema.Database,
                schema.SourceSchemaSha256, schema.TargetSchemaSha256, [table]));
        }
    }

    private sealed class Checkpoints(DeltaSynchronizationPlan plan, FreshSchemaPlan schema)
        : IExact23DeltaCheckpointReader
    {
        public Task<IReadOnlyList<DeltaDatabaseCheckpointEvidence>> ReadAsync(
            DeltaSynchronizationPlan requestedPlan, FreshSchemaPlan schemaPlan,
            CancellationToken cancellationToken)
        {
            IReadOnlyList<DeltaDatabaseCheckpointEvidence> values =
                [.. DatabaseInventory.ActiveDatabases.Select(name =>
                {
                    DeltaDatabasePlan database = plan.Databases.Single(item => item.Database == name);
                    DatabaseSchemaPlan databaseSchema = schema.Databases.Single(item => item.Database == name);
                    DatabaseReconciliationEvidence evidence = new Inspector().InspectAsync(databaseSchema,
                        cancellationToken).GetAwaiter().GetResult();
                    return new DeltaDatabaseCheckpointEvidence(name, plan.PlanId,
                        DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan), plan.SourceCutoffUtc,
                        plan.TargetObservationSha256,
                        DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(database),
                        DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(evidence),
                        plan.SourceCutoffUtc.AddMinutes(1));
                })];
            return Task.FromResult(values);
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
