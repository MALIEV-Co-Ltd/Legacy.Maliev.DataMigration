using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class LocalRolloverTerminalReviewTests
{
    [Fact]
    public void Verify_OnlyExactSignedAllAdoptedTerminalEvidencePasses()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("rollover-terminal",
            key.ExportECPrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore(
            [new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        DateTimeOffset now = new(2026, 9, 29, 0, 0, 0, TimeSpan.Zero);
        DeltaDatabasePlan[] databasePlans = [.. DatabaseInventory.ActiveDatabases.Select(
            database => new DeltaDatabasePlan(database, []))];
        var plan = new DeltaSynchronizationPlan("1.4", Guid.NewGuid(), new string('a', 40),
            now.AddHours(-1), Hash('a'), Hash('b'), Hash('c'), "LOCAL", "LOCAL",
            "docker:target", Hash('d'), Hash('e'), Hash('f'), now.AddMinutes(-30),
            databasePlans, "plan", null);
        string planSha256 = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
        DatabaseReconciliationEvidence[] rows = [.. DatabaseInventory.ActiveDatabases.Select(
            database => new DatabaseReconciliationEvidence(database, Hash('1'), Hash('2'), [])
            {
                TargetExtensionStateSha256 =
                    ApprovedTargetExtensionManifest.ProfileForDatabase(database) is null
                        ? null : Hash('3'),
            })];
        Exact23DeltaReconciliationResult terminal = Receipt(plan.PlanId, planSha256,
            plan.SourceCutoffUtc, rows, databasePlans, now.AddMinutes(-2), signer);
        Exact23DeltaReconciliationResult disposable = Receipt(Guid.NewGuid(), Hash('4'),
            plan.SourceCutoffUtc, rows, databasePlans, now.AddMinutes(-3), signer);
        var claim = new ImmutableRolloverClaim("1.0", Guid.NewGuid(), Hash('5'),
            Hash('6'), Hash('7'), planSha256, plan.TargetGeneration,
            "legacy-maliev-exact23-postgres-data", now.AddDays(-1), Hash('8'),
            [.. DatabaseInventory.ActiveDatabases.Select(database =>
                new HistoricalLocalMetadataBinding(database,
                    PairedLocalTransitionMetadataState.SettledPrior, Hash('9')))],
            now.AddHours(-1), now.AddDays(1));
        HistoricalLocalRolloverDatabaseState[] states = [.. DatabaseInventory.ActiveDatabases
            .Select(database => new HistoricalLocalRolloverDatabaseState(database,
                HistoricalLocalRolloverDatabasePhase.Adopted, Hash('9'), Hash('a')))];
        var identity = new HistoricalCurrentLocalObservation("container", plan.TargetGeneration,
            claim.VolumeName, claim.VolumeCreatedAtUtc, "/volume", "/data", "/data",
            claim.SystemIdentifierSha256);
        var snapshot = new AuthenticatedHistoricalLocalRolloverSnapshot(claim,
            new(claim.ClaimId, claim.InitialAttestationSha256, claim.FuturePlanSha256,
                claim.TargetGeneration, 2, claim.InitialMetadata), states, identity, now);

        LocalRolloverTerminalReview review = LocalRolloverTerminalReviewer.Verify(snapshot,
            plan, disposable, terminal, trust);
        Assert.Equal(23, review.AdoptedDatabases);
        Assert.False(LocalRolloverTerminalReview.AuthorizesExecution);
        Assert.Equal("delta_rollover_terminal_invalid",
            Assert.Throws<DeltaExecutionException>(() => LocalRolloverTerminalReviewer.Verify(
                snapshot with
                {
                    Databases = [states[0] with
                { Phase = HistoricalLocalRolloverDatabasePhase.Prior }, .. states.Skip(1)]
                },
                plan, disposable, terminal, trust)).Code);
        Assert.Equal("delta_rollover_terminal_invalid",
            Assert.Throws<DeltaExecutionException>(() => LocalRolloverTerminalReviewer.Verify(
                snapshot, plan with { PlanId = Guid.NewGuid() }, disposable, terminal,
                trust)).Code);
        Assert.Equal("delta_rollover_terminal_invalid",
            Assert.Throws<DeltaExecutionException>(() => LocalRolloverTerminalReviewer.Verify(
                snapshot, plan, disposable, terminal with
                { AttestationSignature = "forged" }, trust)).Code);
    }

    private static Exact23DeltaReconciliationResult Receipt(Guid planId, string planSha256,
        DateTimeOffset cutoff, IReadOnlyList<DatabaseReconciliationEvidence> rows,
        IReadOnlyList<DeltaDatabasePlan> plans, DateTimeOffset reconciledAt,
        P256MigrationEvidenceSigner signer)
    {
        var unsigned = new Exact23DeltaReconciliationResult("1.2", planId, planSha256,
            cutoff, reconciledAt, rows, signer.KeyId, null)
        {
            Checkpoints = [.. rows.Select(database => new DeltaDatabaseCheckpointEvidence(
                database.Database, planId, planSha256, cutoff, Hash('d'),
                DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(
                    plans.Single(plan => plan.Database == database.Database)),
                DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(database),
                reconciledAt.AddMinutes(-1)))],
        };
        return unsigned with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(
                Exact23DeltaReconciliationCoordinator.CreatePayload(unsigned))),
        };
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }
}
