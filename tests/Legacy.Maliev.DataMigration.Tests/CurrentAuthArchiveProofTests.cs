using System.Security.Cryptography;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveProofTests
{
    private const ulong GiB = 1024UL * 1024 * 1024;
    [Theory]
    [InlineData(true, (3UL * GiB) - 1, 0UL)]
    [InlineData(false, GiB - 1, 0UL)]
    [InlineData(false, GiB, (5UL * GiB) + 1)]
    public void Actual_capacity_thresholds_cannot_be_weakened(bool admission, ulong free, ulong rss)
    { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveCapacity.RequireValues(free, rss, admission)); }
    [Fact]
    public void Capacity_exact_boundaries_are_allowed()
    { CurrentAuthArchiveCapacity.RequireValues(3 * GiB, 5 * GiB, true); CurrentAuthArchiveCapacity.RequireValues(GiB, 5 * GiB, false); }
    [Fact]
    public void Bootstrap_cannot_admit_persistent_or_production_targets()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow; var scope = CurrentAuthLocalSessionArchiveConsoleTests.Scope(now);
        CurrentAuthLocalSessionArchivePolicy.RequireScope(scope, now);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireScope(scope with { ProofAdmission = CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap }, now));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireScope(scope with { ProofAdmission = (CurrentAuthArchiveProofAdmission)99 }, now));
        var local = scope.LocalObservationPolicy with { Target = new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/disposable-aaaaaaaaaaaa", new string('e', 64)) };
        var comparison = scope.ProductionObservationPolicy with { Target = new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/disposable-bbbbbbbbbbbb", new string('f', 64)) };
        CurrentAuthLocalSessionArchivePolicy.RequireScope(CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(now), now);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireScope(scope with { LocalObservationPolicy = local, ProductionObservationPolicy = comparison }, now));
    }
    [Theory]
    [InlineData("helper")]
    [InlineData("native")]
    [InlineData("delete")]
    [InlineData("recovery")]
    public void Genuine_proof_signatures_cannot_cross_phase_or_permission_mode(string phase)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var signer = new P256MigrationEvidenceSigner("proof", key.ExportPkcs8PrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore([new("proof", key.ExportSubjectPublicKeyInfo())]);
        var scope = CurrentAuthLocalSessionArchiveConsoleTests.Scope(DateTimeOffset.UtcNow);
        string domain = CurrentAuthArchiveProofReader.Domain(phase, CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap);
        var claim = CurrentAuthLocalSessionArchivePolicy.Sign(domain, new CurrentAuthArchiveAuthorization(scope.OperationId, new string('a', 64), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1)), signer);
        _ = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveAuthorization>(claim, domain, signer.KeyId, signer.PublicKeyFingerprintSha256, trust);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveAuthorization>(claim,
            CurrentAuthArchiveProofReader.Domain(phase, CurrentAuthArchiveProofAdmission.PersistentWithClosedConsoleProof), signer.KeyId, signer.PublicKeyFingerprintSha256, trust));
        string other = phase == "helper" ? "native" : "helper";
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveAuthorization>(claim,
            CurrentAuthArchiveProofReader.Domain(other, CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap), signer.KeyId, signer.PublicKeyFingerprintSha256, trust));
    }
    [Fact]
    public void Proof_subject_excludes_only_its_four_hashes_and_preserves_device_paths_and_delete_authority()
    {
        var scope = CurrentAuthLocalSessionArchiveConsoleTests.Scope(DateTimeOffset.UtcNow); string subject = CurrentAuthArchiveProofReader.Subject(scope);
        Assert.Equal(subject, CurrentAuthArchiveProofReader.Subject(scope with { ArchiveHelperProofSha256 = new string('0', 64), ArchiveNativeProofSha256 = new string('1', 64), ExactDeleteReviewSha256 = new string('2', 64), RecoveryReviewSha256 = new string('3', 64) }));
        Assert.NotEqual(subject, CurrentAuthArchiveProofReader.Subject(scope with { DeleteSetSha256 = new string('0', 64) }));
        Assert.NotEqual(subject, CurrentAuthArchiveProofReader.Subject(scope with { Paths = scope.Paths with { SecondRecoveryPrivateKey = @"B:\foreign\key" } }));
        Assert.NotEqual(subject, CurrentAuthArchiveProofReader.Subject(scope with { ProofAdmission = CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap }));
    }
    [Theory]
    [InlineData("missing")]
    [InlineData("early-inventory")]
    [InlineData("expired")]
    [InlineData("present-volume")]
    [InlineData("live-listener")]
    public void Cleanup_requires_exact_owned_absence_after_removal_within_lease(string fault)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow; Guid runId = Guid.NewGuid(); var artifact = new CurrentAuthArchiveProofArtifact("unexecuted", new string('a', 64));
        var run = new CurrentAuthArchiveProofRun(runId, new string('a', 64), new string('b', 64), "first", "second", now, now.AddMinutes(8), artifact, artifact, artifact);
        var cleanup = new CurrentAuthArchiveProofCleanup(runId, now.AddMinutes(3), now.AddMinutes(5), true, true, false, [run.ContainerId, run.ComparisonContainerId], [run.Volume, run.ComparisonVolume]);
        var absence = new CurrentAuthArchiveProofAbsence(runId, now.AddMinutes(4), true, true, true, [], [], []);
        CurrentAuthArchiveProofReader.RequireCleanup(run, cleanup, absence, now.AddMinutes(2), now.AddMinutes(6), [1234, 1235]);
        absence = fault switch
        {
            "missing" => absence with { VolumeInventorySucceeded = false },
            "early-inventory" => absence with { ObservedAtUtc = now.AddMinutes(1) },
            "expired" => absence with { ObservedAtUtc = now.AddMinutes(9) },
            "present-volume" => absence with { Volumes = [run.Volume] },
            _ => absence with { LoopbackListeners = [1234] },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofReader.RequireCleanup(run, cleanup, absence, now.AddMinutes(2), now.AddMinutes(10), [1234, 1235]));
    }
    [Fact]
    public void Executed_image_must_equal_both_TRX_paths_and_held_image()
    {
        string image = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "archive-proof", "tests.dll"));
        CurrentAuthArchiveProofReader.RequireImagePath(image, image, image, image);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofReader.RequireImagePath(image, image, "foreign.dll", image));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofReader.RequireImagePath(image, Path.GetFullPath("foreign.dll"), image, image));
    }
    [Fact]
    public void Post_delete_uncertainty_cannot_be_proved_by_empty_receipts()
    {
        var before = new CurrentAppOwnedDatabaseSnapshot("Auth", [], [new("public", "refresh_sessions", 1, new string('a', 64))], []);
        var after = before with { Relations = [new("public", "refresh_sessions", 0, Convert.ToHexStringLower(SHA256.HashData([])))] };
        var scenario = new CurrentAuthArchiveProofScenario("commit-ack-lost", "injected", false, true, false, false, DateTimeOffset.UtcNow);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofReader.RequireEffects("commit-ack-lost", scenario, [], before, after));
    }
    [Fact]
    public void CAS_fault_cannot_hide_an_additional_typed_field_change()
    {
        var row = new CurrentAuthArchiveSession(Guid.NewGuid(), Guid.NewGuid(), "ไทย", 1, null, "synthetic", DateTime.SpecifyKind(new DateTime(2031, 1, 1), DateTimeKind.Utc),
            DateTime.SpecifyKind(new DateTime(2031, 1, 2), DateTimeKind.Utc), null, null, null);
        var changed = row with { SecurityStamp = "different" };
        CurrentAuthArchiveProofReader.RequireCasFaultRows([row], [changed]);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofReader.RequireCasFaultRows([row], [changed with { TokenHash = "also different" }]));
    }
    [Fact]
    public void Private_fault_cannot_hide_catalog_or_unrelated_relation_changes()
    {
        var before = new CurrentAppOwnedDatabaseSnapshot("Auth", [], [new("private", "journal", 1, new string('a', 64)), new("public", "refresh_sessions", 1, new string('b', 64))], []);
        var after = before with { Relations = [before.Relations[0] with { RowSha256 = new string('c', 64) }, before.Relations[1]] };
        CurrentAuthArchiveProofReader.RequireFault("private-journal-drift", before, after);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofReader.RequireFault("private-journal-drift", before,
            after with { Relations = [after.Relations[0], after.Relations[1] with { Rows = 0 }] }));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofReader.RequireFault("CAS-field-drift", before, after));
    }
}
