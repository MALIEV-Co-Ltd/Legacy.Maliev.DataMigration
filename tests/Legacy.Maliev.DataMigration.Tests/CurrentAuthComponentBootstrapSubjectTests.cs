using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

/// <summary>Pure source negatives only; synthetic values are never accepted native evidence.</summary>
public sealed class CurrentAuthComponentBootstrapSubjectTests
{
    [Fact]
    public void Separate_component_model_has_no_future_operational_proof_digests()
    {
        Assert.Equal(2, (int)CurrentAuthProofAdmission.DisposableNativeComponent);
        Assert.DoesNotContain(nameof(CurrentAuthRepairScope.NativeProofSha256), typeof(CurrentAuthComponentBootstrapSubject).GetProperties().Select(x => x.Name));
        Assert.DoesNotContain(nameof(CurrentAuthRepairScope.RecoveryReviewSha256), typeof(CurrentAuthComponentBootstrapSubject).GetProperties().Select(x => x.Name));
        Assert.DoesNotContain(nameof(CurrentAuthRepairScope.ExactRoleTransitionReviewSha256), typeof(CurrentAuthComponentBootstrapSubject).GetProperties().Select(x => x.Name));
        Assert.Contains(nameof(CurrentAuthComponentBootstrapSeed.DefinitionPrecursorSha256), typeof(CurrentAuthComponentBootstrapSeed).GetProperties().Select(x => x.Name));
    }
    [Fact]
    public void Ordinary_reader_keeps_all_eight_closed_cases_for_disposable_named_bootstrap()
    {
        Assert.Equal(8, CurrentAuthRepairProofReader.Cases("native", CurrentAuthProofAdmission.DisposableNativeBootstrap).Length);
        Assert.Equal(6, CurrentAuthRepairProofReader.Cases("native", CurrentAuthProofAdmission.DisposableNativeBootstrap, component: true).Length);
        Assert.Equal(7, CurrentAuthRepairProofReader.Cases("helper", CurrentAuthProofAdmission.DisposableNativeBootstrap, component: true).Length);
        Assert.Equal(8, CurrentAuthRepairProofReader.Cases("maintenance", CurrentAuthProofAdmission.ClosedConsole, component: true).Length);
    }
    [Fact]
    public void Bootstrap_seed_signature_subject_binds_definition_and_actual_source_images_run()
    {
        var seed = new CurrentAuthComponentBootstrapSeed("synthetic-unit-fixture-not-executed-evidence", new('a', 40), new('b', 64),
            ApprovedCurrentAuthSchema.AuthServiceCommit, CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256,
            new('c', 64), new('d', 64), new('e', 64), new('f', 64), new('1', 64), DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddHours(1), "synthetic", null);
        byte[] payload = CurrentAuthComponentBootstrap.SeedPayload(seed);
        Assert.Equal(payload, CurrentAuthComponentBootstrap.SeedPayload(seed with { Signature = "excluded-only-for-signing" }));
        Assert.NotEqual(payload, CurrentAuthComponentBootstrap.SeedPayload(seed with { DefinitionPrecursorSha256 = new('2', 64) }));
        Assert.NotEqual(payload, CurrentAuthComponentBootstrap.SeedPayload(seed with { AcceptedSourceSchemaPlanSha256 = new('3', 64) }));
        Assert.NotEqual(payload, CurrentAuthComponentBootstrap.SeedPayload(seed with { TestAssemblySha256 = new('4', 64) }));
        Assert.NotEqual(payload, CurrentAuthComponentBootstrap.SeedPayload(seed with { ParentRunBindingSha256 = new('5', 64) }));
    }
}
