using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveProofAssemblyV2Tests
{
    // Structural fixtures only: these cannot satisfy RequireCasesAsync or publish an authenticated proof.
    private static CurrentAuthArchiveGeneratedCaseRunV2 StructuralRun(CurrentAuthArchiveProofCaseV2 selected)
    {
        var artifact = new CurrentAuthArchiveProofArtifact("structural-only", new string('a', 64));
        var generated = new CurrentAuthArchiveGeneratedCaseV2(Case: selected, OperationId: Guid.NewGuid(), QualifiedInputBinding: artifact, BindingClaim: artifact,
            SourceCapture: artifact, IntendedObservation: artifact, PreDefinitionIntendedObservation: artifact,
            Seed: artifact, Input: artifact, HostConfiguration: artifact, Definition: null!, Audience: artifact);
        return new("structural-only", generated, default, default, 0, artifact, artifact, artifact, artifact, artifact, artifact, artifact, false);
    }

    [Fact]
    public void Inventory_requires_every_distinct_real_case_and_operation_without_per_case_completion_claims()
    {
        var cases = Enum.GetValues<CurrentAuthArchiveProofCaseV2>().Select(StructuralRun).ToArray();
        CurrentAuthArchiveProofAssemblyV2.RequireInventory(cases);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofAssemblyV2.RequireInventory(cases[..^1]));
        var duplicateCase = cases.ToArray(); duplicateCase[^1] = StructuralRun(cases[0].Generated.Case);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofAssemblyV2.RequireInventory(duplicateCase));
        var duplicateOperation = cases.ToArray(); duplicateOperation[^1] = duplicateOperation[^1] with
        { Generated = duplicateOperation[^1].Generated with { OperationId = cases[0].Generated.OperationId } };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofAssemblyV2.RequireInventory(duplicateOperation));
        var falseCompletion = cases.ToArray(); falseCompletion[0] = falseCompletion[0] with { PhaseProofComplete = true };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofAssemblyV2.RequireInventory(falseCompletion));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    public void Final_readback_binds_immutable_proof_audience_and_a_fresh_bounded_post_proof_window(int change)
    {
        var now = new DateTimeOffset(2026, 11, 24, 0, 0, 0, TimeSpan.Zero);
        string proof = new('a', 64), audience = new('b', 64);
        var reference = new CurrentAuthArchiveProofArtifact("structural-only", new string('c', 64));
        var valid = new CurrentAuthArchiveFinalIntendedReadbackV2("current-auth-archive-final-intended-readback-v2", proof,
            audience, new string('d', 64), reference, reference, now.AddSeconds(-10), now.AddSeconds(60));
        CurrentAuthArchiveProofAssemblyV2.RequireFinalHeader(valid, proof, audience, now.AddSeconds(-20), now.AddMinutes(5), now);
        var changed = change switch
        {
            0 => valid with { Kind = "current-auth-archive-complete-eighteen-proof-v1" },
            1 => valid with { ProofSha256 = new string('e', 64) },
            2 => valid with { AudienceSha256 = new string('e', 64) },
            3 => valid with { ObservedAtUtc = now.AddSeconds(-21) },
            4 => valid with { ObservedAtUtc = now.AddSeconds(1) },
            5 => valid with { ExpiresAtUtc = now },
            _ => valid with { ExpiresAtUtc = now.AddMinutes(3) },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofAssemblyV2.RequireFinalHeader(changed, proof, audience,
            now.AddSeconds(-20), now.AddMinutes(5), now));
    }
}
