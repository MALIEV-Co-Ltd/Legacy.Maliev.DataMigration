using System.Security.Cryptography;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveFinal6AssemblyTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("missing")]
    [InlineData("duplicate-case")]
    [InlineData("reused-operation")]
    [InlineData("complete-flag")]
    public void Assembly_requires_all_eighteen_distinct_actual_case_slots_before_semantic_readback(string fault)
    {
        var now = DateTimeOffset.UtcNow;
        var cases = Enum.GetValues<CurrentAuthArchiveProofCaseV2>().Select(selected => Run(selected, now)).ToArray();
        cases = fault switch
        {
            "missing" => cases.Skip(1).ToArray(),
            "duplicate-case" => [cases[1], .. cases.Skip(1)],
            "reused-operation" => [cases[0] with { Generated = cases[0].Generated with { OperationId = cases[1].Generated.OperationId } }, .. cases.Skip(1)],
            "complete-flag" => [cases[0] with { PhaseProofComplete = true }, .. cases.Skip(1)],
            _ => cases,
        };
        if (fault == "none") { CurrentAuthArchiveFinal6ProofAssembly.RequireInventory(cases); } // Inventory only, never an actual proof.
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFinal6ProofAssembly.RequireInventory(cases)); }
    }

    [Theory]
    [InlineData("none")]
    [InlineData("input")]
    [InlineData("host")]
    [InlineData("source")]
    [InlineData("definition")]
    [InlineData("intended")]
    [InlineData("pre-intended")]
    [InlineData("case-binding")]
    [InlineData("case")]
    [InlineData("operation")]
    [InlineData("expired")]
    public void Preinvocation_generation_commitments_cannot_be_swapped_between_cases(string fault)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var seed = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(now).ComponentSubject!.Seed;
        var generated = Run(CurrentAuthArchiveProofCaseV2.Complete, now).Generated with { OperationId = seed.OperationId };
        var binding = new CurrentAuthArchiveFinal6GenerationBinding("current-auth-archive-final6-generated-binding-v1", generated.Case, seed.OperationId,
            generated.Audience.Sha256, generated.Seed.Sha256, generated.CaseBinding.Sha256, generated.SourceCapture.Sha256, generated.Definition.Sha256,
            generated.Input.Sha256, generated.HostConfiguration.Sha256, generated.IntendedObservation.Sha256, generated.PreDefinitionIntendedObservation.Sha256,
            now, seed.ExpiresAtUtc);
        string changed = new('f', 64);
        binding = fault switch
        {
            "input" => binding with { InputSha256 = changed },
            "host" => binding with { HostConfigurationSha256 = changed },
            "source" => binding with { SourceCaptureSha256 = changed },
            "definition" => binding with { DefinitionSha256 = changed },
            "intended" => binding with { IntendedSha256 = changed },
            "pre-intended" => binding with { PreDefinitionIntendedSha256 = changed },
            "case-binding" => binding with { CaseBindingSha256 = changed },
            "case" => binding with { Case = CurrentAuthArchiveProofCaseV2.ExactDelete },
            "operation" => binding with { OperationId = Guid.NewGuid() },
            "expired" => binding with { ExpiresAtUtc = now },
            _ => binding,
        };
        if (fault == "none") { CurrentAuthArchiveFinal6GenerationPolicy.Require(binding, generated, seed, now); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFinal6GenerationPolicy.Require(binding, generated, seed, now)); }
    }

    [Fact]
    public void Neither_phase3_V2_nor_V1_reader_accepts_the_Final6_proof_domain_or_kind()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("evidence", key.ExportPkcs8PrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, key.ExportSubjectPublicKeyInfo())]);
        var now = DateTimeOffset.UtcNow;
        var proof = new CurrentAuthArchiveFinal6Proof(CurrentAuthArchiveFinal6ProofAssembly.Kind, Guid.NewGuid(), new('a', 64), new('a', 40),
            new('b', 64), new('c', 64), new('d', 64), new('e', 64), new('f', 64), now, now, now.AddMinutes(1), []);
        var claim = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveFinal6ProofAssembly.Domain, proof, signer);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveProofV2>(claim,
            CurrentAuthArchiveProofAssemblyV2.Domain, signer.KeyId, signer.PublicKeyFingerprintSha256, trust));
        var scope = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(now);
        var old = new CurrentAuthArchiveExecutionProof(CurrentAuthArchiveFinal6ProofAssembly.Kind, CurrentAuthArchiveProofReader.Subject(scope),
            scope.LocalObservationPolicy.SourceCommitSha, new('a', 64), new('b', 64), now, now, now.AddMinutes(1), new("synthetic.trx", new('c', 64)), [], []);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofReader.RequireHeader(old, scope, "recovery", new('a', 64), new('b', 64), now));
    }

    private static CurrentAuthArchiveFinal6CaseRun Run(CurrentAuthArchiveProofCaseV2 selected, DateTimeOffset now)
    {
        static CurrentAuthArchiveProofArtifact File(string name)
        {
            return new(name, new('a', 64));
        }

        var generated = new CurrentAuthArchiveFinal6GeneratedCase(selected, Guid.NewGuid(), File("binding"), File("generation"), File("case"),
            File("capture"), File("intended"), File("pre-intended"), File("seed"), File("input"), File("host"), File("definition"), File("audience"));
        return new("structural-only", generated, now, now, 0, File("run"), File("result"), File("provider"), File("vstest"), File("trx"), File("exit"), File("cleanup"), false);
    }
}
