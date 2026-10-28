using System.Reflection;
using System.Security.Cryptography;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Rejected synthetic boundary operands only. No successful reader, precursor/TRX or operational admission is fabricated.
public sealed class CurrentAuthArchiveComponentReadbackTests
{
    [Fact]
    public void Derived_precursor_scope_can_reference_actual_report_without_changing_the_genuine_subject()
    {
        var original = CurrentAuthLocalSessionArchiveConsoleTests.Scope(DateTimeOffset.UtcNow).LocalObservationPolicy;
        var derived = original with { AuthHelperProofSha256 = CurrentAuthLocalSessionArchivePolicy.HashBytes("synthetic-not-an-execution-report"u8.ToArray()) };
        Assert.NotEqual(original.AuthHelperProofSha256, derived.AuthHelperProofSha256);
        Assert.Equal(CurrentAuthRepairProofReader.Subject(original), CurrentAuthRepairProofReader.Subject(derived));
        Assert.NotEqual(CurrentAuthRepairProofReader.Subject(original),
            CurrentAuthRepairProofReader.Subject(derived with { SourceSchemaPlanSha256 = new('0', 64) }));
    }
    [Fact]
    public void Held_artifact_bytes_cannot_be_replaced_by_equal_length_claims_or_a_hash_marker()
    {
        byte[] original = "synthetic-rejected-artifact-A"u8.ToArray();
        byte[] substituted = "synthetic-rejected-artifact-B"u8.ToArray();
        Assert.Equal(original.Length, substituted.Length);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveComponentReadback.RequireArtifactBytes(substituted,
            CurrentAuthLocalSessionArchivePolicy.HashBytes(original)));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveComponentReadback.RequireArtifactBytes(original, new('0', 64)));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveComponentReadback.RequireArtifactBytes([], CurrentAuthLocalSessionArchivePolicy.HashBytes([])));
    }
    [Fact]
    public void Held_reader_cannot_be_constructed_without_the_fixed_async_authentication_path()
    {
        Assert.Empty(typeof(CurrentAuthArchiveComponentReadback).GetConstructors(BindingFlags.Instance | BindingFlags.Public));
        Assert.All(typeof(CurrentAuthArchiveComponentReadback).GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic), constructor => Assert.True(constructor.IsPrivate));
    }

    [Theory]
    [InlineData("relative")]
    [InlineData("hash")]
    [InlineData("reused-parent")]
    [InlineData("duplicate-image")]
    [InlineData("missing-key")]
    [InlineData("duplicate-key")]
    [InlineData("duplicate-key-file")]
    [InlineData("relative-key")]
    public async Task Invalid_input_rejects_before_any_source_network_custody_or_image_access(string fault)
    {
        var input = Input();
        input = fault switch
        {
            "relative" => input with { ParentBinding = input.ParentBinding with { Path = "relative.json" } },
            "hash" => input with { ParentSeed = input.ParentSeed with { Sha256 = "not-an-observation" } },
            "reused-parent" => input with { PrecursorBinding = input.ParentBinding },
            "duplicate-image" => input with { CoreImage = input.ConsoleImage },
            "missing-key" => input with { TrustedKeys = input.TrustedKeys.Take(2).ToArray() },
            "duplicate-key" => input with { PrecursorTrustedKeys = [input.PrecursorTrustedKeys[0], input.PrecursorTrustedKeys[0], input.PrecursorTrustedKeys[2]] },
            "duplicate-key-file" => input with { TrustedKeys = input.TrustedKeys.Select(x => x with { SubjectPublicKeyInfoPath = input.TrustedKeys[0].SubjectPublicKeyInfoPath }).ToArray() },
            "relative-key" => input with { TrustedKeys = input.TrustedKeys.Select(x => x with { SubjectPublicKeyInfoPath = "relative.der" }).ToArray() },
            _ => throw new InvalidOperationException(),
        };
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthArchiveComponentReadback.OpenAsync(input, CancellationToken.None));
    }

    [Theory]
    [InlineData("held-seed")]
    [InlineData("signature")]
    [InlineData("key")]
    [InlineData("pins")]
    [InlineData("expired")]
    public void Authentication_rejects_rebound_or_untrusted_held_seed(string fault)
    {
        using ECDsa reviewKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var review = new P256MigrationEvidenceSigner("synthetic-readback-review", reviewKey.ExportPkcs8PrivateKeyPem());
        using var authorization = new P256MigrationEvidenceSigner("synthetic-readback-authorization", authorizationKey.ExportPkcs8PrivateKeyPem());
        using var evidence = new P256MigrationEvidenceSigner("synthetic-readback-evidence", evidenceKey.ExportPkcs8PrivateKeyPem());
        var pins = new CurrentAuthArchivePins(review.KeyId, review.PublicKeyFingerprintSha256, authorization.KeyId,
            authorization.PublicKeyFingerprintSha256, evidence.KeyId, evidence.PublicKeyFingerprintSha256);
        var trust = new ReceiptAttestationTrustStore([new(review.KeyId, review.ExportSubjectPublicKeyInfo()),
            new(authorization.KeyId, authorization.ExportSubjectPublicKeyInfo()), new(evidence.KeyId, evidence.ExportSubjectPublicKeyInfo())]);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var scope = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(now);
        var seed = scope.ComponentSubject!.Seed with { KeyId = review.KeyId, SigningPinsSha256 = CurrentAuthLocalSessionArchivePolicy.Hash(pins), Signature = null };
        seed = seed with { Signature = Convert.ToBase64String(review.Sign(CurrentAuthArchiveComponentBootstrap.SeedPayload(seed))) };
        scope = scope with { ComponentSubject = scope.ComponentSubject with { Seed = seed } };
        var held = seed;
        if (fault == "held-seed") { held = held with { DefinitionPrecursorSha256 = new('0', 64) }; }
        else if (fault == "pins") { pins = pins with { EvidenceFingerprint = review.PublicKeyFingerprintSha256 }; }
        else
        {
            seed = fault switch
            {
                "signature" => seed with { Signature = Convert.ToBase64String(new byte[64]) },
                "key" => seed with { KeyId = authorization.KeyId },
                "expired" => seed with { ExpiresAtUtc = now.AddSeconds(-1) },
                _ => throw new InvalidOperationException(),
            };
            scope = scope with { ComponentSubject = scope.ComponentSubject with { Seed = seed } }; held = seed;
        }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveComponentReadback.RequireAuthenticatedClaims(scope, held, pins, trust, now));
    }

    [Theory]
    [InlineData("mode")]
    [InlineData("binding")]
    [InlineData("source")]
    [InlineData("source-plan")]
    [InlineData("actual-source")]
    [InlineData("owner")]
    [InlineData("owner-pins")]
    [InlineData("closure")]
    [InlineData("subject")]
    [InlineData("proof")]
    public void Pure_precursor_binding_rejects_foreign_metadata_without_importing_any_success_report(string fault)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var scope = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(now);
        var seed = scope.ComponentSubject!.Seed;
        var precursor = scope.LocalObservationPolicy with
        {
            ProofAdmission = CurrentAuthProofAdmission.DisposableNativeBootstrap,
            AuthHelperProofSha256 = seed.DefinitionPrecursorSha256
        };
        seed = seed with { PrecursorSubjectSha256 = CurrentAuthRepairProofReader.Subject(precursor) };
        string binding = precursor.RunBindingSha256, source = seed.SourceSchemaPlanSha256, proof = seed.DefinitionPrecursorSha256;
        switch (fault)
        {
            case "mode": precursor = precursor with { ProofAdmission = CurrentAuthProofAdmission.ClosedConsole }; break;
            case "binding": binding = new('0', 64); break;
            case "source": precursor = precursor with { SourceCommitSha = new('0', 40) }; break;
            case "source-plan": precursor = precursor with { SourceSchemaPlanSha256 = new('0', 64) }; break;
            case "actual-source": source = new('0', 64); break;
            case "owner": precursor = precursor with { AuthOwnerCommitSha = new('0', 40) }; break;
            case "owner-pins": precursor = precursor with { AuthOwnerSourcePinsSha256 = new('0', 64) }; break;
            case "closure": precursor = precursor with { AuthClosureSha256 = new('0', 64) }; break;
            case "subject": seed = seed with { PrecursorSubjectSha256 = new('0', 64) }; break;
            case "proof": proof = new('0', 64); break;
            default: throw new InvalidOperationException();
        }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveComponentReadback.RequirePrecursorBinding(precursor, seed, binding, source, proof));
    }

    private static CurrentAuthArchiveComponentReadbackInput Input()
    {
        // Names only; these paths are never created or opened by the rejected-input tests.
        string root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "synthetic-archive-readback-no-resources"));
        CurrentAuthArchiveProofArtifact Artifact(string name) { return new(Path.Combine(root, name), new('a', 64)); }
        DeltaTrustedKeyReference[] Keys(string prefix)
        {
            return [new(prefix + "-review", Path.Combine(root, prefix + "-review.der")),
            new(prefix + "-authorization", Path.Combine(root, prefix + "-authorization.der")), new(prefix + "-evidence", Path.Combine(root, prefix + "-evidence.der"))];
        }
        return new(Artifact("parent-binding.json"), Artifact("parent-seed.json"), Artifact("scope.json"), Artifact("source.json"),
            Artifact("pins.json"), Keys("parent"), Artifact("tests.dll"), Artifact("console.dll"), Artifact("core.dll"),
            Artifact("precursor-binding.json"), Artifact("precursor-scope.json"), Artifact("precursor-source.json"), Artifact("precursor-pins.json"),
            Keys("precursor"), Artifact("definition.json"));
    }
}
