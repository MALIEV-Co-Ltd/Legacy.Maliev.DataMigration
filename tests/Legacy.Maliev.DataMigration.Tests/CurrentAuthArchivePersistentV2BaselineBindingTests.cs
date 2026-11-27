using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchivePersistentV2BaselineBindingTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("operation")]
    [InlineData("delete-set")]
    [InlineData("delete-count")]
    [InlineData("target")]
    [InlineData("generation")]
    [InlineData("source")]
    [InlineData("role")]
    [InlineData("expiry")]
    [InlineData("mode")]
    [InlineData("expired")]
    public void Persistent_V2_baseline_is_bound_to_every_field_of_the_exact_current_reviewed_scope(string fault)
    {
        var now = DateTimeOffset.UtcNow;
        var intent = Intent(now);
        var scope = intent.Scope;
        byte[] original = JsonSerializer.SerializeToUtf8Bytes(intent);
        scope = fault switch
        {
            "operation" => scope with { OperationId = Guid.NewGuid() },
            "delete-set" => scope with { DeleteSetSha256 = new('f', 64) },
            "delete-count" => scope with { DeleteCount = scope.DeleteCount + 1 },
            "target" => scope with { LocalObservationPolicy = scope.LocalObservationPolicy with { TargetObservationSha256 = new('f', 64) } },
            "generation" => scope with { ProductionObservationPolicy = scope.ProductionObservationPolicy with { TargetGeneration = "another-generation" } },
            "source" => scope with { LocalObservationPolicy = scope.LocalObservationPolicy with { SourceSchemaPlanSha256 = new('f', 64) } },
            "role" => scope with { LocalObservationPolicy = scope.LocalObservationPolicy with { Maintenance = scope.LocalObservationPolicy.Maintenance with { Role = "another-role" } } },
            "expiry" => scope with { ExpiresAtUtc = scope.ExpiresAtUtc.AddSeconds(-1) },
            "mode" => scope with { ProofAdmission = CurrentAuthArchiveProofAdmission.PersistentWithClosedConsoleProof },
            _ => scope,
        };
        if (fault == "none")
        {
            // Congruence is deliberately non-authorizing; actual construction also requires authenticated claims and the live observer holder.
            CurrentAuthArchivePersistentV2Baselines.RequireSameScope(intent, scope, now);
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireScope(scope, now));
        }
        else
        {
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchivePersistentV2Baselines.RequireSameScope(intent, scope,
                fault == "expired" ? now.AddMinutes(2) : now));
        }
        Assert.Equal(original, JsonSerializer.SerializeToUtf8Bytes(intent));
    }

    [Fact]
    public void The_environment_baseline_holder_cannot_be_deserialized_from_an_admitted_marker()
    {
        _ = Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<CurrentAuthArchivePersistentV2Baselines>(
            "{\"ProofAdmission\":3,\"Verified\":true}"));
    }

    [Theory]
    [InlineData("wrong-review")]
    [InlineData("old-domain")]
    [InlineData("expired")]
    public void Baseline_construction_authenticates_new_claims_before_accessing_the_live_observer(string fault)
    {
        using var reviewKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var reviewer = new P256MigrationEvidenceSigner("review-v2", reviewKey.ExportPkcs8PrivateKeyPem());
        using var authorizer = new P256MigrationEvidenceSigner("authorization-v2", authorizationKey.ExportPkcs8PrivateKeyPem());
        using var evidence = new P256MigrationEvidenceSigner("evidence-v2", evidenceKey.ExportPkcs8PrivateKeyPem());
        var pins = new CurrentAuthArchivePins(reviewer.KeyId, reviewer.PublicKeyFingerprintSha256, authorizer.KeyId,
            authorizer.PublicKeyFingerprintSha256, evidence.KeyId, evidence.PublicKeyFingerprintSha256);
        var trust = new ReceiptAttestationTrustStore([new(reviewer.KeyId, reviewKey.ExportSubjectPublicKeyInfo()),
            new(authorizer.KeyId, authorizationKey.ExportSubjectPublicKeyInfo()), new(evidence.KeyId, evidenceKey.ExportSubjectPublicKeyInfo())]);
        var now = DateTimeOffset.UtcNow; var intent = Intent(now);
        var review = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchivePersistentV2Policy.ReviewDomain, intent, reviewer);
        var authorization = new CurrentAuthArchivePersistentAuthorizationV2("current-auth-persistent-archive-authorization-v2", intent.Scope.OperationId,
            fault == "wrong-review" ? new('f', 64) : CurrentAuthLocalSessionArchivePolicy.Hash(review), now,
            fault == "expired" ? now.AddSeconds(-1) : intent.Scope.ExpiresAtUtc);
        var allowed = CurrentAuthLocalSessionArchivePolicy.Sign(fault == "old-domain" ? CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain :
            CurrentAuthArchivePersistentV2Policy.AuthorizationDomain, authorization, authorizer);
        // A null live holder would fail differently if construction touched targets before authenticating claims.
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchivePersistentV2Baselines.Create(review, allowed, pins, trust, null!));
    }

    private static CurrentAuthArchivePersistentIntentV2 Intent(DateTimeOffset now)
    {
        var scope = CurrentAuthLocalSessionArchiveConsoleTests.Scope(now) with
        {
            ProofAdmission = CurrentAuthArchivePersistentV2Policy.Mode,
            ArchiveHelperProofSha256 = string.Empty,
            ArchiveNativeProofSha256 = string.Empty,
            ExactDeleteReviewSha256 = string.Empty,
            RecoveryReviewSha256 = string.Empty,
            ExpiresAtUtc = now.AddMinutes(1),
        };
        string hash = new('a', 64); var file = new CurrentAuthArchiveGenuineArtifact("structural-only", hash);
        return new("current-auth-persistent-archive-intent-v2", scope, hash, hash, hash, hash, hash, hash, hash, hash, file, file, file);
    }
}
