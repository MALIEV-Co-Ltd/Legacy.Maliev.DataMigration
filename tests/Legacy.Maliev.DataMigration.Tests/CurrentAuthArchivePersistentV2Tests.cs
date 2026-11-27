using System.Security.Cryptography;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchivePersistentV2Tests
{
    [Theory]
    [InlineData("review-current-auth-local-session-archive-v2")]
    [InlineData("authorize-current-auth-local-session-archive-v2")]
    [InlineData("verify-current-auth-local-session-archive-v2")]
    [InlineData("apply-current-auth-local-session-archive-v2")]
    public void New_fixed_commands_are_separate_from_every_V1_command_path(string command)
    {
        MigrationConsole.RequirePersistentArchiveV2Command(command);
        Assert.Equal(command, ConsoleInvocation.Parse([command, "--config", "protected.json"]).Command);
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequireArchiveCommand(command));
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequirePersistentArchiveV2Command(command[..^3]));
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([command, "--config", "protected.json", "--sql", "SELECT 1"]));
    }
    [Fact]
    public async Task Serialized_positive_descriptions_cannot_mint_the_fixed_issuer_capability()
    {
        object description = new { Kind = "current-auth-archive-complete-eighteen-proof-v2", Verified = true, SourceAccepted = true };
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePermit.PersistentV2Capability.AuthenticateAsync(description, CancellationToken.None));
    }
    [Theory]
    [InlineData("none")]
    [InlineData("operation")]
    [InlineData("review")]
    [InlineData("expiry")]
    [InlineData("kind")]
    public void V2_authorization_is_separate_and_binds_the_exact_current_review(string fault)
    {
        using var reviewKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var authKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var reviewer = new P256MigrationEvidenceSigner("review-v2", reviewKey.ExportPkcs8PrivateKeyPem());
        using var authorizer = new P256MigrationEvidenceSigner("authorize-v2", authKey.ExportPkcs8PrivateKeyPem());
        using var evidence = new P256MigrationEvidenceSigner("evidence-v2", evidenceKey.ExportPkcs8PrivateKeyPem());
        var pins = new CurrentAuthArchivePins(reviewer.KeyId, reviewer.PublicKeyFingerprintSha256, authorizer.KeyId,
            authorizer.PublicKeyFingerprintSha256, evidence.KeyId, evidence.PublicKeyFingerprintSha256);
        var trust = new ReceiptAttestationTrustStore([new(reviewer.KeyId, reviewKey.ExportSubjectPublicKeyInfo()),
            new(authorizer.KeyId, authKey.ExportSubjectPublicKeyInfo()), new(evidence.KeyId, evidenceKey.ExportSubjectPublicKeyInfo())]);
        var now = DateTimeOffset.UtcNow; var intent = Intent(now);
        var review = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchivePersistentV2Policy.ReviewDomain, intent, reviewer);
        var authorization = new CurrentAuthArchivePersistentAuthorizationV2("current-auth-persistent-archive-authorization-v2", intent.Scope.OperationId,
            CurrentAuthLocalSessionArchivePolicy.Hash(review), now, intent.Scope.ExpiresAtUtc);
        authorization = fault switch
        {
            "operation" => authorization with { OperationId = Guid.NewGuid() },
            "review" => authorization with { ReviewSha256 = new string('f', 64) },
            "expiry" => authorization with { ExpiresAtUtc = intent.Scope.ExpiresAtUtc.AddSeconds(1) },
            "kind" => authorization with { Kind = "current-auth-session-archive-authorization-v1" },
            _ => authorization,
        };
        var claim = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchivePersistentV2Policy.AuthorizationDomain, authorization, authorizer);
        if (fault == "none") { Assert.Equal(CurrentAuthLocalSessionArchivePolicy.Hash(intent), CurrentAuthLocalSessionArchivePolicy.Hash(CurrentAuthArchivePersistentV2Policy.Claims(review, claim, pins, trust, now))); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchivePersistentV2Policy.Claims(review, claim, pins, trust, now)); }
    }

    [Fact]
    public async Task V1_claims_and_permit_cannot_admit_marker_three_without_the_authenticated_V2_capability()
    {
        var now = DateTimeOffset.UtcNow; var intent = Intent(now);
        CurrentAuthArchivePersistentV2Policy.RequireIntent(intent, now); // Structure only, never a proof or permit.
        Assert.False(Enum.IsDefined(intent.Scope.ProofAdmission));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireScope(intent.Scope, now));
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequireArchiveConsoleScope(intent.Scope));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofReader.Domain("helper", intent.Scope.ProofAdmission));
        using var reviewKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var authKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var reviewer = new P256MigrationEvidenceSigner("review", reviewKey.ExportPkcs8PrivateKeyPem());
        using var authorizer = new P256MigrationEvidenceSigner("authorize", authKey.ExportPkcs8PrivateKeyPem());
        using var evidence = new P256MigrationEvidenceSigner("evidence", evidenceKey.ExportPkcs8PrivateKeyPem());
        var pins = new CurrentAuthArchivePins(reviewer.KeyId, reviewer.PublicKeyFingerprintSha256, authorizer.KeyId, authorizer.PublicKeyFingerprintSha256,
            evidence.KeyId, evidence.PublicKeyFingerprintSha256);
        var trust = new ReceiptAttestationTrustStore([new(reviewer.KeyId, reviewKey.ExportSubjectPublicKeyInfo()), new(authorizer.KeyId, authKey.ExportSubjectPublicKeyInfo()),
            new(evidence.KeyId, evidenceKey.ExportSubjectPublicKeyInfo())]);
        var review = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReviewDomain, intent.Scope, reviewer);
        var authorization = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain,
            new CurrentAuthArchiveAuthorization(intent.Scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(review), now, intent.Scope.ExpiresAtUtc), authorizer);
        // A null environment would fail differently if the old path reached target contact.
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePermit.AdmitAsync(review, authorization, trust, pins, null!, TimeProvider.System, CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePermit.PersistentV2Capability.AuthenticateAsync(new object(), CancellationToken.None));
    }
    [Theory]
    [InlineData("review-current-auth-local-session-archive-v2")]
    [InlineData("authorize-current-auth-local-session-archive-v2")]
    [InlineData("verify-current-auth-local-session-archive-v2")]
    [InlineData("apply-current-auth-local-session-archive-v2")]
    public void V2_has_fixed_separate_commands_and_no_restore_or_callback_route(string command)
    {
        MigrationConsole.RequirePersistentArchiveV2Command(command);
        Assert.Equal(command, ConsoleInvocation.Parse([command, "--config", "protected.json"]).Command);
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequireArchiveCommand(command));
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequirePersistentArchiveV2Command("restore-current-auth-local-session-archive-v2"));
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([command, "--callback", "bypass", "--config", "protected.json"]));
    }
    [Theory]
    [InlineData("old-mode")]
    [InlineData("old-proof-slot")]
    [InlineData("current-intended")]
    [InlineData("lease")]
    public void Shape_validation_does_not_reinterpret_V1_evidence_or_extend_the_review_lease(string fault)
    {
        var now = DateTimeOffset.UtcNow; var intent = Intent(now);
        var changed = fault switch
        {
            "old-mode" => intent with { Scope = intent.Scope with { ProofAdmission = CurrentAuthArchiveProofAdmission.PersistentWithClosedConsoleProof } },
            "old-proof-slot" => intent with { Scope = intent.Scope with { ArchiveNativeProofSha256 = intent.ProofSha256 } },
            "current-intended" => intent with { IntendedObservationSha256 = new string('f', 64) },
            _ => intent with { Scope = intent.Scope with { ExpiresAtUtc = now.AddMinutes(3) } },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchivePersistentV2Policy.RequireIntent(changed, now));
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
            ExpiresAtUtc = now.AddMinutes(1)
        };
        string hash = new('a', 64); var file = new CurrentAuthArchiveGenuineArtifact("structural-only", hash);
        return new("current-auth-persistent-archive-intent-v2", scope, hash, hash, hash, hash, hash, hash, hash, hash, file, file, file);
    }
}
