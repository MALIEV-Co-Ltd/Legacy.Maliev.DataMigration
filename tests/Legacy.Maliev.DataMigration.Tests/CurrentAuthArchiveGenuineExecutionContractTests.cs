using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineExecutionContractTests
{
    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)]
    [InlineData(8)] [InlineData(9)] [InlineData(10)] [InlineData(11)] [InlineData(12)] [InlineData(13)]
    public void Execution_seed_binds_original_signed_bytes_to_one_exact_case(int value)
    {
        var expected = (CurrentAuthArchiveGenuineExecutionCase)value;
        using var reviewKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var reviewer = new P256MigrationEvidenceSigner("unit-execution-review", reviewKey.ExportPkcs8PrivateKeyPem());
        static string Fingerprint(ECDsa key) => Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
        var pins = new CurrentAuthArchivePins(reviewer.KeyId, reviewer.PublicKeyFingerprintSha256,
            "unit-execution-authorization", Fingerprint(authorizationKey), "unit-execution-evidence", Fingerprint(evidenceKey));
        var trust = new ReceiptAttestationTrustStore([
            new(reviewer.KeyId, reviewKey.ExportSubjectPublicKeyInfo()), new(pins.AuthorizationKeyId, authorizationKey.ExportSubjectPublicKeyInfo()),
            new(pins.EvidenceKeyId, evidenceKey.ExportSubjectPublicKeyInfo()),
        ]);
        DateTimeOffset now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var seed = new CurrentAuthArchiveComponentBootstrapSeed("current-auth-genuine-archive-component-seed-v1", Guid.NewGuid(),
            CurrentAuthArchiveGenuineExecutionCases.Identity(expected).CaseId, new string('a', 40), new string('b', 64),
            ApprovedCurrentAuthSchema.AuthServiceCommit, CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256,
            new string('c', 64), new string('d', 64), new string('e', 64), new string('1', 64), new string('2', 64), new string('3', 64),
            CurrentAuthLocalSessionArchivePolicy.Hash(pins), now, now.AddMinutes(8), pins.ReviewKeyId, null);
        seed = seed with { Signature = Convert.ToBase64String(reviewer.Sign(CurrentAuthArchiveComponentBootstrap.SeedPayload(seed))) };
        CurrentAuthArchiveGenuineExecutionSeed.RequireInitial(seed, pins, trust, expected, now);
        var other = expected == CurrentAuthArchiveGenuineExecutionCase.NativeComplete
            ? CurrentAuthArchiveGenuineExecutionCase.ExactReviewedDelete : CurrentAuthArchiveGenuineExecutionCase.NativeComplete;
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineExecutionSeed.RequireInitial(seed, pins, trust, other, now));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineExecutionSeed.RequireInitial(
            seed with { CaseId = CurrentAuthArchiveGenuineExecutionCases.Identity(other).CaseId }, pins, trust, other, now));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveComponentBootstrap.RequireInitialSeed(seed, pins, trust, now));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineRecoveryHelpers.RequireInitialSeed(seed, pins, trust,
            CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback, now));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineExecutionSeed.RequireInitial(seed, pins, trust, expected, now.AddMinutes(8)));
    }

    [Theory]
    [InlineData(0)] [InlineData(3)] [InlineData(5)] [InlineData(6)]
    [InlineData(12)] [InlineData(13)] [InlineData(14)]
    public async Task Missing_execution_bodies_refuse_before_file_or_target_access(int value)
    {
        var error = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthArchiveGenuineExecutionRunner.ExecuteAsync(
            "not-a-protected-path", (CurrentAuthArchiveGenuineExecutionCase)value, CancellationToken.None));
        Assert.Equal("current_auth_archive_genuine_execution_invalid", error.Code);
    }

    [Fact]
    public async Task Cancellation_stops_before_input_or_fixture_access()
    {
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CurrentAuthArchiveGenuineExecutionRunner.ExecuteAsync(
            "not-a-protected-path", CurrentAuthArchiveGenuineExecutionCase.NativeComplete, canceled.Token));
    }

    [Fact]
    public async Task Caller_object_cannot_mint_a_disposable_execution_capability()
    {
        var caller = new CallerOwnedIssuer();
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            CurrentAuthLocalSessionArchivePermit.GenuineExecutionCapability.AuthenticateAsync(caller, CancellationToken.None));
        Assert.False(caller.Invoked);
    }

    [Theory]
    [InlineData("wrong-family")]
    [InlineData("current-auth-archive-genuine-dual-helper-input-v1")]
    [InlineData("current-auth-archive-genuine-recovery-helper-input-v1")]
    public void Other_input_families_cannot_select_execution(string family)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineExecutionInputContract.Require(new(family, null!),
            CurrentAuthArchiveGenuineExecutionCase.NativeComplete));
    }

    [Theory]
    [InlineData("none")] [InlineData("phase")] [InlineData("case")] [InlineData("published-early")]
    [InlineData("phase-proof")] [InlineData("fabricated-os-exit")] [InlineData("actual-return")]
    [InlineData("backwards-clock")]
    public void Final_candidate_requires_actual_completed_method_and_incomplete_live_stage(string fault)
    {
        DateTimeOffset began = DateTimeOffset.UtcNow.AddMinutes(-1), ended = began.AddSeconds(20);
        var artifact = new CurrentAuthArchiveGenuineArtifact("stage", new string('a', 64));
        var method = new CurrentAuthArchiveGenuineExecutionMethodResult(0, began, ended.AddSeconds(1), new(artifact, began, ended));
        JsonObject stage = JsonSerializer.SerializeToNode(new
        {
            Kind = "current-auth-genuine-execution-incomplete-precleanup-v1", Phase = "native", CaseId = "complete",
            BeganAtUtc = began, EndedAtUtc = ended, CleanupVerified = false, PhaseProofComplete = false, ProviderExitCode = (int?)null,
        })!.AsObject();
        switch (fault)
        {
            case "none": break;
            case "phase": stage["Phase"] = "helper"; break;
            case "case": stage["CaseId"] = "exact-reviewed-delete"; break;
            case "published-early": stage["CleanupVerified"] = true; break;
            case "phase-proof": stage["PhaseProofComplete"] = true; break;
            case "fabricated-os-exit": stage["ProviderExitCode"] = 0; break;
            case "actual-return": method = method with { ReturnCode = 1 }; break;
            case "backwards-clock": method = method with { ReturnedAtUtc = began }; break;
        }
        JsonElement value = JsonSerializer.SerializeToElement(stage);
        if (fault == "none") { CurrentAuthArchiveGenuineExecutionRunner.RequireCompletedMethod(value, CurrentAuthArchiveGenuineExecutionCase.NativeComplete, method); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineExecutionRunner.RequireCompletedMethod(value, CurrentAuthArchiveGenuineExecutionCase.NativeComplete, method)); }
    }

    [Theory]
    [InlineData("none")] [InlineData("reservation-auth")] [InlineData("manifest-scope")]
    [InlineData("prepared-previous")] [InlineData("prepared-preimage")] [InlineData("terminal-previous")]
    [InlineData("receipt-signature")] [InlineData("missing-slot")] [InlineData("extra-slot")]
    public void Original_journal_bytes_must_have_exact_signatures_preimages_and_receipt_chain(string fault)
    {
        using var reviewKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var reviewer = new P256MigrationEvidenceSigner("journal-review", reviewKey.ExportPkcs8PrivateKeyPem());
        using var authorizer = new P256MigrationEvidenceSigner("journal-auth", authorizationKey.ExportPkcs8PrivateKeyPem());
        using var evidence = new P256MigrationEvidenceSigner("journal-evidence", evidenceKey.ExportPkcs8PrivateKeyPem());
        var pins = new CurrentAuthArchivePins(reviewer.KeyId, reviewer.PublicKeyFingerprintSha256, authorizer.KeyId,
            authorizer.PublicKeyFingerprintSha256, evidence.KeyId, evidence.PublicKeyFingerprintSha256);
        var trust = new ReceiptAttestationTrustStore([
            new(reviewer.KeyId, reviewKey.ExportSubjectPublicKeyInfo()), new(authorizer.KeyId, authorizationKey.ExportSubjectPublicKeyInfo()),
            new(evidence.KeyId, evidenceKey.ExportSubjectPublicKeyInfo()),
        ]);
        DateTimeOffset began = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var scope = CurrentAuthLocalSessionArchiveConsoleTests.Scope(began);
        var review = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReviewDomain, scope, reviewer);
        var authorization = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain,
            new CurrentAuthArchiveAuthorization(scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(review), began, began.AddMinutes(1)), authorizer);
        var claims = new CurrentAuthArchiveGenuineHelperClaims(review, authorization);
        string auth = CurrentAuthLocalSessionArchivePolicy.Hash(authorization), before = new('a', 64), after = new('b', 64);
        var manifest = new CurrentAuthArchiveRecoveryManifest(CurrentAuthLocalSessionArchivePolicy.Hash(scope), auth,
            new string('c', 64), new string('d', 64), new string('e', 64));
        var prepared = new CurrentAuthArchiveReceipt(scope.OperationId, auth, new string('0', 64), before, after,
            CurrentAuthLocalSessionArchivePolicy.Hash(manifest), CurrentAppOwnedCommitClassification.Prepared, began.AddSeconds(1));
        var preparedClaim = Receipt(prepared);
        var terminal = prepared with { PreviousSha256 = CurrentAuthLocalSessionArchivePolicy.Hash(preparedClaim),
            Classification = CurrentAppOwnedCommitClassification.CommittedAndReadback, ObservedAtUtc = began.AddSeconds(2) };
        var terminalClaim = Receipt(terminal);
        var journal = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["operation-start"] = JsonSerializer.SerializeToUtf8Bytes(new { Domain = "current-auth-session-archive-reservation-v1", scope.OperationId, AuthorizationSha256 = auth }),
            ["recovery-manifest"] = Manifest(manifest), ["prepared"] = JsonSerializer.SerializeToUtf8Bytes(preparedClaim),
            ["committed-readback"] = JsonSerializer.SerializeToUtf8Bytes(terminalClaim),
        };
        switch (fault)
        {
            case "none": break;
            case "reservation-auth": journal["operation-start"] = JsonSerializer.SerializeToUtf8Bytes(new
                { Domain = "current-auth-session-archive-reservation-v1", scope.OperationId, AuthorizationSha256 = new string('f', 64) }); break;
            case "manifest-scope": journal["recovery-manifest"] = Manifest(manifest with { ScopeSha256 = new string('f', 64) }); break;
            case "prepared-previous": journal["prepared"] = JsonSerializer.SerializeToUtf8Bytes(Receipt(prepared with { PreviousSha256 = new string('f', 64) })); break;
            case "prepared-preimage": journal["prepared"] = JsonSerializer.SerializeToUtf8Bytes(Receipt(prepared with { BeforeAuthSha256 = new string('f', 64) })); break;
            case "terminal-previous": journal["committed-readback"] = JsonSerializer.SerializeToUtf8Bytes(Receipt(terminal with { PreviousSha256 = new string('0', 64) })); break;
            case "receipt-signature": journal["committed-readback"] = JsonSerializer.SerializeToUtf8Bytes(terminalClaim with { SignatureBase64 = Convert.ToBase64String(new byte[64]) }); break;
            case "missing-slot": _ = journal.Remove("prepared"); break;
            case "extra-slot": journal.Add("failed-or-uncertain", journal["prepared"]); break;
        }
        if (fault == "none")
        {
            var receipts = CurrentAuthArchiveGenuineOwnedPair.RequireExecutionJournal(journal, scope, claims, terminal, before, after,
                began, began.AddSeconds(3), pins, trust);
            Assert.Equal(new[] { prepared, terminal }, receipts);
        }
        else
        {
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineOwnedPair.RequireExecutionJournal(journal, scope, claims,
                terminal, before, after, began, began.AddSeconds(3), pins, trust));
        }
        CurrentAuthArchiveClaim Receipt(CurrentAuthArchiveReceipt value) => CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReceiptDomain, value, evidence);
        byte[] Manifest(CurrentAuthArchiveRecoveryManifest value) => JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.RecoveryDomain, value, evidence));
    }

    private sealed class CallerOwnedIssuer
    {
        internal bool Invoked { get; private set; }
        internal Task<CurrentAuthArchiveGenuineExecutionAttestation> MintExecutionAsync(Guid id, CancellationToken ct)
        { Invoked = true; throw new InvalidOperationException(); }
    }
}
