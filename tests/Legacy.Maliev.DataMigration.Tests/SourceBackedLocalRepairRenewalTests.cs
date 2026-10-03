using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed partial class DisposableDeltaProofVerifierTests
{
    [Theory]
    [InlineData("success")]
    [InlineData("alternate-auth-key")]
    [InlineData("expired")]
    [InlineData("target")]
    [InlineData("applied-at-basis-zero")]
    [InlineData("original-generation")]
    [InlineData("terminal-key")]
    [InlineData("public-key")]
    [InlineData("signature")]
    [InlineData("overlong")]
    [InlineData("original-schema")]
    [InlineData("ordinal-gap")]
    [InlineData("reused-original-auth")]
    public async Task Renewal_policy_verifies_real_signatures_and_original_five_pinned_roles(string scenario)
    {
        AdmissionFixture state = await AdmissionState();
        var original = new SourceBackedLocalRepairOriginalAuthority(state.Admission, state.Capsule, state.Authorization,
            state.Plans, state.Fixture.ProofResult, state.Fixture.Schema, state.Pins, SourceRepairTerminalPin(),
            state.Fixture.Trust.ExportTrustedPublicKeys(SourceBackedLocalRepairRenewalPolicy.RelevantKeyIds(
                state.Admission, state.Capsule, state.Authorization, state.Plans, state.Fixture.ProofResult, SourceRepairTerminalPin())));
        using var alternate = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trust = new ReceiptAttestationTrustStore([.. original.PublicTrustMaterial,
            new("alternate-authorization", alternate.ExportSubjectPublicKeyInfo())]);
        using var authSigner = new P256MigrationEvidenceSigner("local-transition-authorization", _authorizationKey.ExportECPrivateKeyPem());
        DateTimeOffset now = state.Fixture.Now;
        PairedLocalTransitionAuthorization fresh = PairedLocalTransitionAuthorizationPolicy.Produce(state.Plans,
            state.Fixture.ProofResult, state.Fixture.Schema, trust, state.Plans.Persistent.TargetAuthority!,
            state.Plans.Persistent.TargetObservationSha256, state.Plans.Persistent.QuotationTransitionSchemaSha256!,
            now, now.AddMinutes(15), authSigner);
        if (scenario == "alternate-auth-key")
        {
            using var alternateSigner = new P256MigrationEvidenceSigner("alternate-authorization", alternate.ExportECPrivateKeyPem());
            fresh = fresh with { AttestationKeyId = alternateSigner.KeyId, AttestationSignature = null };
            fresh = fresh with
            {
                AttestationSignature = Convert.ToBase64String(alternateSigner.Sign(
                PairedLocalTransitionAuthorizationCanonicalizer.CreatePayload(fresh)))
            };
        }
        SourceBackedLocalRepairClaim claim = SourceBackedLocalRepairAdmissionPolicy.ExpectedClaim(state.Admission);
        SourceBackedLocalRepairState[] states = [.. claim.InitialMetadata.Select(item =>
            new SourceBackedLocalRepairState(item.Database, SourceBackedLocalRepairPhase.Prior, item.FingerprintSha256, null, null, null))];
        if (scenario == "applied-at-basis-zero")
        {
            states[0] = states[0] with
            {
                Phase = SourceBackedLocalRepairPhase.Applied,
                RepairMarkerSha256 = Hash('a'),
                CheckpointSha256 = Hash('b'),
                ReconciliationSha256 = Hash('c')
            };
        }
        var unsigned = new SourceBackedLocalRepairRenewalGrant("1.0", claim.ClaimId,
            SourceBackedLocalRepairRenewalPolicy.OriginalSha256(original), 1, claim.AdmissionSha256, claim.PreimageSha256,
            claim.SourceCaptureSha256, claim.FuturePlanSha256, 1, null, 0, claim.AdmissionSha256, states, fresh,
            scenario == "target" ? state.Identity with { ContainerId = Hash('f') } : state.Identity,
            now, now, now.AddMinutes(15), "proof-evidence", null);
        unsigned = scenario switch
        {
            "overlong" => unsigned with { ExpiresAtUtc = now.AddMinutes(16) },
            "ordinal-gap" => unsigned with { Counter = 2 },
            "reused-original-auth" => unsigned with { Authorization = state.Authorization },
            _ => unsigned,
        };
        using var signer = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        SourceBackedLocalRepairRenewalGrant signed = unsigned with
        { AttestationSignature = Convert.ToBase64String(signer.Sign(SourceBackedLocalRepairRenewalPolicy.Payload(unsigned))) };
        if (scenario == "signature") { signed = signed with { AttestationSignature = "forged" }; }
        if (scenario == "original-schema") { original = original with { Schema = original.Schema with { SourceCommitSha = Hash('f') } }; }
        if (scenario == "terminal-key") { original = original with { TerminalPin = original.TerminalPin with { PublicKeyFingerprintSha256 = Hash('f') } }; }
        if (scenario == "public-key")
        {
            original = original with
            {
                PublicTrustMaterial = [.. original.PublicTrustMaterial.Select((item, index) =>
            index == 0 ? item with { SubjectPublicKeyInfo = alternate.ExportSubjectPublicKeyInfo() } : item)]
            };
        }
        void Verify()
        {
            SourceBackedLocalRepairRenewalPolicy.Verify(signed, original,
            scenario == "original-generation" ? 2 : 1, claim, null, null, state.Plans, state.Fixture.ProofResult,
            state.Fixture.Schema, state.Identity, trust, state.Pins, scenario == "expired" ? now.AddMinutes(15) : now);
        }

        if (scenario == "success") { Verify(); }
        else { _ = Assert.Throws<DeltaExecutionException>(Verify); }
    }

    [Fact]
    public void Renewal_proofs_cannot_be_constructed_with_a_caller_token()
    {
        _ = Assert.Throws<DeltaExecutionException>(() => new SourceBackedLocalRepairMixedStateReader.RenewalObservation(
            new object(), "caller", null, [], null!, default));
        _ = Assert.Throws<DeltaExecutionException>(() => new SourceBackedLocalRepairRenewalStore.ActiveGrant(
            new object(), null!, null!, null!, null!, null!, null!, []));
        Assert.False(SourceBackedLocalRepairRenewalStore.ActiveGrant.AuthorizesExecution);
        Assert.False(SourceBackedLocalRepairRenewalGrant.AuthorizesExecution);
        Assert.False(SourceBackedLocalRepairOriginalAuthority.AuthorizesExecution);
    }

    [Theory]
    [InlineData("same-epoch")]
    [InlineData("other-claim")]
    [InlineData("nonconsecutive-epoch")]
    [InlineData("changed-authority")]
    public async Task Global_authorization_reservation_allows_only_exact_same_epoch_retry(string mutation)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var gateway = new AdmissionGateway(now);
        Guid authorization = Guid.NewGuid();
        Guid claim = Guid.NewGuid();
        DateTimeOffset expires = now.Add(ImmutableRolloverClaimStore.MaximumClaimAge);
        await MigrationAuthorizationReservation.ReserveAsync(gateway, authorization, claim, 1, Hash('a'), expires, CancellationToken.None);
        Task retry = MigrationAuthorizationReservation.ReserveAsync(gateway, authorization,
            mutation == "other-claim" ? Guid.NewGuid() : claim,
            mutation == "nonconsecutive-epoch" ? 3 : 1,
            mutation == "changed-authority" ? Hash('b') : Hash('a'), expires, CancellationToken.None);
        if (mutation == "same-epoch") { await retry; }
        else { _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => retry); }
        Assert.Equal(1, gateway.Count);
    }

    [Fact]
    public async Task Global_authorization_reservation_competing_claims_have_exactly_one_winner()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var gateway = new AdmissionGateway(now);
        Guid authorization = Guid.NewGuid();
        Task[] competing = [Run(Guid.NewGuid()), Run(Guid.NewGuid())];
        await Task.WhenAll(competing.Select(async task => { try { await task; } catch (DeltaExecutionException) { } }));
        _ = Assert.Single(competing, task => task.IsCompletedSuccessfully);
        _ = Assert.Single(competing, task => task.IsFaulted);
        Assert.Equal(1, gateway.Count);
        Task Run(Guid claim)
        {
            return MigrationAuthorizationReservation.ReserveAsync(gateway, authorization, claim, 1,
            Hash('a'), now.Add(ImmutableRolloverClaimStore.MaximumClaimAge), CancellationToken.None);
        }
    }

    [Fact]
    public async Task Native_actual_expiry_renewal_recovers_old_auth_commit_and_supersedes_fresh_prior_epoch()
    {
        await using MixedNativeFixture fixture = await CreateMixedNativeFixture(TimeSpan.FromSeconds(45));
        using var evidenceSigner = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        SourceBackedLocalRepairMixedStateReader.Observation prior = await fixture.Reader.ObserveAndAdvanceAsync(
            fixture.Bundle, fixture.Plans, fixture.Proof, fixture.Schema, fixture.Authorization, 0, evidenceSigner, CancellationToken.None);
        await fixture.ApplyNext(prior);
        // A real old-auth transaction committed, but ordinal2 publication was interrupted.
        TimeSpan untilExpired = fixture.Authorization.ExpiresAtUtc - DateTimeOffset.UtcNow;
        if (untilExpired > TimeSpan.Zero) { await Task.Delay(untilExpired.Add(TimeSpan.FromMilliseconds(20))); }
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => fixture.Reader.ObserveAndAdvanceAsync(fixture.Bundle,
            fixture.Plans, fixture.Proof, fixture.Schema, fixture.Authorization, 1, evidenceSigner, CancellationToken.None));
        using var authorizationSigner = new P256MigrationEvidenceSigner("local-transition-authorization", _authorizationKey.ExportECPrivateKeyPem());
        PairedLocalTransitionAuthorization fresh = ProduceFresh();
        SourceBackedLocalRepairRenewalStore.ActiveGrant first = await fixture.Reader.RenewAsync(fixture.Bundle,
            fixture.Plans, fixture.Proof, fixture.Schema, fresh, 1, 0, evidenceSigner, CancellationToken.None);
        Assert.Equal(1, first.Counter);
        Assert.Equal(SourceBackedLocalRepairPhase.Applied, first.SignedGrant.Databases[0].Phase);
        Assert.Equal(1, first.SignedGrant.BasisContinuationOrdinal);
        SourceBackedLocalRepairMixedStateReader.Observation recovered = await fixture.Reader.ObserveAndAdvanceAsync(fixture.Bundle,
            fixture.Plans, fixture.Proof, fixture.Schema, fresh, 1, evidenceSigner, CancellationToken.None, first);
        Assert.Equal(2, recovered.Continuation.Ordinal);
        Assert.NotEqual(fixture.Authorization.AuthorizationId, recovered.Continuation.AuthorizationId);
        Assert.Equal(fixture.Bundle.Admission.AuthorizationSha256,
            await LockedIssuerScalar(LockedIssuerDatabase(fixture.Connection, "ContactRequest"),
                "SELECT authorization_sha256 FROM legacy_migration_internal.delta_source_backed_repair;"));
        await fixture.ApplyNext(recovered);
        SourceBackedLocalRepairMixedStateReader.Observation secondApplied = await fixture.Reader.ObserveAndAdvanceAsync(fixture.Bundle,
            fixture.Plans, fixture.Proof, fixture.Schema, fresh, 2, evidenceSigner, CancellationToken.None, first);
        Assert.Equal(3, secondApplied.Continuation.Ordinal);
        PairedLocalTransitionAuthorization next = ProduceFresh();
        SourceBackedLocalRepairRenewalStore.ActiveGrant second = await fixture.Reader.RenewAsync(fixture.Bundle,
            fixture.Plans, fixture.Proof, fixture.Schema, next, 3, 1, evidenceSigner, CancellationToken.None);
        Assert.Equal(2, second.Counter);
        Assert.True(DateTimeOffset.UtcNow < fresh.ExpiresAtUtc);
        DeltaExecutionException stale = await Assert.ThrowsAsync<DeltaExecutionException>(() => fixture.ApplyNext(secondApplied));
        Assert.Equal("delta_source_repair_renewal_invalid", stale.Code);
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => fixture.Admissions.VerifyRetainedAsync(fixture.Bundle.Admission,
            fixture.Bundle.Capsule, fixture.Plans, fixture.Proof, fixture.Schema, fresh, first, CancellationToken.None));
        SourceBackedLocalRepairMixedStateReader.Observation current = await fixture.Reader.ObserveAndAdvanceAsync(fixture.Bundle,
            fixture.Plans, fixture.Proof, fixture.Schema, next, 3, evidenceSigner, CancellationToken.None, second);
        while (!current.IsTerminal)
        {
            await fixture.ApplyNext(current);
            current = await fixture.Reader.ObserveAndAdvanceAsync(fixture.Bundle, fixture.Plans, fixture.Proof,
                fixture.Schema, next, current.Continuation.Ordinal, evidenceSigner, CancellationToken.None, second);
        }
        Assert.Equal(24, current.Continuation.Ordinal);
        Assert.All(current.Continuation.Databases, item => Assert.Equal(SourceBackedLocalRepairPhase.Applied, item.Phase));
        Assert.Equal(fixture.Bundle.Admission.PreimageSha256, second.SignedGrant.PreimageSha256);
        Assert.Equal(fixture.Bundle.Admission.SourceCaptureSha256, second.SignedGrant.SourceCaptureSha256);
        Assert.Equal(fixture.Bundle.Admission.PersistentPlanSha256, second.SignedGrant.PersistentPlanSha256);
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => fixture.ApplyNext(current));

        PairedLocalTransitionAuthorization ProduceFresh()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            return PairedLocalTransitionAuthorizationPolicy.Produce(fixture.Plans, fixture.Proof, fixture.Schema,
                fixture.Trust, fixture.Plans.Persistent.TargetAuthority!, fixture.Plans.Persistent.TargetObservationSha256,
                fixture.Plans.Persistent.QuotationTransitionSchemaSha256!, now, now.AddMinutes(15), authorizationSigner);
        }
    }
}
