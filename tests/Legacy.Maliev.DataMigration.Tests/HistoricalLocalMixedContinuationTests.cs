using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class HistoricalLocalMixedContinuationTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(22)]
    [InlineData(23)]
    public void Verify_Exact23MixedState_ReturnsNonAuthorizingReview(int adopted)
    {
        using Fixture fixture = new(adopted);
        HistoricalLocalMixedContinuationReview review = fixture.Verify();
        Assert.Equal(adopted, review.AdoptedDatabases);
        Assert.Equal(23 - adopted, review.PriorDatabases);
        Assert.False(HistoricalLocalMixedContinuation.AuthorizesExecution);
        Assert.False(HistoricalLocalMixedContinuationReview.AuthorizesExecution);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(22)]
    [InlineData(23)]
    public void Issue_FreshSignedExact23Continuation_ValidatesAtIssuance(int adopted)
    {
        using Fixture fixture = new(adopted);
        HistoricalLocalMixedContinuation issued = fixture.Issue();
        HistoricalLocalMixedContinuationReview review =
            HistoricalLocalMixedContinuationVerifier.Verify(issued, fixture.Claim,
                fixture.Observed, fixture.Authorization, fixture.Trust, fixture.Now);
        Assert.Equal(adopted, review.AdoptedDatabases);
        Assert.Equal(fixture.Authorization.ExpiresAtUtc, issued.ExpiresAtUtc);
        Assert.NotNull(issued.AttestationSignature);
    }

    [Fact]
    public void Verify_UnknownClaimOrReplayOrChangedGeneration_Rejects()
    {
        using Fixture fixture = new(1);
        Assert.Equal("delta_historical_local_mixed_continuation_invalid",
            Assert.Throws<DeltaExecutionException>(() => HistoricalLocalMixedContinuationVerifier.Verify(
                fixture.Continuation, null, fixture.Observed, fixture.Authorization,
                fixture.Trust, fixture.Now)).Code);
        fixture.Reject(claim: fixture.Claim with { ClaimId = Guid.NewGuid() });
        fixture.Reject(claim: fixture.Claim with { NextContinuationOrdinal = 2 });
        fixture.Reject(continuation: fixture.Sign(fixture.Continuation with
        {
            TargetGeneration = "docker:changed",
        }));
        fixture.Reject(observed: fixture.Observed.Select((state, index) =>
            index == 0 ? state with { AdoptionJournalSha256 = Hash('b') } : state).ToArray());
    }

    [Fact]
    public void Verify_ExpiredOrUntrustedAuthorizationAndTamperedEvidence_Rejects()
    {
        using Fixture fixture = new(22);
        fixture.Reject(at: fixture.Authorization.ExpiresAtUtc);
        fixture.Reject(authorization: fixture.Authorization with { AuthorizationId = Guid.NewGuid() });
        fixture.Reject(continuation: fixture.Continuation with { Databases = fixture.Observed[..^1] });
        fixture.Reject(continuation: fixture.Continuation with
        {
            AttestationSignature = Convert.ToBase64String(new byte[64]),
        });
        fixture.Reject(continuation: fixture.Sign(fixture.Continuation with
        {
            Databases = fixture.Observed[..^1],
        }));
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa _authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _continuationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly P256MigrationEvidenceSigner _authorizationSigner;
        private readonly P256MigrationEvidenceSigner _continuationSigner;

        public HistoricalLocalRolloverClaimSnapshot Claim { get; }
        public HistoricalLocalRolloverDatabaseState[] Observed { get; }
        public PairedLocalTransitionAuthorization Authorization { get; }
        public HistoricalLocalMixedContinuation Continuation { get; }

        public Fixture(int adopted)
        {
            _authorizationSigner = new("transition-authorization", _authorizationKey.ExportECPrivateKeyPem());
            _continuationSigner = new("mixed-continuation", _continuationKey.ExportECPrivateKeyPem());
            Trust = new ReceiptAttestationTrustStore(
                [new(_authorizationSigner.KeyId, _authorizationSigner.ExportSubjectPublicKeyInfo()),
                    new(_continuationSigner.KeyId, _continuationSigner.ExportSubjectPublicKeyInfo())]);
            HistoricalLocalMetadataBinding[] initial =
                [.. DatabaseInventory.ActiveDatabases.Select(database =>
                    new HistoricalLocalMetadataBinding(database,
                        PairedLocalTransitionMetadataState.SettledPrior, Hash('a')))];
            Claim = new(Guid.NewGuid(), Hash('1'), Hash('2'), "docker:target-generation", 1, initial);
            Observed = [.. DatabaseInventory.ActiveDatabases.Select((database, index) =>
                new HistoricalLocalRolloverDatabaseState(database,
                    index < adopted ? HistoricalLocalRolloverDatabasePhase.Adopted :
                        HistoricalLocalRolloverDatabasePhase.Prior,
                    Hash('a'), index < adopted ? Hash('c') : null))];
            var unsignedAuthorization = new PairedLocalTransitionAuthorization("1.0", Guid.NewGuid(),
                Guid.NewGuid(), Claim.FuturePlanSha256, Hash('3'), Hash('4'), Hash('5'),
                Hash('6'), new DeltaTargetAuthority(DeltaTargetAuthorityKind.LocalAspire,
                    "aspire://legacy-postgres-main-local/persistent-target", Hash('7')),
                Hash('8'), Now.AddMinutes(-1), Now.AddMinutes(10),
                _authorizationSigner.KeyId, null);
            Authorization = unsignedAuthorization with
            {
                AttestationSignature = Convert.ToBase64String(_authorizationSigner.Sign(
                    PairedLocalTransitionAuthorizationCanonicalizer.CreatePayload(unsignedAuthorization))),
            };
            Continuation = Sign(new HistoricalLocalMixedContinuation("1.0", Claim.ClaimId,
                Claim.InitialAttestationSha256, Claim.FuturePlanSha256, Claim.TargetGeneration,
                Authorization.AuthorizationId, 1, Observed, Now, Now.AddMinutes(5),
                _continuationSigner.KeyId, null));
        }

        public HistoricalLocalMixedContinuation Sign(HistoricalLocalMixedContinuation candidate)
        {
            return candidate with
            {
                AttestationSignature = Convert.ToBase64String(_continuationSigner.Sign(
                HistoricalLocalMixedContinuationCanonicalizer.CreatePayload(candidate))),
            };
        }

        public HistoricalLocalMixedContinuation Issue()
        {
            return HistoricalLocalMixedContinuationIssuer.Issue(Claim, Observed,
                Authorization, _continuationSigner, Trust, Now);
        }

        public HistoricalLocalMixedContinuationReview Verify()
        {
            return HistoricalLocalMixedContinuationVerifier.Verify(Continuation, Claim, Observed,
                Authorization, Trust, Now);
        }

        public ReceiptAttestationTrustStore Trust { get; }
        public DateTimeOffset Now { get; } = new(2026, 9, 28, 12, 0, 0, TimeSpan.Zero);

        public void Reject(HistoricalLocalRolloverClaimSnapshot? claim = default,
            HistoricalLocalMixedContinuation? continuation = default,
            IReadOnlyList<HistoricalLocalRolloverDatabaseState>? observed = default,
            PairedLocalTransitionAuthorization? authorization = default,
            DateTimeOffset? at = default)
        {
            Assert.Equal("delta_historical_local_mixed_continuation_invalid",
                Assert.Throws<DeltaExecutionException>(() => HistoricalLocalMixedContinuationVerifier.Verify(
                    continuation ?? Continuation, claim ?? Claim, observed ?? Observed,
                    authorization ?? Authorization, Trust, at ?? Now)).Code);
        }

        public void Dispose()
        {
            _authorizationSigner.Dispose();
            _continuationSigner.Dispose();
            _authorizationKey.Dispose();
            _continuationKey.Dispose();
        }
    }
}
