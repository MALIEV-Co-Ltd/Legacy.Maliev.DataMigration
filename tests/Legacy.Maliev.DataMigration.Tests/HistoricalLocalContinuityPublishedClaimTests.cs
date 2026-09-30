using System.Collections.Concurrent;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed partial class DisposableDeltaProofVerifierTests
{
    private static readonly JsonSerializerOptions PublishedWireOptions = new(JsonSerializerDefaults.Web);
    [Fact]
    public async Task Published_continuity_bundle_creates_one_authenticated_retained_claim()
    {
        PublishedClaimFixture data = await PublishedClaimAsync();
        string directory = Path.Combine(Path.GetTempPath(), "rollover-bundle-" + Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "issuance.json");
        try
        {
            await MigrationConsole.WriteNewJsonForTestsAsync(path, data.Issuance, CancellationToken.None);
            _ = await Assert.ThrowsAnyAsync<Exception>(() => MigrationConsole.WriteNewJsonForTestsAsync(
                path, data.Issuance, CancellationToken.None));
            HistoricalLocalContinuityIssuance published = JsonSerializer.Deserialize<HistoricalLocalContinuityIssuance>(
                await File.ReadAllTextAsync(path), PublishedWireOptions)!;
            // Admission happens later: the published comparison timestamp must not be regenerated.
            var gateway = new RetainedClaimGateway(data.Now.AddMinutes(1));
            var store = new ImmutableRolloverClaimStore(gateway);
            ImmutableRolloverClaim claim = await CreatePublishedClaimAsync(data, published, store,
                at: data.Now.AddMinutes(1));
            Assert.Equal(data.Issuance.Attestation.AttestationId, claim.ClaimId);
            Assert.Equal(23, claim.InitialMetadata.Count);
            Assert.False(ImmutableRolloverClaim.AuthorizesExecution);
            Assert.Equal(4, gateway.Count);
            ImmutableRolloverClaim authenticated = await store.ReadAuthenticatedAsync(claim.ClaimId,
                published.Attestation, data.Historical.LocalPlan, data.Receipt, data.Trust,
                data.Now.AddMinutes(2), CancellationToken.None);
            Assert.Equal(claim.ClaimId, authenticated.ClaimId);
            Assert.Equal(claim.InitialAttestationSha256, authenticated.InitialAttestationSha256);
            Assert.Equal("delta_rollover_claim_conflict", (await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                CreatePublishedClaimAsync(data, published, store, at: data.Now.AddMinutes(1)))).Code);
            Assert.Equal(4, gateway.Count);
        }
        finally
        {
            File.Delete(path);
            Directory.Delete(directory);
        }
    }

    [Theory]
    [InlineData("missing-review", "delta_historical_local_issuance_invalid")]
    [InlineData("changed-time", "delta_historical_local_issuance_invalid")]
    [InlineData("changed-review", "delta_historical_local_issuance_invalid")]
    [InlineData("changed-review-and-hash", "delta_historical_local_continuity_invalid")]
    [InlineData("changed-attestation-signature", "delta_historical_local_continuity_invalid")]
    [InlineData("changed-authorization-signature", "delta_paired_local_transition_authorization_invalid")]
    [InlineData("changed-authorization-id", "delta_historical_local_issuance_invalid")]
    [InlineData("expired-bundle", "delta_paired_local_transition_authorization_invalid")]
    [InlineData("untrusted-continuity", "delta_historical_local_issuance_invalid")]
    [InlineData("reused-continuity-role", "delta_historical_local_issuance_invalid")]
    [InlineData("changed-current-rows", "shadow_reconciliation_failed")]
    [InlineData("changed-current-identity", "delta_historical_local_current_target_invalid")]
    [InlineData("short-retention", "delta_rollover_claim_retention_invalid")]
    public async Task Published_continuity_bundle_rejects_invalid_evidence_without_active_claim(
        string mutation, string expectedCode)
    {
        PublishedClaimFixture data = await PublishedClaimAsync();
        JsonSerializerOptions options = PublishedWireOptions;
        HistoricalLocalContinuityIssuance published = JsonSerializer.Deserialize<HistoricalLocalContinuityIssuance>(
            JsonSerializer.Serialize(data.Issuance, options), options)!;
        HistoricalPairedLocalCurrentTargetReview review = published.CurrentTargetReview!;
        published = mutation switch
        {
            "missing-review" => JsonSerializer.Deserialize<HistoricalLocalContinuityIssuance>(
                JsonSerializer.Serialize(new { published.FutureAuthorization, published.Attestation }, options), options)!,
            "changed-time" => published with { CurrentTargetReview = review with { ComparedAtUtc = review.ComparedAtUtc.AddTicks(1) } },
            "changed-review" => published with { CurrentTargetReview = review with { DatabasesCompared = 22 } },
            "changed-review-and-hash" => published with
            {
                CurrentTargetReview = review with { ComparedAtUtc = review.ComparedAtUtc.AddTicks(1) },
                Attestation = published.Attestation with
                {
                    CurrentReviewSha256 = HistoricalLocalContinuityAttestationCanonicalizer.ComputeReviewSha256(
                        review with { ComparedAtUtc = review.ComparedAtUtc.AddTicks(1) }),
                },
            },
            "changed-attestation-signature" => published with { Attestation = published.Attestation with { AttestationSignature = "forged" } },
            "changed-authorization-signature" => published with { FutureAuthorization = published.FutureAuthorization with { AttestationSignature = "forged" } },
            "changed-authorization-id" => published with { FutureAuthorization = published.FutureAuthorization with { AuthorizationId = Guid.NewGuid() } },
            _ => published,
        };
        if (mutation == "reused-continuity-role")
        {
            using var reused = new P256MigrationEvidenceSigner("local-transition-authorization", _authorizationKey.ExportECPrivateKeyPem());
            HistoricalLocalContinuityAttestation unsigned = published.Attestation with
            {
                AttestationKeyId = reused.KeyId,
                AttestationSignature = null,
            };
            published = published with
            {
                Attestation = unsigned with
                {
                    AttestationSignature = Convert.ToBase64String(reused.Sign(
                        HistoricalLocalContinuityAttestationCanonicalizer.CreatePayload(unsigned))),
                },
            };
        }
        var gateway = new RetainedClaimGateway(data.Now)
        {
            Retention = mutation == "short-retention" ? TimeSpan.FromDays(7) : TimeSpan.FromDays(366),
        };
        var store = new ImmutableRolloverClaimStore(gateway);
        Exception failure = await Assert.ThrowsAnyAsync<Exception>(() => CreatePublishedClaimAsync(data,
            published, store,
            at: mutation == "expired-bundle" ? published.FutureAuthorization.ExpiresAtUtc : data.Now,
            trust: mutation == "untrusted-continuity" ? data.TrustWithoutContinuity : null,
            driftRows: mutation == "changed-current-rows", driftIdentity: mutation == "changed-current-identity",
            forbidObservation: mutation is "missing-review" or "changed-time" or "changed-review" or "changed-authorization-id"));
        Assert.Equal(expectedCode, failure switch
        {
            DeltaExecutionException typed => typed.Code,
            MigrationExecutionException typed => typed.Code,
            _ => failure.GetType().Name,
        });
        // Failed evidence checks never publish even a reservation; short-retention
        // storage can leave an immutable fail-closed reservation, but never active.
        Assert.False(gateway.Contains("claims/v1/active/" + published.Attestation.AttestationId.ToString("D")));
        if (mutation != "short-retention")
        {
            Assert.Equal(0, gateway.Count);
        }
    }

    private static Task<ImmutableRolloverClaim> CreatePublishedClaimAsync(PublishedClaimFixture data,
        HistoricalLocalContinuityIssuance issuance, ImmutableRolloverClaimStore store,
        DateTimeOffset? at = null, ReceiptAttestationTrustStore? trust = null,
        bool driftRows = false, bool driftIdentity = false, bool forbidObservation = false)
    {
        return HistoricalLocalContinuityClaimIssuer.CreateAsync(store, issuance,
            data.Historical.LocalPlan, data.Receipt, data.Historical.Schema,
            new(data.Future.ProofPlan, data.Future.LocalPlan), data.Future.ProofResult, data.Future.Schema,
            _ => forbidObservation ? throw new InvalidOperationException("Invalid bundle must reject before target observation.")
                : Task.FromResult(driftIdentity ? data.Observation with { SystemIdentifierSha256 = Hash('9') } : data.Observation),
            new CurrentEvidenceInspector(data.Historical.Schema, driftContent: driftRows),
            _ => Task.FromResult<IReadOnlyList<HistoricalLocalMetadataBinding>>(data.Metadata),
            trust ?? data.Trust, new FixedTime(at ?? data.Now), CancellationToken.None);
    }

    private async Task<PublishedClaimFixture> PublishedClaimAsync()
    {
        Fixture historical = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, historicalLocal: true);
        Exact23DeltaReconciliationResult receipt = await HistoricalReceiptAsync(historical);
        Fixture future = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, matchingInsertOperations: true, historicalLocal: true,
            futureDocker: true, at: historical.Now.AddDays(1));
        HistoricalCurrentLocalObservation observation = CurrentObservation(historical);
        HistoricalLocalMetadataBinding[] metadata = [.. DatabaseInventory.ActiveDatabases.Select(database =>
            new HistoricalLocalMetadataBinding(database, PairedLocalTransitionMetadataState.SettledPrior, Hash('f')))];
        using var authorizationSigner = new P256MigrationEvidenceSigner("local-transition-authorization", _authorizationKey.ExportECPrivateKeyPem());
        using var continuitySigner = new P256MigrationEvidenceSigner("continuity-review", _continuityKey.ExportECPrivateKeyPem());
        TrustedAttestationKey[] keys =
        [new(historical.LocalPlan.AttestationKeyId, _localPlanKey.ExportSubjectPublicKeyInfo()),
            new(receipt.AttestationKeyId, _evidenceKey.ExportSubjectPublicKeyInfo()),
            new(future.ProofPlan.AttestationKeyId, _planKey.ExportSubjectPublicKeyInfo()),
            new(authorizationSigner.KeyId, authorizationSigner.ExportSubjectPublicKeyInfo())];
        var withoutContinuity = new ReceiptAttestationTrustStore(keys);
        var trust = new ReceiptAttestationTrustStore([.. keys,
            new(continuitySigner.KeyId, continuitySigner.ExportSubjectPublicKeyInfo())]);
        DateTimeOffset now = future.Now.AddMinutes(1);
        HistoricalLocalContinuityIssuance issued = await HistoricalLocalContinuityIssuer.IssueAsync(
            historical.LocalPlan, receipt, historical.Schema, new(future.ProofPlan, future.LocalPlan),
            future.ProofResult, future.Schema, trust, _ => Task.FromResult(observation),
            new CurrentEvidenceInspector(historical.Schema),
            _ => Task.FromResult<IReadOnlyList<HistoricalLocalMetadataBinding>>(metadata),
            now.AddMinutes(10), authorizationSigner, continuitySigner, new FixedTime(now), CancellationToken.None);
        return new(historical, future, receipt, observation, metadata, issued, trust, withoutContinuity, now);
    }

    private sealed record PublishedClaimFixture(Fixture Historical, Fixture Future,
        Exact23DeltaReconciliationResult Receipt, HistoricalCurrentLocalObservation Observation,
        HistoricalLocalMetadataBinding[] Metadata, HistoricalLocalContinuityIssuance Issuance,
        ReceiptAttestationTrustStore Trust, ReceiptAttestationTrustStore TrustWithoutContinuity, DateTimeOffset Now);

    private sealed class RetainedClaimGateway(DateTimeOffset now) : IRolloverClaimObjectGateway
    {
        private readonly ConcurrentDictionary<string, RolloverClaimObject> _objects = new(StringComparer.Ordinal);
        private long _generation;
        internal int Count => _objects.Count;
        internal TimeSpan Retention { get; init; } = TimeSpan.FromDays(366);
        internal bool Contains(string name)
        {
            return _objects.ContainsKey(name);
        }

        public Task<RolloverClaimBucketPolicy> ReadPolicyAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(new RolloverClaimBucketPolicy(true, 31_557_600, true, false));
        }

        public Task<RolloverClaimObject> CreateOnlyAsync(string name, byte[] content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var value = new RolloverClaimObject(Interlocked.Increment(ref _generation), now, now.Add(Retention), [.. content]);
            return _objects.TryAdd(name, value) ? Task.FromResult(value)
                : throw new DeltaExecutionException("delta_rollover_claim_conflict", "Immutable claim already exists.");
        }

        public Task<RolloverClaimObject?> ReadAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _ = _objects.TryGetValue(name, out RolloverClaimObject? value);
            return Task.FromResult(value);
        }
    }
}
