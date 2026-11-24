using System.Security.Cryptography;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ConsumerColumnBootstrapOperationalTests
{
    private static readonly IReadOnlyList<string> OwnedForwardQuota = Array.AsReadOnly(["Quotation"]);
    private static readonly IReadOnlyList<string> OwnedForwardCustomer = Array.AsReadOnly(["CustomerIdentity"]);
    [Fact]
    public void Owned_forward_characterization_has_only_the_fixed_Quotation_subset_and_no_persistent_target()
    {
        using var fixture = new Fixture();
        var scope = fixture.Scope with
        {
            Mode = ConsumerColumnBootstrapOperationalMode.OwnedForwardRecoveryCharacterization,
            PendingDatabases = OwnedForwardQuota,
            PreviouslyCompletedDatabaseSha256 = new Dictionary<string, string>(StringComparer.Ordinal) { ["CustomerIdentity"] = fixture.Scope.BeforeDatabaseSha256["CustomerIdentity"] },
            NativePreimages = fixture.Scope.NativePreimages.Where(pin => pin.Database == "Quotation").ToArray(),
        };
        ConsumerColumnBootstrapOperationalContract.RequireScope(scope, fixture.Source, fixture.Clock.GetUtcNow());
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapOperationalContract.RequireScope(scope with
        { Target = scope.Target with { Kind = DeltaTargetAuthorityKind.ProductionCloudNativePg } }, fixture.Source, fixture.Clock.GetUtcNow()));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapOperationalContract.RequireOperationSubset(scope with
        { PendingDatabases = ConsumerColumnBootstrapOperationalContract.Databases }));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapOperationalContract.RequireOperationSubset(scope with
        {
            PendingDatabases = OwnedForwardCustomer,
            PreviouslyCompletedDatabaseSha256 = new Dictionary<string, string>(StringComparer.Ordinal) { ["Quotation"] = fixture.Scope.BeforeDatabaseSha256["Quotation"] },
        }));
    }

    [Theory]
    [InlineData("CustomerIdentity", "Quotation")]
    [InlineData("Quotation", "CustomerIdentity")]
    public void Fresh_resume_scope_binds_pending_operand_and_exact_untouched_complement(string pending, string alreadyCorrect)
    {
        using var fixture = new Fixture();
        var scope = fixture.Scope with
        {
            Mode = ConsumerColumnBootstrapOperationalMode.PersistentReviewed,
            PendingDatabases = [pending],
            PreviouslyCompletedDatabaseSha256 = new Dictionary<string, string>(StringComparer.Ordinal)
            { [alreadyCorrect] = fixture.Scope.BeforeDatabaseSha256[alreadyCorrect] },
        };
        ConsumerColumnBootstrapOperationalContract.RequireOperationSubset(scope);
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapOperationalContract.RequireOperationSubset(
            scope with { PreviouslyCompletedDatabaseSha256 = new Dictionary<string, string>(StringComparer.Ordinal) }));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapOperationalContract.RequireOperationSubset(
            scope with { PreviouslyCompletedDatabaseSha256 = new Dictionary<string, string>(StringComparer.Ordinal) { [alreadyCorrect] = new string('0', 64) } }));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapOperationalContract.RequireOperationSubset(
            scope with { PendingDatabases = [pending, pending] }));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapOperationalContract.RequireOperationSubset(
            scope with { Mode = ConsumerColumnBootstrapOperationalMode.DisposableClosedProof }));
    }

    [Fact]
    public void Distinct_signed_scope_is_detached_without_granting_runtime_authority()
    {
        using var fixture = new Fixture();
        var review = fixture.Review(); var authorization = fixture.Authorize(review);
        ConsumerColumnBootstrapOperationalPermit.Validate(review, authorization, fixture.Source, fixture.Trust, fixture.Pins, fixture.Clock.GetUtcNow());
        var returned = ConsumerColumnBootstrapOperationalContract.Copy(authorization.Scope);
        ((Dictionary<string, string>)returned.BeforePhysicalSha256)["CustomerIdentity"] = new string('0', 64);
        Assert.Equal(fixture.Scope.BeforePhysicalSha256["CustomerIdentity"], authorization.Scope.BeforePhysicalSha256["CustomerIdentity"]);
    }

    [Fact]
    public async Task Persistent_scope_cannot_reach_environment_even_with_owner_signing_material()
    {
        using var fixture = new Fixture(); var review = fixture.Review();
        var persistent = review with { Scope = fixture.Scope with { Mode = ConsumerColumnBootstrapOperationalMode.PersistentReviewed } };
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapOperationalPermit.IssueReview(persistent.Scope, fixture.Source, fixture.Reviewer, fixture.Pins, fixture.Clock.GetUtcNow(), fixture.Clock.GetUtcNow().AddMinutes(5)));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => ConsumerColumnBootstrapOperationalPermit.AdmitAsync(persistent, persistent, fixture.Source, fixture.Trust, fixture.Pins, fixture.Environment, fixture.Clock, default));
        Assert.Equal(0, fixture.Environment.Calls);
    }

    [Theory]
    [InlineData("old-family")]
    [InlineData("nonce")]
    [InlineData("review-hash")]
    [InlineData("scope")]
    [InlineData("signature")]
    public void Authorization_cannot_substitute_another_family_review_or_scope(string fault)
    {
        using var fixture = new Fixture(); var review = fixture.Review(); var authorization = fixture.Authorize(review);
        authorization = fault switch
        {
            "old-family" => authorization with { Kind = "current-app-owned-v3-authorization-v1" },
            "nonce" => authorization with { Nonce = review.Nonce },
            "review-hash" => authorization with { ReviewSha256 = new string('0', 64) },
            "scope" => authorization with { Scope = fixture.Scope with { TargetGeneration = "unreviewed" } },
            _ => authorization with { Signature = "invalid-signature" },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapOperationalPermit.Validate(review, authorization, fixture.Source, fixture.Trust, fixture.Pins, fixture.Clock.GetUtcNow()));
    }

    [Fact]
    public async Task Arbitrary_environment_is_rejected_before_any_callback_even_with_system_clock()
    {
        using var fixture = new Fixture(); var review = fixture.Review(); var authorization = fixture.Authorize(review);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => ConsumerColumnBootstrapOperationalPermit.AdmitAsync(review, authorization, fixture.Source,
            fixture.Trust, fixture.Pins, fixture.Environment, TimeProvider.System, default));
        Assert.Equal(0, fixture.Environment.Calls);
    }

    [Fact]
    public void Expired_signed_authorization_is_rejected()
    {
        using var fixture = new Fixture(); var review = fixture.Review(); var authorization = fixture.Authorize(review);
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapOperationalPermit.Validate(review, authorization, fixture.Source,
            fixture.Trust, fixture.Pins, fixture.Clock.GetUtcNow().AddMinutes(16)));
    }

    [Theory]
    [InlineData(false, false, false, 3)]
    [InlineData(false, false, true, 2)]
    [InlineData(true, false, false, 4)]
    [InlineData(true, true, false, 4)]
    [InlineData(true, true, true, 4)]
    public void Commit_attempt_never_claims_rollback_or_definite_failure(bool started, bool acknowledged, bool rollback, int expected)
    {
        Assert.Equal((CurrentAppOwnedCommitClassification)expected, PostgreSqlConsumerColumnBootstrapRepair.ClassifyFailure(started, acknowledged, rollback));
    }

    [Fact]
    public async Task Failed_current_custody_fence_stops_before_reservation_or_database_access()
    {
        using var fixture = new Fixture(); var review = fixture.Review(); var authorization = fixture.Authorize(review); fixture.Environment.Fail = true;
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => ConsumerColumnBootstrapOperationalPermit.AdmitAsync(review, authorization, fixture.Source, fixture.Trust, fixture.Pins, fixture.Environment, fixture.Clock, default));
    }

    // Synthetic full-inventory metadata/unit observations only, never live source or runtime authority.
    private sealed class Fixture : IDisposable
    {
        internal FreshSchemaPlan Source { get; } = ConsumerColumnBootstrapTestData.Logical();
        internal TimeProvider Clock { get; } = new FixedClock();
        internal P256MigrationEvidenceSigner Reviewer { get; } = Signer("bootstrap-review");
        private P256MigrationEvidenceSigner Authorizer { get; } = Signer("bootstrap-authorization");
        private P256MigrationEvidenceSigner Receipt { get; } = Signer("bootstrap-receipt");
        internal CurrentAppOwnedRepairSigningPins Pins { get; }
        internal IReceiptAttestationTrustStore Trust { get; }
        internal ConsumerColumnBootstrapOperationalScope Scope { get; }
        internal FakeEnvironment Environment { get; }
        internal Fixture()
        {
            Pins = new(Reviewer.KeyId, Reviewer.PublicKeyFingerprintSha256, Authorizer.KeyId, Authorizer.PublicKeyFingerprintSha256, Receipt.KeyId, Receipt.PublicKeyFingerprintSha256);
            Trust = new ReceiptAttestationTrustStore([new(Reviewer.KeyId, Public(Reviewer)), new(Authorizer.KeyId, Public(Authorizer)), new(Receipt.KeyId, Public(Receipt))]);
            var contract = ConsumerColumnBootstrapContract.Create(Source, Source.SourceCommitSha, Clock.GetUtcNow());
            CurrentAppOwnedDatabaseSnapshot[] fleet = [.. DatabaseInventory.ActiveDatabases.Concat(["Auth", "legacy_local", "postgres"]).Order(StringComparer.Ordinal)
                .Select(x => new CurrentAppOwnedDatabaseSnapshot(x, [], [], []))];
            var hashes = fleet.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal); string h = new('a', 64); DateTimeOffset now = Clock.GetUtcNow();
            Scope = new(Guid.NewGuid(), ConsumerColumnBootstrapOperationalMode.DisposableClosedProof, Source.SourceCommitSha, contract.LogicalSourcePlanSha256, contract.ComputeSha256(),
                ConsumerColumnBootstrapOperationalContract.Databases.ToDictionary(x => x, x => contract.Before(x).TargetSchemaSha256, StringComparer.Ordinal),
                ConsumerColumnBootstrapOperationalContract.Databases.ToDictionary(x => x, x => contract.After(x).TargetSchemaSha256, StringComparer.Ordinal),
                new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/disposable-aaaaaaaaaaaa", h), "local-aspire", "legacy-postgres-main-local", h, h, h,
                hashes, ConsumerColumnBootstrapOperationalContract.FleetHash(hashes), h, h, h,
                new("synthetic_maintenance", "legacy-maliev-consumer-column-bootstrap-v1:" + h, now.AddMinutes(-1), now.AddHours(1), now.AddMinutes(-1), now.AddMinutes(-1), h, h, "/synthetic/hba"))
            {
                SourceIdentitySha256 = h,
                NativePreimages = ConsumerColumnBootstrapOperationalContract.Databases.Select(database => new ConsumerColumnBootstrapNativePreimagePin(database, h, 180004, string.Empty, 1, now,
                new(180004, 1, "UTF8", 8192, string.Empty, h, h, h))).ToArray()
            };
            Environment = new(fleet);
        }
        internal ConsumerColumnBootstrapOperationalClaim Review()
        {
            return ConsumerColumnBootstrapOperationalPermit.IssueReview(Scope, Source, Reviewer, Pins, Clock.GetUtcNow(), Clock.GetUtcNow().AddMinutes(10));
        }

        internal ConsumerColumnBootstrapOperationalClaim Authorize(ConsumerColumnBootstrapOperationalClaim review)
        {
            return ConsumerColumnBootstrapOperationalPermit.IssueAuthorization(review, Source, Trust, Pins, Authorizer, Clock.GetUtcNow());
        }

        private static P256MigrationEvidenceSigner Signer(string id) { using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); return new(id, key.ExportPkcs8PrivateKeyPem()); }
        private static byte[] Public(P256MigrationEvidenceSigner signer)
        {
            return signer.ExportSubjectPublicKeyInfo();
        }

        public void Dispose() { Reviewer.Dispose(); Authorizer.Dispose(); Receipt.Dispose(); }
    }
    private sealed class FixedClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return ConsumerColumnBootstrapTestData.Now;
        }
    }
    private sealed class FakeEnvironment(IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> fleet) : IConsumerColumnBootstrapOperationalEnvironment
    {
        internal int Calls { get; private set; }
        internal bool Fail { get; set; }
        private bool _reserved;
        public string ConnectionString => throw new InvalidOperationException("Unit test never opens a target.");
        public Task RequireScopeAsync(ConsumerColumnBootstrapOperationalScope scope, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Calls++; return Fail ? throw ConsumerColumnBootstrapOperationalContract.Invalid() : Task.CompletedTask;
        }
        public Task ReserveExecutionAsync(ConsumerColumnBootstrapOperationalScope scope, string authorizationSha256, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); if (_reserved) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); } _reserved = true; return Task.CompletedTask; }
        public Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> ObserveFleetAsync(ConsumerColumnBootstrapOperationalScope scope, CancellationToken ct)
        {
            return Task.FromResult(fleet);
        }

        public Task RequirePolicyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, ConsumerColumnBootstrapOperationalScope scope, CancellationToken ct)
        {
            throw new InvalidOperationException();
        }

        public Task<ConsumerColumnBootstrapProviderObservation> ObserveProviderAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
        {
            throw new InvalidOperationException();
        }

        public Task RetainReceiptAsync(ConsumerColumnBootstrapOperationalReceipt receipt, CancellationToken ct)
        {
            throw new InvalidOperationException();
        }

        public Task RetainRunReceiptAsync(ConsumerColumnBootstrapOperationalRunReceipt receipt, CancellationToken ct)
        {
            throw new InvalidOperationException();
        }

        public Task RetainNativeWitnessAsync(ConsumerColumnBootstrapNativePhase phase, ConsumerColumnBootstrapPreservationObservation observation, CancellationToken ct)
        {
            throw new InvalidOperationException();
        }
    }
}
