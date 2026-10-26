using System.Security.Cryptography;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Pure synthetic signing and binding operands only. No fixture, precursor, device or execution evidence is produced.
public sealed class CurrentAuthArchiveComponentBootstrapSubjectTests
{
    // Pure structural fixtures only. Their private signers/trust are disposed and runtime admission remains fenced.
    internal static CurrentAuthArchiveScope SyntheticScope(DateTimeOffset now)
    {
        using var fixture = new Fixture(now); return fixture.Scope;
    }

    [Fact]
    public async Task First_provider_preparation_cannot_contact_an_environment_or_enter_the_public_Console()
    {
        using var fixture = new Fixture();
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequireArchiveConsoleScope(fixture.Scope));
        MigrationConsole.RequireArchiveConsoleScope(CurrentAuthLocalSessionArchiveConsoleTests.Scope(fixture.Now));
        await fixture.RequireAdmissionFenceAsync();
    }
    [Fact]
    public void First_provider_bootstrap_explicitly_has_no_completed_archive_reports()
    {
        using var fixture = new Fixture();
        Assert.Equal(string.Empty, fixture.Scope.ArchiveHelperProofSha256);
        Assert.Equal(string.Empty, fixture.Scope.ArchiveNativeProofSha256);
        Assert.Equal(string.Empty, fixture.Scope.ExactDeleteReviewSha256);
        Assert.Equal(string.Empty, fixture.Scope.RecoveryReviewSha256);
        Assert.Equal(26, fixture.Scope.LocalObservationPolicy.BeforeDatabaseSha256.Count);
        Assert.Equal(49, fixture.Scope.ProductionObservationPolicy.BeforeDatabaseSha256.Count);
        CurrentAuthLocalSessionArchivePolicy.RequireScope(fixture.Scope, fixture.Now);
        fixture.RequireClaims(fixture.Scope);
        fixture.Require(fixture.Scope);
    }

    [Theory]
    [InlineData("helper")]
    [InlineData("native")]
    [InlineData("delete")]
    [InlineData("recovery")]
    public void Every_future_report_field_rejects_null_zero_or_hash_shaped_substitution(string field)
    {
        using var fixture = new Fixture();
        foreach (string? value in new string?[] { null, new('0', 64), new('a', 64), "not-a-report" })
        {
            var scope = field switch
            {
                "helper" => fixture.Scope with { ArchiveHelperProofSha256 = value! },
                "native" => fixture.Scope with { ArchiveNativeProofSha256 = value! },
                "delete" => fixture.Scope with { ExactDeleteReviewSha256 = value! },
                "recovery" => fixture.Scope with { RecoveryReviewSha256 = value! },
                _ => throw new InvalidOperationException(),
            };
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireScope(scope, fixture.Now));
            _ = Assert.Throws<MigrationExecutionException>(() => fixture.RequireClaims(scope));
            _ = Assert.Throws<MigrationExecutionException>(() => fixture.Require(scope));
        }
    }

    [Fact]
    public void Bootstrap_subject_is_required_and_cannot_be_attached_to_persistent_admission()
    {
        using var fixture = new Fixture();
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireScope(fixture.Scope with { ComponentSubject = null }, fixture.Now));
        var persistent = CurrentAuthLocalSessionArchiveConsoleTests.Scope(fixture.Now) with { ComponentSubject = fixture.Subject };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireScope(persistent, fixture.Now));
        _ = Assert.Throws<MigrationExecutionException>(() => fixture.Require(persistent));
    }

    [Theory]
    [InlineData("helper")]
    [InlineData("native")]
    [InlineData("delete")]
    [InlineData("recovery")]
    public void Persistent_admission_still_requires_every_completed_report_reference(string field)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var scope = CurrentAuthLocalSessionArchiveConsoleTests.Scope(now);
        scope = field switch
        {
            "helper" => scope with { ArchiveHelperProofSha256 = string.Empty },
            "native" => scope with { ArchiveNativeProofSha256 = string.Empty },
            "delete" => scope with { ExactDeleteReviewSha256 = string.Empty },
            "recovery" => scope with { RecoveryReviewSha256 = string.Empty },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireScope(scope, now));
    }

    [Theory]
    [InlineData("key")]
    [InlineData("fingerprint")]
    [InlineData("authorization-pin")]
    [InlineData("evidence-pin")]
    [InlineData("domain")]
    [InlineData("signature")]
    [InlineData("missing-signature")]
    public void Seed_is_authenticated_by_the_pinned_review_identity_and_fixed_domain(string fault)
    {
        using var fixture = new Fixture();
        var seed = fixture.Subject.Seed;
        var pins = fixture.Pins;
        if (fault == "key")
        {
            seed = seed with { KeyId = fixture.Authorization.KeyId };
            seed = seed with { Signature = Convert.ToBase64String(fixture.Authorization.Sign(CurrentAuthArchiveComponentBootstrap.SeedPayload(seed))) };
        }
        else if (fault == "fingerprint") { pins = pins with { ReviewFingerprint = fixture.Authorization.PublicKeyFingerprintSha256 }; }
        else if (fault == "authorization-pin") { pins = pins with { AuthorizationFingerprint = fixture.Review.PublicKeyFingerprintSha256 }; }
        else if (fault == "evidence-pin") { pins = pins with { EvidenceFingerprint = fixture.Review.PublicKeyFingerprintSha256 }; }
        else
        {
            seed = fault == "domain"
                ? (seed with { Signature = Convert.ToBase64String(fixture.Review.Sign("Legacy.Maliev.CurrentAuth.ComponentBootstrapSeed.v1\0wrong-domain"u8.ToArray())) })
                : (seed with { Signature = fault == "missing-signature" ? null : Convert.ToBase64String(new byte[64]) });
        }
        var subject = fixture.Subject with { Seed = seed };
        _ = Assert.Throws<MigrationExecutionException>(() => fixture.RequireClaims(fixture.Scope with { ComponentSubject = subject }, pins));
        _ = Assert.Throws<MigrationExecutionException>(() => fixture.Require(fixture.Scope with { ComponentSubject = subject }, subject, pins));
    }

    [Theory]
    [InlineData("source")]
    [InlineData("source-plan")]
    [InlineData("owner")]
    [InlineData("owner-pins")]
    [InlineData("closure")]
    [InlineData("parent")]
    [InlineData("test-image")]
    [InlineData("console-image")]
    [InlineData("core-image")]
    [InlineData("pins")]
    [InlineData("operation")]
    [InlineData("case")]
    [InlineData("expired")]
    [InlineData("future-issued")]
    public void Even_authentic_seed_cannot_change_accepted_source_images_parent_pins_or_operation(string fault)
    {
        using var fixture = new Fixture();
        var seed = fixture.Subject.Seed;
        seed = fault switch
        {
            "source" => seed with { AcceptedSourceCommitSha = new('0', 40) },
            "source-plan" => seed with { SourceSchemaPlanSha256 = new('0', 64) },
            "owner" => seed with { AuthOwnerCommitSha = new('0', 40) },
            "owner-pins" => seed with { OwnerPinsSha256 = new('0', 64) },
            "closure" => seed with { ClosureSha256 = new('0', 64) },
            "parent" => seed with { ParentRunBindingSha256 = new('0', 64) },
            "test-image" => seed with { TestAssemblySha256 = new('0', 64) },
            "console-image" => seed with { ConsoleAssemblySha256 = new('0', 64) },
            "core-image" => seed with { CoreAssemblySha256 = new('0', 64) },
            "pins" => seed with { SigningPinsSha256 = new('0', 64) },
            "operation" => seed with { OperationId = Guid.NewGuid() },
            "case" => seed with { CaseId = "callback" },
            "expired" => seed with { IssuedAtUtc = fixture.Now.AddMinutes(-6), ExpiresAtUtc = fixture.Now.AddSeconds(-1) },
            "future-issued" => seed with { IssuedAtUtc = fixture.Now.AddSeconds(1) },
            _ => throw new InvalidOperationException(),
        };
        var subject = fixture.Subject with { Seed = fixture.Sign(seed) };
        // The separately supplied observation carries the same seed, so rejection must bind the external accepted context.
        _ = Assert.Throws<MigrationExecutionException>(() => fixture.Require(fixture.Scope with { ComponentSubject = subject }, subject));
    }

    [Theory]
    [InlineData("swapped-pair")]
    [InlineData("reused-pair")]
    [InlineData("container")]
    [InlineData("volume")]
    [InlineData("target")]
    [InlineData("system")]
    [InlineData("fleet")]
    [InlineData("auth-before")]
    [InlineData("catalogs")]
    [InlineData("policy")]
    [InlineData("devices")]
    [InlineData("delete-set")]
    [InlineData("delete-count")]
    [InlineData("application")]
    [InlineData("paths")]
    public void Signed_scope_cannot_rebind_actual_pair_fleets_preimages_devices_or_delete_set(string fault)
    {
        using var fixture = new Fixture();
        var subject = fixture.Subject;
        subject = fault switch
        {
            "swapped-pair" => subject with { Local = subject.Comparison, Comparison = subject.Local },
            "reused-pair" => subject with { Comparison = subject.Local },
            "container" => subject with { Comparison = subject.Comparison with { ContainerId = new('0', 64) } },
            "volume" => subject with { Comparison = subject.Comparison with { VolumeName = subject.Local.VolumeName } },
            "target" => subject with { Comparison = subject.Comparison with { TargetObservationSha256 = new('0', 64) } },
            "system" => subject with { Comparison = subject.Comparison with { SystemIdentifierSha256 = new('0', 64) } },
            "fleet" => subject with { Comparison = subject.Comparison with { FleetBeforeSha256 = new('0', 64) } },
            "auth-before" => subject with { Local = subject.Local with { AuthBeforeSha256 = new('0', 64) } },
            "catalogs" => subject with { Comparison = subject.Comparison with { CatalogsSha256 = new('0', 64) } },
            "policy" => subject with { Comparison = subject.Comparison with { InstalledPolicySha256 = new('0', 64) } },
            "devices" => subject with { RecoveryDeviceProofSha256 = new('0', 64) },
            "delete-set" => subject with { DeleteSetSha256 = new('0', 64) },
            "delete-count" => subject with { DeleteCount = subject.DeleteCount + 1 },
            "application" => subject with { ApplicationComparisonSha256 = new('0', 64) },
            "paths" => subject with { RecoveryPathsSha256 = new('0', 64) },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(() => fixture.Require(fixture.Scope with { ComponentSubject = subject }));
    }

    [Fact]
    public void Seed_payload_is_domain_separated_and_excludes_only_its_signature()
    {
        using var fixture = new Fixture();
        var seed = fixture.Subject.Seed;
        byte[] payload = CurrentAuthArchiveComponentBootstrap.SeedPayload(seed);
        Assert.Equal(payload, CurrentAuthArchiveComponentBootstrap.SeedPayload(seed with { Signature = null }));
        Assert.NotEqual(payload, CurrentAuthArchiveComponentBootstrap.SeedPayload(seed with { DefinitionPrecursorSha256 = new('0', 64) }));
        Assert.NotEqual(payload, CurrentAuthArchiveComponentBootstrap.SeedPayload(seed with { PrecursorSubjectSha256 = new('0', 64) }));
        Assert.NotEqual(CurrentAuthComponentBootstrap.SeedPayload(new("synthetic-not-execution-evidence", new('a', 40), new('b', 64),
            ApprovedCurrentAuthSchema.AuthServiceCommit, CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256,
            new('c', 64), new('d', 64), new('e', 64), new('f', 64), new('1', 64), fixture.Now, fixture.Now.AddMinutes(1), "synthetic", null)), payload);
    }

    private sealed class Fixture : IDisposable
    {
        internal DateTimeOffset Now { get; }
        internal P256MigrationEvidenceSigner Review { get; } = Signer("synthetic-archive-review");
        internal P256MigrationEvidenceSigner Authorization { get; } = Signer("synthetic-archive-authorization");
        private P256MigrationEvidenceSigner Evidence { get; } = Signer("synthetic-archive-evidence");
        internal CurrentAuthArchivePins Pins { get; }
        internal CurrentAuthArchiveScope Scope { get; }
        internal CurrentAuthArchiveComponentBootstrapSubject Subject { get; }
        private ReceiptAttestationTrustStore Trust { get; }
        private const string Parent = "1111111111111111111111111111111111111111111111111111111111111111";
        private const string TestImage = "2222222222222222222222222222222222222222222222222222222222222222";
        private const string ConsoleImage = "3333333333333333333333333333333333333333333333333333333333333333";
        private const string CoreImage = "4444444444444444444444444444444444444444444444444444444444444444";

        internal Fixture(DateTimeOffset? now = null)
        {
            Now = now ?? DateTimeOffset.UtcNow;
            Pins = new(Review.KeyId, Review.PublicKeyFingerprintSha256, Authorization.KeyId, Authorization.PublicKeyFingerprintSha256,
                Evidence.KeyId, Evidence.PublicKeyFingerprintSha256);
            Trust = new([new(Review.KeyId, Review.ExportSubjectPublicKeyInfo()),
                new(Authorization.KeyId, Authorization.ExportSubjectPublicKeyInfo()), new(Evidence.KeyId, Evidence.ExportSubjectPublicKeyInfo())]);
            var scope = CurrentAuthLocalSessionArchiveConsoleTests.Scope(Now);
            var local = scope.LocalObservationPolicy with
            {
                Target = new(DeltaTargetAuthorityKind.LocalAspire,
                "aspire://legacy-postgres-main-local/disposable-aaaaaaaaaaaa", scope.LocalObservationPolicy.Target.SystemIdentifierSha256)
            };
            var comparison = scope.ProductionObservationPolicy with
            {
                Target = new(DeltaTargetAuthorityKind.LocalAspire,
                "aspire://legacy-postgres-main-local/disposable-bbbbbbbbbbbb", scope.ProductionObservationPolicy.Target.SystemIdentifierSha256)
            };
            scope = scope with
            {
                ProofAdmission = CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap,
                LocalObservationPolicy = local,
                ProductionObservationPolicy = comparison,
                ArchiveHelperProofSha256 = string.Empty,
                ArchiveNativeProofSha256 = string.Empty,
                ExactDeleteReviewSha256 = string.Empty,
                RecoveryReviewSha256 = string.Empty
            };
            var seed = Sign(new("current-auth-genuine-archive-component-seed-v1", scope.OperationId, "complete",
                local.SourceCommitSha, local.SourceSchemaPlanSha256, ApprovedCurrentAuthSchema.AuthServiceCommit,
                CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256,
                new('5', 64), new('6', 64), Parent, TestImage, ConsoleImage, CoreImage,
                CurrentAuthLocalSessionArchivePolicy.Hash(Pins), Now.AddSeconds(-1), Now.AddMinutes(4), Review.KeyId, null));
            Subject = new("current-auth-actual-paired-archive-component-subject-v1", seed, Target(local, false), Target(comparison, true),
                scope.RecoveryDeviceProofSha256, scope.DeleteSetSha256, scope.DeleteCount, scope.ApplicationComparisonSha256,
                CurrentAuthLocalSessionArchivePolicy.Hash(scope.Paths));
            Scope = scope with { ComponentSubject = Subject };
        }

        private static CurrentAuthArchiveComponentTargetSubject Target(CurrentAuthRepairScope policy, bool comparison)
        {
            string name = "legacy-delta-proof-" + policy.OperationId.ToString("N") + (comparison ? "-comparison" : string.Empty);
            return new(policy.RunBindingSha256, new(comparison ? 'b' : 'a', 64), name, name, "sha256:" + new string('7', 64),
                "/var/lib/postgresql/18/docker", policy.TargetGeneration, policy.TargetObservationSha256,
                new('8', 64), new('9', 64), policy.Target.SystemIdentifierSha256,
                policy.GlobalPreservationSha256, policy.BeforeDatabaseSha256["Auth"], new('a', 64), new('b', 64));
        }

        internal CurrentAuthArchiveComponentBootstrapSeed Sign(CurrentAuthArchiveComponentBootstrapSeed seed)
        {
            return seed with { Signature = Convert.ToBase64String(Review.Sign(CurrentAuthArchiveComponentBootstrap.SeedPayload(seed))) };
        }

        internal void Require(CurrentAuthArchiveScope scope, CurrentAuthArchiveComponentBootstrapSubject? observation = null, CurrentAuthArchivePins? pins = null)
        {
            CurrentAuthArchiveComponentBootstrap.RequireScope(scope, observation ?? Subject, Trust, pins ?? Pins,
                Scope.LocalObservationPolicy.SourceCommitSha, Scope.LocalObservationPolicy.SourceSchemaPlanSha256,
                Parent, TestImage, ConsoleImage, CoreImage, Now);
        }

        internal void RequireClaims(CurrentAuthArchiveScope scope, CurrentAuthArchivePins? pins = null)
        {
            CurrentAuthArchiveComponentBootstrap.RequireClaims(scope, Trust, pins ?? Pins, Now);
        }

        internal async Task RequireAdmissionFenceAsync()
        {
            var review = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReviewDomain, Scope, Review);
            var authorization = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain,
                new CurrentAuthArchiveAuthorization(Scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(review), Now, Scope.ExpiresAtUtc), Authorization);
            var environment = new UncontactedEnvironment();
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePermit.AdmitAsync(review, authorization,
                Trust, Pins, environment, TimeProvider.System, CancellationToken.None));
            Assert.Equal(0, environment.Calls);
        }

        private static P256MigrationEvidenceSigner Signer(string name)
        {
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return new(name, key.ExportPkcs8PrivateKeyPem());
        }

        public void Dispose() { Review.Dispose(); Authorization.Dispose(); Evidence.Dispose(); }
    }

    private sealed class UncontactedEnvironment : ICurrentAuthLocalSessionArchiveEnvironment
    {
        internal int Calls { get; private set; }
        private InvalidOperationException Contact() { Calls++; return new("Unexpected environment contact in a pure preparation test."); }
        public ICurrentAuthLocalSessionArchiveStorage RecoveryStorage => throw Contact();
        public Task RequireAcceptedSourceOwnerCustodyAndTargetsAsync(CurrentAuthArchiveScope scope, CancellationToken ct) { throw Contact(); }
        public Task<CurrentAuthArchiveFleet> CaptureLocalFleetAsync(CurrentAuthArchiveScope scope, CancellationToken ct) { throw Contact(); }
        public Task<CurrentAuthArchiveFleet> CaptureProductionFleetAsync(CurrentAuthArchiveScope scope, CancellationToken ct) { throw Contact(); }
        public Task ReserveCreateNewAsync(Guid operationId, string authorizationSha256, CancellationToken ct) { throw Contact(); }
        public Task RetainCreateNewAsync(string name, byte[] canonicalSignedBytes, CancellationToken ct) { throw Contact(); }
        public Task RetainRecoveryManifestAsync(byte[] canonicalSignedBytes, CancellationToken ct) { throw Contact(); }
    }
}
