using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentOwnerIsoRepairAdmissionTests
{
    private static readonly string[] ExpectedDatabases = ["Country", "Material"];
    [Theory]
    [InlineData("missing")]
    [InlineData("extra")]
    [InlineData("substituted")]
    [InlineData("case")]
    [InlineData("legacy-53")]
    public async Task Signed_unreviewed_production_inventory_rejects_before_callbacks(string fault)
    {
        using var f = new Fixture(production: true);
        var map = f.Scope.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        string shadow = map.Keys.First(x => x.StartsWith("legacy_shadow_", StringComparison.Ordinal));
        if (fault is "missing" or "substituted" or "case") { _ = map.Remove(shadow); }
        if (fault == "substituted") { map.Add("unreviewed_shadow", new('a', 64)); }
        if (fault == "case") { map.Add(shadow.ToUpperInvariant(), new('a', 64)); }
        if (fault == "extra") { map.Add("unreviewed", new('a', 64)); }
        if (fault == "legacy-53")
        {
            for (int i = 0; i < 4; i++) { map.Add("unreviewed_" + i, new('a', 64)); }
        }
        var (Review, Authorization) = f.Claims(f.Scope with { BeforeDatabaseSha256 = map });
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => f.Admit(Review, Authorization));
        Assert.Equal(0, f.Environment.SourceCalls);
        Assert.Equal(0, f.Environment.Reservations);
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Distinct_signed_iso_claims_admit_exact_complete_fleet_and_reserve_once(bool production)
    {
        using var f = new Fixture(production);
        CurrentOwnerIsoRepairSignedClaim review = await CurrentOwnerIsoRepairPermit.IssueReviewAsync(f.Scope, f.Source,
            f.Owners, f.Baseline, f.Trust, f.Pins, f.Environment, f.ReviewSigner, f.Now.AddHours(1), f.Clock, CancellationToken.None);
        CurrentOwnerIsoRepairSignedClaim authorization = await CurrentOwnerIsoRepairPermit.AuthorizeAsync(review, f.Source,
            f.Owners, f.Trust, f.Pins, f.Environment, f.AuthorizationSigner, f.Clock, CancellationToken.None);
        Assert.NotEqual(review.Nonce, authorization.Nonce);
        Assert.Equal(f.Now.AddMinutes(15), authorization.ExpiresAtUtc);
        var permit = await f.Admit(review, authorization);
        await permit.BeginExecutionAsync(CancellationToken.None);
        Assert.Equal(1, f.Environment.Reservations);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.BeginExecutionAsync(CancellationToken.None));
        await permit.ClaimDatabaseAsync("Country", new('0', 64), CancellationToken.None);
        permit.CompleteDatabase("Country", new('a', 64));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.ClaimDatabaseAsync("Material", new('0', 64), CancellationToken.None));
        await permit.ClaimDatabaseAsync("Material", new('a', 64), CancellationToken.None);
        permit.CompleteDatabase("Material", new('b', 64));
        permit.Stop();
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireExecutionAsync(CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => f.Admit(review, authorization));
    }

    [Theory]
    [InlineData("operation")]
    [InlineData("contract")]
    [InlineData("sql")]
    [InlineData("source")]
    [InlineData("owners")]
    [InlineData("fleet")]
    [InlineData("target")]
    [InlineData("role-comment")]
    [InlineData("recovery")]
    [InlineData("native-proof")]
    public void Even_genuine_signatures_do_not_admit_changed_fixed_scope(string fault)
    {
        using var f = new Fixture();
        var scope = fault switch
        {
            "operation" => f.Scope with { Operation = 0 },
            "contract" => f.Scope with { ContractSha256 = new('f', 64) },
            "sql" => f.Scope with { OperationSha256 = new('f', 64) },
            "source" => f.Scope with { BeforeSchemaPlanSha256 = new('f', 64) },
            "owners" => f.Scope with { OwnerSourcesSha256 = new('f', 64) },
            "fleet" => f.Scope with { BeforeDatabaseSha256 = f.Scope.BeforeDatabaseSha256.Where(x => x.Key != "Auth").ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal) },
            "target" => f.Scope with { TargetNamespace = "maliev" },
            "role-comment" => f.Scope with { Maintenance = f.Scope.Maintenance with { RoleComment = "legacy-maliev-current-app-owned-eight-v1:" + f.Scope.RunBindingSha256 } },
            "recovery" => f.Scope with { RecoveryPolicy = "replay-old-receipts" },
            _ => f.Scope with { NativeProofSha256 = string.Empty },
        };
        var (Review, Authorization) = f.Claims(scope);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoRepairPermit.ValidateClaims(Review,
            Authorization, f.Source, f.Owners, f.Trust, f.Pins, f.Now));
    }

    [Theory]
    [InlineData("expired")]
    [InlineData("old-domain")]
    [InlineData("unlinked")]
    [InlineData("nonce")]
    [InlineData("signature")]
    public void Expired_foreign_unlinked_or_forged_authority_rejects_before_environment(string fault)
    {
        using var f = new Fixture();
        var (Review, Authorization) = f.Claims(f.Scope);
        var authorization = Authorization;
        authorization = fault switch
        {
            "expired" => authorization with { IssuedAtUtc = f.Now.AddMinutes(-16), ExpiresAtUtc = f.Now },
            "old-domain" => authorization with { Kind = "current-app-owned-retained31-authorization-v1" },
            "unlinked" => authorization with { ReviewSha256 = new('f', 64) },
            "nonce" => authorization with { Nonce = Review.Nonce },
            _ => authorization with { Signature = "invalid-base64" },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoRepairPermit.ValidateClaims(Review,
            authorization, f.Source, f.Owners, f.Trust, f.Pins, f.Now));
        Assert.Equal(0, f.Environment.SourceCalls);
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("custody")]
    [InlineData("fleet")]
    public async Task Closed_evidence_requirements_cannot_be_replaced_by_hash_markers(string fault)
    {
        using var f = new Fixture();
        f.Environment.RejectOwner = fault == "owner";
        f.Environment.RejectCustody = fault == "custody";
        f.Environment.WrongGlobal = fault == "fleet";
        var (Review, Authorization) = f.Claims(f.Scope);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => f.Admit(Review, Authorization));
        Assert.Equal(0, f.Environment.Reservations);
    }

    [Fact]
    public async Task Unknown_reservation_ack_stops_without_erasing_reservation()
    {
        using var f = new Fixture();
        var (Review, Authorization) = f.Claims(f.Scope);
        var permit = await f.Admit(Review, Authorization);
        f.Environment.LoseReservationAck = true;
        _ = await Assert.ThrowsAsync<IOException>(() => permit.BeginExecutionAsync(CancellationToken.None));
        Assert.True(f.Environment.Reserved);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.BeginExecutionAsync(CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => f.Admit(Review, Authorization));
        Assert.Equal(1, f.Environment.Reservations);
    }

    [Fact]
    public async Task Permit_defensively_copies_signed_owner_and_fleet_inputs()
    {
        using var f = new Fixture();
        var (Review, Authorization) = f.Claims(f.Scope);
        var permit = await f.Admit(Review, Authorization);
        ((Dictionary<string, string>)f.Owners[0].Files).Clear();
        ((Dictionary<string, string>)permit.Scope.BeforeDatabaseSha256).Clear();
        await permit.RequireAsync(CancellationToken.None);
        Assert.Equal(26, permit.Scope.BeforeDatabaseSha256.Count);
    }

    [Theory]
    [InlineData((int)CurrentAppOwnedCommitClassification.Prepared)]
    [InlineData((int)CurrentAppOwnedCommitClassification.CommittedAndReadback)]
    [InlineData((int)CurrentAppOwnedCommitClassification.RolledBackBeforeCommit)]
    [InlineData((int)CurrentAppOwnedCommitClassification.FailedBeforeCommit)]
    [InlineData((int)CurrentAppOwnedCommitClassification.Uncertain)]
    public void Authentic_late_receipts_are_evidence_not_extended_permission(int classification)
    {
        using var f = new Fixture();
        var receipt = f.Receipt((CurrentAppOwnedCommitClassification)classification);
        PostgreSqlCurrentOwnerIsoRepair.RequireReceipt(receipt, f.Scope, new('b', 64), f.Trust, f.Pins);
        var (Review, Authorization) = f.Claims(f.Scope);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoRepairPermit.ValidateClaims(Review,
            Authorization, f.Source, f.Owners, f.Trust, f.Pins, f.Now.AddHours(3)));
        _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlCurrentOwnerIsoRepair.RequireReceipt(
            receipt with { Kind = "current-app-owned-retained31-receipt-v1" }, f.Scope, new('b', 64), f.Trust, f.Pins));
        _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlCurrentOwnerIsoRepair.RequireReceipt(
            receipt with { Database = "Customer" }, f.Scope, new('b', 64), f.Trust, f.Pins));
        _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlCurrentOwnerIsoRepair.RequireReceipt(
            receipt with { Classification = (CurrentAppOwnedCommitClassification)999 }, f.Scope, new('b', 64), f.Trust, f.Pins));
    }

    [Fact]
    public void Literal_operation_is_fixed_same_width_rpad_and_preserves_database_order_exports()
    {
        Assert.Contains("USING rpad(\"ISO2\"::text,2,' ')", PostgreSqlCurrentOwnerIsoRepair.Sql, StringComparison.Ordinal);
        Assert.Contains("USING rpad(\"ISO3\"::text,3,' ')", PostgreSqlCurrentOwnerIsoRepair.Sql, StringComparison.Ordinal);
        Assert.DoesNotContain("DROP", PostgreSqlCurrentOwnerIsoRepair.Sql, StringComparison.Ordinal);
        Assert.DoesNotContain("TRUNCATE", PostgreSqlCurrentOwnerIsoRepair.Sql, StringComparison.Ordinal);
        string[] returned = PostgreSqlCurrentOwnerIsoRepair.Databases(); returned[0] = "Customer";
        Assert.Equal(ExpectedDatabases, PostgreSqlCurrentOwnerIsoRepair.Databases());
        Assert.Equal(64, PostgreSqlCurrentOwnerIsoRepair.OperationSha256.Length);
    }

    [Theory]
    [InlineData("catalog")]
    [InlineData("helper")]
    [InlineData("proof")]
    [InlineData("aliased-proof")]
    public async Task Genuine_signatures_cannot_omit_or_substitute_distinct_source_and_maintenance_bindings(string fault)
    {
        using var fixture = new Fixture();
        CurrentOwnerIsoRepairScope scope = fault switch
        {
            "catalog" => fixture.Scope with { SourceCatalogSha256 = "" },
            "helper" => fixture.Scope with { MaintenanceValidatorSha256 = new('f', 64) },
            "proof" => fixture.Scope with { MaintenanceProofSha256 = "" },
            _ => fixture.Scope with { MaintenanceProofSha256 = fixture.Scope.NativeProofSha256 },
        };
        var (Review, Authorization) = fixture.Claims(scope);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => fixture.Admit(Review, Authorization));
        Assert.Equal(0, fixture.Environment.SourceCalls);
        Assert.Equal(0, fixture.Environment.Reservations);
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Re_signed_disposable_bootstrap_cannot_target_persistent_local_or_production(bool production)
    {
        using var fixture = new Fixture(production);
        var (Review, Authorization) = fixture.Claims(fixture.Scope with { ProofAdmission = CurrentOwnerIsoProofAdmission.DisposableNativeBootstrap });
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => fixture.Admit(Review, Authorization));
        Assert.Equal(0, fixture.Environment.SourceCalls);
        Assert.Equal(0, fixture.Environment.Reservations);
    }
    [Fact]
    public async Task Explicit_operand_owner_policy_uses_v2_and_omitted_null_preserves_local_v1()
    {
        using var f = new Fixture();
        Assert.DoesNotContain("OwnerPolicySha256", JsonSerializer.Serialize(f.Scope), StringComparison.Ordinal);
        CurrentOwnerIsoRepairScope scope = f.Scope with { OwnerPolicySha256 = CurrentOwnerIsoNativePreservation.OwnerPolicySha256(f.Scope.Target) };
        var (Review, Authorization) = f.Claims(scope);
        Assert.Equal("current-owner-iso-review-v2", Review.Kind);
        Assert.Equal("current-owner-iso-authorization-v2", Authorization.Kind);
        _ = await f.Admit(Review, Authorization);
        Assert.True(f.Environment.SourceCalls > 0);
    }

    [Theory]
    [InlineData("wrong-purpose")]
    [InlineData("wrong-system")]
    [InlineData("missing-production-policy")]
    [InlineData("legacy-claim-domain")]
    [InlineData("legacy-payload-domain")]
    public async Task Legitimately_signed_owner_substitution_or_old_domain_fails_before_callbacks(string fault)
    {
        using var f = new Fixture(production: true);
        CurrentOwnerIsoRepairScope scope = fault switch
        {
            "wrong-purpose" => f.Scope with { OwnerPolicySha256 = CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, f.Scope.Target) },
            "wrong-system" => f.Scope with { OwnerPolicySha256 = CurrentOwnerIsoNativePreservation.OwnerPolicySha256(f.Scope.Target with { SystemIdentifierSha256 = new string('0', 64) }) },
            "missing-production-policy" => f.Scope with { OwnerPolicySha256 = null },
            _ => f.Scope,
        };
        var (Review, Authorization) = f.Claims(scope, legacyKind: fault == "legacy-claim-domain", legacyPayload: fault == "legacy-payload-domain");
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => f.Admit(Review, Authorization));
        Assert.Equal(0, f.Environment.SourceCalls);
        Assert.Equal(0, f.Environment.Reservations);
    }

    [Fact]
    public void Country_and_material_country_policies_are_closed_and_bind_actual_target_system()
    {
        using var f = new Fixture(production: true);
        Assert.Equal("legacy_country_owner", CurrentRepairOperandOwnerProfile.ExpectedOwnerName(CurrentRepairOperandOwnerPurpose.CountryIsoLiteral, f.Scope.Target));
        Assert.Equal("legacy_material_owner", CurrentRepairOperandOwnerProfile.ExpectedOwnerName(CurrentRepairOperandOwnerPurpose.MaterialCountryIsoLiteral, f.Scope.Target));
        Assert.NotEqual(CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.CountryIsoLiteral, f.Scope.Target),
            CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.MaterialCountryIsoLiteral, f.Scope.Target));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentRepairOperandOwnerProfile.ExpectedOwnerName((CurrentRepairOperandOwnerPurpose)99, f.Scope.Target));
    }

    // Pure admission test seam only. These callbacks authenticate no real source/custody/native fleet.
    private sealed class Evidence(string global) : ICurrentOwnerIsoRepairEnvironment
    {
        internal bool Reserved, LoseReservationAck, RejectOwner, RejectCustody, WrongGlobal;
        internal int Reservations, SourceCalls;
        public Task RequireSourceAsync(string sourceCommitSha, CancellationToken cancellationToken)
        { SourceCalls++; return Task.CompletedTask; }
        public Task RequireOwnerSourcesAsync(string evidenceSha256, CancellationToken cancellationToken)
        {
            return RejectOwner ? throw CurrentOwnerIsoRepairPermit.Invalid() : Task.CompletedTask;
        }

        public Task RequireResourceAndCustodyAsync(CurrentOwnerIsoRepairScope scope, CancellationToken cancellationToken)
        {
            return RejectCustody ? throw CurrentOwnerIsoRepairPermit.Invalid() : Task.CompletedTask;
        }

        public Task<string> InspectGlobalPreservationAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(WrongGlobal ? "marker" : global);
        }

        public Task RequireFreshOperationAsync(CurrentOwnerIsoRepairScope scope, CancellationToken cancellationToken)
        {
            return Reserved ? throw CurrentOwnerIsoRepairPermit.Invalid() : Task.CompletedTask;
        }

        public Task ReserveFreshOperationAsync(CurrentOwnerIsoRepairScope scope, string authorizationSha256, CancellationToken cancellationToken)
        {
            if (Reserved) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            Reserved = true; Reservations++;
            return LoseReservationAck ? Task.FromException(new IOException("synthetic lost reservation acknowledgement")) : Task.CompletedTask;
        }
        public Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task ObserveCommittedDatabaseAsync(CurrentOwnerIsoRepairReceipt prepared, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }

    private sealed class Fixture : IDisposable
    {
        internal DateTimeOffset Now { get; } = ApprovedCurrentOwnerIsoOverlayTests.Now;
        internal TimeProvider Clock { get; }
        internal FreshSchemaPlan Source { get; } = ApprovedCurrentOwnerIsoOverlayTests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2);
        internal CurrentOwnerIsoSourceObservation[] Owners { get; } = ApprovedCurrentOwnerIsoOverlayTests.Owners();
        internal CurrentAppOwnedDatabaseSnapshot[] Baseline { get; }
        internal CurrentOwnerIsoRepairScope Scope { get; }
        internal ReceiptAttestationTrustStore Trust { get; }
        internal CurrentOwnerIsoRepairSigningPins Pins { get; }
        internal Evidence Environment { get; }
        internal P256MigrationEvidenceSigner ReviewSigner { get; }
        internal P256MigrationEvidenceSigner AuthorizationSigner { get; }
        private readonly ECDsa _receipt = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        internal Fixture(bool production = false)
        {
            Clock = new Clock(Now);
            using ECDsa review = ECDsa.Create(ECCurve.NamedCurves.nistP256), authorization = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            ReviewSigner = new("iso-review", review.ExportPkcs8PrivateKeyPem());
            AuthorizationSigner = new("iso-authorization", authorization.ExportPkcs8PrivateKeyPem());
            Trust = new([new(ReviewSigner.KeyId, review.ExportSubjectPublicKeyInfo()),
                new(AuthorizationSigner.KeyId, authorization.ExportSubjectPublicKeyInfo()), new("iso-receipt", _receipt.ExportSubjectPublicKeyInfo())]);
            _ = Trust.TryGetPublicKeyFingerprintSha256(ReviewSigner.KeyId, out string rf);
            _ = Trust.TryGetPublicKeyFingerprintSha256(AuthorizationSigner.KeyId, out string af);
            _ = Trust.TryGetPublicKeyFingerprintSha256("iso-receipt", out string ef);
            Pins = new(ReviewSigner.KeyId, rf, AuthorizationSigner.KeyId, af, "iso-receipt", ef);
            string[] names = production ? [.. ReviewedProductionRepairInventory.ExportProductionNames()] : [.. DatabaseInventory.ActiveDatabases, "Auth", "postgres", "legacy_local"];
            Baseline = [.. names.Order(StringComparer.Ordinal).Select(database => new CurrentAppOwnedDatabaseSnapshot(database,
                [new("pg_class", "1", new('a', 64), "1259", "1")],
                [new("legacy_migration_internal", "journal", 2, new('b', 64))],
                [new("public", "retained_sequence", "fixture", new('c', 64))]))];
            string binding = new('d', 64), global = CurrentAppOwnedSnapshotSerialization.Sha256(Baseline);
            Scope = new(Guid.NewGuid(), CurrentOwnerIsoSelection.LiteralWidthV1, Source.SourceCommitSha,
                SchemaPlanCanonicalizer.ComputeSha256(Source), CurrentAppOwnedSnapshotSerialization.Sha256(Owners),
                ApprovedCurrentOwnerIsoOverlay.Create(Source, Source.SourceCommitSha, CurrentOwnerIsoSelection.LiteralWidthV1, Owners, Now).ComputeSha256(),
                PostgreSqlCurrentOwnerIsoRepair.OperationSha256,
                new(production ? DeltaTargetAuthorityKind.ProductionCloudNativePg : DeltaTargetAuthorityKind.LocalAspire,
                    production ? "gke://maliev-website/iso-fixture" : "aspire://legacy-postgres-main-local/persistent-fixture", new('e', 64)),
                production ? "maliev-legacy" : "local-aspire", production ? "legacy-postgres-main" : "legacy-postgres-main-local",
                "fixture-generation", new('f', 64), binding,
                Baseline.ToDictionary(x => x.Database, x => CurrentAppOwnedSnapshotSerialization.Sha256(x), StringComparer.Ordinal),
                global, new('a', 64), new('b', 64), new('c', 64),
                new("iso_operator", "legacy-maliev-current-owner-iso-v1:" + binding, Now, Now.AddHours(2), Now, Now,
                    new('a', 64), new('b', 64), "/fixture/pg_hba.conf"), CurrentOwnerIsoRepairPermit.FreshOnlyPolicy,
                new('1', 64), CurrentOwnerIsoRepairPermit.MaintenanceValidator, new('2', 64));
            if (production) { Scope = Scope with { OwnerPolicySha256 = CurrentOwnerIsoNativePreservation.OwnerPolicySha256(Scope.Target) }; }
            Environment = new(global);
        }
        internal (CurrentOwnerIsoRepairSignedClaim Review, CurrentOwnerIsoRepairSignedClaim Authorization) Claims(CurrentOwnerIsoRepairScope scope, bool legacyKind = false, bool legacyPayload = false)
        {
            string version = scope.OwnerPolicySha256 is null || legacyKind ? "1" : "2";
            var review = Sign(new("current-owner-iso-review-v" + version, scope, Guid.NewGuid(), null, Now, Now.AddHours(1), ReviewSigner.KeyId, null), ReviewSigner, legacyPayload);
            var authorization = Sign(new("current-owner-iso-authorization-v" + version, scope, Guid.NewGuid(),
                CurrentAppOwnedSnapshotSerialization.Sha256(review), Now, Now.AddMinutes(15), AuthorizationSigner.KeyId, null), AuthorizationSigner, legacyPayload);
            return (review, authorization);
        }
        internal Task<CurrentOwnerIsoRepairPermit> Admit(CurrentOwnerIsoRepairSignedClaim review, CurrentOwnerIsoRepairSignedClaim authorization)
        {
            return CurrentOwnerIsoRepairPermit.AdmitAsync(review, authorization, Source, Owners, Trust, Pins, Environment, Clock, CancellationToken.None);
        }

        private static CurrentOwnerIsoRepairSignedClaim Sign(CurrentOwnerIsoRepairSignedClaim value, P256MigrationEvidenceSigner signer, bool legacyPayload = false)
        {
            byte[] payload = legacyPayload
                ? [.. "Legacy.Maliev.CurrentOwnerIsoRepair.Claim.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(value with { Signature = null })]
                : CurrentOwnerIsoRepairPermit.Payload(value);
            return value with { Signature = Convert.ToBase64String(signer.Sign(payload)) };
        }
        internal CurrentOwnerIsoRepairReceipt Receipt(CurrentAppOwnedCommitClassification classification)
        {
            var value = new CurrentOwnerIsoRepairReceipt("current-owner-iso-receipt-v1", Scope.OperationId, "Country",
                Scope.ContractSha256, Scope.OperationSha256, Scope.BeforeDatabaseSha256["Country"], new('a', 64), new('b', 64),
                new('0', 64), classification, Now.AddHours(3), Pins.ReceiptKeyId, null);
            return value with
            {
                Signature = Convert.ToBase64String(_receipt.SignData(PostgreSqlCurrentOwnerIsoRepair.Payload(value),
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            };
        }
        public void Dispose() { ReviewSigner.Dispose(); AuthorizationSigner.Dispose(); _receipt.Dispose(); }
    }
}
