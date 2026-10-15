using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentCustomerSequenceRepairAdmissionTests
{
    [Fact]
    public async Task Reviewed_production_inventory_admits_all_49_bound_baselines()
    {
        using var fixture = new Fixture(production: true);
        Assert.Equal(49, fixture.Scope.BeforeDatabaseSha256.Count);
        CurrentCustomerSequenceRepairPermit permit = await fixture.Admit();
        await permit.StartAsync(CancellationToken.None);
        Assert.Equal(1, fixture.Environment.Reservations);
    }

    [Theory]
    [InlineData("wrong")]
    [InlineData("missing")]
    [InlineData("extra")]
    [InlineData("substituted")]
    [InlineData("case")]
    [InlineData("legacy-53")]
    public async Task Resigned_unreviewed_production_inventory_fails_before_callbacks(string fault)
    {
        using var fixture = new Fixture(production: true);
        var map = fixture.Scope.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        string shadow = map.Keys.First(x => x.StartsWith("legacy_shadow_", StringComparison.Ordinal));
        if (fault is "missing" or "substituted" or "case") { _ = map.Remove(shadow); }
        if (fault == "substituted") { map.Add("unreviewed_shadow", new string('a', 64)); }
        if (fault == "case") { map.Add(shadow.ToUpperInvariant(), new string('a', 64)); }
        if (fault == "extra") { map.Add("unreviewed", new string('a', 64)); }
        if (fault == "legacy-53")
        {
            for (int i = 0; i < 4; i++) { map.Add("unreviewed_" + i, new string('a', 64)); }
        }
        if (fault == "wrong")
        {
            _ = map.Remove("Auth");
            map.Add("auth", new string('a', 64));
        }
        CurrentCustomerSequenceRepairScope scope = fixture.Scope with
        { BeforeDatabaseSha256 = map, GlobalPreservationSha256 = CurrentCustomerSequenceRepairPermit.FleetSha256(map) };
        var (review, authorization) = fixture.SignPair(scope);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentCustomerSequenceRepairPermit.AdmitAsync(review, authorization,
            fixture.Source, fixture.Trust, fixture.Pins, fixture.Environment, new Clock(fixture.Now), CancellationToken.None));
        Assert.Equal(0, fixture.Environment.Calls);
        Assert.Equal(0, fixture.Environment.Reservations);
    }
    [Fact]
    public async Task Owner_policy_v2_claims_admit_and_legacy_null_serialization_remains_unchanged()
    {
        using var fixture = new Fixture();
        Assert.DoesNotContain("OwnerPolicySha256", JsonSerializer.Serialize(fixture.Scope), StringComparison.Ordinal);
        CurrentCustomerSequenceRepairScope scope = fixture.Scope with
        { OwnerPolicySha256 = CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, fixture.Scope.Target) };
        var (review, authorization) = fixture.SignPair(scope);
        Assert.Equal("current-customer-sequence-repair-review-v2", review.Kind);
        Assert.Equal("current-customer-sequence-repair-authorization-v2", authorization.Kind);
        _ = await CurrentCustomerSequenceRepairPermit.AdmitAsync(review, authorization, fixture.Source, fixture.Trust, fixture.Pins,
            fixture.Environment, new Clock(fixture.Now), CancellationToken.None);
        Assert.True(fixture.Environment.Calls > 0);
    }

    [Theory]
    [InlineData("foreign-purpose")]
    [InlineData("legacy-domain")]
    [InlineData("production-missing")]
    public async Task Legitimate_owner_policy_signature_attacks_fail_before_callbacks(string fault)
    {
        using var fixture = new Fixture();
        CurrentCustomerSequenceRepairScope scope = fixture.Scope with
        { OwnerPolicySha256 = CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, fixture.Scope.Target) };
        if (fault == "foreign-purpose") { scope = scope with { OwnerPolicySha256 = CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.AuthCollation16, scope.Target) }; }
        if (fault == "production-missing") { scope = scope with { Target = scope.Target with { Kind = DeltaTargetAuthorityKind.ProductionCloudNativePg }, OwnerPolicySha256 = null }; }
        var (review, authorization) = fixture.SignPair(scope, legacyDomain: fault == "legacy-domain");
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentCustomerSequenceRepairPermit.AdmitAsync(review, authorization,
            fixture.Source, fixture.Trust, fixture.Pins, fixture.Environment, new Clock(fixture.Now), CancellationToken.None));
        Assert.Equal(0, fixture.Environment.Calls);
    }

    [Fact]
    public async Task Genuine_distinct_claims_admit_and_reserve_once()
    {
        using var fixture = new Fixture();
        CurrentCustomerSequenceRepairPermit permit = await fixture.Admit();
        await permit.StartAsync(CancellationToken.None);
        Assert.Equal(1, fixture.Environment.Reservations);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.StartAsync(CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireAsync(CancellationToken.None));
        Assert.Equal(1, fixture.Environment.Reservations);
    }
    [Theory]
    [InlineData("operation")]
    [InlineData("namespace")]
    [InlineData("seed")]
    [InlineData("increment")]
    [InlineData("owner")]
    [InlineData("dirty-owner")]
    [InlineData("catalog-report")]
    [InlineData("definition")]
    [InlineData("future-source")]
    [InlineData("hba-validator")]
    [InlineData("missing-maintenance-proof")]
    [InlineData("maintenance-equals-native-proof")]
    [InlineData("maintenance-equals-definition-proof")]
    [InlineData("source-baseline")]
    [InlineData("missing-local")]
    [InlineData("signature")]
    public async Task Genuine_resigned_semantic_attacks_or_bad_signature_fail_before_callbacks(string fault)
    {
        using var fixture = new Fixture(); CurrentCustomerSequenceRepairScope scope = fixture.Scope;
        scope = fault switch
        {
            "operation" => scope with { Operation = (CurrentCustomerSequenceRepairOperation)8 },
            "namespace" => scope with { TargetNamespace = "maliev" },
            "seed" => scope with { SourceObservation = scope.SourceObservation with { Seed = 1 } },
            "increment" => scope with { SourceObservation = scope.SourceObservation with { Increment = 2 } },
            "owner" => scope with { OwnerObservation = scope.OwnerObservation with { Head = new string('b', 40) } },
            "dirty-owner" => scope with { OwnerObservation = scope.OwnerObservation with { Clean = false } },
            "catalog-report" => scope with { CatalogReportSha256 = new string('0', 64) },
            "definition" => scope with { DefinitionSha256 = new string('0', 64) },
            "future-source" => scope with { SourceObservation = scope.SourceObservation with { ObservedAtUtc = fixture.Now.AddSeconds(1) } },
            "hba-validator" => scope with { MaintenanceValidatorSha256 = new string('0', 64) },
            "missing-maintenance-proof" => scope with { MaintenanceProofSha256 = "" },
            "maintenance-equals-native-proof" => scope with { MaintenanceProofSha256 = scope.NativeProofSha256 },
            "maintenance-equals-definition-proof" => scope with { MaintenanceProofSha256 = scope.DefinitionProofSha256 },
            "source-baseline" => scope with { SourceSchemaPlanSha256 = new string('0', 64) },
            _ => scope,
        };
        if (fault == "missing-local")
        {
            var map = scope.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal); _ = map.Remove("legacy_local");
            scope = scope with { BeforeDatabaseSha256 = map, GlobalPreservationSha256 = CurrentCustomerSequenceRepairPermit.FleetSha256(map) };
        }
        var (review, authorization) = fixture.SignPair(scope);
        if (fault == "signature") { authorization = authorization with { Signature = Convert.ToBase64String(new byte[64]) }; }
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentCustomerSequenceRepairPermit.AdmitAsync(review, authorization, fixture.Source,
            fixture.Trust, fixture.Pins, fixture.Environment, new Clock(fixture.Now), CancellationToken.None));
        Assert.Equal(0, fixture.Environment.Calls); Assert.Equal(0, fixture.Environment.Reservations);
    }
    [Fact]
    public async Task Foreign_review_domain_fails_before_callbacks()
    {
        using var fixture = new Fixture(); var (review, auth) = fixture.SignPair(fixture.Scope);
        review = review with { Kind = "current-app-owned-v3-review-v1" };
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentCustomerSequenceRepairPermit.AdmitAsync(review, auth, fixture.Source,
            fixture.Trust, fixture.Pins, fixture.Environment, new Clock(fixture.Now), CancellationToken.None));
        Assert.Equal(0, fixture.Environment.Calls);
    }
    [Theory]
    [InlineData("unknown-slot")]
    [InlineData("fleet-drift")]
    [InlineData("lost-reservation-ack")]
    public async Task Fresh_storage_or_fleet_failure_never_allows_retry(string fault)
    {
        using var fixture = new Fixture(); CurrentCustomerSequenceRepairPermit permit = await fixture.Admit();
        if (fault == "unknown-slot") { fixture.Environment.Retained = true; }
        else if (fault == "fleet-drift") { fixture.Environment.Fleet = [.. fixture.Environment.Fleet.Skip(1)]; }
        else { fixture.Environment.LostAck = true; }
        _ = await Assert.ThrowsAnyAsync<Exception>(() => permit.StartAsync(CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.StartAsync(CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireAsync(CancellationToken.None));
        Assert.Equal(fault == "lost-reservation-ack" ? 1 : 0, fixture.Environment.Reservations);
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Failure_after_terminal_ack_links_latest_authentic_retained_receipt(bool terminalAcknowledged)
    {
        using var fixture = new Fixture(); string authorizationSha = new('a', 64);
        var chain = new CurrentCustomerSequenceRetainedReceiptChain();
        CurrentCustomerSequenceRepairReceipt prepared = fixture.SignReceipt(new("current-customer-sequence-repair-receipt-v1", fixture.Scope.OperationId, "Customer", fixture.Scope.OperationSha256,
            fixture.Scope.BeforeDatabaseSha256["Customer"], new string('e', 64), authorizationSha, chain.PreviousSha256, CurrentAppOwnedCommitClassification.Prepared, fixture.Now, fixture.Pins.ReceiptKeyId, null));
        chain.RecordRetained(prepared, fixture.Scope, authorizationSha, fixture.Trust, fixture.Pins, fixture.Now);
        string preparedSha = chain.PreviousSha256;
        CurrentCustomerSequenceRepairReceipt terminal = fixture.SignReceipt(prepared with { PreviousReceiptSha256 = preparedSha, Classification = CurrentAppOwnedCommitClassification.CommittedAndReadback, Signature = null });
        if (terminalAcknowledged) { chain.RecordRetained(terminal, fixture.Scope, authorizationSha, fixture.Trust, fixture.Pins, fixture.Now); }
        // A failed final fleet check can never produce success; failure signing uses the last acknowledged publication.
        CurrentCustomerSequenceRepairReceipt failure = fixture.SignReceipt(terminal with { PreviousReceiptSha256 = chain.PreviousSha256, Classification = CurrentAppOwnedCommitClassification.Uncertain, Signature = null });
        PostgreSqlCurrentCustomerSequenceRepair.RequireReceipt(failure, fixture.Scope, authorizationSha, fixture.Trust, fixture.Pins, chain.PreviousSha256, fixture.Now);
        string terminalSha = CurrentCustomerSequenceRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(terminal));
        Assert.Equal(terminalAcknowledged ? terminalSha : preparedSha, failure.PreviousReceiptSha256);
        if (terminalAcknowledged) { Assert.NotEqual(preparedSha, failure.PreviousReceiptSha256); }
        _ = Assert.Throws<MigrationExecutionException>(() => chain.RecordRetained(prepared, fixture.Scope, authorizationSha, fixture.Trust, fixture.Pins, fixture.Now));
    }

    [Theory]
    [InlineData("wrong-predecessor")]
    [InlineData("future")]
    [InlineData("stale")]
    [InlineData("before-maintenance")]
    [InlineData("terminal-after-matching")]
    public void Genuine_receipts_reject_chain_or_freshness_attacks(string fault)
    {
        using var fixture = new Fixture(); string authorizationSha = new('a', 64); var chain = new CurrentCustomerSequenceRetainedReceiptChain();
        CurrentCustomerSequenceRepairReceipt prepared = fixture.SignReceipt(new("current-customer-sequence-repair-receipt-v1", fixture.Scope.OperationId, "Customer", fixture.Scope.OperationSha256,
            fixture.Scope.BeforeDatabaseSha256["Customer"], new string('e', 64), authorizationSha, chain.PreviousSha256, CurrentAppOwnedCommitClassification.Prepared, fixture.Now, fixture.Pins.ReceiptKeyId, null));
        if (fault == "terminal-after-matching")
        {
            chain.RecordRetained(prepared, fixture.Scope, authorizationSha, fixture.Trust, fixture.Pins, fixture.Now);
            CurrentCustomerSequenceRepairReceipt terminal = fixture.SignReceipt(prepared with
            {
                Classification = CurrentAppOwnedCommitClassification.CommittedAndReadback,
                PreviousReceiptSha256 = chain.PreviousSha256,
                AfterSha256 = new string('f', 64),
                Signature = null
            });
            _ = Assert.Throws<MigrationExecutionException>(() => chain.RecordRetained(terminal, fixture.Scope, authorizationSha, fixture.Trust, fixture.Pins, fixture.Now));
            return;
        }
        CurrentCustomerSequenceRepairReceipt changed = fixture.SignReceipt(prepared with
        {
            PreviousReceiptSha256 = fault == "wrong-predecessor" ? new string('f', 64) : prepared.PreviousReceiptSha256,
            ObservedAtUtc = fault == "future" ? fixture.Now.AddSeconds(1) : fault == "stale" ? fixture.Now.AddMinutes(-16) : fault == "before-maintenance" ? fixture.Now.AddMinutes(-2) : fixture.Now,
            Signature = null,
        });
        _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlCurrentCustomerSequenceRepair.RequireReceipt(changed, fixture.Scope, authorizationSha,
            fixture.Trust, fixture.Pins, chain.PreviousSha256, fixture.Now));
    }

    [Theory]
    [InlineData("catalog-report")]
    [InlineData("catalog-value")]
    [InlineData("owner-pin")]
    [InlineData("owner-dirty")]
    public async Task Fresh_independent_catalog_or_owner_change_stops_reserved_permit(string fault)
    {
        using var fixture = new Fixture(); var permit = await fixture.Admit();
        await permit.StartAsync(CancellationToken.None);
        switch (fault)
        {
            case "catalog-report": fixture.Environment.Catalog = fixture.Environment.Catalog with { CatalogReportSha256 = new string('8', 64) }; break;
            case "catalog-value": fixture.Environment.Catalog = fixture.Environment.Catalog with { CurrentValue = 1002 }; break;
            case "owner-pin": fixture.Environment.Owner = fixture.Environment.Owner with { ContextSha256 = new string('8', 64) }; break;
            case "owner-dirty": fixture.Environment.Owner = fixture.Environment.Owner with { Clean = false }; break;
            default:
                break;
        }
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireAsync(CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireAsync(CancellationToken.None));
        Assert.Equal(1, fixture.Environment.Reservations);
    }
    [Fact]
    public void Fake_ordinal_without_matching_signed_native_state_is_rejected()
    {
        using var fixture = new Fixture();
        var fake = fixture.Environment.NativeBefore with { State = fixture.Environment.NativeBefore.State with { AttributeNumber = 9 } };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceRepairPermit.RequireNativePreimage(fake, fixture.Scope, fixture.Now));
        CurrentCustomerSequenceRepairPermit.RequireNativePreimage(fixture.Environment.NativeBefore, fixture.Scope, fixture.Now);
    }
    [Fact]
    public async Task Legitimately_resigned_fake_ordinal_cannot_replace_independent_native_reader()
    {
        using var fixture = new Fixture();
        var fake = fixture.Environment.NativeBefore.State with { AttributeNumber = 9 };
        string fakeHash = ApprovedCurrentCustomerSequenceDefinition.NativeStateSha256(fake);
        var definition = ApprovedCurrentCustomerSequenceDefinition.Create(fixture.Scope.SourceObservation, fixture.Scope.OwnerObservation,
            fixture.Scope.SourceCommitSha, fixture.Scope.CatalogReportSha256, fixture.Now);
        var scope = fixture.Scope with
        {
            NativeBeforeStateSha256 = fakeHash,
            OperationSha256 = CurrentCustomerSequenceRepairPermit.OperationSha256(fixture.Source, definition, fixture.Scope.DefinitionProofSha256, fakeHash)
        };
        var (review, authorization) = fixture.SignPair(scope);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentCustomerSequenceRepairPermit.AdmitAsync(review, authorization, fixture.Source,
            fixture.Trust, fixture.Pins, fixture.Environment, new Clock(fixture.Now), CancellationToken.None));
        Assert.Equal(0, fixture.Environment.Reservations);
    }
    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
    private sealed class Environment : ICurrentCustomerSequenceRepairEnvironment
    {
        internal int Calls, Reservations; internal bool Retained, LostAck;
        internal IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> Fleet = [];
        private Task Observe() { Calls++; return Task.CompletedTask; }
        public Task RequireSourceAsync(string sha, CancellationToken ct)
        {
            return Observe();
        }

        internal CurrentCustomerSequenceSource Catalog = null!;
        internal CurrentCustomerSequenceOwner Owner = null!;
        internal CurrentCustomerSequenceObservation NativeBefore = null!;
        public Task<CurrentCustomerSequenceObservation> ObserveNativeBeforeAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
        { Calls++; return Task.FromResult(NativeBefore); }
        public Task<CurrentCustomerSequenceSource> ObserveCurrentCatalogAsync(string sha, CancellationToken ct)
        { Calls++; return Task.FromResult(Catalog); }
        public Task<CurrentCustomerSequenceOwner> ObserveOwnerAsync(CancellationToken ct)
        { Calls++; return Task.FromResult(Owner); }
        public Task RequireSource23PhysicalBaselineAsync(FreshSchemaPlan source, CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
        {
            return Observe();
        }

        public Task RequireResourceAndCustodyAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
        {
            return Observe();
        }

        public Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
        { Calls++; return Task.FromResult(Fleet); }
        public Task RequireFreshOperationAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
        { Calls++; return Retained ? Task.FromException(CurrentCustomerSequenceRepairPermit.Invalid()) : Task.CompletedTask; }
        public Task ReserveFreshOperationAsync(CurrentCustomerSequenceRepairScope scope, string sha, CancellationToken ct)
        { Calls++; if (Retained) { throw CurrentCustomerSequenceRepairPermit.Invalid(); } Retained = true; Reservations++; return LostAck ? Task.FromException(new IOException("fixture lost acknowledgment")) : Task.CompletedTask; }
        public Task RetainNewEvidenceAsync(string name, byte[] bytes, CancellationToken ct)
        {
            throw new InvalidOperationException("pure fixture has no provider authority");
        }
    }
    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa _review = ECDsa.Create(ECCurve.NamedCurves.nistP256), _authorization = ECDsa.Create(ECCurve.NamedCurves.nistP256), _receipt = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        internal DateTimeOffset Now { get; } = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        internal FreshSchemaPlan Source { get; }
        internal CurrentCustomerSequenceRepairScope Scope { get; }
        internal ReceiptAttestationTrustStore Trust { get; }
        internal CurrentCustomerSequenceRepairSigningPins Pins { get; }
        internal Environment Environment { get; } = new();
        internal Fixture(bool production = false)
        {
            Source = SourcePlan() with { CapturedAtUtc = Now };
            Trust = new([new("customer-sequence-review", _review.ExportSubjectPublicKeyInfo()), new("customer-sequence-authorize", _authorization.ExportSubjectPublicKeyInfo()), new("customer-sequence-receipt", _receipt.ExportSubjectPublicKeyInfo())]);
            _ = Trust.TryGetPublicKeyFingerprintSha256("customer-sequence-review", out string r); _ = Trust.TryGetPublicKeyFingerprintSha256("customer-sequence-authorize", out string a); _ = Trust.TryGetPublicKeyFingerprintSha256("customer-sequence-receipt", out string e);
            Pins = new("customer-sequence-review", r, "customer-sequence-authorize", a, "customer-sequence-receipt", e);
            IEnumerable<string> names = production ? ReviewedProductionRepairInventory.ExportProductionNames()
                : DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]);
            var state = ApprovedCurrentCustomerSequenceDefinitionTests.State();
            if (production) { state = state with { Owner = "legacy_customer_owner" }; }
            Environment.NativeBefore = ApprovedCurrentCustomerSequenceDefinitionTests.Observation(state);
            Environment.Fleet = names.Select(x => x == "Customer" ? Environment.NativeBefore.Snapshot : new CurrentAppOwnedDatabaseSnapshot(x, [], [], [])).ToArray();
            var map = Environment.Fleet.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal); string binding = new('f', 64), helper = new('7', 64);
            var catalog = new CurrentCustomerSequenceSource(Source.SourceCommitSha, new string('9', 64), Now, 1000, 1, 1001);
            var owner = new CurrentCustomerSequenceOwner(ApprovedCurrentCustomerSequenceDefinition.CustomerOwnerHead, true, Now,
                ApprovedCurrentCustomerSequenceDefinition.ContextSha256, ApprovedCurrentCustomerSequenceDefinition.OwnerSnapshotSha256);
            Environment.Catalog = catalog; Environment.Owner = owner;
            var definition = ApprovedCurrentCustomerSequenceDefinition.Create(catalog, owner, Source.SourceCommitSha, catalog.CatalogReportSha256, Now);
            Scope = new(Guid.NewGuid(), CurrentCustomerSequenceRepairOperation.FixedStartDefinitionOnly, Source.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(Source),
                catalog.CatalogReportSha256, catalog, owner, definition.ComputeSha256(), ApprovedCurrentCustomerSequenceDefinition.NativeStateSha256(Environment.NativeBefore.State), CurrentCustomerSequenceRepairPermit.OperationSha256(Source, definition, helper, ApprovedCurrentCustomerSequenceDefinition.NativeStateSha256(Environment.NativeBefore.State)), helper, CurrentCustomerSequenceRepairPermit.MaintenanceValidator,
                new(production ? DeltaTargetAuthorityKind.ProductionCloudNativePg : DeltaTargetAuthorityKind.LocalAspire, production ? "gke://maliev-website/customer-fixture" : "aspire://legacy-postgres-main-local/persistent-aaaaaaaaaaaa", new string('d', 64)), production ? "maliev-legacy" : "local-aspire", production ? "legacy-postgres-main" : "legacy-postgres-main-local", "docker:" + new string('a', 64) + ":1:2:3", new string('e', 64), binding, map, CurrentCustomerSequenceRepairPermit.FleetSha256(map), new string('a', 64), new string('b', 64), new string('c', 64),
                new("legacy_customer_sequence_fixture", "legacy-maliev-current-customer-sequence-v1:" + binding, Now.AddMinutes(-1), Now.AddHours(3), Now.AddMinutes(-2), Now.AddMinutes(-2), new string('b', 64), new string('c', 64), "/fixture/pg_hba.conf"), new string('8', 64));
            if (production)
            {
                Scope = Scope with { OwnerPolicySha256 = CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, Scope.Target) };
            }
        }
        internal (CurrentCustomerSequenceRepairSignedClaim Review, CurrentCustomerSequenceRepairSignedClaim Authorization) SignPair(CurrentCustomerSequenceRepairScope scope, bool legacyDomain = false)
        {
            var review = new CurrentCustomerSequenceRepairSignedClaim(scope.OwnerPolicySha256 is null || legacyDomain ? "current-customer-sequence-repair-review-v1" : "current-customer-sequence-repair-review-v2", scope, Guid.NewGuid(), null, Now, Now.AddHours(1), "customer-sequence-review", null);
            review = review with { Signature = Convert.ToBase64String(_review.SignData(CurrentCustomerSequenceRepairPermit.Payload(review), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) };
            var auth = new CurrentCustomerSequenceRepairSignedClaim(scope.OwnerPolicySha256 is null || legacyDomain ? "current-customer-sequence-repair-authorization-v1" : "current-customer-sequence-repair-authorization-v2", scope, Guid.NewGuid(), CurrentCustomerSequenceRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(review)), Now, Now.AddMinutes(10), "customer-sequence-authorize", null);
            auth = auth with { Signature = Convert.ToBase64String(_authorization.SignData(CurrentCustomerSequenceRepairPermit.Payload(auth), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) }; return (review, auth);
        }
        internal CurrentCustomerSequenceRepairReceipt SignReceipt(CurrentCustomerSequenceRepairReceipt receipt)
        {
            return receipt with
            {
                Signature = Convert.ToBase64String(_receipt.SignData(PostgreSqlCurrentCustomerSequenceRepair.ReceiptPayload(receipt), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            };
        }

        internal Task<CurrentCustomerSequenceRepairPermit> Admit() { var (r, a) = SignPair(Scope); return CurrentCustomerSequenceRepairPermit.AdmitAsync(r, a, Source, Trust, Pins, Environment, new Clock(Now), CancellationToken.None); }
        public void Dispose() { _review.Dispose(); _authorization.Dispose(); _receipt.Dispose(); }
    }
    private static FreshSchemaPlan SourcePlan()
    {
        FreshSchemaPlan source = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
        return source with { Databases = [.. source.Databases.Select(x => x.Database == "Quotation" ? Map(x) : x)] };
        static DatabaseSchemaPlan Map(DatabaseSchemaPlan database)
        {
            TableCopyPlan[] tables = [database.Tables[0],ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,"PK_GoogleAnalyticsOutbox","UX_GoogleAnalyticsOutbox_EventKey",true),
                ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,"PK_QuotationOutcomeOutbox","UQ_QuotationOutcomeOutbox_EventKey",false),..database.Tables.Skip(3)];
            database = database with { Tables = tables, SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1, SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables) };
            return database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
        }
    }
}
