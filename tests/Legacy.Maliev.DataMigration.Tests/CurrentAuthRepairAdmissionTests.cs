using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthRepairAdmissionTests
{
    [Fact]
    public async Task Genuine_distinct_claims_admit_and_reserve_once()
    {
        using var fixture = new Fixture();
        CurrentAuthRepairPermit permit = await fixture.Admit();
        await permit.StartAsync(CancellationToken.None);
        Assert.Equal(1, fixture.Environment.Reservations);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.StartAsync(CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireAsync(CancellationToken.None));
        Assert.Equal(1, fixture.Environment.Reservations);
    }
    [Theory]
    [InlineData("operation")]
    [InlineData("namespace")]
    [InlineData("owner")]
    [InlineData("pins")]
    [InlineData("closure")]
    [InlineData("before")]
    [InlineData("after")]
    [InlineData("helper")]
    [InlineData("hba-validator")]
    [InlineData("operand-owner-policy")]
    [InlineData("source-baseline")]
    [InlineData("missing-local")]
    [InlineData("signature")]
    public async Task Genuine_resigned_semantic_attacks_or_bad_signature_fail_before_callbacks(string fault)
    {
        using var fixture = new Fixture(); CurrentAuthRepairScope scope = fixture.Scope;
        scope = fault switch
        {
            "operation" => scope with { Operation = (CurrentAuthRepairOperation)8 },
            "namespace" => scope with { TargetNamespace = "maliev" },
            "owner" => scope with { AuthOwnerCommitSha = new string('b', 40) },
            "pins" => scope with { AuthOwnerSourcePinsSha256 = new string('0', 64) },
            "closure" => scope with { AuthClosureSha256 = new string('0', 64) },
            "before" => scope with { AuthBeforeSchemaSha256 = new string('0', 64) },
            "after" => scope with { AuthAfterSchemaSha256 = new string('0', 64) },
            "helper" => scope with { AuthHelperProofSha256 = new string('b', 64) },
            "operand-owner-policy" => scope with { OwnerPolicySha256 = CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, scope.Target) },
            "hba-validator" => scope with { MaintenanceValidatorSha256 = new string('0', 64) },
            "source-baseline" => scope with { SourceSchemaPlanSha256 = new string('0', 64) },
            _ => scope,
        };
        if (fault == "missing-local")
        {
            var map = scope.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal); _ = map.Remove("legacy_local");
            scope = scope with { BeforeDatabaseSha256 = map, GlobalPreservationSha256 = CurrentAuthRepairPermit.FleetSha256(map) };
        }
        var (review, authorization) = fixture.SignPair(scope);
        if (fault == "signature") { authorization = authorization with { Signature = Convert.ToBase64String(new byte[64]) }; }
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthRepairPermit.AdmitAsync(review, authorization, fixture.Source,
            fixture.Trust, fixture.Pins, fixture.Environment, new Clock(fixture.Now), CancellationToken.None));
        Assert.Equal(0, fixture.Environment.Calls); Assert.Equal(0, fixture.Environment.Reservations);
    }
    [Fact]
    public async Task Explicit_owner_policy_uses_v2_claims_and_null_keeps_original_local_serialization()
    {
        using var fixture = new Fixture();
        Assert.DoesNotContain("OwnerPolicySha256", JsonSerializer.Serialize(fixture.Scope), StringComparison.Ordinal);
        CurrentAuthRepairScope scope = fixture.Scope with
        { OwnerPolicySha256 = CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.AuthCollation16, fixture.Scope.Target) };
        var (review, authorization) = fixture.SignPair(scope);
        Assert.Equal("current-auth-repair-review-v2", review.Kind);
        Assert.Equal("current-auth-repair-authorization-v2", authorization.Kind);
        _ = await CurrentAuthRepairPermit.AdmitAsync(review, authorization, fixture.Source, fixture.Trust, fixture.Pins,
            fixture.Environment, new Clock(fixture.Now), CancellationToken.None);
        Assert.True(fixture.Environment.Calls > 0);
    }

    [Fact]
    public void Fixed_operand_policy_binds_operation_kind_and_actual_system_without_portable_role_oids()
    {
        var production = new DeltaTargetAuthority(DeltaTargetAuthorityKind.ProductionCloudNativePg, "pure-profile-only", new string('d', 64));
        Assert.Equal("legacy_auth_refresh", CurrentRepairOperandOwnerProfile.ExpectedOwnerName(CurrentRepairOperandOwnerPurpose.AuthCollation16, production));
        Assert.Equal("legacy_customer_owner", CurrentRepairOperandOwnerProfile.ExpectedOwnerName(CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, production));
        Assert.Equal("legacy_local", CurrentRepairOperandOwnerProfile.ExpectedOwnerName(CurrentRepairOperandOwnerPurpose.AuthCollation16,
            production with { Kind = DeltaTargetAuthorityKind.LocalAspire }));
        string auth = CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.AuthCollation16, production);
        Assert.NotEqual(auth, CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, production));
        Assert.NotEqual(auth, CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.AuthCollation16,
            production with { SystemIdentifierSha256 = new string('e', 64) }));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentRepairOperandOwnerProfile.ExpectedOwnerName((CurrentRepairOperandOwnerPurpose)99, production));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentRepairOperandOwnerProfile.ExpectedOwnerName(CurrentRepairOperandOwnerPurpose.AuthCollation16,
            production with { Kind = "caller-supplied-owner" }));
    }

    [Fact]
    public async Task Legacy_claim_domain_cannot_accept_new_owner_policy_even_with_legitimate_signature()
    {
        using var fixture = new Fixture();
        CurrentAuthRepairScope scope = fixture.Scope with
        { OwnerPolicySha256 = CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.AuthCollation16, fixture.Scope.Target) };
        var (review, authorization) = fixture.SignPair(scope, legacyDomain: true);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthRepairPermit.AdmitAsync(review, authorization,
            fixture.Source, fixture.Trust, fixture.Pins, fixture.Environment, new Clock(fixture.Now), CancellationToken.None));
        Assert.Equal(0, fixture.Environment.Calls);
    }

    [Fact]
    public async Task Production_owner_policy_is_required_before_any_environment_callback()
    {
        using var fixture = new Fixture();
        CurrentAuthRepairScope scope = fixture.Scope with
        { Target = fixture.Scope.Target with { Kind = DeltaTargetAuthorityKind.ProductionCloudNativePg }, OwnerPolicySha256 = null };
        var (review, authorization) = fixture.SignPair(scope);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthRepairPermit.AdmitAsync(review, authorization,
            fixture.Source, fixture.Trust, fixture.Pins, fixture.Environment, new Clock(fixture.Now), CancellationToken.None));
        Assert.Equal(0, fixture.Environment.Calls);
    }

    [Fact]
    public async Task Foreign_review_domain_fails_before_callbacks()
    {
        using var fixture = new Fixture(); var (review, auth) = fixture.SignPair(fixture.Scope);
        review = review with { Kind = "current-app-owned-v3-review-v1" };
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthRepairPermit.AdmitAsync(review, auth, fixture.Source,
            fixture.Trust, fixture.Pins, fixture.Environment, new Clock(fixture.Now), CancellationToken.None));
        Assert.Equal(0, fixture.Environment.Calls);
    }
    [Theory]
    [InlineData("unknown-slot")]
    [InlineData("fleet-drift")]
    [InlineData("lost-reservation-ack")]
    public async Task Fresh_storage_or_fleet_failure_never_allows_retry(string fault)
    {
        using var fixture = new Fixture(); CurrentAuthRepairPermit permit = await fixture.Admit();
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
        var chain = new CurrentAuthRetainedReceiptChain();
        CurrentAuthRepairReceipt prepared = fixture.SignReceipt(new("current-auth-repair-receipt-v1", fixture.Scope.OperationId, "Auth", fixture.Scope.OperationSha256,
            fixture.Scope.BeforeDatabaseSha256["Auth"], new string('e', 64), authorizationSha, chain.PreviousSha256, CurrentAppOwnedCommitClassification.Prepared, fixture.Now, fixture.Pins.ReceiptKeyId, null));
        chain.RecordRetained(prepared, fixture.Scope, authorizationSha, fixture.Trust, fixture.Pins, fixture.Now);
        string preparedSha = chain.PreviousSha256;
        CurrentAuthRepairReceipt terminal = fixture.SignReceipt(prepared with { PreviousReceiptSha256 = preparedSha, Classification = CurrentAppOwnedCommitClassification.CommittedAndReadback, Signature = null });
        if (terminalAcknowledged) { chain.RecordRetained(terminal, fixture.Scope, authorizationSha, fixture.Trust, fixture.Pins, fixture.Now); }
        // A failed final fleet check can never produce success; failure signing uses the last acknowledged publication.
        CurrentAuthRepairReceipt failure = fixture.SignReceipt(terminal with { PreviousReceiptSha256 = chain.PreviousSha256, Classification = CurrentAppOwnedCommitClassification.Uncertain, Signature = null });
        PostgreSqlCurrentAuthRepair.RequireReceipt(failure, fixture.Scope, authorizationSha, fixture.Trust, fixture.Pins, chain.PreviousSha256, fixture.Now);
        string terminalSha = CurrentAuthRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(terminal));
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
        using var fixture = new Fixture(); string authorizationSha = new('a', 64); var chain = new CurrentAuthRetainedReceiptChain();
        CurrentAuthRepairReceipt prepared = fixture.SignReceipt(new("current-auth-repair-receipt-v1", fixture.Scope.OperationId, "Auth", fixture.Scope.OperationSha256,
            fixture.Scope.BeforeDatabaseSha256["Auth"], new string('e', 64), authorizationSha, chain.PreviousSha256, CurrentAppOwnedCommitClassification.Prepared, fixture.Now, fixture.Pins.ReceiptKeyId, null));
        if (fault == "terminal-after-matching")
        {
            chain.RecordRetained(prepared, fixture.Scope, authorizationSha, fixture.Trust, fixture.Pins, fixture.Now);
            CurrentAuthRepairReceipt terminal = fixture.SignReceipt(prepared with
            {
                Classification = CurrentAppOwnedCommitClassification.CommittedAndReadback,
                PreviousReceiptSha256 = chain.PreviousSha256,
                AfterSha256 = new string('f', 64),
                Signature = null
            });
            _ = Assert.Throws<MigrationExecutionException>(() => chain.RecordRetained(terminal, fixture.Scope, authorizationSha, fixture.Trust, fixture.Pins, fixture.Now));
            return;
        }
        CurrentAuthRepairReceipt changed = fixture.SignReceipt(prepared with
        {
            PreviousReceiptSha256 = fault == "wrong-predecessor" ? new string('f', 64) : prepared.PreviousReceiptSha256,
            ObservedAtUtc = fault == "future" ? fixture.Now.AddSeconds(1) : fault == "stale" ? fixture.Now.AddMinutes(-16) : fault == "before-maintenance" ? fixture.Now.AddMinutes(-2) : fixture.Now,
            Signature = null,
        });
        _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlCurrentAuthRepair.RequireReceipt(changed, fixture.Scope, authorizationSha,
            fixture.Trust, fixture.Pins, chain.PreviousSha256, fixture.Now));
    }

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
    private sealed class Environment : ICurrentAuthRepairEnvironment
    {
        internal int Calls, Reservations; internal bool Retained, LostAck;
        internal IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> Fleet = [];
        private Task Observe() { Calls++; return Task.CompletedTask; }
        public Task RequireSourceAsync(string sha, CancellationToken ct)
        {
            return Observe();
        }

        public Task RequireAuthOwnerSourceAsync(CurrentAuthRepairScope scope, CancellationToken ct)
        {
            return Observe();
        }

        public Task RequireSource23PhysicalBaselineAsync(FreshSchemaPlan source, CancellationToken ct)
        {
            return Observe();
        }

        public Task RequireResourceAndCustodyAsync(CurrentAuthRepairScope scope, CancellationToken ct)
        {
            return Observe();
        }

        public Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CurrentAuthRepairScope scope, CancellationToken ct)
        { Calls++; return Task.FromResult(Fleet); }
        public Task RequireFreshOperationAsync(CurrentAuthRepairScope scope, CancellationToken ct)
        { Calls++; return Retained ? Task.FromException(CurrentAuthRepairPermit.Invalid()) : Task.CompletedTask; }
        public Task ReserveFreshOperationAsync(CurrentAuthRepairScope scope, string sha, CancellationToken ct)
        { Calls++; if (Retained) { throw CurrentAuthRepairPermit.Invalid(); } Retained = true; Reservations++; return LostAck ? Task.FromException(new IOException("fixture lost acknowledgment")) : Task.CompletedTask; }
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
        internal CurrentAuthRepairScope Scope { get; }
        internal ReceiptAttestationTrustStore Trust { get; }
        internal CurrentAuthRepairSigningPins Pins { get; }
        internal Environment Environment { get; } = new();
        internal Fixture()
        {
            Source = SourcePlan() with { CapturedAtUtc = Now };
            Trust = new([new("auth-review", _review.ExportSubjectPublicKeyInfo()), new("auth-authorize", _authorization.ExportSubjectPublicKeyInfo()), new("auth-receipt", _receipt.ExportSubjectPublicKeyInfo())]);
            _ = Trust.TryGetPublicKeyFingerprintSha256("auth-review", out string r); _ = Trust.TryGetPublicKeyFingerprintSha256("auth-authorize", out string a); _ = Trust.TryGetPublicKeyFingerprintSha256("auth-receipt", out string e);
            Pins = new("auth-review", r, "auth-authorize", a, "auth-receipt", e);
            Environment.Fleet = DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]).Select(x => new CurrentAppOwnedDatabaseSnapshot(x, [], [], [])).ToArray();
            var map = Environment.Fleet.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal); string binding = new('f', 64), helper = new('a', 64);
            Scope = new(Guid.NewGuid(), CurrentAuthRepairOperation.SixteenSameTypeTextCollations, Source.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(Source), ApprovedCurrentAuthSchema.AuthServiceCommit,
                CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256, ApprovedCurrentAuthSchema.PhysicalSha256(false), ApprovedCurrentAuthSchema.PhysicalSha256(true), CurrentAuthRepairPermit.OperationSha256(Source, helper), helper, CurrentAuthRepairPermit.MaintenanceValidator,
                new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/persistent-aaaaaaaaaaaa", new string('d', 64)), "local-aspire", "legacy-postgres-main-local", "docker:" + new string('a', 64) + ":1:2:3", new string('e', 64), binding, map, CurrentAuthRepairPermit.FleetSha256(map), new string('a', 64), new string('b', 64), new string('c', 64),
                new("legacy_auth_fixture", "legacy-maliev-current-auth-v1:" + binding, Now.AddMinutes(-1), Now.AddHours(3), Now.AddMinutes(-2), Now.AddMinutes(-2), new string('b', 64), new string('c', 64), "/fixture/pg_hba.conf"));
        }
        internal (CurrentAuthRepairSignedClaim Review, CurrentAuthRepairSignedClaim Authorization) SignPair(CurrentAuthRepairScope scope, bool legacyDomain = false)
        {
            var review = new CurrentAuthRepairSignedClaim(scope.OwnerPolicySha256 is null || legacyDomain ? "current-auth-repair-review-v1" : "current-auth-repair-review-v2", scope, Guid.NewGuid(), null, Now, Now.AddHours(1), "auth-review", null);
            review = review with { Signature = Convert.ToBase64String(_review.SignData(CurrentAuthRepairPermit.Payload(review), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) };
            var auth = new CurrentAuthRepairSignedClaim(scope.OwnerPolicySha256 is null || legacyDomain ? "current-auth-repair-authorization-v1" : "current-auth-repair-authorization-v2", scope, Guid.NewGuid(), CurrentAuthRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(review)), Now, Now.AddMinutes(10), "auth-authorize", null);
            auth = auth with { Signature = Convert.ToBase64String(_authorization.SignData(CurrentAuthRepairPermit.Payload(auth), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) }; return (review, auth);
        }
        internal CurrentAuthRepairReceipt SignReceipt(CurrentAuthRepairReceipt receipt)
        {
            return receipt with
            {
                Signature = Convert.ToBase64String(_receipt.SignData(PostgreSqlCurrentAuthRepair.ReceiptPayload(receipt), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            };
        }

        internal Task<CurrentAuthRepairPermit> Admit() { var (r, a) = SignPair(Scope); return CurrentAuthRepairPermit.AdmitAsync(r, a, Source, Trust, Pins, Environment, new Clock(Now), CancellationToken.None); }
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
