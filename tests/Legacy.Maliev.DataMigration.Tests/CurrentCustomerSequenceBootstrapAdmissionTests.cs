using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentCustomerSequenceBootstrapAdmissionTests
{
    [Theory]
    [InlineData("native-component")]
    [InlineData("maintenance-component")]
    public void Completed_disposable_component_route_does_not_accept_persistent_or_incomplete_scope(string phase)
    {
        using var fixture = new Fixture(); var complete = Bootstrap(fixture.Scope) with { BootstrapSubject = null };
        CustomerGuardedBootstrapProofReader.RequireComponentScope(phase, complete);
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerGuardedBootstrapProofReader.RequireComponentScope(phase, fixture.Scope));
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerGuardedBootstrapProofReader.RequireComponentScope(phase, Bootstrap(fixture.Scope)));
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerGuardedBootstrapProofReader.RequireComponentScope(phase, complete with { Target = fixture.Scope.Target }));
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerGuardedBootstrapProofReader.RequireComponentScope("native", complete));
    }
    [Theory]
    [InlineData("duplicate-name")]
    [InlineData("duplicate-hash")]
    [InlineData("two-unack")]
    [InlineData("four-slots")]
    [InlineData("relative-slot")]
    [InlineData("marker-hash")]
    public void Retained_slot_inventory_rejects_duplicate_and_unbounded_evidence(string fault)
    {
        var rows = new List<object>
        {
            new { name = "prepared.json", sha256 = new string('a', 64), acknowledged = false },
            fault switch
            {
                "duplicate-name" => new { name = "prepared.json", sha256 = new string('b', 64), acknowledged = true },
                "duplicate-hash" => new { name = "committed.json", sha256 = new string('a', 64), acknowledged = true },
                "two-unack" => new { name = "committed.json", sha256 = new string('b', 64), acknowledged = false },
                "relative-slot" => new { name = "sub/prepared.json", sha256 = new string('b', 64), acknowledged = true },
                "marker-hash" => new { name = "committed.json", sha256 = "marker", acknowledged = true },
                "four-slots" => new { name = "committed.json", sha256 = new string('b', 64), acknowledged = true },
                _ => throw new InvalidOperationException()
            }
        };
        if (fault == "four-slots") { rows.Add(new { name = "failed.json", sha256 = new string('c', 64), acknowledged = true }); rows.Add(new { name = "other.json", sha256 = new string('d', 64), acknowledged = true }); }
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(rows));
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerGuardedBootstrapProofReader.RequireRetainedSlotInventory(document.RootElement));
    }
    [Fact]
    public void Unique_immutable_slots_with_one_unacknowledged_copy_are_bounded()
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(new[] {
            new {name="prepared.json",sha256=new string('a',64),acknowledged=true},
            new {name="committed.json",sha256=new string('b',64),acknowledged=false},
            new {name="failed.json",sha256=new string('c',64),acknowledged=true}}));
        CustomerGuardedBootstrapProofReader.RequireRetainedSlotInventory(document.RootElement);
    }
    [Fact]
    public async Task Exact_typed_disposable_subject_admits_without_its_own_result_hashes()
    {
        using var fixture = new Fixture(); var scope = Bootstrap(fixture.Scope);
        var (review, authorization) = fixture.SignPair(scope);
        var permit = await CurrentCustomerSequenceRepairPermit.AdmitAsync(review, authorization, fixture.Source, fixture.Trust, fixture.Pins, fixture.Environment, new Clock(fixture.Now), CancellationToken.None);
        Assert.Equal(CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap, permit.Scope.ProofAdmission);
        Assert.Empty(permit.Scope.NativeProofSha256); Assert.Empty(permit.Scope.MaintenanceProofSha256); permit.Stop();
    }
    [Theory]
    [InlineData("missing-subject")]
    [InlineData("persistent-subject")]
    [InlineData("persistent-target")]
    [InlineData("changed-source")]
    [InlineData("changed-definition")]
    [InlineData("placeholder-native")]
    [InlineData("missing-definition")]
    [InlineData("missing-binary")]
    public async Task Legitimately_signed_bootstrap_attack_is_rejected_before_callbacks(string fault)
    {
        using var fixture = new Fixture(); var scope = Bootstrap(fixture.Scope);
        scope = fault switch
        {
            "missing-subject" => scope with { BootstrapSubject = null },
            "persistent-subject" => scope with { ProofAdmission = CurrentCustomerSequenceProofAdmission.PersistentWithClosedConsoleProof },
            "persistent-target" => scope with { Target = fixture.Scope.Target },
            "changed-source" => scope with { BootstrapSubject = scope.BootstrapSubject! with { SourceCommitSha = new('b', 40) } },
            "changed-definition" => scope with { BootstrapSubject = scope.BootstrapSubject! with { DefinitionSha256 = new('b', 64) } },
            "placeholder-native" => scope with { NativeProofSha256 = new('b', 64) },
            "missing-definition" => scope with { DefinitionProofSha256 = string.Empty },
            "missing-binary" => scope with { BootstrapSubject = scope.BootstrapSubject! with { TestAssemblySha256 = string.Empty } },
            _ => throw new InvalidOperationException()
        };
        var (review, authorization) = fixture.SignPair(scope);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentCustomerSequenceRepairPermit.AdmitAsync(review, authorization, fixture.Source, fixture.Trust, fixture.Pins, fixture.Environment, new Clock(fixture.Now), CancellationToken.None));
        Assert.Equal(0, fixture.Environment.Calls); Assert.Equal(0, fixture.Environment.Reservations);
    }
    private static CurrentCustomerSequenceRepairScope Bootstrap(CurrentCustomerSequenceRepairScope scope)
    {
        var subject = new CurrentCustomerSequenceBootstrapSubject("current-customer-sequence-disposable-component-subject-v1", scope.SourceCommitSha, scope.SourceSchemaPlanSha256,
            scope.CatalogReportSha256, scope.OwnerObservation.Head, scope.OwnerObservation.ContextSha256, scope.OwnerObservation.SnapshotSha256,
            scope.DefinitionSha256, scope.DefinitionProofSha256, scope.NativeBeforeStateSha256, scope.TargetObservationSha256, scope.RunBindingSha256, new('1', 64), new('2', 64), new('3', 64));
        return scope with
        {
            Target = scope.Target with { AuthorityId = "aspire://legacy-postgres-main-local/disposable-" + new string('a', 64) },
            ProofAdmission = CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap,
            BootstrapSubject = subject,
            NativeProofSha256 = string.Empty,
            MaintenanceProofSha256 = string.Empty,
            RecoveryReviewSha256 = string.Empty,
            ExactRoleTransitionReviewSha256 = string.Empty
        };
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
        internal int Calls, Reservations; internal bool Retained; internal bool LostAck { get; set; }
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
        internal Fixture()
        {
            Source = SourcePlan() with { CapturedAtUtc = Now };
            Trust = new([new("customer-sequence-review", _review.ExportSubjectPublicKeyInfo()), new("customer-sequence-authorize", _authorization.ExportSubjectPublicKeyInfo()), new("customer-sequence-receipt", _receipt.ExportSubjectPublicKeyInfo())]);
            _ = Trust.TryGetPublicKeyFingerprintSha256("customer-sequence-review", out string r); _ = Trust.TryGetPublicKeyFingerprintSha256("customer-sequence-authorize", out string a); _ = Trust.TryGetPublicKeyFingerprintSha256("customer-sequence-receipt", out string e);
            Pins = new("customer-sequence-review", r, "customer-sequence-authorize", a, "customer-sequence-receipt", e);
            Environment.Fleet = DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]).Select(x => x == "Customer" ? ApprovedCurrentCustomerSequenceDefinitionTests.Observation(ApprovedCurrentCustomerSequenceDefinitionTests.State()).Snapshot : new CurrentAppOwnedDatabaseSnapshot(x, [], [], [])).ToArray();
            Environment.NativeBefore = ApprovedCurrentCustomerSequenceDefinitionTests.Observation(ApprovedCurrentCustomerSequenceDefinitionTests.State());
            var map = Environment.Fleet.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal); string binding = new('f', 64), helper = new('7', 64);
            var catalog = new CurrentCustomerSequenceSource(Source.SourceCommitSha, new string('9', 64), Now, 1000, 1, 1001);
            var owner = new CurrentCustomerSequenceOwner(ApprovedCurrentCustomerSequenceDefinition.CustomerOwnerHead, true, Now,
                ApprovedCurrentCustomerSequenceDefinition.ContextSha256, ApprovedCurrentCustomerSequenceDefinition.OwnerSnapshotSha256);
            Environment.Catalog = catalog; Environment.Owner = owner;
            var definition = ApprovedCurrentCustomerSequenceDefinition.Create(catalog, owner, Source.SourceCommitSha, catalog.CatalogReportSha256, Now);
            Scope = new(Guid.NewGuid(), CurrentCustomerSequenceRepairOperation.FixedStartDefinitionOnly, Source.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(Source),
                catalog.CatalogReportSha256, catalog, owner, definition.ComputeSha256(), ApprovedCurrentCustomerSequenceDefinition.NativeStateSha256(Environment.NativeBefore.State), CurrentCustomerSequenceRepairPermit.OperationSha256(Source, definition, helper, ApprovedCurrentCustomerSequenceDefinition.NativeStateSha256(Environment.NativeBefore.State)), helper, CurrentCustomerSequenceRepairPermit.MaintenanceValidator,
                new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/persistent-aaaaaaaaaaaa", new string('d', 64)), "local-aspire", "legacy-postgres-main-local", "docker:" + new string('a', 64) + ":1:2:3", new string('e', 64), binding, map, CurrentCustomerSequenceRepairPermit.FleetSha256(map), new string('a', 64), new string('b', 64), new string('c', 64),
                new("legacy_customer_sequence_fixture", "legacy-maliev-current-customer-sequence-v1:" + binding, Now.AddMinutes(-1), Now.AddHours(3), Now.AddMinutes(-2), Now.AddMinutes(-2), new string('b', 64), new string('c', 64), "/fixture/pg_hba.conf"), new string('8', 64));
        }
        internal (CurrentCustomerSequenceRepairSignedClaim Review, CurrentCustomerSequenceRepairSignedClaim Authorization) SignPair(CurrentCustomerSequenceRepairScope scope)
        {
            var review = new CurrentCustomerSequenceRepairSignedClaim("current-customer-sequence-repair-review-v1", scope, Guid.NewGuid(), null, Now, Now.AddHours(1), "customer-sequence-review", null);
            review = review with { Signature = Convert.ToBase64String(_review.SignData(CurrentCustomerSequenceRepairPermit.Payload(review), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) };
            var auth = new CurrentCustomerSequenceRepairSignedClaim("current-customer-sequence-repair-authorization-v1", scope, Guid.NewGuid(), CurrentCustomerSequenceRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(review)), Now, Now.AddMinutes(10), "customer-sequence-authorize", null);
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
