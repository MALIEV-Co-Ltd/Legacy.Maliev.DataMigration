using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAppOwnedV3RepairAdmissionTests
{
    [Theory]
    [InlineData("before-hash")]
    [InlineData("after-hash")]
    [InlineData("operation-digest")]
    [InlineData("signature")]
    public void Pure_review_gate_rejects_invalid_review_before_environment_construction(string fault)
    {
        using var fixture = new Claims();
        CurrentAppOwnedV3RepairPermit.ValidateReview(fixture.Review, fixture.Before, fixture.After,
            fixture.Trust, fixture.Pins, fixture.Now);
        CurrentAppOwnedV3RepairScope changed = fault switch
        {
            "before-hash" => fixture.Scope with { BeforeSchemaPlanSha256 = new string('0', 64) },
            "after-hash" => fixture.Scope with { AfterSchemaPlanSha256 = new string('0', 64) },
            "operation-digest" => fixture.Scope with { OperationSha256 = new string('0', 64) },
            _ => fixture.Scope,
        };
        var (review, _) = fixture.SignPair(changed);
        if (fault == "signature") { review = review with { Signature = Convert.ToBase64String(new byte[64]) }; }
        bool environmentConstructed = false;
        _ = Assert.Throws<MigrationExecutionException>(() =>
        {
            CurrentAppOwnedV3RepairPermit.ValidateReview(review, fixture.Before, fixture.After,
                fixture.Trust, fixture.Pins, fixture.Now);
            environmentConstructed = true;
        });
        Assert.False(environmentConstructed);
        Assert.Equal(0, fixture.Environment.SourceCalls);
        Assert.Equal(0, fixture.Environment.PublicationAttempts);
    }

    [Fact]
    public async Task Genuine_v3_claims_admit_exact_schema_pair_and_single_use_start()
    {
        using var fixture = new Claims();
        CurrentAppOwnedV3RepairPermit permit = await fixture.Admit();
        await permit.StartAsync(CancellationToken.None);
        _ = Assert.Single(fixture.Environment.Publications);
        Assert.EndsWith("-v3-operation-start.json", fixture.Environment.Publications[0], StringComparison.Ordinal);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.StartAsync(CancellationToken.None));
        _ = Assert.Single(fixture.Environment.Publications);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Reservation_failure_consumes_permit_even_if_publication_acknowledgment_is_lost(bool acknowledged)
    {
        using var fixture = new Claims();
        CurrentAppOwnedV3RepairPermit permit = await fixture.Admit();
        fixture.Environment.FailPublication = true;
        fixture.Environment.RetainBeforeFailure = acknowledged;
        _ = await Assert.ThrowsAsync<IOException>(() => permit.StartAsync(CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.StartAsync(CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireAsync(CancellationToken.None));
        Assert.Equal(1, fixture.Environment.PublicationAttempts);
        Assert.Equal(acknowledged ? 1 : 0, fixture.Environment.Publications.Count);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("rows")]
    [InlineData("extra")]
    public async Task Whole_fleet_drift_fails_before_reservation(string fault)
    {
        using var fixture = new Claims();
        CurrentAppOwnedV3RepairPermit permit = await fixture.Admit();
        fixture.Environment.Fleet = fault switch
        {
            "missing" => [.. fixture.Environment.Fleet.Skip(1)],
            "duplicate" => [.. fixture.Environment.Fleet.Skip(1), fixture.Environment.Fleet[1]],
            "rows" => [fixture.Environment.Fleet[0] with { Relations = [new("private", "receipt", 1, new string('a', 64))] }, .. fixture.Environment.Fleet.Skip(1)],
            _ => [.. fixture.Environment.Fleet, new("unreviewed", [], [], [])],
        };
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.StartAsync(CancellationToken.None));
        Assert.Equal(0, fixture.Environment.PublicationAttempts);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.StartAsync(CancellationToken.None));
    }

    [Theory]
    [InlineData("eight-kind")]
    [InlineData("eight-operation")]
    [InlineData("source")]
    [InlineData("namespace")]
    [InlineData("proof")]
    [InlineData("scope")]
    [InlineData("expiry")]
    [InlineData("wrong-key")]
    [InlineData("signature")]
    public void Distinct_v3_claims_reject_foreign_authority_and_changed_signed_binding(string fault)
    {
        using var fixture = new Claims();
        CurrentAppOwnedV3RepairSignedClaim changed = fault switch
        {
            "eight-kind" => fixture.Authorization with { Kind = "current-app-owned-eight-authorization-v1" },
            "eight-operation" => fixture.Authorization with { Scope = fixture.Scope with { Operation = (CurrentAppOwnedV3RepairOperation)8 } },
            "source" => fixture.Authorization with { Scope = fixture.Scope with { SourceCommitSha = new string('A', 40) } },
            "namespace" => fixture.Authorization with { Scope = fixture.Scope with { TargetNamespace = "maliev" } },
            "proof" => fixture.Authorization with { Scope = fixture.Scope with { NativeProofSha256 = string.Empty } },
            "scope" => fixture.Authorization with { Scope = fixture.Scope with { TargetGeneration = "other" } },
            "expiry" => fixture.Authorization with { ExpiresAtUtc = fixture.Now },
            "wrong-key" => fixture.Authorization with { KeyId = fixture.Pins.ReviewKeyId },
            _ => fixture.Authorization with { Signature = Convert.ToBase64String(new byte[64]) },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedV3RepairPermit.ValidateClaims(
            fixture.Review, changed, fixture.Trust, fixture.Pins, fixture.Now));
    }

    [Fact]
    public async Task Re_signed_wrong_operation_digest_and_missing_local_database_are_not_authority()
    {
        using var fixture = new Claims();
        var changed = fixture.Scope with { OperationSha256 = new string('0', 64) };
        var (review, authorization) = fixture.SignPair(changed);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAppOwnedV3RepairPermit.AdmitAsync(
            review, authorization, fixture.Before, fixture.After, fixture.Trust, fixture.Pins,
            fixture.Environment, new FixedTime(fixture.Now), CancellationToken.None));
        var fleet = fixture.Scope.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        string hash = fleet["legacy_local"]; _ = fleet.Remove("legacy_local"); fleet.Add("unreviewed", hash);
        changed = fixture.Scope with { BeforeDatabaseSha256 = fleet, GlobalPreservationSha256 = CurrentAppOwnedV3RepairPermit.FleetSha256(fleet) };
        (review, authorization) = fixture.SignPair(changed);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedV3RepairPermit.ValidateClaims(review, authorization, fixture.Trust, fixture.Pins, fixture.Now));
    }

    [Theory]
    [InlineData("missing-control")]
    [InlineData("missing-shadow")]
    [InlineData("substituted-shadow")]
    [InlineData("extra")]
    public void Re_signed_production_inventory_is_exact_even_with_matching_fleet_digest(string fault)
    {
        using var f = new Claims();
        var hashes = ReviewedProductionRepairInventory.ExportProductionNames()
            .ToDictionary(x => x, _ => new string('a', 64), StringComparer.Ordinal);
        var scope = f.Scope with
        {
            Target = new(DeltaTargetAuthorityKind.ProductionCloudNativePg, "gke://maliev-website/inventory-fixture", new string('d', 64)),
            TargetNamespace = "maliev-legacy", TargetCluster = "legacy-postgres-main", BeforeDatabaseSha256 = hashes,
            GlobalPreservationSha256 = CurrentAppOwnedV3RepairPermit.FleetSha256(hashes),
        };
        var (review, authorization) = f.SignPair(scope);
        CurrentAppOwnedV3RepairPermit.ValidateClaims(review, authorization, f.Trust, f.Pins, f.Now);
        string shadow = hashes.Keys.First(x => x.StartsWith("legacy_shadow_", StringComparison.Ordinal));
        switch (fault)
        {
            case "missing-control": _ = hashes.Remove("legacy_migration_control"); break;
            case "missing-shadow": _ = hashes.Remove(shadow); break;
            case "substituted-shadow":
                string hash = hashes[shadow];
                _ = hashes.Remove(shadow);
                hashes.Add("replacement_shadow", hash);
                break;
            case "extra": hashes.Add("unreviewed_extra", new string('a', 64)); break;
            default: throw new InvalidOperationException();
        }
        scope = scope with { GlobalPreservationSha256 = CurrentAppOwnedV3RepairPermit.FleetSha256(hashes) };
        (review, authorization) = f.SignPair(scope);
        Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedV3RepairPermit.ValidateClaims(review, authorization,
            f.Trust, f.Pins, f.Now));
    }

    [Fact]
    public async Task Caller_mutation_cannot_change_admitted_scope_or_preimages()
    {
        using var fixture = new Claims();
        CurrentAppOwnedV3RepairPermit permit = await fixture.Admit();
        var original = permit.Scope.BeforeDatabaseSha256["Invoice"];
        ((IDictionary<string, string>)fixture.Scope.BeforeDatabaseSha256)["Invoice"] = new string('9', 64);
        ((IDictionary<string, string>)permit.Scope.BeforeDatabaseSha256)["Invoice"] = new string('8', 64);
        Assert.Equal(original, permit.Scope.BeforeDatabaseSha256["Invoice"]);
        await permit.StartAsync(CancellationToken.None);
    }

    [Theory]
    [InlineData(false, false, false, 3)]
    [InlineData(false, false, true, 2)]
    [InlineData(true, false, false, 4)]
    [InlineData(true, true, false, 4)]
    [InlineData(true, true, true, 4)]
    public void Any_started_commit_failure_stops_as_uncertain(bool started, bool acknowledged, bool rollback, int expected)
    {
        Assert.Equal((CurrentAppOwnedCommitClassification)expected,
            PostgreSqlCurrentAppOwnedV3Repair.ClassifyFailure(started, acknowledged, rollback));
    }

    [Fact]
    public async Task Native_capture_rejects_arbitrary_owner_before_connection_access()
    {
        using var fixture = new Claims();
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAppOwnedV3AdditivePreservation.CaptureAsync(
            null!, null!, fixture.Before, fixture.After, fixture.Scope.SourceCommitSha, true, fixture.Now,
            CancellationToken.None, "arbitrary-maintenance-role"));
    }
    [Theory]
    [InlineData("Invoice-prepared")]
    [InlineData("Invoice-committed-readback")]
    [InlineData("Quotation-failed-or-uncertain")]
    [InlineData("v3-operation-start")]
    [InlineData("unknown-slot")]
    public async Task Any_operation_slot_blocks_review_authorization_admission_and_atomic_start(string slot)
    {
        using var fixture = new Claims();
        CurrentAppOwnedV3RepairPermit permit = await fixture.Admit();
        fixture.Environment.Publications.Add($"{fixture.Scope.OperationId:D}-{slot}.json");
        using var reviewSigner = fixture.ReviewSigner();
        using var authorizationSigner = fixture.AuthorizationSigner();
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAppOwnedV3RepairPermit.IssueReviewAsync(
            fixture.Scope, fixture.Before, fixture.After, fixture.Environment.Fleet, fixture.Trust, fixture.Pins,
            fixture.Environment, reviewSigner, fixture.Now.AddHours(1), new FixedTime(fixture.Now), CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAppOwnedV3RepairPermit.AuthorizeAsync(
            fixture.Review, fixture.Before, fixture.After, fixture.Trust, fixture.Pins, fixture.Environment,
            authorizationSigner, new FixedTime(fixture.Now), CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(fixture.Admit);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.StartAsync(CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireAsync(CancellationToken.None));
        Assert.Equal(0, fixture.Environment.PublicationAttempts);
    }

    [Fact]
    public async Task Atomic_reservation_detects_unknown_slot_added_after_freshness_observation()
    {
        using var fixture = new Claims();
        CurrentAppOwnedV3RepairPermit permit = await fixture.Admit();
        fixture.Environment.RaceSlot = "unknown-racing-slot";
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.StartAsync(CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireAsync(CancellationToken.None));
        Assert.Equal(0, fixture.Environment.PublicationAttempts);
    }

    [Fact]
    public async Task Genuine_issuer_validates_preimages_and_signer_before_environment_then_rechecks_actual_fleet()
    {
        using var fixture = new Claims();
        using var signer = fixture.ReviewSigner();
        CurrentAppOwnedV3RepairSignedClaim issued = await CurrentAppOwnedV3RepairPermit.IssueReviewAsync(
            fixture.Scope, fixture.Before, fixture.After, fixture.Environment.Fleet, fixture.Trust, fixture.Pins,
            fixture.Environment, signer, fixture.Now.AddHours(1), new FixedTime(fixture.Now), CancellationToken.None);
        Assert.Equal("current-app-owned-v3-review-v1", issued.Kind);
        int calls = fixture.Environment.SourceCalls;
        var wrong = fixture.Scope with { OperationSha256 = new string('0', 64) };
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAppOwnedV3RepairPermit.IssueReviewAsync(
            wrong, fixture.Before, fixture.After, fixture.Environment.Fleet, fixture.Trust, fixture.Pins,
            fixture.Environment, signer, fixture.Now.AddHours(1), new FixedTime(fixture.Now), CancellationToken.None));
        Assert.Equal(calls, fixture.Environment.SourceCalls);
        using var foreign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrongSigner = new P256MigrationEvidenceSigner(fixture.Pins.ReviewKeyId, foreign.ExportECPrivateKeyPem());
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAppOwnedV3RepairPermit.IssueReviewAsync(
            fixture.Scope, fixture.Before, fixture.After, fixture.Environment.Fleet, fixture.Trust, fixture.Pins,
            fixture.Environment, wrongSigner, fixture.Now.AddHours(1), new FixedTime(fixture.Now), CancellationToken.None));
        Assert.Equal(calls, fixture.Environment.SourceCalls);
        var baseline = fixture.Environment.Fleet;
        fixture.Environment.Fleet = [.. baseline.Skip(1)];
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(fixture.Admit);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAppOwnedV3RepairPermit.IssueReviewAsync(
            fixture.Scope, fixture.Before, fixture.After, baseline, fixture.Trust, fixture.Pins,
            fixture.Environment, signer, fixture.Now.AddHours(1), new FixedTime(fixture.Now), CancellationToken.None));
    }

    [Fact]
    public void Snapshot_copy_retains_exact_digest_and_copies_collections_without_json_roundtrip()
    {
        var catalog = new[] { new CurrentAppOwnedCatalogFact("pg_class", "1", new string('a', 64), "1259", "1") };
        var original = new CurrentAppOwnedDatabaseSnapshot("Invoice", catalog, [], []);
        CurrentAppOwnedDatabaseSnapshot copy = CurrentAppOwnedV3RepairPermit.CopySnapshot(original);
        string before = CurrentAppOwnedSnapshotSerialization.Sha256(copy);
        Assert.Equal(CurrentAppOwnedSnapshotSerialization.Sha256(original), before);
        catalog[0] = catalog[0] with { Sha256 = new string('b', 64) };
        Assert.Equal(before, CurrentAppOwnedSnapshotSerialization.Sha256(copy));
        Assert.NotEqual(CurrentAppOwnedSnapshotSerialization.Sha256(original), before);
        _ = Assert.Throws<NotSupportedException>(() => ((IList<CurrentAppOwnedCatalogFact>)copy.Catalog)[0] = catalog[0]);
    }
    [Theory]
    [InlineData("foreign-operation")]
    [InlineData("upper-source")]
    [InlineData("eight-maintenance")]
    [InlineData("empty-proof")]
    public async Task Legitimate_signatures_do_not_bypass_semantic_admission(string fault)
    {
        using var fixture = new Claims();
        CurrentAppOwnedV3RepairScope changed = fault switch
        {
            "foreign-operation" => fixture.Scope with { Operation = (CurrentAppOwnedV3RepairOperation)31 },
            "upper-source" => fixture.Scope with { SourceCommitSha = new string('A', 40) },
            "eight-maintenance" => fixture.Scope with { Maintenance = fixture.Scope.Maintenance with { RoleComment = "legacy-maliev-current-app-owned-eight-v1:" + fixture.Scope.RunBindingSha256 } },
            _ => fixture.Scope with { NativeProofSha256 = string.Empty },
        };
        var (review, authorization) = fixture.SignPair(changed);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAppOwnedV3RepairPermit.AdmitAsync(
            review, authorization, fixture.Before, fixture.After, fixture.Trust, fixture.Pins, fixture.Environment,
            new FixedTime(fixture.Now), CancellationToken.None));
        Assert.Equal(0, fixture.Environment.SourceCalls);
        Assert.Equal(0, fixture.Environment.PublicationAttempts);
    }
    [Fact]
    public void V3_effect_receipts_authenticate_but_never_accept_foreign_domains_or_resigned_scope_changes()
    {
        using var fixture = new Claims();
        string auth = CurrentAppOwnedSnapshotSerialization.Sha256(fixture.Authorization);
        var unsigned = new CurrentAppOwnedV3RepairReceipt("current-app-owned-v3-receipt-v1", fixture.Scope.OperationId,
            "Invoice", fixture.Scope.OperationSha256, fixture.Scope.BeforeDatabaseSha256["Invoice"], new string('c', 64),
            auth, new string('0', 64), CurrentAppOwnedCommitClassification.Prepared, fixture.Now, fixture.Pins.ReceiptKeyId, null);
        var receipt = fixture.SignReceipt(unsigned);
        PostgreSqlCurrentAppOwnedV3Repair.RequireReceipt(receipt, fixture.Scope, auth, fixture.Trust, fixture.Pins);
        foreach (CurrentAppOwnedV3RepairReceipt changed in new[]
        {
            unsigned with { Kind = "current-app-owned-eight-receipt-v1" },
            unsigned with { BeforeSha256 = new string('9', 64) },
            unsigned with { OperationId = Guid.NewGuid() },
            unsigned with { AfterSha256 = null },
            unsigned with { Classification = (CurrentAppOwnedCommitClassification)99 },
        })
        {
            _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlCurrentAppOwnedV3Repair.RequireReceipt(
                fixture.SignReceipt(changed), fixture.Scope, auth, fixture.Trust, fixture.Pins));
        }
        _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlCurrentAppOwnedV3Repair.RequireReceipt(
            receipt with { Signature = Convert.ToBase64String(new byte[64]) }, fixture.Scope, auth, fixture.Trust, fixture.Pins));
    }
    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }

    private sealed class Environment : ICurrentAppOwnedV3RepairEnvironment
    {
        internal IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> Fleet { get; set; } = [];
        internal List<string> Publications { get; } = [];
        internal int PublicationAttempts { get; private set; }
        internal bool FailPublication { get; set; }
        internal bool RetainBeforeFailure { get; set; }
        internal string? RaceSlot { get; set; }
        internal int SourceCalls { get; private set; }
        private readonly Lock _gate = new();
        public Task RequireSourceAsync(string sourceCommitSha, CancellationToken cancellationToken) { SourceCalls++; return Task.CompletedTask; }
        public Task RequireResourceAndCustodyAsync(CurrentAppOwnedV3RepairScope scope, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CurrentAppOwnedV3RepairScope scope, CancellationToken cancellationToken)
        {
            return Task.FromResult(Fleet);
        }

        public Task RequireFreshOperationAsync(CurrentAppOwnedV3RepairScope scope, CancellationToken cancellationToken)
        {
            return Publications.Any(x => x.StartsWith(scope.OperationId.ToString("D") + "-", StringComparison.Ordinal))
                ? Task.FromException(CurrentAppOwnedV3RepairPermit.Invalid()) : Task.CompletedTask;
        }
        public Task ReserveFreshOperationAsync(CurrentAppOwnedV3RepairScope scope, string authorizationSha256, CancellationToken cancellationToken)
        {
            lock (_gate)
            {
                if (RaceSlot is not null) { Publications.Add($"{scope.OperationId:D}-{RaceSlot}.json"); }
                return Publications.Any(x => x.StartsWith(scope.OperationId.ToString("D") + "-", StringComparison.Ordinal))
                    ? Task.FromException(CurrentAppOwnedV3RepairPermit.Invalid())
                    : RetainNewEvidenceAsync($"{scope.OperationId:D}-v3-operation-start.json",
                    JsonSerializer.SerializeToUtf8Bytes(new { scope.OperationId, AuthorizationSha256 = authorizationSha256 }), cancellationToken);
            }
        }
        public Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken cancellationToken)
        {
            PublicationAttempts++;
            if (!FailPublication || RetainBeforeFailure)
            {
                if (Publications.Contains(name, StringComparer.Ordinal)) { throw new IOException("CREATE_NEW conflict"); }
                Publications.Add(name);
            }
            return FailPublication ? Task.FromException(new IOException("fixture publication failure")) : Task.CompletedTask;
        }
    }

    private sealed class Claims : IDisposable
    {
        private readonly ECDsa _review = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _authorization = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _receipt = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        internal DateTimeOffset Now { get; } = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        internal FreshSchemaPlan Before { get; }
        internal FreshSchemaPlan After { get; }
        internal ReceiptAttestationTrustStore Trust { get; }
        internal CurrentAppOwnedRepairSigningPins Pins { get; }
        internal CurrentAppOwnedV3RepairScope Scope { get; }
        internal CurrentAppOwnedV3RepairSignedClaim Review { get; }
        internal CurrentAppOwnedV3RepairSignedClaim Authorization { get; }
        internal Environment Environment { get; } = new();
        internal Claims()
        {
            Before = WithOutboxes(CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2));
            After = Before with { Databases = [.. Before.Databases.Select(Reprofile)] };
            Trust = new([new("v3-review", _review.ExportSubjectPublicKeyInfo()),
                new("v3-authorization", _authorization.ExportSubjectPublicKeyInfo()), new("v3-receipt", _receipt.ExportSubjectPublicKeyInfo())]);
            _ = Trust.TryGetPublicKeyFingerprintSha256("v3-review", out string review);
            _ = Trust.TryGetPublicKeyFingerprintSha256("v3-authorization", out string authorization);
            _ = Trust.TryGetPublicKeyFingerprintSha256("v3-receipt", out string receipt);
            Pins = new("v3-review", review, "v3-authorization", authorization, "v3-receipt", receipt);
            Environment.Fleet = DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"])
                .Select(x => new CurrentAppOwnedDatabaseSnapshot(x, [], [], [])).ToArray();
            var preimages = Environment.Fleet.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal);
            Scope = new(Guid.NewGuid(), CurrentAppOwnedV3RepairOperation.AppendFourNullableColumnsAndCreateThreeTables, new string('a', 40),
                SchemaPlanCanonicalizer.ComputeSha256(Before), SchemaPlanCanonicalizer.ComputeSha256(After),
                CurrentAppOwnedV3AdditiveContract.Create(Before, After, new string('a', 40), Now).ComputeSha256(),
                new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/persistent-aaaaaaaaaaaa", new string('d', 64)),
                "local-aspire", "legacy-postgres-main-local", "docker:" + new string('a', 64) + ":1:2:3",
                new string('e', 64), new string('f', 64), preimages, CurrentAppOwnedV3RepairPermit.FleetSha256(preimages),
                new string('c', 64), new string('d', 64), new string('e', 64),
                new("legacy_v3_fixture", "legacy-maliev-current-app-owned-v3-v1:" + new string('f', 64),
                    Now.AddMinutes(-1), Now.AddHours(3), Now.AddMinutes(-2), Now.AddMinutes(-2), new string('b', 64), new string('c', 64), "/fixture/pg_hba.conf"));
            (Review, Authorization) = SignPair(Scope);
        }
        internal CurrentAppOwnedV3RepairReceipt SignReceipt(CurrentAppOwnedV3RepairReceipt value)
        {
            byte[] payload = [.. "Legacy.Maliev.CurrentAppOwnedV3.Receipt.v1\0"u8,
                .. JsonSerializer.SerializeToUtf8Bytes(value with { Signature = null })];
            return value with { Signature = Convert.ToBase64String(_receipt.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) };
        }
        internal P256MigrationEvidenceSigner ReviewSigner()
        {
            return new(Pins.ReviewKeyId, _review.ExportECPrivateKeyPem());
        }

        internal P256MigrationEvidenceSigner AuthorizationSigner()
        {
            return new(Pins.AuthorizationKeyId, _authorization.ExportECPrivateKeyPem());
        }

        internal Task<CurrentAppOwnedV3RepairPermit> Admit()
        {
            return CurrentAppOwnedV3RepairPermit.AdmitAsync(
                    Review, Authorization, Before, After, Trust, Pins, Environment, new FixedTime(Now), CancellationToken.None);
        }

        internal (CurrentAppOwnedV3RepairSignedClaim Review, CurrentAppOwnedV3RepairSignedClaim Authorization) SignPair(CurrentAppOwnedV3RepairScope scope)
        {
            var review = Sign(new("current-app-owned-v3-review-v1", scope, Guid.NewGuid(), null, Now.AddMinutes(-1), Now.AddHours(1), Pins.ReviewKeyId, null), _review);
            var authorization = Sign(new("current-app-owned-v3-authorization-v1", scope, Guid.NewGuid(), CurrentAppOwnedV3RepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(review)), Now, Now.AddMinutes(15), Pins.AuthorizationKeyId, null), _authorization);
            return (review, authorization);
        }
        private static CurrentAppOwnedV3RepairSignedClaim Sign(CurrentAppOwnedV3RepairSignedClaim value, ECDsa key)
        {
            return value with
            {
                Signature = Convert.ToBase64String(key.SignData(CurrentAppOwnedV3RepairPermit.Payload(value), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            };
        }

        public void Dispose() { _review.Dispose(); _authorization.Dispose(); _receipt.Dispose(); }
    }

    private static DatabaseSchemaPlan Reprofile(DatabaseSchemaPlan plan)
    {
        plan = plan with { TargetExtensionProfile = ApprovedConsumerOverlaySelection.ProfileForDatabase(plan.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3) };
        return plan with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(plan) };
    }

    private static FreshSchemaPlan WithOutboxes(FreshSchemaPlan schema)
    {
        return schema with { Databases = [.. schema.Databases.Select(database => database.Database == "Quotation" ? Map(database) : database)] };
        static DatabaseSchemaPlan Map(DatabaseSchemaPlan database)
        {
            TableCopyPlan[] tables = [database.Tables[0],
                ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                    "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
                ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                    "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false), .. database.Tables.Skip(3)];
            database = database with
            {
                Tables = tables,
                SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
                SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables)
            };
            return database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
        }
    }
}
