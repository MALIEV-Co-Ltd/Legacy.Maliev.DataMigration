using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAppOwnedRetained31AdmissionTests
{
    [Fact]
    public void Pure_review_validation_rejects_invalid_or_expired_signature_without_environment()
    {
        using var f = new Fixture();
        var (review, _) = f.Claims(f.Scope);
        CurrentAppOwnedRetained31Permit.ValidateReview(review, f.Before, f.After, f.Trust, f.Pins, f.Now);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Permit.ValidateReview(
            review with { Signature = Convert.ToBase64String(new byte[64]) }, f.Before, f.After, f.Trust, f.Pins, f.Now));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Permit.ValidateReview(
            review, f.Before, f.After, f.Trust, f.Pins, review.ExpiresAtUtc));
    }

    [Theory]
    [InlineData("missing-control")]
    [InlineData("missing-shadow")]
    [InlineData("substituted-shadow")]
    [InlineData("extra")]
    public void Re_signed_production_fleet_change_is_not_authority(string fault)
    {
        using var f = new Fixture(production: true);
        var hashes = f.Scope.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
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
        var changed = f.Scope with { BeforeDatabaseSha256 = hashes };
        var (review, authorization) = f.Claims(changed);
        Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Permit.ValidateClaims(review, authorization,
            f.Before, f.After, f.Trust, f.Pins, f.Now));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Genuine_issuer_authorization_and_single_use_reservation_bind_complete_target_fleet(bool production)
    {
        using var f = new Fixture(production);
        var review = await CurrentAppOwnedRetained31Permit.IssueReviewAsync(f.Scope, f.Before, f.After, f.Baseline,
            f.Trust, f.Pins, f.Environment, f.ReviewSigner, f.Now.AddHours(1), f.Clock, default);
        var authorization = await CurrentAppOwnedRetained31Permit.AuthorizeAsync(review, f.Before, f.After, f.Trust,
            f.Pins, f.Environment, f.AuthorizationSigner, f.Clock, default);
        CurrentAppOwnedRetained31Permit permit = await CurrentAppOwnedRetained31Permit.AdmitAsync(review, authorization,
            f.Before, f.After, f.Trust, f.Pins, f.Environment, f.Clock, default);
        Assert.Equal(production ? 49 : 26, permit.Scope.BeforeDatabaseSha256.Count);
        Assert.Equal(CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations, permit.Scope.Operation);
        Assert.Equal(f.Scope.ContractSha256, permit.Scope.ContractSha256);
        Assert.Equal(f.Now.AddMinutes(15), authorization.ExpiresAtUtc);
        Assert.Equal(0, f.Environment.Reservations);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireExecutionAsync(default));
        await permit.BeginExecutionAsync(default);
        Assert.Equal(1, f.Environment.Reservations);
        Assert.Equal(permit.AuthorizationSha256, f.Environment.ReservedAuthorization);
        await permit.RequireExecutionAsync(default);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.BeginExecutionAsync(default));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAppOwnedRetained31Permit.AdmitAsync(review,
            authorization, f.Before, f.After, f.Trust, f.Pins, f.Environment, f.Clock, default));
        permit.Stop();
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireExecutionAsync(default));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireAsync(default));
        Assert.Equal(1, f.Environment.Reservations);
    }

    [Theory]
    [InlineData("operation")]
    [InlineData("contract")]
    [InlineData("literal")]
    [InlineData("source")]
    [InlineData("before-plan")]
    [InlineData("after-plan")]
    [InlineData("target-kind")]
    [InlineData("namespace")]
    [InlineData("system-id")]
    [InlineData("fleet-count")]
    [InlineData("fleet-name")]
    [InlineData("fleet-hash")]
    [InlineData("native-proof")]
    [InlineData("recovery-policy")]
    [InlineData("role-comment")]
    [InlineData("lease")]
    [InlineData("hba")]
    public void Resigned_scope_mutations_cannot_convert_other_authority_or_omit_preservation(string fault)
    {
        using var f = new Fixture();
        CurrentAppOwnedRetained31Scope changed = fault switch
        {
            "operation" => f.Scope with { Operation = CurrentAppOwnedRepairOperation.CreateEightTables },
            "contract" => f.Scope with { ContractSha256 = new string('9', 64) },
            "literal" => f.Scope with { OperationSha256 = new string('9', 64) },
            "source" => f.Scope with { SourceCommitSha = new string('9', 40) },
            "before-plan" => f.Scope with { BeforeSchemaPlanSha256 = new string('9', 64) },
            "after-plan" => f.Scope with { AfterSchemaPlanSha256 = new string('9', 64) },
            "target-kind" => f.Scope with { Target = f.Scope.Target with { Kind = DeltaTargetAuthorityKind.ProductionCloudNativePg } },
            "namespace" => f.Scope with { TargetNamespace = "maliev" },
            "system-id" => f.Scope with { Target = f.Scope.Target with { SystemIdentifierSha256 = "marker" } },
            "fleet-count" => f.Scope with { BeforeDatabaseSha256 = f.Scope.BeforeDatabaseSha256.Skip(1).ToDictionary(x => x.Key, x => x.Value) },
            "fleet-name" => f.Scope with { BeforeDatabaseSha256 = f.Scope.BeforeDatabaseSha256.ToDictionary(x => x.Key == "Invoice" ? "unreviewed" : x.Key, x => x.Value) },
            "fleet-hash" => f.Scope with { BeforeDatabaseSha256 = f.Scope.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Key == "Auth" ? "marker" : x.Value) },
            "native-proof" => f.Scope with { NativeProofSha256 = string.Empty },
            "recovery-policy" => f.Scope with { RecoveryPolicy = "resume-old-operation" },
            "role-comment" => f.Scope with { Maintenance = f.Scope.Maintenance with { RoleComment = "legacy-maliev-current-app-owned-eight-v1:" + f.Scope.RunBindingSha256 } },
            "lease" => f.Scope with { Maintenance = f.Scope.Maintenance with { ExpiresAtUtc = f.Now.AddHours(5) } },
            _ => f.Scope with { Maintenance = f.Scope.Maintenance with { HbaRulesSha256 = string.Empty } },
        };
        var (review, authorization) = f.Claims(changed);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Permit.ValidateClaims(review,
            authorization, f.Before, f.After, f.Trust, f.Pins, f.Now));
    }

    [Theory]
    [InlineData("eight-kind")]
    [InlineData("signature")]
    [InlineData("link")]
    [InlineData("nonce")]
    [InlineData("key")]
    [InlineData("expired")]
    [InlineData("future")]
    [InlineData("review-expiry")]
    [InlineData("maintenance-expiry")]
    public void Signed_authorization_must_be_distinct_fresh_and_link_exact_review(string fault)
    {
        using var f = new Fixture();
        var (review, authorization) = f.Claims(f.Scope);
        authorization = fault switch
        {
            "eight-kind" => authorization with { Kind = "current-app-owned-eight-authorization-v1" },
            "signature" => authorization with { Signature = Convert.ToBase64String(new byte[64]) },
            "link" => authorization with { ReviewSha256 = new string('9', 64) },
            "nonce" => authorization with { Nonce = review.Nonce },
            "key" => authorization with { KeyId = f.Pins.ReviewKeyId },
            "expired" => authorization with { ExpiresAtUtc = f.Now },
            "future" => authorization with { IssuedAtUtc = f.Now.AddSeconds(1) },
            "review-expiry" => authorization with { ExpiresAtUtc = review.ExpiresAtUtc.AddMinutes(1) },
            _ => authorization with { ExpiresAtUtc = f.Scope.Maintenance.ExpiresAtUtc.AddMinutes(1) },
        };
        if (fault != "signature") { authorization = Fixture.Sign(authorization, f.AuthorizationSigner); }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Permit.ValidateClaims(review,
            authorization, f.Before, f.After, f.Trust, f.Pins, f.Now));
    }

    [Fact]
    public void Genuine_claims_reject_reused_key_pins_and_eight_signature_domain()
    {
        using var f = new Fixture();
        var (review, authorization) = f.Claims(f.Scope);
        CurrentAppOwnedRetained31Permit.ValidateClaims(review, authorization, f.Before, f.After, f.Trust, f.Pins, f.Now);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Permit.ValidateClaims(review,
            authorization, f.Before, f.After, f.Trust, f.Pins with { ReceiptKeyId = f.Pins.AuthorizationKeyId }, f.Now));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Permit.ValidateClaims(review,
            authorization, f.Before, f.After, f.Trust, f.Pins with { ReceiptFingerprint = f.Pins.AuthorizationFingerprint }, f.Now));
        byte[] eightPayload = [.. "Legacy.Maliev.CurrentAppOwnedEight.current-app-owned-eight-authorization-v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(authorization with { Signature = null })];
        authorization = authorization with { Signature = Convert.ToBase64String(f.AuthorizationSigner.Sign(eightPayload)) };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Permit.ValidateClaims(review,
            authorization, f.Before, f.After, f.Trust, f.Pins, f.Now));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Authorization_expiry_is_capped_by_both_review_and_installed_maintenance(bool shortReview)
    {
        using var f = new Fixture();
        var scope = f.Scope with { Maintenance = f.Scope.Maintenance with { ExpiresAtUtc = f.Now.AddMinutes(8) } };
        var review = await CurrentAppOwnedRetained31Permit.IssueReviewAsync(scope, f.Before, f.After, f.Baseline,
            f.Trust, f.Pins, f.Environment, f.ReviewSigner, f.Now.AddMinutes(shortReview ? 3 : 30), f.Clock, default);
        var authorization = await CurrentAppOwnedRetained31Permit.AuthorizeAsync(review, f.Before, f.After, f.Trust,
            f.Pins, f.Environment, f.AuthorizationSigner, f.Clock, default);
        Assert.Equal(f.Now.AddMinutes(shortReview ? 3 : 8), authorization.ExpiresAtUtc);
    }

    [Theory]
    [InlineData("baseline")]
    [InlineData("global")]
    [InlineData("custody")]
    [InlineData("retained")]
    public async Task Issuer_cannot_replace_live_or_complete_storage_observation_with_a_marker(string fault)
    {
        using var f = new Fixture();
        IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> baseline = fault == "baseline" ? [.. f.Baseline.Skip(1)] : f.Baseline;
        f.Environment.WrongGlobal = fault == "global";
        f.Environment.RejectCustody = fault == "custody";
        f.Environment.Reserved = fault == "retained";
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAppOwnedRetained31Permit.IssueReviewAsync(
            f.Scope, f.Before, f.After, baseline, f.Trust, f.Pins, f.Environment, f.ReviewSigner, f.Now.AddHours(1), f.Clock, default));
        Assert.Equal(0, f.Environment.Reservations);
    }

    [Fact]
    public async Task Uncertain_reservation_result_stops_permit_and_cannot_be_retried_or_erased()
    {
        using var f = new Fixture();
        var (review, authorization) = f.Claims(f.Scope);
        var permit = await CurrentAppOwnedRetained31Permit.AdmitAsync(review, authorization, f.Before, f.After,
            f.Trust, f.Pins, f.Environment, f.Clock, default);
        f.Environment.FailAfterReservation = true;
        _ = await Assert.ThrowsAsync<IOException>(() => permit.BeginExecutionAsync(default));
        Assert.True(f.Environment.Reserved);
        Assert.Equal(1, f.Environment.Reservations);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.BeginExecutionAsync(default));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireAsync(default));
        Assert.Equal(1, f.Environment.Reservations);
    }

    [Fact]
    public async Task Execution_is_unavailable_while_atomic_reservation_is_pending()
    {
        using var f = new Fixture();
        var (review, authorization) = f.Claims(f.Scope);
        var permit = await CurrentAppOwnedRetained31Permit.AdmitAsync(review, authorization, f.Before, f.After,
            f.Trust, f.Pins, f.Environment, f.Clock, default);
        f.Environment.PauseReservation = true;
        Task begin = permit.BeginExecutionAsync(default);
        try
        {
            Assert.True(f.Environment.Reserved);
            Assert.False(begin.IsCompleted);
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireExecutionAsync(default));
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.BeginExecutionAsync(default));
            permit.Stop();
        }
        finally { f.Environment.ReleaseReservation.SetResult(); }
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => begin);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireExecutionAsync(default));
        Assert.Equal(1, f.Environment.Reservations);
    }

    [Fact]
    public async Task Admitted_scope_and_plans_are_defensive_copies_and_freshness_is_rechecked()
    {
        using var f = new Fixture();
        var (review, authorization) = f.Claims(f.Scope);
        var permit = await CurrentAppOwnedRetained31Permit.AdmitAsync(review, authorization, f.Before, f.After,
            f.Trust, f.Pins, f.Environment, f.Clock, default);
        string digest = permit.Scope.BeforeDatabaseSha256["Invoice"];
        ((IDictionary<string, string>)f.Scope.BeforeDatabaseSha256)["Invoice"] = new string('9', 64);
        ((IDictionary<string, string>)permit.Scope.BeforeDatabaseSha256)["Invoice"] = new string('8', 64);
        ((IDictionary<string, string>)f.Before.Databases[0].Tables[0].ColumnTypes)["Value"] = "integer";
        Assert.Equal(digest, permit.Scope.BeforeDatabaseSha256["Invoice"]);
        await permit.RequireAsync(default);
        f.Clock.Now = f.Now.AddMinutes(16);
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireAsync(default));
    }

    // Component-only fake: none of these tests assert real storage completeness, role/HBA or Console admission.
    private sealed class Environment(string global) : ICurrentAppOwnedRetained31Environment
    {
        internal bool Reserved, WrongGlobal, RejectCustody, FailAfterReservation, PauseReservation;
        internal int Reservations;
        internal string? ReservedAuthorization;
        internal TaskCompletionSource ReleaseReservation { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task RequireSourceAsync(string sourceCommitSha, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task RequireResourceAndCustodyAsync(CurrentAppOwnedRetained31Scope scope, CancellationToken cancellationToken)
        {
            return RejectCustody ? throw CurrentAppOwnedRetained31Permit.Invalid() : Task.CompletedTask;
        }
        public Task<string> InspectGlobalPreservationAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(WrongGlobal ? "marker" : global);
        }

        public Task RequireFreshOperationAsync(CurrentAppOwnedRetained31Scope scope, CancellationToken cancellationToken)
        {
            return Reserved ? throw CurrentAppOwnedRetained31Permit.Invalid() : Task.CompletedTask;
        }
        public async Task ReserveFreshOperationAsync(CurrentAppOwnedRetained31Scope scope, string authorizationSha256, CancellationToken cancellationToken)
        {
            if (Reserved) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            Reserved = true; Reservations++; ReservedAuthorization = authorizationSha256;
            if (PauseReservation) { await ReleaseReservation.Task.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken); }
            if (FailAfterReservation) { throw new IOException("synthetic lost reservation acknowledgement"); }
        }
        public Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task ObserveCommittedDatabaseAsync(CurrentAppOwnedRetained31Receipt prepared, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        internal DateTimeOffset Now = now;
        public override DateTimeOffset GetUtcNow()
        {
            return Now;
        }
    }

    private sealed class Fixture : IDisposable
    {
        internal DateTimeOffset Now { get; } = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        internal Clock Clock { get; }
        internal FreshSchemaPlan Before { get; }
        internal FreshSchemaPlan After { get; }
        internal CurrentAppOwnedDatabaseSnapshot[] Baseline { get; }
        internal CurrentAppOwnedRetained31Scope Scope { get; }
        internal ReceiptAttestationTrustStore Trust { get; }
        internal CurrentAppOwnedRetained31SigningPins Pins { get; }
        internal Environment Environment { get; }
        internal P256MigrationEvidenceSigner ReviewSigner { get; }
        internal P256MigrationEvidenceSigner AuthorizationSigner { get; }
        private readonly ECDsa _receipt = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        internal Fixture(bool production = false)
        {
            Clock = new(Now);
            Before = WithOutboxes(CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerColumnsV1));
            After = WithOutboxes(CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2));
            using ECDsa review = ECDsa.Create(ECCurve.NamedCurves.nistP256), authorization = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            ReviewSigner = new("retained31-review", review.ExportPkcs8PrivateKeyPem());
            AuthorizationSigner = new("retained31-authorization", authorization.ExportPkcs8PrivateKeyPem());
            Trust = new([new(ReviewSigner.KeyId, review.ExportSubjectPublicKeyInfo()),
                new(AuthorizationSigner.KeyId, authorization.ExportSubjectPublicKeyInfo()), new("retained31-receipt", _receipt.ExportSubjectPublicKeyInfo())]);
            _ = Trust.TryGetPublicKeyFingerprintSha256(ReviewSigner.KeyId, out string rf);
            _ = Trust.TryGetPublicKeyFingerprintSha256(AuthorizationSigner.KeyId, out string af);
            _ = Trust.TryGetPublicKeyFingerprintSha256("retained31-receipt", out string ef);
            Pins = new(ReviewSigner.KeyId, rf, AuthorizationSigner.KeyId, af, "retained31-receipt", ef);
            string[] names = production ? ReviewedProductionRepairInventory.ExportProductionNames().ToArray()
                : [.. DatabaseInventory.ActiveDatabases, "Auth", "postgres", "legacy_local"];
            Baseline = [.. names.Order(StringComparer.Ordinal).Select(database => new CurrentAppOwnedDatabaseSnapshot(database,
                [new("pg_class", "1", new string('a', 64), "1259", "1")],
                [new("legacy_migration_internal", "delta_journal", 2, new string('b', 64))],
                [new("public", "retained_sequence", "fixture", new string('c', 64))]))];
            string global = CurrentAppOwnedSnapshotSerialization.Sha256(Baseline);
            string binding = new('d', 64);
            Scope = new(Guid.NewGuid(), CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations, Before.SourceCommitSha,
                SchemaPlanCanonicalizer.ComputeSha256(Before), SchemaPlanCanonicalizer.ComputeSha256(After),
                CurrentAppOwnedRetained31Contract.Create(Before, After, Before.SourceCommitSha, Now).ComputeSha256(),
                CurrentAppOwnedRepairManifest.OperationSha256(CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations),
                new(production ? DeltaTargetAuthorityKind.ProductionCloudNativePg : DeltaTargetAuthorityKind.LocalAspire,
                    production ? "gke://maliev-website/retained31-fixture" : "aspire://legacy-postgres-main-local/persistent-fixture",
                    new string('e', 64)), production ? "maliev-legacy" : "local-aspire", production ? "legacy-postgres-main" : "legacy-postgres-main-local",
                "fixture-generation", new string('f', 64), binding, Baseline.ToDictionary(x => x.Database, x => CurrentAppOwnedSnapshotSerialization.Sha256(x), StringComparer.Ordinal),
                global, new string('a', 64), new string('b', 64), new string('c', 64),
                new("fixture-role", "legacy-maliev-current-app-owned-retained31-v1:" + binding, Now, Now.AddHours(2), Now, Now,
                    new string('a', 64), new string('b', 64), "/fixture/pg_hba.conf"), CurrentAppOwnedRetained31Permit.FreshOnlyPolicy);
            Environment = new(global);
        }

        internal (CurrentAppOwnedRetained31SignedClaim Review, CurrentAppOwnedRetained31SignedClaim Authorization) Claims(CurrentAppOwnedRetained31Scope scope)
        {
            var review = Sign(new("current-app-owned-retained31-review-v1", scope, Guid.NewGuid(), null,
                Now, Now.AddHours(1), ReviewSigner.KeyId, null), ReviewSigner);
            var authorization = Sign(new("current-app-owned-retained31-authorization-v1", scope, Guid.NewGuid(),
                CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(review)), Now, Now.AddMinutes(15), AuthorizationSigner.KeyId, null), AuthorizationSigner);
            return (review, authorization);
        }

        internal static CurrentAppOwnedRetained31SignedClaim Sign(CurrentAppOwnedRetained31SignedClaim value, P256MigrationEvidenceSigner signer)
        {
            return value with { Signature = Convert.ToBase64String(signer.Sign(CurrentAppOwnedRetained31Permit.Payload(value))) };
        }

        public void Dispose() { ReviewSigner.Dispose(); AuthorizationSigner.Dispose(); _receipt.Dispose(); }
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
