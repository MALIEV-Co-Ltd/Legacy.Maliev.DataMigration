using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAppOwnedRepairAdmissionTests
{
    [Fact]
    public void Genuine_distinct_signed_claims_require_review_authorization_scope_and_fresh_window()
    {
        using var fixture = new Claims();
        CurrentAppOwnedRepairPermit.ValidateClaims(fixture.Review, fixture.Authorization, fixture.Trust, fixture.Pins, fixture.Now);
        foreach (string fault in new[] { "expired", "future", "review-binding", "wrong-key", "wrong-operation", "missing-proof",
            "wrong-namespace", "wrong-source", "scope-cas", "missing-database", "lease-expired", "signature" })
        {
            CurrentAppOwnedRepairSignedClaim changed = fault switch
            {
                "expired" => fixture.Authorization with { ExpiresAtUtc = fixture.Now },
                "future" => fixture.Authorization with { IssuedAtUtc = fixture.Now.AddSeconds(1) },
                "review-binding" => fixture.Authorization with { ReviewSha256 = new string('e', 64) },
                "wrong-key" => fixture.Authorization with { KeyId = fixture.Pins.ReviewKeyId },
                "wrong-operation" => fixture.Authorization with { Scope = fixture.Scope with { Operation = CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations } },
                "missing-proof" => fixture.Authorization with { Scope = fixture.Scope with { NativeProofSha256 = string.Empty } },
                "wrong-namespace" => fixture.Authorization with { Scope = fixture.Scope with { TargetNamespace = "maliev" } },
                "wrong-source" => fixture.Authorization with { Scope = fixture.Scope with { SourceCommitSha = "unaccepted" } },
                "scope-cas" => fixture.Authorization with { Scope = fixture.Scope with { GlobalPreservationSha256 = new string('e', 64) } },
                "missing-database" => fixture.Authorization with { Scope = fixture.Scope with { BeforeDatabaseSha256 = new Dictionary<string, string>() } },
                "lease-expired" => fixture.Authorization with { Scope = fixture.Scope with { Maintenance = fixture.Scope.Maintenance with { ExpiresAtUtc = fixture.Now } } },
                _ => fixture.Authorization with { Signature = Convert.ToBase64String(new byte[64]) },
            };
            _ = Assert.Throws<MigrationExecutionException>(() =>
                CurrentAppOwnedRepairPermit.ValidateClaims(fixture.Review, changed, fixture.Trust, fixture.Pins, fixture.Now));
        }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairPermit.ValidateClaims(fixture.Review, fixture.Authorization,
            fixture.Trust, fixture.Pins with { ReceiptFingerprint = fixture.Pins.AuthorizationFingerprint }, fixture.Now));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairPermit.ValidateClaims(fixture.Review,
            fixture.Authorization, fixture.Trust, fixture.Pins, fixture.Now.AddMinutes(16)));
    }

    [Fact]
    public void Full_preservation_rejects_old_rows_catalog_sequence_effect_and_unreviewed_new_objects()
    {
        var before = new CurrentAppOwnedDatabaseSnapshot("Customer",
            [new("pg_class", "101", new string('a', 64), "1259", "101")],
            [new("public", "Customer", 2, new string('b', 64)), new("legacy_migration_internal", "delta_journal", 8, new string('c', 64))],
            [new("public", "Customer_ID_seq", "legacy_local", new string('d', 64))]);
        IReadOnlySet<string> closure = new HashSet<string>(StringComparer.Ordinal) { "1259/202" };
        var after = before with
        {
            Catalog = [.. before.Catalog, new("pg_class", "202", new string('e', 64), "1259", "202")],
            Relations = [.. before.Relations, new("public", "CustomerCreateOperation", 0, new string('f', 64))],
        };
        CurrentAppOwnedRepairPreservation.RequirePreserved(before, after, closure, ["CustomerCreateOperation"]);
        foreach (string fault in new[] { "catalog", "source-row", "journal-row", "sequence", "extra-role", "new-data", "missing-old" })
        {
            CurrentAppOwnedDatabaseSnapshot changed = fault switch
            {
                "catalog" => after with { Catalog = [after.Catalog[0] with { Sha256 = new string('9', 64) }, after.Catalog[1]] },
                "source-row" => after with { Relations = [after.Relations[0] with { RowSha256 = new string('9', 64) }, .. after.Relations.Skip(1)] },
                "journal-row" => after with { Relations = [after.Relations[0], after.Relations[1] with { RowSha256 = new string('9', 64) }, after.Relations[2]] },
                "sequence" => after with { Sequences = [after.Sequences[0] with { TupleSha256 = new string('9', 64) }] },
                "extra-role" => after with { Catalog = [.. after.Catalog, new("pg_authid", "303", new string('9', 64), "1260", "303")] },
                "new-data" => after with { Relations = [after.Relations[0], after.Relations[1], after.Relations[2] with { Rows = 1 }] },
                _ => after with { Relations = [.. after.Relations.Skip(1)] },
            };
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairPreservation.RequirePreserved(before, changed, closure, ["CustomerCreateOperation"]));
        }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairPreservation.RequirePreserved(before, after,
            new HashSet<string>(StringComparer.Ordinal), ["CustomerCreateOperation"]));
    }

    [Theory]
    [InlineData(false, false, false, 3)]
    [InlineData(false, false, true, 2)]
    [InlineData(true, false, false, 4)]
    [InlineData(true, true, false, 4)]
    [InlineData(true, true, true, 4)]
    public void Commit_acknowledgement_or_readback_failure_is_not_fabricated_as_rollback(
        bool started, bool acknowledged, bool rollback, int expected)
    {
        Assert.Equal((CurrentAppOwnedCommitClassification)expected, PostgreSqlCurrentAppOwnedEightRepair.ClassifyFailure(started, acknowledged, rollback));
    }

    private sealed class Claims : IDisposable
    {
        private readonly ECDsa _review = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _authorization = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _receipt = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        internal DateTimeOffset Now { get; } = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        internal ReceiptAttestationTrustStore Trust { get; }
        internal CurrentAppOwnedRepairSigningPins Pins { get; }
        internal CurrentAppOwnedRepairScope Scope { get; }
        internal CurrentAppOwnedRepairSignedClaim Review { get; }
        internal CurrentAppOwnedRepairSignedClaim Authorization { get; }
        internal Claims()
        {
            Trust = new([
                new("eight-review", _review.ExportSubjectPublicKeyInfo()),
                new("eight-authorization", _authorization.ExportSubjectPublicKeyInfo()),
                new("eight-receipt", _receipt.ExportSubjectPublicKeyInfo())
            ]);
            _ = Trust.TryGetPublicKeyFingerprintSha256("eight-review", out string review);
            _ = Trust.TryGetPublicKeyFingerprintSha256("eight-authorization", out string authorization);
            _ = Trust.TryGetPublicKeyFingerprintSha256("eight-receipt", out string receipt);
            Pins = new("eight-review", review, "eight-authorization", authorization, "eight-receipt", receipt);
            var preimages = CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.CreateEightTables)
                .ToDictionary(x => x, _ => new string('b', 64), StringComparer.Ordinal);
            Scope = new(Guid.NewGuid(), CurrentAppOwnedRepairOperation.CreateEightTables, new string('a', 40),
                new string('b', 64), new string('c', 64),
                CurrentAppOwnedRepairManifest.OperationSha256(CurrentAppOwnedRepairOperation.CreateEightTables),
                new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/persistent-aaaaaaaaaaaa", new string('d', 64)),
                "local-aspire", "legacy-postgres-main-local", "docker:" + new string('a', 64) + ":1:2:3",
                new string('e', 64), new string('f', 64), preimages, new string('b', 64), new string('c', 64),
                new string('d', 64), new string('e', 64),
                new("legacy_eight_fixture", "legacy-maliev-current-app-owned-eight-v1:" + new string('f', 64),
                    Now.AddMinutes(-1), Now.AddHours(3), Now.AddMinutes(-2), Now.AddMinutes(-2),
                    new string('b', 64), new string('c', 64), "/fixture/pg_hba.conf"));
            CurrentAppOwnedRepairSignedClaim unsignedReview = new("current-app-owned-eight-review-v1", Scope,
                Guid.NewGuid(), null, Now.AddMinutes(-1), Now.AddHours(1), Pins.ReviewKeyId, null);
            Review = Sign(unsignedReview, _review);
            CurrentAppOwnedRepairSignedClaim unsignedAuthorization = new("current-app-owned-eight-authorization-v1", Scope,
                Guid.NewGuid(), CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(Review)),
                Now, Now.AddMinutes(15), Pins.AuthorizationKeyId, null);
            Authorization = Sign(unsignedAuthorization, _authorization);
        }
        private static CurrentAppOwnedRepairSignedClaim Sign(CurrentAppOwnedRepairSignedClaim value, ECDsa key)
        {
            return value with
            {
                Signature = Convert.ToBase64String(key.SignData(CurrentAppOwnedRepairPermit.Payload(value),
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            };
        }

        public void Dispose() { _review.Dispose(); _authorization.Dispose(); _receipt.Dispose(); }
    }
}