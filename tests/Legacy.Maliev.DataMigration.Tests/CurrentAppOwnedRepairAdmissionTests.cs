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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Historical_receipts_authenticate_expired_claims_without_issuing_a_permit(bool committed)
    {
        using var fixture = new Claims();
        var prepared = fixture.Receipt("Customer", CurrentAppOwnedCommitClassification.Prepared, new string('0', 64), 1);
        var artifacts = new List<CurrentAppOwnedRetainedReceipt> { Artifact(prepared, "prepared") };
        if (committed)
        {
            var terminal = fixture.Receipt("Customer", CurrentAppOwnedCommitClassification.CommittedAndReadback,
                CurrentAppOwnedRepairPermit.Hash(artifacts[0].ExactBytes), 2);
            artifacts.Add(Artifact(terminal, "committed-readback"));
        }
        CurrentAppOwnedHistoricalTranscript history = CurrentAppOwnedRepairHistory.Authenticate(
            JsonSerializer.SerializeToUtf8Bytes(fixture.Review), JsonSerializer.SerializeToUtf8Bytes(fixture.Authorization),
            artifacts, fixture.Trust, fixture.Pins, fixture.Now.AddDays(1));
        Assert.Equal(fixture.Scope.OperationId, history.OperationId);
        Assert.Equal(new string('c', 64), history.Databases[0].PreparedAfterSha256);
        Assert.Null(history.Databases[1].PreparedAfterSha256);
        Assert.Equal(committed ? CurrentAppOwnedCommitClassification.CommittedAndReadback : null,
            history.Databases[0].TerminalClassification);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairPermit.ValidateClaims(
            fixture.Review, fixture.Authorization, fixture.Trust, fixture.Pins, fixture.Now.AddDays(1)));
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("before")]
    [InlineData("chain")]
    [InlineData("name")]
    [InlineData("future")]
    [InlineData("duplicate")]
    [InlineData("later-database")]
    [InlineData("terminal-without-prepared")]
    [InlineData("noncanonical")]
    [InlineData("unknown-field")]
    [InlineData("duplicate-field")]
    public void Historical_receipt_authentication_rejects_forgery_contradiction_and_unreviewed_shapes(string fault)
    {
        using var fixture = new Claims();
        CurrentAppOwnedRepairReceipt prepared = fixture.Receipt("Customer", CurrentAppOwnedCommitClassification.Prepared,
            new string('0', 64), 1);
        prepared = fault switch
        {
            "signature" => prepared with { Signature = Convert.ToBase64String(new byte[64]) },
            "before" => fixture.SignReceipt(prepared with { BeforeSha256 = new string('e', 64) }),
            "chain" => fixture.SignReceipt(prepared with { PreviousReceiptSha256 = new string('e', 64) }),
            "future" => fixture.SignReceipt(prepared with { ObservedAtUtc = fixture.Now.AddDays(2) }),
            _ => prepared,
        };
        var artifact = Artifact(prepared, "prepared");
        if (fault == "name") { artifact = artifact with { Name = "unbound.json" }; }
        if (fault == "noncanonical") { artifact = artifact with { ExactBytes = [.. artifact.ExactBytes, (byte)' '] }; }
        if (fault == "unknown-field")
        { artifact = artifact with { ExactBytes = [.. "{\"Ignored\":true,"u8, .. artifact.ExactBytes.Skip(1)] }; }
        if (fault == "duplicate-field")
        { artifact = artifact with { ExactBytes = [.. "{\"Kind\":\"current-app-owned-eight-receipt-v1\","u8, .. artifact.ExactBytes.Skip(1)] }; }
        var artifacts = new List<CurrentAppOwnedRetainedReceipt> { artifact };
        if (fault == "duplicate") { artifacts.Add(artifact); }
        if (fault == "later-database")
        { artifacts.Add(Artifact(fixture.Receipt("Order", CurrentAppOwnedCommitClassification.Prepared, new string('0', 64), 2), "prepared")); }
        if (fault == "terminal-without-prepared")
        {
            artifacts.Clear();
            artifacts.Add(Artifact(fixture.Receipt("Customer", CurrentAppOwnedCommitClassification.CommittedAndReadback,
                new string('0', 64), 2), "committed-readback"));
        }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairHistory.Authenticate(
            JsonSerializer.SerializeToUtf8Bytes(fixture.Review), JsonSerializer.SerializeToUtf8Bytes(fixture.Authorization),
            artifacts, fixture.Trust, fixture.Pins, fixture.Now.AddDays(1)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Historical_prepared_publication_failure_preserves_both_authentic_acknowledgment_forms(bool acknowledgmentReturned)
    {
        using var fixture = new Claims();
        var prepared = Artifact(fixture.Receipt("Customer", CurrentAppOwnedCommitClassification.Prepared, new string('0', 64), 1), "prepared");
        var failure = Artifact(fixture.Receipt("Customer", CurrentAppOwnedCommitClassification.RolledBackBeforeCommit,
            acknowledgmentReturned ? CurrentAppOwnedRepairPermit.Hash(prepared.ExactBytes) : new string('0', 64), 2), "failed-or-uncertain");
        var history = CurrentAppOwnedRepairHistory.Authenticate(JsonSerializer.SerializeToUtf8Bytes(fixture.Review),
            JsonSerializer.SerializeToUtf8Bytes(fixture.Authorization), [failure, prepared], fixture.Trust, fixture.Pins, fixture.Now.AddDays(1));
        Assert.Equal(!acknowledgmentReturned, history.Databases[0].PreparedPublicationUncertain);
        Assert.Equal(CurrentAppOwnedCommitClassification.RolledBackBeforeCommit, history.Databases[0].TerminalClassification);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Historical_committed_publication_failure_keeps_both_terminals_without_claiming_success(bool contradictory)
    {
        using var fixture = new Claims();
        var prepared = Artifact(fixture.Receipt("Customer", CurrentAppOwnedCommitClassification.Prepared, new string('0', 64), 1), "prepared");
        string preparedHash = CurrentAppOwnedRepairPermit.Hash(prepared.ExactBytes);
        var committed = Artifact(fixture.Receipt("Customer", CurrentAppOwnedCommitClassification.CommittedAndReadback, preparedHash, 2), "committed-readback");
        var uncertain = fixture.Receipt("Customer", CurrentAppOwnedCommitClassification.Uncertain, preparedHash, 3);
        if (contradictory) { uncertain = fixture.SignReceipt(uncertain with { AfterSha256 = new string('e', 64) }); }
        CurrentAppOwnedRetainedReceipt[] artifacts = [committed, Artifact(uncertain, "failed-or-uncertain"), prepared];
        if (contradictory)
        {
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairHistory.Authenticate(
                JsonSerializer.SerializeToUtf8Bytes(fixture.Review), JsonSerializer.SerializeToUtf8Bytes(fixture.Authorization),
                artifacts, fixture.Trust, fixture.Pins, fixture.Now.AddDays(1)));
        }
        else
        {
            var history = CurrentAppOwnedRepairHistory.Authenticate(JsonSerializer.SerializeToUtf8Bytes(fixture.Review),
                JsonSerializer.SerializeToUtf8Bytes(fixture.Authorization), artifacts, fixture.Trust, fixture.Pins, fixture.Now.AddDays(1));
            Assert.True(history.Databases[0].CommittedPublicationUncertain);
            Assert.Equal(CurrentAppOwnedCommitClassification.Uncertain, history.Databases[0].TerminalClassification);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Historical_late_receipts_are_timing_provenance_without_renewing_execution(bool committed)
    {
        using var fixture = new Claims();
        var prepared = Artifact(fixture.Receipt("Customer", CurrentAppOwnedCommitClassification.Prepared, new string('0', 64), 901), "prepared");
        var artifacts = new List<CurrentAppOwnedRetainedReceipt> { prepared };
        if (committed)
        {
            artifacts.Add(Artifact(fixture.Receipt("Customer", CurrentAppOwnedCommitClassification.CommittedAndReadback,
                CurrentAppOwnedRepairPermit.Hash(prepared.ExactBytes), 902), "committed-readback"));
        }
        var history = CurrentAppOwnedRepairHistory.Authenticate(JsonSerializer.SerializeToUtf8Bytes(fixture.Review),
            JsonSerializer.SerializeToUtf8Bytes(fixture.Authorization), artifacts, fixture.Trust, fixture.Pins, fixture.Now.AddDays(1));
        Assert.False(history.Databases[0].ReceiptTimesWithinAuthorizationWindow);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Historical_cross_database_chain_authenticates_complete_prefix_and_final_publication_uncertainty(bool finalPublicationFailure)
    {
        using var fixture = new Claims();
        var artifacts = new List<CurrentAppOwnedRetainedReceipt>();
        string previous = new('0', 64);
        int seconds = 0;
        foreach (string database in CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.CreateEightTables))
        {
            var prepared = Artifact(fixture.Receipt(database, CurrentAppOwnedCommitClassification.Prepared, previous, ++seconds), "prepared");
            previous = CurrentAppOwnedRepairPermit.Hash(prepared.ExactBytes);
            var committed = Artifact(fixture.Receipt(database, CurrentAppOwnedCommitClassification.CommittedAndReadback, previous, ++seconds), "committed-readback");
            artifacts.Add(prepared); artifacts.Add(committed);
            if (database == "Upload" && finalPublicationFailure)
            {
                artifacts.Add(Artifact(fixture.Receipt(database, CurrentAppOwnedCommitClassification.Uncertain, previous, ++seconds), "failed-or-uncertain"));
            }
            previous = CurrentAppOwnedRepairPermit.Hash(committed.ExactBytes);
        }
        var first = CurrentAppOwnedRepairHistory.Authenticate(JsonSerializer.SerializeToUtf8Bytes(fixture.Review),
            JsonSerializer.SerializeToUtf8Bytes(fixture.Authorization), artifacts, fixture.Trust, fixture.Pins, fixture.Now.AddDays(1));
        artifacts.Reverse();
        var reversed = CurrentAppOwnedRepairHistory.Authenticate(JsonSerializer.SerializeToUtf8Bytes(fixture.Review),
            JsonSerializer.SerializeToUtf8Bytes(fixture.Authorization), artifacts, fixture.Trust, fixture.Pins, fixture.Now.AddDays(1));
        Assert.Equal(first.ReceiptManifestSha256, reversed.ReceiptManifestSha256);
        Assert.Equal(finalPublicationFailure ? CurrentAppOwnedCommitClassification.Uncertain : CurrentAppOwnedCommitClassification.CommittedAndReadback,
            first.Databases[^1].TerminalClassification);
    }

    private static CurrentAppOwnedRetainedReceipt Artifact(CurrentAppOwnedRepairReceipt receipt, string suffix)
    {
        return new($"{receipt.OperationId:D}-{receipt.Database}-{suffix}.json", JsonSerializer.SerializeToUtf8Bytes(receipt));
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
        internal CurrentAppOwnedRepairReceipt Receipt(string database, CurrentAppOwnedCommitClassification classification,
            string previous, int seconds)
        {
            return SignReceipt(new("current-app-owned-eight-receipt-v1", Scope.OperationId, database,
                Scope.OperationSha256, Scope.BeforeDatabaseSha256[database], new string('c', 64),
                CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(Authorization)), previous,
                classification, Now.AddSeconds(seconds), Pins.ReceiptKeyId, null));
        }
        internal CurrentAppOwnedRepairReceipt SignReceipt(CurrentAppOwnedRepairReceipt value)
        {
            byte[] payload = [.. "Legacy.Maliev.CurrentAppOwnedEight.Receipt.v1\0"u8,
                .. JsonSerializer.SerializeToUtf8Bytes(value with { Signature = null })];
            return value with
            {
                Signature = Convert.ToBase64String(_receipt.SignData(payload,
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            };
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
