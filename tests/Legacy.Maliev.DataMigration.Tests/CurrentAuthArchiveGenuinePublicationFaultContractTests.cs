using System.Text.Json;
using System.Reflection;
using System.Security.Cryptography;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuinePublicationFaultContractTests
{
    private static readonly bool[] JournalModes = [true, false];
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    [InlineData(11)]
    [InlineData(12)]
    [InlineData(13)]
    [InlineData(14)]
    public void Unsupported_publication_slots_return_the_guarded_error(int value)
    {
        var error = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePublicationFault.Slot((CurrentAuthArchiveGenuineExecutionCase)value));
        Assert.Equal("current_auth_archive_genuine_execution_invalid", error.Code);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Exact_native_slot_witness_keeps_the_two_fixed_cases_distinct(bool prepared)
    {
        var data = Witness(prepared);
        CurrentAuthArchiveGenuinePublicationFault.RequireWitness(data.Witness, data.Scope, data.Authorization, data.Case, data.Began, data.Now);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePublicationFault.RequireWitness(data.Witness,
            data.Scope, data.Authorization, prepared ? CurrentAuthArchiveGenuineExecutionCase.TerminalPublication :
                CurrentAuthArchiveGenuineExecutionCase.PreparedPublication, data.Began, data.Now));
    }

    [Theory]
    [InlineData("operation")]
    [InlineData("scope")]
    [InlineData("authorization")]
    [InlineData("local-binding")]
    [InlineData("comparison-binding")]
    [InlineData("slot")]
    [InlineData("root")]
    [InlineData("file-name")]
    [InlineData("volume")]
    [InlineData("zero-volume")]
    [InlineData("file-id")]
    [InlineData("zero-file-id")]
    [InlineData("bytes")]
    [InlineData("owner")]
    [InlineData("delete-on-close")]
    [InlineData("native-error")]
    [InlineData("absent")]
    [InlineData("creation-clock")]
    [InlineData("failure-clock")]
    [InlineData("removal-clock")]
    [InlineData("future-removal")]
    public void Witness_rejects_changed_ownership_filesystem_denial_or_cleanup_facts(string fault)
    {
        foreach (bool prepared in JournalModes)
        {
            var data = Witness(prepared); var witness = data.Witness;
            witness = fault switch
            {
                "operation" => witness with { OperationId = Guid.NewGuid() },
                "scope" => witness with { ScopeSha256 = new string('f', 64) },
                "authorization" => witness with { AuthorizationSha256 = new string('f', 64) },
                "local-binding" => witness with { LocalBindingSha256 = new string('f', 64) },
                "comparison-binding" => witness with { ComparisonBindingSha256 = new string('f', 64) },
                "slot" => witness with { Slot = "operation-start" },
                "root" => witness with { OriginalPath = Path.Combine(Path.GetTempPath(), "unowned", Path.GetFileName(witness.OriginalPath)) },
                "file-name" => witness with { OriginalPath = Path.Combine(Path.GetDirectoryName(witness.OriginalPath)!, "other.json") },
                "volume" => witness with { VolumeIdentity = "windows-ntfs:invented" },
                "zero-volume" => witness with { VolumeIdentity = "windows-ntfs:11111111-1111-1111-1111-111111111111:0000000000000000" },
                "file-id" => witness with { FileIdentity = "file-id-128:invented" },
                "zero-file-id" => witness with { FileIdentity = "file-id-128:" + new string('0', 32) },
                "bytes" => witness with { Bytes = 1 },
                "owner" => witness with { NativeOwnerAndSingleLinkVerified = false },
                "delete-on-close" => witness with { DeleteOnClose = false },
                "native-error" => witness with { NativeCreateError = 2 },
                "absent" => witness with { VerifiedAbsent = false },
                "creation-clock" => witness with { CreatedAtUtc = data.Began.AddSeconds(-1) },
                "failure-clock" => witness with { FailedAtUtc = data.Began },
                "removal-clock" => witness with { RemovedAtUtc = data.Began },
                "future-removal" => witness with { RemovedAtUtc = data.Now.AddSeconds(1) },
                _ => throw new InvalidOperationException(),
            };
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePublicationFault.RequireWitness(witness,
                data.Scope, data.Authorization, data.Case, data.Began, data.Now));
        }
    }

    [Fact]
    public void Serialized_json_cannot_construct_the_owned_denial_hook()
    {
        _ = Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<CurrentAuthArchiveGenuineExecutionIssuer.SlotDenial>("{}"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Fault_candidate_requires_the_recorded_fault_method_return_and_preserves_OS_exit_as_unknown(bool prepared)
    {
        var data = Witness(prepared);
        DateTimeOffset began = DateTimeOffset.UtcNow.AddMinutes(-1), ended = began.AddSeconds(10);
        var artifacts = new CurrentAuthArchiveGenuineDualArtifacts(new("synthetic-stage", new string('a', 64)), began, ended);
        var method = new CurrentAuthArchiveGenuineExecutionMethodResult(1, began, ended.AddSeconds(1), artifacts);
        var (Phase, CaseId) = CurrentAuthArchiveGenuineExecutionCases.Identity(data.Case);
        var stage = JsonSerializer.SerializeToElement(new
        {
            Kind = "current-auth-genuine-execution-incomplete-precleanup-v1",
            Phase,
            CaseId,
            CleanupVerified = false,
            PhaseProofComplete = false,
            ProviderExitCode = (int?)null,
            BeganAtUtc = began,
            EndedAtUtc = ended,
        });
        CurrentAuthArchiveGenuineExecutionRunner.RequireCompletedMethod(stage, data.Case, method);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineExecutionRunner.RequireCompletedMethod(stage, data.Case, method with { ReturnCode = 0 }));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Actual_signed_three_or_four_slot_failure_journal_verifies_exact_chain_and_classification(bool prepared)
    {
        using var fixture = new JournalFixture(prepared);
        var receipts = fixture.Require();
        Assert.Equal(prepared ? 1 : 2, receipts.Length);
        Assert.Equal(prepared ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.Uncertain,
            receipts[^1].Classification);
        if (!prepared) { Assert.Equal(CurrentAppOwnedCommitClassification.Prepared, receipts[0].Classification); }
    }

    [Theory]
    [InlineData("missing-slot")]
    [InlineData("extra-slot")]
    [InlineData("case")]
    [InlineData("scope")]
    [InlineData("reservation-operation")]
    [InlineData("reservation-auth")]
    [InlineData("manifest-scope")]
    [InlineData("manifest-signature")]
    [InlineData("receipt-signature")]
    [InlineData("receipt-signer")]
    [InlineData("classification")]
    [InlineData("chain")]
    [InlineData("before")]
    [InlineData("after")]
    [InlineData("manifest-link")]
    [InlineData("early-receipt")]
    [InlineData("late-receipt")]
    [InlineData("native-error")]
    public void Failure_journal_rejects_tampered_actual_signed_bytes_or_observed_binding(string fault)
    {
        foreach (bool prepared in JournalModes)
        {
            using var fixture = new JournalFixture(prepared);
            switch (fault)
            {
                case "missing-slot": _ = fixture.Journal.Remove("failed-or-uncertain"); break;
                case "extra-slot": fixture.Journal.Add("committed-readback", fixture.Journal["failed-or-uncertain"]); break;
                case "case": fixture.Facts = fixture.Facts with { Case = CurrentAuthArchiveGenuineExecutionCase.NativeComplete }; break;
                case "scope": fixture.Scope = fixture.Scope with { OperationId = Guid.NewGuid() }; break;
                case "reservation-operation": fixture.Reservation(Guid.NewGuid(), fixture.Authorization); break;
                case "reservation-auth": fixture.Reservation(fixture.Scope.OperationId, new string('f', 64)); break;
                case "manifest-scope": fixture.ManifestBytes(fixture.Manifest with { ScopeSha256 = new string('f', 64) }); break;
                case "manifest-signature": fixture.BadSignature("recovery-manifest"); break;
                case "receipt-signature": fixture.BadSignature("failed-or-uncertain"); break;
                case "receipt-signer": fixture.FailureBytes(fixture.FailureReceipt, wrongSigner: true); break;
                case "classification": fixture.FailureBytes(fixture.FailureReceipt with { Classification = CurrentAppOwnedCommitClassification.CommittedAndReadback }); break;
                case "chain": fixture.FailureBytes(fixture.FailureReceipt with { PreviousSha256 = new string('f', 64) }); break;
                case "before": fixture.FailureBytes(fixture.FailureReceipt with { BeforeAuthSha256 = new string('f', 64) }); break;
                case "after": fixture.FailureBytes(fixture.FailureReceipt with { AfterAuthSha256 = new string('f', 64) }); break;
                case "manifest-link": fixture.FailureBytes(fixture.FailureReceipt with { RecoveryManifestSha256 = new string('f', 64) }); break;
                case "early-receipt": fixture.FailureBytes(fixture.FailureReceipt with { ObservedAtUtc = fixture.Facts.BeganAtUtc.AddSeconds(-1) }); break;
                case "late-receipt": fixture.FailureBytes(fixture.FailureReceipt with { ObservedAtUtc = fixture.Failure.FailedAtUtc.AddSeconds(1) }); break;
                case "native-error": fixture.Failure = fixture.Failure with { ActualHResult = unchecked((int)0x80070020) }; break;
                default:
                    break;
            }
            _ = Assert.Throws<MigrationExecutionException>(fixture.Require);
        }
    }

    // Comparator operands only. This fixed data constructor creates no issuer, permit, target or native proof.
    private sealed class JournalFixture : IDisposable
    {
        private readonly P256MigrationEvidenceSigner _reviewer, _authorizer, _evidence;
        private readonly CurrentAuthArchivePins _pins;
        private readonly ReceiptAttestationTrustStore _trust;
        private readonly CurrentAuthArchiveGenuineSlotWitness _witness;
        internal CurrentAuthArchiveScope Scope { get; set; }
        internal CurrentAuthArchiveGenuineExecutionFacts Facts { get; set; }
        internal CurrentAuthArchiveGenuinePublicationFailureFacts Failure { get; set; }
        internal CurrentAuthArchiveRecoveryManifest Manifest { get; }
        internal CurrentAuthArchiveReceipt FailureReceipt { get; }
        internal string Authorization { get; }
        internal Dictionary<string, byte[]> Journal { get; } = new(StringComparer.Ordinal);

        internal JournalFixture(bool prepared)
        {
            using var reviewKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            _reviewer = new("failure-review", reviewKey.ExportPkcs8PrivateKeyPem());
            _authorizer = new("failure-auth", authorizationKey.ExportPkcs8PrivateKeyPem());
            _evidence = new("failure-evidence", evidenceKey.ExportPkcs8PrivateKeyPem());
            _pins = new(_reviewer.KeyId, _reviewer.PublicKeyFingerprintSha256, _authorizer.KeyId, _authorizer.PublicKeyFingerprintSha256,
                _evidence.KeyId, _evidence.PublicKeyFingerprintSha256);
            _trust = new ReceiptAttestationTrustStore([
                new(_reviewer.KeyId, reviewKey.ExportSubjectPublicKeyInfo()), new(_authorizer.KeyId, authorizationKey.ExportSubjectPublicKeyInfo()),
                new(_evidence.KeyId, evidenceKey.ExportSubjectPublicKeyInfo()),
            ]);
            var data = Witness(prepared); Scope = data.Scope;
            var review = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReviewDomain, Scope, _reviewer);
            var authorization = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain,
                new CurrentAuthArchiveAuthorization(Scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(review), data.Began, data.Began.AddMinutes(1)), _authorizer);
            var claims = new CurrentAuthArchiveGenuineHelperClaims(review, authorization);
            Authorization = CurrentAuthLocalSessionArchivePolicy.Hash(authorization);
            _witness = data.Witness with { AuthorizationSha256 = Authorization };
            var before = new CurrentAppOwnedDatabaseSnapshot("Auth", [],
                [new("public", "__EFMigrationsHistory", 5, new string('a', 64)), new("private", "journal", 2, new string('b', 64)),
                 new("public", "refresh_sessions", 2, new string('c', 64))], [new("private", "allocation", "synthetic-owner", new string('d', 64))]);
            var deleted = before with
            {
                Relations = before.Relations.Select(row => row.Name == "refresh_sessions"
                ? row with { Rows = 0, RowSha256 = CurrentAuthLocalSessionArchivePolicy.HashBytes([]) } : row).ToArray()
            };
            var localBefore = Fleet(before, Scope.LocalObservationPolicy.RunBindingSha256, data.Began);
            var localAfter = Fleet(prepared ? before : deleted, Scope.LocalObservationPolicy.RunBindingSha256, data.Began);
            var comparison = Fleet(deleted, Scope.ProductionObservationPolicy.RunBindingSha256, data.Began);
            Facts = new(data.Case, claims, null, localBefore, localAfter, comparison, comparison, data.Began, data.Began.AddSeconds(6));
            Failure = new(data.Case, claims, "System.IO.IOException", unchecked((int)0x80070050), localBefore, comparison, data.Began, data.Began.AddSeconds(5));
            Manifest = new(CurrentAuthLocalSessionArchivePolicy.Hash(Scope), Authorization, new string('e', 64), new string('1', 64), new string('2', 64));
            Reservation(Scope.OperationId, Authorization); ManifestBytes(Manifest);
            string previous = new('0', 64);
            if (!prepared)
            {
                var receipt = new CurrentAuthArchiveReceipt(Scope.OperationId, Authorization, previous, before.Sha256, deleted.Sha256,
                    CurrentAuthLocalSessionArchivePolicy.Hash(Manifest), CurrentAppOwnedCommitClassification.Prepared, data.Began.AddSeconds(1));
                var signed = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReceiptDomain, receipt, _evidence);
                Journal.Add("prepared", JsonSerializer.SerializeToUtf8Bytes(signed)); previous = CurrentAuthLocalSessionArchivePolicy.Hash(signed);
            }
            FailureReceipt = new(Scope.OperationId, Authorization, previous, before.Sha256, deleted.Sha256,
                CurrentAuthLocalSessionArchivePolicy.Hash(Manifest), prepared ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit :
                    CurrentAppOwnedCommitClassification.Uncertain, data.Began.AddSeconds(4));
            FailureBytes(FailureReceipt);
        }
        internal CurrentAuthArchiveReceipt[] Require()
        {
            return CurrentAuthArchiveGenuineOwnedPair.RequireFailureJournal(Journal, Scope, Facts, Failure, _witness, _pins, _trust);
        }

        internal void Reservation(Guid operation, string authorization)
        {
            Journal["operation-start"] = JsonSerializer.SerializeToUtf8Bytes(new
            { Domain = "current-auth-session-archive-reservation-v1", OperationId = operation, AuthorizationSha256 = authorization });
        }

        internal void ManifestBytes(CurrentAuthArchiveRecoveryManifest value)
        {
            Journal["recovery-manifest"] = JsonSerializer.SerializeToUtf8Bytes(
                    CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.RecoveryDomain, value, _evidence));
        }

        internal void FailureBytes(CurrentAuthArchiveReceipt value, bool wrongSigner = false)
        {
            Journal["failed-or-uncertain"] = JsonSerializer.SerializeToUtf8Bytes(
                    CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReceiptDomain, value, wrongSigner ? _reviewer : _evidence));
        }

        internal void BadSignature(string name)
        {
            var claim = JsonSerializer.Deserialize<CurrentAuthArchiveClaim>(Journal[name])!;
            Journal[name] = JsonSerializer.SerializeToUtf8Bytes(claim with { SignatureBase64 = Convert.ToBase64String(new byte[64]) });
        }
        private static CurrentAuthArchiveFleet Fleet(CurrentAppOwnedDatabaseSnapshot snapshot, string binding, DateTimeOffset began)
        {
            var native = new CurrentAuthNativeObservation(snapshot, new(StringComparer.Ordinal), new(StringComparer.Ordinal), new(StringComparer.Ordinal));
            ConstructorInfo constructor = typeof(CurrentAuthLocalSessionArchiveObservation).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null, types: [typeof(string), typeof(CurrentAuthNativeObservation), typeof(CurrentAuthArchiveSession[])], modifiers: null)!;
            var observation = (CurrentAuthLocalSessionArchiveObservation)constructor.Invoke([binding, native, Array.Empty<CurrentAuthArchiveSession>()])!;
            return new(observation, [snapshot], began, began.AddSeconds(1));
        }
        public void Dispose() { _evidence.Dispose(); _authorizer.Dispose(); _reviewer.Dispose(); }
    }

    private static (CurrentAuthArchiveScope Scope, CurrentAuthArchiveGenuineSlotWitness Witness, string Authorization,
        CurrentAuthArchiveGenuineExecutionCase Case, DateTimeOffset Began, DateTimeOffset Now) Witness(bool prepared)
    {
        DateTimeOffset began = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var value = prepared ? CurrentAuthArchiveGenuineExecutionCase.PreparedPublication : CurrentAuthArchiveGenuineExecutionCase.TerminalPublication;
        var scope = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(began);
        // Pure structural witness fixture only; this is never a signed runtime seed or admission.
        scope = scope with
        {
            ComponentSubject = scope.ComponentSubject! with
            { Seed = scope.ComponentSubject.Seed with { CaseId = CurrentAuthArchiveGenuineExecutionCases.Identity(value).CaseId } }
        };
        string root = Path.Combine(Path.GetTempPath(), "genuine-publication-contract-first");
        string second = Path.Combine(Path.GetTempPath(), "genuine-publication-contract-second");
        scope = scope with
        {
            Paths = new(Path.Combine(root, "first.cipher"), Path.Combine(second, "second.cipher"),
            Path.Combine(root, "first.key"), Path.Combine(second, "second.key"))
        };
        string authorization = new('a', 64), slot = CurrentAuthArchiveGenuinePublicationFault.Slot(value);
        var witness = new CurrentAuthArchiveGenuineSlotWitness(scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(scope), authorization,
            scope.LocalObservationPolicy.RunBindingSha256, scope.ProductionObservationPolicy.RunBindingSha256, slot,
            Path.Combine(root, $"{scope.OperationId:D}-Auth-session-archive-{slot}.json"),
            "windows-ntfs:11111111-1111-1111-1111-111111111111:0000000000000001", "file-id-128:" + new string('0', 31) + "1",
            0, true, true, 80, began.AddSeconds(1), began.AddSeconds(2), began.AddSeconds(3), true);
        return (scope, witness, authorization, value, began, began.AddSeconds(4));
    }
}
