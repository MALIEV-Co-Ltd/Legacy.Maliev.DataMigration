using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveRecoveryV2ContractTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("return")]
    [InlineData("restored")]
    [InlineData("kind")]
    [InlineData("case")]
    [InlineData("proof")]
    [InlineData("cleanup")]
    [InlineData("os-exit")]
    [InlineData("time")]
    public void Cleanup_candidate_requires_actual_successful_method_and_keeps_OS_exit_and_full_proof_separate(string fault)
    {
        DateTimeOffset began = DateTimeOffset.UtcNow.AddMinutes(-1), ended = began.AddSeconds(1);
        var method = new CurrentAuthArchiveGenuineExecutionMethodResult(0, began, ended.AddSeconds(1), new(new("stage", new('a', 64)), began, ended));
        var stage = JsonSerializer.SerializeToNode(new
        {
            Kind = "current-auth-genuine-recovery-incomplete-precleanup-v2",
            Phase = "recovery",
            CaseId = "first-only-decrypt-insert-readback",
            BeganAtUtc = began,
            EndedAtUtc = ended,
            RestoreCompleted = true,
            CleanupVerified = false,
            PhaseProofComplete = false,
            ProviderExitCode = (int?)null,
        })!.AsObject();
        switch (fault)
        {
            case "none": break;
            case "return": method = method with { ReturnCode = 1 }; break;
            case "restored": stage["RestoreCompleted"] = false; break;
            case "kind": stage["Kind"] = "current-auth-genuine-execution-incomplete-precleanup-v1"; break;
            case "case": stage["CaseId"] = "second-only-decrypt-insert-readback"; break;
            case "proof": stage["PhaseProofComplete"] = true; break;
            case "cleanup": stage["CleanupVerified"] = true; break;
            case "os-exit": stage["ProviderExitCode"] = 0; break;
            case "time": method = method with { ReturnedAtUtc = began }; break;
            default: throw new InvalidOperationException();
        }
        var json = JsonSerializer.SerializeToElement(stage);
        if (fault == "none") { CurrentAuthArchiveRecoveryV2Runner.RequireCompletedMethod(json, CurrentAuthArchiveRecoveryV2Case.FirstOnly, method); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveRecoveryV2Runner.RequireCompletedMethod(json, CurrentAuthArchiveRecoveryV2Case.FirstOnly, method)); }
    }
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void New_two_case_identity_does_not_activate_the_old_execution_gate(int value)
    {
        var selected = (CurrentAuthArchiveRecoveryV2Case)value;
        Assert.Equal("recovery", CurrentAuthArchiveRecoveryV2.Identity(selected).Phase);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineExecutionCases.RequireImplemented(CurrentAuthArchiveRecoveryV2.SetupCase(selected)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(12)]
    [InlineData(13)]
    public async Task Unknown_new_case_refuses_before_any_file_access(int value)
    { _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthArchiveRecoveryV2Runner.ExecuteAsync("not-a-protected-input", (CurrentAuthArchiveRecoveryV2Case)value, CancellationToken.None)); }

    [Fact]
    public void Actual_capture_runtime_holder_cannot_be_deserialized_from_a_positive_descriptor()
    { _ = Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<CurrentReviewedCapture>("{}")); }

    [Theory]
    [InlineData("none")]
    [InlineData("operation")]
    [InlineData("original")]
    [InlineData("target")]
    [InlineData("rows")]
    [InlineData("native")]
    [InlineData("source")]
    [InlineData("expiry-extension")]
    [InlineData("expired")]
    public void Restore_scope_is_distinct_and_remains_bound_to_original_identity_rows_devices_and_finite_lease(string fault)
    {
        DateTimeOffset now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var original = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(now); var restore = Scope(original, now);
        restore = fault switch
        {
            "none" => restore,
            "operation" => restore with { OperationId = original.OperationId },
            "original" => restore with { SetupScopeSha256 = new('f', 64) },
            "target" => restore with { LocalTargetSha256 = new('f', 64) },
            "rows" => restore with { OriginalRowsSha256 = new('f', 64) },
            "native" => restore with { EmptyNativeSha256 = "not-a-hash" },
            "source" => restore with { SourceFullSha256 = "not-a-hash" },
            "expiry-extension" => restore with { ExpiresAtUtc = original.ExpiresAtUtc.AddTicks(1) },
            "expired" => restore with { ExpiresAtUtc = now },
            _ => throw new InvalidOperationException(),
        };
        if (fault == "none") { CurrentAuthArchiveRecoveryV2Preservation.RequireScope(restore, original, now); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveRecoveryV2Preservation.RequireScope(restore, original, now)); }
    }

    [Theory]
    [InlineData("none")]
    [InlineData("signature")]
    [InlineData("review")]
    [InlineData("reservation")]
    [InlineData("setup")]
    [InlineData("preimage")]
    [InlineData("after")]
    [InlineData("rows")]
    [InlineData("chain")]
    [InlineData("classification")]
    [InlineData("time")]
    public void Restore_journal_requires_its_own_review_authorization_and_Prepared_to_readback_chain(string fault)
    {
        using var fixture = new JournalFixture();
        var terminal = fixture.Terminal;
        switch (fault)
        {
            case "none": break;
            case "signature": fixture.TerminalClaim = fixture.TerminalClaim with { SignatureBase64 = Convert.ToBase64String(new byte[64]) }; break;
            case "review": fixture.AuthorizationClaim = fixture.SignAuthorization(fixture.Permission with { ReviewSha256 = new('f', 64) }); break;
            case "reservation": fixture.ReservationClaim = fixture.SignReservation(new(fixture.Restore.OperationId, new('f', 64), fixture.AuthorizationSha)); break;
            case "setup": terminal = terminal with { SetupManifestSha256 = new('f', 64) }; break;
            case "preimage": terminal = terminal with { BeforeAuthSha256 = new('f', 64) }; break;
            case "after": terminal = terminal with { AfterAuthSha256 = new('f', 64) }; break;
            case "rows": terminal = terminal with { RecoveredRowsSha256 = new('f', 64) }; break;
            case "chain": terminal = terminal with { PreviousSha256 = new('f', 64) }; break;
            case "classification": terminal = terminal with { Classification = CurrentAppOwnedCommitClassification.Uncertain }; break;
            case "time": terminal = terminal with { ObservedAtUtc = fixture.Restore.CapturedAtUtc.AddTicks(-1) }; break;
            default: throw new InvalidOperationException();
        }
        if (terminal != fixture.Terminal) { fixture.TerminalClaim = fixture.SignReceipt(terminal); }
        if (fault == "none") { fixture.Require(); }
        else { _ = Assert.Throws<MigrationExecutionException>(fixture.Require); }
    }

    [Theory]
    [InlineData(false, "none")]
    [InlineData(true, "none")]
    [InlineData(false, "blocks")]
    [InlineData(true, "blocks")]
    [InlineData(false, "file")]
    [InlineData(true, "file")]
    [InlineData(false, "tuple")]
    [InlineData(true, "tuple")]
    [InlineData(false, "expression")]
    [InlineData(true, "expression")]
    public void Restore_preserves_original_eleven_fields_and_native_auxiliary_on_both_sides(bool comparison, string fault)
    {
        DateTimeOffset now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var scope = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(now);
        var rows = new[] { new CurrentAuthArchiveSession(Guid.Parse("00000000-0000-0000-0000-000000000001"), Guid.Parse("00000000-0000-0000-0000-000000000002"),
            "synthetic", 1, "ไทย stamp ", "synthetic-token ", now.UtcDateTime, now.AddMinutes(1).UtcDateTime, null, null, null) };
        byte[] encoded = CurrentAuthLocalSessionArchivePolicy.EncodeRows(rows);
        scope = scope with { DeleteSetSha256 = CurrentAuthLocalSessionArchivePolicy.HashBytes(encoded), DeleteCount = rows.Length }; CryptographicOperations.ZeroMemory(encoded);
        var snapshot = new CurrentAppOwnedDatabaseSnapshot("Auth", [], [new("public", "refresh_sessions", 1, new('a', 64)), new("private", "journal", 2, new('b', 64))], [new("private", "allocation", "owner", new('c', 64))]);
        var emptySnapshot = snapshot with { Relations = snapshot.Relations.Select(row => row.Name == "refresh_sessions" ? row with { Rows = 0, RowSha256 = CurrentAuthLocalSessionArchivePolicy.HashBytes([]) } : row).ToArray() };
        var original = Fleet(scope.LocalObservationPolicy.RunBindingSha256, snapshot, rows, now);
        var empty = Fleet(scope.LocalObservationPolicy.RunBindingSha256, emptySnapshot, [], now);
        var restored = Fleet(scope.LocalObservationPolicy.RunBindingSha256, snapshot, rows, now);
        var second = Fleet(scope.ProductionObservationPolicy.RunBindingSha256, emptySnapshot, [], now); var secondAfter = second;
        if (fault != "none")
        {
            var selected = comparison ? secondAfter : restored; var native = selected.Auth.Native;
            var tuples = native.CopyTuples(); var storage = native.CopyStorage(); var expressions = native.CopyExpressions();
            switch (fault)
            {
                case "blocks": storage["123"] = (456, 8); break;
                case "file": storage["123"] = (457, 7); break;
                case "tuple": tuples["synthetic"] = [/*lang=json,strict*/ "{\"value\":2}"]; break;
                case "expression": expressions["123"] = "different"; break;
                default: throw new InvalidOperationException();
            }
            var changed = new CurrentAuthNativeObservation(native.Snapshot, tuples, storage, expressions);
            Assert.NotEqual(CurrentAuthArchiveRecoveryV2Preservation.NativeSha(native), CurrentAuthArchiveRecoveryV2Preservation.NativeSha(changed));
            selected = selected with { Auth = Observation(selected.Auth.TargetBindingSha256, changed, selected.Auth.Sessions.ToArray()) };
            if (comparison) { secondAfter = selected; } else { restored = selected; }
        }
        if (fault == "none") { CurrentAuthArchiveRecoveryV2Preservation.RequireRestored(original, empty, restored, second, secondAfter, scope); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveRecoveryV2Preservation.RequireRestored(original, empty, restored, second, secondAfter, scope)); }
    }
    private static CurrentAuthArchiveFleet Fleet(string binding, CurrentAppOwnedDatabaseSnapshot snapshot, CurrentAuthArchiveSession[] rows, DateTimeOffset now)
    {
        var native = new CurrentAuthNativeObservation(snapshot, new(StringComparer.Ordinal) { ["synthetic"] = [/*lang=json,strict*/ "{\"value\":1}"] },
            new(StringComparer.Ordinal) { ["123"] = (456, 7) }, new(StringComparer.Ordinal) { ["123"] = "original" });
        return new(Observation(binding, native, rows), [snapshot], now, now);
    }
    // Pure data wrapper only, with no target, source acceptance, issuer, environment or capability.
    private static CurrentAuthLocalSessionArchiveObservation Observation(string binding, CurrentAuthNativeObservation native, CurrentAuthArchiveSession[] rows)
    {
        var constructor = typeof(CurrentAuthLocalSessionArchiveObservation).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null, types: [typeof(string), typeof(CurrentAuthNativeObservation), typeof(CurrentAuthArchiveSession[])], modifiers: null)!;
        return (CurrentAuthLocalSessionArchiveObservation)constructor.Invoke([binding, native, rows]);
    }
    private static CurrentAuthArchiveRestoreScopeV2 Scope(CurrentAuthArchiveScope original, DateTimeOffset now)
    {
        return new(
        "current-auth-owned-disposable-restore-scope-v2", Guid.NewGuid(), original.OperationId, new('a', 64), CurrentAuthLocalSessionArchivePolicy.Hash(original), new('b', 64), new('c', 64),
        new('d', 64), new('e', 64), new('1', 64), original.LocalObservationPolicy.RunBindingSha256, original.ProductionObservationPolicy.RunBindingSha256,
        original.LocalObservationPolicy.TargetObservationSha256, original.ProductionObservationPolicy.TargetObservationSha256, new('2', 64), new('3', 64), new('4', 64), new('5', 64),
        original.DeleteSetSha256, original.DeleteCount, true, "synthetic-volume/cipher", new('6', 64), "synthetic-volume/key", new('7', 64), new('8', 64),
        original.RecoveryDeviceProofSha256, now, new[] { now.AddMinutes(1), original.ExpiresAtUtc }.Min());
    }

    private sealed class JournalFixture : IDisposable
    {
        private readonly P256MigrationEvidenceSigner _reviewer, _authorizer, _evidence;
        private readonly CurrentAuthArchivePins _pins;
        private readonly ReceiptAttestationTrustStore _trust;
        internal CurrentAuthArchiveScope Original { get; }
        internal CurrentAuthArchiveRestoreScopeV2 Restore { get; }
        internal CurrentAuthArchiveAuthorization Permission { get; }
        internal CurrentAuthArchiveRestoreReceiptV2 Terminal { get; }
        internal CurrentAuthArchiveClaim Review { get; }
        internal CurrentAuthArchiveClaim AuthorizationClaim { get; set; }
        internal CurrentAuthArchiveClaim ReservationClaim { get; set; }
        internal CurrentAuthArchiveClaim PreparedClaim { get; }
        internal CurrentAuthArchiveClaim TerminalClaim { get; set; }
        internal string AuthorizationSha => CurrentAuthLocalSessionArchivePolicy.Hash(AuthorizationClaim);
        internal JournalFixture()
        {
            using var r = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var a = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var e = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            _reviewer = new("restore-unit-review", r.ExportPkcs8PrivateKeyPem()); _authorizer = new("restore-unit-auth", a.ExportPkcs8PrivateKeyPem()); _evidence = new("restore-unit-evidence", e.ExportPkcs8PrivateKeyPem());
            _pins = new(_reviewer.KeyId, _reviewer.PublicKeyFingerprintSha256, _authorizer.KeyId, _authorizer.PublicKeyFingerprintSha256, _evidence.KeyId, _evidence.PublicKeyFingerprintSha256);
            _trust = new([new(_reviewer.KeyId, r.ExportSubjectPublicKeyInfo()), new(_authorizer.KeyId, a.ExportSubjectPublicKeyInfo()), new(_evidence.KeyId, e.ExportSubjectPublicKeyInfo())]);
            DateTimeOffset now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero); Original = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(now); Restore = Scope(Original, now);
            Review = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveRecoveryV2.ReviewDomain, Restore, _reviewer);
            Permission = new(Restore.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(Review), now, Restore.ExpiresAtUtc); AuthorizationClaim = SignAuthorization(Permission);
            ReservationClaim = SignReservation(new(Restore.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(Restore), AuthorizationSha));
            var prepared = new CurrentAuthArchiveRestoreReceiptV2(Restore.OperationId, AuthorizationSha, new('0', 64), Restore.SetupManifestSha256, Restore.EmptyAuthSha256,
                Original.LocalObservationPolicy.BeforeDatabaseSha256["Auth"], Restore.OriginalRowsSha256, CurrentAppOwnedCommitClassification.Prepared, now.AddSeconds(1));
            PreparedClaim = SignReceipt(prepared); Terminal = prepared with { PreviousSha256 = CurrentAuthLocalSessionArchivePolicy.Hash(PreparedClaim), Classification = CurrentAppOwnedCommitClassification.CommittedAndReadback, ObservedAtUtc = now.AddSeconds(2) };
            TerminalClaim = SignReceipt(Terminal);
        }
        internal CurrentAuthArchiveClaim SignAuthorization(CurrentAuthArchiveAuthorization value)
        {
            return CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveRecoveryV2.AuthorizationDomain, value, _authorizer);
        }

        internal CurrentAuthArchiveClaim SignReservation(CurrentAuthArchiveRestoreReservationV2 value)
        {
            return CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveRecoveryV2Journal.ReservationDomain, value, _evidence);
        }

        internal CurrentAuthArchiveClaim SignReceipt(CurrentAuthArchiveRestoreReceiptV2 value)
        {
            return CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveRecoveryV2.ReceiptDomain, value, _evidence);
        }

        internal void Require()
        {
            CurrentAuthArchiveRecoveryV2Journal.Require(Restore, Original, Review, AuthorizationClaim, ReservationClaim, PreparedClaim, TerminalClaim, _pins, _trust, Restore.CapturedAtUtc.AddSeconds(3));
        }

        public void Dispose() { _reviewer.Dispose(); _authorizer.Dispose(); _evidence.Dispose(); }
    }
}
