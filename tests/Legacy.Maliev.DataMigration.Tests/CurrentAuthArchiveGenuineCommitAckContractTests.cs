using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineCommitAckContractTests
{
    [Theory]
    [InlineData("file-node")]
    [InlineData("blocks")]
    [InlineData("expression")]
    [InlineData("tuple")]
    public void Untouched_comparison_rejects_auxiliary_changes_with_identical_snapshot_hash(string fault)
    {
        var before = ComparisonObservation(null);
        // First admit a separately constructed valid baseline, so a malformed fixture cannot prove rejection.
        CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(ComparisonObservation(null), before);
        var changed = ComparisonObservation(fault);
        Assert.Equal(before.Native.Snapshot.Sha256, changed.Native.Snapshot.Sha256);
        var error = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(changed, before));
        Assert.Equal("current_auth_local_archive_invalid", error.Code);
    }

    private static CurrentAuthLocalSessionArchiveObservation ComparisonObservation(string? fault)
    {
        var snapshot = new CurrentAppOwnedDatabaseSnapshot("Auth", [], [], []);
        var tuples = new Dictionary<string, string[]>(StringComparer.Ordinal)
        { ["pg_class"] = [fault == "tuple" ? /*lang=json,strict*/ "{\"oid\":1,\"relpages\":2}" : /*lang=json,strict*/ "{\"oid\":1,\"relpages\":1}"] };
        var storage = new Dictionary<string, (uint FileNode, long Blocks)>(StringComparer.Ordinal)
        { ["1"] = (fault == "file-node" ? 101u : 100u, fault == "blocks" ? 4L : 3L) };
        var expressions = new Dictionary<string, string>(StringComparer.Ordinal)
        { ["1"] = fault == "expression" ? "changed-synthetic-expression" : "synthetic-expression" };
        var native = new CurrentAuthNativeObservation(snapshot, tuples, storage, expressions);
        // The same fixed data-only constructor used by the signed-journal comparator fixtures.
        var ctor = typeof(CurrentAuthLocalSessionArchiveObservation).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null, types: [typeof(string), typeof(CurrentAuthNativeObservation), typeof(CurrentAuthArchiveSession[])], modifiers: null)!;
        return (CurrentAuthLocalSessionArchiveObservation)ctor.Invoke([new string('a', 64), native, Array.Empty<CurrentAuthArchiveSession>()])!;
    }

    [Theory]
    [InlineData(67, "COMMIT\0", true)]
    [InlineData(67, "COMMIT", false)]
    [InlineData(67, "ROLLBACK\0", false)]
    [InlineData(67, "COMMIT\0extra", false)]
    [InlineData(68, "COMMIT\0", false)]
    [InlineData(67, "BEGIN\0", false)]
    public void Only_exact_server_command_completion_can_consume_the_drop(int type, string payload, bool expected)
    { Assert.Equal(expected, CurrentAuthArchiveGenuineCommitFacts.IsCommitCompletion((byte)type, System.Text.Encoding.UTF8.GetBytes(payload))); }

    [Fact]
    public void Opaque_transport_and_owned_factory_cannot_be_deserialized()
    {
        _ = Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<CurrentAuthLocalSessionArchivePermit.GenuineExecutionCapability.CommitWriterLease>("{}"));
        _ = Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<CurrentAuthArchiveGenuineExecutionIssuer.CommitProxyFactory>("{}"));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("operation")]
    [InlineData("scope")]
    [InlineData("auth")]
    [InlineData("role")]
    [InlineData("same-port")]
    [InlineData("sessions")]
    [InlineData("backend")]
    [InlineData("still-armed")]
    [InlineData("drop-zero")]
    [InlineData("drop-two")]
    [InlineData("worker")]
    [InlineData("listener")]
    [InlineData("clients")]
    [InlineData("not-closed")]
    [InlineData("arm-clock")]
    [InlineData("drop-clock")]
    public void Commit_proof_requires_one_real_drop_and_fully_settled_resources(string fault)
    {
        using var fixture = new JournalFixture(); var info = fixture.Failure.Proxy;
        info = fault switch
        {
            "none" => info,
            "operation" => info with { OperationId = Guid.NewGuid() },
            "scope" => info with { ScopeSha256 = new string('f', 64) },
            "auth" => info with { AuthorizationSha256 = new string('f', 64) },
            "role" => info with { Role = "unowned_role" },
            "same-port" => info with { Port = info.UpstreamPort },
            "sessions" => info with { AcceptedSessions = 2 },
            "backend" => info with { BackendPid = 0 },
            "still-armed" => info with { Armed = true },
            "drop-zero" => info with { DroppedCommits = 0 },
            "drop-two" => info with { DroppedCommits = 2 },
            "worker" => info with { WorkerSettled = false },
            "listener" => info with { ListenerAbsent = false },
            "clients" => info with { ClientsAbsent = false },
            "not-closed" => info with { Closed = false },
            "arm-clock" => info with { ArmedAtUtc = info.CreatedAtUtc.AddSeconds(-1) },
            "drop-clock" => info with { DroppedAtUtc = info.ArmedAtUtc!.Value.AddSeconds(-1) },
            _ => throw new InvalidOperationException(),
        };
        if (fault == "none") { CurrentAuthArchiveGenuineCommitFacts.RequireSettled(info, fixture.Scope, fixture.Authorization); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineCommitFacts.RequireSettled(info, fixture.Scope, fixture.Authorization)); }
    }

    [Theory]
    [InlineData("none")]
    [InlineData("missing")]
    [InlineData("extra")]
    [InlineData("signature")]
    [InlineData("classification")]
    [InlineData("chain")]
    [InlineData("before")]
    [InlineData("after")]
    [InlineData("manifest")]
    [InlineData("unarmed")]
    [InlineData("before-drop")]
    public void Actual_signed_Prepared_Uncertain_chain_is_required(string fault)
    {
        using var fixture = new JournalFixture();
        switch (fault)
        {
            case "none": break;
            case "missing": _ = fixture.Journal.Remove("prepared"); break;
            case "extra": fixture.Journal.Add("committed-readback", fixture.Journal["failed-or-uncertain"]); break;
            case "signature": fixture.BadSignature(); break;
            case "classification": fixture.WriteFailure(fixture.Uncertain with { Classification = CurrentAppOwnedCommitClassification.CommittedAndReadback }); break;
            case "chain": fixture.WriteFailure(fixture.Uncertain with { PreviousSha256 = new string('f', 64) }); break;
            case "before": fixture.WriteFailure(fixture.Uncertain with { BeforeAuthSha256 = new string('f', 64) }); break;
            case "after": fixture.WriteFailure(fixture.Uncertain with { AfterAuthSha256 = new string('f', 64) }); break;
            case "manifest": fixture.WriteFailure(fixture.Uncertain with { RecoveryManifestSha256 = new string('f', 64) }); break;
            case "unarmed": fixture.Failure = fixture.Failure with { Proxy = fixture.Failure.Proxy with { ArmedAtUtc = null } }; break;
            case "before-drop": fixture.WriteFailure(fixture.Uncertain with { ObservedAtUtc = fixture.Failure.Proxy.DroppedAtUtc!.Value.AddSeconds(-1) }); break;
            default:
                break;
        }
        if (fault == "none")
        {
            var receipts = fixture.Require(); Assert.Equal(2, receipts.Length); Assert.Equal(fixture.Uncertain, receipts[1]);
        }
        else { _ = Assert.Throws<MigrationExecutionException>(fixture.Require); }
    }

    // Pure comparator data, not an issuer, target, native observation or executable permission.
    private sealed class JournalFixture : IDisposable
    {
        private readonly P256MigrationEvidenceSigner _reviewer, _authorizer, _evidence;
        private readonly CurrentAuthArchivePins _pins;
        private readonly ReceiptAttestationTrustStore _trust;
        internal CurrentAuthArchiveScope Scope { get; }
        internal string Authorization { get; }
        internal CurrentAuthArchiveGenuineExecutionFacts Facts { get; }
        internal CurrentAuthArchiveGenuineCommitFailureFacts Failure { get; set; }
        internal CurrentAuthArchiveReceipt Uncertain { get; }
        internal Dictionary<string, byte[]> Journal { get; } = new(StringComparer.Ordinal);
        internal JournalFixture()
        {
            using var r = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var a = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var e = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            _reviewer = new("commit-review", r.ExportPkcs8PrivateKeyPem()); _authorizer = new("commit-auth", a.ExportPkcs8PrivateKeyPem()); _evidence = new("commit-evidence", e.ExportPkcs8PrivateKeyPem());
            _pins = new(_reviewer.KeyId, _reviewer.PublicKeyFingerprintSha256, _authorizer.KeyId, _authorizer.PublicKeyFingerprintSha256, _evidence.KeyId, _evidence.PublicKeyFingerprintSha256);
            _trust = new([new(_reviewer.KeyId, r.ExportSubjectPublicKeyInfo()), new(_authorizer.KeyId, a.ExportSubjectPublicKeyInfo()), new(_evidence.KeyId, e.ExportSubjectPublicKeyInfo())]);
            DateTimeOffset began = DateTimeOffset.UtcNow.AddMinutes(-1);
            var structural = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(began);
            Scope = structural with { ComponentSubject = structural.ComponentSubject! with { Seed = structural.ComponentSubject.Seed with { CaseId = "commit-ack-lost" } } };
            var review = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReviewDomain, Scope, _reviewer);
            var auth = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain,
                new CurrentAuthArchiveAuthorization(Scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(review), began, Scope.ExpiresAtUtc), _authorizer);
            var claims = new CurrentAuthArchiveGenuineHelperClaims(review, auth); Authorization = CurrentAuthLocalSessionArchivePolicy.Hash(auth);
            var before = new CurrentAppOwnedDatabaseSnapshot("Auth", [], [new("public", "refresh_sessions", 2, new string('a', 64)), new("private", "journal", 2, new string('b', 64))], []);
            var after = before with { Relations = before.Relations.Select(row => row.Name == "refresh_sessions" ? row with { Rows = 0, RowSha256 = CurrentAuthLocalSessionArchivePolicy.HashBytes([]) } : row).ToArray() };
            var local = Fleet(before, Scope.LocalObservationPolicy.RunBindingSha256, began); var deleted = Fleet(after, Scope.LocalObservationPolicy.RunBindingSha256, began);
            var comparison = Fleet(after, Scope.ProductionObservationPolicy.RunBindingSha256, began);
            var proxy = new CurrentAuthArchiveGenuineCommitProxyInfo(Scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(Scope), Authorization,
                Scope.LocalObservationPolicy.Maintenance.Role, 15432, 25432, 1234, began.AddSeconds(-1), new string('c', 64), began.AddSeconds(1), Scope.ExpiresAtUtc,
                1, 71, false, 1, began.AddSeconds(3), began.AddSeconds(4), true, true, true, true, began.AddSeconds(7), null!);
            Facts = new(CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost, claims, null, local, deleted, comparison, comparison, began, began.AddSeconds(9));
            Failure = new(CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost, claims, "Npgsql.NpgsqlException", local, comparison, began, began.AddSeconds(6), proxy);
            var manifest = new CurrentAuthArchiveRecoveryManifest(CurrentAuthLocalSessionArchivePolicy.Hash(Scope), Authorization, new string('d', 64), new string('e', 64), new string('f', 64));
            Journal.Add("operation-start", JsonSerializer.SerializeToUtf8Bytes(new { Domain = "current-auth-session-archive-reservation-v1", Scope.OperationId, AuthorizationSha256 = Authorization }));
            Journal.Add("recovery-manifest", JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.RecoveryDomain, manifest, _evidence)));
            var prepared = new CurrentAuthArchiveReceipt(Scope.OperationId, Authorization, new string('0', 64), before.Sha256, after.Sha256,
                CurrentAuthLocalSessionArchivePolicy.Hash(manifest), CurrentAppOwnedCommitClassification.Prepared, began.AddSeconds(2));
            var signed = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReceiptDomain, prepared, _evidence);
            Journal.Add("prepared", JsonSerializer.SerializeToUtf8Bytes(signed));
            Uncertain = prepared with { PreviousSha256 = CurrentAuthLocalSessionArchivePolicy.Hash(signed), Classification = CurrentAppOwnedCommitClassification.Uncertain, ObservedAtUtc = began.AddSeconds(5) };
            WriteFailure(Uncertain);
        }
        internal CurrentAuthArchiveReceipt[] Require()
        {
            return CurrentAuthArchiveGenuineOwnedPair.RequireCommitFailureJournal(Journal, Scope, Facts, Failure, _pins, _trust);
        }

        internal void WriteFailure(CurrentAuthArchiveReceipt receipt)
        {
            Journal["failed-or-uncertain"] = JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReceiptDomain, receipt, _evidence));
        }

        internal void BadSignature()
        { var claim = JsonSerializer.Deserialize<CurrentAuthArchiveClaim>(Journal["failed-or-uncertain"])!; Journal["failed-or-uncertain"] = JsonSerializer.SerializeToUtf8Bytes(claim with { SignatureBase64 = Convert.ToBase64String(new byte[64]) }); }
        private static CurrentAuthArchiveFleet Fleet(CurrentAppOwnedDatabaseSnapshot snapshot, string binding, DateTimeOffset began)
        {
            var native = new CurrentAuthNativeObservation(snapshot, new(StringComparer.Ordinal), new(StringComparer.Ordinal), new(StringComparer.Ordinal));
            var ctor = typeof(CurrentAuthLocalSessionArchiveObservation).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null, types: [typeof(string), typeof(CurrentAuthNativeObservation), typeof(CurrentAuthArchiveSession[])], modifiers: null)!;
            var observation = (CurrentAuthLocalSessionArchiveObservation)ctor.Invoke([binding, native, Array.Empty<CurrentAuthArchiveSession>()])!;
            return new(observation, [snapshot], began, began.AddSeconds(1));
        }
        public void Dispose() { _evidence.Dispose(); _authorizer.Dispose(); _reviewer.Dispose(); }
    }
}
