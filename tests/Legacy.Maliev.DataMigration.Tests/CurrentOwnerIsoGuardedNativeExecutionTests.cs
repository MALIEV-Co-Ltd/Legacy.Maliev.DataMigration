using System.Diagnostics;
using System.Security.Cryptography;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(CurrentOwnerIsoNativeProofGroup.Name)]
public sealed class CurrentOwnerIsoGuardedNativeExecutionTests
{
    private static readonly string[] RepairedDatabases = ["Country", "Material"];
    [WindowsLocalRunFact]
    public Task Complete_26_database_fleet_is_preserved_after_Country_and_Material_commit()
    {
        return RunAsync("complete");
    }

    [WindowsLocalRunFact]
    public Task Prepared_receipt_publication_failure_rolls_back_without_commit()
    {
        return RunAsync("prepared-publication");
    }

    [WindowsLocalRunFact]
    public Task Dropped_commit_ack_stops_without_Material_apply()
    {
        return RunAsync("lost-commit-ack");
    }

    [WindowsLocalRunFact]
    public Task Terminal_publication_uncertainty_stops_without_Material_apply()
    {
        return RunAsync("terminal-publication");
    }

    [WindowsLocalRunFact]
    public Task Wrong_owner_rejected_before_DDL()
    {
        return RunAsync("wrong-owner");
    }

    [WindowsLocalRunFact]
    public Task Full_fleet_drift_after_Country_stops_Material()
    {
        return RunAsync("fleet-drift");
    }

    [WindowsLocalRunFact]
    public Task Unsafe_unprobed_host_rule_rejected()
    {
        return RunAsync("unsafe-host");
    }

    [WindowsLocalRunFact]
    public Task Local_trust_rejected()
    {
        return RunAsync("local-trust");
    }

    [WindowsLocalRunFact]
    public Task Ordinary_client_rejected_in_all_26_databases()
    {
        return RunAsync("ordinary-all26");
    }

    [WindowsLocalRunFact]
    public Task Exact_installed_policy_accepts_only_maintenance_client()
    {
        return RunAsync("exclusive-policy");
    }

    private static async Task RunAsync(string fault)
    {
        Guid run = Guid.NewGuid(); using var proof = IsoExecutedProofRecorder.Open(run, fault);
        await proof.RecordAsync("host-entry", IsoExecutedHostEntry.Capture(run, fault, typeof(CurrentOwnerIsoGuardedNativeExecutionTests).Assembly.Location), CancellationToken.None);
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        await IsoDisposableFixture.RunAsync(run, fault, proof, async (adminText, containerId, ct) =>
        {
            using var process = Process.GetCurrentProcess(); string executable = Environment.ProcessPath ?? throw CurrentOwnerIsoRepairPermit.Invalid();
            string testAssembly = typeof(CurrentOwnerIsoGuardedNativeExecutionTests).Assembly.Location;
            using var executableFile = SecureLocalFile.OpenReadShared(executable); using var testFile = SecureLocalFile.OpenReadShared(testAssembly);
            await proof.RecordAsync("entry", new IsoActualCaseEntry("current-owner-iso-actual-component-entry-v1", run, fault, containerId,
                DateTimeOffset.UtcNow, testAssembly, Convert.ToHexStringLower(SHA256.HashData(testFile)), process.Id,
                new DateTimeOffset(process.StartTime.ToUniversalTime()), executable, Convert.ToHexStringLower(SHA256.HashData(executableFile))), ct);
            var admin = new NpgsqlConnectionStringBuilder(adminText) { Host = "127.0.0.1", SslMode = SslMode.Disable, Pooling = false, Timeout = 5, CommandTimeout = 30 };
            var source = proof.Source; var owners = proof.Owners;
            var contract = ApprovedCurrentOwnerIsoOverlay.Create(source, source.SourceCommitSha, CurrentOwnerIsoSelection.LiteralWidthV1, owners, DateTimeOffset.UtcNow);
            await IsoGuardedFleetFixture.BootstrapAsync(admin.ConnectionString, source, contract, fault, ct);
            using var attempt = System.Text.Json.JsonDocument.Parse(proof.ReadHeld("attempt"));
            var policy = await IsoFixtureMaintenance.InstallAsync(admin.ConnectionString, proof.Binding.ComputeSha256(), fault, attempt.RootElement.GetProperty("expires").GetDateTimeOffset(), ct);
            await proof.RecordAsync("native-policy", await IsoMaintenanceNativeObserver.CaptureAsync(policy.Endpoint, ct), ct);
            await proof.RecordAsync("installed-policy", new { policy.Identity, policy.Pin, rawHba = policy.RawHba, rawRules = policy.RawRules, observedAtUtc = DateTimeOffset.UtcNow }, ct);
            var native = new Dictionary<string, CurrentOwnerIsoNativeObservation>(StringComparer.Ordinal);
            foreach (string database in RepairedDatabases)
            {
                native.Add(database, await IsoGuardedFleetFixture.NativeAsync(policy.Endpoint, database, contract, false, ct));
                CurrentOwnerIsoNativePreservation.RequireBefore(native[database], contract); await proof.NativeAsync("before-" + database, native[database], ct);
            }
            var pool = new CurrentAppOwnedSnapshotInternPool(); var baseline = new List<CurrentAppOwnedDatabaseSnapshot>();
            foreach (string database in IsoGuardedFleetFixture.Names.Order(StringComparer.Ordinal))
            { baseline.Add(pool.Intern(await IsoGuardedFleetFixture.CaptureAsync(policy.Endpoint, database, ct))); }
            await proof.FleetAsync("fleet-before", baseline, ct);
            using var rk = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var ak = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var ek = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var bk = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var rs = new P256MigrationEvidenceSigner("iso-component-review-" + run.ToString("N"), rk.ExportPkcs8PrivateKeyPem());
            using var au = new P256MigrationEvidenceSigner("iso-component-authorization-" + run.ToString("N"), ak.ExportPkcs8PrivateKeyPem());
            using var es = new P256MigrationEvidenceSigner("iso-component-receipt-" + run.ToString("N"), ek.ExportPkcs8PrivateKeyPem());
            using var bs = new P256MigrationEvidenceSigner("iso-component-subject-" + run.ToString("N"), bk.ExportPkcs8PrivateKeyPem());
            TrustedAttestationKey[] keys = [new(rs.KeyId, rk.ExportSubjectPublicKeyInfo()), new(au.KeyId, ak.ExportSubjectPublicKeyInfo()), new(es.KeyId, ek.ExportSubjectPublicKeyInfo()), new(bs.KeyId, bk.ExportSubjectPublicKeyInfo())];
            var trust = new ReceiptAttestationTrustStore(keys);
            _ = trust.TryGetPublicKeyFingerprintSha256(rs.KeyId, out string rf); _ = trust.TryGetPublicKeyFingerprintSha256(au.KeyId, out string af);
            _ = trust.TryGetPublicKeyFingerprintSha256(es.KeyId, out string ef); _ = trust.TryGetPublicKeyFingerprintSha256(bs.KeyId, out string bf);
            var pins = new CurrentOwnerIsoRepairSigningPins(rs.KeyId, rf, au.KeyId, af, es.KeyId, ef);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var subject = new CurrentOwnerIsoComponentSubject(run, proof.DefinitionSha256, source.SourceCommitSha, proof.SourceCatalogSha256,
                SchemaPlanCanonicalizer.ComputeSha256(source), CurrentAppOwnedSnapshotSerialization.Sha256(owners), contract.ComputeSha256(), PostgreSqlCurrentOwnerIsoRepair.OperationSha256,
                new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/disposable-" + containerId, policy.Identity),
                CurrentAppOwnedRepairPermit.Hash(proof.ReadHeld("container")), proof.Binding.ComputeSha256(),
                FileHash(typeof(MigrationConsole).Assembly.Location), FileHash(typeof(CurrentOwnerIsoRepairPermit).Assembly.Location), FileHash(testAssembly), now, policy.Pin.ExpiresAtUtc);
            var unsigned = new CurrentOwnerIsoComponentSubjectClaim("current-owner-iso-component-subject-v1", subject, bs.KeyId, null);
            var signed = unsigned with { Signature = Convert.ToBase64String(bs.Sign(CurrentOwnerIsoBootstrapSubjectValidator.Payload(unsigned))) };
            var bootstrap = new CurrentOwnerIsoExecutionBootstrap("current-owner-iso-component-bootstrap-v1", fault, signed, bs.KeyId, bf,
                policy.Pin.Postmaster.ToString("O") + ":" + policy.Identity, native["Country"].Snapshot.Sha256, native["Material"].Snapshot.Sha256,
                CurrentAppOwnedSnapshotSerialization.Sha256(baseline), subject.SourceSchemaPlanSha256);
            var scope = new CurrentOwnerIsoRepairScope(run, CurrentOwnerIsoSelection.LiteralWidthV1, subject.SourceCommitSha, subject.SourceSchemaPlanSha256,
                subject.OwnerSourcesSha256, subject.ContractSha256, subject.FixedOperationSha256, subject.IntendedTarget, "local-aspire", "legacy-postgres-main-local",
                bootstrap.TargetGeneration, subject.TargetObservationSha256, subject.RunBindingSha256,
                baseline.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal), bootstrap.FleetBeforeSha256,
                string.Empty, string.Empty, string.Empty, policy.Pin, CurrentOwnerIsoRepairPermit.FreshOnlyPolicy,
                subject.SourceCatalogSha256, CurrentOwnerIsoRepairPermit.MaintenanceValidator, string.Empty, CurrentOwnerIsoProofAdmission.DisposableNativeComponent, bootstrap);
            await proof.RecordAsync("scope", scope, ct); await proof.RecordAsync("case-source", source, ct); await proof.RecordAsync("case-owners", owners, ct);
            await proof.RecordAsync("pins", pins, ct); await proof.RecordAsync("public-keys", keys.Select(x => new IsoCasePublicKey(x.KeyId, Convert.ToBase64String(x.SubjectPublicKeyInfo))).ToArray(), ct);
            IsoCommitAcknowledgementProxy? proxy = null;
            try
            {
                if (fault == "lost-commit-ack") { proxy = await IsoCommitAcknowledgementProxy.StartAsync("127.0.0.1", admin.Port, proof, ct); }
                using var environment = new IsoGuardedNativeEnvironment(policy.Endpoint, admin.ConnectionString, scope, source, owners, baseline, native, contract, trust, pins, proof, fault, proxy);
                bool rejectReview = fault is "wrong-owner" or "unsafe-host" or "local-trust";
                if (fault == "unsafe-host")
                {
                    await using var sdk = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(admin.ConnectionString) { Username = "iso_unprobed_sdk" }.ConnectionString); await sdk.OpenAsync(ct);
                    await using var query = new NpgsqlCommand("SELECT current_user;", sdk); Assert.Equal("iso_unprobed_sdk", await query.ExecuteScalarAsync(ct));
                    await proof.RecordAsync("unprobed-sdk-allowed", new { role = "iso_unprobed_sdk", observedAtUtc = DateTimeOffset.UtcNow }, ct);
                }
                DateTimeOffset started = DateTimeOffset.UtcNow; Exception? actualFailure = null;
                CurrentOwnerIsoRepairPermit? permit = null;
                try
                {
                    var review = await CurrentOwnerIsoRepairPermit.IssueReviewAsync(scope, source, owners, baseline, trust, pins, environment, rs, DateTimeOffset.UtcNow.AddMinutes(6), TimeProvider.System, ct);
                    await proof.RecordAsync("review", review, ct);
                    if (rejectReview) { throw new InvalidOperationException("Expected genuine review boundary rejection."); }
                    if (fault is not ("ordinary-all26" or "exclusive-policy"))
                    {
                        var authorization = await CurrentOwnerIsoRepairPermit.AuthorizeAsync(review, source, owners, trust, pins, environment, au, TimeProvider.System, ct);
                        environment.AuthorizationSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(authorization); await proof.RecordAsync("authorization", authorization, ct);
                        permit = await CurrentOwnerIsoRepairPermit.AdmitAsync(review, authorization, source, owners, trust, pins, environment, TimeProvider.System, ct);
                        string execution = proxy is null ? policy.Endpoint : new NpgsqlConnectionStringBuilder(policy.Endpoint) { Port = proxy.Port }.ConnectionString;
                        _ = await PostgreSqlCurrentOwnerIsoRepair.ExecuteFleetAsync(execution, source, owners, baseline, permit, es, trust, pins, ct);
                    }
                }
                catch (Exception failure) { actualFailure = failure; }
                bool expectFailure = rejectReview || fault is "prepared-publication" or "lost-commit-ack" or "terminal-publication" or "fleet-drift";
                Assert.Equal(expectFailure, actualFailure is not null);
                if (rejectReview)
                {
                    _ = Assert.IsType<MigrationExecutionException>(actualFailure);
                    string expectedCode = fault == "wrong-owner" ? "current_owner_iso_admission_invalid" : "current_app_owned_maintenance_hba_not_exclusive";
                    Assert.Equal(expectedCode, ((MigrationExecutionException)actualFailure!).Code); Assert.Equal(0, environment.Reservations); Assert.Equal(0, environment.ReceiptCount);
                }
                if (fault == "lost-commit-ack") { await proxy!.Dropped.WaitAsync(TimeSpan.FromSeconds(10), ct); Assert.Equal(1, proxy.DroppedCommits); }
                var after = new List<CurrentAppOwnedDatabaseSnapshot>();
                foreach (string database in IsoGuardedFleetFixture.Names.Order(StringComparer.Ordinal))
                {
                    var snapshot = pool.Intern(await IsoGuardedFleetFixture.CaptureAsync(policy.Endpoint, database, ct)); after.Add(snapshot);
                    bool selected = (database == "Country" && (fault is "complete" or "lost-commit-ack" or "terminal-publication" or "fleet-drift")) || (database == "Material" && fault == "complete");
                    if (database is "Country" or "Material")
                    {
                        var observed = await IsoGuardedFleetFixture.NativeAsync(policy.Endpoint, database, contract, selected, ct);
                        if (selected) { Assert.Equal(environment.CandidateSha256(database), observed.Snapshot.Sha256); CurrentOwnerIsoNativePreservation.RequirePreserved(native[database], observed, contract); }
                        else { Assert.Equal(native[database].Snapshot.Sha256, observed.Snapshot.Sha256); CurrentOwnerIsoNativePreservation.RequireBefore(observed, contract); }
                        await proof.NativeAsync("after-" + database, observed, ct);
                    }
                    if (!selected && !(fault == "fleet-drift" && database == "Upload")) { Assert.Equal(baseline.Single(x => x.Database == database).Sha256, snapshot.Sha256); }
                    if (fault == "fleet-drift" && database == "Upload") { Assert.NotEqual(baseline.Single(x => x.Database == database).Sha256, snapshot.Sha256); }
                }
                await proof.FleetAsync("fleet-after", after, ct);
                if (permit is not null)
                {
                    int slots = proof.OperationSlots().Length;
                    _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireExecutionAsync(ct));
                    _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.BeginExecutionAsync(ct));
                    Assert.Equal(slots, proof.OperationSlots().Length); Assert.Equal(1, environment.Reservations);
                    await proof.RecordAsync("replay-rejected", new { unchangedSlots = slots, reservations = environment.Reservations, observedAtUtc = DateTimeOffset.UtcNow }, ct);
                }
                await proof.RecordAsync("provider-invocation", new
                {
                    startedAtUtc = started,
                    exitedAtUtc = DateTimeOffset.UtcNow,
                    returned = actualFailure is null,
                    exceptionType = actualFailure?.GetType().FullName,
                    rejectionCode = (actualFailure as MigrationExecutionException)?.Code,
                    reservations = environment.Reservations
                }, ct);
            }
            finally { if (proxy is not null) { await proxy.DisposeAsync(); } }
        }, deadline.Token);
    }
    private static string FileHash(string path) { using var held = SecureLocalFile.OpenReadShared(path); return Convert.ToHexStringLower(SHA256.HashData(held)); }
}
