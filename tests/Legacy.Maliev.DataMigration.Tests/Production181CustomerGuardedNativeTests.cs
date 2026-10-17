using System.Buffers.Binary;
using System.Data;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;
using Xunit.Abstractions;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Actual provider component proof; source/custody seams are not closed Console authority.
[Collection(Production181CustomerNativeGroup.Name)]
public sealed class Production181CustomerGuardedNativeTests(ITestOutputHelper output)
{
    [WindowsLocalRunFact]
    public Task Customer_sequence_complete()
    {
        return RunCase("complete");
    }

    [WindowsLocalRunFact]
    public Task Customer_sequence_prepared_publication()
    {
        return RunCase("prepared-publication");
    }

    [WindowsLocalRunFact]
    public Task Customer_sequence_commit_ack_lost()
    {
        return RunCase("commit-ack-lost");
    }

    [WindowsLocalRunFact]
    public Task Customer_sequence_terminal_publication()
    {
        return RunCase("terminal-publication");
    }

    [WindowsLocalRunFact]
    public Task Customer_sequence_final_fleet()
    {
        return RunCase("final-fleet");
    }

    [WindowsLocalRunFact]
    public Task Customer_sequence_replay()
    {
        return RunCase("replay");
    }

    [WindowsLocalRunFact]
    public Task Customer_sequence_unsafe_host()
    {
        return RunCase("unsafe-host");
    }

    [WindowsLocalRunFact]
    public Task Customer_sequence_local_trust()
    {
        return RunCase("local-trust");
    }

    [WindowsLocalRunFact]
    public Task Customer_sequence_ordinary_all26()
    {
        return RunCase("ordinary-all26");
    }

    [WindowsLocalRunFact]
    public Task Customer_sequence_exclusive_policy()
    {
        return RunCase("exclusive-policy");
    }

    private Task RunCase(string fault)
    {
        CurrentCustomerSequenceCapacity.Require(admission: true);
        return RunOwnedAsync(async (operation, containerId, adminText, ct) =>
                {
                    var admin = new NpgsqlConnectionStringBuilder(adminText)
                    { Host = "127.0.0.1", Pooling = false, SslMode = SslMode.Disable, Timeout = 5, CommandTimeout = 30 };
                    var prerequisites = ReadPrerequisites();
                    FreshSchemaPlan source = Source() with { SourceCommitSha = prerequisites.Subject.Source.CommitSha };
                    string[] names = [.. DatabaseInventory.ActiveDatabases, "Auth", "postgres", "legacy_local"];
                    Assert.Equal(26, names.Length);
                    await using (var setup = new NpgsqlConnection(admin.ConnectionString))
                    {
                        await setup.OpenAsync(ct);
                        await Sql(setup, null, "CREATE ROLE legacy_local NOLOGIN;", ct);
                        foreach (string database in names.Where(x => x is not ("postgres" or "Auth")))
                        { await Sql(setup, null, $"CREATE DATABASE {Q(database)};", ct); }
                    }
                    await using (var setup = new NpgsqlConnection(admin.ConnectionString)) { await setup.OpenAsync(ct); await Sql(setup, null, "CREATE DATABASE \"Auth\" TEMPLATE template0;", ct); }
                    foreach (string database in names)
                    {
                        await using var setup = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(admin.ConnectionString) { Database = database }.ConnectionString);
                        await setup.OpenAsync(ct);
                        await using var tx = await setup.BeginTransactionAsync(ct);
                        if (DatabaseInventory.ActiveDatabases.Contains(database, StringComparer.Ordinal))
                        {
                            DatabaseSchemaPlan plan = source.Databases.Single(x => x.Database == database);
                            var fixture = plan with
                            {
                                Tables = ApprovedConsumerColumnOverlayManifest.ComposePhysical(plan),
                                TargetExtensionProfile = null,
                                SourceDispositionProfile = null,
                                SourceTableDispositions = []
                            };
                            await using var inspector = new PostgreSqlWholeDatabaseTransaction(setup, tx, ownsResources: false);
                            await inspector.ApplySchemaAsync(fixture, ct); await inspector.FinalizeSchemaAsync(fixture, ct);
                            string rootName = database == "Customer" ? "Customer" : database == "CustomerIdentity" ? "AspNetUsers" : database == "Quotation" ? "Quotation" : "Probe";
                            TableCopyPlan root = fixture.Tables.Single(x => x.TargetSchema == "public" && x.TargetTable == rootName);
                            string key = root.PrimaryKey!.Columns.Single();
                            await Sql(setup, tx, $"INSERT INTO public.{Q(rootName)} ({Q(key)},\"Value\") VALUES ('1','ไทย retained');", ct);
                            if (database == "Customer")
                            {
                                await Sql(setup, tx, "INSERT INTO public.\"Customer\"(\"ID\",\"Value\") VALUES (9,NULL); SELECT setval('public.\"Customer_ID_seq\"',69830,true); SELECT nextval('public.\"Customer_ID_seq\"');", ct);
                            }
                        }
                        await Sql(setup, tx, """
                    CREATE SCHEMA legacy_migration_internal;
                    CREATE TABLE legacy_migration_internal.retained_journal(id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,payload text NOT NULL);
                    INSERT INTO legacy_migration_internal.retained_journal(payload) VALUES ('synthetic receipt ไทย'),('synthetic receipt ไทย');
                    SELECT setval(pg_get_serial_sequence('legacy_migration_internal.retained_journal','id'),91,true);
                    """, ct);
                        // Local installed maintenance policy requires these exact application owners.
                        await using (var query = new NpgsqlCommand("SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p');", setup, tx))
                        {
                            var relations = new List<(string Schema, string Table)>();
                            await using (var reader = await query.ExecuteReaderAsync(ct))
                            { while (await reader.ReadAsync(ct)) { relations.Add((reader.GetString(0), reader.GetString(1))); } }
                            foreach (var (Schema, Table) in relations) { await Sql(setup, tx, $"ALTER TABLE {Q(Schema)}.{Q(Table)} OWNER TO legacy_local;", ct); }
                        }
                        await tx.CommitAsync(ct);
                    }
                    string password = Guid.NewGuid().ToString("N");
                    string binding = CurrentAppOwnedSnapshotSerialization.Sha256(new { operation, containerId, source = SchemaPlanCanonicalizer.ComputeSha256(source) });
                    const string role = "legacy_customer_sequence_native";
                    DateTimeOffset issued = DateTimeOffset.UtcNow;
                    string comment = "legacy-maliev-current-customer-sequence-v1:" + binding;
                    await using (var setup = new NpgsqlConnection(admin.ConnectionString))
                    {
                        await setup.OpenAsync(ct);
                        await Sql(setup, null, $"CREATE ROLE {role} LOGIN SUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{password}' VALID UNTIL '{issued.AddMinutes(30):O}'; COMMENT ON ROLE {role} IS '{comment}';", ct);
                        if (fault == "unsafe-host") { await Sql(setup, null, "CREATE ROLE customer_unprobed_sdk LOGIN;", ct); }
                        await using var path = new NpgsqlCommand("SELECT current_setting('hba_file');", setup);
                        string hbaPath = (string)(await path.ExecuteScalarAsync(ct))!;
                        string local = fault == "local-trust" ? "trust" : "reject";
                        string unprobed = fault == "unsafe-host" ? "('host all customer_unprobed_sdk 0.0.0.0/0 trust')," : string.Empty;
                        await Sql(setup, null, $"COPY (VALUES ('host all {role} 0.0.0.0/0 scram-sha-256'),('host all {role} ::/0 scram-sha-256'),{unprobed}('local all all {local}'),('host all all 0.0.0.0/0 reject'),('host all all ::/0 reject')) TO '{hbaPath.Replace("'", "''", StringComparison.Ordinal)}'; SELECT pg_reload_conf();", ct);
                        bool rejected = false;
                        for (int attempt = 0; attempt < 40 && !rejected; attempt++)
                        {
                            try { await using var ordinary = new NpgsqlConnection(admin.ConnectionString); await ordinary.OpenAsync(ct); }
                            catch (PostgresException failure) when (failure.SqlState == "28000") { rejected = true; }
                            if (!rejected) { await Task.Delay(TimeSpan.FromMilliseconds(50), ct); }
                        }
                        Assert.True(rejected);
                    }
                    var op = new NpgsqlConnectionStringBuilder(admin.ConnectionString) { Username = role, Password = password };
                    string identity;
                    CurrentAppOwnedMaintenancePin maintenance;
                    await using (var observe = new NpgsqlConnection(op.ConnectionString))
                    {
                        await observe.OpenAsync(ct);
                        await using var query = new NpgsqlCommand("""
                    SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),pg_postmaster_start_time(),pg_conf_load_time(),
                      encode(sha256(convert_to(pg_read_file(current_setting('hba_file')),'UTF8')),'hex'),
                      (SELECT encode(sha256(convert_to(jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text,'UTF8')),'hex') FROM pg_hba_file_rules h),
                      current_setting('hba_file'),rolvaliduntil FROM pg_control_system(),pg_roles WHERE rolname=current_user;
                    """, observe);
                        await using var reader = await query.ExecuteReaderAsync(ct);
                        Assert.True(await reader.ReadAsync(ct)); identity = reader.GetString(0);
                        maintenance = new(role, comment, issued, reader.GetFieldValue<DateTimeOffset>(6), reader.GetFieldValue<DateTimeOffset>(1),
                            reader.GetFieldValue<DateTimeOffset>(2), reader.GetString(3), reader.GetString(4), reader.GetString(5));
                    }
                    CurrentCustomerSequenceObservation nativeBefore = await CaptureCustomer(op.ConnectionString, ct);
                    ApprovedCurrentCustomerSequenceDefinition.RequireBefore(nativeBefore, "legacy_local");
                    Assert.Equal(9, nativeBefore.State.AttributeNumber); Assert.Equal(69831, nativeBefore.State.LastValue); Assert.True(nativeBefore.State.LogCount > 0);
                    Assert.Equal(2, nativeBefore.Snapshot.Relations.Single(x => x.Schema == "public" && x.Name == "Customer").Rows);
                    var pool = new CurrentAppOwnedSnapshotInternPool();
                    var baseline = new List<CurrentAppOwnedDatabaseSnapshot>();
                    foreach (string database in names.Order(StringComparer.Ordinal))
                    { baseline.Add(pool.Intern(await Capture(op.ConnectionString, database, ct))); }
                    using ECDsa rk = ECDsa.Create(ECCurve.NamedCurves.nistP256), ak = ECDsa.Create(ECCurve.NamedCurves.nistP256), ek = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                    using var rs = new P256MigrationEvidenceSigner("customer-native-review", rk.ExportPkcs8PrivateKeyPem());
                    using var au = new P256MigrationEvidenceSigner("customer-native-authorization", ak.ExportPkcs8PrivateKeyPem());
                    using var es = new P256MigrationEvidenceSigner("customer-native-receipt", ek.ExportPkcs8PrivateKeyPem());
                    var trust = new ReceiptAttestationTrustStore([new(rs.KeyId, rk.ExportSubjectPublicKeyInfo()), new(au.KeyId, ak.ExportSubjectPublicKeyInfo()), new(es.KeyId, ek.ExportSubjectPublicKeyInfo())]);
                    _ = trust.TryGetPublicKeyFingerprintSha256(rs.KeyId, out string rf);
                    _ = trust.TryGetPublicKeyFingerprintSha256(au.KeyId, out string af);
                    _ = trust.TryGetPublicKeyFingerprintSha256(es.KeyId, out string ef);
                    var pins = new CurrentCustomerSequenceRepairSigningPins(rs.KeyId, rf, au.KeyId, af, es.KeyId, ef);
                    var hashes = baseline.ToDictionary(x => x.Database, CurrentAppOwnedSnapshotSerialization.Sha256, StringComparer.Ordinal);
                    DateTimeOffset sourceTime = DateTimeOffset.UtcNow;
                    var sourceObservation = prerequisites.Subject.Source with { };
                    var ownerObservation = prerequisites.Subject.Owner with { };
                    var definition = ApprovedCurrentCustomerSequenceDefinition.Create(sourceObservation, ownerObservation, source.SourceCommitSha, prerequisites.Catalog, sourceTime);
                    string nativeState = ApprovedCurrentCustomerSequenceDefinition.NativeStateSha256(nativeBefore.State);
                    var scope = new CurrentCustomerSequenceRepairScope(operation, CurrentCustomerSequenceRepairOperation.FixedStartDefinitionOnly,
                        source.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(source), prerequisites.Catalog, sourceObservation, ownerObservation,
                        definition.ComputeSha256(), nativeState, CurrentCustomerSequenceRepairPermit.OperationSha256(source, definition, prerequisites.Definition, nativeState),
                        prerequisites.Definition, CurrentCustomerSequenceRepairPermit.MaintenanceValidator,
                        new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/disposable-" + containerId, identity),
                        "local-aspire", "legacy-postgres-main-local", maintenance.Postmaster.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                        ArtifactHash(operation, "proof-container"), binding,
                        hashes, CurrentCustomerSequenceRepairPermit.FleetSha256(hashes), string.Empty, string.Empty, string.Empty,
                        maintenance, string.Empty, CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap);
                    var subject = new CurrentCustomerSequenceBootstrapSubject("current-customer-sequence-disposable-component-subject-v1",
                        scope.SourceCommitSha, scope.SourceSchemaPlanSha256, scope.CatalogReportSha256, ownerObservation.Head, ownerObservation.ContextSha256,
                        ownerObservation.SnapshotSha256, definition.ComputeSha256(), prerequisites.Definition, nativeState, scope.TargetObservationSha256, binding,
                        AssemblyHash(typeof(MigrationConsole).Assembly.Location), AssemblyHash(typeof(CurrentCustomerSequenceRepairPermit).Assembly.Location),
                        AssemblyHash(typeof(Production181CustomerGuardedNativeTests).Assembly.Location));
                    scope = scope with { BootstrapSubject = subject };
                    WriteLedger(operation, "case-entered", new { operation, containerId, fault, enteredAtUtc = DateTimeOffset.UtcNow });
                    await Production181OwnedHarness.RetainEngineAsync(operation, new NpgsqlConnectionStringBuilder(op.ConnectionString) { Database = "Customer" }.ConnectionString, ct);
                    WriteLedger(operation, "source-schema", source); WriteLedger(operation, "scope", scope); WriteLedger(operation, "signing-pins", pins);
                    WriteLedger(operation, "public-keys", new[] { new { id = rs.KeyId, spki = Convert.ToBase64String(rk.ExportSubjectPublicKeyInfo()) }, new { id = au.KeyId, spki = Convert.ToBase64String(ak.ExportSubjectPublicKeyInfo()) }, new { id = es.KeyId, spki = Convert.ToBase64String(ek.ExportSubjectPublicKeyInfo()) } });
                    WriteLedger(operation, "customer-before", nativeBefore); WriteLedger(operation, "fleet-before", baseline);
                    await RetainPolicyAsync(operation, op.ConnectionString, scope, ct);
                    if (fault is "unsafe-host" or "local-trust")
                    {
                        if (fault == "unsafe-host")
                        {
                            await using var sdk = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(admin.ConnectionString) { Username = "customer_unprobed_sdk" }.ConnectionString);
                            await sdk.OpenAsync(ct); await using var query = new NpgsqlCommand("SELECT current_user;", sdk);
                            Assert.Equal("customer_unprobed_sdk", await query.ExecuteScalarAsync(ct));
                        }
                        var unsafeEnvironment = new NativeEnvironment(op.ConnectionString, admin.ConnectionString, scope, source, baseline, nativeBefore, null, fault);
                        DateTimeOffset now = DateTimeOffset.UtcNow;
                        var ur = new CurrentCustomerSequenceRepairSignedClaim("current-customer-sequence-repair-review-v1", scope, Guid.NewGuid(), null, now, now.AddMinutes(20), rs.KeyId, null);
                        var review = ur with { Signature = Convert.ToBase64String(rs.Sign(CurrentCustomerSequenceRepairPermit.Payload(ur))) };
                        var ua = new CurrentCustomerSequenceRepairSignedClaim("current-customer-sequence-repair-authorization-v1", scope, Guid.NewGuid(), CurrentAppOwnedSnapshotSerialization.Sha256(review), now, now.AddMinutes(15), au.KeyId, null);
                        var authorization = ua with { Signature = Convert.ToBase64String(au.Sign(CurrentCustomerSequenceRepairPermit.Payload(ua))) };
                        CurrentCustomerSequenceRepairPermit.ValidateClaims(review, authorization, source, trust, pins, now);
                        WriteLedger(operation, "review", review); WriteLedger(operation, "authorization", authorization);
                        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentCustomerSequenceRepairPermit.AdmitAsync(review, authorization, source, trust, pins, unsafeEnvironment, TimeProvider.System, ct));
                        Assert.Equal("current_app_owned_maintenance_hba_not_exclusive", failure.Code);
                        Assert.Empty(unsafeEnvironment.Evidence); Assert.Equal(0, unsafeEnvironment.Reservations);
                        Assert.Equal(nativeBefore.Snapshot.Sha256, (await CaptureCustomer(op.ConnectionString, ct)).Snapshot.Sha256);
                        await RetainFinalAsync(operation, fault, op.ConnectionString, names, unsafeEnvironment, failure.Code, false, ct);
                        return;
                    }
                    if (fault is "ordinary-all26" or "exclusive-policy")
                    {
                        var probeEnvironment = new NativeEnvironment(op.ConnectionString, admin.ConnectionString, scope, source, baseline, nativeBefore, null, fault);
                        await probeEnvironment.RequireResourceAndCustodyAsync(scope, ct);
                        var probeFleet = await probeEnvironment.InspectFleetAsync(scope, ct);
                        Assert.Equal(names.Order(StringComparer.Ordinal), probeEnvironment.OrdinaryRejected.Order(StringComparer.Ordinal));
                        Assert.All(probeFleet, x => Assert.Equal(hashes[x.Database], x.Sha256)); Assert.Empty(probeEnvironment.Evidence); Assert.Equal(0, probeEnvironment.Reservations);
                        var review = await CurrentCustomerSequenceRepairPermit.IssueReviewAsync(scope, source, baseline, trust, pins, probeEnvironment, rs, DateTimeOffset.UtcNow.AddMinutes(20), TimeProvider.System, ct);
                        var authorization = await CurrentCustomerSequenceRepairPermit.AuthorizeAsync(review, source, trust, pins, probeEnvironment, au, TimeProvider.System, ct);
                        WriteLedger(operation, "review", review); WriteLedger(operation, "authorization", authorization);
                        await RetainFinalAsync(operation, fault, op.ConnectionString, names, probeEnvironment, null, false, ct); return;
                    }
                    await using var proxy = new CommitAcknowledgementProxy("127.0.0.1", op.Port, operation);
                    using (var process = System.Diagnostics.Process.GetCurrentProcess())
                    { WriteLedger(operation, "proxy", new { operation, port = proxy.Port, processId = process.Id, processStartTimeUtc = process.StartTime.ToUniversalTime(), executable = Environment.ProcessPath, expiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(8), persistent = false }); }
                    var execution = new NpgsqlConnectionStringBuilder(op.ConnectionString) { Port = proxy.Port };
                    var environment = new NativeEnvironment(op.ConnectionString, admin.ConnectionString, scope, source, baseline, nativeBefore, fault == "commit-ack-lost" ? proxy : null, fault);
                    var r = await CurrentCustomerSequenceRepairPermit.IssueReviewAsync(scope, source, baseline, trust, pins, environment, rs, DateTimeOffset.UtcNow.AddMinutes(20), TimeProvider.System, ct);
                    var a = await CurrentCustomerSequenceRepairPermit.AuthorizeAsync(r, source, trust, pins, environment, au, TimeProvider.System, ct);
                    WriteLedger(operation, "review", r); WriteLedger(operation, "authorization", a);
                    environment.AuthorizationSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(a);
                    var permit = await CurrentCustomerSequenceRepairPermit.AdmitAsync(r, a, source, trust, pins, environment, TimeProvider.System, ct);
                    Exception? observedFailure = null;
                    if (fault is "complete" or "replay")
                    {
                        CurrentCustomerSequenceRepairReceipt terminal = await PostgreSqlCurrentCustomerSequenceRepair.ExecuteAsync(execution.ConnectionString, nativeBefore, permit, es, trust, pins, ct);
                        Assert.Equal(CurrentAppOwnedCommitClassification.CommittedAndReadback, terminal.Classification);
                        Assert.Equal(2, environment.Evidence.Count);
                    }
                    else
                    {
                        observedFailure = await Assert.ThrowsAnyAsync<Exception>(() => PostgreSqlCurrentCustomerSequenceRepair.ExecuteAsync(execution.ConnectionString, nativeBefore, permit, es, trust, pins, ct));
                        if (fault == "commit-ack-lost") { await proxy.Dropped.WaitAsync(TimeSpan.FromSeconds(10), ct); Assert.Equal(1, proxy.DroppedCommits); }
                        CurrentCustomerSequenceRepairReceipt failure = environment.Receipt("failed-or-uncertain");
                        Assert.Equal(fault == "prepared-publication" ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.Uncertain, failure.Classification);
                        Assert.Equal(nativeBefore.Snapshot.Sha256, failure.BeforeSha256);
                        Assert.Equal(environment.Receipt("prepared").AfterSha256, failure.AfterSha256);
                    }
                    CurrentCustomerSequenceObservation actual = await CaptureCustomer(op.ConnectionString, ct);
                    CurrentCustomerSequenceRepairReceipt prepared = environment.Receipt("prepared");
                    if (fault == "prepared-publication") { Assert.Equal(nativeBefore.Snapshot.Sha256, actual.Snapshot.Sha256); ApprovedCurrentCustomerSequenceDefinition.RequireBefore(actual, "legacy_local"); }
                    else { ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(nativeBefore, actual, "legacy_local"); Assert.Equal(prepared.AfterSha256, actual.Snapshot.Sha256); }
                    var actualFleet = new List<CurrentAppOwnedDatabaseSnapshot>();
                    var finalPool = new CurrentAppOwnedSnapshotInternPool();
                    foreach (string database in names.Order(StringComparer.Ordinal)) { actualFleet.Add(finalPool.Intern(await Capture(op.ConnectionString, database, ct))); }
                    foreach (string remaining in names.Where(x => x != "Customer")) { Assert.Equal(hashes[remaining], actualFleet.Single(x => x.Database == remaining).Sha256); }
                    string zero = new('0', 64), preparedHash = CurrentAppOwnedSnapshotSerialization.Sha256(prepared);
                    PostgreSqlCurrentCustomerSequenceRepair.RequireReceipt(prepared, scope, permit.AuthorizationSha256, trust, pins, zero, DateTimeOffset.UtcNow);
                    foreach (var pair in environment.Evidence.Where(x => !x.Key.EndsWith("-prepared.json", StringComparison.Ordinal)))
                    {
                        CurrentCustomerSequenceRepairReceipt receipt = JsonSerializer.Deserialize<CurrentCustomerSequenceRepairReceipt>(pair.Value)!;
                        string previous = fault == "prepared-publication" ? zero : receipt.Classification == CurrentAppOwnedCommitClassification.Uncertain && fault == "final-fleet" ?
                            CurrentAppOwnedSnapshotSerialization.Sha256(environment.Receipt("committed-readback")) : preparedHash;
                        PostgreSqlCurrentCustomerSequenceRepair.RequireReceipt(receipt, scope, permit.AuthorizationSha256, trust, pins, previous, DateTimeOffset.UtcNow);
                    }
                    var retained = environment.Evidence.ToDictionary(x => x.Key, x => x.Value.ToArray(), StringComparer.Ordinal);
                    _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireAsync(ct));
                    MigrationExecutionException? replayFailure = null;
                    if (fault == "replay")
                    {
                        replayFailure = await Assert.ThrowsAsync<MigrationExecutionException>(() => PostgreSqlCurrentCustomerSequenceRepair.ExecuteAsync(execution.ConnectionString, nativeBefore, permit, es, trust, pins, ct));
                        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentCustomerSequenceRepairPermit.AdmitAsync(r, a, source, trust, pins, environment, TimeProvider.System, ct));
                    }
                    Assert.Equal(1, environment.Reservations); Assert.Equal(retained.Count, environment.Evidence.Count);
                    foreach (var pair in retained) { Assert.Equal(pair.Value, environment.Evidence[pair.Key]); }
                    Assert.Equal(actual.Snapshot.Sha256, (await CaptureCustomer(op.ConnectionString, ct)).Snapshot.Sha256);
                    string? rejection = fault == "replay" ? replayFailure?.Code : observedFailure is MigrationExecutionException executionFailure ? executionFailure.Code : observedFailure?.GetType().FullName;
                    await RetainFinalAsync(operation, fault, op.ConnectionString, names, environment, rejection, fault is not ("prepared-publication" or "commit-ack-lost"), ct);
                });
    }

    // Source/owner/custody checks below are deliberately supplied component seams.
    // Installed role/HBA/system identity and complete native fleet observations are real.
    private sealed class NativeEnvironment(string op, string ordinary, CurrentCustomerSequenceRepairScope scope, FreshSchemaPlan source,
        IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> baseline, CurrentCustomerSequenceObservation nativeBefore,
        CommitAcknowledgementProxy? proxy, string fault) : ICurrentCustomerSequenceRepairEnvironment, ICurrentCustomerSequenceCandidateProofObserver
    {
        private bool _reserved, _arm, _terminalAcknowledged;
        private readonly Lock _gate = new();
        internal int Reservations { get; private set; }
        internal string AuthorizationSha256 { get; set; } = string.Empty;
        internal Dictionary<string, byte[]> Evidence { get; } = new(StringComparer.Ordinal);
        internal HashSet<string> Acknowledged { get; } = new(StringComparer.Ordinal);
        internal CurrentCustomerSequenceObservation? Candidate { get; private set; }
        internal List<string> OrdinaryRejected { get; } = [];
        internal IReadOnlyDictionary<string, string> Expected => scope.BeforeDatabaseSha256;
        public Task RequireSourceAsync(string commit, CancellationToken ct)
        {
            return commit == scope.SourceCommitSha ? Task.CompletedTask : throw CurrentCustomerSequenceRepairPermit.Invalid();
        }

        public Task<CurrentCustomerSequenceSource> ObserveCurrentCatalogAsync(string accepted, CancellationToken ct)
        {
            return accepted == scope.SourceCommitSha ? Task.FromResult(scope.SourceObservation with { }) : throw CurrentCustomerSequenceRepairPermit.Invalid();
        }

        public Task<CurrentCustomerSequenceOwner> ObserveOwnerAsync(CancellationToken ct)
        {
            return Task.FromResult(scope.OwnerObservation with { });
        }

        public Task<CurrentCustomerSequenceObservation> ObserveNativeBeforeAsync(CurrentCustomerSequenceRepairScope current, CancellationToken ct)
        {
            return CaptureCustomer(op, ct);
        }

        public Task RequireSource23PhysicalBaselineAsync(FreshSchemaPlan supplied, CurrentCustomerSequenceRepairScope current, CancellationToken ct)
        {
            return SchemaPlanCanonicalizer.ComputeSha256(supplied) != SchemaPlanCanonicalizer.ComputeSha256(source)
                ? throw CurrentCustomerSequenceRepairPermit.Invalid()
                : Task.CompletedTask;
        }
        public async Task RequireResourceAndCustodyAsync(CurrentCustomerSequenceRepairScope current, CancellationToken ct)
        {
            if (JsonSerializer.Serialize(current) != JsonSerializer.Serialize(scope)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            foreach (string database in scope.BeforeDatabaseSha256.Keys)
            {
                bool rejected = false;
                try { await using var probe = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(ordinary) { Database = database }.ConnectionString); await probe.OpenAsync(ct); }
                catch (PostgresException failure) when (failure.SqlState == "28000") { rejected = true; }
                if (!rejected) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                if (!OrdinaryRejected.Contains(database, StringComparer.Ordinal)) { OrdinaryRejected.Add(database); }
            }
            if (_arm) { proxy?.Arm(); _arm = false; }
        }
        public async Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CurrentCustomerSequenceRepairScope current, CancellationToken ct)
        {
            if (JsonSerializer.Serialize(current) != JsonSerializer.Serialize(scope)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            if (_terminalAcknowledged && fault == "final-fleet") { throw new IOException("Actual final fleet observation unavailable after acknowledged terminal retention."); }
            await using (var connection = new NpgsqlConnection(op))
            {
                await connection.OpenAsync(ct);
                await using var query = new NpgsqlCommand("SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname COLLATE \"C\";", connection);
                var names = new List<string>(); await using var reader = await query.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct)) { names.Add(reader.GetString(0)); }
                Assert.Equal(scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal), names);
            }
            var pool = new CurrentAppOwnedSnapshotInternPool(); var actual = new List<CurrentAppOwnedDatabaseSnapshot>();
            foreach (CurrentAppOwnedDatabaseSnapshot expected in baseline)
            {
                await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(op) { Database = expected.Database }.ConnectionString);
                await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
                await Sql(connection, tx, "SET TRANSACTION READ ONLY;", ct);
                await PostgreSqlCurrentCustomerSequenceRepair.RequireInstalledPolicyAsync(connection, tx, scope, ct);
                CurrentAppOwnedDatabaseSnapshot snapshot;
                if (expected.Database == "Customer")
                {
                    CurrentCustomerSequenceObservation auth = await CurrentCustomerSequenceNativeObservation.CaptureAsync(connection, tx, ct);
                    snapshot = pool.Intern(auth.Snapshot);
                    if (snapshot.Sha256 == scope.BeforeDatabaseSha256["Customer"]) { ApprovedCurrentCustomerSequenceDefinition.RequireBefore(auth, "legacy_local"); }
                    else
                    {
                        CurrentCustomerSequenceRepairReceipt prepared = Receipt("prepared");
                        if (prepared.AfterSha256 != snapshot.Sha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                        ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(nativeBefore, auth, "legacy_local");
                    }
                }
                else
                {
                    snapshot = pool.Intern(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct));
                    Assert.Equal(expected.Sha256, snapshot.Sha256);
                    if (DatabaseInventory.ActiveDatabases.Contains(expected.Database, StringComparer.Ordinal))
                    {
                        DatabaseSchemaPlan physical = source.Databases.Single(x => x.Database == expected.Database);
                        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                        Assert.Equal(physical.TargetSchemaSha256, await inspector.InspectSchemaAsync(physical, ct));
                    }
                }
                actual.Add(snapshot); await tx.RollbackAsync(ct);
            }
            return actual.AsReadOnly();
        }
        public Task RequireFreshOperationAsync(CurrentCustomerSequenceRepairScope current, CancellationToken ct)
        {
            return _reserved || Evidence.Count != 0 ? throw CurrentCustomerSequenceRepairPermit.Invalid() : Task.CompletedTask;
        }

        public Task ReserveFreshOperationAsync(CurrentCustomerSequenceRepairScope current, string authorization, CancellationToken ct)
        {
            lock (_gate)
            {
                if (_reserved || Evidence.Count != 0 || authorization != AuthorizationSha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                _reserved = true; Reservations++;
                WriteLedger(scope.OperationId, "operation-reservation", new { scope.OperationId, scope.OperationSha256, authorizationSha256 = authorization, observedAtUtc = DateTimeOffset.UtcNow });
                return Task.CompletedTask;
            }
        }
        public Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken ct)
        {
            if (!Evidence.TryAdd(name, payload.ToArray())) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            WriteImmutablePayload(name, payload);
            bool prepared = name.EndsWith("-prepared.json", StringComparison.Ordinal);
            if (prepared) { _arm = true; }
            WriteLedger(scope.OperationId, "receipt-slot-" + Evidence.Count, new { name, payload = JsonSerializer.Deserialize<JsonElement>(payload), acknowledged = false, observedAtUtc = DateTimeOffset.UtcNow });
            if ((prepared && fault == "prepared-publication") || (name.EndsWith("-committed-readback.json", StringComparison.Ordinal) && fault == "terminal-publication"))
            { throw new IOException("Actual immutable retention completed; publication acknowledgement deliberately withheld."); }
            _ = Acknowledged.Add(name); WriteLedger(scope.OperationId, "receipt-ack-" + Acknowledged.Count, new { name, observedAtUtc = DateTimeOffset.UtcNow });
            if (name.EndsWith("-committed-readback.json", StringComparison.Ordinal)) { _terminalAcknowledged = true; }
            return Task.CompletedTask;
        }
        public async Task RetainActualCandidateAsync(CurrentCustomerSequenceObservation before, CurrentCustomerSequenceObservation candidate, CancellationToken ct)
        {
            Assert.Equal(nativeBefore.Snapshot.Sha256, before.Snapshot.Sha256);
            ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, candidate, "legacy_local");
            Candidate = new(candidate.State with { }, CurrentCustomerSequenceRepairPermit.CopySnapshot(candidate.Snapshot));
            WriteLedger(scope.OperationId, "customer-candidate", Candidate);
            var actual = new List<CurrentAppOwnedDatabaseSnapshot>(); var candidatePool = new CurrentAppOwnedSnapshotInternPool();
            foreach (string database in scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))
            { actual.Add(candidatePool.Intern(database == "Customer" ? candidate.Snapshot : await Capture(op, database, ct))); }
            WriteLedger(scope.OperationId, "fleet-candidate", actual);
        }
        internal CurrentCustomerSequenceRepairReceipt Receipt(string suffix)
        {
            return JsonSerializer.Deserialize<CurrentCustomerSequenceRepairReceipt>(Evidence[$"{scope.OperationId:D}-Customer-{suffix}.json"])!;
        }
    }

    private static async Task<CurrentCustomerSequenceObservation> CaptureCustomer(string text, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(text) { Database = "Customer", Pooling = false }.ConnectionString);
        await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await Sql(connection, tx, "SET TRANSACTION READ ONLY;", ct);
        CurrentCustomerSequenceObservation value = await CurrentCustomerSequenceNativeObservation.CaptureAsync(connection, tx, ct);
        await tx.RollbackAsync(ct); return value;
    }
    private static async Task<CurrentAppOwnedDatabaseSnapshot> Capture(string connectionString, string database, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(connectionString) { Database = database, Pooling = false }.ConnectionString);
        await connection.OpenAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await Sql(connection, tx, "SET TRANSACTION READ ONLY;", ct);
        var snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct);
        await tx.RollbackAsync(ct); return snapshot;
    }
    private static async Task Sql(NpgsqlConnection connection, NpgsqlTransaction? tx, string text, CancellationToken ct)
    { await using var command = new NpgsqlCommand(text, connection, tx); _ = await command.ExecuteNonQueryAsync(ct); }
    private static string Q(string text)
    {
        return PostgreSqlShadowTarget.QuoteIdentifier(text);
    }

    private sealed record ObservedPrerequisites(string Catalog, string Definition, CustomerDefinitionSubject Subject);
    private static ObservedPrerequisites ReadPrerequisites()
    {
        string path = Environment.GetEnvironmentVariable("MALIEV_PRODUCTION181_PREREQUISITES") ?? throw new InvalidDataException("Actual prerequisite paths required.");
        using var manifest = SecureLocalFile.OpenReadShared(path);
        if (manifest.Length is < 1 or > 65536) { throw new InvalidDataException("Bounded actual manifest required."); }
        var paths = JsonSerializer.Deserialize<Production181PrerequisitePaths>(manifest) ?? throw new InvalidDataException("Actual prerequisite paths required.");
        using var held = Production181HeldDefinition.Open(paths);
        if (held.Proof.Subject.ConsoleAssemblySha256 != AssemblyHash(typeof(MigrationConsole).Assembly.Location) ||
            held.Proof.Subject.CoreAssemblySha256 != AssemblyHash(typeof(CurrentCustomerSequenceRepairPermit).Assembly.Location) ||
            held.Proof.Cases.Any(x => x.TestAssembly.Sha256 != AssemblyHash(typeof(Production181CustomerGuardedNativeTests).Assembly.Location))) { throw new InvalidDataException("Current actual executing image mismatch."); }
        held.Require(); return new(held.CatalogSha256, held.DefinitionSha256, held.Proof.Subject);
    }
    private static string AssemblyHash(string path)
    {
        FileSystemInfo? item = new FileInfo(path);
        while (item is not null)
        { if ((item.Attributes & FileAttributes.ReparsePoint) != 0) { throw new InvalidDataException("Actual non-link binary required."); } item = item is FileInfo file ? file.Directory : (item as DirectoryInfo)?.Parent; }
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return !SecureLocalFile.HandleResolvesToApprovedPath(stream, path) || stream.Length is < 1 or > 128 * 1024 * 1024
            ? throw new InvalidDataException("Actual bounded binary required.")
            : Convert.ToHexStringLower(SHA256.HashData(stream));
    }
    private static string ArtifactHash(Guid run, string phase)
    { using var stream = SecureLocalFile.OpenRead(Path.Combine(RequireLedgerDirectory(), run.ToString("N") + "-" + phase + ".json")); return Convert.ToHexStringLower(SHA256.HashData(stream)); }
    private static async Task RetainFinalAsync(Guid operation, string fault, string op, IReadOnlyList<string> names, NativeEnvironment environment, string? code, bool acknowledged, CancellationToken ct)
    {
        var customer = await CaptureCustomer(op, ct); var fleet = new List<CurrentAppOwnedDatabaseSnapshot>(); var finalPool = new CurrentAppOwnedSnapshotInternPool();
        foreach (string database in names.Order(StringComparer.Ordinal)) { fleet.Add(finalPool.Intern(await Capture(op, database, ct))); }
        foreach (var retained in fleet.Where(x => x.Database != "Customer")) { Assert.Equal(environment.Expected[retained.Database], retained.Sha256); }
        if (fault is "unsafe-host" or "local-trust" or "ordinary-all26" or "exclusive-policy" or "prepared-publication")
        { Assert.Equal(environment.Expected["Customer"], customer.Snapshot.Sha256); }
        WriteLedger(operation, "customer-after", customer); WriteLedger(operation, "fleet-after", fleet);
        WriteLedger(operation, "scenario", new
        {
            operation,
            fault,
            rejectionCode = code,
            commitAcknowledged = acknowledged,
            installedSemanticPolicyAccepted = fault is not ("unsafe-host" or "local-trust"),
            ordinaryRejected = environment.OrdinaryRejected,
            retainedSlots = environment.Evidence.Select(x => new { name = x.Key, sha256 = CurrentCustomerSequenceRepairPermit.Hash(x.Value), acknowledged = environment.Acknowledged.Contains(x.Key) }).ToArray(),
            replayRejected = fault == "replay",
            observedAtUtc = DateTimeOffset.UtcNow
        });
    }
    private static async Task RetainPolicyAsync(Guid operation, string endpoint, CurrentCustomerSequenceRepairScope scope, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(endpoint); await connection.OpenAsync(ct);
        const string sql = """
            SELECT pg_read_file(current_setting('hba_file')),
              (SELECT jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text FROM pg_hba_file_rules h),
              jsonb_build_object('systemIdentifierSha256',encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),
                'postmaster',pg_postmaster_start_time(),'configLoaded',pg_conf_load_time(),'role',current_user,
                'roleExpires',r.rolvaliduntil,'roleComment',shobj_description(r.oid,'pg_authid'),'superuser',r.rolsuper,
                'login',r.rolcanlogin,'createRole',r.rolcreaterole,'createDatabase',r.rolcreatedb,'replication',r.rolreplication,
                'bypassRls',r.rolbypassrls,'memberships',(SELECT count(*) FROM pg_auth_members WHERE member=r.oid),
                'scram',(SELECT rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE oid=r.oid),
                'defaultAcls',(SELECT count(*) FROM pg_default_acl WHERE defaclrole=r.oid),
                'otherClients',(SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid()),
                'preparedTransactions',(SELECT count(*) FROM pg_prepared_xacts),
                'eventTriggers',(SELECT count(*) FROM pg_event_trigger WHERE evtenabled<>'D'),
                'hbaPath',current_setting('hba_file'),'primary',NOT pg_is_in_recovery())::text
            FROM pg_control_system(),pg_roles r WHERE rolname=current_user;
            """;
        await using var command = new NpgsqlCommand(sql, connection); await using var reader = await command.ExecuteReaderAsync(ct);
        Assert.True(await reader.ReadAsync(ct)); string hba = reader.GetString(0), rules = reader.GetString(1); JsonElement policy = JsonSerializer.Deserialize<JsonElement>(reader.GetString(2));
        WriteLedger(operation, "hba-file", new { operation, text = hba }); WriteLedger(operation, "hba-rules", new { operation, text = rules });
        Assert.Equal(scope.Maintenance.HbaSha256, Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(hba))));
        Assert.Equal(scope.Maintenance.HbaRulesSha256, Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(rules))));
        WriteLedger(operation, "installed-policy", new { operation, policy, observedAtUtc = DateTimeOffset.UtcNow });
    }
    private static FreshSchemaPlan Source()
    {
        var schema = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3) with { CapturedAtUtc = DateTimeOffset.UtcNow };
        return schema with { Databases = [.. schema.Databases.Select(database => database.Database == "Customer" ? Customer(database) : database.Database == "Quotation" ? Map(database) : database)] };
        static DatabaseSchemaPlan Customer(DatabaseSchemaPlan database)
        {
            string[] preceding = [.. Enumerable.Range(1, 8).Select(x => "p" + x)]; string[] columns = [.. preceding, "ID", "Value"];
            var types = columns.ToDictionary(x => x, x => x == "ID" ? "integer" : "text", StringComparer.Ordinal);
            var root = new TableCopyPlan("dbo", "Customer", "public", "Customer", columns, ["ID"])
            { ColumnTypes = types, PrimaryKey = new("PK_Customer", ["ID"]), NullableColumns = [.. preceding, "Value"], IdentityColumns = ["ID"], Identities = [new("ID", 1, 1, 1, false)] };
            var mapped = database with { Tables = [root, .. database.Tables.Skip(1)] };
            return mapped with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(mapped) };
        }
        static DatabaseSchemaPlan Map(DatabaseSchemaPlan database)
        {
            TableCopyPlan[] tables = [database.Tables[0], ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", true), ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", false), .. database.Tables.Skip(3)];
            database = database with
            {
                Tables = tables,
                SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
                SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables)
            };
            return database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
        }
    }

    private sealed class CommitAcknowledgementProxy : IAsyncDisposable
    {
        private readonly Guid _operation;
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _lifetime = new(TimeSpan.FromMinutes(8));
        private readonly TaskCompletionSource _dropped = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Task _worker;
        private int _armed, _droppedCommits;
        internal int Port { get; }
        internal Task Dropped => _dropped.Task;
        internal int DroppedCommits => Volatile.Read(ref _droppedCommits);
        internal void Arm() { _ = Interlocked.Exchange(ref _armed, 1); }
        internal CommitAcknowledgementProxy(string host, int port, Guid operation)
        { _operation = operation; _listener.Start(1); Port = ((IPEndPoint)_listener.LocalEndpoint).Port; _worker = RunAsync(host, port); }
        private async Task RunAsync(string host, int port)
        {
            try
            {
                while (!_lifetime.IsCancellationRequested)
                {
                    using TcpClient client = await _listener.AcceptTcpClientAsync(_lifetime.Token);
                    using var server = new TcpClient(); await server.ConnectAsync(host, port, _lifetime.Token);
                    using var session = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
                    Task frontend = client.GetStream().CopyToAsync(server.GetStream(), session.Token);
                    Task backend = Relay(server.GetStream(), client.GetStream(), session.Token);
                    try { _ = await Task.WhenAny(frontend, backend); }
                    finally
                    {
                        await session.CancelAsync(); client.Close(); server.Close();
                        try { await Task.WhenAll(frontend, backend); }
                        catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
                        if (DroppedCommits > 0) { _ = _dropped.TrySetResult(); }
                    }
                }
            }
            catch (Exception e) when (_lifetime.IsCancellationRequested && e is OperationCanceledException or SocketException or ObjectDisposedException) { }
        }
        private async Task Relay(NetworkStream server, NetworkStream client, CancellationToken ct)
        {
            byte[] header = new byte[5];
            while (true)
            {
                int first = await server.ReadAsync(header.AsMemory(0, 1), ct); if (first == 0) { return; }
                await server.ReadExactlyAsync(header.AsMemory(1, 4), ct);
                int length = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(1));
                if (length is < 4 or > 16 * 1024 * 1024) { throw new InvalidDataException("Invalid owned PostgreSQL frame."); }
                byte[] payload = new byte[length - 4]; await server.ReadExactlyAsync(payload, ct);
                if (header[0] == (byte)'C' && payload.AsSpan().SequenceEqual("COMMIT\0"u8) && Interlocked.CompareExchange(ref _armed, 0, 1) == 1)
                {
                    int count = Interlocked.Increment(ref _droppedCommits);
                    WriteLedger(_operation, "commit-ack-observed-drop", new { operation = _operation, count, frameTag = header[0], payloadSha256 = CurrentCustomerSequenceRepairPermit.Hash(payload), observedAtUtc = DateTimeOffset.UtcNow });
                    return;
                }
                await client.WriteAsync(header, ct); await client.WriteAsync(payload, ct);
            }
        }
        public async ValueTask DisposeAsync()
        {
            await _lifetime.CancelAsync(); _listener.Stop();
            try { await _worker.WaitAsync(TimeSpan.FromSeconds(10)); }
            finally { _lifetime.Dispose(); WriteLedger(_operation, "proxy-disposed", new { operation = _operation, port = Port, workerCompleted = _worker.IsCompleted, completedAtUtc = DateTimeOffset.UtcNow }); }
            Assert.True(_worker.IsCompleted);
        }
    }
    private Task RunOwnedAsync(Func<Guid, string, string, CancellationToken, Task> body)
    {
        return Production181OwnedHarness.RunAsync(body, output, RequireLedgerDirectory(), typeof(Production181CustomerGuardedNativeTests).Assembly.Location);
    }

    private static void WriteLedger(Guid run, string phase, object record)
    {
        string directory = RequireLedgerDirectory(); string path = Path.Combine(directory, run.ToString("N") + "-" + phase + ".json");
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        if (!SecureLocalFile.HandleResolvesToApprovedPath(file, path) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path))) { throw new InvalidOperationException("Owned Customer guarded ledger file required."); }
        JsonSerializer.Serialize(file, record);
        file.Flush(flushToDisk: true);
    }
    private static void WriteImmutablePayload(string name, byte[] bytes)
    {
        if (Path.GetFileName(name) != name) { throw new InvalidOperationException("Fixed immutable receipt basename required."); }
        string path = Path.Combine(RequireLedgerDirectory(), name); using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        if (!SecureLocalFile.HandleResolvesToApprovedPath(file, path) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path))) { throw new InvalidOperationException("Owned receipt required."); }
        file.Write(bytes); file.Flush(flushToDisk: true);
    }
    private static string RequireLedgerDirectory()
    {
        string path = Environment.GetEnvironmentVariable("MALIEV_PRODUCTION181_NATIVE_LEDGER") ?? throw new InvalidOperationException("Existing owned guarded native ledger directory required.");
        string full = Path.GetFullPath(path); if (!Directory.Exists(full)) { throw new InvalidOperationException("Existing ledger required."); }
        SecureLocalFile.EnsureOwnerOnlyDirectory(full); return full;
    }
}
