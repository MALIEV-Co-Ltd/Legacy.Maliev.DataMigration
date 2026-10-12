using System.Buffers.Binary;
using System.Data;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;
using Testcontainers.PostgreSql;
using Xunit.Abstractions;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAppOwnedV3RepairNativeTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData("success")]
    [InlineData("prepared-publication")]
    [InlineData("lost-commit-ack")]
    [InlineData("terminal-publication")]
    [InlineData("host-unprobed-sdk")]
    [InlineData("local-ordinary-trust")]
    public async Task Real_fixed_v3_execution_preserves_fleet_and_immutable_receipts_or_stops(string fault)
    {
        // Genuine native provider/policy/receipt component proof. Source/custody and Docker
        // target observations below are component seams, never closed Console authority.
        using var expiry = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        CancellationToken ct = expiry.Token;
        Guid operation = Guid.NewGuid();
        string run = operation.ToString("N"), name = "v3-guarded-executor-" + run;
        DateTimeOffset started = DateTimeOffset.UtcNow;
        WriteLedger(run, "attempt", new { run, name, fault, startedAtUtc = started, expiresAtUtc = started.AddMinutes(8), persistent = false });
        string? containerId = null;
        output.WriteLine("Owned attempt run={0}; name={1}; start={2:O}; expiry={3:O}; persistent=false", run, name, started, started.AddMinutes(8));
        var postgres = new PostgreSqlBuilder("postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382")
            .WithDatabase("postgres").WithUsername("postgres").WithPassword(Guid.NewGuid().ToString("N"))
            .WithName(name).WithLabel("codex.repair.run", run).WithLabel("codex.repair.purpose", "v3-native-executor")
            .WithCreateParameterModifier(p => { p.Cmd = ["postgres", "-c", "autovacuum=off"]; p.HostConfig!.Memory = 512 * 1024 * 1024; p.HostConfig.MemorySwap = 512 * 1024 * 1024; p.HostConfig.NanoCPUs = 750_000_000; }).Build();
        try
        {
            await postgres.StartAsync(ct);
            containerId = postgres.Id;
            WriteLedger(run, "observed", new { run, name, containerId = postgres.Id, port = postgres.GetMappedPublicPort(5432) });
            output.WriteLine("Owned observed run={0}; container={1}; name={2}; port={3}", run, postgres.Id, name, postgres.GetMappedPublicPort(5432));
            var admin = new NpgsqlConnectionStringBuilder(postgres.GetConnectionString())
            { Host = "127.0.0.1", Pooling = false, SslMode = SslMode.Disable, Timeout = 10, CommandTimeout = 30 };
            FreshSchemaPlan before = Pair(ConsumerOverlaySelection.CurrentConsumerSchemaV2);
            FreshSchemaPlan after = Pair(ConsumerOverlaySelection.CurrentConsumerSchemaV3) with { CapturedAtUtc = before.CapturedAtUtc };
            CurrentAppOwnedV3AdditiveContract contract = CurrentAppOwnedV3AdditiveContract.Create(before, after, before.SourceCommitSha, DateTimeOffset.UtcNow);
            string[] names = [.. DatabaseInventory.ActiveDatabases, "Auth", "postgres", "legacy_local"];
            Assert.Equal(26, names.Length);
            await using (var create = new NpgsqlConnection(admin.ConnectionString))
            {
                await create.OpenAsync(ct);
                await using (var setting = new NpgsqlCommand("SHOW autovacuum;", create))
                { Assert.Equal("off", (string)(await setting.ExecuteScalarAsync(ct))!); }
                WriteLedger(run, "fixture-setting", new { run, containerId, autovacuum = "off", disposableOnly = true });
                await Sql(create, null, "CREATE ROLE legacy_local NOLOGIN;", ct);
                foreach (string database in names.Where(x => x != "postgres"))
                { await Sql(create, null, $"CREATE DATABASE {Q(database)};", ct); }
            }
            foreach (string database in names)
            {
                var settings = new NpgsqlConnectionStringBuilder(admin.ConnectionString) { Database = database };
                await using var setup = new NpgsqlConnection(settings.ConnectionString);
                await setup.OpenAsync(ct);
                await using var tx = await setup.BeginTransactionAsync(ct);
                if (DatabaseInventory.ActiveDatabases.Contains(database, StringComparer.Ordinal))
                {
                    DatabaseSchemaPlan physical = contract.BeforeForDatabase(database);
                    var fixture = physical with
                    {
                        Tables = ApprovedConsumerColumnOverlayManifest.ComposePhysical(physical),
                        TargetExtensionProfile = null,
                        SourceDispositionProfile = null,
                        SourceTableDispositions = []
                    };
                    await using var inspector = new PostgreSqlWholeDatabaseTransaction(setup, tx, ownsResources: false);
                    await inspector.ApplySchemaAsync(fixture, ct);
                    await inspector.FinalizeSchemaAsync(fixture, ct);
                    foreach (TableCopyPlan table in fixture.Tables)
                    { await Sql(setup, tx, $"ALTER TABLE public.{Q(table.TargetTable)} OWNER TO legacy_local;", ct); }
                    TableCopyPlan root = fixture.Tables[0];
                    await Sql(setup, tx, $"INSERT INTO public.{Q(root.TargetTable)} ({Q(root.OrderedColumns[0])},\"Value\") VALUES ('1','ต้นฉบับ กขค 🇹🇭');", ct);
                    if (database == "Invoice")
                    {
                        await Sql(setup, tx, """
                            INSERT INTO public."InvoiceCreationAdmission" VALUES
                            ('00000000-0000-0000-0000-000000000001',1,'พนักงาน กขค','service:invoice','fingerprint-1','prepared',NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'),
                            ('00000000-0000-0000-0000-000000000002',2,'พนักงาน กขค','service:invoice','fingerprint-2','prepared','{"ไทย":"กขค"}','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');
                            ANALYZE public."InvoiceCreationAdmission";
                            COMMENT ON TABLE public."InvoiceCreationAdmission" IS 'retained admission comment';
                            """, ct);
                    }
                }
                await Sql(setup, tx, """
                    CREATE SCHEMA legacy_migration_internal;
                    CREATE TABLE legacy_migration_internal.retained_journal (id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, payload text NOT NULL);
                    INSERT INTO legacy_migration_internal.retained_journal(payload) VALUES ('synthetic immutable receipt กขค'),('synthetic immutable receipt กขค');
                    SELECT setval(pg_get_serial_sequence('legacy_migration_internal.retained_journal','id'),91,true);
                    """, ct);
                await tx.CommitAsync(ct);
            }
            string password = Guid.NewGuid().ToString("N"), binding = new('f', 64);
            const string role = "legacy_v3_native";
            DateTimeOffset issued = DateTimeOffset.UtcNow;
            string comment = "legacy-maliev-current-app-owned-v3-v1:" + binding;
            await using (var setup = new NpgsqlConnection(admin.ConnectionString))
            {
                await setup.OpenAsync(ct);
                await Sql(setup, null, $"CREATE ROLE {role} LOGIN SUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{password}' VALID UNTIL '{issued.AddMinutes(30):O}'; COMMENT ON ROLE {role} IS '{comment}';", ct);
                if (fault == "host-unprobed-sdk") { await Sql(setup, null, "CREATE ROLE v3_unprobed_sdk LOGIN;", ct); }
                await using var path = new NpgsqlCommand("SELECT current_setting('hba_file');", setup);
                string hbaPath = (string)(await path.ExecuteScalarAsync(ct))!;
                                string local = fault == "local-ordinary-trust" ? "trust" : "reject";
                string unprobed = fault == "host-unprobed-sdk" ? "('host all v3_unprobed_sdk 0.0.0.0/0 trust')," : string.Empty;
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
            var pool = new CurrentAppOwnedSnapshotInternPool();
            var baseline = new List<CurrentAppOwnedDatabaseSnapshot>();
            foreach (string database in names.Order(StringComparer.Ordinal))
            { baseline.Add(pool.Intern(await Capture(op.ConnectionString, database, ct))); }
            using ECDsa reviewKey = ECDsa.Create(ECCurve.NamedCurves.nistP256), authKey = ECDsa.Create(ECCurve.NamedCurves.nistP256), receiptKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var reviewSigner = new P256MigrationEvidenceSigner("v3-native-review", reviewKey.ExportPkcs8PrivateKeyPem());
            using var authSigner = new P256MigrationEvidenceSigner("v3-native-authorization", authKey.ExportPkcs8PrivateKeyPem());
            using var receiptSigner = new P256MigrationEvidenceSigner("v3-native-receipt", receiptKey.ExportPkcs8PrivateKeyPem());
            var trust = new ReceiptAttestationTrustStore([new(reviewSigner.KeyId, reviewKey.ExportSubjectPublicKeyInfo()),
                new(authSigner.KeyId, authKey.ExportSubjectPublicKeyInfo()), new(receiptSigner.KeyId, receiptKey.ExportSubjectPublicKeyInfo())]);
            _ = trust.TryGetPublicKeyFingerprintSha256(reviewSigner.KeyId, out string rf);
            _ = trust.TryGetPublicKeyFingerprintSha256(authSigner.KeyId, out string af);
            _ = trust.TryGetPublicKeyFingerprintSha256(receiptSigner.KeyId, out string ef);
            var pins = new CurrentAppOwnedRepairSigningPins(reviewSigner.KeyId, rf, authSigner.KeyId, af, receiptSigner.KeyId, ef);
            var hashes = baseline.ToDictionary(x => x.Database, CurrentAppOwnedSnapshotSerialization.Sha256, StringComparer.Ordinal);
            var scope = new CurrentAppOwnedV3RepairScope(operation, CurrentAppOwnedV3RepairOperation.AppendFourNullableColumnsAndCreateThreeTables,
                before.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(before), SchemaPlanCanonicalizer.ComputeSha256(after), contract.ComputeSha256(),
                new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/disposable-" + postgres.Id, identity),
                "local-aspire", "legacy-postgres-main-local", "owned-native-fixture-" + postgres.Id, new string('a', 64), binding,
                hashes, CurrentAppOwnedV3RepairPermit.FleetSha256(hashes), new string('b', 64), new string('c', 64), new string('d', 64), maintenance);
            var repairPreimages = new List<V3AdditiveObservation>();
            foreach (string database in new[] { "Invoice", "PurchaseOrder", "Quotation" })
            { repairPreimages.Add(await CaptureV3(op.ConnectionString, database, before, after, false, "legacy_local", ct)); }
            if (fault is "host-unprobed-sdk" or "local-ordinary-trust")
            {
                // Fresh signed hashes exactly match this unsafe installed HBA. The
                // configured postgres host probe has already rejected, but that is insufficient.
                if (fault == "host-unprobed-sdk")
                {
                    await using var sdk = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(admin.ConnectionString) { Username = "v3_unprobed_sdk" }.ConnectionString);
                    await sdk.OpenAsync(ct);
                    await using var query = new NpgsqlCommand("SELECT current_user;", sdk);
                    Assert.Equal("v3_unprobed_sdk", await query.ExecuteScalarAsync(ct));
                }
                var unsafeEnvironment = new NativeEnvironment(op.ConnectionString, admin.ConnectionString, scope,
                    contract, before, after, baseline, repairPreimages, null, fault);
                DateTimeOffset now = DateTimeOffset.UtcNow;
                var unsignedReview = new CurrentAppOwnedV3RepairSignedClaim("current-app-owned-v3-review-v1", scope,
                    Guid.NewGuid(), null, now, now.AddMinutes(20), reviewSigner.KeyId, null);
                var signedReview = unsignedReview with { Signature = Convert.ToBase64String(reviewSigner.Sign(CurrentAppOwnedV3RepairPermit.Payload(unsignedReview))) };
                var unsignedAuthorization = new CurrentAppOwnedV3RepairSignedClaim("current-app-owned-v3-authorization-v1", scope,
                    Guid.NewGuid(), CurrentAppOwnedSnapshotSerialization.Sha256(signedReview), now, now.AddMinutes(15), authSigner.KeyId, null);
                var signedAuthorization = unsignedAuthorization with { Signature = Convert.ToBase64String(authSigner.Sign(CurrentAppOwnedV3RepairPermit.Payload(unsignedAuthorization))) };
                CurrentAppOwnedV3RepairPermit.ValidateClaims(signedReview, signedAuthorization, trust, pins, now);
                MigrationExecutionException rejected = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                    CurrentAppOwnedV3RepairPermit.AdmitAsync(signedReview, signedAuthorization, before, after, trust, pins,
                        unsafeEnvironment, TimeProvider.System, ct));
                Assert.Equal("current_app_owned_maintenance_hba_not_exclusive", rejected.Code);
                Assert.Empty(unsafeEnvironment.Evidence);
                Assert.Equal(0, unsafeEnvironment.Reservations);
                return;
            }
await using var proxy = new CommitAcknowledgementProxy("127.0.0.1", op.Port);
            using (var process = System.Diagnostics.Process.GetCurrentProcess())
            { WriteLedger(run, "proxy", new { run, port = proxy.Port, processId = process.Id, processStartTimeUtc = process.StartTime.ToUniversalTime(), executable = System.Environment.ProcessPath, expiresAtUtc = started.AddMinutes(8), persistent = false }); }
            var execution = new NpgsqlConnectionStringBuilder(op.ConnectionString) { Port = proxy.Port };
            var environment = new NativeEnvironment(op.ConnectionString, admin.ConnectionString, scope, contract, before, after, baseline, repairPreimages,
                fault == "lost-commit-ack" ? proxy : null, fault);
            var review = await CurrentAppOwnedV3RepairPermit.IssueReviewAsync(scope, before, after, baseline, trust, pins, environment,
                reviewSigner, DateTimeOffset.UtcNow.AddMinutes(20), TimeProvider.System, ct);
            var authorization = await CurrentAppOwnedV3RepairPermit.AuthorizeAsync(review, before, after, trust, pins, environment, authSigner, TimeProvider.System, ct);
            environment.AuthorizationSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(authorization);
            var permit = await CurrentAppOwnedV3RepairPermit.AdmitAsync(review, authorization, before, after, trust, pins, environment, TimeProvider.System, ct);
                        string previous = new('0', 64);
            string[] fixedDatabases = ["Invoice", "PurchaseOrder", "Quotation"];
            if (fault == "success")
            {
                var receipts = await PostgreSqlCurrentAppOwnedV3Repair.ExecuteFleetAsync(execution.ConnectionString,
                    before, after, repairPreimages, permit, receiptSigner, trust, pins, ct);
                Assert.Equal(3, receipts.Count);
                foreach (CurrentAppOwnedV3RepairReceipt receipt in receipts)
                {
                    Assert.Equal(CurrentAppOwnedCommitClassification.CommittedAndReadback, receipt.Classification);
                    Assert.Equal(contract.AfterForDatabase(receipt.Database).TargetSchemaSha256,
                        await InspectSchema(op.ConnectionString, contract.AfterForDatabase(receipt.Database), ct));
                }
                Assert.Equal(6, environment.Evidence.Count);
                IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> actual = await environment.InspectFleetAsync(scope, ct);
                foreach (string remaining in names.Except(fixedDatabases, StringComparer.Ordinal))
                { Assert.Equal(scope.BeforeDatabaseSha256[remaining], CurrentAppOwnedSnapshotSerialization.Sha256(actual.Single(x => x.Database == remaining))); }
                // Real owner is legacy_local. The other valid fixed owner must fail
                // despite identical schema/types/fingerprint and application rows.
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CaptureV3(op.ConnectionString, "PurchaseOrder", before, after, true, "postgres", ct));
                Assert.Equal(receipts.Single(x => x.Database == "PurchaseOrder").AfterSha256,
                    CurrentAppOwnedSnapshotSerialization.Sha256(await Capture(op.ConnectionString, "PurchaseOrder", ct)));
            }
            else
            {
                string database = fixedDatabases[0];
                _ = await Assert.ThrowsAnyAsync<Exception>(() => PostgreSqlCurrentAppOwnedV3Repair.ExecuteFleetAsync(execution.ConnectionString,
                    before, after, repairPreimages, permit, receiptSigner, trust, pins, ct));
                if (fault == "lost-commit-ack") { await proxy.Dropped.WaitAsync(TimeSpan.FromSeconds(10), ct); Assert.Equal(1, proxy.DroppedCommits); }
                var prepared = environment.Receipt(database, "prepared");
                var failed = environment.Receipt(database, "failed-or-uncertain");
                if (fault == "terminal-publication")
                {
                    var terminal = environment.Receipt(database, "committed-readback");
                    Assert.Equal(CurrentAppOwnedCommitClassification.CommittedAndReadback, terminal.Classification);
                    Assert.Equal(terminal.AfterSha256, failed.AfterSha256);
                    Assert.Equal(terminal.PreviousReceiptSha256, failed.PreviousReceiptSha256);
                }
                Assert.Equal(fault == "prepared-publication" ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.Uncertain, failed.Classification);
                string actual = CurrentAppOwnedSnapshotSerialization.Sha256(await Capture(op.ConnectionString, database, ct));
                Assert.Equal(fault == "prepared-publication" ? scope.BeforeDatabaseSha256[database] : prepared.AfterSha256, actual);
                DatabaseSchemaPlan expectedPhysical = fault == "prepared-publication" ? contract.BeforeForDatabase(database) : contract.AfterForDatabase(database);
                Assert.Equal(expectedPhysical.TargetSchemaSha256, await InspectSchema(op.ConnectionString, expectedPhysical, ct));
                Assert.Equal(fault == "prepared-publication" ? previous : CurrentAppOwnedSnapshotSerialization.Sha256(prepared), failed.PreviousReceiptSha256);
                Assert.DoesNotContain(environment.Evidence.Keys, x => x.Contains("PurchaseOrder", StringComparison.Ordinal) || x.Contains("Quotation", StringComparison.Ordinal));
                foreach (string remaining in names.Where(x => x != database))
                { Assert.Equal(scope.BeforeDatabaseSha256[remaining], CurrentAppOwnedSnapshotSerialization.Sha256(await Capture(op.ConnectionString, remaining, ct))); }
            }
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireAsync(ct));
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => PostgreSqlCurrentAppOwnedV3Repair.ExecuteFleetAsync(execution.ConnectionString,
                before, after, repairPreimages, permit, receiptSigner, trust, pins, ct));
            var retained = environment.Evidence.ToDictionary(x => x.Key, x => x.Value.ToArray(), StringComparer.Ordinal);
            foreach (byte[] bytes in retained.Values)
            {
                var receipt = JsonSerializer.Deserialize<CurrentAppOwnedV3RepairReceipt>(bytes)!;
                PostgreSqlCurrentAppOwnedV3Repair.RequireReceipt(receipt, scope, permit.AuthorizationSha256, trust, pins);
            }
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAppOwnedV3RepairPermit.AdmitAsync(review,
                authorization, before, after, trust, pins, environment, TimeProvider.System, ct));
            Assert.Equal(retained.Count, environment.Evidence.Count);
            foreach (var item in retained) { Assert.Equal(item.Value, environment.Evidence[item.Key]); }
            Assert.Equal(1, environment.Reservations);
        }
        finally
        {
            await postgres.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(30));
            WriteLedger(run, "disposed", new { run, containerId, completedAtUtc = DateTimeOffset.UtcNow });
            output.WriteLine("Owned disposal completed run={0}; id={1}; external ledger must verify exact container and anonymous-volume absence", run, containerId);
        }
    }

    private static void WriteLedger(string run, string phase, object record)
    {
        string? directory = Environment.GetEnvironmentVariable("MALIEV_V3_NATIVE_LEDGER");
        if (directory is null) { return; }
        using var file = new FileStream(Path.Combine(directory, run + "-" + phase + ".json"), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        JsonSerializer.Serialize(file, record);
        file.Flush(flushToDisk: true);
    }

        private sealed class NativeEnvironment(string op, string ordinary, CurrentAppOwnedV3RepairScope scope,
        CurrentAppOwnedV3AdditiveContract contract, FreshSchemaPlan before, FreshSchemaPlan after,
        IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> baseline, IReadOnlyList<V3AdditiveObservation> repairPreimages,
        CommitAcknowledgementProxy? proxy, string fault) : ICurrentAppOwnedV3RepairEnvironment
    {
        private bool _reserved, _arm;
        private readonly object _operationGate = new();
        internal int Reservations { get; private set; }
        internal string AuthorizationSha256 { get; set; } = string.Empty;
        internal Dictionary<string, byte[]> Evidence { get; } = new(StringComparer.Ordinal);
        public Task RequireSourceAsync(string sourceCommitSha, CancellationToken cancellationToken)
        {
            return sourceCommitSha != scope.SourceCommitSha ? throw CurrentAppOwnedV3RepairPermit.Invalid() : Task.CompletedTask;
        }
        public async Task RequireResourceAndCustodyAsync(CurrentAppOwnedV3RepairScope current, CancellationToken ct)
        {
            if (JsonSerializer.Serialize(current) != JsonSerializer.Serialize(scope)) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            foreach (string database in scope.BeforeDatabaseSha256.Keys)
            {
                var settings = new NpgsqlConnectionStringBuilder(ordinary) { Database = database };
                bool rejected = false;
                try { await using var probe = new NpgsqlConnection(settings.ConnectionString); await probe.OpenAsync(ct); }
                catch (PostgresException failure) when (failure.SqlState == "28000") { rejected = true; }
                if (!rejected) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            }
            if (_arm) { proxy?.Arm(); _arm = false; }
        }
        public async Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CurrentAppOwnedV3RepairScope current, CancellationToken ct)
        {
            if (JsonSerializer.Serialize(current) != JsonSerializer.Serialize(scope)) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            await using (var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(op) { Database = "postgres" }.ConnectionString))
            {
                await connection.OpenAsync(ct);
                await using var inventory = new NpgsqlCommand("SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname COLLATE \"C\";", connection);
                var names = new List<string>();
                await using var reader = await inventory.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct)) { names.Add(reader.GetString(0)); }
                Assert.Equal(scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal), names);
            }
            var pool = new CurrentAppOwnedSnapshotInternPool();
            var snapshots = new List<CurrentAppOwnedDatabaseSnapshot>();
            foreach (CurrentAppOwnedDatabaseSnapshot expected in baseline)
            {
                var settings = new NpgsqlConnectionStringBuilder(op) { Database = expected.Database };
                await using var connection = new NpgsqlConnection(settings.ConnectionString); await connection.OpenAsync(ct);
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
                await Sql(connection, tx, "SET TRANSACTION READ ONLY;", ct);
                await PostgreSqlCurrentAppOwnedV3Repair.RequireInstalledPolicyAsync(connection, tx, scope, ct);
                CurrentAppOwnedDatabaseSnapshot actual = pool.Intern(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct));
                snapshots.Add(actual);
                V3AdditiveObservation? original = repairPreimages.SingleOrDefault(x => x.Snapshot.Database == expected.Database);
                if (original is null)
                {
                    Assert.Equal(CurrentAppOwnedSnapshotSerialization.Sha256(expected), CurrentAppOwnedSnapshotSerialization.Sha256(actual));
                    if (DatabaseInventory.ActiveDatabases.Contains(expected.Database, StringComparer.Ordinal))
                    {
                        DatabaseSchemaPlan physical = contract.BeforeForDatabase(expected.Database);
                        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                        Assert.Equal(physical.TargetSchemaSha256, await inspector.InspectSchemaAsync(physical, ct));
                    }
                }
                else
                {
                    bool isAfter = CurrentAppOwnedSnapshotSerialization.Sha256(actual) != scope.BeforeDatabaseSha256[expected.Database];
                    V3AdditiveObservation observed = await CurrentAppOwnedV3AdditivePreservation.CaptureAsync(connection, tx, before, after,
                        scope.SourceCommitSha, isAfter, DateTimeOffset.UtcNow, ct, "legacy_local");
                    if (isAfter) { CurrentAppOwnedV3AdditivePreservation.RequirePreserved(original, observed); }
                    else { Assert.Equal(scope.BeforeDatabaseSha256[expected.Database], CurrentAppOwnedSnapshotSerialization.Sha256(observed.Snapshot)); }
                }
                await tx.RollbackAsync(ct);
            }
            return snapshots.AsReadOnly();
        }
        public Task RequireFreshOperationAsync(CurrentAppOwnedV3RepairScope current, CancellationToken ct)
        {
            return _reserved || Evidence.Count != 0 ? throw CurrentAppOwnedV3RepairPermit.Invalid() : Task.CompletedTask;
        }
        public Task ReserveFreshOperationAsync(CurrentAppOwnedV3RepairScope current, string auth, CancellationToken ct)
        {
            lock (_operationGate)
            {
                if (_reserved || Evidence.Count != 0 || auth != AuthorizationSha256) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
                _reserved = true; Reservations++; return Task.CompletedTask;
            }
        }
        public Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken ct)
        {
            if (!Evidence.TryAdd(name, payload.ToArray())) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            bool prepared = name.EndsWith("-prepared.json", StringComparison.Ordinal);
            if (prepared) { _arm = true; }
            return (prepared && fault == "prepared-publication") || (name.EndsWith("-committed-readback.json", StringComparison.Ordinal) && fault == "terminal-publication")
                ? throw new IOException("synthetic publication acknowledgement lost after immutable retention") : Task.CompletedTask;
        }
        internal CurrentAppOwnedV3RepairReceipt Receipt(string database, string suffix)
        {
            return JsonSerializer.Deserialize<CurrentAppOwnedV3RepairReceipt>(Evidence[$"{scope.OperationId:D}-{database}-{suffix}.json"])!;
        }
    }

    private static async Task<V3AdditiveObservation> CaptureV3(string connectionString, string database,
        FreshSchemaPlan before, FreshSchemaPlan after, bool isAfter, string owner, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(connectionString) { Database = database, Pooling = false }.ConnectionString);
        await connection.OpenAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await Sql(connection, tx, "SET TRANSACTION READ ONLY;", ct);
        V3AdditiveObservation observation = await CurrentAppOwnedV3AdditivePreservation.CaptureAsync(connection, tx, before, after,
            before.SourceCommitSha, isAfter, DateTimeOffset.UtcNow, ct, owner);
        await tx.RollbackAsync(ct); return observation;
    }
private static async Task<CurrentAppOwnedDatabaseSnapshot> Capture(string connectionString, string database, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(connectionString) { Database = database, Pooling = false }.ConnectionString);
        await connection.OpenAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await Sql(connection, tx, "SET TRANSACTION READ ONLY;", ct);
        var snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct);
        await tx.RollbackAsync(ct); return snapshot;
    }
    private static async Task<string> InspectSchema(string connectionString, DatabaseSchemaPlan physical, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(connectionString) { Database = physical.Database, Pooling = false }.ConnectionString);
        await connection.OpenAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await Sql(connection, tx, "SET TRANSACTION READ ONLY;", ct);
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
        string hash = await inspector.InspectSchemaAsync(physical, ct);
        await tx.RollbackAsync(ct); return hash;
    }
    private static async Task Sql(NpgsqlConnection connection, NpgsqlTransaction? tx, string text, CancellationToken ct)
    { await using var command = new NpgsqlCommand(text, connection, tx); _ = await command.ExecuteNonQueryAsync(ct); }
    private static string Q(string text)
    {
        return PostgreSqlShadowTarget.QuoteIdentifier(text);
    }

    private static FreshSchemaPlan Pair(ConsumerOverlaySelection selection)
    {
        var schema = CurrentConsumerSchemaV2Tests.Schema(selection) with { CapturedAtUtc = DateTimeOffset.UtcNow };
        return schema with { Databases = [.. schema.Databases.Select(database => database.Database == "Quotation" ? Map(database) : database)] };
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
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _lifetime = new(TimeSpan.FromMinutes(8));
        private readonly TaskCompletionSource _dropped = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Task _worker;
        private int _armed, _droppedCommits;
        internal int Port { get; }
        internal Task Dropped => _dropped.Task;
        internal int DroppedCommits => Volatile.Read(ref _droppedCommits);
        internal void Arm() { _ = Interlocked.Exchange(ref _armed, 1); }
        internal CommitAcknowledgementProxy(string host, int port)
        { _listener.Start(1); Port = ((IPEndPoint)_listener.LocalEndpoint).Port; _worker = RunAsync(host, port); }
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
                { _ = Interlocked.Increment(ref _droppedCommits); return; }
                await client.WriteAsync(header, ct); await client.WriteAsync(payload, ct);
            }
        }
        public async ValueTask DisposeAsync()
        {
            await _lifetime.CancelAsync(); _listener.Stop();
            try { await _worker.WaitAsync(TimeSpan.FromSeconds(10)); }
            finally { _lifetime.Dispose(); }
            Assert.True(_worker.IsCompleted);
        }
    }
}
