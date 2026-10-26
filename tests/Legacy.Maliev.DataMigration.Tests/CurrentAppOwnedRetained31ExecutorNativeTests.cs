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
public sealed class CurrentAppOwnedRetained31ExecutorNativeTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData("success")]
    [InlineData("prepared-publication")]
    [InlineData("lost-commit-ack")]
    [InlineData("terminal-publication")]
    [InlineData("host-unprobed-sdk")]
    [InlineData("local-ordinary-trust")]
    public async Task Real_fixed31_execution_preserves_fleet_and_immutable_receipts_or_stops(string fault)
    {
        // Genuine native provider/policy/receipt component proof. Source/custody and Docker
        // target observations below are component seams, never closed Console authority.
        using var expiry = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        CancellationToken ct = expiry.Token;
        Guid operation = Guid.NewGuid();
        string run = operation.ToString("N"), name = "retained31-executor-" + run;
        DateTimeOffset started = DateTimeOffset.UtcNow;
        WriteLedger(run, "attempt", new { run, name, fault, startedAtUtc = started, expiresAtUtc = started.AddMinutes(8), persistent = false });
        string? containerId = null;
        output.WriteLine("Owned attempt run={0}; name={1}; start={2:O}; expiry={3:O}; persistent=false", run, name, started, started.AddMinutes(8));
        var postgres = new PostgreSqlBuilder("postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382")
            .WithDatabase("postgres").WithUsername("postgres").WithPassword(Guid.NewGuid().ToString("N"))
            .WithCommand("-c", "autovacuum=off")
            .WithName(name).WithLabel("codex.repair.run", run).WithLabel("codex.repair.purpose", "retained31-native-executor")
            .WithCreateParameterModifier(p => { p.HostConfig!.Memory = 512 * 1024 * 1024; p.HostConfig.MemorySwap = 512 * 1024 * 1024; p.HostConfig.NanoCPUs = 750_000_000; }).Build();
        try
        {
            await postgres.StartAsync(ct);
            containerId = postgres.Id;
            WriteLedger(run, "observed", new { run, name, containerId = postgres.Id, port = postgres.GetMappedPublicPort(5432) });
            output.WriteLine("Owned observed run={0}; container={1}; name={2}; port={3}", run, postgres.Id, name, postgres.GetMappedPublicPort(5432));
            var admin = new NpgsqlConnectionStringBuilder(postgres.GetConnectionString())
            { Host = "127.0.0.1", Pooling = false, SslMode = SslMode.Disable, Timeout = 10, CommandTimeout = 30 };
            FreshSchemaPlan before = Pair(ConsumerOverlaySelection.CurrentConsumerColumnsV1);
            FreshSchemaPlan after = Pair(ConsumerOverlaySelection.CurrentConsumerSchemaV2) with { CapturedAtUtc = before.CapturedAtUtc };
            CurrentAppOwnedRetained31Contract contract = CurrentAppOwnedRetained31Contract.Create(before, after, before.SourceCommitSha, DateTimeOffset.UtcNow);
            string[] names = [.. DatabaseInventory.ActiveDatabases, "Auth", "postgres", "legacy_local"];
            Assert.Equal(26, names.Length);
            await using (var create = new NpgsqlConnection(admin.ConnectionString))
            {
                await create.OpenAsync(ct);
                // Keep disposable fixture statistics stable without masking any catalog field.
                await using (var setting = new NpgsqlCommand("SELECT current_setting('autovacuum');", create))
                { Assert.Equal("off", await setting.ExecuteScalarAsync(ct)); }
                WriteLedger(run, "fixture-setting", new { run, autovacuum = "off", persistent = false });
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
                    foreach (TableCopyPlan table in fixture.Tables.Where(x => CurrentAppOwnedRepairManifest.RetainedOperands().Any(o => o.Database == database && o.Table == x.TargetTable)))
                    {
                        for (int row = 1; row <= 3; row++)
                        { await Sql(setup, tx, $"INSERT INTO public.{Q(table.TargetTable)} ({string.Join(',', table.OrderedColumns.Select(Q))}) VALUES ({string.Join(',', table.OrderedColumns.Select(column => Seed(table, column, row)))});", ct); }
                        await Sql(setup, tx, $"ANALYZE public.{Q(table.TargetTable)}; COMMENT ON TABLE public.{Q(table.TargetTable)} IS 'synthetic retained executor table';", ct);
                        foreach (string constraint in table.CheckConstraints.Select(x => x.Name).Concat(table.UniqueConstraints.Select(x => x.Name)).Concat(table.PrimaryKey is { } pk ? [pk.Name] : []))
                        { await Sql(setup, tx, $"COMMENT ON CONSTRAINT {Q(constraint)} ON public.{Q(table.TargetTable)} IS 'synthetic retained constraint';", ct); }
                    }
                }
                await Sql(setup, tx, """
                    CREATE SCHEMA legacy_migration_internal;
                    CREATE TABLE legacy_migration_internal.retained_journal (id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, payload text NOT NULL);
                    INSERT INTO legacy_migration_internal.retained_journal(payload) VALUES ('synthetic immutable receipt'),('synthetic Thai sentinel กขค');
                    SELECT setval(pg_get_serial_sequence('legacy_migration_internal.retained_journal','id'),91,true);
                    """, ct);
                await tx.CommitAsync(ct);
            }
            string password = Guid.NewGuid().ToString("N"), binding = new('f', 64);
            const string role = "legacy_retained31_native";
            DateTimeOffset issued = DateTimeOffset.UtcNow;
            string comment = "legacy-maliev-current-app-owned-retained31-v1:" + binding;
            await using (var setup = new NpgsqlConnection(admin.ConnectionString))
            {
                await setup.OpenAsync(ct);
                await Sql(setup, null, $"CREATE ROLE {role} LOGIN SUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{password}' VALID UNTIL '{issued.AddMinutes(30):O}'; COMMENT ON ROLE {role} IS '{comment}';", ct);
                if (fault == "host-unprobed-sdk") { await Sql(setup, null, "CREATE ROLE retained31_unprobed_sdk LOGIN;", ct); }
                await using var path = new NpgsqlCommand("SELECT current_setting('hba_file');", setup);
                string hbaPath = (string)(await path.ExecuteScalarAsync(ct))!;
                string local = fault == "local-ordinary-trust" ? "trust" : "reject";
                string unprobed = fault == "host-unprobed-sdk" ? "('host all retained31_unprobed_sdk 0.0.0.0/0 trust')," : string.Empty;
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
            using var reviewSigner = new P256MigrationEvidenceSigner("retained31-native-review", reviewKey.ExportPkcs8PrivateKeyPem());
            using var authSigner = new P256MigrationEvidenceSigner("retained31-native-authorization", authKey.ExportPkcs8PrivateKeyPem());
            using var receiptSigner = new P256MigrationEvidenceSigner("retained31-native-receipt", receiptKey.ExportPkcs8PrivateKeyPem());
            var trust = new ReceiptAttestationTrustStore([new(reviewSigner.KeyId, reviewKey.ExportSubjectPublicKeyInfo()),
                new(authSigner.KeyId, authKey.ExportSubjectPublicKeyInfo()), new(receiptSigner.KeyId, receiptKey.ExportSubjectPublicKeyInfo())]);
            _ = trust.TryGetPublicKeyFingerprintSha256(reviewSigner.KeyId, out string rf);
            _ = trust.TryGetPublicKeyFingerprintSha256(authSigner.KeyId, out string af);
            _ = trust.TryGetPublicKeyFingerprintSha256(receiptSigner.KeyId, out string ef);
            var pins = new CurrentAppOwnedRetained31SigningPins(reviewSigner.KeyId, rf, authSigner.KeyId, af, receiptSigner.KeyId, ef);
            var scope = new CurrentAppOwnedRetained31Scope(operation, CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations,
                before.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(before), SchemaPlanCanonicalizer.ComputeSha256(after), contract.ComputeSha256(),
                CurrentAppOwnedRepairManifest.OperationSha256(CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations),
                new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/disposable-" + postgres.Id, identity),
                "local-aspire", "legacy-postgres-main-local", "owned-native-fixture-" + postgres.Id, new string('a', 64), binding,
                baseline.ToDictionary(x => x.Database, CurrentAppOwnedSnapshotSerialization.Sha256, StringComparer.Ordinal),
                CurrentAppOwnedSnapshotSerialization.Sha256(baseline), new string('b', 64), new string('c', 64), new string('d', 64), maintenance,
                CurrentAppOwnedRetained31Permit.FreshOnlyPolicy);
            if (fault is "host-unprobed-sdk" or "local-ordinary-trust")
            {
                // Hashes are freshly observed and match the unsafe installed policy. The
                // configured postgres host probe above is rejected; complete rule semantics
                // must still reject unprobed host and local ordinary-role access.
                if (fault == "host-unprobed-sdk")
                {
                    await using var sdk = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(admin.ConnectionString) { Username = "retained31_unprobed_sdk" }.ConnectionString);
                    await sdk.OpenAsync(ct);
                    await using var query = new NpgsqlCommand("SELECT current_user;", sdk);
                    Assert.Equal("retained31_unprobed_sdk", await query.ExecuteScalarAsync(ct));
                }
                await using var observe = new NpgsqlConnection(op.ConnectionString);
                await observe.OpenAsync(ct);
                await using var tx = await observe.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
                await Sql(observe, tx, "SET TRANSACTION READ ONLY;", ct);
                MigrationExecutionException rejected = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                    PostgreSqlCurrentAppOwnedRetained31Repair.RequireInstalledPolicyAsync(observe, tx, scope, ct));
                Assert.Equal("current_app_owned_maintenance_hba_not_exclusive", rejected.Code);
                await tx.RollbackAsync(ct);
                return;
            }
            await using var proxy = new CommitAcknowledgementProxy("127.0.0.1", op.Port, run);
            var execution = new NpgsqlConnectionStringBuilder(op.ConnectionString) { Port = proxy.Port };
            var environment = new NativeEnvironment(op.ConnectionString, admin.ConnectionString, scope, contract, baseline, trust, pins,
                fault == "lost-commit-ack" ? proxy : null, fault);
            var review = await CurrentAppOwnedRetained31Permit.IssueReviewAsync(scope, before, after, baseline, trust, pins, environment,
                reviewSigner, DateTimeOffset.UtcNow.AddMinutes(20), TimeProvider.System, ct);
            var authorization = await CurrentAppOwnedRetained31Permit.AuthorizeAsync(review, before, after, trust, pins, environment, authSigner, TimeProvider.System, ct);
            environment.AuthorizationSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(authorization);
            var permit = await CurrentAppOwnedRetained31Permit.AdmitAsync(review, authorization, before, after, trust, pins, environment, TimeProvider.System, ct);
            await permit.BeginExecutionAsync(ct);
            string previous = new('0', 64);
            string[] fixedDatabases = CurrentAppOwnedRepairManifest.Databases(scope.Operation);
            if (fault == "success")
            {
                foreach (string database in fixedDatabases)
                {
                    var receipt = await PostgreSqlCurrentAppOwnedRetained31Repair.ExecuteDatabaseAsync(execution.ConnectionString, database,
                        before, after, baseline.Single(x => x.Database == database), permit, receiptSigner, trust, pins, previous, ct);
                    Assert.Equal(CurrentAppOwnedCommitClassification.CommittedAndReadback, receipt.Classification);
                    Assert.Equal(contract.AfterForDatabase(database).TargetSchemaSha256,
                        await InspectSchema(op.ConnectionString, contract.AfterForDatabase(database), ct));
                    previous = CurrentAppOwnedSnapshotSerialization.Sha256(receipt);
                }
                Assert.Equal(10, environment.Evidence.Count);
                _ = await environment.InspectGlobalPreservationAsync(ct);
            }
            else
            {
                string database = fixedDatabases[0];
                _ = await Assert.ThrowsAnyAsync<Exception>(() => PostgreSqlCurrentAppOwnedRetained31Repair.ExecuteDatabaseAsync(execution.ConnectionString,
                    database, before, after, baseline.Single(x => x.Database == database), permit, receiptSigner, trust, pins, previous, ct));
                if (fault == "lost-commit-ack") { await proxy.Dropped.WaitAsync(TimeSpan.FromSeconds(10), ct); Assert.Equal(1, proxy.DroppedCommits); }
                var prepared = environment.Receipt(database, "prepared");
                var failed = environment.Receipt(database, "failed-or-uncertain");
                Assert.Equal(fault == "prepared-publication" ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.Uncertain, failed.Classification);
                string actual = CurrentAppOwnedSnapshotSerialization.Sha256(await Capture(op.ConnectionString, database, ct));
                Assert.Equal(fault == "prepared-publication" ? scope.BeforeDatabaseSha256[database] : prepared.AfterSha256, actual);
                DatabaseSchemaPlan expectedPhysical = fault == "prepared-publication" ? contract.BeforeForDatabase(database) : contract.AfterForDatabase(database);
                Assert.Equal(expectedPhysical.TargetSchemaSha256, await InspectSchema(op.ConnectionString, expectedPhysical, ct));
                Assert.Equal(fault == "prepared-publication" ? previous : CurrentAppOwnedSnapshotSerialization.Sha256(prepared), failed.PreviousReceiptSha256);
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => permit.RequireExecutionAsync(ct));
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => PostgreSqlCurrentAppOwnedRetained31Repair.ExecuteDatabaseAsync(execution.ConnectionString,
                    fixedDatabases[1], before, after, baseline.Single(x => x.Database == fixedDatabases[1]), permit, receiptSigner, trust, pins, previous, ct));
                Assert.DoesNotContain(environment.Evidence.Keys, x => x.Contains(fixedDatabases[1], StringComparison.Ordinal));
                foreach (string remaining in names.Where(x => x != database))
                { Assert.Equal(scope.BeforeDatabaseSha256[remaining], CurrentAppOwnedSnapshotSerialization.Sha256(await Capture(op.ConnectionString, remaining, ct))); }
            }
            var retained = environment.Evidence.ToDictionary(x => x.Key, x => x.Value.ToArray(), StringComparer.Ordinal);
            foreach (byte[] bytes in retained.Values)
            {
                var receipt = JsonSerializer.Deserialize<CurrentAppOwnedRetained31Receipt>(bytes)!;
                PostgreSqlCurrentAppOwnedRetained31Repair.RequireReceipt(receipt, scope, permit.AuthorizationSha256, trust, pins);
            }
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAppOwnedRetained31Permit.AdmitAsync(review,
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
        string? directory = Environment.GetEnvironmentVariable("MALIEV_RETAINED31_NATIVE_LEDGER");
        if (directory is null) { return; }
        using var file = new FileStream(Path.Combine(directory, run + "-" + phase + ".json"), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        JsonSerializer.Serialize(file, record);
        file.Flush(flushToDisk: true);
    }

    private sealed class NativeEnvironment(string op, string ordinary, CurrentAppOwnedRetained31Scope scope, CurrentAppOwnedRetained31Contract contract,
        IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> baseline, IReceiptAttestationTrustStore trust,
        CurrentAppOwnedRetained31SigningPins pins, CommitAcknowledgementProxy? proxy, string fault) : ICurrentAppOwnedRetained31Environment
    {
        private readonly Dictionary<string, string> _phase = baseline.ToDictionary(x => x.Database, CurrentAppOwnedSnapshotSerialization.Sha256, StringComparer.Ordinal);
        private readonly Dictionary<string, CurrentAppOwnedDatabaseSnapshot> _expected = baseline.ToDictionary(x => x.Database, StringComparer.Ordinal);
        private bool _reserved, _arm;
        internal int Reservations { get; private set; }
        internal string AuthorizationSha256 { get; set; } = string.Empty;
        internal Dictionary<string, byte[]> Evidence { get; } = new(StringComparer.Ordinal);
        public Task RequireSourceAsync(string sourceCommitSha, CancellationToken cancellationToken)
        {
            return sourceCommitSha != scope.SourceCommitSha ? throw CurrentAppOwnedRetained31Permit.Invalid() : Task.CompletedTask;
        }
        public async Task RequireResourceAndCustodyAsync(CurrentAppOwnedRetained31Scope current, CancellationToken ct)
        {
            if (JsonSerializer.Serialize(current) != JsonSerializer.Serialize(scope)) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            foreach (string database in _phase.Keys)
            {
                var settings = new NpgsqlConnectionStringBuilder(ordinary) { Database = database };
                bool rejected = false;
                try { await using var probe = new NpgsqlConnection(settings.ConnectionString); await probe.OpenAsync(ct); }
                catch (PostgresException failure) when (failure.SqlState == "28000") { rejected = true; }
                if (!rejected) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            }
            if (_arm) { proxy?.Arm(); _arm = false; }
        }
        public async Task<string> InspectGlobalPreservationAsync(CancellationToken ct)
        {
            await using (var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(op) { Database = "postgres" }.ConnectionString))
            {
                await connection.OpenAsync(ct);
                await using var inventory = new NpgsqlCommand("SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname COLLATE \"C\";", connection);
                var names = new List<string>();
                await using var reader = await inventory.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct)) { names.Add(reader.GetString(0)); }
                Assert.Equal(_phase.Keys.Order(StringComparer.Ordinal), names);
            }
            var pool = new CurrentAppOwnedSnapshotInternPool();
            foreach (var item in _phase)
            {
                var settings = new NpgsqlConnectionStringBuilder(op) { Database = item.Key };
                await using var connection = new NpgsqlConnection(settings.ConnectionString); await connection.OpenAsync(ct);
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
                await Sql(connection, tx, "SET TRANSACTION READ ONLY;", ct);
                await PostgreSqlCurrentAppOwnedRetained31Repair.RequireInstalledPolicyAsync(connection, tx, scope, ct);
                CurrentAppOwnedDatabaseSnapshot current = pool.Intern(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct));
                string currentHash = CurrentAppOwnedSnapshotSerialization.Sha256(current);
                if (item.Value != currentHash)
                {
                    CurrentAppOwnedDatabaseSnapshot expected = _expected[item.Key];
                    string[] changedCatalogs = expected.Catalog.Select(x => x.Catalog).Concat(current.Catalog.Select(x => x.Catalog))
                        .Distinct(StringComparer.Ordinal).Where(name => !expected.Catalog.Where(x => x.Catalog == name)
                            .SequenceEqual(current.Catalog.Where(x => x.Catalog == name))).ToArray();
                    Assert.Fail($"Native fleet raw snapshot drift in {item.Key}; catalogs={string.Join(',', changedCatalogs)}; " +
                        $"relationsEqual={expected.Relations.SequenceEqual(current.Relations)}; sequencesEqual={expected.Sequences.SequenceEqual(current.Sequences)}");
                }
                if (DatabaseInventory.ActiveDatabases.Contains(item.Key, StringComparer.Ordinal))
                {
                    DatabaseSchemaPlan physical = item.Value == scope.BeforeDatabaseSha256[item.Key]
                        ? contract.BeforeForDatabase(item.Key) : contract.AfterForDatabase(item.Key);
                    await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                    string physicalHash = await inspector.InspectSchemaAsync(physical, ct);
                    Assert.True(physical.TargetSchemaSha256 == physicalHash,
                        $"Native fleet physical preimage mismatch in {item.Key}; expected={physical.TargetSchemaSha256}; actual={physicalHash}");
                }
                await tx.RollbackAsync(ct);
            }
            return scope.GlobalPreservationSha256;
        }
        public Task RequireFreshOperationAsync(CurrentAppOwnedRetained31Scope current, CancellationToken ct)
        {
            return _reserved || Evidence.Count != 0 ? throw CurrentAppOwnedRetained31Permit.Invalid() : Task.CompletedTask;
        }
        public Task ReserveFreshOperationAsync(CurrentAppOwnedRetained31Scope current, string auth, CancellationToken ct)
        { if (_reserved || Evidence.Count != 0 || auth != AuthorizationSha256) { throw CurrentAppOwnedRetained31Permit.Invalid(); } _reserved = true; Reservations++; return Task.CompletedTask; }
        public Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken ct)
        {
            if (!Evidence.TryAdd(name, payload.ToArray())) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            bool prepared = name.EndsWith("-prepared.json", StringComparison.Ordinal);
            if (prepared) { _arm = true; }
            return (prepared && fault == "prepared-publication") || (name.EndsWith("-committed-readback.json", StringComparison.Ordinal) && fault == "terminal-publication")
                ? throw new IOException("synthetic publication acknowledgement lost after immutable retention")
                : Task.CompletedTask;
        }
        public async Task ObserveCommittedDatabaseAsync(CurrentAppOwnedRetained31Receipt prepared, CancellationToken ct)
        {
            PostgreSqlCurrentAppOwnedRetained31Repair.RequireReceipt(prepared, scope, AuthorizationSha256, trust, pins);
            Assert.Equal(CurrentAppOwnedCommitClassification.Prepared, prepared.Classification);
            CurrentAppOwnedDatabaseSnapshot observed = await Capture(op, prepared.Database, ct);
            Assert.Equal(prepared.AfterSha256, CurrentAppOwnedSnapshotSerialization.Sha256(observed));
            _expected[prepared.Database] = observed;
            _phase[prepared.Database] = prepared.AfterSha256!;
        }
        internal CurrentAppOwnedRetained31Receipt Receipt(string database, string suffix)
        {
            return JsonSerializer.Deserialize<CurrentAppOwnedRetained31Receipt>(Evidence[$"{scope.OperationId:D}-{database}-{suffix}.json"])!;
        }
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

    private static string Seed(TableCopyPlan table, string column, int row)
    {
        if (table.NullableColumns.Contains(column, StringComparer.Ordinal)) { return "NULL"; }
        if (column == "Purpose") { return table.TargetTable == "InvoiceNotificationCorrelation" ? "'invoice-issued'" : "'employee-email-confirmation'"; }
        if (column == "SenderServiceSubject") { return "'service:legacy-accounting'"; }
        if (column == "Phase") { return "'Prepared'"; }
        if (column == "PayloadFrameVersion") { return "'notification-payload-v1'"; }
        if (column == "BindingVersion") { return "'accounting-invoice-notification-hmac-v1'"; }
        string type = table.ColumnTypes[column];
        return type is "smallint" or "integer" or "bigint"
            ? row.ToString(System.Globalization.CultureInfo.InvariantCulture)
            : type == "uuid"
            ? "'" + Guid.NewGuid().ToString("D") + "'"
            : type == "bytea"
            ? "decode('" + new string('a', 64) + "','hex')"
            : type.StartsWith("timestamp", StringComparison.Ordinal) ? "'2026-01-01T00:00:00Z'"
            : column is "TokenSha256" or "KeyHash" or "Fingerprint" or "IntentFingerprint" ? "'" + new string((char)('a' + row), 64) + "'" : "'synthetic-" + row.ToString(System.Globalization.CultureInfo.InvariantCulture) + "'";
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
        private readonly string _run;
        private int _armed, _droppedCommits;
        internal int Port { get; }
        internal Task Dropped => _dropped.Task;
        internal int DroppedCommits => Volatile.Read(ref _droppedCommits);
        internal void Arm() { _ = Interlocked.Exchange(ref _armed, 1); }
        internal CommitAcknowledgementProxy(string host, int port, string run)
        {
            _run = run;
            _listener.Start(1); Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            try { WriteLedger(run, "proxy", new { run, host = "127.0.0.1", port = Port, expiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(8) }); }
            catch { _listener.Stop(); _lifetime.Dispose(); throw; }
            _worker = RunAsync(host, port);
        }
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
            WriteLedger(_run, "proxy-disposed", new { run = _run, port = Port, workerCompleted = _worker.IsCompleted, completedAtUtc = DateTimeOffset.UtcNow });
        }
    }
}
