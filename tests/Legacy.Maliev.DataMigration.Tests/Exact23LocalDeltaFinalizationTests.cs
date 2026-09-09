using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Exact23LocalDeltaFinalizationTests : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"legacy-delta-export-{Guid.NewGuid():N}");

    [Fact]
    public async Task Terminal_receipt_is_verified_before_queries_snapshot_or_AppHost_evidence()
    {
        Fixture fixture = await Fixture.CreateAsync(_key, terminalValid: false);

        DeltaExecutionException error = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            fixture.Coordinator.FinalizeAsync(fixture.Plan, fixture.Schema, CancellationToken.None));

        Assert.Equal("local_delta_terminal_receipt_invalid", error.Code);
        Assert.Equal(["apply", "reconcile"], fixture.Runtime.Calls);
    }

    [Fact]
    public async Task Complete_local_delta_publishes_artifacts_only_in_fail_closed_order()
    {
        Fixture fixture = await Fixture.CreateAsync(_key, terminalValid: true);

        Exact23LocalDeltaFinalizationResult result = await fixture.Coordinator
            .FinalizeAsync(fixture.Plan, fixture.Schema, CancellationToken.None);

        Assert.Equal(["apply", "reconcile", "queries", "snapshot", "apphost-evidence"], fixture.Runtime.Calls);
        Assert.Equal(fixture.Plan.PlanId, result.TerminalReceipt.PlanId);
        Assert.Equal(DatabaseInventory.ActiveDatabases, result.QueryEvidence.Queries.Select(item => item.Database));
        Assert.Equal(DatabaseInventory.ActiveDatabases, result.Snapshot.Databases.Select(item => item.Database));
    }

    [Fact]
    public async Task Canonical_snapshot_rejects_invalid_terminal_receipt_before_opening_any_dump()
    {
        Fixture fixture = await Fixture.CreateAsync(_key, terminalValid: false);
        var source = new DumpSource();

        MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            LocalSnapshotExporter.ExportCanonicalDeltaAsync(fixture.Terminal, fixture.Trust, _root, "delta-invalid",
                RandomNumberGenerator.GetBytes(32), source, CancellationToken.None));

        Assert.Equal("snapshot_terminal_receipt_invalid", error.Code);
        Assert.Empty(source.Opened);
        Assert.False(Directory.Exists(_root));
    }

    [Fact]
    public async Task Canonical_snapshot_exports_exact_active_inventory_after_terminal_verification()
    {
        Fixture fixture = await Fixture.CreateAsync(_key, terminalValid: true);
        var source = new DumpSource();

        LocalSnapshotManifest manifest = await LocalSnapshotExporter.ExportCanonicalDeltaAsync(
            fixture.Terminal, fixture.Trust, _root, "delta-valid", RandomNumberGenerator.GetBytes(32), source,
            CancellationToken.None);

        Assert.Equal(DatabaseInventory.ActiveDatabases, source.Opened);
        Assert.Equal(DatabaseInventory.ActiveDatabases, manifest.Databases.Select(item => item.Database));
        Assert.All(manifest.Databases, item => Assert.Equal(item.Database, item.ShadowDatabase));
    }

    [Fact]
    public async Task Failed_representative_query_prevents_snapshot_and_AppHost_evidence()
    {
        Fixture fixture = await Fixture.CreateAsync(_key, terminalValid: true);
        fixture.Runtime.FailRepresentativeQuery = true;

        DeltaExecutionException error = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            fixture.Coordinator.FinalizeAsync(fixture.Plan, fixture.Schema, CancellationToken.None));

        Assert.Equal("local_delta_service_query_evidence_invalid", error.Code);
        Assert.Equal(["apply", "reconcile", "queries"], fixture.Runtime.Calls);
    }

    [Fact]
    public async Task Replay_of_committed_plan_still_requires_fresh_terminal_checks_and_artifacts()
    {
        Fixture fixture = await Fixture.CreateAsync(_key, terminalValid: true);
        fixture.Runtime.Replay = true;

        Exact23LocalDeltaFinalizationResult result = await fixture.Coordinator
            .FinalizeAsync(fixture.Plan, fixture.Schema, CancellationToken.None);

        Assert.All(result.Execution.Databases,
            item => Assert.Equal(DeltaExecutionDisposition.AlreadyCommitted, item.Disposition));
        Assert.Equal(["apply", "reconcile", "queries", "snapshot", "apphost-evidence"], fixture.Runtime.Calls);
    }

    [Fact]
    public async Task Representative_query_validator_verifies_terminal_before_opening_PostgreSql()
    {
        Fixture fixture = await Fixture.CreateAsync(_key, terminalValid: false);
        var executor = new QueryExecutor();
        var validator = new Exact23RepresentativeServiceQueryValidator(executor, fixture.Trust, new FixedTime(fixture.Now));

        DeltaExecutionException error = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            validator.ValidateAsync(fixture.Plan, fixture.Schema, fixture.Terminal, CancellationToken.None));

        Assert.Equal("local_delta_terminal_receipt_invalid", error.Code);
        Assert.Empty(executor.Calls);
    }

    [Fact]
    public async Task Representative_query_validator_reads_one_signed_table_per_database_and_records_owner()
    {
        Fixture fixture = await Fixture.CreateAsync(_key, terminalValid: true);
        var executor = new QueryExecutor();
        var validator = new Exact23RepresentativeServiceQueryValidator(executor, fixture.Trust, new FixedTime(fixture.Now));

        Exact23RepresentativeServiceQueryEvidence evidence = await validator.ValidateAsync(
            fixture.Plan, fixture.Schema, fixture.Terminal, CancellationToken.None);

        Assert.Equal(DatabaseInventory.ActiveDatabases, executor.Calls.Select(item => item.Database));
        Assert.All(executor.Calls, item => Assert.Equal("public.items", item.Table));
        Assert.All(evidence.Queries, item => Assert.Equal(DatabaseInventory.Entries[item.Database].Owner, item.Service));
    }

    [Fact]
    public async Task Delta_AppHost_evidence_binds_terminal_queries_and_snapshot_without_replacement_authority()
    {
        Fixture fixture = await Fixture.CreateAsync(_key, terminalValid: true);
        Exact23LocalDeltaFinalizationResult finalized = await fixture.Coordinator
            .FinalizeAsync(fixture.Plan, fixture.Schema, CancellationToken.None);
        using var signer = new P256MigrationEvidenceSigner("local-evidence", _key.ExportECPrivateKeyPem());

        AppHostMigrationEvidenceV2Document document = Exact23LocalDeltaAppHostEvidenceV2Producer.Produce(
            fixture.Plan, fixture.Schema, finalized.TerminalReceipt, finalized.QueryEvidence, finalized.Snapshot,
            fixture.Trust, signer, new FixedTime(fixture.Now));
        JsonObject evidence = JsonNode.Parse(document.EvidenceJson)!.AsObject();

        Assert.Equal(2, evidence["schemaVersion"]!.GetValue<int>());
        Assert.Equal("incremental", evidence["target"]!["mode"]!.GetValue<string>());
        Assert.Equal("local-aspire", evidence["target"]!["authority"]!.GetValue<string>());
        Assert.False(evidence["constraints"]!["databaseReplacementAllowed"]!.GetValue<bool>());
        Assert.Equal(23, evidence["databases"]!.AsArray().Count);
        Assert.NotNull(evidence["attestation"]);
        Assert.DoesNotContain("password", document.EvidenceJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connection", document.EvidenceJson, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Delta_AppHost_evidence_rejects_failed_query_before_signing()
    {
        Fixture fixture = await Fixture.CreateAsync(_key, terminalValid: true);
        Exact23LocalDeltaFinalizationResult finalized = await fixture.Coordinator
            .FinalizeAsync(fixture.Plan, fixture.Schema, CancellationToken.None);
        Exact23RepresentativeServiceQueryEvidence failed = finalized.QueryEvidence with
        {
            Queries = [finalized.QueryEvidence.Queries[0] with { Succeeded = false }, .. finalized.QueryEvidence.Queries.Skip(1)],
        };
        var signer = new CountingSigner(new P256MigrationEvidenceSigner("local-evidence", _key.ExportECPrivateKeyPem()));

        DeltaExecutionException error = Assert.Throws<DeltaExecutionException>(() =>
            Exact23LocalDeltaAppHostEvidenceV2Producer.Produce(fixture.Plan, fixture.Schema,
                finalized.TerminalReceipt, failed, finalized.Snapshot, fixture.Trust, signer, new FixedTime(fixture.Now)));

        Assert.Equal("local_delta_apphost_evidence_invalid", error.Code);
        Assert.Equal(0, signer.SignCount);
        signer.Dispose();
    }

    [Fact]
    public async Task Guarded_console_runtime_binds_apply_reconcile_queries_snapshot_and_evidence()
    {
        Fixture fixture = await Fixture.CreateAsync(_key, terminalValid: true);
        var guarded = new GuardedRuntime(fixture.Runtime);
        using var signer = new P256MigrationEvidenceSigner("local-evidence", _key.ExportECPrivateKeyPem());
        var apply = new Console.DeltaApplyRuntimeRequest(
            fixture.Schema, fixture.Plan, null!, "source", "target", fixture.Plan.TargetAuthority!, fixture.Trust);
        var reconcile = new Console.DeltaReconcileRuntimeRequest(
            fixture.Schema, fixture.Plan, "source", "target", signer);
        var queryExecutor = new QueryExecutor();
        var runtime = new Console.GuardedLocalDeltaFinalizationRuntime(
            guarded, apply, reconcile,
            new(queryExecutor, fixture.Trust, new FixedTime(fixture.Now)), fixture.Trust, _root, "bound-delta",
            RandomNumberGenerator.GetBytes(32), new DumpSource(), signer, new FixedTime(fixture.Now));

        Exact23LocalDeltaFinalizationResult result = await new Exact23LocalDeltaFinalizationCoordinator(runtime, fixture.Trust)
            .FinalizeAsync(fixture.Plan, fixture.Schema, CancellationToken.None);

        Assert.Equal(1, guarded.ApplyCalls);
        Assert.Equal(1, guarded.ReconcileCalls);
        Assert.Equal(23, result.QueryEvidence.Queries.Count);
        Assert.Equal(23, result.Snapshot.Databases.Count);
        Assert.Contains("\"mode\": \"incremental\"", result.AppHostEvidence.EvidenceJson, StringComparison.Ordinal);
    }

    private sealed record Fixture(
        FreshSchemaPlan Schema,
        DeltaSynchronizationPlan Plan,
        Runtime Runtime,
        Exact23LocalDeltaFinalizationCoordinator Coordinator,
        Exact23DeltaReconciliationResult Terminal,
        ReceiptAttestationTrustStore Trust,
        DateTimeOffset Now)
    {
        internal static async Task<Fixture> CreateAsync(ECDsa key, bool terminalValid)
        {
            DateTimeOffset now = new(2026, 9, 9, 8, 0, 0, TimeSpan.Zero);
            FreshSchemaPlan schema = Schemas(now);
            DeltaSynchronizationPlan plan = PlanFor(schema, now);
            using var signer = new P256MigrationEvidenceSigner("evidence", key.ExportECPrivateKeyPem());
            var inspector = new Inspector(Evidence);
            var terminalCoordinator = new Exact23DeltaReconciliationCoordinator(inspector, inspector,
                new Checkpoints(plan, schema), new FixedTime(now), signer);
            Exact23DeltaReconciliationResult terminal = await terminalCoordinator
                .ReconcileAsync(plan, schema, CancellationToken.None);
            if (!terminalValid)
            {
                terminal = terminal with { PlanSha256 = Hash('9') };
            }
            var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
            var runtime = new Runtime(plan, terminal, now);
            return new(schema, plan, runtime, new(runtime, trust), terminal, trust, now);
        }
    }

    private sealed class Runtime(
        DeltaSynchronizationPlan plan,
        Exact23DeltaReconciliationResult terminal,
        DateTimeOffset now) : IExact23LocalDeltaFinalizationRuntime
    {
        internal List<string> Calls { get; } = [];
        internal bool FailRepresentativeQuery { get; set; }
        internal bool Replay { get; set; }

        public Task<Exact23DeltaExecutionResult> ApplyAsync(DeltaSynchronizationPlan value, FreshSchemaPlan schema, CancellationToken token)
        {
            Calls.Add("apply");
            return Task.FromResult(new Exact23DeltaExecutionResult(plan.PlanId,
                DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan), plan.SourceCutoffUtc,
                [.. DatabaseInventory.ActiveDatabases.Select(database => new DeltaDatabaseExecutionResult(
                    database, Replay ? DeltaExecutionDisposition.AlreadyCommitted : DeltaExecutionDisposition.Committed, 1,
                    DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan), Hash('7')))]));
        }

        public Task<Exact23DeltaReconciliationResult> ReconcileAsync(DeltaSynchronizationPlan value, FreshSchemaPlan schema, CancellationToken token)
        {
            Calls.Add("reconcile");
            return Task.FromResult(terminal);
        }

        public Task<Exact23RepresentativeServiceQueryEvidence> ValidateRepresentativeQueriesAsync(
            DeltaSynchronizationPlan value, Exact23DeltaReconciliationResult receipt, CancellationToken token)
        {
            Calls.Add("queries");
            RepresentativeServiceQueryResult[] results = [.. DatabaseInventory.ActiveDatabases.Select(database =>
                new RepresentativeServiceQueryResult(database, $"Legacy.Maliev.{database}Service", "read-one",
                    !FailRepresentativeQuery || database != DatabaseInventory.ActiveDatabases[0]))];
            return Task.FromResult(new Exact23RepresentativeServiceQueryEvidence("1.0", plan.PlanId,
                DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan), plan.SourceCutoffUtc, now, results));
        }

        public Task<LocalSnapshotManifest> ExportEncryptedSnapshotAsync(
            DeltaSynchronizationPlan value,
            Exact23DeltaReconciliationResult receipt,
            Exact23RepresentativeServiceQueryEvidence queries,
            CancellationToken token)
        {
            Calls.Add("snapshot");
            return Task.FromResult(new LocalSnapshotManifest(2, "MLVSNP02", "AES-256-GCM-chunked-v2", "delta-snapshot",
                Hash('3'), Hash('4'), [.. DatabaseInventory.ActiveDatabases.Select(database =>
                    new LocalSnapshotDatabase(database, database, $"{database}.dump.aes256", 1, Hash('5'), 2, Hash('6')))]));
        }

        public Task<AppHostMigrationEvidenceV2Document> ProduceAppHostEvidenceAsync(
            DeltaSynchronizationPlan value,
            Exact23DeltaReconciliationResult receipt,
            Exact23RepresentativeServiceQueryEvidence queries,
            LocalSnapshotManifest snapshot,
            CancellationToken token)
        {
            Calls.Add("apphost-evidence");
            return Task.FromResult(new AppHostMigrationEvidenceV2Document("{}", "{}"));
        }
    }

    private static FreshSchemaPlan Schemas(DateTimeOffset now)
    {
        return new("2.0", now, new string('1', 40), [.. DatabaseInventory.ActiveDatabases.Select(database =>
            new DatabaseSchemaPlan(database, "1.0", Hash('a'), Hash('b'), [Table()]))]);
    }

    private static DeltaSynchronizationPlan PlanFor(FreshSchemaPlan schemas, DateTimeOffset now)
    {
        string operations = DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256([]);
        return new("1.1", Guid.NewGuid(), schemas.SourceCommitSha, now.AddMinutes(-1), Hash('1'),
            SchemaPlanCanonicalizer.ComputeSha256(schemas), Hash('2'), "local-aspire", "legacy-postgres-main-local",
            "generation-1", Hash('3'), Hash('4'), Hash('5'), now,
            [.. DatabaseInventory.ActiveDatabases.Select(database => new DeltaDatabasePlan(database,
                [new("public.items", 0, 0, 0, 1, operations, [])]))], "plan", "signature")
        {
            TargetAuthority = new(DeltaTargetAuthorityKind.LocalAspire,
                "aspire://legacy-postgres-main-local/test", Hash('6')),
        };
    }

    private static TableCopyPlan Table()
    {
        return new("dbo", "items", "public", "items", ["id"], ["id"])
        {
            SourceColumnTypes = new Dictionary<string, string> { ["id"] = "int" },
            ColumnTypes = new Dictionary<string, string> { ["id"] = "integer" },
            PrimaryKey = new("pk_items", ["id"]),
        };
    }

    private static DatabaseReconciliationEvidence Evidence(DatabaseSchemaPlan schema)
    {
        var table = new TableReconciliationEvidence("public.items", 1, Hash('c'), Hash('d'),
            new Dictionary<string, long> { ["id"] = 0 }, new Dictionary<string, long>());
        return new(schema.Database, schema.SourceSchemaSha256, schema.TargetSchemaSha256, [table]);
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    public void Dispose()
    {
        _key.Dispose();
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class DumpSource : IPostgreSqlDumpSource
    {
        internal List<string> Opened { get; } = [];

        public Task<Stream> OpenDumpAsync(string database, string shadowDatabase, CancellationToken cancellationToken)
        {
            Opened.Add(database);
            return Task.FromResult<Stream>(new MemoryStream(System.Text.Encoding.UTF8.GetBytes($"{database}:{shadowDatabase}")));
        }
    }

    private sealed class QueryExecutor : IExact23RepresentativeServiceQueryExecutor
    {
        internal List<(string Database, string Table)> Calls { get; } = [];

        public Task<bool> ExecuteAsync(string database, TableCopyPlan table, CancellationToken cancellationToken)
        {
            Calls.Add((database, $"{table.TargetSchema}.{table.TargetTable}"));
            return Task.FromResult(true);
        }
    }

    private sealed class CountingSigner(P256MigrationEvidenceSigner inner) : IMigrationEvidenceSigner, IDisposable
    {
        internal int SignCount { get; private set; }
        public string KeyId => inner.KeyId;
        public string PublicKeyFingerprintSha256 => inner.PublicKeyFingerprintSha256;
        public byte[] Sign(ReadOnlySpan<byte> payload)
        {
            SignCount++;
            return inner.Sign(payload);
        }
        public void Dispose()
        {
            inner.Dispose();
        }
    }

    private sealed class GuardedRuntime(Runtime runtime) : Console.IGuardedDeltaConsoleRuntime
    {
        internal int ApplyCalls { get; private set; }
        internal int ReconcileCalls { get; private set; }

        public Task<DeltaSynchronizationPlan> PlanAsync(
            Console.DeltaPlanRuntimeRequest request,
            CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<Exact23DeltaExecutionResult> ApplyAsync(
            Console.DeltaApplyRuntimeRequest request,
            CancellationToken cancellationToken)
        {
            ApplyCalls++;
            return runtime.ApplyAsync(request.Plan, request.Schema, cancellationToken);
        }

        public Task<Exact23DeltaReconciliationResult> ReconcileAsync(
            Console.DeltaReconcileRuntimeRequest request,
            CancellationToken cancellationToken)
        {
            ReconcileCalls++;
            return runtime.ReconcileAsync(request.Plan, request.Schema, cancellationToken);
        }
    }

    private sealed class Inspector(Func<DatabaseSchemaPlan, DatabaseReconciliationEvidence> inspect) : IDeltaReconciliationInspector
    {
        public Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema, CancellationToken token)
        {
            return Task.FromResult(inspect(schema));
        }
    }

    private sealed class Checkpoints(DeltaSynchronizationPlan plan, FreshSchemaPlan schemas) : IExact23DeltaCheckpointReader
    {
        public Task<IReadOnlyList<DeltaDatabaseCheckpointEvidence>> ReadAsync(
            DeltaSynchronizationPlan value, FreshSchemaPlan schema, CancellationToken token)
        {
            string planHash = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
            return Task.FromResult<IReadOnlyList<DeltaDatabaseCheckpointEvidence>>(
                [.. DatabaseInventory.ActiveDatabases.Select(database => new DeltaDatabaseCheckpointEvidence(
                    database, plan.PlanId, planHash, plan.SourceCutoffUtc, plan.TargetObservationSha256,
                    DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(
                        plan.Databases.Single(item => item.Database == database)),
                    DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(Evidence(
                        schemas.Databases.Single(item => item.Database == database))),
                    plan.SourceCutoffUtc.AddSeconds(1)))]);
        }
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
}
