using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DeltaExecutionCoordinatorTests : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public async Task Applies_parent_writes_before_children_and_child_deletes_before_parents()
    {
        Fixture fixture = CreateFixture();

        DeltaDatabaseExecutionResult result = await fixture.Coordinator.ExecuteDatabaseAsync(
            fixture.Plan, fixture.Schema, fixture.Database, CancellationToken.None);

        Assert.Equal(DeltaExecutionDisposition.Committed, result.Disposition);
        Assert.Equal(
            ["Insert:public.parents", "Insert:public.children", "Delete:public.children", "Delete:public.parents"],
            fixture.Target.Applied);
        Assert.True(fixture.Target.Committed);
        Assert.False(fixture.Target.RolledBack);
        Assert.NotNull(result.ReconciliationSha256);
    }

    [Fact]
    public async Task Fingerprint_drift_rolls_back_without_later_mutations()
    {
        Fixture fixture = CreateFixture();
        fixture.Rows.SourceRows["public.parents"] = [Row(100, "tampered")];

        DeltaExecutionException exception = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            fixture.Coordinator.ExecuteDatabaseAsync(fixture.Plan, fixture.Schema, fixture.Database, CancellationToken.None));

        Assert.Equal("delta_execution_source_row_drift", exception.Code);
        Assert.Empty(fixture.Target.Applied);
        Assert.False(fixture.Target.Committed);
        Assert.True(fixture.Target.RolledBack);
    }

    [Fact]
    public async Task Identical_completed_plan_is_a_noop()
    {
        Fixture fixture = CreateFixture(DeltaExecutionDisposition.AlreadyCommitted);

        DeltaDatabaseExecutionResult result = await fixture.Coordinator.ExecuteDatabaseAsync(
            fixture.Plan, fixture.Schema, fixture.Database, CancellationToken.None);

        Assert.Equal(DeltaExecutionDisposition.AlreadyCommitted, result.Disposition);
        Assert.Empty(fixture.Target.Applied);
        Assert.False(fixture.Target.Committed);
        Assert.Equal(new string('7', 64), result.ReconciliationSha256);
    }

    [Fact]
    public async Task Reconciliation_failure_rolls_back_without_commit_or_checkpoint()
    {
        Fixture fixture = CreateFixture();
        fixture.Target.FailReconciliation = true;

        DeltaExecutionException error = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            fixture.Coordinator.ExecuteDatabaseAsync(fixture.Plan, fixture.Schema, fixture.Database, CancellationToken.None));

        Assert.Equal("shadow_reconciliation_failed", error.Code);
        Assert.False(fixture.Target.Committed);
        Assert.False(fixture.Target.Checkpointed);
        Assert.True(fixture.Target.RolledBack);
    }

    private Fixture CreateFixture(DeltaExecutionDisposition disposition = DeltaExecutionDisposition.Pending)
    {
        const string database = "ContactRequest";
        TableCopyPlan parents = Table("parents");
        TableCopyPlan children = Table("children") with
        {
            ForeignKeys =
            [
                new ForeignKeyCopyPlan("FK_children_parents", ["Id"], "public", "parents", ["Id"]),
            ],
        };
        MigrationRow parentSource = Row(100, "parent-new");
        MigrationRow parentTarget = Row(10, "parent-old");
        MigrationRow childSource = Row(200, "child-new");
        MigrationRow childTarget = Row(20, "child-old");
        CanonicalDeltaOperation parentInsert = Insert(parents, parentSource);
        CanonicalDeltaOperation parentDelete = Delete(parents, parentTarget);
        CanonicalDeltaOperation childInsert = Insert(children, childSource);
        CanonicalDeltaOperation childDelete = Delete(children, childTarget);
        DeltaTablePlan parentDelta = Delta(parents, [parentInsert, parentDelete]);
        DeltaTablePlan childDelta = Delta(children, [childInsert, childDelete]);
        var databaseDelta = new DeltaDatabasePlan(database, [parentDelta, childDelta]);
        DeltaDatabasePlan[] databases = [.. DatabaseInventory.ActiveDatabases.Select(name =>
            string.Equals(name, database, StringComparison.Ordinal)
                ? databaseDelta
                : new DeltaDatabasePlan(name, [Delta(Table("items"), [])]))];
        using var signer = new P256MigrationEvidenceSigner("delta-plan", _key.ExportECPrivateKeyPem());
        string signerHash = signer.PublicKeyFingerprintSha256;
        string hashA = new('a', 64);
        DeltaSynchronizationPlan plan = DeltaSynchronizationPlanProducer.Produce(new(
            "5ac7d045c51194edd9e64d8564f1b726b001be34",
            Now().AddMinutes(-1), hashA, new('b', 64), new('c', 64), "maliev-legacy", "legacy-postgres-main",
            "generation-1", new('d', 64), Different(signerHash, 'e'), Different(signerHash, 'f'), databases)
        {
            TargetAuthority = new(DeltaTargetAuthorityKind.ProductionCloudNativePg,
                "gke://maliev-website/us-central1-a/maliev-legacy/legacy-postgres-main/uid-1", new('8', 64)),
        }, signer, Now());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        var rows = new FakeRows();
        rows.SourceRows["public.parents"] = [parentSource];
        rows.SourceRows["public.children"] = [childSource];
        rows.TargetRows["public.parents"] = [parentTarget];
        rows.TargetRows["public.children"] = [childTarget];
        var target = new FakeTarget(disposition);
        return new(
            database,
            new DatabaseSchemaPlan(database, "1.0", hashA, new('b', 64), [parents, children]),
            plan,
            new DeltaExecutionCoordinator(target, rows, new AllowAuthorization(), new FakeSourceReconciliation(database, [parents, children]), trust, TimeProvider.System),
            target,
            rows,
            parentInsert);
    }

    private static string Different(string value, char character)
    {
        string candidate = new(character, 64);
        return string.Equals(candidate, value, StringComparison.OrdinalIgnoreCase) ? new('1', 64) : candidate;
    }

    private static DateTimeOffset Now()
    {
        return DateTimeOffset.UtcNow;
    }

    private static TableCopyPlan Table(string name)
    {
        return new("dbo", name, "public", name, ["Id", "Name"], ["Id"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["Id"] = "integer", ["Name"] = "text" },
            PrimaryKey = new PrimaryKeyCopyPlan($"PK_{name}", ["Id"]),
        };
    }

    private static MigrationRow Row(int id, string name)
    {
        return new(new Dictionary<string, object?> { ["Id"] = id, ["Name"] = name });
    }

    private static CanonicalDeltaOperation Insert(TableCopyPlan table, MigrationRow row)
    {
        CanonicalTableDelta delta = CanonicalDeltaPlanner.Plan(table, [row], []);
        return Assert.Single(delta.Operations);
    }

    private static CanonicalDeltaOperation Delete(TableCopyPlan table, MigrationRow row)
    {
        CanonicalTableDelta delta = CanonicalDeltaPlanner.Plan(table, [], [row]);
        return Assert.Single(delta.Operations);
    }

    private static DeltaTablePlan Delta(TableCopyPlan table, IReadOnlyList<CanonicalDeltaOperation> operations)
    {
        return new(
            $"{table.TargetSchema}.{table.TargetTable}",
            operations.LongCount(item => item.Kind == DeltaOperationKind.Insert),
            operations.LongCount(item => item.Kind == DeltaOperationKind.Update),
            operations.LongCount(item => item.Kind == DeltaOperationKind.Delete),
            0,
            DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(operations),
            operations);
    }

    public void Dispose()
    {
        _key.Dispose();
    }

    private sealed record Fixture(
        string Database,
        DatabaseSchemaPlan Schema,
        DeltaSynchronizationPlan Plan,
        DeltaExecutionCoordinator Coordinator,
        FakeTarget Target,
        FakeRows Rows,
        CanonicalDeltaOperation ParentInsert);

    private sealed class FakeRows : IDeltaExecutionRowSessionProvider
    {
        internal Dictionary<string, IReadOnlyList<MigrationRow>> SourceRows { get; } = new(StringComparer.Ordinal);
        internal Dictionary<string, IReadOnlyList<MigrationRow>> TargetRows { get; } = new(StringComparer.Ordinal);

        public Task<IDeltaExecutionRowSession> OpenAsync(string database, TableCopyPlan table, CancellationToken token)
        {
            string name = $"{table.TargetSchema}.{table.TargetTable}";
            var provider = new OrderedDeltaExecutionRowSessionProvider(
                new Rows(SourceRows.GetValueOrDefault(name) ?? []),
                new Rows(TargetRows.GetValueOrDefault(name) ?? []));
            return provider.OpenAsync(database, table, token);
        }

        private sealed class Rows(IReadOnlyList<MigrationRow> values) : IDeltaOrderedRowSource
        {
            public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(string database, TableCopyPlan table,
                [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
            {
                foreach (MigrationRow row in values) { cancellationToken.ThrowIfCancellationRequested(); yield return row; await Task.Yield(); }
            }
        }
    }

    private sealed class FakeTarget(DeltaExecutionDisposition disposition) : IDeltaCanonicalTarget
    {
        internal List<string> Applied { get; } = [];
        internal bool Committed { get; private set; }
        internal bool RolledBack { get; private set; }
        internal bool Checkpointed { get; private set; }
        internal bool FailReconciliation { get; set; }

        public Task<IDeltaCanonicalTransaction> BeginAsync(DeltaSynchronizationPlan plan, DatabaseSchemaPlan schema, string database, CancellationToken token)
        {
            return Task.FromResult<IDeltaCanonicalTransaction>(new Transaction(this, disposition));
        }

        private sealed class Transaction(FakeTarget owner, DeltaExecutionDisposition disposition) : IDeltaCanonicalTransaction
        {
            public DeltaExecutionDisposition Disposition => disposition;

            public string? ReconciliationSha256 => disposition == DeltaExecutionDisposition.AlreadyCommitted ? new('7', 64) : null;

            public Task ApplyAsync(TableCopyPlan table, CanonicalDeltaOperation operation, MigrationRow? source, MigrationRow? target, CancellationToken token)
            {
                owner.Applied.Add($"{operation.Kind}:{table.TargetSchema}.{table.TargetTable}");
                return Task.CompletedTask;
            }

            public Task<string> ReconcileAsync(DatabaseReconciliationEvidence expected, CancellationToken token)
            {
                return owner.FailReconciliation
                    ? throw new DeltaExecutionException("shadow_reconciliation_failed", "Synthetic mismatch.")
                    : Task.FromResult(DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(expected));
            }

            public Task CommitAsync(string planSha256, string reconciliationSha256, CancellationToken token)
            {
                owner.Checkpointed = true;
                owner.Committed = true;
                return Task.CompletedTask;
            }

            public ValueTask DisposeAsync()
            {
                if (!owner.Committed && disposition == DeltaExecutionDisposition.Pending) { owner.RolledBack = true; }
                return ValueTask.CompletedTask;
            }
        }
    }

    private sealed class FakeSourceReconciliation(string database, IReadOnlyList<TableCopyPlan> tables) : IDeltaReconciliationInspector
    {
        public Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema, CancellationToken cancellationToken)
        {
            TableReconciliationEvidence[] evidence = [.. tables.Select(table => new TableReconciliationEvidence(
                $"{table.TargetSchema}.{table.TargetTable}", 0, new('1', 64), new('2', 64),
                table.OrderedColumns.ToDictionary(column => column, _ => 0L, StringComparer.Ordinal),
                table.ForeignKeys.ToDictionary(foreignKey => foreignKey.Name, _ => 0L, StringComparer.Ordinal))
            {
                ForeignKeyRelationshipCounts = table.ForeignKeys.ToDictionary(foreignKey => foreignKey.Name, _ => 0L, StringComparer.Ordinal),
            })];
            return Task.FromResult(new DatabaseReconciliationEvidence(database, schema.SourceSchemaSha256, schema.TargetSchemaSha256, evidence));
        }
    }

    private sealed class AllowAuthorization : IDeltaExecutionAuthorizationGate
    {
        public Task ValidateAsync(DeltaSynchronizationPlan plan, string database, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
