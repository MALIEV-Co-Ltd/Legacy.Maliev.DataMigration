using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Exact23DeltaExecutionCoordinatorTests : IDisposable
{
    private readonly ECDsa _planKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public async Task Completed_checkpoint_replay_visits_and_completes_every_database_snapshot()
    {
        DateTimeOffset now = new(2026, 9, 8, 8, 0, 0, TimeSpan.Zero);
        FreshSchemaPlan schemas = Schemas(now);
        (DeltaSynchronizationPlan plan, ReceiptAttestationTrustStore trust) = Plan(schemas, now);
        var source = new Source();
        var coordinator = new Exact23DeltaExecutionCoordinator(source,
            _ => Executor(trust, now, failAuthorization: false));

        Exact23DeltaExecutionResult result = await coordinator.ExecuteAsync(plan, schemas, CancellationToken.None);

        Assert.Equal(DatabaseInventory.ActiveDatabases, result.Databases.Select(item => item.Database));
        Assert.All(result.Databases, item => Assert.Equal(DeltaExecutionDisposition.AlreadyCommitted, item.Disposition));
        Assert.Equal(DatabaseInventory.ActiveDatabases, source.Begun);
        Assert.Equal(DatabaseInventory.ActiveDatabases, source.Completed);
        Assert.Empty(source.RolledBack);
    }

    [Fact]
    public async Task Database_failure_rolls_back_its_source_snapshot_and_stops_later_databases()
    {
        DateTimeOffset now = new(2026, 9, 8, 8, 0, 0, TimeSpan.Zero);
        FreshSchemaPlan schemas = Schemas(now);
        (DeltaSynchronizationPlan plan, ReceiptAttestationTrustStore trust) = Plan(schemas, now);
        string failureDatabase = DatabaseInventory.ActiveDatabases[1];
        var source = new Source();
        var coordinator = new Exact23DeltaExecutionCoordinator(source,
            database => Executor(trust, now, database == failureDatabase));

        DeltaExecutionException error = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            coordinator.ExecuteAsync(plan, schemas, CancellationToken.None));

        Assert.Equal("synthetic_authorization_failure", error.Code);
        Assert.Equal(DatabaseInventory.ActiveDatabases.Take(2), source.Begun);
        Assert.Equal([DatabaseInventory.ActiveDatabases[0]], source.Completed);
        Assert.Equal([failureDatabase], source.RolledBack);
    }

    private static DeltaExecutionCoordinator Executor(
        ReceiptAttestationTrustStore trust,
        DateTimeOffset now,
        bool failAuthorization)
    {
        return new(new ReplayTarget(), new NoRows(), new Authorization(failAuthorization),
            new UnusedInspector(), trust, new FixedTime(now));
    }

    private (DeltaSynchronizationPlan, ReceiptAttestationTrustStore) Plan(FreshSchemaPlan schemas, DateTimeOffset now)
    {
        using var signer = new P256MigrationEvidenceSigner("plan", _planKey.ExportECPrivateKeyPem());
        string operations = DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256([]);
        DeltaSynchronizationPlan plan = DeltaSynchronizationPlanProducer.Produce(new(
            schemas.SourceCommitSha, now.AddMinutes(-1), Hash('a'), SchemaPlanCanonicalizer.ComputeSha256(schemas),
            Hash('b'), "local-aspire", "legacy-postgres-main-local", "generation-1", Hash('c'), Hash('d'), Hash('e'),
            [.. DatabaseInventory.ActiveDatabases.Select(database => new DeltaDatabasePlan(database,
                [new("public.items", 0, 0, 0, 0, operations, [])]))])
        {
            TargetAuthority = new(DeltaTargetAuthorityKind.LocalAspire,
                "aspire://legacy-postgres-main-local/test", Hash('f')),
        }, signer, now);
        return (plan, new([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]));
    }

    private static FreshSchemaPlan Schemas(DateTimeOffset now)
    {
        return new("2.0", now, new string('1', 40), [.. DatabaseInventory.ActiveDatabases.Select(database =>
            new DatabaseSchemaPlan(database, "1.0", Hash('1'), Hash('2'), [Table()]))]);
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

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    public void Dispose()
    {
        _planKey.Dispose();
    }

    private sealed class Source : IReadOnlySqlServerMigrationSource
    {
        internal List<string> Begun { get; } = [];
        internal List<string> Completed { get; } = [];
        internal List<string> RolledBack { get; } = [];
        public Task BeginDatabaseSnapshotAsync(string database, CancellationToken token) { Begun.Add(database); return Task.CompletedTask; }
        public Task CompleteDatabaseSnapshotAsync(string database, CancellationToken token) { Completed.Add(database); return Task.CompletedTask; }
        public Task RollbackDatabaseSnapshotAsync(string database, CancellationToken token) { RolledBack.Add(database); return Task.CompletedTask; }
        public Task<SourceSchemaEvidence> InspectSchemaAsync(string database, CancellationToken token)
        {
            throw new NotSupportedException();
        }

        public IAsyncEnumerable<MigrationRow> ReadTableAsync(string database, TableCopyPlan table, CancellationToken token)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyOrphansAsync(string database, TableCopyPlan table, CancellationToken token)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyRelationshipsAsync(string database, TableCopyPlan table, CancellationToken token)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyDictionary<string, long>> InspectSequenceNextValuesAsync(string database, DatabaseSchemaPlan plan, CancellationToken token)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class ReplayTarget : IDeltaCanonicalTarget
    {
        public Task<IDeltaCanonicalTransaction> BeginAsync(DeltaSynchronizationPlan plan, DatabaseSchemaPlan schema, string database, CancellationToken token)
        {
            return Task.FromResult<IDeltaCanonicalTransaction>(new ReplayTransaction());
        }
    }

    private sealed class ReplayTransaction : IDeltaCanonicalTransaction
    {
        public DeltaExecutionDisposition Disposition => DeltaExecutionDisposition.AlreadyCommitted;
        public string? ReconciliationSha256 => Hash('9');
        public Task ApplyAsync(TableCopyPlan table, CanonicalDeltaOperation operation, MigrationRow? source, MigrationRow? target, CancellationToken token)
        {
            throw new NotSupportedException();
        }

        public Task<string> ReconcileAsync(DatabaseReconciliationEvidence expected, CancellationToken token)
        {
            throw new NotSupportedException();
        }

        public Task CommitAsync(string planSha256, string reconciliationSha256, CancellationToken token)
        {
            throw new NotSupportedException();
        }

        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }
    }

    private sealed class Authorization(bool fail) : IDeltaExecutionAuthorizationGate
    {
        public Task ValidateAsync(DeltaSynchronizationPlan plan, string database, CancellationToken token)
        {
            return fail
                ? Task.FromException(new DeltaExecutionException("synthetic_authorization_failure", "Synthetic failure."))
                : Task.CompletedTask;
        }
    }

    private sealed class NoRows : IDeltaExecutionRowSessionProvider
    {
        public Task<IDeltaExecutionRowSession> OpenAsync(string database, TableCopyPlan table, CancellationToken token)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class UnusedInspector : IDeltaReconciliationInspector
    {
        public Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema, CancellationToken token)
        {
            throw new NotSupportedException();
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
