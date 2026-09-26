using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Exact23CapturedDeltaPlanCoordinatorTests : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public async Task Plans_all_23_from_encrypted_cutoffs_and_ignores_later_source_writes()
    {
        string directory = Path.Combine(Path.GetTempPath(), "legacy-delta-planner-tests", Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(directory);
        try
        {
            FreshSchemaPlan schema = Schema();
            var source = new LiveSource();
            var archive = new DeltaCapturedTableArchive(directory);
            byte[] captureKey = RandomNumberGenerator.GetBytes(32);
            using var signer = new P256MigrationEvidenceSigner("captured-plan", _key.ExportECPrivateKeyPem());
            using var authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var authorizer = new P256MigrationEvidenceSigner("captured-authorization",
                authorizationKey.ExportECPrivateKeyPem());
            var coordinator = new Exact23CapturedDeltaPlanCoordinator(source, new EmptyTarget(),
                new SourceEvidence(), archive, signer, new FixedTime());

            DeltaSynchronizationPlan plan = await coordinator.ProduceAsync(Request(schema) with
            {
                ExecutionAuthorizationKeyFingerprintSha256 = authorizer.PublicKeyFingerprintSha256,
            },
                captureKey, CancellationToken.None);

            Assert.Equal("1.3", plan.SchemaVersion);
            Assert.Equal(DatabaseInventory.ActiveDatabases.Count, source.Completed.Count);
            Assert.Equal(DatabaseInventory.ActiveDatabases.Count, plan.SourceCaptureManifest!.Databases.Count);
            Assert.All(plan.Databases, database =>
            {
                Assert.Equal(1, Assert.Single(database.Tables).InsertCount);
                Assert.Equal(0, database.Tables[0].DeleteCount);
                Assert.Equal(2, source.LiveRowCount(database.Database));
            });
            var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
            Assert.True(DeltaSynchronizationPlanVerifier.Verify(plan, trust, Now()));
            using DeltaCapturedTableRowSource replay = DeltaCapturedTableRowSource.FromSignedPlan(
                archive, plan, trust, Now(), captureKey);
            var rows = new List<MigrationRow>();
            await foreach (MigrationRow row in replay.ReadOrderedAsync("Quotation", Table(), CancellationToken.None))
            {
                rows.Add(row);
            }
            Assert.Equal(1, Assert.Single(rows).Values["id"]);
            DeltaExecutionAuthorization authorization = DeltaExecutionAuthorizationProducer.Produce(plan,
                Now().AddMinutes(-1), Now().AddMinutes(5), authorizer);
            var authorizationTrust = new ReceiptAttestationTrustStore(
                [new(authorizer.KeyId, authorizer.ExportSubjectPublicKeyInfo())]);
            var gate = new SignedDeltaExecutionAuthorizationGate(authorization, authorizationTrust,
                new FixedTime(), plan.TargetAuthority!);
            await gate.ValidateAsync(plan, "Quotation", CancellationToken.None);

            int sourceSnapshotsBeforeReplay = source.Begun.Count;
            var applied = new List<string>();
            var exact23 = new Exact23DeltaExecutionCoordinator(source, _ => new DeltaExecutionCoordinator(
                new CapturingTarget(applied), new CapturedDeltaExecutionRowSessionProvider(replay, new EmptyTarget()),
                gate, new SignedCapturedSourceReconciliationInspector(plan, schema, trust, new FixedTime()),
                trust, new FixedTime()), capturedSourceReplay: true);
            Exact23DeltaExecutionResult execution = await exact23.ExecuteAsync(plan, schema, CancellationToken.None);
            Assert.Equal(DatabaseInventory.ActiveDatabases.Count, execution.Databases.Count);
            Assert.All(execution.Databases, result => Assert.Equal(1, result.AppliedOperations));
            Assert.Equal(DatabaseInventory.ActiveDatabases.Count, applied.Count);
            Assert.Equal(sourceSnapshotsBeforeReplay, source.Begun.Count);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static Exact23DeltaPlanRequest Request(FreshSchemaPlan schema)
    {
        return new(schema, Now().AddMinutes(-5), Hash('a'), Hash('b'), "local-aspire",
            "legacy-postgres-main-local", "generation-1", Hash('c'), Hash('d'), Hash('e'))
        {
            TargetAuthority = new(DeltaTargetAuthorityKind.LocalAspire,
                "aspire://legacy-postgres-main-local/disposable-capture-test", Hash('f')),
            SourceMode = DeltaSourceMode.LiveReadOnly,
            SourceObservationSha256 = Hash('9'),
        };
    }

    private static FreshSchemaPlan Schema()
    {
        return new("2.0", Now(), new string('1', 40), [.. DatabaseInventory.ActiveDatabases.Select(database =>
        {
            var draft = new DatabaseSchemaPlan(database, "1.0", Hash('a'), string.Empty, [Table()]);
            return draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        })]);
    }

    private static TableCopyPlan Table()
    {
        return new("dbo", "items", "public", "items", ["id"], ["id"])
        {
            SourceColumnTypes = new Dictionary<string, string> { ["id"] = "int" },
            ColumnTypes = new Dictionary<string, string> { ["id"] = "integer" },
            PrimaryKey = new PrimaryKeyCopyPlan("pk_items", ["id"]),
        };
    }

    private static MigrationRow Row(int id)
    {
        return new(new Dictionary<string, object?> { ["id"] = id });
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    private static DateTimeOffset Now()
    {
        return new(2026, 9, 26, 2, 0, 0, TimeSpan.Zero);
    }

    public void Dispose()
    {
        _key.Dispose();
    }

    private sealed class FixedTime : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return Now();
        }
    }

    private sealed class LiveSource : IReadOnlyMigrationSource
    {
        private readonly Dictionary<string, List<MigrationRow>> _rows = DatabaseInventory.ActiveDatabases
            .ToDictionary(database => database, _ => new List<MigrationRow> { Row(1) }, StringComparer.Ordinal);
        private readonly HashSet<string> _open = new(StringComparer.Ordinal);
        public List<string> Begun { get; } = [];
        public List<string> Completed { get; } = [];

        public int LiveRowCount(string database)
        {
            return _rows[database].Count;
        }

        public Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            Begun.Add(database);
            _ = _open.Add(database);
            return Task.CompletedTask;
        }

        public Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            Assert.True(_open.Remove(database));
            Completed.Add(database);
            _rows[database].Add(Row(2));
            return Task.CompletedTask;
        }

        public Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            _ = _open.Remove(database);
            return Task.CompletedTask;
        }

        public Task<SourceSchemaEvidence> InspectSchemaAsync(string database, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public async IAsyncEnumerable<MigrationRow> ReadTableAsync(string database, TableCopyPlan table,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            Assert.Contains(database, _open);
            foreach (MigrationRow row in _rows[database])
            {
                cancellationToken.ThrowIfCancellationRequested();
                await Task.Yield();
                yield return row;
            }
        }

        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyOrphansAsync(
            string database, TableCopyPlan table, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyRelationshipsAsync(
            string database, TableCopyPlan table, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyDictionary<string, long>> InspectSequenceNextValuesAsync(
            string database, DatabaseSchemaPlan plan, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class SourceEvidence : IDeltaReconciliationInspector
    {
        public Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema,
            CancellationToken cancellationToken)
        {
            using var collector = new TableEvidenceCollector(schema.Tables[0]);
            collector.Append(Row(1));
            return Task.FromResult(new DatabaseReconciliationEvidence(schema.Database,
                schema.SourceSchemaSha256, schema.TargetSchemaSha256, [collector.Finish()]));
        }
    }

    private sealed class EmptyTarget : IDeltaOrderedRowSource
    {
        public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(string database, TableCopyPlan table,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();
            yield break;
        }
    }

    private sealed class CapturingTarget(List<string> applied) : IDeltaCanonicalTarget
    {
        public Task<IDeltaCanonicalTransaction> BeginAsync(DeltaSynchronizationPlan plan,
            DatabaseSchemaPlan schema, string database, CancellationToken cancellationToken)
        {
            return Task.FromResult<IDeltaCanonicalTransaction>(new Transaction(database, applied));
        }

        private sealed class Transaction(string database, List<string> applied) : IDeltaCanonicalTransaction
        {
            public DeltaExecutionDisposition Disposition => DeltaExecutionDisposition.Pending;
            public string? ReconciliationSha256 { get; private set; }

            public Task ApplyAsync(TableCopyPlan table, CanonicalDeltaOperation operation,
                MigrationRow? source, MigrationRow? target, CancellationToken cancellationToken)
            {
                Assert.Equal(DeltaOperationKind.Insert, operation.Kind);
                Assert.Equal(1, source!.Values["id"]);
                Assert.Null(target);
                applied.Add(database);
                return Task.CompletedTask;
            }

            public Task<string> ReconcileAsync(DatabaseReconciliationEvidence expected,
                CancellationToken cancellationToken)
            {
                Assert.Equal(database, expected.Database);
                Assert.Equal(1, Assert.Single(expected.Tables).RowCount);
                ReconciliationSha256 = DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(expected);
                return Task.FromResult(ReconciliationSha256);
            }

            public Task CommitAsync(string planSha256, string reconciliationSha256,
                CancellationToken cancellationToken)
            {
                Assert.Equal(ReconciliationSha256, reconciliationSha256);
                return Task.CompletedTask;
            }

            public ValueTask DisposeAsync()
            {
                return ValueTask.CompletedTask;
            }
        }
    }
}
