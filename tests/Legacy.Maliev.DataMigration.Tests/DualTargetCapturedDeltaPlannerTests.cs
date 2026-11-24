using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DualTargetCapturedDeltaPlannerTests
{
    [Fact]
    public async Task One_SQL_capture_supports_different_target_deltas_and_separate_operation_proofs()
    {
        string directory = Path.Combine(Path.GetTempPath(), "legacy-common-capture-tests", Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(directory);
        var keys = Enumerable.Range(0, 9).Select(_ => ECDsa.Create(ECCurve.NamedCurves.nistP256)).ToArray();
        var signers = keys.Select((key, i) => new P256MigrationEvidenceSigner("common-capture-" + i, key.ExportECPrivateKeyPem())).ToArray();
        try
        {
            FreshSchemaPlan schema = Schema();
            var source = new LiveSource();
            var destinations = new List<DualTargetCapturedDeltaDestination>();
            foreach (DualTargetCapturedDeltaPurpose purpose in Enum.GetValues<DualTargetCapturedDeltaPurpose>())
            {
                bool production = purpose == DualTargetCapturedDeltaPurpose.Production;
                bool persistent = purpose == DualTargetCapturedDeltaPurpose.PersistentLocal;
                string id = production ? "gke://maliev-website/common-capture-test" :
                    "aspire://legacy-postgres-main-local/" + (persistent ? "persistent-" : "disposable-") + purpose;
                var request = new Exact23DeltaPlanRequest(schema, Now().AddMinutes(-5), Hash('a'), Hash('b'),
                    production ? "maliev-legacy" : "local-aspire", production ? "legacy-postgres-main" : "legacy-postgres-main-local",
                    "generation-" + purpose, Hash((char)('c' + (int)purpose)), Hash('8'), Hash('9'))
                {
                    TargetAuthority = new(production ? DeltaTargetAuthorityKind.ProductionCloudNativePg : DeltaTargetAuthorityKind.LocalAspire,
                        id, Hash((char)('1' + (int)purpose))),
                    SourceMode = DeltaSourceMode.LiveReadOnly,
                    SourceObservationSha256 = Hash('7')
                };
                string[] inventory = purpose is DualTargetCapturedDeltaPurpose.Production or DualTargetCapturedDeltaPurpose.ProductionProof ?
                    [.. ReviewedProductionRepairInventory.ExportProductionNames()] : [.. DatabaseInventory.ActiveDatabases, "Auth", "postgres", "legacy_local"];
                var observed = new DualTargetCapturedTargetObservation(Hash('6'), request.TargetAuthority!, request.TargetGeneration,
                    new("synthetic_maintenance", "synthetic-only", Now().AddMinutes(-1), Now().AddHours(1), Now().AddDays(-1), Now().AddHours(-1), Hash('a'), Hash('b'), "synthetic_hba"),
                    inventory.ToDictionary(x => x, _ => Hash('5'), StringComparer.Ordinal));
                request = request with { TargetObservationSha256 = observed.Sha256 };
                destinations.Add(new(purpose, request, new EmptyTarget(containsSourceRow: persistent || purpose == DualTargetCapturedDeltaPurpose.LocalProof), signers[(int)purpose],
                    new(signers[5 + (int)purpose].KeyId, signers[5 + (int)purpose].ExportSubjectPublicKeyInfo()), observed));
            }
            var planner = new DualTargetCapturedDeltaPlanner(source, new SourceEvidence(), new DeltaCapturedTableArchive(directory), new FixedTime());
            byte[] captureKey = RandomNumberGenerator.GetBytes(32);
            DualTargetCapturedDeltaBundle bundle = await planner.ProduceAsync(destinations, captureKey, signers[4], CancellationToken.None);
            await DualTargetCapturedDeltaPlanner.VerifyFullArchivesAsync(bundle, schema, new DeltaCapturedTableArchive(directory), captureKey, CancellationToken.None);
            Assert.Equal(23, source.Begun.Count);
            Assert.All(DatabaseInventory.ActiveDatabases, database => Assert.Equal(2, source.LiveRowCount(database)));
            var trust = new ReceiptAttestationTrustStore(signers.Select(x => new TrustedAttestationKey(x.KeyId, x.ExportSubjectPublicKeyInfo())));
            DualTargetCapturedDeltaContract.Verify(bundle, schema, trust, Now());
            Assert.All(bundle.Plans, member => Assert.Equal("1.3", member.Plan.SchemaVersion));
            Assert.All(bundle.Plans.Single(x => x.Purpose == DualTargetCapturedDeltaPurpose.Production).Plan.Databases,
                database => Assert.Equal(1, Assert.Single(database.Tables).InsertCount));
            Assert.All(bundle.Plans.Single(x => x.Purpose == DualTargetCapturedDeltaPurpose.PersistentLocal).Plan.Databases,
                database => Assert.Equal(0, Assert.Single(database.Tables).InsertCount));
            Assert.Equal(4, bundle.Plans.Select(x => x.Plan.SourceCaptureManifest!.Databases[0].Tables[0].CaptureId).Distinct().Count());
            var changedNative = bundle with
            {
                Plans = [.. bundle.Plans.Select((x, i) => i == 0 ? x with
                { Observation = x.Observation with { NativeBeforeSha256 = x.Observation.NativeBeforeSha256.ToDictionary(p => p.Key, _ => Hash('4'), StringComparer.Ordinal) } } : x)]
            };
            Assert.Equal(bundle.Plans[0].Observation.Sha256, changedNative.Plans[0].Observation.Sha256);
            Assert.NotEqual(DualTargetCapturedDeltaContract.Hash(bundle), DualTargetCapturedDeltaContract.Hash(changedNative));
            var changed = bundle with
            {
                Databases = [.. bundle.Databases.Select((x, i) => i == 0 ? x with
                { FullTables = [.. x.FullTables.Select(t => t with { RowCount = t.RowCount + 1 })] } : x)]
            };
            changed = changed with { AttestationSignature = Convert.ToBase64String(signers[4].Sign(DualTargetCapturedDeltaContract.Payload(changed))) };
            _ = Assert.Throws<DeltaExecutionException>(() => DualTargetCapturedDeltaContract.Verify(changed, schema, trust, Now()));
        }
        finally
        {
            foreach (P256MigrationEvidenceSigner signer in signers) { signer.Dispose(); }
            foreach (ECDsa key in keys) { key.Dispose(); }
            Directory.Delete(directory, recursive: true);
        }
    }
    private static DateTimeOffset Now()
    {
        return new(2026, 11, 24, 0, 0, 0, TimeSpan.Zero);
    }

    private sealed class FixedTime : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return Now();
        }
    }
    private static string Hash(char c)
    {
        return new(c, 64);
    }

    private static MigrationRow Row(int id)
    {
        return new(new Dictionary<string, object?> { ["id"] = id });
    }

    private static TableCopyPlan Table()
    {
        return new("dbo", "items", "public", "items", ["id"], ["id"])
        {
            SourceColumnTypes = new Dictionary<string, string> { ["id"] = "int" },
            ColumnTypes = new Dictionary<string, string> { ["id"] = "integer" },
            PrimaryKey = new("pk_items", ["id"])
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

    private sealed class LiveSource : IReadOnlyMigrationSource
    {
        private readonly Dictionary<string, List<MigrationRow>> _rows = DatabaseInventory.ActiveDatabases
            .ToDictionary(database => database, _ => new List<MigrationRow> { Row(1) }, StringComparer.Ordinal);
        private readonly HashSet<string> _open = new(StringComparer.Ordinal);
        public List<string> Begun { get; } = [];
        public List<string> Completed { get; } = [];
        public List<string> RolledBack { get; } = [];

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
            RolledBack.Add(database);
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

    private sealed class EmptyTarget(bool containsSourceRow = false, bool containsExtraRow = false)
        : IDeltaDatabaseSnapshotRowSource
    {
        private string? _database;

        public Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            Assert.Null(_database);
            _database = database;
            return Task.CompletedTask;
        }

        public Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            Assert.Equal(database, _database);
            _database = null;
            return Task.CompletedTask;
        }

        public Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            Assert.Equal(database, _database);
            _database = null;
            return Task.CompletedTask;
        }

        public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(string database, TableCopyPlan table,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();
            if (containsSourceRow)
            {
                yield return Row(1);
            }
            if (containsExtraRow)
            {
                yield return Row(2);
            }
        }
    }

}
