using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ConsumerOverlaySelectionTests
{
    [Fact]
    public void HistoricalSelectionPreservesEveryDefaultProfileAndPhysicalFingerprint()
    {
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            DatabaseSchemaPlan old = Database(database, ConsumerOverlaySelection.HistoricalDefaults);
            Assert.Equal(ApprovedTargetExtensionManifest.ProfileForDatabase(database), old.TargetExtensionProfile);
            Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpected(old), old.TargetSchemaSha256);
            Assert.Equal(JsonSerializer.Serialize(old.Tables.Concat(ApprovedTargetExtensionManifest.TablesFor(old))),
                JsonSerializer.Serialize(ApprovedConsumerColumnOverlayManifest.ComposePhysical(old, mapSourceDispositions: false)));
        }
    }

    [Fact]
    public void CurrentSelectionChangesOnlyTwoSignedPhysicalProfilesAndNeverSourceProjection()
    {
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            DatabaseSchemaPlan old = Database(database, ConsumerOverlaySelection.HistoricalDefaults);
            DatabaseSchemaPlan current = Database(database, ConsumerOverlaySelection.CurrentConsumerColumnsV1);
            Assert.Equal(JsonSerializer.Serialize(old.Tables), JsonSerializer.Serialize(current.Tables));
            if (database is "CustomerIdentity" or "Quotation")
            {
                Assert.NotEqual(old.TargetExtensionProfile, current.TargetExtensionProfile);
                Assert.NotEqual(old.TargetSchemaSha256, current.TargetSchemaSha256);
            }
            else { Assert.Equal(JsonSerializer.Serialize(old), JsonSerializer.Serialize(current)); }
        }
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(2)]
    [InlineData(2147483647)]
    public void UnknownSelectionCannotMintAProfile(int selection)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedConsumerOverlaySelection.ProfileForDatabase(
            "CustomerIdentity", (ConsumerOverlaySelection)selection));
    }

    [Theory]
    [InlineData("CustomerIdentity")]
    [InlineData("Quotation")]
    [InlineData("Material")]
    public void PartialOrCrossDatabaseActivationIsRejected(string database)
    {
        FreshSchemaPlan schema = Schema(ConsumerOverlaySelection.HistoricalDefaults);
        schema = schema with
        {
            Databases = [.. schema.Databases.Select(item => item.Database == database
            ? item with { TargetExtensionProfile = ApprovedConsumerColumnOverlayManifest.CustomerV2 } : item)]
        };
        Assert.False(ApprovedConsumerOverlaySelection.IsApproved(schema));
    }

    [Theory]
    [InlineData("CustomerIdentity", "PasswordSetupRequired")]
    [InlineData("Quotation", "DecisionOrderVersion")]
    public void SourceColumnCannotBeReclassifiedAsConsumerOverlay(string database, string column)
    {
        DatabaseSchemaPlan schema = Database(database, ConsumerOverlaySelection.CurrentConsumerColumnsV1);
        TableCopyPlan root = schema.Tables[0];
        schema = schema with { Tables = [root with { OrderedColumns = [.. root.OrderedColumns, column] }] };
        _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlSchemaFingerprint.ComputeExpected(schema));
    }

    [Fact]
    public async Task ActiveReceiptRequiresExactSchemaBoundVerificationAndPreservesHistoricalVerifier()
    {
        FreshSchemaPlan schema = Schema(ConsumerOverlaySelection.CurrentConsumerColumnsV1);
        DeltaSynchronizationPlan plan = Plan(schema);
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("overlay-receipt", key.ExportECPrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        var inspector = new Inspector();
        var coordinator = new Exact23DeltaReconciliationCoordinator(inspector, inspector,
            new Checkpoints(plan, schema), new Clock(), signer);
        Exact23DeltaReconciliationResult receipt = await coordinator.ReconcileAsync(plan, schema, default);
        Assert.False(Exact23DeltaReconciliationCoordinator.Verify(receipt, trust));
        Assert.True(Exact23DeltaReconciliationCoordinator.Verify(receipt, plan, schema, trust));
        Assert.True(Exact23DeltaReconciliationCoordinator.VerifyForSchema(receipt, plan, schema, trust));
        FreshSchemaPlan old = Schema(ConsumerOverlaySelection.HistoricalDefaults);
        Assert.False(Exact23DeltaReconciliationCoordinator.Verify(receipt, plan, old, trust));
        Assert.False(Exact23DeltaReconciliationCoordinator.Verify(receipt with { AttestationSignature = null }, plan, schema, trust));

        foreach (string fault in new[] { "state", "physical", "source", "target", "operations", "tables" })
        {
            var changed = receipt with
            {
                Databases = [.. receipt.Databases.Select(database => database.Database != "Quotation" ? database : fault switch
                {
                    "state" => database with { TargetExtensionStateSha256 = null },
                    "physical" => database with { TargetSchemaSha256 = Hash('9') },
                    "source" => database with { SourceSchemaSha256 = Hash('9') },
                    "tables" => database with { Tables = [] },
                    _ => database,
                })],
                Checkpoints = [.. receipt.Checkpoints.Select(checkpoint => checkpoint.Database != "Quotation" ? checkpoint : fault switch
                {
                    "target" => checkpoint with { TargetObservationSha256 = Hash('9') },
                    "operations" => checkpoint with { OperationsSha256 = Hash('9') },
                    _ => checkpoint,
                })],
                AttestationSignature = null,
            };
            changed = changed with
            {
                AttestationSignature = Convert.ToBase64String(signer.Sign(
                Exact23DeltaReconciliationCoordinator.CreatePayload(changed)))
            };
            Assert.False(Exact23DeltaReconciliationCoordinator.Verify(changed, plan, schema, trust));
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task SchemaBoundSnapshotRejectsWrongHistoricalOrCurrentBindingsBeforeDump(int selection)
    {
        FreshSchemaPlan schema = Schema((ConsumerOverlaySelection)selection);
        DeltaSynchronizationPlan plan = Plan(schema);
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("snapshot-bound", key.ExportECPrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        var inspector = new Inspector();
        var coordinator = new Exact23DeltaReconciliationCoordinator(inspector, inspector,
            new Checkpoints(plan, schema), new Clock(), signer);
        Exact23DeltaReconciliationResult receipt = await coordinator.ReconcileAsync(plan, schema, default);
        Assert.True(Exact23DeltaReconciliationCoordinator.Verify(receipt, plan, schema, trust));
        string root = Path.Combine(Path.GetTempPath(), $"overlay-snapshot-{Guid.NewGuid():N}");
        byte[] encryptionKey = RandomNumberGenerator.GetBytes(32);
        var dumps = new SnapshotDumps();
        try
        {
            foreach (string fault in new[] { "plan", "schema", "default-schema" })
            {
                DeltaSynchronizationPlan suppliedPlan = fault == "plan" ? plan with { PlanId = Guid.NewGuid() } : plan;
                FreshSchemaPlan suppliedSchema = fault switch
                {
                    "schema" => schema with { SourceCommitSha = new string('2', 40) },
                    "default-schema" => new FreshSchemaPlan("2.0", Now, schema.SourceCommitSha, []),
                    _ => schema,
                };
                MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                    LocalSnapshotExporter.ExportCanonicalDeltaAsync(receipt, suppliedPlan, suppliedSchema, trust,
                        root, "bound-snapshot", encryptionKey, dumps, default));
                Assert.Equal("snapshot_terminal_receipt_invalid", failure.Code);
                Assert.Equal(0, dumps.Opened);
                Assert.False(Directory.Exists(root));
            }

            LocalSnapshotManifest bound = await LocalSnapshotExporter.ExportCanonicalDeltaAsync(receipt, plan, schema,
                trust, root, "bound-snapshot", encryptionKey, dumps, default);
            Assert.Equal(23, bound.Databases.Count);
            Assert.Equal(23, dumps.Opened);
            string legacyRoot = root + "-legacy";
            if (selection == 0)
            {
                LocalSnapshotManifest legacy = await LocalSnapshotExporter.ExportCanonicalDeltaAsync(receipt, trust,
                    legacyRoot, "legacy-snapshot", encryptionKey, dumps, default);
                Assert.Equal(23, legacy.Databases.Count);
                Assert.Equal(46, dumps.Opened);
            }
            else
            {
                var apply = new Console.DeltaApplyRuntimeRequest(schema, plan, null!, "source", "target", plan.TargetAuthority!, trust);
                var runtime = new Console.GuardedLocalDeltaFinalizationRuntime(null!, apply, null!, null!, trust,
                    root + "-routed", "routed-snapshot", encryptionKey, dumps, signer, new Clock());
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => runtime.ExportEncryptedSnapshotAsync(
                    plan with { PlanId = Guid.NewGuid() }, receipt, null!, default));
                Assert.False(Directory.Exists(root + "-routed"));
                Assert.Equal(23, dumps.Opened);
                LocalSnapshotManifest routed = await runtime.ExportEncryptedSnapshotAsync(plan, receipt, null!, default);
                Assert.Equal(23, routed.Databases.Count);
                Assert.Equal(46, dumps.Opened);
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                    LocalSnapshotExporter.ExportCanonicalDeltaAsync(receipt, trust, legacyRoot,
                        "legacy-snapshot", encryptionKey, dumps, default));
                Assert.False(Directory.Exists(legacyRoot));
                Assert.Equal(46, dumps.Opened);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encryptionKey);
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }

            if (Directory.Exists(root + "-legacy"))
            {
                Directory.Delete(root + "-legacy", recursive: true);
            }

            if (Directory.Exists(root + "-routed"))
            {
                Directory.Delete(root + "-routed", recursive: true);
            }
        }
    }

    private sealed class SnapshotDumps : IPostgreSqlDumpSource
    {
        internal int Opened { get; private set; }
        public Task<Stream> OpenDumpAsync(string database, string shadowDatabase, CancellationToken cancellationToken)
        {
            Opened++;
            return Task.FromResult<Stream>(new MemoryStream([1, 2, 3]));
        }
    }

    internal static FreshSchemaPlan Schema(ConsumerOverlaySelection selection)
    {
        return new("2.0", Now, new string('1', 40),
        [.. DatabaseInventory.ActiveDatabases.Select(database => Database(database, selection))]);
    }

    private static DatabaseSchemaPlan Database(string database, ConsumerOverlaySelection selection)
    {
        string table = database == "CustomerIdentity" ? "AspNetUsers" : database == "Quotation" ? "Quotation" : "items";
        string id = database == "CustomerIdentity" ? "Id" : "ID";
        var root = new TableCopyPlan("dbo", table, "public", table, [id, "Value"], [id])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            { [id] = database == "CustomerIdentity" ? "character varying(450)" : "integer", ["Value"] = "text" },
            PrimaryKey = new("PK_" + table, [id]),
        };
        var schema = new DatabaseSchemaPlan(database, "1.0", Hash('a'), Hash('b'), [root])
        { TargetExtensionProfile = ApprovedConsumerOverlaySelection.ProfileForDatabase(database, selection) };
        return schema with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(schema) };
    }

    private static DeltaSynchronizationPlan Plan(FreshSchemaPlan schema)
    {
        return new("1.0", Guid.NewGuid(), schema.SourceCommitSha,
        Now.AddMinutes(-1), Hash('a'), SchemaPlanCanonicalizer.ComputeSha256(schema), Hash('c'), "maliev-legacy",
        "legacy-postgres-main", "generation-test", Hash('d'), Hash('e'), Hash('f'), Now,
        [.. schema.Databases.Select(database => new DeltaDatabasePlan(database.Database,
            [new($"public.{database.Tables[0].TargetTable}", 0, 0, 0, 1,
                DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256([]), [])]))], "component-plan", null);
    }

    private static DatabaseReconciliationEvidence Evidence(DatabaseSchemaPlan schema)
    {
        return new(schema.Database,
        schema.SourceSchemaSha256, schema.TargetSchemaSha256,
        [new($"public.{schema.Tables[0].TargetTable}", 1, Hash('c'), Hash('d'), new Dictionary<string, long>(), new Dictionary<string, long>())])
        { TargetExtensionStateSha256 = ApprovedConsumerColumnOverlayManifest.HasState(schema) ? Hash('e') : null };
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    private static readonly DateTimeOffset Now = new(2026, 10, 3, 8, 0, 0, TimeSpan.Zero);
    private sealed class Clock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return Now;
        }
    }
    private sealed class Inspector : IDeltaReconciliationInspector
    {
        public Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema, CancellationToken cancellationToken)
        {
            return Task.FromResult(Evidence(schema));
        }
    }
    private sealed class Checkpoints(DeltaSynchronizationPlan plan, FreshSchemaPlan schema) : IExact23DeltaCheckpointReader
    {
        public Task<IReadOnlyList<DeltaDatabaseCheckpointEvidence>> ReadAsync(DeltaSynchronizationPlan requestedPlan,
            FreshSchemaPlan schemaPlan, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<DeltaDatabaseCheckpointEvidence>>(
            [.. schema.Databases.Select(database => new DeltaDatabaseCheckpointEvidence(database.Database, plan.PlanId,
                DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan), plan.SourceCutoffUtc, plan.TargetObservationSha256,
                DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(plan.Databases.Single(item => item.Database == database.Database)),
                DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(Evidence(database)), Now.AddSeconds(-1)))]);
        }
    }
}
