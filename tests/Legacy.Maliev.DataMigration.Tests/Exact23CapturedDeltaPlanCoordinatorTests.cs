using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class Exact23CapturedDeltaPlanCoordinatorTests(PostgreSqlAdapterFixture fixture) : IDisposable
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

    [Fact]
    public async Task Quotation_outboxes_capture_reviewed_targets_and_replay_exact_timestamp_ticks()
    {
        string directory = Path.Combine(Path.GetTempPath(), "legacy-quotation-capture-tests", Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(directory);
        try
        {
            FreshSchemaPlan schema = QuotationSchema();
            var source = new QuotationSource(schema);
            var archive = new DeltaCapturedTableArchive(directory);
            byte[] key = RandomNumberGenerator.GetBytes(32);
            using var signer = new P256MigrationEvidenceSigner("quotation-capture", _key.ExportECPrivateKeyPem());
            using var authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var authorizer = new P256MigrationEvidenceSigner("quotation-authorization",
                authorizationKey.ExportECPrivateKeyPem());
            var coordinator = new Exact23CapturedDeltaPlanCoordinator(source, new EmptyTarget(),
                new QuotationEvidence(source), archive, signer, new FixedTime());
            DeltaSynchronizationPlan plan = await coordinator.ProduceAsync(Request(schema) with
            {
                ExecutionAuthorizationKeyFingerprintSha256 = authorizer.PublicKeyFingerprintSha256,
            }, key, CancellationToken.None);

            DeltaDatabasePlan quotation = plan.Databases.Single(database => database.Database == "Quotation");
            Assert.Equal(["legacy_compatibility.GoogleAnalyticsOutbox", "public.QuotationAcceptedOutcome"],
                quotation.Tables.Select(table => table.Table));
            Assert.All(quotation.Tables, table => Assert.Equal(1, table.InsertCount));
            Assert.Equal(quotation.Tables.Select(table => table.Table),
                plan.SourceCaptureManifest!.Databases.Single(database => database.Database == "Quotation")
                    .Tables.Select(table => table.Table));
            var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
            QuotationDeltaExecutionPreflight.Validate(plan, schema);
            using DeltaCapturedTableRowSource replay = DeltaCapturedTableRowSource.FromSignedPlan(
                archive, plan, trust, Now(), key);
            DatabaseSchemaPlan target = new QuotationDeltaExecutionMapping(
                schema.Databases.Single(database => database.Database == "Quotation")).TargetSchema;
            var rows = new List<MigrationRow>();
            foreach (TableCopyPlan table in target.Tables)
            {
                await foreach (MigrationRow row in replay.ReadOrderedAsync("Quotation", table, CancellationToken.None))
                {
                    rows.Add(row);
                }
            }
            Assert.Equal(2, rows.Count);
            Assert.Contains(rows, row => row.Values.TryGetValue("AcceptedUtcSubMicrosecondTicks", out object? value) &&
                Equals(value, (short)7));
            Assert.Contains(rows, row => row.Values.TryGetValue("OccurredUtcSubMicrosecondTicks", out object? value) &&
                Equals(value, (short)7));
            var provider = new CapturedDeltaExecutionRowSessionProvider(replay, new EmptyTarget());
            foreach (TableCopyPlan table in target.Tables)
            {
                DeltaTablePlan signedTable = quotation.Tables.Single(item =>
                    item.Table == $"{table.TargetSchema}.{table.TargetTable}");
                for (int attempt = 0; attempt < 2; attempt++)
                {
                    await using IDeltaExecutionRowSession session = await provider.OpenAsync(
                        "Quotation", table, CancellationToken.None);
                    var resolved = new List<ResolvedDeltaRow>();
                    await foreach (ResolvedDeltaRow row in session.ResolveAsync(signedTable, CancellationToken.None))
                    {
                        resolved.Add(row);
                    }
                    Assert.Equal(DeltaOperationKind.Insert, Assert.Single(resolved).Operation.Kind);
                    Assert.NotNull(resolved[0].Source);
                }
                var conflicting = new CapturedDeltaExecutionRowSessionProvider(replay,
                    new SingleTarget(rows[target.Tables.ToList().IndexOf(table)]));
                await using IDeltaExecutionRowSession mismatchSession = await conflicting.OpenAsync(
                    "Quotation", table, CancellationToken.None);
                DeltaExecutionException mismatch = await Assert.ThrowsAsync<DeltaExecutionException>(async () =>
                {
                    await foreach (ResolvedDeltaRow _ in mismatchSession.ResolveAsync(signedTable, CancellationToken.None))
                    {
                    }
                });
                Assert.Equal("delta_capture_target_drift", mismatch.Code);
            }
            _ = await Assert.ThrowsAsync<DeltaPlanException>(async () =>
            {
                await foreach (MigrationRow _ in replay.ReadOrderedAsync("Quotation",
                    schema.Databases.Single(database => database.Database == "Quotation").Tables[0], CancellationToken.None))
                {
                }
            });
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Captured_quotation_replay_commits_and_is_idempotent_on_disposable_postgres()
    {
        const string database = "Quotation";
        string directory = Path.Combine(Path.GetTempPath(), "legacy-quotation-postgres-tests", Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(directory);
        await using var administrative = new NpgsqlConnection(fixture.ConnectionString);
        await administrative.OpenAsync();
        await using (var create = new NpgsqlCommand("CREATE DATABASE \"Quotation\" TEMPLATE template0;", administrative))
        {
            _ = await create.ExecuteNonQueryAsync();
        }
        try
        {
            FreshSchemaPlan schemaPlan = QuotationSchema();
            DatabaseSchemaPlan sourceSchema = schemaPlan.Databases.Single(item => item.Database == database);
            DatabaseSchemaPlan targetSchema = new QuotationDeltaExecutionMapping(sourceSchema).TargetSchema;
            string connectionString = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
            {
                Database = database,
                Pooling = false,
            }.ConnectionString;
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync();
                await using var writer = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                await writer.ApplySchemaAsync(targetSchema, CancellationToken.None);
                await writer.FinalizeSchemaAsync(targetSchema, CancellationToken.None);
                await transaction.CommitAsync();
            }
            var source = new QuotationSource(schemaPlan);
            var archive = new DeltaCapturedTableArchive(directory);
            byte[] key = RandomNumberGenerator.GetBytes(32);
            using var signer = new P256MigrationEvidenceSigner("quotation-postgres-capture", _key.ExportECPrivateKeyPem());
            using var authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var authorizer = new P256MigrationEvidenceSigner("quotation-postgres-authorization",
                authorizationKey.ExportECPrivateKeyPem());
            var planner = new Exact23CapturedDeltaPlanCoordinator(source, new EmptyTarget(),
                new QuotationEvidence(source), archive, signer, new FixedTime());
            DeltaSynchronizationPlan plan = await planner.ProduceAsync(Request(schemaPlan) with
            {
                ExecutionAuthorizationKeyFingerprintSha256 = authorizer.PublicKeyFingerprintSha256,
            }, key, CancellationToken.None);
            var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync();
                await PostgreSqlDeltaMetadataProvisioner.ProvisionDatabaseAsync(connection, transaction,
                    plan, sourceSchema, CancellationToken.None);
                await transaction.CommitAsync();
            }
            using DeltaCapturedTableRowSource replay = DeltaCapturedTableRowSource.FromSignedPlan(
                archive, plan, trust, Now(), key);
            var targetRows = new PostgreSqlDeltaRowSource(new(fixture.ConnectionString));
            var coordinator = new DeltaExecutionCoordinator(
                new PostgreSqlDeltaCanonicalTarget(new(connectionString, database, plan.TargetGeneration)),
                new CapturedDeltaExecutionRowSessionProvider(replay, targetRows),
                new AllowAuthorization(),
                new SignedCapturedSourceReconciliationInspector(plan, schemaPlan, trust, new FixedTime()),
                trust, new FixedTime());
            DeltaDatabaseExecutionResult applied = await coordinator.ExecuteDatabaseAsync(
                plan, sourceSchema, database, CancellationToken.None);
            Assert.Equal(DeltaExecutionDisposition.Committed, applied.Disposition);
            Assert.Equal(2, applied.AppliedOperations);
            DeltaDatabaseExecutionResult again = await coordinator.ExecuteDatabaseAsync(
                plan, sourceSchema, database, CancellationToken.None);
            Assert.Equal(DeltaExecutionDisposition.AlreadyCommitted, again.Disposition);
            Assert.Equal(0, again.AppliedOperations);
            DatabaseReconciliationEvidence actual = await new PostgreSqlDeltaReconciliationInspector(
                new(fixture.ConnectionString)).InspectAsync(sourceSchema, CancellationToken.None);
            DatabaseReconciliationEvidence expected = await new QuotationEvidence(source).InspectAsync(
                sourceSchema, CancellationToken.None);
            Assert.Equal(DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(expected),
                DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(actual));
        }
        finally
        {
            await using var drop = new NpgsqlCommand("DROP DATABASE IF EXISTS \"Quotation\" WITH (FORCE);", administrative);
            _ = await drop.ExecuteNonQueryAsync();
            Directory.Delete(directory, recursive: true);
        }
    }

    [Theory]
    [InlineData(true, false, "delta_capture_key_order_invalid")]
    [InlineData(false, true, "delta_capture_source_evidence_mismatch")]
    public async Task Captured_quotation_rejects_duplicate_or_missing_source_evidence(
        bool duplicateOutcome, bool omitOutcomeEvidence, string expectedCode)
    {
        string directory = Path.Combine(Path.GetTempPath(), "legacy-quotation-negative-tests", Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(directory);
        try
        {
            FreshSchemaPlan schema = QuotationSchema();
            var source = new QuotationSource(schema, duplicateOutcome);
            byte[] key = RandomNumberGenerator.GetBytes(32);
            using var signer = new P256MigrationEvidenceSigner("quotation-negative", _key.ExportECPrivateKeyPem());
            using var authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var authorizer = new P256MigrationEvidenceSigner("quotation-negative-authorization",
                authorizationKey.ExportECPrivateKeyPem());
            var coordinator = new Exact23CapturedDeltaPlanCoordinator(source, new EmptyTarget(),
                new QuotationEvidence(source, omitOutcomeEvidence),
                new DeltaCapturedTableArchive(directory), signer, new FixedTime());
            Exception failure = await Assert.ThrowsAnyAsync<Exception>(() => coordinator.ProduceAsync(
                Request(schema) with
                {
                    ExecutionAuthorizationKeyFingerprintSha256 = authorizer.PublicKeyFingerprintSha256,
                }, key, CancellationToken.None));
            Assert.Equal(expectedCode, failure switch
            {
                DeltaPlanningException planning => planning.Code,
                DeltaPlanException plan => plan.Code,
                _ => throw failure,
            });
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static FreshSchemaPlan QuotationSchema()
    {
        TableCopyPlan[] outboxes =
        [
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
        ];
        return new("2.0", Now(), new string('1', 40), [.. DatabaseInventory.ActiveDatabases.Select(database =>
        {
            var draft = new DatabaseSchemaPlan(database, "1.0", Hash('a'), string.Empty,
                database == "Quotation" ? outboxes : [Table()])
            {
                SourceDispositionProfile = database == "Quotation"
                    ? ApprovedSourceDispositionManifest.QuotationOutboxesV1 : null,
                SourceTableDispositions = database == "Quotation"
                    ? ApprovedSourceDispositionManifest.DispositionsForDatabase(database, outboxes) : [],
            };
            return draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        })]);
    }

    private sealed class QuotationSource(FreshSchemaPlan plan, bool duplicateOutcome = false) : IReadOnlyMigrationSource
    {
        private readonly Dictionary<(string, string), MigrationRow[]> _rows = plan.Databases
            .SelectMany(database => database.Tables.Select(table =>
                (Key: (database.Database, $"{table.TargetSchema}.{table.TargetTable}"),
                    Rows: RowsFor(database.Database, table, duplicateOutcome))))
            .ToDictionary(item => item.Key, item => item.Rows);

        private static MigrationRow[] RowsFor(string database, TableCopyPlan table, bool duplicateOutcome)
        {
            return database == "Quotation" && duplicateOutcome && table.SourceTable == "QuotationOutcomeOutbox"
                ? [QuotationRow(table), QuotationRow(table)]
                : [database == "Quotation" ? QuotationRow(table) : Row(1)];
        }

        public MigrationRow[] Get(string database, TableCopyPlan table)
        {
            return _rows[(database, $"{table.TargetSchema}.{table.TargetTable}")];
        }

        public Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task<SourceSchemaEvidence> InspectSchemaAsync(string database, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public async IAsyncEnumerable<MigrationRow> ReadTableAsync(string database, TableCopyPlan table,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();
            foreach (MigrationRow row in Get(database, table))
            {
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

        private static MigrationRow QuotationRow(TableCopyPlan table)
        {
            DateTime at = new DateTime(2026, 9, 26, 12, 34, 56, DateTimeKind.Unspecified).AddTicks(1234567);
            return table.SourceTable == "QuotationOutcomeOutbox"
                ? new(new Dictionary<string, object?>
                {
                    ["ID"] = 30L,
                    ["EventKey"] = "synthetic-accepted-30",
                    ["QuotationID"] = 41,
                    ["SourceRequestID"] = null,
                    ["SourceJourneyID"] = null,
                    ["AcceptedUtc"] = at,
                    ["AcceptanceOrigin"] = "customer",
                })
                : new(new Dictionary<string, object?>
                {
                    ["ID"] = 17L,
                    ["QuotationID"] = 41,
                    ["EventKey"] = "synthetic-event-17",
                    ["EventName"] = "quote_accepted",
                    ["ClientId"] = "synthetic-client",
                    ["SessionId"] = "synthetic-session",
                    ["UserId"] = null,
                    ["Currency"] = "THB",
                    ["Value"] = 123.45m,
                    ["OccurredUtc"] = at,
                    ["AttemptCount"] = 1,
                    ["NextAttemptUtc"] = at,
                    ["LeaseToken"] = null,
                    ["LeaseUntilUtc"] = null,
                    ["SentUtc"] = null,
                    ["FailedUtc"] = null,
                    ["LastError"] = null,
                    ["SourceRequestID"] = null,
                    ["SourceJourneyID"] = null,
                });
        }
    }

    private sealed class QuotationEvidence(QuotationSource source, bool omitOutcomeEvidence = false)
        : IDeltaReconciliationInspector
    {
        public Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema,
            CancellationToken cancellationToken)
        {
            var mapping = new QuotationDeltaExecutionMapping(schema);
            TableReconciliationEvidence[] tables = [.. mapping.TargetSchema.Tables
                .Where(target => !omitOutcomeEvidence || schema.Database != "Quotation" ||
                    target.TargetTable != "QuotationAcceptedOutcome").Select(target =>
            {
                using var collector = new TableEvidenceCollector(target);
                foreach (MigrationRow row in source.Get(schema.Database, mapping.SourceTableFor(target)))
                {
                    collector.Append(mapping.MapRow(target, row));
                }
                return collector.Finish();
            })];
            return Task.FromResult(new DatabaseReconciliationEvidence(schema.Database,
                schema.SourceSchemaSha256, schema.TargetSchemaSha256, tables)
            {
                SequenceNextValues = schema.Database == "Quotation"
                    ? mapping.MapSequences(new Dictionary<string, long>(StringComparer.Ordinal)
                    {
                        ["public.GoogleAnalyticsOutbox.ID"] = 18,
                        ["public.QuotationOutcomeOutbox.ID"] = 31,
                    })
                    : new Dictionary<string, long>(StringComparer.Ordinal),
            });
        }
    }

    private sealed class AllowAuthorization : IDeltaExecutionAuthorizationGate
    {
        public Task ValidateAsync(DeltaSynchronizationPlan plan, string database, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class SingleTarget(MigrationRow row) : IDeltaOrderedRowSource
    {
        public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(string database, TableCopyPlan table,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();
            yield return row;
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
