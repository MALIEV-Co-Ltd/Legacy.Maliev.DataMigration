using System.Security.Cryptography;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class QuotationDeltaExecutionIntegrationTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task Source_reconciliation_uses_mapped_content_and_target_identity_names()
    {
        DatabaseSchemaPlan schema = Schema();
        var binding = new QuotationDeltaExecutionMapping(schema);
        MigrationRow analytics = AnalyticsRow();
        MigrationRow outcome = OutcomeRow();
        var source = new QuotationSource(schema.SourceSchemaSha256, analytics, outcome);
        var inspector = new SqlServerDeltaReconciliationInspector(source);

        DatabaseReconciliationEvidence observed = await inspector.InspectAsync(schema, CancellationToken.None);
        DatabaseReconciliationEvidence expected = Evidence(schema, binding.TargetSchema,
            binding.MapRow(binding.TargetSchema.Tables[0], analytics),
            binding.MapRow(binding.TargetSchema.Tables[1], outcome));

        Assert.Equal(DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(expected),
            DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(observed));
        Assert.Equal(["dbo.GoogleAnalyticsOutbox", "dbo.QuotationOutcomeOutbox"], source.ReadTables);
        Assert.Equal(["legacy_compatibility.GoogleAnalyticsOutbox.ID", "public.QuotationAcceptedOutcome.ID"],
            observed.SequenceNextValues.Keys.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Preflight_rejects_unbound_target_inventory_and_accepts_captured_mapping()
    {
        DateTimeOffset now = new(2026, 9, 26, 8, 0, 0, TimeSpan.Zero);
        DatabaseSchemaPlan schema = Schema();
        FreshSchemaPlan all = Exact23Schema(schema, now);
        var binding = new QuotationDeltaExecutionMapping(schema);
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("quotation-preflight-test", key.ExportECPrivateKeyPem());
        DeltaSynchronizationPlan plan = Plan(all, binding.TargetSchema,
            binding.MapRow(binding.TargetSchema.Tables[0], AnalyticsRow()),
            binding.MapRow(binding.TargetSchema.Tables[1], OutcomeRow()), signer, now);

        QuotationDeltaExecutionPreflight.Validate(plan, all);
        QuotationDeltaExecutionPreflight.Validate(plan with { SchemaVersion = "1.3" }, all);
        DeltaSynchronizationPlan wrongTable = plan with
        {
            Databases = plan.Databases.Select(database => database.Database == "Quotation"
                ? database with { Tables = [database.Tables[0], database.Tables[1] with { Table = "public.QuotationOutcomeOutbox" }] }
                : database).ToArray(),
        };
        Assert.Equal("delta_execution_table_inventory_invalid",
            Assert.Throws<DeltaExecutionException>(() => QuotationDeltaExecutionPreflight.Validate(wrongTable, all)).Code);
        FreshSchemaPlan unbound = all with
        {
            Databases = all.Databases.Select(database => database.Database == "Quotation"
                ? database with { SourceDispositionProfile = null, SourceTableDispositions = [] }
                : database).ToArray(),
        };
        Assert.Equal("delta_execution_quotation_transformation_required",
            Assert.Throws<DeltaExecutionException>(() => QuotationDeltaExecutionPreflight.Validate(plan, unbound)).Code);
    }

    [Fact]
    public async Task Exact23_final_reconciliation_accepts_only_mapped_quotation_target_evidence()
    {
        DateTimeOffset now = new(2026, 9, 26, 8, 0, 0, TimeSpan.Zero);
        DatabaseSchemaPlan quotation = Schema();
        FreshSchemaPlan all = Exact23Schema(quotation, now);
        var binding = new QuotationDeltaExecutionMapping(quotation);
        MigrationRow mappedAnalytics = binding.MapRow(binding.TargetSchema.Tables[0], AnalyticsRow());
        MigrationRow mappedOutcome = binding.MapRow(binding.TargetSchema.Tables[1], OutcomeRow());
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("quotation-final-reconciliation-test", key.ExportECPrivateKeyPem());
        DeltaSynchronizationPlan plan = Plan(all, binding.TargetSchema, mappedAnalytics, mappedOutcome, signer, now);
        DatabaseReconciliationEvidence Inspect(DatabaseSchemaPlan schema)
        {
            return schema.Database == "Quotation"
                ? Evidence(schema, binding.TargetSchema, mappedAnalytics, mappedOutcome)
                : DummyEvidence(schema);
        }
        var inspector = new SchemaEvidence(Inspect);
        var coordinator = new Exact23DeltaReconciliationCoordinator(inspector, inspector,
            new MatchingCheckpoints(Inspect, now), new FixedTime(now), signer, checkpointBound: true);

        Exact23DeltaReconciliationResult result = await coordinator.ReconcileAsync(plan, all, CancellationToken.None);
        Assert.Equal(["legacy_compatibility.GoogleAnalyticsOutbox", "public.QuotationAcceptedOutcome"],
            result.Databases.Single(database => database.Database == "Quotation").Tables.Select(table => table.Table));
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        Assert.True(Exact23DeltaReconciliationCoordinator.Verify(result, trust));

        var sourceNamed = new SchemaEvidence(schema => schema.Database == "Quotation"
            ? Inspect(schema) with
            {
                Tables = [Inspect(schema).Tables[0] with { Table = "public.GoogleAnalyticsOutbox" }, Inspect(schema).Tables[1]],
            }
            : Inspect(schema));
        var rejected = new Exact23DeltaReconciliationCoordinator(inspector, sourceNamed,
            new MatchingCheckpoints(Inspect, now), new FixedTime(now), signer, checkpointBound: true);
        Assert.Equal("delta_reconciliation_shape_invalid", (await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            rejected.ReconcileAsync(plan, all, CancellationToken.None))).Code);
    }

    [Fact]
    public async Task Reviewed_outboxes_rollback_on_source_drift_then_commit_and_replay_atomically()
    {
        const string database = "Quotation";
        await using var administrative = new NpgsqlConnection(fixture.ConnectionString);
        await administrative.OpenAsync();
        await ExecuteAsync(administrative, "CREATE DATABASE \"Quotation\" TEMPLATE template0;");
        try
        {
            string connectionString = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
            {
                Database = database,
                Pooling = false,
            }.ConnectionString;
            DatabaseSchemaPlan sourceSchema = Schema();
            var binding = new QuotationDeltaExecutionMapping(sourceSchema);
            MigrationRow analytics = AnalyticsRow();
            MigrationRow outcome = OutcomeRow();
            MigrationRow mappedAnalytics = binding.MapRow(binding.TargetSchema.Tables[0], analytics);
            MigrationRow mappedOutcome = binding.MapRow(binding.TargetSchema.Tables[1], outcome);
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync();
                await using var schemaWriter = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                await schemaWriter.ApplySchemaAsync(binding.TargetSchema, CancellationToken.None);
                await schemaWriter.FinalizeSchemaAsync(binding.TargetSchema, CancellationToken.None);
                Assert.Equal(sourceSchema.TargetSchemaSha256,
                    await schemaWriter.InspectSchemaAsync(binding.TargetSchema, CancellationToken.None));
                await transaction.CommitAsync();
            }

            DateTimeOffset now = new(2026, 9, 26, 8, 0, 0, TimeSpan.Zero);
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var signer = new P256MigrationEvidenceSigner("quotation-delta-test", key.ExportECPrivateKeyPem());
            FreshSchemaPlan schemaPlan = Exact23Schema(sourceSchema, now);
            DeltaSynchronizationPlan plan = Plan(schemaPlan, binding.TargetSchema, mappedAnalytics, mappedOutcome,
                signer, now);
            var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
            Assert.True(DeltaSynchronizationPlanVerifier.Verify(plan, trust, now));
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync();
                await PostgreSqlDeltaMetadataProvisioner.ProvisionDatabaseAsync(connection, transaction, plan,
                    sourceSchema, CancellationToken.None);
                await transaction.CommitAsync();
            }

            var rows = new QuotationRows(analytics, outcome);
            var mappedSource = new QuotationMappedDeltaRowSource(rows, schemaPlan);
            var targetRows = new PostgreSqlDeltaRowSource(new(fixture.ConnectionString));
            var expected = new StaticEvidence(Evidence(sourceSchema, binding.TargetSchema,
                mappedAnalytics, mappedOutcome));
            var coordinator = new DeltaExecutionCoordinator(
                new PostgreSqlDeltaCanonicalTarget(new(connectionString, database, plan.TargetGeneration)),
                new OrderedDeltaExecutionRowSessionProvider(mappedSource, targetRows),
                new AllowAuthorization(), expected, trust, new FixedTime(now));

            rows.Outcome = outcome with
            {
                Values = new Dictionary<string, object?>(outcome.Values, StringComparer.Ordinal)
                {
                    ["EventKey"] = "drifted-event",
                },
            };
            _ = await Assert.ThrowsAnyAsync<Exception>(() => coordinator.ExecuteDatabaseAsync(
                plan, sourceSchema, database, CancellationToken.None));
            Assert.Equal(0L, await ScalarAsync(connectionString,
                "SELECT count(*) FROM legacy_migration_internal.delta_journal;"));
            Assert.Equal(0L, await ScalarAsync(connectionString,
                "SELECT count(*) FROM public.\"QuotationAcceptedOutcome\";"));
            Assert.Equal(0L, await ScalarAsync(connectionString,
                "SELECT count(*) FROM legacy_compatibility.\"GoogleAnalyticsOutbox\";"));

            rows.Outcome = outcome;
            DeltaDatabaseExecutionResult applied = await coordinator.ExecuteDatabaseAsync(
                plan, sourceSchema, database, CancellationToken.None);
            Assert.Equal(DeltaExecutionDisposition.Committed, applied.Disposition);
            Assert.Equal(2, applied.AppliedOperations);
            Assert.Equal(1L, await ScalarAsync(connectionString,
                "SELECT count(*) FROM legacy_migration_internal.delta_journal;"));
            Assert.Equal(1L, await ScalarAsync(connectionString,
                "SELECT count(*) FROM public.\"QuotationAcceptedOutcome\";"));
            Assert.Equal(1L, await ScalarAsync(connectionString,
                "SELECT count(*) FROM legacy_compatibility.\"GoogleAnalyticsOutbox\";"));
            DatabaseReconciliationEvidence inspected = await new PostgreSqlDeltaReconciliationInspector(
                new(fixture.ConnectionString)).InspectAsync(sourceSchema, CancellationToken.None);
            Assert.Equal(DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(
                Evidence(sourceSchema, binding.TargetSchema, mappedAnalytics, mappedOutcome)),
                DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(inspected));
            var archiveRows = new List<MigrationRow>();
            await foreach (MigrationRow row in targetRows.ReadOrderedAsync(database,
                binding.TargetSchema.Tables[0], CancellationToken.None))
            {
                archiveRows.Add(row);
            }
            Assert.Equal((short)7, Assert.Single(archiveRows).Values["OccurredUtcSubMicrosecondTicks"]);
            Assert.Equal((short)8, archiveRows[0].Values["NextAttemptUtcSubMicrosecondTicks"]);

            DeltaDatabaseExecutionResult replay = await coordinator.ExecuteDatabaseAsync(
                plan, sourceSchema, database, CancellationToken.None);
            Assert.Equal(DeltaExecutionDisposition.AlreadyCommitted, replay.Disposition);
            Assert.Equal(0, replay.AppliedOperations);
            Assert.Equal(applied.ReconciliationSha256, replay.ReconciliationSha256);
        }
        finally
        {
            await ExecuteAsync(administrative, "DROP DATABASE IF EXISTS \"Quotation\" WITH (FORCE);");
        }
    }

    private static DatabaseSchemaPlan Schema()
    {
        TableCopyPlan[] tables =
        [
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
        ];
        var draft = new DatabaseSchemaPlan("Quotation", "1.0", Hash('a'), string.Empty, tables)
        {
            SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
            SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables),
        };
        return draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
    }

    private static FreshSchemaPlan Exact23Schema(DatabaseSchemaPlan quotation, DateTimeOffset now)
    {
        return new("2.0", now, new string('1', 40),
            [.. DatabaseInventory.ActiveDatabases.Select(database => database == "Quotation" ? quotation :
                new DatabaseSchemaPlan(database, "1.0", Hash('a'), Hash('b'),
                    [new TableCopyPlan("dbo", "items", "public", "items", ["id"], ["id"])])
                {
                    TargetExtensionProfile = ApprovedTargetExtensionManifest.ProfileForDatabase(database),
                })]);
    }

    private static DeltaSynchronizationPlan Plan(
        FreshSchemaPlan schemaPlan, DatabaseSchemaPlan targetSchema, MigrationRow analytics,
        MigrationRow outcome, P256MigrationEvidenceSigner signer, DateTimeOffset now)
    {
        IReadOnlyList<DeltaDatabasePlan> databases = [.. DatabaseInventory.ActiveDatabases.Select(database =>
        {
            return database != "Quotation"
                ? new DeltaDatabasePlan(database, [TablePlan("public.items", [])])
                : new DeltaDatabasePlan(database,
            [
                TablePlan("legacy_compatibility.GoogleAnalyticsOutbox",
                    CanonicalDeltaPlanner.Plan(targetSchema.Tables[0], [analytics], []).Operations),
                TablePlan("public.QuotationAcceptedOutcome",
                    CanonicalDeltaPlanner.Plan(targetSchema.Tables[1], [outcome], []).Operations),
            ]); })];
        return DeltaSynchronizationPlanProducer.Produce(new(
            schemaPlan.SourceCommitSha, now.AddMinutes(-1), Hash('c'), SchemaPlanCanonicalizer.ComputeSha256(schemaPlan),
            Hash('d'), "local-aspire", "legacy-postgres-main-local", "generation-1", Hash('e'), Hash('f'), Hash('1'),
            databases)
        {
            TargetAuthority = new(DeltaTargetAuthorityKind.LocalAspire,
                "aspire://legacy-postgres-main-local/disposable-quotation-test", Hash('2')),
            SourceMode = DeltaSourceMode.LiveReadOnly,
            SourceObservationSha256 = Hash('3'),
            SourceCaptureCompletedAtUtc = now,
        }, signer, now);
    }

    private static DeltaTablePlan TablePlan(string name, IReadOnlyList<CanonicalDeltaOperation> operations)
    {
        return new(name, operations.LongCount(operation => operation.Kind == DeltaOperationKind.Insert),
            operations.LongCount(operation => operation.Kind == DeltaOperationKind.Update),
            operations.LongCount(operation => operation.Kind == DeltaOperationKind.Delete), 0,
            DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(operations), operations);
    }

    private static DatabaseReconciliationEvidence Evidence(
        DatabaseSchemaPlan source, DatabaseSchemaPlan target, params MigrationRow[] rows)
    {
        var tables = new List<TableReconciliationEvidence>();
        for (var index = 0; index < target.Tables.Count; index++)
        {
            using var collector = new TableEvidenceCollector(target.Tables[index]);
            collector.Append(rows[index]);
            tables.Add(collector.Finish());
        }
        return new(source.Database, source.SourceSchemaSha256, source.TargetSchemaSha256, tables)
        {
            SequenceNextValues = target.Tables.ToDictionary(
                table => $"{table.TargetSchema}.{table.TargetTable}.ID", _ => 2L, StringComparer.Ordinal),
        };
    }

    private static DatabaseReconciliationEvidence DummyEvidence(DatabaseSchemaPlan schema)
    {
        return new(schema.Database, schema.SourceSchemaSha256, schema.TargetSchemaSha256,
            [new TableReconciliationEvidence("public.items", 0, Hash('4'), Hash('5'),
                new Dictionary<string, long>(), new Dictionary<string, long>())])
        {
            TargetExtensionStateSha256 = schema.TargetExtensionProfile is null ? null : Hash('6'),
        };
    }

    private static MigrationRow AnalyticsRow()
    {
        DateTime occurred = new(2026, 9, 26, 12, 34, 56, DateTimeKind.Unspecified);
        return new(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ID"] = 1L,
            ["QuotationID"] = 42,
            ["EventKey"] = "analytics-event-1",
            ["EventName"] = "quote_accepted",
            ["ClientId"] = "client",
            ["SessionId"] = "session",
            ["UserId"] = null,
            ["Currency"] = "THB",
            ["Value"] = 123.45m,
            ["OccurredUtc"] = occurred.AddTicks(7),
            ["AttemptCount"] = 0,
            ["NextAttemptUtc"] = occurred.AddTicks(8),
            ["LeaseToken"] = null,
            ["LeaseUntilUtc"] = null,
            ["SentUtc"] = null,
            ["FailedUtc"] = null,
            ["LastError"] = null,
            ["SourceRequestID"] = null,
            ["SourceJourneyID"] = null,
        });
    }

    private static MigrationRow OutcomeRow()
    {
        DateTime accepted = new(2026, 9, 26, 12, 34, 56, DateTimeKind.Unspecified);
        return new(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ID"] = 1L,
            ["EventKey"] = "outcome-event-1",
            ["QuotationID"] = 42,
            ["SourceRequestID"] = null,
            ["SourceJourneyID"] = null,
            ["AcceptedUtc"] = accepted.AddTicks(7),
            ["AcceptanceOrigin"] = "customer",
        });
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static async Task<long> ScalarAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        return Convert.ToInt64(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string Hash(char character)
    {
        return new(character, 64);
    }

    private sealed class QuotationRows(MigrationRow analytics, MigrationRow outcome) : IDeltaOrderedRowSource
    {
        internal MigrationRow Outcome { get; set; } = outcome;

        public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(string database, TableCopyPlan table,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Yield();
            yield return table.SourceTable switch
            {
                "GoogleAnalyticsOutbox" => analytics,
                "QuotationOutcomeOutbox" => Outcome,
                _ => throw new InvalidOperationException("Unexpected source table."),
            };
        }
    }

    private sealed class QuotationSource(string schemaSha256, MigrationRow analytics, MigrationRow outcome)
        : IReadOnlyMigrationSource
    {
        internal List<string> ReadTables { get; } = [];

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
            return Task.FromResult(new SourceSchemaEvidence(database, schemaSha256, []));
        }

        public async IAsyncEnumerable<MigrationRow> ReadTableAsync(string database, TableCopyPlan table,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            ReadTables.Add($"{table.SourceSchema}.{table.SourceTable}");
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Yield();
            yield return table.SourceTable == "GoogleAnalyticsOutbox" ? analytics : outcome;
        }

        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyOrphansAsync(
            string database, TableCopyPlan table, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("No target foreign key is signed.");
        }

        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyRelationshipsAsync(
            string database, TableCopyPlan table, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("No target foreign key is signed.");
        }

        public Task<IReadOnlyDictionary<string, long>> InspectSequenceNextValuesAsync(
            string database, DatabaseSchemaPlan plan, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyDictionary<string, long>>(new Dictionary<string, long>(StringComparer.Ordinal)
            {
                ["public.GoogleAnalyticsOutbox.ID"] = 2,
                ["public.QuotationOutcomeOutbox.ID"] = 2,
            });
        }
    }

    private sealed class StaticEvidence(DatabaseReconciliationEvidence evidence) : IDeltaReconciliationInspector
    {
        public Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema, CancellationToken cancellationToken)
        {
            return Task.FromResult(evidence);
        }
    }

    private sealed class SchemaEvidence(Func<DatabaseSchemaPlan, DatabaseReconciliationEvidence> inspect)
        : IDeltaReconciliationInspector
    {
        public Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(inspect(schema));
        }
    }

    private sealed class MatchingCheckpoints(
        Func<DatabaseSchemaPlan, DatabaseReconciliationEvidence> inspect,
        DateTimeOffset now) : IExact23DeltaCheckpointReader
    {
        public Task<IReadOnlyList<DeltaDatabaseCheckpointEvidence>> ReadAsync(
            DeltaSynchronizationPlan plan, FreshSchemaPlan schemaPlan, CancellationToken cancellationToken)
        {
            string planSha256 = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
            IReadOnlyList<DeltaDatabaseCheckpointEvidence> checkpoints =
            [
                .. schemaPlan.Databases.Select(schema => new DeltaDatabaseCheckpointEvidence(
                    schema.Database, plan.PlanId, planSha256, plan.SourceCutoffUtc,
                    plan.TargetObservationSha256,
                    DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(
                        plan.Databases.Single(database => database.Database == schema.Database)),
                    DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(inspect(schema)), now.AddSeconds(-1))),
            ];
            return Task.FromResult(checkpoints);
        }
    }

    private sealed class AllowAuthorization : IDeltaExecutionAuthorizationGate
    {
        public Task ValidateAsync(DeltaSynchronizationPlan plan, string database, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
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
