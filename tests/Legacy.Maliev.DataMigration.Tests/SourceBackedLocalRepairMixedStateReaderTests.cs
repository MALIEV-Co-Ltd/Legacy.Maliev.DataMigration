using System.Data;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed partial class DisposableDeltaProofVerifierTests
{
    [Fact]
    public void Mixed_observation_cannot_be_constructed_with_caller_token()
    {
        _ = Assert.Throws<DeltaExecutionException>(() => new SourceBackedLocalRepairMixedStateReader.Observation(
            new object(), "caller", null!, null!, default));
        Assert.False(SourceBackedLocalRepairMixedStateReader.Observation.AuthorizesExecution);
    }

    [Fact]
    public async Task Native_exact23_reader_recovers_commit_before_publication_and_rechecks_all_applied_data()
    {
        await using MixedNativeFixture fixture = await CreateMixedNativeFixture();
        using var signer = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        SourceBackedLocalRepairMixedStateReader.Observation observation = await fixture.Reader.ObserveAndAdvanceAsync(
            fixture.Bundle, fixture.Plans, fixture.Proof, fixture.Schema, fixture.Authorization, 0, signer, CancellationToken.None);
        Assert.Equal(1, observation.Continuation.Ordinal);
        Assert.All(observation.Continuation.Databases, state => Assert.Equal(SourceBackedLocalRepairPhase.Prior, state.Phase));
        for (int index = 0; index < DatabaseInventory.ActiveDatabases.Count; index++)
        {
            await fixture.ApplyNext(observation);
            // The transaction is committed, but the retained next ordinal has not been published.
            SourceBackedLocalRepairMixedStateReader.Observation recovered = await fixture.Reader.ObserveAndAdvanceAsync(
                fixture.Bundle, fixture.Plans, fixture.Proof, fixture.Schema, fixture.Authorization,
                observation.Continuation.Ordinal, signer, CancellationToken.None);
            Assert.Equal(index + 2, recovered.Continuation.Ordinal);
            Assert.Equal(SourceBackedLocalRepairPhase.Applied, recovered.Continuation.Databases[index].Phase);
            if (index == 0)
            {
                // Reobserve the old ordinal after publication: competing create resolves only
                // authenticated retained content matching the actual current state.
                SourceBackedLocalRepairMixedStateReader.Observation repeated = await fixture.Reader.ObserveAndAdvanceAsync(
                    fixture.Bundle, fixture.Plans, fixture.Proof, fixture.Schema, fixture.Authorization,
                    observation.Continuation.Ordinal, signer, CancellationToken.None);
                Assert.Equal(SourceBackedLocalRepairContinuationStore.ComputeSha256(recovered.Continuation),
                    SourceBackedLocalRepairContinuationStore.ComputeSha256(repeated.Continuation));
            }
            observation = recovered;
        }
        Assert.True(observation.IsTerminal);
        Assert.All(observation.Continuation.Databases, state => Assert.Equal(SourceBackedLocalRepairPhase.Applied, state.Phase));
        await Assert.ThrowsAsync<DeltaExecutionException>(() => fixture.ApplyNext(observation));

        (string Database, string Mutate, string Restore)[] churn =
        [
            ("ContactRequest", "UPDATE public.items SET id=3 WHERE id=2;", "UPDATE public.items SET id=2 WHERE id=3;"),
            ("ContactRequest", "UPDATE legacy_migration_internal.effects SET value='changed';", "UPDATE legacy_migration_internal.effects SET value='immutable';"),
            ("ContactRequest", "UPDATE legacy_migration_internal.delta_journal SET reconciliation_sha256='changed' WHERE plan_sha256='old-plan';", "UPDATE legacy_migration_internal.delta_journal SET reconciliation_sha256='old-reconciliation' WHERE plan_sha256='old-plan';"),
            ("ContactRequest", "UPDATE legacy_migration_internal.delta_source_backed_repair SET checkpoint_sha256='changed';", "UPDATE legacy_migration_internal.delta_source_backed_repair SET checkpoint_sha256=(SELECT encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex') FROM legacy_migration_internal.delta_journal j WHERE plan_sha256<>'old-plan');"),
            ("ContactRequest", "UPDATE legacy_migration_internal.delta_fence SET preserved_value='changed';", "UPDATE legacy_migration_internal.delta_fence SET preserved_value='immutable';"),
            ("ContactRequest", "ALTER SEQUENCE legacy_migration_internal.effect_seq CACHE 9;", "ALTER SEQUENCE legacy_migration_internal.effect_seq CACHE 7;"),
            ("ContactRequest", "UPDATE pg_index SET indisready=false WHERE indexrelid='public.pk_items'::regclass;", "UPDATE pg_index SET indisready=true WHERE indexrelid='public.pk_items'::regclass;"),
            ("ContactRequest", "CREATE FUNCTION public.unreviewed_hook() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'; CREATE TRIGGER unreviewed BEFORE UPDATE ON public.items FOR EACH ROW EXECUTE FUNCTION public.unreviewed_hook();", "DROP TRIGGER unreviewed ON public.items; DROP FUNCTION public.unreviewed_hook();"),
            ("Material", "INSERT INTO public.\"Country\"(\"ID\",\"Name\") VALUES(1,'changed');", "DELETE FROM public.\"Country\" WHERE \"ID\"=1;"),
            ("Quotation", "UPDATE public.\"GoogleAnalyticsOutbox\" SET \"EventName\"='changed' WHERE \"ID\"=1;", "UPDATE public.\"GoogleAnalyticsOutbox\" SET \"EventName\"='preserved' WHERE \"ID\"=1;"),
            ("Quotation", "UPDATE public.\"QuotationOutcomeOutbox\" SET \"AcceptanceOrigin\"='changed' WHERE \"ID\"=1;", "UPDATE public.\"QuotationOutcomeOutbox\" SET \"AcceptanceOrigin\"='customer' WHERE \"ID\"=1;"),
        ];
        foreach (var mutation in churn)
        {
            string cs = LockedIssuerDatabase(fixture.Connection, mutation.Database);
            await LockedIssuerExecute(cs, "SET timezone='UTC'; " + mutation.Mutate);
            await Assert.ThrowsAnyAsync<Exception>(() => fixture.Reader.ObserveAndAdvanceAsync(fixture.Bundle,
                fixture.Plans, fixture.Proof, fixture.Schema, fixture.Authorization, 24, signer, CancellationToken.None));
            await LockedIssuerExecute(cs, "SET timezone='UTC'; " + mutation.Restore);
        }
        SourceBackedLocalRepairMixedStateReader.Observation terminal = await fixture.Reader.ObserveAndAdvanceAsync(
            fixture.Bundle, fixture.Plans, fixture.Proof, fixture.Schema, fixture.Authorization, 24, signer, CancellationToken.None);
        Assert.Equal(SourceBackedLocalRepairContinuationStore.ComputeSha256(observation.Continuation),
            SourceBackedLocalRepairContinuationStore.ComputeSha256(terminal.Continuation));
        fixture.Clock.Now = fixture.Authorization.ExpiresAtUtc.AddTicks(1);
        fixture.Clock.FollowWallClock = false;
        await Assert.ThrowsAsync<DeltaExecutionException>(() => fixture.Reader.ObserveAndAdvanceAsync(fixture.Bundle,
            fixture.Plans, fixture.Proof, fixture.Schema, fixture.Authorization, 24, signer, CancellationToken.None));
    }

    [Fact]
    public async Task Native_final_exact23_reader_preserves_private_retired_rows_and_catalogs()
    {
        await using MixedNativeFixture fixture = await CreateMixedNativeFixture(physicalVariant: ReviewedQuotationPhysicalVariant.MappedFinal);
        using var signer = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        SourceBackedLocalRepairMixedStateReader.Observation current = await fixture.Reader.ObserveAndAdvanceAsync(
            fixture.Bundle, fixture.Plans, fixture.Proof, fixture.Schema, fixture.Authorization, 0, signer, CancellationToken.None);
        while (!current.IsTerminal)
        {
            await fixture.ApplyNext(current);
            current = await fixture.Reader.ObserveAndAdvanceAsync(fixture.Bundle, fixture.Plans, fixture.Proof,
                fixture.Schema, fixture.Authorization, current.Continuation.Ordinal, signer, CancellationToken.None);
        }
        string quotation = LockedIssuerDatabase(fixture.Connection, "Quotation");
        Assert.Equal(2L, await LockedIssuerScalar(quotation, "SELECT count(*) FROM legacy_migration_internal.retired_google_analytics_outbox;"));
        Assert.Equal(30L, await LockedIssuerScalar(quotation, "SELECT count(*) FROM legacy_migration_internal.retired_quotation_outcome_outbox;"));
        Assert.Equal(true, await LockedIssuerScalar(quotation, "SELECT to_regclass('public.\"GoogleAnalyticsOutbox\"') IS NULL;"));
        await LockedIssuerExecute(quotation, "UPDATE legacy_migration_internal.retired_quotation_outcome_outbox SET \"AcceptanceOrigin\"='changed' WHERE \"ID\"=1;");
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => fixture.Reader.ObserveAndAdvanceAsync(fixture.Bundle,
            fixture.Plans, fixture.Proof, fixture.Schema, fixture.Authorization, 24, signer, CancellationToken.None));
        await LockedIssuerExecute(quotation, "UPDATE legacy_migration_internal.retired_quotation_outcome_outbox SET \"AcceptanceOrigin\"='customer' WHERE \"ID\"=1;");
        _ = await fixture.Reader.ObserveAndAdvanceAsync(fixture.Bundle, fixture.Plans, fixture.Proof,
            fixture.Schema, fixture.Authorization, 24, signer, CancellationToken.None);
        await VerifyFollowOnQuotationDailyRefresh(fixture);
    }

    private async Task VerifyFollowOnQuotationDailyRefresh(MixedNativeFixture fixture)
    {
        string quotation = LockedIssuerDatabase(fixture.Connection, "Quotation");
        string source = new NpgsqlConnectionStringBuilder(fixture.Disposable.GetConnectionString())
        { Host = "127.0.0.1", Pooling = false }.ConnectionString;
        string sourceQuotation = LockedIssuerDatabase(source, "Quotation");
        string preservationSql = """
            SELECT encode(sha256(convert_to(jsonb_build_object(
              'marker',(SELECT jsonb_agg(to_jsonb(t) ORDER BY database_name) FROM legacy_migration_internal.delta_source_backed_repair t),
              'analytics',(SELECT jsonb_agg(to_jsonb(t) ORDER BY "ID") FROM legacy_migration_internal.retired_google_analytics_outbox t),
              'outcome',(SELECT jsonb_agg(to_jsonb(t) ORDER BY "ID") FROM legacy_migration_internal.retired_quotation_outcome_outbox t),
              'journals',(SELECT jsonb_agg(to_jsonb(t) ORDER BY plan_sha256) FROM legacy_migration_internal.delta_journal t)
            )::text,'UTF8')),'hex');
            """;
        string retained = (string)(await LockedIssuerScalar(quotation, preservationSql))!;
        await LockedIssuerExecute(sourceQuotation, """
            INSERT INTO public."QuotationAcceptedOutcome"
              ("ID","EventKey","QuotationID","AcceptedUtc","AcceptanceOrigin","AcceptedUtcSubMicrosecondTicks")
              VALUES(30,'synthetic-daily-outcome',41,'2026-09-26 12:34:56','customer',7);
            SELECT setval(pg_get_serial_sequence('public."QuotationAcceptedOutcome"','ID'),30,true);
            """);
        MigrationRow outcome = new(new Dictionary<string, object?>
        {
            ["ID"] = 30L,
            ["EventKey"] = "synthetic-daily-outcome",
            ["QuotationID"] = 41,
            ["SourceRequestID"] = null,
            ["SourceJourneyID"] = null,
            ["AcceptedUtc"] = new DateTime(2026, 9, 26, 12, 34, 56, DateTimeKind.Unspecified).AddTicks(7),
            ["AcceptanceOrigin"] = "customer",
        });
        var raw = new MixedDailyRawSource(new PostgreSqlDeltaRowSource(new(source)), outcome);
        var targetRows = new PostgreSqlDeltaRowSource(new(fixture.Connection));
        using var planSigner = new P256MigrationEvidenceSigner("local-plan", _localPlanKey.ExportECPrivateKeyPem());
        using var authSigner = new P256MigrationEvidenceSigner("local-transition-authorization", _authorizationKey.ExportECPrivateKeyPem());
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DeltaSynchronizationPlan prior = fixture.Plans.Persistent;
        DeltaSynchronizationPlan daily = await new Exact23DeltaPlanCoordinator(raw, targetRows, planSigner, fixture.Clock)
            .ProduceAsync(new(fixture.Schema, now, prior.BackupManifestSha256, prior.RunnerDigestSha256,
                prior.TargetNamespace, prior.TargetCluster, prior.TargetGeneration, prior.TargetObservationSha256,
                prior.BackupKeyFingerprintSha256, prior.ExecutionAuthorizationKeyFingerprintSha256)
            {
                TargetAuthority = prior.TargetAuthority,
                SourceMode = DeltaSourceMode.LiveReadOnly,
                SourceObservationSha256 = Hash('a'),
            }, CancellationToken.None);
        Assert.Equal("1.2", daily.SchemaVersion);
        Assert.Null(daily.SourceCaptureManifest);
        Assert.Null(daily.QuotationTransitionSchemaSha256);
        now = DateTimeOffset.UtcNow;
        DeltaExecutionAuthorization authorization = DeltaExecutionAuthorizationProducer.Produce(daily, now, now.AddMinutes(15), authSigner);
        DatabaseSchemaPlan database = fixture.Schema.Databases.Single(item => item.Database == "Quotation");
        var coordinator = new DeltaExecutionCoordinator(new PostgreSqlDeltaCanonicalTarget(new(quotation, "Quotation", daily.TargetGeneration)),
            new OrderedDeltaExecutionRowSessionProvider(new QuotationMappedDeltaRowSource(raw, fixture.Schema), targetRows),
            new SignedDeltaExecutionAuthorizationGate(authorization, fixture.Trust, fixture.Clock, daily.TargetAuthority!),
            new MixedNativeInspector(source), fixture.Trust, fixture.Clock);
        DeltaDatabaseExecutionResult result = await coordinator.ExecuteDatabaseAsync(daily, database, "Quotation", CancellationToken.None);
        Assert.Equal(DeltaExecutionDisposition.Committed, result.Disposition);
        Assert.Equal(1, result.AppliedOperations);
        Assert.Equal(1L, await LockedIssuerScalar(quotation, "SELECT count(*) FROM public.\"QuotationAcceptedOutcome\" WHERE \"ID\"=30 AND \"AcceptedUtcSubMicrosecondTicks\"=7;"));
        // Compare the exact old checkpoint multiset independently from the newly appended daily checkpoint.
        string withoutDaily = preservationSql.Replace("FROM legacy_migration_internal.delta_journal t)",
            "FROM legacy_migration_internal.delta_journal t WHERE plan_sha256<>'" + result.PlanSha256 + "')", StringComparison.Ordinal);
        Assert.Equal(retained, await LockedIssuerScalar(quotation, withoutDaily));
        DatabaseReconciliationEvidence expected = await new MixedNativeInspector(source).InspectAsync(database, CancellationToken.None);
        DatabaseReconciliationEvidence actual = await new MixedNativeInspector(fixture.Connection).InspectAsync(database, CancellationToken.None);
        Assert.Equal(DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(expected), DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(actual));
    }

    private sealed class MixedDailyRawSource(IDeltaOrderedRowSource other, MigrationRow outcome) : IDeltaOrderedRowSource
    {
        public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(string database, TableCopyPlan table,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            if (database == "Quotation")
            {
                if (table.SourceTable == "QuotationOutcomeOutbox") { yield return outcome; }
                yield break;
            }
            await foreach (MigrationRow row in other.ReadOrderedAsync(database, table, cancellationToken)) { yield return row; }
        }
    }

    private async Task<MixedNativeFixture> CreateMixedNativeFixture(TimeSpan? initialAuthorizationLifetime = null,
        ReviewedQuotationPhysicalVariant physicalVariant = ReviewedQuotationPhysicalVariant.RetainedOutboxes)
    {
        var persistent = new PostgreSqlBuilder("postgres:18-alpine").Build();
        var disposable = new PostgreSqlBuilder("postgres:18-alpine").Build();
        try
        {
            await persistent.StartAsync();
            await disposable.StartAsync();
            string local = new NpgsqlConnectionStringBuilder(persistent.GetConnectionString()) { Host = "127.0.0.1", Pooling = false }.ConnectionString;
            string proofConnection = new NpgsqlConnectionStringBuilder(disposable.GetConnectionString()) { Host = "127.0.0.1", Pooling = false }.ConnectionString;
            string localSystem = HashText((string)(await LockedIssuerScalar(local, "SELECT system_identifier::text FROM pg_control_system();"))!);
            string proofSystem = HashText((string)(await LockedIssuerScalar(proofConnection, "SELECT system_identifier::text FROM pg_control_system();"))!);
            Fixture original = AddSourceRepairTerminalTrust(await CreateAsync(pairedTransition: true, quotationDisposition: true, captured: true,
                historicalLocal: true, localSystemHash: localSystem, physicalTargetHashes: true, at: DateTimeOffset.UtcNow));
            foreach (string admin in new[] { local, proofConnection })
                foreach (DatabaseSchemaPlan database in original.Schema.Databases)
                {
                    await LockedIssuerExecute(admin, $"CREATE DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(database.Database)};");
                    string cs = LockedIssuerDatabase(admin, database.Database);
                    await using var connection = new NpgsqlConnection(cs);
                    await connection.OpenAsync();
                    await using (NpgsqlTransaction transaction = await connection.BeginTransactionAsync())
                    {
                        DatabaseSchemaPlan initial = database.SourceDispositionProfile is null ? database : database with
                        {
                            Database = "QuotationBootstrapFixture",
                            SourceDispositionProfile = null,
                            SourceTableDispositions = [],
                            TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpectedSourceShape(database),
                        };
                        await using var writer = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                        await writer.ApplySchemaAsync(initial, CancellationToken.None);
                        await writer.FinalizeSchemaAsync(initial, CancellationToken.None);
                        await transaction.CommitAsync();
                    }
                    if (database.Database == "Quotation")
                    {
                        string systemHash = admin == local ? localSystem : proofSystem;
                        _ = await QuotationDispositionTargetBootstrap.ExecuteAsync(database, cs, database.Database, systemHash, CancellationToken.None);
                    }
                    else { await LockedIssuerExecute(cs, "INSERT INTO public.items(id) VALUES(1);"); }
                }
            // Retired local-only public outboxes are preserved independently from the reviewed
            // mapped archive/outcome source parity. They cannot disappear through row refresh.
            await LockedIssuerExecute(LockedIssuerDatabase(local, "Quotation"), """
                INSERT INTO public."GoogleAnalyticsOutbox"
                  ("ID","QuotationID","EventKey","EventName","ClientId","SessionId","Currency","Value","OccurredUtc","AttemptCount","NextAttemptUtc")
                  SELECT n,42,'retained-analytics-'||n,'preserved','synthetic','synthetic','THB',1.25,
                    '2026-09-26 12:00:00'::timestamp,0,'2026-09-26 12:00:00'::timestamp FROM generate_series(1,2) n;
                INSERT INTO public."QuotationOutcomeOutbox" ("ID","EventKey","QuotationID","AcceptedUtc","AcceptanceOrigin")
                  SELECT n,'retained-outcome-'||n,42,'2026-09-26 12:00:00'::timestamp,'customer' FROM generate_series(1,30) n;
                """);
            if (physicalVariant == ReviewedQuotationPhysicalVariant.MappedFinal)
            {
                foreach (string admin in new[] { local, proofConnection })
                {
                    // Preserve the complete retired tables and all dependencies before the
                    // original capsule. The row executor performs no retirement DDL.
                    await LockedIssuerExecute(LockedIssuerDatabase(admin, "Quotation"), """
                        CREATE SCHEMA IF NOT EXISTS legacy_migration_internal;
                        ALTER TABLE public."GoogleAnalyticsOutbox" SET SCHEMA legacy_migration_internal;
                        ALTER TABLE legacy_migration_internal."GoogleAnalyticsOutbox" RENAME TO retired_google_analytics_outbox;
                        ALTER TABLE public."QuotationOutcomeOutbox" SET SCHEMA legacy_migration_internal;
                        ALTER TABLE legacy_migration_internal."QuotationOutcomeOutbox" RENAME TO retired_quotation_outcome_outbox;
                        """);
                }
            }
            var nativeInspector = new MixedNativeInspector(proofConnection);
            TableCopyPlan insertedTable = original.Schema.Databases.Single(item => item.Database == "ContactRequest").Tables.Single();
            MigrationRow insertedRow = MixedInsertedRow();
            var insertedOperation = new CanonicalDeltaOperation(DeltaOperationKind.Insert,
                CanonicalDeltaPlanner.ComputeKeySha256(insertedTable, insertedRow), CanonicalRowFingerprint.Compute(insertedTable, [insertedRow]), null);
            await LockedIssuerExecute(LockedIssuerDatabase(proofConnection, "ContactRequest"), "INSERT INTO public.items VALUES(2);");
            var captured = new List<DatabaseReconciliationEvidence>();
            DateTimeOffset captureStarted = DateTimeOffset.UtcNow;
            foreach (DatabaseSchemaPlan database in original.Schema.Databases)
            {
                DatabaseReconciliationEvidence evidence = await nativeInspector.InspectAsync(database, CancellationToken.None);
                captured.Add(evidence with { TargetSchemaSha256 = database.TargetSchemaSha256, TargetExtensionStateSha256 = null });
            }
            DateTimeOffset captureCompleted = DateTimeOffset.UtcNow;
            // The immutable captured evidence came from real PostgreSQL rows. Prepare the
            // disposable proof target at the same prior row state as persistent LOCAL.
            await LockedIssuerExecute(LockedIssuerDatabase(proofConnection, "ContactRequest"), "DELETE FROM public.items WHERE id=2;");
            using var proofSigner = new P256MigrationEvidenceSigner("proof-plan", _planKey.ExportECPrivateKeyPem());
            using var localSigner = new P256MigrationEvidenceSigner("local-plan", _localPlanKey.ExportECPrivateKeyPem());
            DeltaSynchronizationPlan proofPlan = Rebind(original.ProofPlan with
            {
                TargetAuthority = original.ProofPlan.TargetAuthority! with { SystemIdentifierSha256 = proofSystem },
            }, proofSigner);
            DeltaSynchronizationPlan localPlan = Rebind(original.LocalPlan, localSigner);
            await new PostgreSqlDeltaMetadataProvisioner(new(proofConnection, proofPlan.TargetAuthority!))
                .ProvisionAsync(proofPlan, original.Schema, CancellationToken.None);
            foreach (DatabaseSchemaPlan database in original.Schema.Databases)
            {
                var target = new PostgreSqlDeltaCanonicalTarget(new(LockedIssuerDatabase(proofConnection, database.Database),
                    database.Database, proofPlan.TargetGeneration)
                { SignedSourceSchemaPlan = original.Schema });
                await using IDeltaCanonicalTransaction transaction = await target.BeginAsync(proofPlan,
                    new QuotationDeltaExecutionMapping(database).TargetSchema, database.Database, CancellationToken.None);
                if (database.Database == "ContactRequest")
                {
                    await transaction.ApplyAsync(insertedTable, insertedOperation, insertedRow, null, CancellationToken.None);
                }
                string reconciliation = await transaction.ReconcileAsync(captured.Single(item => item.Database == database.Database), CancellationToken.None);
                await transaction.CommitAsync(DeltaSynchronizationPlanCanonicalizer.ComputeSha256(proofPlan), reconciliation, CancellationToken.None);
            }
            // PostgreSQL checkpoints use wall clock. The fixture authority clock follows the
            // real disposable commits, without weakening any freshness comparison.
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var clock = new AdmissionClock(now) { FollowWallClock = true };
            using var evidenceSigner = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
            var coordinator = new Exact23DeltaReconciliationCoordinator(nativeInspector, nativeInspector,
                new PostgreSqlExact23DeltaCheckpointReader(new(proofConnection)), clock, evidenceSigner);
            Exact23DeltaReconciliationResult proof = await coordinator.ReconcileAsync(proofPlan, original.Schema, CancellationToken.None);
            now = DateTimeOffset.UtcNow;
            using var authorizationSigner = new P256MigrationEvidenceSigner("local-transition-authorization", _authorizationKey.ExportECPrivateKeyPem());
            var plans = new PairedCapturedDeltaPlans(proofPlan, localPlan);
            PairedLocalTransitionAuthorization authorization = PairedLocalTransitionAuthorizationPolicy.Produce(plans,
                proof, original.Schema, original.Trust, localPlan.TargetAuthority!, localPlan.TargetObservationSha256,
                localPlan.QuotationTransitionSchemaSha256!, now, now.Add(initialAuthorizationLifetime ?? TimeSpan.FromMinutes(15)), authorizationSigner);
            var identity = new HistoricalCurrentLocalObservation(Hash('7'), localPlan.TargetGeneration,
                "legacy-maliev-exact23-postgres-data", DateTimeOffset.FromUnixTimeMilliseconds(3),
                "/var/lib/docker/volumes/legacy-maliev-exact23-postgres-data/_data", "/var/lib/postgresql",
                "/var/lib/postgresql/18/docker", localSystem);
            var snapshots = new List<SourceBackedLocalRepairDatabasePreimage>();
            foreach (DatabaseSchemaPlan database in original.Schema.Databases)
            {
                string cs = LockedIssuerDatabase(local, database.Database);
                await LockedIssuerExecute(cs, """
                    CREATE SCHEMA IF NOT EXISTS legacy_migration_internal;
                    CREATE TABLE legacy_migration_internal.delta_fence(database_name text PRIMARY KEY,
                      schema_plan_sha256 text NOT NULL,target_schema_sha256 text NOT NULL,
                      target_generation text NOT NULL,target_observation_sha256 text NOT NULL,preserved_value text NOT NULL);
                    CREATE TABLE legacy_migration_internal.delta_journal(plan_sha256 text PRIMARY KEY,plan_id uuid NOT NULL UNIQUE,
                      source_cutoff_utc timestamptz NOT NULL,target_observation_sha256 text NOT NULL,operations_sha256 text NOT NULL,
                      reconciliation_sha256 text NOT NULL,committed_at_utc timestamptz NOT NULL);
                    INSERT INTO legacy_migration_internal.delta_journal VALUES('old-plan','00000000-0000-0000-0000-000000000001',
                      '2026-09-01T00:00:00.123456Z','old-observation','old-operations','old-reconciliation','2026-09-01T00:00:00.123456Z');
                    CREATE TABLE legacy_migration_internal.effects(id bigint PRIMARY KEY,value text NOT NULL);
                    INSERT INTO legacy_migration_internal.effects VALUES(9007199254740993,'immutable');
                    CREATE SEQUENCE legacy_migration_internal.effect_seq AS bigint START 9007199254740993 CACHE 7;
                    """);
                await LockedIssuerExecute(cs, $"INSERT INTO legacy_migration_internal.delta_fence VALUES('{database.Database}','old-schema','old-physical','old-generation','old-observation','immutable');");
                await using var connection = new NpgsqlConnection(cs);
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
                await PostgreSqlSourceBackedLocalRepair.StageAsync(connection, transaction, CancellationToken.None);
                await transaction.CommitAsync();
                snapshots.Add(await LockedIssuerRead(cs, database));
            }
            var pins = new SourceBackedLocalRepairSigningPins(localSigner.PublicKeyFingerprintSha256,
                proofSigner.PublicKeyFingerprintSha256, authorizationSigner.PublicKeyFingerprintSha256, evidenceSigner.PublicKeyFingerprintSha256);
            var gateway = new AdmissionGateway(now, clock);
            var claims = new SourceBackedLocalRepairClaimStore(gateway);
            var admissions = new SourceBackedLocalRepairAdmissionStore(claims, original.Trust, pins, _ => Task.FromResult(identity), clock,
                terminalPin: SourceRepairTerminalPin());
            var maintenance = new LockedIssuerMaintenance(_ => Task.CompletedTask);
            SourceBackedLocalRepairAdmissionBundle bundle = await admissions.CreateAsync(new SourceBackedLocalRepairLockedIssuer(
                local, _ => Task.FromResult(identity), maintenance, clock), plans, proof, original.Schema, authorization,
                snapshots, authorization.ExpiresAtUtc, evidenceSigner, CancellationToken.None);
            var continuations = new SourceBackedLocalRepairContinuationStore(gateway, claims, original.Trust,
                pins.AuthorizationFingerprint, pins.EvidenceFingerprint);
            var reader = new SourceBackedLocalRepairMixedStateReader(local, admissions, continuations,
                _ => Task.FromResult(identity), maintenance, clock);
            return new(persistent, disposable, local, plans, proof, original.Schema, original.Trust,
                authorization, identity, bundle, admissions, continuations, reader, clock, SourceRepairTerminalPin());

            DeltaSynchronizationPlan Rebind(DeltaSynchronizationPlan plan, P256MigrationEvidenceSigner signer)
            {
                DeltaDatabasePlan[] deltas = [.. plan.Databases.Select(database => database with
                {
                    Tables = [.. database.Tables.Select(table => table with
                    {
                        InsertCount = database.Database == "ContactRequest" ? 1 : 0,
                        UnchangedCount = captured.Single(item => item.Database == database.Database)
                            .Tables.Single(item => item.Table == table.Table).RowCount - (database.Database == "ContactRequest" ? 1 : 0),
                        Operations = database.Database == "ContactRequest" ? [insertedOperation] : [],
                        OperationsSha256 = DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(
                            database.Database == "ContactRequest" ? [insertedOperation] : []),
                    })],
                })];
                var unsigned = plan with
                {
                    QuotationTransitionSchemaSha256 = ReviewedQuotationPhysicalSchemaResolver.GetExpected(
                        original.Schema.Databases.Single(item => item.Database == "Quotation"), physicalVariant),
                    SourceCutoffUtc = captureStarted,
                    SourceCaptureCompletedAtUtc = captureCompleted,
                    CreatedAtUtc = captureCompleted.AddTicks(1),
                    SourceCaptureManifest = plan.SourceCaptureManifest! with
                    {
                        Databases = [.. plan.SourceCaptureManifest.Databases.Select(binding => binding with
                        {
                            StartedAtUtc = captureStarted,
                            CompletedAtUtc = captureCompleted,
                            SourceReconciliation = captured.Single(item => item.Database == binding.Database),
                            Tables = [.. binding.Tables.Select(table => table with
                            {
                                CapturedRowCount = binding.Database == "ContactRequest" ? 1 : 0,
                                OperationsSha256 = deltas.Single(item => item.Database == binding.Database).Tables.Single(item => item.Table == table.Table).OperationsSha256,
                            })],
                        })],
                    },
                    Databases = deltas,
                    AttestationSignature = null,
                };
                return unsigned with { AttestationSignature = Convert.ToBase64String(signer.Sign(DeltaSynchronizationPlanCanonicalizer.CreatePayload(unsigned))) };
            }
        }
        catch
        {
            await disposable.DisposeAsync();
            await persistent.DisposeAsync();
            throw;
        }
    }

    private static string HashText(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    private SourceBackedLocalRepairTerminalSigningPin SourceRepairTerminalPin() =>
        new(Convert.ToHexString(SHA256.HashData(_continuityKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant(), "source-repair-terminal");
    private Fixture AddSourceRepairTerminalTrust(Fixture source) => source with
    {
        Trust = new ReceiptAttestationTrustStore([.. source.Trust.ExportTrustedPublicKeys(
            [source.LocalPlan.AttestationKeyId, source.ProofPlan.AttestationKeyId, source.ProofResult.AttestationKeyId,
                "local-transition-authorization"]), new("source-repair-terminal", _continuityKey.ExportSubjectPublicKeyInfo())]),
    };
    private static MigrationRow MixedInsertedRow() => new(new Dictionary<string, object?> { ["id"] = 2 });

    private sealed class MixedNativeInspector(string admin) : IDeltaReconciliationInspector
    {
        public async Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema, CancellationToken cancellationToken)
        {
            await using var connection = new NpgsqlConnection(LockedIssuerDatabase(admin, schema.Database));
            await connection.OpenAsync(cancellationToken);
            await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellationToken);
            DatabaseSchemaPlan target = new QuotationDeltaExecutionMapping(schema).TargetSchema;
            await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
            var tables = new List<TableReconciliationEvidence>();
            foreach (TableCopyPlan table in target.Tables) { tables.Add(await inspector.InspectTableAsync(table, cancellationToken)); }
            IReadOnlyDictionary<string, long> sequences = await inspector.InspectSequenceNextValuesAsync(target, cancellationToken);
            string physical = await inspector.InspectSchemaAsync(schema, cancellationToken);
            string? extensionHash = null;
            if (ApprovedConsumerColumnOverlayManifest.HasState(target))
            {
                ApprovedTargetExtensionState extensions = await ApprovedTargetExtensionStateInspector.InspectAsync(connection, transaction, target, cancellationToken);
                extensionHash = ApprovedTargetExtensionStateInspector.ComputeSha256(target, extensions);
            }
            await transaction.RollbackAsync(cancellationToken);
            return new(schema.Database, schema.SourceSchemaSha256, physical, tables)
            {
                SequenceNextValues = sequences,
                TargetExtensionStateSha256 = extensionHash,
            };
        }
    }

    private sealed record MixedNativeFixture(PostgreSqlContainer Persistent, PostgreSqlContainer Disposable,
        string Connection, PairedCapturedDeltaPlans Plans, Exact23DeltaReconciliationResult Proof,
        FreshSchemaPlan Schema, ReceiptAttestationTrustStore Trust, PairedLocalTransitionAuthorization Authorization,
        HistoricalCurrentLocalObservation Identity, SourceBackedLocalRepairAdmissionBundle Bundle,
        SourceBackedLocalRepairAdmissionStore Admissions, SourceBackedLocalRepairContinuationStore Continuations,
        SourceBackedLocalRepairMixedStateReader Reader, AdmissionClock Clock,
        SourceBackedLocalRepairTerminalSigningPin TerminalPin) : IAsyncDisposable
    {
        internal async Task ApplyNext(SourceBackedLocalRepairMixedStateReader.Observation observation)
        {
            Clock.Now = DateTimeOffset.UtcNow;
            PairedLocalTransitionAuthorization currentAuthorization = observation.ActiveGrant?.Authorization ?? Authorization;
            var maintenance = new ExecutionMaintenance();
            SourceBackedLocalRepairExecutionPermit repair = await SourceBackedLocalRepairExecutionPermit.AdmitAsync(
                Admissions, Continuations, Bundle, Plans, Proof, Schema, currentAuthorization, observation,
                _ => Task.FromResult(Identity), maintenance, Clock, CancellationToken.None);
            var paired = PairedLocalTransitionExecutionPermit.Admit(Plans, Proof, currentAuthorization, Schema,
                Trust, Plans.Persistent.TargetAuthority!, Plans.Persistent.TargetObservationSha256, Clock);
            DatabaseSchemaPlan database = Schema.Databases[checked((int)observation.Continuation.Ordinal - 1)];
            var target = new PostgreSqlDeltaCanonicalTarget(new(LockedIssuerDatabase(Connection, database.Database),
                database.Database, Plans.Persistent.TargetGeneration)
            { LocalTransitionPermit = paired, SourceRepairPermit = repair });
            await using IDeltaCanonicalTransaction transaction = await target.BeginAsync(Plans.Persistent,
                new QuotationDeltaExecutionMapping(database).TargetSchema, database.Database, CancellationToken.None);
            if (database.Database == "ContactRequest")
            {
                await transaction.ApplyAsync(database.Tables.Single(), Plans.Persistent.Databases.Single(item => item.Database == database.Database)
                    .Tables.Single().Operations.Single(), MixedInsertedRow(), null, CancellationToken.None);
            }
            string reconciliation = await transaction.ReconcileAsync(Plans.Persistent.SourceCaptureManifest!.Databases
                .Single(item => item.Database == database.Database).SourceReconciliation, CancellationToken.None);
            await transaction.CommitAsync(DeltaSynchronizationPlanCanonicalizer.ComputeSha256(Plans.Persistent), reconciliation, CancellationToken.None);
            Clock.Now = DateTimeOffset.UtcNow;
        }

        public async ValueTask DisposeAsync()
        {
            await Disposable.DisposeAsync();
            await Persistent.DisposeAsync();
        }
    }
}
