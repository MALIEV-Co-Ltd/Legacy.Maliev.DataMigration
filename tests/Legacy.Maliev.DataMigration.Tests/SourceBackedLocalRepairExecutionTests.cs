using System.Data;
using System.Security.Cryptography;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed partial class DisposableDeltaProofVerifierTests
{
    [Fact]
    public async Task Source_repair_execution_cannot_accept_a_caller_minted_mixed_state_token()
    {
        AdmissionFixture state = await AdmissionState();
        _ = Assert.Throws<DeltaExecutionException>(() => new SourceBackedLocalRepairMixedStateReader.Observation(
            new object(), state.Admission.PersistentPlanSha256, null!, state.Identity, state.Fixture.Now));
    }

    [Theory]
    [InlineData("column")]
    [InlineData("index")]
    [InlineData("policy")]
    [InlineData("trigger")]
    [InlineData("nonempty")]
    public async Task Source_repair_staged_marker_rejects_changed_catalog_and_nonempty_preimage(string mutation)
    {
        await using PostgreSqlContainer container = new PostgreSqlBuilder("postgres:18-alpine")
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 384L * 1024 * 1024;
                parameters.HostConfig.MemorySwap = 384L * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 500000000;
            }).Build();
        await container.StartAsync();
        string admin = new NpgsqlConnectionStringBuilder(container.GetConnectionString()) { Host = "127.0.0.1", Pooling = false }.ConnectionString;
        await LockedIssuerExecute(admin, "CREATE DATABASE \"ContactRequest\";");
        string cs = LockedIssuerDatabase(admin, "ContactRequest");
        await LockedIssuerExecute(cs, "CREATE SCHEMA legacy_migration_internal; CREATE TABLE legacy_migration_internal.delta_journal(id bigint);");
        await using var connection = new NpgsqlConnection(cs);
        await connection.OpenAsync();
        await using (NpgsqlTransaction stage = await connection.BeginTransactionAsync(IsolationLevel.Serializable))
        {
            await PostgreSqlSourceBackedLocalRepair.StageAsync(connection, stage, CancellationToken.None);
            await stage.CommitAsync();
        }
        await LockedIssuerExecute(cs, mutation switch
        {
            "column" => "ALTER TABLE legacy_migration_internal.delta_source_backed_repair ADD extra text;",
            "index" => "UPDATE pg_index SET indisvalid=false WHERE indexrelid='legacy_migration_internal.delta_source_backed_repair_pkey'::regclass;",
            "policy" => "CREATE POLICY unsafe ON legacy_migration_internal.delta_source_backed_repair USING(true);",
            "trigger" => "CREATE FUNCTION public.marker_hook() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'; CREATE TRIGGER unsafe BEFORE INSERT ON legacy_migration_internal.delta_source_backed_repair FOR EACH ROW EXECUTE FUNCTION public.marker_hook();",
            _ => "INSERT INTO legacy_migration_internal.delta_source_backed_repair VALUES('ContactRequest','a','00000000-0000-0000-0000-000000000001','b','c','d',1,'e','f','g','h','i');",
        });
        await using NpgsqlTransaction verify = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => SourceBackedLocalRepairPreimage.RequireMarkerCatalogAsync(connection, verify, 0, CancellationToken.None));
        await verify.RollbackAsync();
    }

    [Theory]
    [InlineData("rollback")]
    [InlineData("commit")]
    [InlineData("effect")]
    [InlineData("sequence")]
    [InlineData("sequence-parameters")]
    [InlineData("fence-catalog")]
    [InlineData("journal-catalog")]
    [InlineData("checkpoint")]
    [InlineData("expiry")]
    [InlineData("identity")]
    [InlineData("maintenance")]
    public async Task Source_repair_native_atomic_adoption_preserves_prior_state_or_rolls_back(string scenario)
    {
        await using PostgreSqlContainer container = new PostgreSqlBuilder("postgres:18-alpine")
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 384L * 1024 * 1024;
                parameters.HostConfig.MemorySwap = 384L * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 500000000;
            }).Build();
        await container.StartAsync();
        string admin = new NpgsqlConnectionStringBuilder(container.GetConnectionString())
        { Host = "127.0.0.1", Database = "postgres", Pooling = false, Enlist = false }.ConnectionString;
        string system = (string)(await LockedIssuerScalar(admin, "SELECT system_identifier::text FROM pg_control_system();"))!;
        string systemHash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(system))).ToLowerInvariant();
        AdmissionFixture state = await AdmissionState(systemHash);
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string terminalKeyId = "execution-terminal";
        var executionTrust = new ReceiptAttestationTrustStore(
            [new("proof-plan", _planKey.ExportSubjectPublicKeyInfo()),
                new("local-plan", _localPlanKey.ExportSubjectPublicKeyInfo()),
                new("proof-evidence", _evidenceKey.ExportSubjectPublicKeyInfo()),
                new("local-transition-authorization", _authorizationKey.ExportSubjectPublicKeyInfo()),
                new(terminalKeyId, terminalKey.ExportSubjectPublicKeyInfo())]);
        state = state with { Fixture = state.Fixture with { Trust = executionTrust } };
        var terminalPin = new SourceBackedLocalRepairTerminalSigningPin(Fingerprint(executionTrust, terminalKeyId), terminalKeyId);
        await LockedIssuerExecute(admin, "CREATE DATABASE \"ContactRequest\";");
        string cs = LockedIssuerDatabase(admin, "ContactRequest");
        await LockedIssuerExecute(cs, """
            CREATE SCHEMA legacy_migration_internal;
            CREATE TABLE legacy_migration_internal.delta_fence(database_name text PRIMARY KEY,
                schema_plan_sha256 text,target_schema_sha256 text,target_generation text,target_observation_sha256 text,
                preserved_value text NOT NULL);
            INSERT INTO legacy_migration_internal.delta_fence VALUES('ContactRequest','old-schema','old-physical','old-generation','old-observation','immutable-authority');
            CREATE TABLE legacy_migration_internal.delta_journal(plan_sha256 text PRIMARY KEY,
                plan_id uuid, source_cutoff_utc timestamptz,target_observation_sha256 text,
                operations_sha256 text,reconciliation_sha256 text,committed_at_utc timestamptz);
            INSERT INTO legacy_migration_internal.delta_journal VALUES('old-plan','00000000-0000-0000-0000-000000000001',
                '2026-09-01T00:00:00.123456Z','old-observation','old-operations','old-reconciliation','2026-09-01T00:00:00.123456Z');
            CREATE TABLE legacy_migration_internal.effects(id bigint PRIMARY KEY,value text NOT NULL);
            INSERT INTO legacy_migration_internal.effects VALUES(9007199254740993,'immutable-effect');
            CREATE TABLE public.items(id bigint PRIMARY KEY);
            INSERT INTO public.items VALUES(9007199254740993);
            CREATE SEQUENCE legacy_migration_internal.effect_seq AS bigint START 9007199254740993 CACHE 7;
            """);
        DatabaseSchemaPlan schema = state.Fixture.Schema.Databases.Single(item => item.Database == "ContactRequest");
        await using (var stage = new NpgsqlConnection(cs))
        {
            await stage.OpenAsync();
            await using NpgsqlTransaction stageTransaction = await stage.BeginTransactionAsync(IsolationLevel.Serializable);
            await PostgreSqlSourceBackedLocalRepair.StageAsync(stage, stageTransaction, CancellationToken.None);
            await stageTransaction.CommitAsync();
        }
        SourceBackedLocalRepairDatabasePreimage prior = await LockedIssuerRead(cs, schema);
        await using (var stageAgain = new NpgsqlConnection(cs))
        {
            await stageAgain.OpenAsync();
            await using NpgsqlTransaction stageAgainTransaction = await stageAgain.BeginTransactionAsync(IsolationLevel.Serializable);
            await PostgreSqlSourceBackedLocalRepair.StageAsync(stageAgain, stageAgainTransaction, CancellationToken.None);
            await stageAgainTransaction.CommitAsync();
        }
        SourceBackedLocalRepairPreimage.RequireMatches(prior, await LockedIssuerRead(cs, schema));
        using var signer = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        SourceBackedLocalRepairDatabasePreimage[] preimages = [prior, .. state.Capsule.Databases.Skip(1)];
        SourceBackedLocalRepairPreimageAttestation capsule = SourceBackedLocalRepairPreimageAttestationPolicy.Produce(
            state.Plans, state.Fixture.ProofResult, state.Fixture.Schema, state.Authorization, state.Identity,
            preimages, state.Fixture.Trust, state.Fixture.Now, state.Fixture.Now.AddMinutes(5), signer);
        SourceBackedLocalRepairAdmission admission = SignAdmission(state.Admission with
        {
            PreimageSha256 = SourceBackedLocalRepairPreimageAttestationPolicy.ComputeSha256(capsule),
            InitialMetadata = SourceBackedLocalRepairAdmissionPolicy.Metadata(preimages),
        });
        var gateway = new AdmissionGateway(state.Fixture.Now);
        var claims = new SourceBackedLocalRepairClaimStore(gateway);
        var clock = new AdmissionClock(state.Fixture.Now);
        HistoricalCurrentLocalObservation currentIdentity = state.Identity;
        var continuations = new SourceBackedLocalRepairContinuationStore(gateway, claims, state.Fixture.Trust,
            state.Pins.AuthorizationFingerprint, state.Pins.EvidenceFingerprint);
        var renewals = new SourceBackedLocalRepairRenewalStore(gateway, claims, continuations,
            state.Fixture.Trust, state.Pins, terminalPin, _ => Task.FromResult(currentIdentity), clock);
        await renewals.RetainOriginalAsync(admission, capsule, state.Authorization, state.Plans,
            state.Fixture.ProofResult, state.Fixture.Schema, CancellationToken.None);
        SourceBackedLocalRepairClaim claim = await claims.ReserveAsync(SourceBackedLocalRepairAdmissionPolicy.ExpectedClaim(admission), state.Fixture.Now, CancellationToken.None);
        var admissions = new SourceBackedLocalRepairAdmissionStore(claims, state.Fixture.Trust, state.Pins,
            _ => Task.FromResult(currentIdentity), clock, renewals);
        SourceBackedLocalRepairState[] states = [.. admission.InitialMetadata.Select(item =>
            new SourceBackedLocalRepairState(item.Database, SourceBackedLocalRepairPhase.Prior, item.FingerprintSha256, null, null, null))];
        var unsigned = new SourceBackedLocalRepairContinuation("1.0", claim.ClaimId, claim.AdmissionSha256,
            claim.PreimageSha256, claim.SourceCaptureSha256, claim.FuturePlanSha256, claim.TargetGeneration,
            state.Authorization.AuthorizationId, admission.AuthorizationSha256, 1, null, states,
            state.Fixture.Now, state.Fixture.Now.AddMinutes(5), "proof-evidence", null);
        SourceBackedLocalRepairContinuation continuation = unsigned with
        { AttestationSignature = Convert.ToBase64String(signer.Sign(SourceBackedLocalRepairContinuationStore.Payload(unsigned))) };
        _ = await continuations.AppendAsync(continuation, state.Authorization, states, state.Fixture.Now, CancellationToken.None);
        var maintenance = new ExecutionMaintenance();
        SourceBackedLocalRepairExecutionPermit permit = await SourceBackedLocalRepairExecutionPermit.AdmitAsync(admissions,
            continuations, new(admission, capsule, claim), state.Plans, state.Fixture.ProofResult, state.Fixture.Schema,
            state.Authorization, 1, _ => Task.FromResult(currentIdentity), maintenance, clock, CancellationToken.None);
        _ = Assert.Throws<DeltaExecutionException>(() => permit.Require(state.Plans.Persistent,
            state.Fixture.Schema.Databases[1]));
        await using (var connection = new NpgsqlConnection(cs))
        {
            await connection.OpenAsync();
            await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
            _ = await SourceBackedLocalRepairLockSet.AcquireAndVerifyAsync(connection, transaction, schema, prior, CancellationToken.None);
            DeltaSynchronizationPlan plan = state.Plans.Persistent;
            string planHash = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
            var binding = new CanonicalDeltaTargetBinding(plan.PlanId, planHash, plan.SourceCutoffUtc, schema.Database,
                plan.SchemaPlanSha256, prior.ObservedPhysicalSchemaSha256, plan.TargetGeneration, plan.TargetObservationSha256);
            PostgreSqlSourceBackedLocalRepair repair = await PostgreSqlSourceBackedLocalRepair.AdoptAsync(connection,
                transaction, plan, schema, permit, binding, CancellationToken.None);
            await using (var checkpoint = new NpgsqlCommand("INSERT INTO legacy_migration_internal.delta_journal VALUES($1,$2,$3,$4,$5,$6,clock_timestamp());", connection, transaction))
            {
                object[] values = [planHash, plan.PlanId, plan.SourceCutoffUtc, plan.TargetObservationSha256, Hash('a'), Hash('b')];
                foreach (object value in values) { _ = checkpoint.Parameters.AddWithValue(value); }
                _ = await checkpoint.ExecuteNonQueryAsync();
            }
            if (scenario is "effect" or "sequence" or "sequence-parameters" or "fence-catalog" or "journal-catalog" or "checkpoint")
            {
                await using var mutation = new NpgsqlCommand(scenario switch
                {
                    "effect" => "UPDATE legacy_migration_internal.effects SET value='changed';",
                    "sequence-parameters" => "ALTER SEQUENCE legacy_migration_internal.effect_seq INCREMENT BY 2 CACHE 9;",
                    "fence-catalog" => "ALTER TABLE legacy_migration_internal.delta_fence ADD CONSTRAINT changed_fence CHECK(preserved_value<>'forbidden');",
                    "journal-catalog" => "ALTER TABLE legacy_migration_internal.delta_journal ADD CONSTRAINT changed_journal CHECK(reconciliation_sha256<>'forbidden');",
                    "checkpoint" => "UPDATE legacy_migration_internal.delta_journal SET reconciliation_sha256='wrong' WHERE plan_sha256<>'old-plan';",
                    _ => "ALTER SEQUENCE legacy_migration_internal.effect_seq RESTART WITH 9007199254740995;",
                }, connection, transaction);
                _ = await mutation.ExecuteNonQueryAsync();
            }
            if (scenario == "expiry") { clock.Now = state.Fixture.Now.AddMinutes(5); }
            if (scenario == "identity") { currentIdentity = state.Identity with { ContainerId = Hash('f') }; }
            if (scenario == "maintenance") { maintenance.Quiescent = false; }
            if (scenario is "rollback" or "commit") { await repair.RecordAsync(connection, transaction, binding, schema, Hash('b'), CancellationToken.None); }
            else { _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => repair.RecordAsync(connection, transaction, binding, schema, Hash('b'), CancellationToken.None)); }
            if (scenario == "commit") { await transaction.CommitAsync(); }
            else { await transaction.RollbackAsync(); }
        }
        if (scenario == "commit")
        {
            Assert.Equal(2L, await LockedIssuerScalar(cs, "SELECT count(*) FROM legacy_migration_internal.delta_journal;"));
            Assert.Equal("immutable-effect", await LockedIssuerScalar(cs, "SELECT value FROM legacy_migration_internal.effects;"));
            Assert.Equal("immutable-authority", await LockedIssuerScalar(cs, "SELECT preserved_value FROM legacy_migration_internal.delta_fence;"));
            Assert.Equal(9007199254740993L, await LockedIssuerScalar(cs, "SELECT last_value FROM legacy_migration_internal.effect_seq;"));
            Assert.Equal(1L, await LockedIssuerScalar(cs, "SELECT count(*) FROM legacy_migration_internal.delta_source_backed_repair;"));
            return;
        }
        SourceBackedLocalRepairPreimage.RequireMatches(prior, await LockedIssuerRead(cs, schema));
        Assert.Equal(1L, await LockedIssuerScalar(cs, "SELECT count(*) FROM legacy_migration_internal.delta_journal;"));
        Assert.Equal(0L, await LockedIssuerScalar(cs, "SELECT count(*) FROM legacy_migration_internal.delta_source_backed_repair;"));
    }

    private sealed class ExecutionMaintenance : ISourceBackedLocalRepairMaintenanceLease
    {
        internal bool Quiescent { get; set; } = true;
        public Task RequireStillQuiescentAsync(HistoricalCurrentLocalObservation identity, CancellationToken cancellationToken)
        { return Quiescent ? Task.CompletedTask : Task.FromException(SourceBackedLocalRepairExecutionPermit.Invalid()); }
        public ValueTask DisposeAsync() { return ValueTask.CompletedTask; }
    }
}
