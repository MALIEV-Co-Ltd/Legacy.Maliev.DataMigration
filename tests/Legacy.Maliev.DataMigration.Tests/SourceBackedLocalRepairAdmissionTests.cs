using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed partial class DisposableDeltaProofVerifierTests
{
    [Theory]
    [InlineData("success")]
    [InlineData("signature")]
    [InlineData("preimage")]
    [InlineData("capture")]
    [InlineData("plan")]
    [InlineData("proof")]
    [InlineData("schema")]
    [InlineData("auth")]
    [InlineData("auth-hash")]
    [InlineData("identity")]
    [InlineData("metadata")]
    [InlineData("expiry")]
    [InlineData("claim-age")]
    [InlineData("pin")]
    [InlineData("aliased-pin")]
    [InlineData("old-journal")]
    public async Task Source_repair_admission_verifies_real_signatures_current_bindings_and_distinct_pinned_roles(string scenario)
    {
        AdmissionFixture state = await AdmissionState();
        SourceBackedLocalRepairAdmission admission = state.Admission;
        SourceBackedLocalRepairPreimageAttestation capsule = state.Capsule;
        SourceBackedLocalRepairSigningPins pins = state.Pins;
        if (scenario == "pin") { pins = pins with { PersistentPlanFingerprint = Hash('f') }; }
        if (scenario == "aliased-pin") { pins = pins with { EvidenceFingerprint = pins.AuthorizationFingerprint }; }
        if (scenario == "old-journal")
        {
            SourceBackedLocalRepairDatabasePreimage first = capsule.Databases[0];
            capsule = capsule with { Databases = [first with { Relations = first.Relations.Select(item => item.Table == "delta_journal" ? item with { RowMultisetSha256 = Hash('f') } : item).ToArray() }, .. capsule.Databases.Skip(1)] };
            using var signer = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
            capsule = capsule with { AttestationSignature = Convert.ToBase64String(signer.Sign(SourceBackedLocalRepairPreimageAttestationPolicy.CreatePayload(capsule))) };
        }
        admission = scenario switch
        {
            "preimage" => admission with { PreimageSha256 = Hash('f') },
            "capture" => admission with { SourceCaptureSha256 = Hash('f') },
            "plan" => admission with { PersistentPlanSha256 = Hash('f') },
            "proof" => admission with { DisposableReceiptSha256 = Hash('f') },
            "schema" => admission with { SchemaPlanSha256 = Hash('f') },
            "auth" => admission with { AuthorizationId = Guid.NewGuid() },
            "auth-hash" => admission with { AuthorizationSha256 = Hash('f') },
            "identity" => admission with { TargetIdentity = admission.TargetIdentity with { VolumeMountpoint = "/changed" } },
            "metadata" => admission with { InitialMetadata = admission.InitialMetadata.Select((item, index) => index == 0 ? item with { FingerprintSha256 = Hash('f') } : item).ToArray() },
            "claim-age" => admission with { ClaimExpiresAtUtc = admission.ClaimExpiresAtUtc.AddDays(1) },
            _ => admission,
        };
        admission = SignAdmission(admission);
        if (scenario == "signature") { admission = admission with { AttestationSignature = "forged" }; }
        DateTimeOffset now = scenario == "expiry" ? state.Fixture.Now.AddMinutes(5) : state.Fixture.Now;
        void verify()
        {
            SourceBackedLocalRepairAdmissionPolicy.Verify(admission, capsule, state.Plans, state.Fixture.ProofResult,
                state.Fixture.Schema, state.Authorization, state.Identity, state.Fixture.Trust, pins, now);
        }
        if (scenario == "success")
        {
            verify();
            var roundtrip = JsonSerializer.Deserialize<SourceBackedLocalRepairAdmission>(JsonSerializer.Serialize(admission))!;
            SourceBackedLocalRepairAdmissionPolicy.Verify(roundtrip, capsule, state.Plans, state.Fixture.ProofResult, state.Fixture.Schema,
                state.Authorization, state.Identity, state.Fixture.Trust, pins, now);
            Assert.False(SourceBackedLocalRepairAdmission.AuthorizesExecution);
            Assert.False(SourceBackedLocalRepairAdmissionBundle.AuthorizesExecution);
            Assert.Equal(23, admission.InitialMetadata.Count);
            Assert.NotEqual(Hash('c'), admission.InitialMetadata[0].FingerprintSha256);
        }
        else { _ = Assert.Throws<DeltaExecutionException>(verify); }
    }

    [Theory]
    [InlineData("success")]
    [InlineData("caller-claim")]
    [InlineData("old-metadata")]
    [InlineData("system")]
    [InlineData("unretained")]
    [InlineData("policy")]
    [InlineData("expiry-during-read")]
    [InlineData("target-during-read")]
    [InlineData("superseded-original")]
    public async Task Source_repair_admission_reads_and_authenticates_retained_claim_without_accepting_caller_claim(string scenario)
    {
        AdmissionFixture state = await AdmissionState();
        var gateway = new AdmissionGateway(state.Fixture.Now);
        var claims = new SourceBackedLocalRepairClaimStore(gateway);
        SourceBackedLocalRepairClaim expected = SourceBackedLocalRepairAdmissionPolicy.ExpectedClaim(state.Admission);
        if (scenario != "unretained")
        {
            var retainer = new SourceBackedLocalRepairRenewalStore(gateway, claims,
                new(gateway, claims, state.Fixture.Trust, state.Pins.AuthorizationFingerprint, state.Pins.EvidenceFingerprint),
                state.Fixture.Trust, state.Pins, SourceRepairTerminalPin(), _ => Task.FromResult(state.Identity), new AdmissionClock(state.Fixture.Now));
            await retainer.RetainOriginalAsync(state.Admission, state.Capsule, state.Authorization,
                state.Plans, state.Fixture.ProofResult, state.Fixture.Schema, CancellationToken.None);
            _ = await claims.ReserveAsync(expected, state.Fixture.Now, CancellationToken.None);
        }
        if (scenario is "caller-claim" or "old-metadata" or "system")
        {
            SourceBackedLocalRepairClaim changed = scenario switch
            {
                "old-metadata" => expected with { InitialMetadata = expected.InitialMetadata.Select((item, index) => index == 0 ? item with { FingerprintSha256 = Hash('f') } : item).ToArray() },
                "system" => expected with { SystemIdentifierSha256 = Hash('f') },
                _ => expected with { SourceCaptureSha256 = Hash('f') },
            };
            // A forged body plus internally consistent reservation hashes must still fail the
            // independent signed admission comparison. Real retained storage forbids these rewrites.
            gateway.ForgeClaimAndReservations(changed);
        }
        if (scenario == "policy") { gateway.SafePolicy = false; }
        if (scenario == "superseded-original")
        {
            // Even a still-fresh original permit must fail closed as soon as epoch1 is
            // retained. An unreadable newer object cannot restore superseded authority.
            _ = await gateway.CreateOnlyAsync("source-backed-local-repair/v1/renewals/" +
                expected.ClaimId.ToString("D") + "/00000001", [1], CancellationToken.None);
        }
        int observed = 0;
        var clock = new AdmissionClock(state.Fixture.Now);
        var store = new SourceBackedLocalRepairAdmissionStore(claims, state.Fixture.Trust, state.Pins, _ =>
        {
            observed++;
            if (observed == 2 && scenario == "expiry-during-read") { clock.Now = state.Fixture.Now.AddMinutes(5); }
            return Task.FromResult(observed == 2 && scenario == "target-during-read" ? state.Identity with { ContainerId = Hash('f') } : state.Identity);
        }, clock, terminalPin: SourceRepairTerminalPin());
        Task<SourceBackedLocalRepairClaim> verification = store.VerifyRetainedAsync(state.Admission, state.Capsule, state.Plans,
            state.Fixture.ProofResult, state.Fixture.Schema, state.Authorization, CancellationToken.None);
        if (scenario == "success")
        {
            SourceBackedLocalRepairClaim result = await verification;
            Assert.Equal(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(result));
            Assert.Equal(4, observed);
            _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => claims.ReserveAsync(expected, state.Fixture.Now, CancellationToken.None));
        }
        else { _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => verification); }
    }

    [Fact]
    public async Task Source_repair_trusted_admission_creation_invokes_locked_exact23_issuer_and_retains_matching_claim()
    {
        await using PostgreSqlContainer container = new PostgreSqlBuilder("postgres:18-alpine")
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 384L * 1024 * 1024;
                parameters.HostConfig.MemorySwap = 384L * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 500000000;
            }).Build();
        await container.StartAsync();
        string admin = new NpgsqlConnectionStringBuilder(container.GetConnectionString()) { Host = "127.0.0.1", Database = "postgres", Pooling = false, Enlist = false }.ConnectionString;
        string system = (string)(await LockedIssuerScalar(admin, "SELECT system_identifier::text FROM pg_control_system();"))!;
        string systemHash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(system))).ToLowerInvariant();
        AdmissionFixture state = await AdmissionState(systemHash, physicalTargetHashes: true);
        var expected = new List<SourceBackedLocalRepairDatabasePreimage>();
        foreach (DatabaseSchemaPlan database in state.Fixture.Schema.Databases)
        {
            await LockedIssuerExecute(admin, $"CREATE DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(database.Database)};");
            string cs = LockedIssuerDatabase(admin, database.Database);
            await using (var connection = new NpgsqlConnection(cs))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync();
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
            { _ = await QuotationDispositionTargetBootstrap.ExecuteAsync(database, cs, database.Database, systemHash, CancellationToken.None); }
            else { await LockedIssuerExecute(cs, "INSERT INTO public.items(id) VALUES(1);"); }
            await LockedIssuerExecute(cs, """
                CREATE SCHEMA legacy_migration_internal;
                CREATE TABLE legacy_migration_internal.delta_fence(database_name text NOT NULL);
                INSERT INTO legacy_migration_internal.delta_fence VALUES('preserved');
                CREATE TABLE legacy_migration_internal.delta_journal(reconciliation_sha256 text);
                INSERT INTO legacy_migration_internal.delta_journal VALUES('settled');
                CREATE TABLE legacy_migration_internal.effects(id bigint PRIMARY KEY);
                INSERT INTO legacy_migration_internal.effects VALUES(9007199254740993);
                CREATE SEQUENCE legacy_migration_internal.authority_seq AS bigint START 9007199254740993 CACHE 7;
                """);
            await using (var connection = new NpgsqlConnection(cs))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(System.Data.IsolationLevel.Serializable);
                await PostgreSqlSourceBackedLocalRepair.StageAsync(connection, transaction, CancellationToken.None);
                await transaction.CommitAsync();
            }
            expected.Add(await LockedIssuerRead(cs, database));
        }
        var clock = new AdmissionClock(state.Fixture.Now);
        var maintenance = new LockedIssuerMaintenance(async check =>
        {
            if (check == 2)
            {
                Assert.Equal(23L, await LockedIssuerScalar(admin, "SELECT count(DISTINCT l.database) FROM pg_locks l JOIN pg_database d ON d.oid=l.database WHERE l.granted AND l.mode='ShareRowExclusiveLock' AND d.datname<>'postgres';"));
            }
        });
        var issuer = new SourceBackedLocalRepairLockedIssuer(admin, _ => Task.FromResult(state.Identity), maintenance, clock);
        var gateway = new AdmissionGateway(state.Fixture.Now);
        var store = new SourceBackedLocalRepairAdmissionStore(new(gateway), state.Fixture.Trust, state.Pins, _ => Task.FromResult(state.Identity), clock,
            terminalPin: SourceRepairTerminalPin());
        using var signer = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        SourceBackedLocalRepairAdmissionBundle bundle = await store.CreateAsync(issuer, state.Plans, state.Fixture.ProofResult,
            state.Fixture.Schema, state.Authorization, expected, state.Fixture.Now.AddMinutes(5), signer, CancellationToken.None);
        Assert.Equal(SourceBackedLocalRepairAdmissionPolicy.ComputeSha256(bundle.Admission), bundle.VerifiedClaim.AdmissionSha256);
        Assert.Equal(23, bundle.VerifiedClaim.InitialMetadata.Count);
        Assert.Equal(SourceBackedLocalRepairAdmissionPolicy.Metadata(bundle.Capsule.Databases), bundle.Admission.InitialMetadata);
        Assert.Equal(6, gateway.Count);
        Assert.Equal(2, maintenance.Checks);
        foreach (DatabaseSchemaPlan database in state.Fixture.Schema.Databases)
        {
            SourceBackedLocalRepairPreimage.RequireMatches(expected.Single(item => item.Database == database.Database),
                await LockedIssuerRead(LockedIssuerDatabase(admin, database.Database), database));
        }
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => store.CreateAsync(issuer, state.Plans, state.Fixture.ProofResult,
            state.Fixture.Schema, state.Authorization, expected, state.Fixture.Now.AddMinutes(5), signer, CancellationToken.None));
    }

    private async Task<AdmissionFixture> AdmissionState(string? systemHash = null, bool physicalTargetHashes = false)
    {
        Fixture fixture = AddSourceRepairTerminalTrust(await CreateAsync(pairedTransition: true, quotationDisposition: true, captured: true, historicalLocal: true,
            localSystemHash: systemHash, physicalTargetHashes: physicalTargetHashes));
        var plans = new PairedCapturedDeltaPlans(fixture.ProofPlan, fixture.LocalPlan);
        using var authorizationSigner = new P256MigrationEvidenceSigner("local-transition-authorization", _authorizationKey.ExportECPrivateKeyPem());
        using var evidenceSigner = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        PairedLocalTransitionAuthorization authorization = PairedLocalTransitionAuthorizationPolicy.Produce(plans, fixture.ProofResult,
            fixture.Schema, fixture.Trust, fixture.LocalPlan.TargetAuthority!, fixture.LocalPlan.TargetObservationSha256,
            fixture.LocalPlan.QuotationTransitionSchemaSha256!, fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(5), authorizationSigner);
        var identity = new HistoricalCurrentLocalObservation(Hash('7'), fixture.LocalPlan.TargetGeneration,
            "legacy-maliev-exact23-postgres-data", DateTimeOffset.FromUnixTimeMilliseconds(3),
            "/var/lib/docker/volumes/legacy-maliev-exact23-postgres-data/_data", "/var/lib/postgresql",
            "/var/lib/postgresql/18/docker", fixture.LocalPlan.TargetAuthority!.SystemIdentifierSha256);
        SourceBackedLocalRepairDatabasePreimage[] snapshots = [.. fixture.Schema.Databases.Select(database => new SourceBackedLocalRepairDatabasePreimage(database.Database, Hash('a'), Hash('b'),
            [new("legacy_migration_internal", "delta_fence", 1, Hash('c'), Hash('d')),
                new("legacy_migration_internal", "delta_journal", 1, Hash('c'), Hash('d')),
                new("legacy_migration_internal", "effects", 1, Hash('c'), Hash('d')),
                new("public", "source", 1, Hash('c'), Hash('d'))], []))];
        SourceBackedLocalRepairPreimageAttestation capsule = SourceBackedLocalRepairPreimageAttestationPolicy.Produce(plans, fixture.ProofResult,
            fixture.Schema, authorization, identity, snapshots, fixture.Trust, fixture.Now, fixture.Now.AddMinutes(5), evidenceSigner);
        var pins = new SourceBackedLocalRepairSigningPins(Fingerprint(fixture.Trust, fixture.LocalPlan.AttestationKeyId),
            Fingerprint(fixture.Trust, fixture.ProofPlan.AttestationKeyId), authorizationSigner.PublicKeyFingerprintSha256, evidenceSigner.PublicKeyFingerprintSha256);
        var admission = new SourceBackedLocalRepairAdmission("1.0", Guid.NewGuid(), Guid.NewGuid(),
            SourceBackedLocalRepairPreimageAttestationPolicy.ComputeSha256(capsule), capsule.SourceCaptureSha256,
            capsule.PersistentPlanSha256, capsule.DisposablePlanSha256, capsule.DisposableReceiptSha256,
            fixture.LocalPlan.SchemaPlanSha256, authorization.AuthorizationId, SourceBackedLocalRepairContinuationStore.AuthorizationHash(authorization),
            identity, SourceBackedLocalRepairAdmissionPolicy.Metadata(snapshots), fixture.Now,
            fixture.Now.Add(ImmutableRolloverClaimStore.MaximumClaimAge), fixture.Now, fixture.Now.AddMinutes(5), evidenceSigner.KeyId, null);
        return new(fixture, plans, authorization, identity, capsule, pins, SignAdmission(admission));
    }

    private SourceBackedLocalRepairAdmission SignAdmission(SourceBackedLocalRepairAdmission value)
    {
        using var signer = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        return value with { AttestationSignature = Convert.ToBase64String(signer.Sign(SourceBackedLocalRepairAdmissionPolicy.Payload(value))) };
    }

    private static string Fingerprint(ReceiptAttestationTrustStore trust, string keyId)
    {
        Assert.True(trust.TryGetPublicKeyFingerprintSha256(keyId, out string value));
        return value;
    }

    private sealed record AdmissionFixture(Fixture Fixture, PairedCapturedDeltaPlans Plans, PairedLocalTransitionAuthorization Authorization,
        HistoricalCurrentLocalObservation Identity, SourceBackedLocalRepairPreimageAttestation Capsule, SourceBackedLocalRepairSigningPins Pins,
        SourceBackedLocalRepairAdmission Admission);

    private sealed class AdmissionClock(DateTimeOffset now) : TimeProvider
    {
        internal DateTimeOffset Now { get; set; } = now;
        internal bool FollowWallClock { get; set; }
        public override DateTimeOffset GetUtcNow()
        {
            return FollowWallClock ? DateTimeOffset.UtcNow : Now;
        }
    }

    private sealed class AdmissionGateway(DateTimeOffset now, TimeProvider? clock = null) : IRolloverClaimObjectGateway
    {
        private readonly ConcurrentDictionary<string, RolloverClaimObject> _objects = new(StringComparer.Ordinal);
        private long _generation;
        internal bool SafePolicy { get; set; } = true;
        internal int Count => _objects.Count;
        public Task<RolloverClaimBucketPolicy> ReadPolicyAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(new RolloverClaimBucketPolicy(SafePolicy, 31557600, true, false));
        }

        public Task<RolloverClaimObject?> ReadAsync(string name, CancellationToken cancellationToken)
        {
            return Task.FromResult(_objects.TryGetValue(name, out RolloverClaimObject? value) ? value : null);
        }

        public Task<RolloverClaimObject> CreateOnlyAsync(string name, byte[] content, CancellationToken cancellationToken)
        {
            DateTimeOffset createdAt = clock?.GetUtcNow() ?? now;
            var value = new RolloverClaimObject(Interlocked.Increment(ref _generation), createdAt, createdAt.AddDays(366), [.. content]);
            return Task.FromResult(_objects.TryAdd(name, value) ? value : throw new DeltaExecutionException("delta_rollover_claim_conflict", "Already reserved."));
        }
        internal void ForgeClaimAndReservations(SourceBackedLocalRepairClaim claim)
        {
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(claim);
            string hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            foreach (string name in _objects.Keys)
            {
                _objects[name] = _objects[name] with
                {
                    Content = name.Contains("/active/", StringComparison.Ordinal)
                    ? bytes : JsonSerializer.SerializeToUtf8Bytes(new { SchemaVersion = "1.0", claim.ClaimId, ClaimSha256 = hash })
                };
            }
        }
    }
}
