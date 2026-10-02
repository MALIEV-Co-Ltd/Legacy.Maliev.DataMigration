using System.Data;
using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed partial class DisposableDeltaProofVerifierTests
{
    [Theory]
    [InlineData("success")]
    [InlineData("forged-authorization")]
    [InlineData("identity-change")]
    [InlineData("late-23-preimage")]
    [InlineData("late-23-database")]
    [InlineData("late-23-physical")]
    [InlineData("late-23-marker-missing")]
    [InlineData("late-23-marker-altered")]
    [InlineData("late-23-marker-nonempty")]
    [InlineData("expiry")]
    [InlineData("cancellation")]
    [InlineData("maintenance-lost")]
    [InlineData("untrusted-signer")]
    [InlineData("wrong-system")]
    [InlineData("remote")]
    [InlineData("inventory")]
    public async Task Source_repair_locked_issuer_holds_exact23_and_releases_every_lease_without_data_changes(string scenario)
    {
        await using PostgreSqlContainer container = new PostgreSqlBuilder("postgres:18-alpine").Build();
        await container.StartAsync();
        string admin = new NpgsqlConnectionStringBuilder(container.GetConnectionString())
        {
            Host = "127.0.0.1",
            Database = "postgres",
            Pooling = false,
            Enlist = false,
        }.ConnectionString;
        string system = (string)(await LockedIssuerScalar(admin, "SELECT system_identifier::text FROM pg_control_system();"))!;
        string systemHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(system))).ToLowerInvariant();
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, historicalLocal: true, localSystemHash: systemHash, physicalTargetHashes: true);
        var plans = new PairedCapturedDeltaPlans(fixture.ProofPlan, fixture.LocalPlan);
        using var authorizationSigner = new P256MigrationEvidenceSigner("local-transition-authorization", _authorizationKey.ExportECPrivateKeyPem());
        using var evidenceSigner = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        using var wrongSigner = new P256MigrationEvidenceSigner("proof-evidence", _continuityKey.ExportECPrivateKeyPem());
        PairedLocalTransitionAuthorization authorization = PairedLocalTransitionAuthorizationPolicy.Produce(
            plans, fixture.ProofResult, fixture.Schema, fixture.Trust, fixture.LocalPlan.TargetAuthority!,
            fixture.LocalPlan.TargetObservationSha256, fixture.LocalPlan.QuotationTransitionSchemaSha256!,
            fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(5), authorizationSigner);
        var identity = new HistoricalCurrentLocalObservation(Hash('7'), fixture.LocalPlan.TargetGeneration,
            "legacy-maliev-exact23-postgres-data", DateTimeOffset.FromUnixTimeMilliseconds(3),
            "/var/lib/docker/volumes/legacy-maliev-exact23-postgres-data/_data", "/var/lib/postgresql",
            "/var/lib/postgresql/18/docker", systemHash);
        var baseline = new List<SourceBackedLocalRepairDatabasePreimage>();
        foreach (DatabaseSchemaPlan database in fixture.Schema.Databases)
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
                CREATE TABLE legacy_migration_internal.preserved_rows(id bigint PRIMARY KEY, value text NOT NULL);
                INSERT INTO legacy_migration_internal.preserved_rows VALUES(9007199254740993,'preserved');
                CREATE SEQUENCE legacy_migration_internal.authority_seq AS bigint START 9007199254740993 CACHE 7;
                ALTER SEQUENCE legacy_migration_internal.authority_seq OWNED BY legacy_migration_internal.preserved_rows.id;
                SELECT setval('legacy_migration_internal.authority_seq',9007199254740993,false);
                """);
            await using (var stagingConnection = new NpgsqlConnection(cs))
            {
                await stagingConnection.OpenAsync();
                await using NpgsqlTransaction stagingTransaction = await stagingConnection.BeginTransactionAsync(IsolationLevel.Serializable);
                await PostgreSqlSourceBackedLocalRepair.StageAsync(stagingConnection, stagingTransaction, CancellationToken.None);
                await stagingTransaction.CommitAsync();
            }
            if (scenario == "late-23-marker-missing" && database.Database == DatabaseInventory.ActiveDatabases[^1])
            {
                await LockedIssuerExecute(cs, "DROP TABLE legacy_migration_internal.delta_source_backed_repair;");
            }
            if (scenario == "late-23-marker-altered" && database.Database == DatabaseInventory.ActiveDatabases[^1])
            {
                await LockedIssuerExecute(cs, "ALTER TABLE legacy_migration_internal.delta_source_backed_repair ADD COLUMN unreviewed boolean;");
            }
            if (scenario == "late-23-marker-nonempty" && database.Database == DatabaseInventory.ActiveDatabases[^1])
            {
                await LockedIssuerExecute(cs, """
                    INSERT INTO legacy_migration_internal.delta_source_backed_repair VALUES(
                        'preserved','preserved','00000000-0000-0000-0000-000000000001',
                        'preserved','preserved','preserved',1,'preserved','preserved',
                        'preserved','preserved','preserved');
                    """);
            }
            if (scenario == "late-23-physical" && database.Database == DatabaseInventory.ActiveDatabases[^1])
            {
                TableCopyPlan table = database.Tables[0];
                await LockedIssuerExecute(cs, $"ALTER TABLE {PostgreSqlShadowTarget.QuoteIdentifier(table.TargetSchema)}.{PostgreSqlShadowTarget.QuoteIdentifier(table.TargetTable)} ADD COLUMN unreviewed boolean NOT NULL DEFAULT false;");
            }
            baseline.Add(await LockedIssuerRead(cs, database));
        }
        SourceBackedLocalRepairDatabasePreimage[] expected = [.. baseline];
        if (scenario == "late-23-preimage") { expected[^1] = expected[^1] with { CatalogObjectsSha256 = Hash('f') }; }
        if (scenario == "inventory") { expected = expected.Reverse().ToArray(); }
        if (scenario == "forged-authorization") { authorization = authorization with { AttestationSignature = "forged" }; }
        if (scenario == "late-23-database")
        {
            await LockedIssuerExecute(admin, $"ALTER DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(DatabaseInventory.ActiveDatabases[^1])} ALLOW_CONNECTIONS false;");
        }
        using var cancellation = new CancellationTokenSource();
        var clock = new LockedIssuerClock(fixture.Now);
        int observations = 0;
        var maintenance = new LockedIssuerMaintenance(async check =>
        {
            if (check != 2) { return; }
            // The final prerequisite check happens with every transaction still open.
            Assert.Equal(23L, await LockedIssuerScalar(admin, """
                SELECT count(DISTINCT l.database) FROM pg_locks l JOIN pg_database d ON d.oid=l.database
                WHERE l.granted AND l.mode='ShareRowExclusiveLock' AND d.datname<>'postgres';
                """));
            if (scenario == "expiry") { clock.Now = fixture.Now.AddMinutes(5); }
            if (scenario == "cancellation") { await cancellation.CancelAsync(); }
            if (scenario == "maintenance-lost") { throw new InvalidOperationException("maintenance lost"); }
        });
        string endpoint = scenario == "remote"
            ? new NpgsqlConnectionStringBuilder(admin) { Host = "localhost" }.ConnectionString : admin;
        var issuer = new SourceBackedLocalRepairLockedIssuer(endpoint, _ =>
        {
            observations++;
            return Task.FromResult(scenario == "identity-change" && observations == 2
                ? identity with { VolumeMountpoint = "/changed" }
                : scenario == "wrong-system" ? identity with { SystemIdentifierSha256 = Hash('f') } : identity);
        }, maintenance, clock);
        try
        {
            Task<SourceBackedLocalRepairPreimageAttestation> issue = issuer.IssueAsync(plans,
                fixture.ProofResult, fixture.Schema, authorization, expected, fixture.Trust,
                fixture.Now.AddMinutes(5), scenario == "untrusted-signer" ? wrongSigner : evidenceSigner,
                cancellation.Token);
            if (scenario == "success")
            {
                SourceBackedLocalRepairPreimageAttestation attestation = await issue;
                Assert.Equal(2, observations);
                Assert.Equal(2, maintenance.Checks);
                SourceBackedLocalRepairPreimageAttestationPolicy.Verify(attestation, plans, fixture.ProofResult,
                    fixture.Schema, authorization, identity, baseline, fixture.Trust, fixture.Now);
                Assert.False(SourceBackedLocalRepairLockedIssuer.AuthorizesExecution);
                Assert.False(SourceBackedLocalRepairPreimageAttestation.AuthorizesExecution);
            }
            else
            {
                switch (scenario)
                {
                    case "cancellation":
                        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => issue);
                        break;
                    case "late-23-database":
                        Assert.Equal("55000", (await Assert.ThrowsAsync<PostgresException>(() => issue)).SqlState);
                        break;
                    case "remote":
                        Assert.Equal("local_archive_connection", (await Assert.ThrowsAsync<MigrationExecutionException>(() => issue)).Code);
                        break;
                    case "maintenance-lost":
                        Assert.Equal("maintenance lost", (await Assert.ThrowsAsync<InvalidOperationException>(() => issue)).Message);
                        break;
                    default:
                        string code = scenario switch
                        {
                            "forged-authorization" or "expiry" => "delta_paired_local_transition_authorization_invalid",
                            "late-23-preimage" => "delta_source_repair_preimage_changed",
                            "untrusted-signer" => "delta_source_repair_preimage_attestation_invalid",
                            "late-23-marker-missing" or "late-23-marker-altered" or "late-23-marker-nonempty" => "delta_source_repair_marker_catalog_invalid",
                            _ => "delta_source_repair_locked_issuer_invalid",
                        };
                        Assert.Equal(code, (await Assert.ThrowsAsync<DeltaExecutionException>(() => issue)).Code);
                        break;
                }
            }
        }
        finally
        {
            if (scenario == "late-23-database")
            {
                await LockedIssuerExecute(admin, $"ALTER DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(DatabaseInventory.ActiveDatabases[^1])} ALLOW_CONNECTIONS true;");
            }
        }
        Assert.Equal(0L, await LockedIssuerScalar(admin, """
            SELECT count(*) FROM pg_locks l JOIN pg_database d ON d.oid=l.database
            WHERE l.granted AND l.mode='ShareRowExclusiveLock' AND d.datname<>'postgres';
            """));
        Assert.Equal(0L, await LockedIssuerScalar(admin, "SELECT count(*) FROM pg_stat_activity WHERE datname<>'postgres' AND backend_type='client backend';"));
        if (maintenance.Acquired) { Assert.True(maintenance.Disposed); }
        foreach (var (database, original) in fixture.Schema.Databases.Zip(baseline))
        {
            SourceBackedLocalRepairPreimage.RequireMatches(original,
                await LockedIssuerRead(LockedIssuerDatabase(admin, database.Database), database));
        }
    }

    private sealed class LockedIssuerClock(DateTimeOffset now) : TimeProvider
    {
        internal DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() { return Now; }
    }

    private sealed class LockedIssuerMaintenance(Func<int, Task> check)
        : ISourceBackedLocalRepairMaintenance, ISourceBackedLocalRepairMaintenanceLease
    {
        internal bool Acquired { get; private set; }
        internal bool Disposed { get; private set; }
        internal int Checks { get; private set; }
        public Task<ISourceBackedLocalRepairMaintenanceLease> AcquireAsync(HistoricalCurrentLocalObservation identity, CancellationToken cancellationToken)
        {
            Acquired = true;
            return Task.FromResult<ISourceBackedLocalRepairMaintenanceLease>(this);
        }
        public Task RequireStillQuiescentAsync(HistoricalCurrentLocalObservation identity, CancellationToken cancellationToken) { return check(++Checks); }
        public ValueTask DisposeAsync() { Disposed = true; return ValueTask.CompletedTask; }
    }

    private static string LockedIssuerDatabase(string admin, string database)
    {
        return new NpgsqlConnectionStringBuilder(admin) { Database = database }.ConnectionString;
    }

    private static async Task<SourceBackedLocalRepairDatabasePreimage> LockedIssuerRead(string cs, DatabaseSchemaPlan schema)
    {
        await using var connection = new NpgsqlConnection(cs);
        await connection.OpenAsync();
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead);
        SourceBackedLocalRepairDatabasePreimage preimage = await SourceBackedLocalRepairPreimage.InspectAsync(connection, transaction, schema, CancellationToken.None);
        await transaction.RollbackAsync();
        return preimage;
    }

    private static async Task LockedIssuerExecute(string cs, string sql)
    {
        await using var connection = new NpgsqlConnection(cs);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static async Task<object?> LockedIssuerScalar(string cs, string sql)
    {
        await using var connection = new NpgsqlConnection(cs);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        return await command.ExecuteScalarAsync();
    }
}
