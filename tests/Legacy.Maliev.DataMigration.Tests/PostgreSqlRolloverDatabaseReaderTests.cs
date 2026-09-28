using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlRolloverDatabaseReaderTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task PriorDatabase_RequiresMatchingFenceJournalRowsAndSchema()
    {
        const string database = "ContactRequest";
        await ExecuteAsync(fixture.ConnectionString, "CREATE DATABASE \"ContactRequest\";");
        try
        {
            string databaseConnection = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
            {
                Database = database,
                Pooling = false,
            }.ConnectionString;
            var temporarySchema = new DatabaseSchemaPlan(database, "1", Hash('a'), Hash('b'), []);
            string physical;
            await using (var connection = new NpgsqlConnection(databaseConnection))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.RepeatableRead);
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection,
                    transaction, ownsResources: false);
                physical = await inspector.InspectSchemaAsync(temporarySchema,
                    CancellationToken.None);
                await transaction.RollbackAsync();
            }
            DatabaseSchemaPlan schema = temporarySchema with { TargetSchemaSha256 = physical };
            DateTimeOffset now = DateTimeOffset.UtcNow;
            DeltaSynchronizationPlan historicalPlan = Plan("docker:" + Hash('1'), now);
            await using (var connection = new NpgsqlConnection(databaseConnection))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable);
                await PostgreSqlDeltaMetadataProvisioner.ProvisionDatabaseAsync(connection,
                    transaction, historicalPlan, schema, CancellationToken.None);
                await using var journal = new NpgsqlCommand("""
                    INSERT INTO legacy_migration_internal.delta_journal
                        (plan_sha256,plan_id,source_cutoff_utc,target_observation_sha256,
                         operations_sha256,reconciliation_sha256,committed_at_utc)
                    VALUES ($1,$2,$3,$4,$5,$6,$7);
                    """, connection, transaction);
                _ = journal.Parameters.AddWithValue(
                    DeltaSynchronizationPlanCanonicalizer.ComputeSha256(historicalPlan));
                _ = journal.Parameters.AddWithValue(historicalPlan.PlanId);
                _ = journal.Parameters.AddWithValue(historicalPlan.SourceCutoffUtc);
                _ = journal.Parameters.AddWithValue(historicalPlan.TargetObservationSha256);
                _ = journal.Parameters.AddWithValue(Hash('c'));
                _ = journal.Parameters.AddWithValue(Hash('d'));
                _ = journal.Parameters.AddWithValue(now);
                _ = await journal.ExecuteNonQueryAsync();
                await transaction.CommitAsync();
            }
            string adminConnection = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
            {
                Host = "127.0.0.1",
                Database = "postgres",
                Pooling = false,
            }.ConnectionString;
            var metadataInspector = new HistoricalPostgreSqlLocalMetadataInspector(adminConnection);
            HistoricalLocalMetadataSnapshot metadata = await metadataInspector.ReadDatabaseAsync(
                database, CancellationToken.None);
            string fingerprint = HistoricalLocalMetadataReceiptBinder.ComputePriorFingerprint(
                metadata);
            var evidence = new DatabaseReconciliationEvidence(database, schema.SourceSchemaSha256,
                physical, []);
            var historicalReceipt = new Exact23DeltaReconciliationResult("1.2",
                historicalPlan.PlanId,
                DeltaSynchronizationPlanCanonicalizer.ComputeSha256(historicalPlan),
                historicalPlan.SourceCutoffUtc, now, [evidence], "test", null);
            DeltaSynchronizationPlan futurePlan = Plan("docker:" + Hash('2'), now);
            ImmutableRolloverClaim claim = new("1.0", Guid.NewGuid(), Hash('a'), Hash('b'),
                Hash('c'), DeltaSynchronizationPlanCanonicalizer.ComputeSha256(futurePlan),
                futurePlan.TargetGeneration, "legacy-maliev-exact23-postgres-data",
                now.AddDays(-1), Hash('e'),
                [.. DatabaseInventory.ActiveDatabases.Select(item =>
                    new HistoricalLocalMetadataBinding(item,
                        PairedLocalTransitionMetadataState.SettledPrior,
                        item == database ? fingerprint : Hash('f')))], now, now.AddDays(1));
            var reader = new PostgreSqlRolloverDatabaseReader(adminConnection);
            var store = new ImmutableRolloverClaimStore(new UnusedGateway());
            var trust = new ReceiptAttestationTrustStore([]);
            var schemaPlan = new FreshSchemaPlan("2.0", now, Hash('9'), [schema]);
            HistoricalLocalRolloverDatabaseState prior = await reader.ReadAsync(database,
                claim, historicalPlan, historicalReceipt, schemaPlan, futurePlan,
                historicalReceipt, schemaPlan, store, trust, 0, now, CancellationToken.None);
            Assert.Equal(HistoricalLocalRolloverDatabasePhase.Prior, prior.Phase);
            Assert.Equal(fingerprint, prior.PriorMetadataSha256);
            DeltaExecutionException changed = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                reader.ReadAsync(database, claim with
                {
                    InitialMetadata = [.. claim.InitialMetadata.Select(item => item.Database == database
                        ? item with { FingerprintSha256 = Hash('0') } : item)],
                }, historicalPlan, historicalReceipt, schemaPlan, futurePlan,
                historicalReceipt, schemaPlan, store, trust, 0, now, CancellationToken.None));
            Assert.Equal("delta_rollover_database_state_invalid", changed.Code);
        }
        finally
        {
            await ExecuteAsync(fixture.ConnectionString,
                "DROP DATABASE \"ContactRequest\" WITH (FORCE);");
        }
    }

    private static DeltaSynchronizationPlan Plan(string generation, DateTimeOffset now)
    {
        return new("1.1", Guid.NewGuid(), new string('1', 40), now.AddHours(-1),
            Hash('e'), Hash('f'), Hash('a'), "local-aspire", "legacy-postgres-local",
            generation, Hash('b'), Hash('c'), Hash('d'), now.AddMinutes(-1), [], "test", null);
    }

    private static async Task ExecuteAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    private sealed class UnusedGateway : IRolloverClaimObjectGateway
    {
        public Task<RolloverClaimBucketPolicy> ReadPolicyAsync(CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("Prior reader must not call the claim gateway.");
        }

        public Task<RolloverClaimObject> CreateOnlyAsync(string name, byte[] content,
            CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("Prior reader must not create a claim object.");
        }

        public Task<RolloverClaimObject?> ReadAsync(string name, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("Prior reader must not call the claim gateway.");
        }
    }
}
