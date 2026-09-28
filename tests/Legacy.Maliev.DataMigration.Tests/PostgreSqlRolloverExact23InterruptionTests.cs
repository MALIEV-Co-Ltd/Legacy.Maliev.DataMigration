using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlRolloverExact23InterruptionTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task SequentialDatabaseCommits_AreAtomicAtZeroOneTwentyTwoAndTwentyThree()
    {
        string[] names = [.. DatabaseInventory.ActiveDatabases];
        var created = new List<string>();
        try
        {
            foreach (string name in names)
            {
                await ExecuteAsync(fixture.ConnectionString,
                    $"CREATE DATABASE {Quote(name)};");
                created.Add(name);
            }
            DateTimeOffset now = DateTimeOffset.UtcNow;
            DeltaSynchronizationPlan priorPlan = Plan("docker:" + Hash('1'), now);
            DeltaSynchronizationPlan futurePlan = Plan("docker:" + Hash('2'), now);
            string planSha = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(futurePlan);
            ImmutableRolloverClaim claim = new("1.0", Guid.NewGuid(), Hash('3'),
                Hash('4'), Hash('5'), planSha, futurePlan.TargetGeneration,
                "legacy-maliev-exact23-postgres-data", now.AddDays(-1), Hash('6'),
                [.. names.Select(name => new HistoricalLocalMetadataBinding(name,
                    PairedLocalTransitionMetadataState.SettledPrior, Hash('7')))],
                now.AddMinutes(-1), now.AddDays(1));
            var continuation = new HistoricalLocalMixedContinuation("1.0", claim.ClaimId,
                claim.InitialAttestationSha256, claim.FuturePlanSha256,
                claim.TargetGeneration, Guid.NewGuid(), 1,
                [.. names.Select(name => new HistoricalLocalRolloverDatabaseState(name,
                    HistoricalLocalRolloverDatabasePhase.Prior, Hash('7'), null))],
                now.AddMinutes(-1), now.AddMinutes(10), "test", null);
            var authorization = new PairedLocalTransitionAuthorization("1.0",
                continuation.AuthorizationId, Guid.NewGuid(), planSha, Hash('8'),
                Hash('9'), Hash('a'), Hash('b'), new DeltaTargetAuthority(
                    DeltaTargetAuthorityKind.LocalAspire,
                    "aspire://legacy-postgres-main-local/persistent-test", Hash('c')),
                Hash('d'), now.AddMinutes(-1), now.AddMinutes(10), "test", null);
            var permit = new LocalRolloverAdoptionPermit(claim, continuation,
                authorization, TimeProvider.System,
                _ => Task.FromResult(new HistoricalCurrentLocalObservation(
                    claim.TargetGeneration.Split(':')[1], claim.TargetGeneration,
                    claim.VolumeName, claim.VolumeCreatedAtUtc, "/volume", "/data", "/data",
                    claim.SystemIdentifierSha256)));
            var schema = new Dictionary<string, DatabaseSchemaPlan>(StringComparer.Ordinal);
            foreach (string name in names)
            {
                DatabaseSchemaPlan item = new(name, "1", Hash('e'), Hash('f'), []);
                schema.Add(name, item);
                await using var connection = new NpgsqlConnection(Connection(name));
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable);
                await PostgreSqlDeltaMetadataProvisioner.ProvisionDatabaseAsync(connection,
                    transaction, priorPlan, item, CancellationToken.None);
                await transaction.CommitAsync();
            }
            await AssertStateAsync(names, priorPlan, futurePlan, 0);
            await AdoptAsync(names[0], schema[names[0]], futurePlan, planSha, permit);
            await AssertStateAsync(names, priorPlan, futurePlan, 1);

            await using (var connection = new NpgsqlConnection(Connection(names[1])))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable);
                await PostgreSqlRolloverAdoption.AdoptPriorFenceAsync(connection, transaction,
                    futurePlan, schema[names[1]], Hash('7'), null, permit,
                    CancellationToken.None);
                await transaction.RollbackAsync();
            }
            await AssertStateAsync(names, priorPlan, futurePlan, 1);
            for (int index = 1; index < 22; index++)
            {
                await AdoptAsync(names[index], schema[names[index]], futurePlan,
                    planSha, permit);
            }
            await AssertStateAsync(names, priorPlan, futurePlan, 22);
            await AdoptAsync(names[22], schema[names[22]], futurePlan, planSha, permit);
            await AssertStateAsync(names, priorPlan, futurePlan, 23);

            await using (var connection = new NpgsqlConnection(Connection(names[0])))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable);
                DeltaExecutionException replay = await Assert.ThrowsAsync<DeltaExecutionException>(
                    () => PostgreSqlRolloverAdoption.AdoptPriorFenceAsync(connection,
                        transaction, futurePlan, schema[names[0]], Hash('7'), null,
                        permit, CancellationToken.None));
                Assert.Equal("delta_rollover_adoption_replay_conflict", replay.Code);
                await transaction.RollbackAsync();
            }
        }
        finally
        {
            foreach (string name in created)
            {
                await ExecuteAsync(fixture.ConnectionString,
                    $"DROP DATABASE {Quote(name)} WITH (FORCE);");
            }
        }
    }

    private async Task AdoptAsync(string name, DatabaseSchemaPlan schema,
        DeltaSynchronizationPlan plan, string planSha,
        LocalRolloverAdoptionPermit permit)
    {
        await using var connection = new NpgsqlConnection(Connection(name));
        await connection.OpenAsync();
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable);
        await PostgreSqlRolloverAdoption.AdoptPriorFenceAsync(connection, transaction,
            plan, schema, Hash('7'), null, permit, CancellationToken.None);
        await using (var command = new NpgsqlCommand("""
            INSERT INTO legacy_migration_internal.delta_journal
                (plan_sha256,plan_id,source_cutoff_utc,target_observation_sha256,
                 operations_sha256,reconciliation_sha256,committed_at_utc)
            VALUES ($1,$2,$3,$4,$5,$6,clock_timestamp());
            """, connection, transaction))
        {
            _ = command.Parameters.AddWithValue(planSha);
            _ = command.Parameters.AddWithValue(plan.PlanId);
            _ = command.Parameters.AddWithValue(plan.SourceCutoffUtc);
            _ = command.Parameters.AddWithValue(plan.TargetObservationSha256);
            _ = command.Parameters.AddWithValue(
                DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(
                    plan.Databases.Single(item => item.Database == name)));
            _ = command.Parameters.AddWithValue(Hash('b'));
            _ = await command.ExecuteNonQueryAsync();
        }
        await PostgreSqlRolloverAdoption.RecordMarkerAsync(connection, transaction,
            name, planSha, Hash('b'), permit, CancellationToken.None);
        await transaction.CommitAsync();
    }

    private async Task AssertStateAsync(string[] names,
        DeltaSynchronizationPlan oldPlan, DeltaSynchronizationPlan newPlan, int adopted)
    {
        for (int index = 0; index < names.Length; index++)
        {
            await using var connection = new NpgsqlConnection(Connection(names[index]));
            await connection.OpenAsync();
            await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                IsolationLevel.RepeatableRead);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;",
                connection, transaction))
            {
                _ = await readOnly.ExecuteNonQueryAsync();
            }
            await using (var fence = new NpgsqlCommand("""
                SELECT target_generation FROM legacy_migration_internal.delta_fence
                WHERE database_name=$1;
                """, connection, transaction))
            {
                _ = fence.Parameters.AddWithValue(names[index]);
                Assert.Equal(index < adopted ? newPlan.TargetGeneration : oldPlan.TargetGeneration,
                    await fence.ExecuteScalarAsync());
            }
            RolloverAdoptionMarkerEvidence? marker = await RolloverAdoptionMarkerReader
                .ReadAsync(connection, transaction, names[index], CancellationToken.None);
            Assert.Equal(index < adopted, marker is not null);
            await transaction.RollbackAsync();
        }
    }

    private string Connection(string database)
    {
        return new NpgsqlConnectionStringBuilder(
        fixture.ConnectionString)
        {
            Database = database,
            Pooling = false,
        }.ConnectionString;
    }

    private static DeltaSynchronizationPlan Plan(string generation, DateTimeOffset now)
    {
        return new("1.1", Guid.NewGuid(), new string('1', 40),
            now.AddHours(-1), Hash('a'), Hash('b'), Hash('c'), "LOCAL", "LOCAL",
            generation, Hash('d'), Hash('e'), Hash('f'), now.AddMinutes(-1),
            [.. DatabaseInventory.ActiveDatabases.Select(name =>
                new DeltaDatabasePlan(name, []))], "test", null);
    }

    private static async Task ExecuteAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }
}
