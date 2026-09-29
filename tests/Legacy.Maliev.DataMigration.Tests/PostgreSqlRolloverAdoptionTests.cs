using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlRolloverAdoptionTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task MetadataPreflight_AcceptsDifferentFullDockerGenerationOnlyForClaimBoundPath()
    {
        string connectionString = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = fixture.CanonicalDatabase,
            Pooling = false,
        }.ConnectionString;
        await ExecuteAsync(connectionString,
            "DROP SCHEMA IF EXISTS legacy_migration_internal CASCADE;");
        try
        {
            long volume = DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeMilliseconds();
            string priorGeneration = $"docker:{Hash('1')}:1700000000000:1700000001000:{volume}";
            string currentGeneration = $"docker:{Hash('2')}:1700000002000:1700000003000:{volume}";
            DatabaseSchemaPlan schema = new("ContactRequest", "1", Hash('a'), Hash('b'), []);
            DeltaSynchronizationPlan oldPlan = Plan(priorGeneration);
            DeltaSynchronizationPlan futurePlan = Plan(currentGeneration) with
            {
                SchemaVersion = "1.4",
                PairedTransitionPlanOnly = true,
                TargetAuthority = new(DeltaTargetAuthorityKind.LocalAspire,
                    "aspire://legacy-postgres-main-local/persistent-test", Hash('3')),
                Databases = [new DeltaDatabasePlan(schema.Database, [])],
            };
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable);
                await PostgreSqlDeltaMetadataProvisioner.ProvisionDatabaseAsync(connection,
                    transaction, oldPlan, schema, CancellationToken.None);
                await InsertJournalAsync(connection, transaction, oldPlan,
                    DeltaSynchronizationPlanCanonicalizer.ComputeSha256(oldPlan), Hash('4'));
                await transaction.CommitAsync();
            }
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.RepeatableRead);
                await ExecuteAsync(connection, transaction, "SET TRANSACTION READ ONLY;");
                DeltaExecutionException unclaimed = await Assert.ThrowsAsync<DeltaExecutionException>(
                    () => PairedLocalTransitionMetadataInspector.InspectInTransactionAsync(
                        connection, transaction, futurePlan, schema, CancellationToken.None));
                Assert.Equal("delta_paired_local_metadata_preimage_invalid", unclaimed.Code);
                PairedLocalTransitionMetadataObservation claimed =
                    await PairedLocalTransitionMetadataInspector.InspectInTransactionAsync(
                        connection, transaction, futurePlan, schema, CancellationToken.None,
                        allowHistoricalGeneration: true);
                Assert.Equal(PairedLocalTransitionMetadataState.SettledPrior, claimed.State);
                Assert.Equal(64, claimed.FingerprintSha256.Length);
                DeltaExecutionException changedVolume = await Assert.ThrowsAsync<DeltaExecutionException>(
                    () => PairedLocalTransitionMetadataInspector.InspectInTransactionAsync(
                        connection, transaction, futurePlan with
                        {
                            TargetGeneration = $"docker:{Hash('2')}:1700000002000:1700000003000:{volume + 1}",
                        }, schema, CancellationToken.None, allowHistoricalGeneration: true));
                Assert.Equal("delta_paired_local_metadata_preimage_invalid", changedVolume.Code);
                await transaction.RollbackAsync();
            }
        }
        finally
        {
            await ExecuteAsync(connectionString,
                "DROP SCHEMA IF EXISTS legacy_migration_internal CASCADE;");
        }
    }

    [Fact]
    public async Task PriorFence_DmlJournalAndMarker_RollBackTogetherThenCommitOnce()
    {
        string connectionString = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = fixture.CanonicalDatabase,
            Pooling = false,
        }.ConnectionString;
        await ExecuteAsync(connectionString, """
            DROP SCHEMA IF EXISTS legacy_migration_internal CASCADE;
            DROP TABLE IF EXISTS public.rollover_atomic_probe;
            CREATE TABLE public.rollover_atomic_probe(value integer NOT NULL);
            INSERT INTO public.rollover_atomic_probe VALUES (0);
            """);
        try
        {
            DatabaseSchemaPlan schema = new("ContactRequest", "1", Hash('a'), Hash('b'), []);
            DeltaSynchronizationPlan oldPlan = Plan("docker:" + Hash('a'));
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable);
                await PostgreSqlDeltaMetadataProvisioner.ProvisionDatabaseAsync(connection, transaction,
                    oldPlan, schema, CancellationToken.None);
                await transaction.CommitAsync();
            }
            DeltaSynchronizationPlan newPlan = Plan("docker:" + Hash('b'));
            string newPlanSha256 = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(newPlan);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            ImmutableRolloverClaim claim = Claim(newPlanSha256, newPlan.TargetGeneration, now);
            HistoricalLocalMixedContinuation prior = Continuation(claim, now, adopted: false);
            LocalRolloverAdoptionPermit permit = Permit(claim, prior, now);
            string reconciliation = Hash('c');

            await ExecuteAsync(connectionString, """
            CREATE TABLE legacy_migration_internal.delta_rollover_adoption(
                database_name text);
            """);
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.RepeatableRead);
                await ExecuteAsync(connection, transaction, "SET TRANSACTION READ ONLY;");
                DeltaExecutionException malformedRead = await Assert.ThrowsAsync<DeltaExecutionException>(
                    () => RolloverAdoptionMarkerReader.ReadAsync(connection, transaction,
                        schema.Database, CancellationToken.None));
                Assert.Equal("delta_rollover_adoption_marker_schema_invalid", malformedRead.Code);
                await transaction.RollbackAsync();
            }
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable);
                DeltaExecutionException malformed = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                    PostgreSqlRolloverAdoption.AdoptPriorFenceAsync(connection, transaction,
                        newPlan, schema, Hash('d'), null, permit, CancellationToken.None));
                Assert.Equal("delta_rollover_adoption_marker_schema_invalid", malformed.Code);
                await transaction.RollbackAsync();
            }
            await ExecuteAsync(connectionString,
                "DROP TABLE legacy_migration_internal.delta_rollover_adoption;");

            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable);
                await PostgreSqlRolloverAdoption.AdoptPriorFenceAsync(connection, transaction,
                    newPlan, schema, Hash('d'), null, permit, CancellationToken.None);
                await ExecuteAsync(connection, transaction,
                    "UPDATE public.rollover_atomic_probe SET value=1;");
                await InsertJournalAsync(connection, transaction, newPlan, newPlanSha256,
                    reconciliation);
                await PostgreSqlRolloverAdoption.RecordMarkerAsync(connection, transaction,
                    schema.Database, newPlanSha256, reconciliation, permit, CancellationToken.None);
                await transaction.RollbackAsync();
            }
            Assert.Equal(0L, await ScalarAsync(connectionString,
                "SELECT value FROM public.rollover_atomic_probe;"));
            Assert.Equal(oldPlan.TargetGeneration, await TextAsync(connectionString,
                "SELECT target_generation FROM legacy_migration_internal.delta_fence " +
                "WHERE database_name='ContactRequest';"));
            Assert.Equal(0L, await ScalarAsync(connectionString,
                "SELECT count(*) FROM legacy_migration_internal.delta_journal;"));
            Assert.Null(await NullableTextAsync(connectionString,
                "SELECT to_regclass('legacy_migration_internal.delta_rollover_adoption')::text;"));

            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable);
                await PostgreSqlRolloverAdoption.AdoptPriorFenceAsync(connection, transaction,
                    newPlan, schema, Hash('d'), null, permit, CancellationToken.None);
                DeltaExecutionException missingJournal = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                    PostgreSqlRolloverAdoption.RecordMarkerAsync(connection, transaction,
                        schema.Database, newPlanSha256, reconciliation, permit, CancellationToken.None));
                Assert.Equal("delta_rollover_adoption_marker_write_failed", missingJournal.Code);
                await transaction.RollbackAsync();
            }

            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable);
                await PostgreSqlRolloverAdoption.AdoptPriorFenceAsync(connection, transaction,
                    newPlan, schema, Hash('d'), null, permit, CancellationToken.None);
                await ExecuteAsync(connection, transaction,
                    "UPDATE public.rollover_atomic_probe SET value=2;");
                await InsertJournalAsync(connection, transaction, newPlan, newPlanSha256,
                    reconciliation);
                await PostgreSqlRolloverAdoption.RecordMarkerAsync(connection, transaction,
                    schema.Database, newPlanSha256, reconciliation, permit, CancellationToken.None);
                await transaction.CommitAsync();
            }
            Assert.Equal(2L, await ScalarAsync(connectionString,
                "SELECT value FROM public.rollover_atomic_probe;"));
            Assert.Equal(newPlan.TargetGeneration, await TextAsync(connectionString,
                "SELECT target_generation FROM legacy_migration_internal.delta_fence " +
                "WHERE database_name='ContactRequest';"));
            Assert.Equal(1L, await ScalarAsync(connectionString,
                "SELECT count(*) FROM legacy_migration_internal.delta_journal;"));
            Assert.Equal(1L, await ScalarAsync(connectionString,
                "SELECT count(*) FROM legacy_migration_internal.delta_rollover_adoption;"));

            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.RepeatableRead);
                await ExecuteAsync(connection, transaction, "SET TRANSACTION READ ONLY;");
                RolloverAdoptionMarkerEvidence marker = Assert.IsType<RolloverAdoptionMarkerEvidence>(
                    await RolloverAdoptionMarkerReader.ReadAsync(connection, transaction,
                        schema.Database, CancellationToken.None));
                var ordinal = new ImmutableRolloverClaimStore.SignedClaimOrdinal("1.0",
                    claim.ClaimId, 1, prior, permit.Authorization, now.AddMinutes(-1));
                HistoricalLocalRolloverDatabaseState state =
                    RolloverAdoptionMarkerReader.Authenticate(marker, claim, ordinal, newPlan);
                Assert.Equal(HistoricalLocalRolloverDatabasePhase.Adopted, state.Phase);
                Assert.Equal(PostgreSqlRolloverAdoption.ComputeJournalSha256(schema.Database,
                    claim.ClaimId, newPlanSha256, reconciliation,
                    HistoricalLocalMixedContinuationCanonicalizer.ComputeSha256(prior)),
                    state.AdoptionJournalSha256);
                Assert.Equal("delta_rollover_adoption_marker_invalid",
                    Assert.Throws<DeltaExecutionException>(() =>
                        RolloverAdoptionMarkerReader.Authenticate(marker with
                        { AuthorizationId = Guid.NewGuid() }, claim, ordinal, newPlan)).Code);
                Assert.Equal("delta_rollover_adoption_marker_invalid",
                    Assert.Throws<DeltaExecutionException>(() =>
                        RolloverAdoptionMarkerReader.Authenticate(marker, claim, ordinal,
                            newPlan with { PlanId = Guid.NewGuid() })).Code);
                await transaction.RollbackAsync();
            }

            string journalSha = PostgreSqlRolloverAdoption.ComputeJournalSha256(schema.Database,
                claim.ClaimId, newPlanSha256, reconciliation,
                HistoricalLocalMixedContinuationCanonicalizer.ComputeSha256(prior));
            HistoricalLocalMixedContinuation adopted = Continuation(claim, now,
                adopted: true, journalSha) with
            { ContinuationOrdinal = 2 };
            LocalRolloverAdoptionPermit resumed = Permit(claim, adopted, now);
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable);
                string observed = await PostgreSqlRolloverAdoption.VerifyReplayedMarkerAsync(
                    connection, transaction, newPlan, schema, reconciliation, resumed,
                    CancellationToken.None);
                Assert.Equal(journalSha, observed);
                DeltaExecutionException unclaimedReplay = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                    PostgreSqlRolloverAdoption.RequireNoAdoptionMarkerAsync(connection, transaction,
                        schema.Database, CancellationToken.None));
                Assert.Equal("delta_rollover_adoption_claim_required", unclaimedReplay.Code);
                ImmutableRolloverClaim competingClaim = claim with { ClaimId = Guid.NewGuid() };
                LocalRolloverAdoptionPermit competing = Permit(competingClaim,
                    adopted with { ClaimId = competingClaim.ClaimId }, now);
                DeltaExecutionException changedClaim = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                    PostgreSqlRolloverAdoption.VerifyReplayedMarkerAsync(connection, transaction,
                        newPlan, schema, reconciliation, competing, CancellationToken.None));
                Assert.Equal("delta_rollover_adoption_replay_conflict", changedClaim.Code);
                DeltaExecutionException unknownPlan = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                    PostgreSqlRolloverAdoption.VerifyReplayedMarkerAsync(connection, transaction,
                        newPlan with { PlanId = Guid.NewGuid() }, schema, reconciliation,
                        resumed, CancellationToken.None));
                Assert.Equal("delta_rollover_adoption_permit_invalid", unknownPlan.Code);
                await transaction.RollbackAsync();
            }
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                    IsolationLevel.Serializable);
                DeltaExecutionException failure = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                    PostgreSqlRolloverAdoption.AdoptPriorFenceAsync(connection, transaction,
                        newPlan, schema, Hash('d'), null, permit, CancellationToken.None));
                Assert.Equal("delta_rollover_adoption_replay_conflict", failure.Code);
                await transaction.RollbackAsync();
            }
        }
        finally
        {
            await ExecuteAsync(connectionString, """
                DROP SCHEMA IF EXISTS legacy_migration_internal CASCADE;
                DROP TABLE IF EXISTS public.rollover_atomic_probe;
                """);
        }
    }

    private static DeltaSynchronizationPlan Plan(string generation)
    {
        return new("1.1", Guid.NewGuid(), new string('1', 40),
            DateTimeOffset.UtcNow.AddHours(-1), Hash('e'), Hash('f'), Hash('a'),
            "local-aspire", "legacy-postgres-local", generation, Hash('b'),
            Hash('c'), Hash('d'), DateTimeOffset.UtcNow.AddMinutes(-1), [], "test", null);
    }

    private static ImmutableRolloverClaim Claim(string planSha256, string generation,
        DateTimeOffset now)
    {
        return new("1.0", Guid.NewGuid(), Hash('1'), Hash('2'), Hash('3'),
            planSha256, generation, "legacy-maliev-exact23-postgres-data",
            now.AddDays(-1), Hash('4'),
            [.. DatabaseInventory.ActiveDatabases.Select(database =>
                new HistoricalLocalMetadataBinding(database,
                    PairedLocalTransitionMetadataState.SettledPrior, Hash('d')))],
            now, now.AddDays(1));
    }

    private static HistoricalLocalMixedContinuation Continuation(ImmutableRolloverClaim claim,
        DateTimeOffset now, bool adopted, string? journalSha = null)
    {
        return new("1.0", claim.ClaimId, claim.InitialAttestationSha256,
            claim.FuturePlanSha256, claim.TargetGeneration, Guid.NewGuid(), 1,
            [.. DatabaseInventory.ActiveDatabases.Select(database =>
                new HistoricalLocalRolloverDatabaseState(database,
                    adopted && database == "ContactRequest"
                        ? HistoricalLocalRolloverDatabasePhase.Adopted
                        : HistoricalLocalRolloverDatabasePhase.Prior,
                    Hash('d'), adopted && database == "ContactRequest" ? journalSha : null))],
            now.AddMinutes(-1), now.AddMinutes(10), "test", null);
    }

    private static LocalRolloverAdoptionPermit Permit(ImmutableRolloverClaim claim,
        HistoricalLocalMixedContinuation continuation, DateTimeOffset now)
    {
        var authorization = new PairedLocalTransitionAuthorization("1.0",
            continuation.AuthorizationId, Guid.NewGuid(), claim.FuturePlanSha256,
            Hash('a'), Hash('b'), Hash('c'), Hash('d'),
            new DeltaTargetAuthority(DeltaTargetAuthorityKind.LocalAspire,
                "aspire://legacy-postgres-main-local/persistent-test", Hash('e')),
            Hash('f'), now.AddMinutes(-1), now.AddMinutes(10), "test", null);
        return new(claim, continuation, authorization, TimeProvider.System,
            _ => Task.FromResult(new HistoricalCurrentLocalObservation(
                claim.TargetGeneration.Split(':')[1], claim.TargetGeneration,
                claim.VolumeName, claim.VolumeCreatedAtUtc, "/volume", "/data", "/data",
                claim.SystemIdentifierSha256)));
    }

    private static async Task InsertJournalAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, DeltaSynchronizationPlan plan,
        string planSha256, string reconciliation)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO legacy_migration_internal.delta_journal
                (plan_sha256, plan_id, source_cutoff_utc, target_observation_sha256,
                 operations_sha256, reconciliation_sha256, committed_at_utc)
            VALUES ($1,$2,$3,$4,$5,$6,clock_timestamp());
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(planSha256);
        _ = command.Parameters.AddWithValue(plan.PlanId);
        _ = command.Parameters.AddWithValue(plan.SourceCutoffUtc);
        _ = command.Parameters.AddWithValue(plan.TargetObservationSha256);
        _ = command.Parameters.AddWithValue(Hash('a'));
        _ = command.Parameters.AddWithValue(reconciliation);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static async Task ExecuteAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static async Task<long> ScalarAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        return Convert.ToInt64(await command.ExecuteScalarAsync(),
            System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task<string> TextAsync(string connectionString, string sql)
    {
        return (await NullableTextAsync(connectionString, sql))!;
    }

    private static async Task<string?> NullableTextAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        object? value = await command.ExecuteScalarAsync();
        return value is null or DBNull ? null : (string)value;
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }
}
