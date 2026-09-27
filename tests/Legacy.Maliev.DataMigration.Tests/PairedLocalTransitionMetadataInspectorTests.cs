using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PairedLocalTransitionMetadataInspectorTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task Disposable_postgresql_preflight_detects_missing_stale_and_conflicting_metadata_without_writes()
    {
        string admin = fixture.ConnectionString;
        const string database = "ContactRequest";
        await ExecuteAsync(admin, $"CREATE DATABASE \"{database}\";");
        try
        {
            string target = new NpgsqlConnectionStringBuilder(admin)
            {
                Database = database,
                Pooling = false,
            }.ConnectionString;
            DatabaseSchemaPlan schema = new(database, "1.0", Hash('a'), Hash('b'), []);
            DeltaDatabasePlan signedDatabase = new(database, []);
            string generation = $"docker:{Hash('1')}:100:200:300";
            var plan = new DeltaSynchronizationPlan("1.4", Guid.NewGuid(), new('1', 40),
                new DateTimeOffset(2026, 9, 27, 1, 2, 3, TimeSpan.Zero), Hash('c'), Hash('7'),
                Hash('d'), "local-aspire", "legacy-postgres-main-local", generation, Hash('e'),
                Hash('f'), Hash('9'), new DateTimeOffset(2026, 9, 27, 1, 3, 0, TimeSpan.Zero),
                [signedDatabase], "test", null)
            {
                TargetAuthority = new(DeltaTargetAuthorityKind.LocalAspire,
                    "aspire://legacy-postgres-main-local/persistent-metadata-test", Hash('8')),
                PairedTransitionPlanOnly = true,
                QuotationTransitionSchemaSha256 = Hash('6'),
            };
            var inspector = new PairedLocalTransitionMetadataInspector(admin);
            Assert.Equal("delta_paired_local_metadata_preimage_invalid",
                (await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                    new PairedLocalTransitionMetadataInspector("Host=should-not-connect")
                        .InspectAsync(plan with
                        {
                            TargetAuthority = new(DeltaTargetAuthorityKind.ProductionCloudNativePg,
                                "gke://maliev-website/production-test", Hash('8')),
                        }, schema, CancellationToken.None))).Code);
            Assert.Equal(PairedLocalTransitionMetadataState.Unprovisioned,
                (await inspector.InspectAsync(plan, schema, CancellationToken.None)).State);
            Assert.Equal(DBNull.Value, await ScalarAsync(target,
                "SELECT to_regclass('legacy_migration_internal.delta_fence')::text;"));

            await ExecuteAsync(target, """
                CREATE SCHEMA legacy_migration_internal;
                CREATE TABLE legacy_migration_internal.delta_fence(
                    database_name text PRIMARY KEY,
                    schema_plan_sha256 text NOT NULL,
                    target_schema_sha256 text NOT NULL,
                    target_generation text NOT NULL,
                    target_observation_sha256 text NOT NULL);
                """);
            Assert.Equal("delta_paired_local_metadata_preimage_invalid",
                (await Assert.ThrowsAsync<DeltaExecutionException>(() => inspector.InspectAsync(
                    plan, schema, CancellationToken.None))).Code);

            await ExecuteAsync(target, """
                CREATE TABLE legacy_migration_internal.delta_journal(
                    plan_sha256 text PRIMARY KEY,
                    plan_id uuid NOT NULL UNIQUE,
                    source_cutoff_utc timestamptz NOT NULL,
                    target_observation_sha256 text NOT NULL,
                    operations_sha256 text NOT NULL,
                    reconciliation_sha256 text NOT NULL,
                    committed_at_utc timestamptz NOT NULL);
                """);
            await ExecuteAsync(target, $"""
                INSERT INTO legacy_migration_internal.delta_fence
                  (database_name, schema_plan_sha256, target_schema_sha256,
                   target_generation, target_observation_sha256)
                VALUES ('{database}', '{plan.SchemaPlanSha256}', '{schema.TargetSchemaSha256}',
                    '{plan.TargetGeneration}', '{plan.TargetObservationSha256}');
                """);
            Assert.Equal(PairedLocalTransitionMetadataState.Pending,
                (await inspector.InspectAsync(plan, schema, CancellationToken.None)).State);
            await ExecuteAsync(target, $"""
                UPDATE legacy_migration_internal.delta_fence
                SET target_observation_sha256='{Hash('0')}' WHERE database_name='{database}';
                """);
            Assert.Equal("delta_paired_local_metadata_preimage_invalid",
                (await Assert.ThrowsAsync<DeltaExecutionException>(() => inspector.InspectAsync(
                    plan, schema, CancellationToken.None))).Code);

            await ExecuteAsync(target, $"""
                UPDATE legacy_migration_internal.delta_fence
                SET target_observation_sha256='{plan.TargetObservationSha256}' WHERE database_name='{database}';
                """);
            string planHash = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
            string operations = DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(signedDatabase);
            await ExecuteAsync(target, $"""
                INSERT INTO legacy_migration_internal.delta_journal
                  (plan_sha256, plan_id, source_cutoff_utc, target_observation_sha256,
                   operations_sha256, reconciliation_sha256, committed_at_utc)
                VALUES ('{planHash}', '{plan.PlanId}', '2026-09-27T01:02:03Z',
                    '{plan.TargetObservationSha256}', '{operations}', '{Hash('5')}',
                    '2026-09-27T01:04:00Z');
                """);
            PairedLocalTransitionMetadataObservation replayed = await inspector.InspectAsync(
                plan, schema, CancellationToken.None);
            Assert.Equal(PairedLocalTransitionMetadataState.Replayed, replayed.State);
            await ExecuteAsync(target, $"""
                UPDATE legacy_migration_internal.delta_journal
                SET reconciliation_sha256='{Hash('4')}';
                """);
            PairedLocalTransitionMetadataObservation changedCheckpoint = await inspector.InspectAsync(
                plan, schema, CancellationToken.None);
            Assert.Equal(PairedLocalTransitionMetadataState.Replayed, changedCheckpoint.State);
            Assert.NotEqual(replayed.FingerprintSha256, changedCheckpoint.FingerprintSha256);
            await ExecuteAsync(target, $"""
                UPDATE legacy_migration_internal.delta_journal SET operations_sha256='{Hash('0')}';
                """);
            Assert.Equal("delta_paired_local_metadata_preimage_invalid",
                (await Assert.ThrowsAsync<DeltaExecutionException>(() => inspector.InspectAsync(
                    plan, schema, CancellationToken.None))).Code);
            await ExecuteAsync(target, $"""
                UPDATE legacy_migration_internal.delta_journal
                SET operations_sha256='{operations}', plan_id='{Guid.NewGuid()}';
                """);
            Assert.Equal("delta_paired_local_metadata_preimage_invalid",
                (await Assert.ThrowsAsync<DeltaExecutionException>(() => inspector.InspectAsync(
                    plan, schema, CancellationToken.None))).Code);

            string priorObservation = Hash('1');
            await ExecuteAsync(target, $"""
                UPDATE legacy_migration_internal.delta_fence
                SET schema_plan_sha256='{Hash('2')}', target_schema_sha256='{Hash('9')}',
                    target_generation='docker:{Hash('1')}', target_observation_sha256='{priorObservation}';
                """);
            Assert.Equal("delta_paired_local_metadata_preimage_invalid",
                (await Assert.ThrowsAsync<DeltaExecutionException>(() => inspector.InspectAsync(
                    plan, schema, CancellationToken.None))).Code);
            await ExecuteAsync(target, $"""
                UPDATE legacy_migration_internal.delta_journal
                SET plan_sha256='{Hash('3')}', plan_id='{Guid.NewGuid()}',
                    target_observation_sha256='{priorObservation}',
                    operations_sha256='{Hash('4')}', reconciliation_sha256='{Hash('5')}';
                """);
            PairedLocalTransitionMetadataObservation settled = await inspector.InspectAsync(
                plan, schema, CancellationToken.None);
            Assert.Equal(PairedLocalTransitionMetadataState.SettledPrior, settled.State);
            await ExecuteAsync(target, "UPDATE legacy_migration_internal.delta_fence SET target_schema_sha256='invalid';");
            Assert.Equal("delta_paired_local_metadata_preimage_invalid",
                (await Assert.ThrowsAsync<DeltaExecutionException>(() => inspector.InspectAsync(
                    plan, schema, CancellationToken.None))).Code);
            await ExecuteAsync(target, $"UPDATE legacy_migration_internal.delta_fence SET target_schema_sha256='{Hash('9')}';");
            await ExecuteAsync(target, "UPDATE legacy_migration_internal.delta_fence SET target_generation='other';");
            Assert.Equal("delta_paired_local_metadata_preimage_invalid",
                (await Assert.ThrowsAsync<DeltaExecutionException>(() => inspector.InspectAsync(
                    plan, schema, CancellationToken.None))).Code);
            await ExecuteAsync(target, $"UPDATE legacy_migration_internal.delta_fence SET target_generation='docker:{Hash('1')}';");
            await ExecuteAsync(target, $"UPDATE legacy_migration_internal.delta_journal SET target_observation_sha256='{Hash('6')}';");
            Assert.Equal("delta_paired_local_metadata_preimage_invalid",
                (await Assert.ThrowsAsync<DeltaExecutionException>(() => inspector.InspectAsync(
                    plan, schema, CancellationToken.None))).Code);
            await ExecuteAsync(target, $"UPDATE legacy_migration_internal.delta_journal SET target_observation_sha256='{priorObservation}';");
            await ExecuteAsync(target, "UPDATE legacy_migration_internal.delta_journal SET reconciliation_sha256='invalid';");
            Assert.Equal("delta_paired_local_metadata_preimage_invalid",
                (await Assert.ThrowsAsync<DeltaExecutionException>(() => inspector.InspectAsync(
                    plan, schema, CancellationToken.None))).Code);
            await ExecuteAsync(target, $"UPDATE legacy_migration_internal.delta_journal SET reconciliation_sha256='{Hash('5')}';");
            Assert.Equal(settled, await inspector.InspectAsync(plan, schema, CancellationToken.None));

            await using (var connection = new NpgsqlConnection(target))
            {
                await connection.OpenAsync();
                await using var transaction = await connection.BeginTransactionAsync(System.Data.IsolationLevel.Serializable);
                Assert.Equal(PairedLocalTransitionMetadataState.SettledPrior,
                    (await PairedLocalTransitionMetadataInspector.InspectInTransactionAsync(
                        connection, transaction, plan, schema, CancellationToken.None, lockFence: true)).State);
                await UpdateFenceAsync(connection, transaction, plan, schema);
                await transaction.RollbackAsync();
            }
            Assert.Equal(settled, await inspector.InspectAsync(plan, schema, CancellationToken.None));
            await using (var connection = new NpgsqlConnection(target))
            {
                await connection.OpenAsync();
                await using var transaction = await connection.BeginTransactionAsync(System.Data.IsolationLevel.Serializable);
                Assert.Equal(PairedLocalTransitionMetadataState.SettledPrior,
                    (await PairedLocalTransitionMetadataInspector.InspectInTransactionAsync(
                        connection, transaction, plan, schema, CancellationToken.None, lockFence: true)).State);
                await UpdateFenceAsync(connection, transaction, plan, schema);
                await transaction.CommitAsync();
            }
            Assert.Equal(PairedLocalTransitionMetadataState.Pending,
                (await inspector.InspectAsync(plan, schema, CancellationToken.None)).State);
        }
        finally
        {
            await ExecuteAsync(admin, $"DROP DATABASE \"{database}\" WITH (FORCE);");
        }
    }

    private static async Task ExecuteAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static async Task UpdateFenceAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        DeltaSynchronizationPlan plan, DatabaseSchemaPlan schema)
    {
        await using var command = new NpgsqlCommand("""
            UPDATE legacy_migration_internal.delta_fence
            SET schema_plan_sha256=$1, target_schema_sha256=$2,
                target_generation=$3, target_observation_sha256=$4
            WHERE database_name=$5;
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(plan.SchemaPlanSha256);
        _ = command.Parameters.AddWithValue(schema.TargetSchemaSha256);
        _ = command.Parameters.AddWithValue(plan.TargetGeneration);
        _ = command.Parameters.AddWithValue(plan.TargetObservationSha256);
        _ = command.Parameters.AddWithValue(schema.Database);
        Assert.Equal(1, await command.ExecuteNonQueryAsync());
    }

    private static async Task<object?> ScalarAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        return await command.ExecuteScalarAsync();
    }

    private static string Hash(char value)
    {
        return new string(value, 64);
    }
}
