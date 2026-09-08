using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public sealed record PostgreSqlDeltaMetadataProvisionerOptions(
    string AdministrativeConnectionString,
    DeltaTargetAuthority ExpectedAuthority);

public sealed class PostgreSqlDeltaMetadataProvisioner(PostgreSqlDeltaMetadataProvisionerOptions options)
{
    public async Task ProvisionAsync(
        DeltaSynchronizationPlan plan,
        FreshSchemaPlan schemaPlan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(schemaPlan);
        if (plan.TargetAuthority != options.ExpectedAuthority ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(plan.TargetAuthority, plan.TargetNamespace, plan.TargetCluster) ||
            !schemaPlan.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !plan.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !string.Equals(plan.SourceCommitSha, schemaPlan.SourceCommitSha, StringComparison.Ordinal) ||
            !string.Equals(plan.SchemaPlanSha256, SchemaPlanCanonicalizer.ComputeSha256(schemaPlan), StringComparison.Ordinal))
        {
            throw new DeltaExecutionException("delta_metadata_authority_invalid",
                "Delta metadata provisioning is not bound to the exact target authority and database inventory.");
        }

        foreach (DatabaseSchemaPlan schema in schemaPlan.Databases)
        {
            var builder = new NpgsqlConnectionStringBuilder(options.AdministrativeConnectionString)
            {
                Database = schema.Database,
                Pooling = false,
            };
            await using var connection = new NpgsqlConnection(builder.ConnectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            try
            {
                await ProvisionDatabaseAsync(connection, transaction, plan, schema, cancellationToken).ConfigureAwait(false);
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
                throw;
            }
        }
    }

    internal static async Task ProvisionDatabaseAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        DeltaSynchronizationPlan plan,
        DatabaseSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        await ExecuteAsync(connection, transaction, """
            CREATE SCHEMA IF NOT EXISTS legacy_migration_internal;
            CREATE TABLE IF NOT EXISTS legacy_migration_internal.delta_fence(
                database_name text PRIMARY KEY,
                schema_plan_sha256 text NOT NULL,
                target_schema_sha256 text NOT NULL,
                target_generation text NOT NULL,
                target_observation_sha256 text NOT NULL);
            CREATE TABLE IF NOT EXISTS legacy_migration_internal.delta_journal(
                plan_sha256 text PRIMARY KEY,
                plan_id uuid NOT NULL UNIQUE,
                source_cutoff_utc timestamptz NOT NULL,
                target_observation_sha256 text NOT NULL,
                operations_sha256 text NOT NULL,
                reconciliation_sha256 text NOT NULL,
                committed_at_utc timestamptz NOT NULL);
            ALTER TABLE legacy_migration_internal.delta_journal
                ADD COLUMN IF NOT EXISTS reconciliation_sha256 text;
            """, cancellationToken).ConfigureAwait(false);

        await using (var legacyRows = new NpgsqlCommand(
            "SELECT count(*) FROM legacy_migration_internal.delta_journal WHERE reconciliation_sha256 IS NULL;",
            connection,
            transaction))
        {
            if (Convert.ToInt64(await legacyRows.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
                System.Globalization.CultureInfo.InvariantCulture) != 0)
            {
                throw new DeltaExecutionException("delta_metadata_legacy_journal_unreconciled",
                    "An existing delta journal contains entries without atomic reconciliation evidence.");
            }
        }

        await ExecuteAsync(connection, transaction,
            "ALTER TABLE legacy_migration_internal.delta_journal ALTER COLUMN reconciliation_sha256 SET NOT NULL;",
            cancellationToken).ConfigureAwait(false);
        await using var fence = new NpgsqlCommand("""
            INSERT INTO legacy_migration_internal.delta_fence
                (database_name, schema_plan_sha256, target_schema_sha256, target_generation, target_observation_sha256)
            VALUES ($1,$2,$3,$4,$5)
            ON CONFLICT (database_name) DO UPDATE SET
                schema_plan_sha256=EXCLUDED.schema_plan_sha256,
                target_schema_sha256=EXCLUDED.target_schema_sha256,
                target_generation=EXCLUDED.target_generation,
                target_observation_sha256=EXCLUDED.target_observation_sha256;
            """, connection, transaction);
        _ = fence.Parameters.AddWithValue(schema.Database);
        _ = fence.Parameters.AddWithValue(plan.SchemaPlanSha256);
        _ = fence.Parameters.AddWithValue(schema.TargetSchemaSha256);
        _ = fence.Parameters.AddWithValue(plan.TargetGeneration);
        _ = fence.Parameters.AddWithValue(plan.TargetObservationSha256);
        _ = await fence.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task ExecuteAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
