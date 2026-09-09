using System.Collections.ObjectModel;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public sealed record DeltaDatabaseCheckpointEvidence(
    string Database,
    Guid PlanId,
    string PlanSha256,
    DateTimeOffset SourceCutoffUtc,
    string TargetObservationSha256,
    string OperationsSha256,
    string ReconciliationSha256,
    DateTimeOffset CommittedAtUtc);

public interface IExact23DeltaCheckpointReader
{
    Task<IReadOnlyList<DeltaDatabaseCheckpointEvidence>> ReadAsync(
        DeltaSynchronizationPlan plan,
        FreshSchemaPlan schemaPlan,
        CancellationToken cancellationToken);
}

public sealed record PostgreSqlExact23DeltaCheckpointReaderOptions(string AdministrativeConnectionString);

public sealed class PostgreSqlExact23DeltaCheckpointReader(PostgreSqlExact23DeltaCheckpointReaderOptions options)
    : IExact23DeltaCheckpointReader
{
    private readonly NpgsqlConnectionStringBuilder _settings = Validate(options);

    public async Task<IReadOnlyList<DeltaDatabaseCheckpointEvidence>> ReadAsync(
        DeltaSynchronizationPlan plan,
        FreshSchemaPlan schemaPlan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(schemaPlan);
        if (!plan.Databases.Select(item => item.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !schemaPlan.Databases.Select(item => item.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !string.Equals(plan.SourceCommitSha, schemaPlan.SourceCommitSha, StringComparison.Ordinal) ||
            !string.Equals(plan.SchemaPlanSha256, SchemaPlanCanonicalizer.ComputeSha256(schemaPlan), StringComparison.Ordinal))
        {
            throw Invalid();
        }
        string planSha256 = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
        var checkpoints = new List<DeltaDatabaseCheckpointEvidence>(DatabaseInventory.ActiveDatabases.Count);
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var builder = new NpgsqlConnectionStringBuilder(_settings.ConnectionString)
            {
                Database = database,
                Pooling = false,
            };
            await using var connection = new NpgsqlConnection(builder.ConnectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = new NpgsqlCommand("""
                SELECT plan_id, plan_sha256, source_cutoff_utc, target_observation_sha256,
                       operations_sha256, reconciliation_sha256, committed_at_utc
                FROM legacy_migration_internal.delta_journal
                WHERE plan_sha256=$1;
                """, connection);
            _ = command.Parameters.AddWithValue(planSha256);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                throw Invalid();
            }
            checkpoints.Add(new(database, reader.GetGuid(0), reader.GetString(1),
                reader.GetFieldValue<DateTimeOffset>(2), reader.GetString(3), reader.GetString(4),
                reader.GetString(5), reader.GetFieldValue<DateTimeOffset>(6)));
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                throw Invalid();
            }
        }
        return new ReadOnlyCollection<DeltaDatabaseCheckpointEvidence>(checkpoints);
    }

    private static NpgsqlConnectionStringBuilder Validate(PostgreSqlExact23DeltaCheckpointReaderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.AdministrativeConnectionString))
        {
            throw new ArgumentException("A PostgreSQL checkpoint connection string is required.", nameof(options));
        }
        var builder = new NpgsqlConnectionStringBuilder(options.AdministrativeConnectionString);
        return string.IsNullOrWhiteSpace(builder.Host) || string.IsNullOrWhiteSpace(builder.Username)
            ? throw new ArgumentException("The PostgreSQL checkpoint endpoint is incomplete.", nameof(options))
            : builder;
    }

    private static DeltaExecutionException Invalid()
    {
        return new("delta_reconciliation_checkpoint_invalid",
            "Signed exact-23 success requires one matching atomic checkpoint in every active database.");
    }
}
