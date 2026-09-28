using System.Data;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public enum PairedLocalTransitionMetadataState
{
    Unprovisioned,
    Pending,
    Replayed,
    SettledPrior,
}

public sealed record PairedLocalTransitionMetadataObservation(
    PairedLocalTransitionMetadataState State,
    string FingerprintSha256);

/// <summary>
/// Reads existing delta fence/journal state before any schema-1.4 LOCAL metadata
/// provisioning. The atomic executor must recheck this inside its transaction.
/// </summary>
public sealed class PairedLocalTransitionMetadataInspector(string administrativeConnectionString)
{
    public async Task<PairedLocalTransitionMetadataObservation> InspectAsync(
        DeltaSynchronizationPlan plan,
        DatabaseSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(schema);
        if (plan.SchemaVersion != "1.4" || plan.PairedTransitionPlanOnly != true ||
            !DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(plan.TargetAuthority) ||
            !plan.Databases.Any(database => database.Database == schema.Database) ||
            !DatabaseInventory.ActiveDatabases.Contains(schema.Database, StringComparer.Ordinal))
        {
            throw Invalid();
        }
        var builder = new NpgsqlConnectionStringBuilder(administrativeConnectionString)
        {
            Database = schema.Database,
            Pooling = false,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            IsolationLevel.RepeatableRead, cancellationToken).ConfigureAwait(false);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction))
        {
            _ = await readOnly.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        try
        {
            PairedLocalTransitionMetadataObservation state = await InspectInTransactionAsync(
                connection, transaction, plan, schema, cancellationToken).ConfigureAwait(false);
            await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return state;
        }
        catch
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    internal static async Task<PairedLocalTransitionMetadataObservation> InspectInTransactionAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        DeltaSynchronizationPlan plan,
        DatabaseSchemaPlan schema,
        CancellationToken cancellationToken,
        bool lockFence = false,
        bool allowHistoricalGeneration = false)
    {
        if (plan.SchemaVersion != "1.4" || plan.PairedTransitionPlanOnly != true ||
            !DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(plan.TargetAuthority) ||
            !plan.Databases.Any(database => database.Database == schema.Database) ||
            !DatabaseInventory.ActiveDatabases.Contains(schema.Database, StringComparer.Ordinal))
        {
            throw Invalid();
        }
        await using (var catalog = new NpgsqlCommand("""
            SELECT to_regclass('legacy_migration_internal.delta_fence') IS NOT NULL,
                   to_regclass('legacy_migration_internal.delta_journal') IS NOT NULL;
            """, connection, transaction))
        await using (NpgsqlDataReader reader = await catalog.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                throw Invalid();
            }
            bool fence = reader.GetBoolean(0);
            bool journalExists = reader.GetBoolean(1);
            if (!fence && !journalExists)
            {
                return Observe(PairedLocalTransitionMetadataState.Unprovisioned, schema.Database);
            }
            if (!fence || !journalExists)
            {
                throw Invalid();
            }
        }
        string physical = schema.Database == "Quotation"
            ? plan.QuotationTransitionSchemaSha256 ?? string.Empty
            : schema.TargetSchemaSha256;
        string priorSchemaPlan;
        string priorPhysical;
        string priorGeneration;
        string priorObservation;
        await using (var fence = new NpgsqlCommand(lockFence ? """
            SELECT schema_plan_sha256, target_schema_sha256, target_generation,
                   target_observation_sha256
            FROM legacy_migration_internal.delta_fence WHERE database_name=$1 FOR UPDATE;
            """ : """
            SELECT schema_plan_sha256, target_schema_sha256, target_generation,
                   target_observation_sha256
            FROM legacy_migration_internal.delta_fence WHERE database_name=$1;
            """, connection, transaction))
        {
            _ = fence.Parameters.AddWithValue(schema.Database);
            await using NpgsqlDataReader reader = await fence.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                throw Invalid();
            }
            priorSchemaPlan = reader.GetString(0);
            priorPhysical = reader.GetString(1);
            priorGeneration = reader.GetString(2);
            priorObservation = reader.GetString(3);
            if (!Hash(priorSchemaPlan) || !Hash(priorPhysical) || !Hash(priorObservation) ||
                await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                throw Invalid();
            }
        }
        bool currentFence = Fixed(priorSchemaPlan, plan.SchemaPlanSha256) &&
            Fixed(priorObservation, plan.TargetObservationSha256) &&
            priorGeneration == plan.TargetGeneration;
        if (currentFence
            ? !Fixed(priorPhysical, physical)
            : !SameDockerGeneration(priorGeneration, plan.TargetGeneration) &&
              !(allowHistoricalGeneration &&
                SameRolloverVolumeGeneration(priorGeneration, plan.TargetGeneration)))
        {
            throw Invalid();
        }
        await using (var legacy = new NpgsqlCommand("""
            SELECT EXISTS (SELECT 1 FROM legacy_migration_internal.delta_journal
                           WHERE reconciliation_sha256 IS NULL);
            """, connection, transaction))
        {
            if (await legacy.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is not false)
            {
                throw Invalid();
            }
        }
        await using var journal = new NpgsqlCommand("""
            SELECT plan_sha256, plan_id, source_cutoff_utc, target_observation_sha256,
                   operations_sha256, reconciliation_sha256, committed_at_utc
            FROM legacy_migration_internal.delta_journal
            WHERE plan_sha256=$1 OR plan_id=$2;
            """, connection, transaction);
        string planHash = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
        _ = journal.Parameters.AddWithValue(planHash);
        _ = journal.Parameters.AddWithValue(plan.PlanId);
        await using NpgsqlDataReader replay = await journal.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!await replay.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            await replay.DisposeAsync().ConfigureAwait(false);
            return currentFence
                ? Observe(PairedLocalTransitionMetadataState.Pending, schema.Database, planHash)
                : await ObserveSettledPriorAsync(connection, transaction, schema.Database,
                    priorSchemaPlan, priorPhysical, priorGeneration, priorObservation,
                    cancellationToken).ConfigureAwait(false);
        }
        if (!currentFence)
        {
            throw Invalid();
        }
        string operationHash = DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(
            plan.Databases.Single(database => database.Database == schema.Database));
        string reconciliation = replay.IsDBNull(5) ? string.Empty : replay.GetString(5);
        DateTimeOffset committedAt = replay.GetFieldValue<DateTimeOffset>(6).ToUniversalTime();
        bool valid = Fixed(replay.GetString(0), planHash) && replay.GetGuid(1) == plan.PlanId &&
            SameTimestamp(replay.GetFieldValue<DateTimeOffset>(2), plan.SourceCutoffUtc) &&
            Fixed(replay.GetString(3), plan.TargetObservationSha256) &&
            Fixed(replay.GetString(4), operationHash) &&
            Hash(reconciliation) &&
            !await replay.ReadAsync(cancellationToken).ConfigureAwait(false);
        return valid ? Observe(PairedLocalTransitionMetadataState.Replayed, schema.Database,
            planHash, reconciliation, committedAt.ToString("O",
                System.Globalization.CultureInfo.InvariantCulture)) : throw Invalid();
    }

    private static async Task<PairedLocalTransitionMetadataObservation> ObserveSettledPriorAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, string database,
        string priorSchemaPlan, string priorPhysical, string priorGeneration,
        string priorObservation, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            SELECT plan_sha256, plan_id, source_cutoff_utc, target_observation_sha256,
                   operations_sha256, reconciliation_sha256, committed_at_utc
            FROM legacy_migration_internal.delta_journal ORDER BY plan_sha256;
            """, connection, transaction);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        var settled = new List<string>();
        bool currentObservationReconciled = false;
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            string planHash = reader.GetString(0);
            Guid planId = reader.GetGuid(1);
            string observation = reader.GetString(3);
            string operations = reader.GetString(4);
            string reconciliation = reader.GetString(5);
            if (!Hash(planHash) || planId == Guid.Empty || !Hash(observation) ||
                !Hash(operations) || !Hash(reconciliation))
            {
                throw Invalid();
            }
            currentObservationReconciled |= Fixed(observation, priorObservation);
            settled.Add(string.Join("|", [planHash, planId.ToString("D"),
                reader.GetFieldValue<DateTimeOffset>(2).ToUniversalTime().ToString("O"),
                observation, operations, reconciliation,
                reader.GetFieldValue<DateTimeOffset>(6).ToUniversalTime().ToString("O")]));
        }
        return currentObservationReconciled
            ? Observe(PairedLocalTransitionMetadataState.SettledPrior, database,
                priorSchemaPlan, priorPhysical, priorGeneration, priorObservation,
                string.Join('\n', settled))
            : throw Invalid();
    }

    private static bool SameDockerGeneration(string prior, string signed)
    {
        if (prior == signed)
        {
            return true;
        }
        string[] parts = signed.Split(':');
        return parts.Length == 5 && parts[0] == "docker" && parts[1].Length == 64 &&
            parts[1].All(char.IsAsciiHexDigit) && prior == $"docker:{parts[1]}" &&
            parts.Skip(2).All(part => long.TryParse(part,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out long value) && value > 0);
    }

    private static bool SameRolloverVolumeGeneration(string prior, string signed)
    {
        string[] old = prior.Split(':');
        string[] current = signed.Split(':');
        return old.Length == 5 && current.Length == 5 &&
            old[0] == "docker" && current[0] == "docker" &&
            old[1].Length == 64 && current[1].Length == 64 &&
            old[1].All(char.IsAsciiHexDigit) &&
            current[1].All(char.IsAsciiHexDigit) && old[1] != current[1] &&
            old[4] == current[4] && old.Skip(2).Concat(current.Skip(2))
                .All(part => long.TryParse(part,
                    System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out long value) && value > 0);
    }

    private static bool Hash(string value)
    {
        return value.Length == 64 && value.All(char.IsAsciiHexDigit);
    }

    private static PairedLocalTransitionMetadataObservation Observe(
        PairedLocalTransitionMetadataState state, params string[] values)
    {
        string payload = string.Join("\0", ["paired-local-transition-metadata-v1", state.ToString(), .. values]);
        return new(state, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)))
            .ToLowerInvariant());
    }

    private static bool Fixed(string left, string right)
    {
        return PostgreSqlDeltaCanonicalTarget.Fixed(left, right);
    }

    private static bool SameTimestamp(DateTimeOffset stored, DateTimeOffset signed)
    {
        const long ticksPerMicrosecond = TimeSpan.TicksPerMillisecond / 1000;
        long signedTicks = signed.ToUniversalTime().Ticks;
        long storedTicks = stored.ToUniversalTime().Ticks;
        return storedTicks == signedTicks - (signedTicks % ticksPerMicrosecond);
    }

    private static DeltaExecutionException Invalid()
    {
        return new DeltaExecutionException("delta_paired_local_metadata_preimage_invalid",
            "Existing local delta metadata does not match the signed transition plan.");
    }
}
