using System.Data;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>A read-only copy of one historical LOCAL database's generation fence.</summary>
public sealed record HistoricalLocalFence(string Database, string SchemaPlanSha256,
    string TargetSchemaSha256, string TargetGeneration, string TargetObservationSha256);

/// <summary>Only migration metadata; no application rows or connection details.</summary>
public sealed record HistoricalLocalMetadataSnapshot(string Database, HistoricalLocalFence Fence,
    IReadOnlyList<DeltaDatabaseCheckpointEvidence> Journal);

/// <summary>
/// Binds historical LOCAL fences and every settled journal entry to a separately
/// signed exact-23 terminal receipt. Journal inputs must retain PostgreSQL
/// ORDER BY plan_sha256 order. This cannot authorize execution or adoption.
/// </summary>
public static class HistoricalLocalMetadataReceiptBinder
{
    public static bool AuthorizesExecution => false;

    public static IReadOnlyList<HistoricalLocalMetadataBinding> Bind(
        DeltaSynchronizationPlan plan, Exact23DeltaReconciliationResult receipt,
        FreshSchemaPlan schema, IReceiptAttestationTrustStore trust,
        IReadOnlyList<HistoricalLocalMetadataSnapshot> snapshots, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(trust);
        HistoricalPairedLocalEvidenceReview historical =
            HistoricalPairedLocalEvidenceReviewer.Verify(plan, receipt, trust, nowUtc);
        if (schema.SchemaVersion != "2.0" || schema.Databases is null || snapshots is null ||
            !schema.Databases.Select(item => item.Database).SequenceEqual(
                DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !Fixed(plan.SchemaPlanSha256, SchemaPlanCanonicalizer.ComputeSha256(schema)) ||
            !snapshots.Select(item => item?.Database).SequenceEqual(
                DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            throw Invalid();
        }
        var bindings = new List<HistoricalLocalMetadataBinding>(DatabaseInventory.ActiveDatabases.Count);
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            HistoricalLocalMetadataSnapshot snapshot = snapshots.Single(item => item.Database == database);
            HistoricalLocalFence fence = snapshot.Fence;
            DeltaDatabaseCheckpointEvidence signed = receipt.Checkpoints.Single(item => item.Database == database);
            string physical = receipt.Databases.Single(item => item.Database == database).TargetSchemaSha256;
            if (fence is null || snapshot.Journal is null ||
                fence.Database != database || !Fixed(fence.SchemaPlanSha256, plan.SchemaPlanSha256) ||
                !Fixed(fence.TargetSchemaSha256, physical) ||
                fence.TargetGeneration != plan.TargetGeneration ||
                !Fixed(fence.TargetObservationSha256, plan.TargetObservationSha256) ||
                !CanonicalHash(fence.SchemaPlanSha256) || !CanonicalHash(fence.TargetSchemaSha256) ||
                !CanonicalHash(fence.TargetObservationSha256) ||
                signed.PlanId != plan.PlanId || !Fixed(signed.PlanSha256, historical.PlanSha256) ||
                signed.SourceCutoffUtc != plan.SourceCutoffUtc ||
                !Fixed(signed.ReconciliationSha256,
                    DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(
                        receipt.Databases.Single(item => item.Database == database))) ||
                signed.CommittedAtUtc > receipt.ReconciledAtUtc)
            {
                throw Invalid();
            }
            var entries = new List<string>();
            var planHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var planIds = new HashSet<Guid>();
            int signedMatches = 0;
            foreach (DeltaDatabaseCheckpointEvidence entry in snapshot.Journal)
            {
                if (entry is null || entry.Database != database || entry.PlanId == Guid.Empty ||
                    !CanonicalHash(entry.PlanSha256) || !CanonicalHash(entry.TargetObservationSha256) ||
                    !CanonicalHash(entry.OperationsSha256) || !CanonicalHash(entry.ReconciliationSha256) ||
                    entry.SourceCutoffUtc.Offset != TimeSpan.Zero ||
                    entry.CommittedAtUtc.Offset != TimeSpan.Zero ||
                    entry.CommittedAtUtc > signed.CommittedAtUtc ||
                    !planHashes.Add(entry.PlanSha256) || !planIds.Add(entry.PlanId))
                {
                    throw Invalid();
                }
                if (Fixed(entry.PlanSha256, historical.PlanSha256) || entry.PlanId == plan.PlanId)
                {
                    if (!ExactCheckpoint(entry, signed))
                    {
                        throw Invalid();
                    }
                    signedMatches++;
                }
                entries.Add(string.Join("|", [entry.PlanSha256,
                    entry.PlanId.ToString("D"), Utc(entry.SourceCutoffUtc),
                    entry.TargetObservationSha256, entry.OperationsSha256,
                    entry.ReconciliationSha256, Utc(entry.CommittedAtUtc)]));
            }
            if (signedMatches != 1)
            {
                throw Invalid();
            }
            // Keep the PostgreSQL ORDER BY plan_sha256 sequence supplied by the reader.
            // A .NET ordinal re-sort could disagree with the target column collation.
            string payload = string.Join("\0", ["paired-local-transition-metadata-v1",
                PairedLocalTransitionMetadataState.SettledPrior.ToString(), database,
                fence.SchemaPlanSha256, fence.TargetSchemaSha256, fence.TargetGeneration,
                fence.TargetObservationSha256, string.Join('\n', entries)]);
            bindings.Add(new(database, PairedLocalTransitionMetadataState.SettledPrior,
                Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant()));
        }
        return bindings.AsReadOnly();
    }

    private static bool ExactCheckpoint(DeltaDatabaseCheckpointEvidence actual,
        DeltaDatabaseCheckpointEvidence signed)
    {
        return actual.Database == signed.Database && actual.PlanId == signed.PlanId &&
            Fixed(actual.PlanSha256, signed.PlanSha256) &&
            SamePostgreSqlTimestamp(actual.SourceCutoffUtc, signed.SourceCutoffUtc) &&
            Fixed(actual.TargetObservationSha256, signed.TargetObservationSha256) &&
            Fixed(actual.OperationsSha256, signed.OperationsSha256) &&
            Fixed(actual.ReconciliationSha256, signed.ReconciliationSha256) &&
            SamePostgreSqlTimestamp(actual.CommittedAtUtc, signed.CommittedAtUtc);
    }

    private static bool SamePostgreSqlTimestamp(DateTimeOffset actual, DateTimeOffset signed)
    {
        const long ticksPerMicrosecond = TimeSpan.TicksPerMillisecond / 1000;
        long ticks = signed.ToUniversalTime().Ticks;
        return actual.ToUniversalTime().Ticks == ticks - (ticks % ticksPerMicrosecond);
    }

    private static string Utc(DateTimeOffset value)
    {
        return value.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static bool Hash(string? value)
    {
        return value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
    }

    private static bool CanonicalHash(string? value)
    {
        return Hash(value) && value!.All(character =>
            char.IsAsciiDigit(character) || (character is >= 'a' and <= 'f'));
    }

    private static bool Fixed(string? left, string? right)
    {
        return Hash(left) && Hash(right) &&
            CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(left!.ToLowerInvariant()),
                Encoding.ASCII.GetBytes(right!.ToLowerInvariant()));
    }

    internal static DeltaExecutionException Invalid()
    {
        return new("delta_historical_local_metadata_invalid",
            "Historical LOCAL metadata does not match the signed settled exact-23 receipt.");
    }
}

/// <summary>Reads only existing metadata through explicit read-only snapshots.</summary>
public sealed class HistoricalPostgreSqlLocalMetadataInspector(string administrativeConnectionString)
{
    private readonly NpgsqlConnectionStringBuilder _settings = ValidateConnection(administrativeConnectionString);

    public async Task<IReadOnlyList<HistoricalLocalMetadataBinding>> InspectAsync(
        DeltaSynchronizationPlan plan, Exact23DeltaReconciliationResult receipt,
        FreshSchemaPlan schema, IReceiptAttestationTrustStore trust, DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        _ = HistoricalPairedLocalEvidenceReviewer.Verify(plan, receipt, trust, nowUtc);
        if (schema.SchemaVersion != "2.0" || schema.Databases is null ||
            !schema.Databases.Select(item => item.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !DeltaSynchronizationPlanProducer.FixedHashEquals(
                SchemaPlanCanonicalizer.ComputeSha256(schema), plan.SchemaPlanSha256))
        {
            throw HistoricalLocalMetadataReceiptBinder.Invalid();
        }
        var snapshots = new List<HistoricalLocalMetadataSnapshot>(DatabaseInventory.ActiveDatabases.Count);
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            snapshots.Add(await ReadDatabaseAsync(database, cancellationToken).ConfigureAwait(false));
        }
        return HistoricalLocalMetadataReceiptBinder.Bind(plan, receipt, schema, trust, snapshots, nowUtc);
    }

    internal async Task<HistoricalLocalMetadataSnapshot> ReadDatabaseAsync(string database,
        CancellationToken cancellationToken)
    {
        if (!DatabaseInventory.ActiveDatabases.Contains(database, StringComparer.Ordinal))
        {
            throw HistoricalLocalMetadataReceiptBinder.Invalid();
        }
        var builder = new NpgsqlConnectionStringBuilder(_settings.ConnectionString)
        {
            Database = database,
            Pooling = false,
        };
        try
        {
            await using var connection = new NpgsqlConnection(builder.ConnectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                IsolationLevel.RepeatableRead, cancellationToken).ConfigureAwait(false);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction))
            {
                _ = await readOnly.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            HistoricalLocalFence fence;
            await using (var command = new NpgsqlCommand("""
                SELECT database_name, schema_plan_sha256, target_schema_sha256,
                       target_generation, target_observation_sha256
                FROM legacy_migration_internal.delta_fence;
                """, connection, transaction))
            await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false))
            {
                if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    throw HistoricalLocalMetadataReceiptBinder.Invalid();
                }
                fence = new(reader.GetString(0), reader.GetString(1), reader.GetString(2),
                    reader.GetString(3), reader.GetString(4));
                if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    throw HistoricalLocalMetadataReceiptBinder.Invalid();
                }
            }
            var journal = new List<DeltaDatabaseCheckpointEvidence>();
            // Match PairedLocalTransitionMetadataInspector.ObserveSettledPriorAsync exactly:
            // the same ORDER BY uses the target database's plan_sha256 collation.
            await using (var command = new NpgsqlCommand("""
                SELECT plan_id, plan_sha256, source_cutoff_utc, target_observation_sha256,
                       operations_sha256, reconciliation_sha256, committed_at_utc
                FROM legacy_migration_internal.delta_journal ORDER BY plan_sha256;
                """, connection, transaction))
            await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false))
            {
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    if (reader.IsDBNull(5))
                    {
                        throw HistoricalLocalMetadataReceiptBinder.Invalid();
                    }
                    journal.Add(new(database, reader.GetGuid(0), reader.GetString(1),
                        reader.GetFieldValue<DateTimeOffset>(2), reader.GetString(3),
                        reader.GetString(4), reader.GetString(5), reader.GetFieldValue<DateTimeOffset>(6)));
                }
            }
            await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return new(database, fence, journal.AsReadOnly());
        }
        catch (PostgresException)
        {
            throw HistoricalLocalMetadataReceiptBinder.Invalid();
        }
    }

    private static NpgsqlConnectionStringBuilder ValidateConnection(string value)
    {
        var builder = new NpgsqlConnectionStringBuilder(value);
        if (builder.Host != "127.0.0.1" || builder.Database != "postgres" ||
            string.IsNullOrWhiteSpace(builder.Username) || string.IsNullOrWhiteSpace(builder.Password) ||
            !string.IsNullOrWhiteSpace(builder.Options))
        {
            throw HistoricalLocalMetadataReceiptBinder.Invalid();
        }
        builder.Options = "-c default_transaction_read_only=on";
        builder.Pooling = false;
        return builder;
    }
}
