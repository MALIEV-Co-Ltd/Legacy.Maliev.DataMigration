using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Read-only projection of one atomic adoption marker and its journal.</summary>
internal sealed record RolloverAdoptionMarkerEvidence(
    string Database, Guid ClaimId, string InitialAttestationSha256,
    string FuturePlanSha256, string TargetGeneration, string PriorMetadataSha256,
    long ContinuationOrdinal, string ContinuationSha256, Guid AuthorizationId,
    string PlanSha256, string ReconciliationSha256, DateTimeOffset AdoptedAtUtc);

internal static class RolloverAdoptionMarkerReader
{
    internal static async Task<RolloverAdoptionMarkerEvidence?> ReadAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, string database,
        CancellationToken cancellationToken)
    {
        if (transaction.IsolationLevel != IsolationLevel.RepeatableRead ||
            !DatabaseInventory.ActiveDatabases.Contains(database, StringComparer.Ordinal))
        {
            throw Invalid();
        }
        await using (var exists = new NpgsqlCommand("""
            SELECT to_regclass('legacy_migration_internal.delta_rollover_adoption') IS NOT NULL;
            """, connection, transaction))
        {
            if (await exists.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is not true)
            {
                return null;
            }
        }
        await PostgreSqlRolloverAdoption.VerifyMarkerTableAsync(connection, transaction,
            cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand("""
            SELECT m.database_name,m.claim_id,m.initial_attestation_sha256,
                   m.future_plan_sha256,m.target_generation,m.prior_metadata_sha256,
                   m.continuation_ordinal,m.continuation_sha256,m.authorization_id,
                   m.plan_sha256,m.reconciliation_sha256,m.adopted_at_utc
            FROM legacy_migration_internal.delta_rollover_adoption AS m
            JOIN legacy_migration_internal.delta_journal AS j
              ON j.plan_sha256=m.plan_sha256 AND
                 j.reconciliation_sha256=m.reconciliation_sha256
            WHERE m.database_name=$1;
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(database);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            // A marker may exist without its joined journal only in a malformed
            // database. Check that separately rather than treating it as prior.
            await reader.DisposeAsync().ConfigureAwait(false);
            await using var orphan = new NpgsqlCommand("""
                SELECT EXISTS(SELECT 1 FROM legacy_migration_internal.delta_rollover_adoption
                              WHERE database_name=$1);
                """, connection, transaction);
            _ = orphan.Parameters.AddWithValue(database);
            return await orphan.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is true
                ? throw Invalid() : null;
        }
        var result = new RolloverAdoptionMarkerEvidence(reader.GetString(0),
            reader.GetGuid(1), reader.GetString(2), reader.GetString(3),
            reader.GetString(4), reader.GetString(5), reader.GetInt64(6),
            reader.GetString(7), reader.GetGuid(8), reader.GetString(9),
            reader.GetString(10), reader.GetFieldValue<DateTimeOffset>(11).ToUniversalTime());
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? throw Invalid() : result;
    }

    internal static HistoricalLocalRolloverDatabaseState Authenticate(
        RolloverAdoptionMarkerEvidence marker, ImmutableRolloverClaim claim,
        ImmutableRolloverClaimStore.SignedClaimOrdinal ordinal,
        DeltaSynchronizationPlan futurePlan)
    {
        string planSha256 = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(futurePlan);
        HistoricalLocalRolloverDatabaseState? preimage = ordinal.Continuation.Databases
            .SingleOrDefault(item => item.Database == marker.Database);
        HistoricalLocalMetadataBinding? initial = claim.InitialMetadata.SingleOrDefault(item =>
            item.Database == marker.Database);
        return marker.ClaimId != claim.ClaimId ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(marker.InitialAttestationSha256,
                claim.InitialAttestationSha256) ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(marker.FuturePlanSha256,
                claim.FuturePlanSha256) ||
            marker.TargetGeneration != claim.TargetGeneration ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(marker.PriorMetadataSha256,
                initial?.FingerprintSha256 ?? string.Empty) ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(marker.PriorMetadataSha256,
                preimage?.PriorMetadataSha256 ?? string.Empty) ||
            preimage?.Phase != HistoricalLocalRolloverDatabasePhase.Prior ||
            preimage.AdoptionJournalSha256 is not null ||
            marker.ContinuationOrdinal != ordinal.Ordinal ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(marker.ContinuationSha256,
                HistoricalLocalMixedContinuationCanonicalizer.ComputeSha256(
                    ordinal.Continuation)) ||
            marker.AuthorizationId != ordinal.Authorization.AuthorizationId ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(marker.PlanSha256, planSha256) ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(marker.PlanSha256,
                claim.FuturePlanSha256) ||
            !PostgreSqlDeltaCanonicalTarget.Hash(marker.ReconciliationSha256) ||
            marker.AdoptedAtUtc.Offset != TimeSpan.Zero ||
            marker.AdoptedAtUtc < ordinal.CreatedAtUtc ||
            marker.AdoptedAtUtc >= ordinal.Continuation.ExpiresAtUtc ||
            marker.AdoptedAtUtc >= ordinal.Authorization.ExpiresAtUtc
            ? throw Invalid()
            : new(marker.Database, HistoricalLocalRolloverDatabasePhase.Adopted,
            marker.PriorMetadataSha256, PostgreSqlRolloverAdoption.ComputeJournalSha256(
                marker.Database, claim.ClaimId, marker.PlanSha256,
                marker.ReconciliationSha256, marker.ContinuationSha256));
    }

    private static DeltaExecutionException Invalid()
    {
        return new("delta_rollover_adoption_marker_invalid",
            "The retained signed ordinal does not authenticate the adoption marker and journal.");
    }
}
