using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Internal transaction binding only. An authenticated mixed-state reader must
/// create this from retained claim, signed continuation, and observed database
/// evidence. No public caller can supply it to a canonical target.
/// </summary>
internal sealed class LocalRolloverAdoptionPermit(
    ImmutableRolloverClaim claim,
    HistoricalLocalMixedContinuation continuation,
    PairedLocalTransitionAuthorization authorization,
    TimeProvider clock)
{
    internal ImmutableRolloverClaim Claim => claim;
    internal HistoricalLocalMixedContinuation Continuation => continuation;
    internal PairedLocalTransitionAuthorization Authorization => authorization;
    internal DateTimeOffset NowUtc => clock.GetUtcNow();

    internal HistoricalLocalRolloverDatabaseState Require(
        DeltaSynchronizationPlan plan, DatabaseSchemaPlan schema)
    {
        DateTimeOffset now = NowUtc;
        string planHash = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
        HistoricalLocalRolloverDatabaseState? state = continuation.Databases?.SingleOrDefault(
            item => item.Database == schema.Database);
        return claim.ClaimId == Guid.Empty || continuation.ClaimId != claim.ClaimId ||
            continuation.InitialAttestationSha256 != claim.InitialAttestationSha256 ||
            continuation.FuturePlanSha256 != claim.FuturePlanSha256 ||
            continuation.TargetGeneration != claim.TargetGeneration ||
            authorization.AuthorizationId != continuation.AuthorizationId ||
            plan.TargetGeneration != claim.TargetGeneration ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(planHash, claim.FuturePlanSha256) ||
            schema.Database != state?.Database ||
            continuation.IssuedAtUtc.Offset != TimeSpan.Zero ||
            continuation.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            authorization.IssuedAtUtc.Offset != TimeSpan.Zero ||
            authorization.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            now < continuation.IssuedAtUtc || now >= continuation.ExpiresAtUtc ||
            now < authorization.IssuedAtUtc || now >= authorization.ExpiresAtUtc ||
            now >= claim.ExpiresAtUtc || continuation.ContinuationOrdinal <= 0
            ? throw Invalid("delta_rollover_adoption_permit_invalid")
            : state;
    }

    private static DeltaExecutionException Invalid(string code)
    {
        return new(code, "The LOCAL rollover adoption is not bound to fresh signed mixed-state evidence.");
    }
}

internal static class PostgreSqlRolloverAdoption
{
    private const string Table = "legacy_migration_internal.delta_rollover_adoption";

    internal static async Task RequireNoAdoptionMarkerAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string database, CancellationToken cancellationToken)
    {
        await using (var exists = new NpgsqlCommand(
            "SELECT to_regclass('legacy_migration_internal.delta_rollover_adoption') IS NOT NULL;",
            connection, transaction))
        {
            if (await exists.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is not true)
            {
                return;
            }
        }
        await using var marker = new NpgsqlCommand(
            $"SELECT count(*) FROM {Table} WHERE database_name=$1;", connection, transaction);
        _ = marker.Parameters.AddWithValue(database);
        if (Convert.ToInt64(await marker.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
                System.Globalization.CultureInfo.InvariantCulture) != 0)
        {
            throw Invalid("delta_rollover_adoption_claim_required");
        }
    }

    internal static async Task AdoptPriorFenceAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, DeltaSynchronizationPlan plan,
        DatabaseSchemaPlan schema, string expectedPriorMetadataSha256,
        PairedLocalTransitionExecutionPermit? localPermit,
        LocalRolloverAdoptionPermit permit, CancellationToken cancellationToken)
    {
        HistoricalLocalRolloverDatabaseState signed = permit.Require(plan, schema);
        if (signed.Phase != HistoricalLocalRolloverDatabasePhase.Prior ||
            signed.AdoptionJournalSha256 is not null ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(signed.PriorMetadataSha256,
                expectedPriorMetadataSha256) ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(
                permit.Claim.InitialMetadata.Single(item => item.Database == schema.Database)
                    .FingerprintSha256, expectedPriorMetadataSha256))
        {
            throw Invalid("delta_rollover_adoption_preimage_invalid");
        }

        await EnsureMarkerTableAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        await using (var existingMarker = new NpgsqlCommand(
            $"SELECT count(*) FROM {Table} WHERE database_name=$1;", connection, transaction))
        {
            _ = existingMarker.Parameters.AddWithValue(schema.Database);
            if (Convert.ToInt64(await existingMarker.ExecuteScalarAsync(cancellationToken)
                    .ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) != 0)
            {
                throw Invalid("delta_rollover_adoption_replay_conflict");
            }
        }
        string[] old = new string[4];
        await using (var current = new NpgsqlCommand("""
            SELECT schema_plan_sha256, target_schema_sha256, target_generation,
                   target_observation_sha256
            FROM legacy_migration_internal.delta_fence
            WHERE database_name=$1 FOR UPDATE;
            """, connection, transaction))
        {
            _ = current.Parameters.AddWithValue(schema.Database);
            await using NpgsqlDataReader reader = await current.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                throw Invalid("delta_rollover_adoption_preimage_invalid");
            }
            for (int index = 0; index < old.Length; index++)
            {
                old[index] = reader.GetString(index);
            }
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
                old[2] == plan.TargetGeneration)
            {
                throw Invalid("delta_rollover_adoption_preimage_invalid");
            }
        }

        await using var update = new NpgsqlCommand("""
            UPDATE legacy_migration_internal.delta_fence SET
                schema_plan_sha256=$1, target_schema_sha256=$2,
                target_generation=$3, target_observation_sha256=$4
            WHERE database_name=$5 AND schema_plan_sha256=$6 AND
                target_schema_sha256=$7 AND target_generation=$8 AND
                target_observation_sha256=$9;
            """, connection, transaction);
        _ = update.Parameters.AddWithValue(plan.SchemaPlanSha256);
        _ = update.Parameters.AddWithValue(
            QuotationDeltaPhysicalSchemaGuard.ExpectedPhysicalSchema(plan, schema,
                localPermit));
        _ = update.Parameters.AddWithValue(plan.TargetGeneration);
        _ = update.Parameters.AddWithValue(plan.TargetObservationSha256);
        _ = update.Parameters.AddWithValue(schema.Database);
        foreach (string value in old)
        {
            _ = update.Parameters.AddWithValue(value);
        }
        if (await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
        {
            throw Invalid("delta_rollover_adoption_cas_failed");
        }
    }

    internal static async Task RecordMarkerAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string database, string planSha256,
        string reconciliationSha256, LocalRolloverAdoptionPermit permit,
        CancellationToken cancellationToken)
    {
        if (permit.NowUtc >= permit.Continuation.ExpiresAtUtc ||
            permit.NowUtc >= permit.Authorization.ExpiresAtUtc)
        {
            throw Invalid("delta_rollover_adoption_authorization_expired");
        }
        await using var insert = new NpgsqlCommand($"""
            INSERT INTO {Table}
                (database_name, claim_id, initial_attestation_sha256,
                 future_plan_sha256, target_generation, prior_metadata_sha256,
                 continuation_ordinal, continuation_sha256, authorization_id,
                 plan_sha256, reconciliation_sha256, adopted_at_utc)
            SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,j.plan_sha256,
                   j.reconciliation_sha256,clock_timestamp()
            FROM legacy_migration_internal.delta_journal AS j
            WHERE j.plan_sha256=$10 AND j.reconciliation_sha256=$11;
            """, connection, transaction);
        HistoricalLocalMetadataBinding prior = permit.Claim.InitialMetadata.Single(
            item => item.Database == database);
        _ = insert.Parameters.AddWithValue(database);
        _ = insert.Parameters.AddWithValue(permit.Claim.ClaimId);
        _ = insert.Parameters.AddWithValue(permit.Claim.InitialAttestationSha256);
        _ = insert.Parameters.AddWithValue(permit.Claim.FuturePlanSha256);
        _ = insert.Parameters.AddWithValue(permit.Claim.TargetGeneration);
        _ = insert.Parameters.AddWithValue(prior.FingerprintSha256);
        _ = insert.Parameters.AddWithValue(permit.Continuation.ContinuationOrdinal);
        _ = insert.Parameters.AddWithValue(HistoricalLocalMixedContinuationCanonicalizer.ComputeSha256(
            permit.Continuation));
        _ = insert.Parameters.AddWithValue(permit.Authorization.AuthorizationId);
        _ = insert.Parameters.AddWithValue(planSha256);
        _ = insert.Parameters.AddWithValue(reconciliationSha256);
        if (await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
        {
            throw Invalid("delta_rollover_adoption_marker_write_failed");
        }
    }

    internal static async Task<string> VerifyReplayedMarkerAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, DeltaSynchronizationPlan plan,
        DatabaseSchemaPlan schema, string reconciliationSha256,
        LocalRolloverAdoptionPermit permit, CancellationToken cancellationToken)
    {
        HistoricalLocalRolloverDatabaseState signed = permit.Require(plan, schema);
        if (signed.Phase != HistoricalLocalRolloverDatabasePhase.Adopted ||
            !PostgreSqlDeltaCanonicalTarget.Hash(signed.AdoptionJournalSha256 ?? string.Empty))
        {
            throw Invalid("delta_rollover_adoption_replay_conflict");
        }
        await using var command = new NpgsqlCommand($"""
            SELECT claim_id, initial_attestation_sha256, future_plan_sha256,
                   target_generation, prior_metadata_sha256, continuation_ordinal,
                   continuation_sha256, authorization_id, plan_sha256,
                   reconciliation_sha256
            FROM {Table} WHERE database_name=$1 FOR UPDATE;
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(schema.Database);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
            reader.GetGuid(0) != permit.Claim.ClaimId ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(reader.GetString(1),
                permit.Claim.InitialAttestationSha256) ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(reader.GetString(2),
                permit.Claim.FuturePlanSha256) ||
            reader.GetString(3) != permit.Claim.TargetGeneration ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(reader.GetString(4),
                signed.PriorMetadataSha256) ||
            reader.GetInt64(5) > permit.Continuation.ContinuationOrdinal ||
            !PostgreSqlDeltaCanonicalTarget.Hash(reader.GetString(6)) ||
            reader.GetGuid(7) == Guid.Empty ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(reader.GetString(8),
                permit.Claim.FuturePlanSha256) ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(reader.GetString(9), reconciliationSha256))
        {
            throw Invalid("delta_rollover_adoption_replay_conflict");
        }
        string hash = ComputeJournalSha256(schema.Database, permit.Claim.ClaimId,
            reader.GetString(8), reader.GetString(9), reader.GetString(6));
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? throw Invalid("delta_rollover_adoption_replay_conflict")
            : PostgreSqlDeltaCanonicalTarget.Fixed(hash,
            signed.AdoptionJournalSha256 ?? string.Empty)
            ? hash : throw Invalid("delta_rollover_adoption_replay_conflict");
    }

    internal static string ComputeJournalSha256(string database, Guid claimId,
        string planSha256, string reconciliationSha256, string continuationSha256)
    {
        byte[] payload = Encoding.UTF8.GetBytes(string.Join('\0',
            "legacy-maliev-rollover-adoption-journal-v1", database, claimId.ToString("D"),
            planSha256, reconciliationSha256, continuationSha256));
        return Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
    }

    private static async Task EnsureMarkerTableAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand($"""
            CREATE TABLE IF NOT EXISTS {Table}(
                database_name text PRIMARY KEY,
                claim_id uuid NOT NULL,
                initial_attestation_sha256 text NOT NULL,
                future_plan_sha256 text NOT NULL,
                target_generation text NOT NULL,
                prior_metadata_sha256 text NOT NULL,
                continuation_ordinal bigint NOT NULL CHECK (continuation_ordinal > 0),
                continuation_sha256 text NOT NULL,
                authorization_id uuid NOT NULL,
                plan_sha256 text NOT NULL REFERENCES legacy_migration_internal.delta_journal(plan_sha256),
                reconciliation_sha256 text NOT NULL,
                adopted_at_utc timestamptz NOT NULL);
            """, connection, transaction);
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await VerifyMarkerTableAsync(connection, transaction, cancellationToken)
            .ConfigureAwait(false);
    }

    internal static async Task VerifyMarkerTableAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        await using var catalog = new NpgsqlCommand("""
            SELECT
                (SELECT string_agg(a.attname || ':' || format_type(a.atttypid,a.atttypmod) || ':' ||
                        CASE WHEN a.attnotnull THEN '1' ELSE '0' END, ',' ORDER BY a.attnum)
                 FROM pg_attribute AS a
                 WHERE a.attrelid='legacy_migration_internal.delta_rollover_adoption'::regclass
                   AND a.attnum > 0 AND NOT a.attisdropped),
                (SELECT count(*) FROM pg_constraint AS c
                 WHERE c.conrelid='legacy_migration_internal.delta_rollover_adoption'::regclass
                   AND c.contype='p' AND pg_get_constraintdef(c.oid)='PRIMARY KEY (database_name)'),
                (SELECT count(*) FROM pg_constraint AS c
                 WHERE c.conrelid='legacy_migration_internal.delta_rollover_adoption'::regclass
                   AND c.contype='f' AND
                       c.confrelid='legacy_migration_internal.delta_journal'::regclass),
                (SELECT count(*) FROM pg_constraint AS c
                 WHERE c.conrelid='legacy_migration_internal.delta_rollover_adoption'::regclass
                   AND c.contype='c');
            """, connection, transaction);
        await using NpgsqlDataReader reader = await catalog.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        const string columns = "database_name:text:1,claim_id:uuid:1," +
            "initial_attestation_sha256:text:1,future_plan_sha256:text:1," +
            "target_generation:text:1,prior_metadata_sha256:text:1," +
            "continuation_ordinal:bigint:1,continuation_sha256:text:1," +
            "authorization_id:uuid:1,plan_sha256:text:1," +
            "reconciliation_sha256:text:1,adopted_at_utc:timestamp with time zone:1";
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
            reader.IsDBNull(0) || reader.GetString(0) != columns ||
            reader.GetInt64(1) != 1 || reader.GetInt64(2) != 1 ||
            reader.GetInt64(3) != 1 ||
            await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw Invalid("delta_rollover_adoption_marker_schema_invalid");
        }
    }

    private static DeltaExecutionException Invalid(string code)
    {
        return new(code, "The LOCAL rollover marker and settled journal do not match the immutable claim.");
    }
}
