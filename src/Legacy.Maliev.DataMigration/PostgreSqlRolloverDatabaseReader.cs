using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Inspects one database's metadata, marker, rows, schema, and sequences in one
/// repeatable-read, read-only snapshot. This result is evidence, not a permit.
/// </summary>
internal sealed class PostgreSqlRolloverDatabaseReader(string administrativeConnectionString)
{
    private readonly NpgsqlConnectionStringBuilder _settings = ValidateConnection(
        administrativeConnectionString);

    internal async Task<HistoricalLocalRolloverDatabaseState> ReadAsync(string database,
        ImmutableRolloverClaim claim, DeltaSynchronizationPlan historicalPlan,
        Exact23DeltaReconciliationResult historicalReceipt, FreshSchemaPlan historicalSchema,
        DeltaSynchronizationPlan futurePlan, Exact23DeltaReconciliationResult disposableProof,
        FreshSchemaPlan futureSchema, ImmutableRolloverClaimStore store,
        IReceiptAttestationTrustStore trust, long maxReservedOrdinal, DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        if (!DatabaseInventory.ActiveDatabases.Contains(database, StringComparer.Ordinal) ||
            historicalSchema.Databases is null || futureSchema.Databases is null ||
            !historicalSchema.Databases.Any(item => item.Database == database) ||
            !futureSchema.Databases.Any(item => item.Database == database))
        {
            throw Invalid();
        }
        var builder = new NpgsqlConnectionStringBuilder(_settings.ConnectionString)
        {
            Database = database,
            Pooling = false,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            IsolationLevel.RepeatableRead, cancellationToken).ConfigureAwait(false);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;",
            connection, transaction))
        {
            _ = await readOnly.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        try
        {
            RolloverAdoptionMarkerEvidence? marker = await RolloverAdoptionMarkerReader
                .ReadAsync(connection, transaction, database, cancellationToken)
                .ConfigureAwait(false);
            HistoricalLocalRolloverDatabaseState state;
            DatabaseSchemaPlan schema;
            DatabaseReconciliationEvidence expected;
            if (marker is null)
            {
                HistoricalLocalMetadataSnapshot snapshot = await ReadPriorMetadataAsync(
                    connection, transaction, database, cancellationToken).ConfigureAwait(false);
                DatabaseReconciliationEvidence receiptDatabase = historicalReceipt.Databases
                    .Single(item => item.Database == database);
                if (snapshot.Fence.Database != database ||
                    !PostgreSqlDeltaCanonicalTarget.Fixed(snapshot.Fence.SchemaPlanSha256,
                        historicalPlan.SchemaPlanSha256) ||
                    !PostgreSqlDeltaCanonicalTarget.Fixed(snapshot.Fence.TargetSchemaSha256,
                        receiptDatabase.TargetSchemaSha256) ||
                    snapshot.Fence.TargetGeneration != historicalPlan.TargetGeneration ||
                    !PostgreSqlDeltaCanonicalTarget.Fixed(
                        snapshot.Fence.TargetObservationSha256,
                        historicalPlan.TargetObservationSha256) ||
                    !PostgreSqlDeltaCanonicalTarget.Fixed(
                        HistoricalLocalMetadataReceiptBinder.ComputePriorFingerprint(snapshot),
                        claim.InitialMetadata.Single(item => item.Database == database)
                            .FingerprintSha256))
                {
                    throw Invalid();
                }
                state = new(database, HistoricalLocalRolloverDatabasePhase.Prior,
                    claim.InitialMetadata.Single(item => item.Database == database)
                        .FingerprintSha256, null);
                schema = historicalSchema.Databases.Single(item => item.Database == database);
                expected = receiptDatabase;
            }
            else
            {
                if (marker.ContinuationOrdinal < 1 ||
                    marker.ContinuationOrdinal > maxReservedOrdinal)
                {
                    throw Invalid();
                }
                ImmutableRolloverClaimStore.SignedClaimOrdinal ordinal = await store
                    .ReadSignedOrdinalAsync(claim, marker.ContinuationOrdinal, trust,
                        nowUtc, cancellationToken).ConfigureAwait(false);
                state = RolloverAdoptionMarkerReader.Authenticate(marker, claim, ordinal,
                    futurePlan);
                schema = futureSchema.Databases.Single(item => item.Database == database);
                PairedLocalTransitionMetadataObservation metadata =
                    await PairedLocalTransitionMetadataInspector.InspectInTransactionAsync(
                        connection, transaction, futurePlan, schema, cancellationToken)
                        .ConfigureAwait(false);
                if (metadata.State != PairedLocalTransitionMetadataState.Replayed)
                {
                    throw Invalid();
                }
                expected = disposableProof.Databases.Single(item => item.Database == database);
            }
            DatabaseReconciliationEvidence observed = await InspectRowsAsync(connection,
                transaction, schema, cancellationToken).ConfigureAwait(false);
            if (!PostgreSqlDeltaCanonicalTarget.Fixed(
                    DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(expected),
                    DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(observed)) ||
                (marker is not null && !PostgreSqlDeltaCanonicalTarget.Fixed(
                    marker.ReconciliationSha256,
                    DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(observed))))
            {
                throw Invalid();
            }
            await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return state;
        }
        catch
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private static async Task<HistoricalLocalMetadataSnapshot> ReadPriorMetadataAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, string database,
        CancellationToken cancellationToken)
    {
        HistoricalLocalFence fence;
        await using (var command = new NpgsqlCommand("""
            SELECT database_name,schema_plan_sha256,target_schema_sha256,
                   target_generation,target_observation_sha256
            FROM legacy_migration_internal.delta_fence;
            """, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                throw Invalid();
            }
            fence = new(reader.GetString(0), reader.GetString(1), reader.GetString(2),
                reader.GetString(3), reader.GetString(4));
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                throw Invalid();
            }
        }
        var journal = new List<DeltaDatabaseCheckpointEvidence>();
        await using (var command = new NpgsqlCommand("""
            SELECT plan_id,plan_sha256,source_cutoff_utc,target_observation_sha256,
                   operations_sha256,reconciliation_sha256,committed_at_utc
            FROM legacy_migration_internal.delta_journal ORDER BY plan_sha256;
            """, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (reader.IsDBNull(5))
                {
                    throw Invalid();
                }
                journal.Add(new(database, reader.GetGuid(0), reader.GetString(1),
                    reader.GetFieldValue<DateTimeOffset>(2), reader.GetString(3),
                    reader.GetString(4), reader.GetString(5),
                    reader.GetFieldValue<DateTimeOffset>(6)));
            }
        }
        return new(database, fence, journal.AsReadOnly());
    }

    private static async Task<DatabaseReconciliationEvidence> InspectRowsAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, DatabaseSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection,
            transaction, ownsResources: false);
        string physical = await inspector.InspectSchemaAsync(schema, cancellationToken)
            .ConfigureAwait(false);
        DatabaseSchemaPlan target = new QuotationDeltaExecutionMapping(schema).TargetSchema;
        var tables = new List<TableReconciliationEvidence>(target.Tables.Count);
        foreach (TableCopyPlan table in target.Tables)
        {
            tables.Add(await inspector.InspectTableAsync(table, cancellationToken)
                .ConfigureAwait(false));
        }
        IReadOnlyDictionary<string, long> sequences = await inspector
            .InspectSequenceNextValuesAsync(target, cancellationToken).ConfigureAwait(false);
        string? extensionSha256 = null;
        if (ApprovedTargetExtensionManifest.TablesFor(schema).Count != 0)
        {
            ApprovedTargetExtensionState extension = await ApprovedTargetExtensionStateInspector
                .InspectAsync(connection, transaction, schema, cancellationToken).ConfigureAwait(false);
            extensionSha256 = ApprovedTargetExtensionStateInspector.ComputeSha256(schema, extension);
        }
        return new(schema.Database, schema.SourceSchemaSha256, physical, tables.AsReadOnly())
        {
            SequenceNextValues = sequences,
            TargetExtensionStateSha256 = extensionSha256,
        };
    }

    private static NpgsqlConnectionStringBuilder ValidateConnection(string value)
    {
        var builder = new NpgsqlConnectionStringBuilder(value);
        if (builder.Host != "127.0.0.1" || builder.Database != "postgres" ||
            string.IsNullOrWhiteSpace(builder.Username) ||
            string.IsNullOrWhiteSpace(builder.Password) ||
            !string.IsNullOrWhiteSpace(builder.Options))
        {
            throw Invalid();
        }
        builder.Options = "-c default_transaction_read_only=on";
        builder.Pooling = false;
        return builder;
    }

    private static DeltaExecutionException Invalid()
    {
        return new("delta_rollover_database_state_invalid",
            "The database does not match a signed prior receipt or retained adopted journal.");
    }
}
