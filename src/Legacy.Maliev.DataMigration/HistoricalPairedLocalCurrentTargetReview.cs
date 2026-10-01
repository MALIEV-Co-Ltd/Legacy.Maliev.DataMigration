using System.Collections.ObjectModel;
using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>A fresh, independently observed LOCAL Docker/PostgreSQL identity.</summary>
public sealed record HistoricalCurrentLocalObservation(
    string ContainerId,
    string DockerGeneration,
    string VolumeName,
    DateTimeOffset VolumeCreatedAtUtc,
    string VolumeMountpoint,
    string VolumeDestination,
    string PgData,
    string SystemIdentifierSha256);

/// <summary>
/// PII-free read-only comparison against a historical signed terminal receipt.
/// It does not attest a container rollover or authorize a fence update.
/// </summary>
public sealed record HistoricalPairedLocalCurrentTargetReview(
    string HistoricalPlanSha256,
    string HistoricalReceiptSha256,
    DateTimeOffset HistoricalSourceCutoffUtc,
    string CurrentDockerGeneration,
    int DatabasesCompared,
    DateTimeOffset ComparedAtUtc)
{
    public static bool AuthorizesExecution => false;
}

public static class HistoricalPairedLocalCurrentTargetReviewer
{
    public static async Task<HistoricalPairedLocalCurrentTargetReview> CompareAsync(
        DeltaSynchronizationPlan historicalPlan,
        Exact23DeltaReconciliationResult historicalReceipt,
        FreshSchemaPlan historicalSchema,
        IReceiptAttestationTrustStore trust,
        Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observeCurrentTarget,
        IDeltaReconciliationInspector currentTarget,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(historicalSchema);
        ArgumentNullException.ThrowIfNull(observeCurrentTarget);
        ArgumentNullException.ThrowIfNull(currentTarget);
        ArgumentNullException.ThrowIfNull(clock);
        HistoricalPairedLocalEvidenceReview historical = HistoricalPairedLocalEvidenceReviewer.Verify(
            historicalPlan, historicalReceipt, trust, clock.GetUtcNow());
        if (historicalSchema.SchemaVersion != "2.0" || historicalSchema.Databases is null ||
            !historicalSchema.Databases.Select(item => item.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !DeltaSynchronizationPlanProducer.FixedHashEquals(
                SchemaPlanCanonicalizer.ComputeSha256(historicalSchema), historicalPlan.SchemaPlanSha256))
        {
            throw Invalid();
        }

        HistoricalCurrentLocalObservation before = await observeCurrentTarget(cancellationToken)
            .ConfigureAwait(false);
        RequireIdentity(historicalPlan, before);
        foreach (DatabaseSchemaPlan schema in historicalSchema.Databases)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DatabaseReconciliationEvidence expected = historicalReceipt.Databases.Single(item =>
                item.Database == schema.Database);
            DatabaseReconciliationEvidence observed = await currentTarget.InspectAsync(schema,
                cancellationToken).ConfigureAwait(false);
            DatabaseSchemaPlan mapped = new QuotationDeltaExecutionMapping(schema).TargetSchema;
            string[] tables = [.. mapped.Tables.Select(item => $"{item.TargetSchema}.{item.TargetTable}")
                .Order(StringComparer.Ordinal)];
            if (observed.Database != schema.Database ||
                !observed.Tables.Select(item => item.Table).Order(StringComparer.Ordinal)
                    .SequenceEqual(tables, StringComparer.Ordinal))
            {
                throw Invalid();
            }
            ReconciliationDiagnostics.CompareSchema(schema.Database, expected.TargetSchemaSha256,
                observed.TargetSchemaSha256);
            foreach (TableReconciliationEvidence table in expected.Tables)
            {
                ReconciliationDiagnostics.CompareTable(schema.Database, table,
                    observed.Tables.Single(item => item.Table == table.Table));
            }
            ReconciliationDiagnostics.CompareSequences(mapped, expected.SequenceNextValues,
                observed.SequenceNextValues);
            if (!DeltaSynchronizationPlanProducer.FixedHashEquals(
                    DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(expected),
                    DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(observed)))
            {
                throw Invalid();
            }
        }

        HistoricalCurrentLocalObservation after = await observeCurrentTarget(cancellationToken)
            .ConfigureAwait(false);
        RequireIdentity(historicalPlan, after);
        if (before != after)
        {
            throw Invalid();
        }
        _ = HistoricalPairedLocalEvidenceReviewer.Verify(historicalPlan, historicalReceipt, trust,
            clock.GetUtcNow());
        return new(historical.PlanSha256, historical.ReconciliationSha256, historical.SourceCutoffUtc,
            after.DockerGeneration,
            DatabaseInventory.ActiveDatabases.Count, clock.GetUtcNow());
    }

    private static void RequireIdentity(DeltaSynchronizationPlan plan,
        HistoricalCurrentLocalObservation observation)
    {
        string[] current = observation.DockerGeneration?.Split(':') ?? [];
        string[] old = plan.TargetGeneration.Split(':');
        bool valid = current.Length == 5 && old.Length == 5 && current[0] == "docker" &&
            current[1] == observation.ContainerId && current[1].Length == 64 &&
            current[1].All(char.IsAsciiHexDigit) && current[1] != old[1] &&
            current.Skip(2).All(value => long.TryParse(value,
                System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture,
                out long milliseconds) && milliseconds > 0) &&
            observation.VolumeName == "legacy-maliev-exact23-postgres-data" &&
            observation.VolumeCreatedAtUtc.Offset == TimeSpan.Zero &&
            observation.VolumeCreatedAtUtc.ToUnixTimeMilliseconds().ToString(
                System.Globalization.CultureInfo.InvariantCulture) == current[4] &&
            current[4] == old[4] && !string.IsNullOrWhiteSpace(observation.VolumeMountpoint) &&
            !string.IsNullOrWhiteSpace(observation.VolumeDestination) &&
            (observation.PgData == observation.VolumeDestination ||
                observation.PgData.StartsWith(observation.VolumeDestination.TrimEnd('/') + "/",
                    StringComparison.Ordinal)) &&
            DeltaSynchronizationPlanProducer.FixedHashEquals(observation.SystemIdentifierSha256,
                plan.TargetAuthority!.SystemIdentifierSha256);
        if (!valid)
        {
            throw Invalid();
        }
    }

    private static DeltaExecutionException Invalid()
    {
        return new("delta_historical_local_current_target_invalid",
            "The current LOCAL target does not match the verified historical exact-23 completion.");
    }
}

/// <summary>
/// Reads only the tables named in the signed historical schema. Each database is
/// inspected in its own repeatable-read, explicitly read-only transaction.
/// </summary>
public sealed class HistoricalPostgreSqlDeltaReconciliationInspector(
    string administrativeConnectionString,
    DeltaSynchronizationPlan historicalPlan,
    Exact23DeltaReconciliationResult historicalReceipt,
    FreshSchemaPlan historicalSchema,
    IReceiptAttestationTrustStore trust,
    DateTimeOffset nowUtc) : IDeltaReconciliationInspector
{
    private readonly NpgsqlConnectionStringBuilder _settings = ValidateConnection(administrativeConnectionString);
    private readonly FreshSchemaPlan _schema = ValidateSchema(historicalPlan, historicalReceipt,
        historicalSchema, trust, nowUtc);

    public async Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(schema);
        DatabaseSchemaPlan historicalDatabase = _schema.Databases.Single(item => item.Database == schema.Database);
        if (!string.Equals(historicalDatabase.SourceSchemaSha256, schema.SourceSchemaSha256,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(historicalDatabase.TargetSchemaSha256, schema.TargetSchemaSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new DeltaExecutionException("delta_historical_local_schema_invalid",
                "The requested historical database schema is not the signed schema.");
        }
        var builder = new NpgsqlConnectionStringBuilder(_settings.ConnectionString)
        {
            Database = historicalDatabase.Database,
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
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction,
            ownsResources: false);
        try
        {
            string physical = await inspector.InspectSchemaAsync(historicalDatabase, cancellationToken).ConfigureAwait(false);
            string expectedPhysical = historicalDatabase.Database == "Quotation"
                ? historicalPlan.QuotationTransitionSchemaSha256!
                : historicalDatabase.TargetSchemaSha256;
            ReconciliationDiagnostics.CompareSchema(historicalDatabase.Database, expectedPhysical, physical);
            DatabaseSchemaPlan mapped = new QuotationDeltaExecutionMapping(historicalDatabase).TargetSchema;
            var tables = new List<TableReconciliationEvidence>(mapped.Tables.Count);
            foreach (TableCopyPlan table in mapped.Tables)
            {
                tables.Add(await inspector.InspectTableAsync(table, cancellationToken).ConfigureAwait(false));
            }
            IReadOnlyDictionary<string, long> sequences = await inspector
                .InspectSequenceNextValuesAsync(mapped, cancellationToken).ConfigureAwait(false);
            string? extensionState = null;
            if (ApprovedConsumerColumnOverlayManifest.HasState(historicalDatabase))
            {
                ApprovedTargetExtensionState extension = await ApprovedTargetExtensionStateInspector
                    .InspectAsync(connection, transaction, historicalDatabase, cancellationToken).ConfigureAwait(false);
                extensionState = ApprovedTargetExtensionStateInspector.ComputeSha256(historicalDatabase, extension);
            }
            await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return new(historicalDatabase.Database, historicalDatabase.SourceSchemaSha256, physical,
                new ReadOnlyCollection<TableReconciliationEvidence>(tables))
            {
                SequenceNextValues = sequences,
                TargetExtensionStateSha256 = extensionState,
            };
        }
        catch
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private static FreshSchemaPlan ValidateSchema(DeltaSynchronizationPlan plan,
        Exact23DeltaReconciliationResult receipt, FreshSchemaPlan schema,
        IReceiptAttestationTrustStore trust, DateTimeOffset nowUtc)
    {
        _ = HistoricalPairedLocalEvidenceReviewer.Verify(plan, receipt, trust, nowUtc);
        return schema.Databases is null || !schema.Databases.Select(item => item.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !DeltaSynchronizationPlanProducer.FixedHashEquals(
                SchemaPlanCanonicalizer.ComputeSha256(schema), plan.SchemaPlanSha256)
            ? throw new DeltaExecutionException("delta_historical_local_schema_invalid",
                "The historical schema does not match the signed persistent LOCAL plan.")
            : schema;
    }

    private static NpgsqlConnectionStringBuilder ValidateConnection(string value)
    {
        var builder = new NpgsqlConnectionStringBuilder(value);
        if (builder.Host != "127.0.0.1" || builder.Database != "postgres" ||
            string.IsNullOrWhiteSpace(builder.Username) || string.IsNullOrWhiteSpace(builder.Password) ||
            !string.IsNullOrWhiteSpace(builder.Options))
        {
            throw new DeltaExecutionException("delta_historical_local_connection_invalid",
                "Historical LOCAL inspection requires a loopback-only PostgreSQL connection.");
        }
        builder.Options = "-c default_transaction_read_only=on";
        builder.Pooling = false;
        return builder;
    }
}
