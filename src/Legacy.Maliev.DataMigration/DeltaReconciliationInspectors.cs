using System.Collections.ObjectModel;
using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public sealed class SqlServerDeltaReconciliationInspector(IReadOnlyMigrationSource source)
    : IDeltaReconciliationInspector
{
    public async Task<DatabaseReconciliationEvidence> InspectAsync(
        DatabaseSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(schema);
        SourceSchemaEvidence observedSchema = await source.InspectSchemaForPlanAsync(schema, cancellationToken)
            .ConfigureAwait(false);
        if (!string.Equals(observedSchema.SchemaSha256, schema.SourceSchemaSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new DeltaExecutionException("delta_reconciliation_source_schema_drift",
                "The restored SQL Server source schema changed after planning.");
        }
        var binding = new QuotationDeltaExecutionMapping(schema);
        var tables = new List<TableReconciliationEvidence>(binding.TargetSchema.Tables.Count);
        foreach (TableCopyPlan table in binding.TargetSchema.Tables)
        {
            TableCopyPlan sourceTable = binding.SourceTableFor(table);
            using var collector = new TableEvidenceCollector(table);
            await foreach (MigrationRow row in source.ReadTableImmediatelyAsync(schema.Database, sourceTable, cancellationToken)
                .WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                foreach (StreamingLob lob in row.Values.Values.OfType<StreamingLob>())
                {
                    await lob.ConsumeAsync(Stream.Null, cancellationToken).ConfigureAwait(false);
                }
                collector.Append(binding.MapRow(table, row));
            }
            TableReconciliationEvidence evidence = collector.Finish() with
            {
                ForeignKeyOrphanCounts = table.ForeignKeys.Count == 0
                    ? new Dictionary<string, long>(StringComparer.Ordinal)
                    : await source.InspectForeignKeyOrphansAsync(
                        schema.Database, sourceTable, cancellationToken).ConfigureAwait(false),
                ForeignKeyRelationshipCounts = table.ForeignKeys.Count == 0
                    ? new Dictionary<string, long>(StringComparer.Ordinal)
                    : await source.InspectForeignKeyRelationshipsAsync(
                        schema.Database, sourceTable, cancellationToken).ConfigureAwait(false),
            };
            if (table.SourceKnownEmpty && evidence.RowCount != 0)
            {
                throw new DeltaExecutionException("delta_reconciliation_source_empty_table_drift",
                    "A table declared empty in the signed schema now contains source rows.");
            }
            tables.Add(evidence);
        }
        IReadOnlyDictionary<string, long> sourceSequences = await source.InspectSequenceNextValuesAsync(
            schema.Database, schema, cancellationToken).ConfigureAwait(false);
        return new(schema.Database, schema.SourceSchemaSha256, schema.TargetSchemaSha256,
            new ReadOnlyCollection<TableReconciliationEvidence>(tables))
        {
            SequenceNextValues = binding.MapSequences(sourceSequences),
        };
    }
}

public sealed record PostgreSqlDeltaReconciliationInspectorOptions(string AdministrativeConnectionString);

public sealed class PostgreSqlDeltaReconciliationInspector(PostgreSqlDeltaReconciliationInspectorOptions options)
    : IDeltaReconciliationInspector
{
    private readonly NpgsqlConnectionStringBuilder _settings = Validate(options);

    public async Task<string> InspectSchemaAsync(
        DatabaseSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(schema);
        var builder = new NpgsqlConnectionStringBuilder(_settings.ConnectionString)
        {
            Database = schema.Database,
            Pooling = false,
        };
        var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            IsolationLevel.RepeatableRead, cancellationToken).ConfigureAwait(false);
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction);
        try
        {
            string result = await inspector.InspectSchemaAsync(schema, cancellationToken).ConfigureAwait(false);
            await inspector.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch
        {
            try
            {
                await inspector.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception rollbackFailure) when (rollbackFailure is InvalidOperationException or NpgsqlException)
            {
                // Preserve the primary schema inspection failure.
            }
            throw;
        }
    }

    public async Task ValidateSchemaAsync(
        DatabaseSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        string observed = await InspectSchemaAsync(schema, cancellationToken).ConfigureAwait(false);
        QuotationDeltaPhysicalSchemaGuard.RequireFinalSchema(schema, observed);
    }

    public async Task<DatabaseReconciliationEvidence> InspectAsync(
        DatabaseSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(schema);
        var builder = new NpgsqlConnectionStringBuilder(_settings.ConnectionString)
        {
            Database = schema.Database,
            Pooling = false,
        };
        var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            IsolationLevel.RepeatableRead, cancellationToken).ConfigureAwait(false);
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction);
        try
        {
            string schemaSha256 = await inspector.InspectSchemaAsync(schema, cancellationToken).ConfigureAwait(false);
            QuotationDeltaPhysicalSchemaGuard.RequireFinalSchema(schema, schemaSha256);
            DatabaseSchemaPlan targetSchema = new QuotationDeltaExecutionMapping(schema).TargetSchema;
            var tables = new List<TableReconciliationEvidence>(targetSchema.Tables.Count);
            foreach (TableCopyPlan table in targetSchema.Tables)
            {
                tables.Add(await inspector.InspectTableAsync(table, cancellationToken).ConfigureAwait(false));
            }
            IReadOnlyDictionary<string, long> sequences = await inspector
                .InspectSequenceNextValuesAsync(targetSchema, cancellationToken).ConfigureAwait(false);
            string? extensionStateSha256 = null;
            if (ApprovedTargetExtensionManifest.TablesFor(schema).Count != 0)
            {
                ApprovedTargetExtensionState extensionState = await ApprovedTargetExtensionStateInspector
                    .InspectAsync(connection, transaction, schema, cancellationToken).ConfigureAwait(false);
                extensionStateSha256 = ApprovedTargetExtensionStateInspector.ComputeSha256(schema, extensionState);
            }
            await inspector.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return new(schema.Database, schema.SourceSchemaSha256, schemaSha256,
                new ReadOnlyCollection<TableReconciliationEvidence>(tables))
            {
                SequenceNextValues = sequences,
                TargetExtensionStateSha256 = extensionStateSha256,
            };
        }
        catch
        {
            try
            {
                await inspector.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception rollbackFailure) when (rollbackFailure is InvalidOperationException or NpgsqlException)
            {
                // Preserve the primary reconciliation failure.
            }
            throw;
        }
    }

    private static NpgsqlConnectionStringBuilder Validate(PostgreSqlDeltaReconciliationInspectorOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.AdministrativeConnectionString))
        {
            throw new ArgumentException("A PostgreSQL reconciliation connection string is required.", nameof(options));
        }
        var builder = new NpgsqlConnectionStringBuilder(options.AdministrativeConnectionString);
        return string.IsNullOrWhiteSpace(builder.Host) || string.IsNullOrWhiteSpace(builder.Username)
            ? throw new ArgumentException("The PostgreSQL reconciliation endpoint is incomplete.", nameof(options))
            : builder;
    }
}
