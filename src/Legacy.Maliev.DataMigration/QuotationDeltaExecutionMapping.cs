using System.Collections.ObjectModel;
using System.Runtime.CompilerServices;

namespace Legacy.Maliev.DataMigration;

/// <summary>Projects a signed source schema onto its reviewed Quotation delta targets.</summary>
internal sealed class QuotationDeltaExecutionMapping
{
    private readonly DatabaseSchemaPlan _sourceSchema;
    private readonly QuotationDispositionRowMapper? _mapper;
    private readonly Dictionary<string, TableCopyPlan> _sourceTables;

    internal QuotationDeltaExecutionMapping(DatabaseSchemaPlan sourceSchema)
    {
        _sourceSchema = sourceSchema ?? throw new ArgumentNullException(nameof(sourceSchema));
        ApprovedSourceDispositionManifest.Validate(sourceSchema);
        _mapper = sourceSchema.SourceDispositionProfile is null ? null : new(sourceSchema);
        TargetSchema = _mapper is null ? sourceSchema : sourceSchema with
        {
            Tables = ApprovedSourceDispositionManifest.TargetTablesFor(sourceSchema),
            SourceDispositionProfile = null,
            SourceTableDispositions = [],
        };
        if (_mapper is not null && !string.Equals(sourceSchema.TargetSchemaSha256,
            PostgreSqlSchemaFingerprint.ComputeExpected(TargetSchema), StringComparison.Ordinal))
        {
            throw new DeltaExecutionException("delta_execution_disposition_target_schema_invalid",
                "The reviewed Quotation target shape differs from the signed schema fingerprint.");
        }
        _sourceTables = sourceSchema.Tables.ToDictionary(
            table => $"{table.SourceSchema}.{table.SourceTable}", StringComparer.Ordinal);
    }

    internal DatabaseSchemaPlan TargetSchema { get; }

    internal TableCopyPlan SourceTableFor(TableCopyPlan target)
    {
        TableCopyPlan? signed = TargetSchema.Tables.SingleOrDefault(table =>
            string.Equals(table.TargetSchema, target.TargetSchema, StringComparison.Ordinal) &&
            string.Equals(table.TargetTable, target.TargetTable, StringComparison.Ordinal));
        if (signed is null || signed.SourceSchema != target.SourceSchema ||
            signed.SourceTable != target.SourceTable ||
            !signed.OrderedColumns.SequenceEqual(target.OrderedColumns, StringComparer.Ordinal))
        {
            throw new DeltaExecutionException("delta_execution_disposition_table_invalid",
                "A target table is absent from the signed Quotation disposition.");
        }
        string sourceSchema = target.SourceSchema == "disposition" ? "dbo" : target.SourceSchema;
        return !_sourceTables.TryGetValue($"{sourceSchema}.{target.SourceTable}", out TableCopyPlan? source)
            ? throw new DeltaExecutionException("delta_execution_disposition_table_invalid",
                "A reviewed target has no signed source table.")
            : source;
    }

    internal MigrationRow MapRow(TableCopyPlan target, MigrationRow source)
    {
        _ = SourceTableFor(target);
        return _mapper is null || target.SourceSchema != "disposition"
            ? source
            : MapDispositionRow(target, source);
    }

    private MigrationRow MapDispositionRow(TableCopyPlan target, MigrationRow source)
    {
        QuotationDispositionRowMapper mapper = _mapper ?? throw new DeltaExecutionException(
            "delta_execution_disposition_table_invalid", "The reviewed Quotation row mapper is unavailable.");
        return target.TargetSchema switch
        {
            "legacy_compatibility" when target.TargetTable == "GoogleAnalyticsOutbox" => mapper.MapAnalytics(source),
            "public" when target.TargetTable == "QuotationAcceptedOutcome" => mapper.MapOutcome(source),
            _ => throw new DeltaExecutionException("delta_execution_disposition_table_invalid",
                "The signed Quotation disposition target is unknown."),
        };
    }

    internal IReadOnlyDictionary<string, long> MapSequences(IReadOnlyDictionary<string, long> sourceSequences)
    {
        string[] expectedSource = [.. _sourceSchema.Tables.SelectMany(table => table.Identities.Select(identity =>
            $"{table.TargetSchema}.{table.TargetTable}.{identity.Column}")).Order(StringComparer.Ordinal)];
        if (!expectedSource.SequenceEqual(sourceSequences.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal))
        {
            throw new DeltaExecutionException("delta_reconciliation_source_sequence_shape_invalid",
                "The SQL Server sequence evidence does not cover the signed source identity inventory.");
        }
        var mapped = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (TableCopyPlan target in TargetSchema.Tables)
        {
            TableCopyPlan source = SourceTableFor(target);
            foreach (IdentityCopyPlan identity in target.Identities)
            {
                string sourceKey = $"{source.TargetSchema}.{source.TargetTable}.{identity.Column}";
                mapped.Add($"{target.TargetSchema}.{target.TargetTable}.{identity.Column}", sourceSequences[sourceKey]);
            }
        }
        return new ReadOnlyDictionary<string, long>(mapped);
    }
}

public static class QuotationDeltaExecutionPreflight
{
    public static void Validate(DeltaSynchronizationPlan plan, FreshSchemaPlan schemaPlan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(schemaPlan);
        if (!schemaPlan.Databases.Any(ApprovedSourceDispositionManifest.RequiresQuotationExecution))
        {
            return;
        }
        if (plan.SchemaVersion is not ("1.2" or "1.3" or "1.4") ||
            !plan.Databases.Select(database => database.Database).SequenceEqual(
                DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !schemaPlan.Databases.Select(database => database.Database).SequenceEqual(
                DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !string.Equals(plan.SourceCommitSha, schemaPlan.SourceCommitSha, StringComparison.Ordinal) ||
            !string.Equals(plan.SchemaPlanSha256, SchemaPlanCanonicalizer.ComputeSha256(schemaPlan), StringComparison.Ordinal))
        {
            throw new DeltaExecutionException("delta_execution_quotation_transformation_required",
                "Unbound Quotation disposition execution is not supported.");
        }
        foreach (DatabaseSchemaPlan schema in schemaPlan.Databases)
        {
            _ = QuotationDeltaPhysicalSchemaGuard.ExpectedPhysicalSchema(plan, schema);
            if (schema.SourceDispositionProfile is null &&
                ApprovedSourceDispositionManifest.RequiresQuotationExecution(schema))
            {
                throw new DeltaExecutionException("delta_execution_quotation_transformation_required",
                    "Quotation outboxes require their reviewed signed disposition.");
            }
            DatabaseSchemaPlan target = new QuotationDeltaExecutionMapping(schema).TargetSchema;
            DeltaDatabasePlan databasePlan = plan.Databases.Single(database => database.Database == schema.Database);
            if (!databasePlan.Tables.Select(table => table.Table).Order(StringComparer.Ordinal).SequenceEqual(
                target.Tables.Select(table => $"{table.TargetSchema}.{table.TargetTable}").Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
            {
                throw new DeltaExecutionException("delta_execution_table_inventory_invalid",
                    "The signed delta operations do not cover the reviewed target table inventory.");
            }
        }
    }

    public static bool RequiresQuotationExecution(DatabaseSchemaPlan schema)
    {
        return ApprovedSourceDispositionManifest.RequiresQuotationExecution(schema);
    }
}

public sealed class QuotationMappedDeltaRowSource(
    IDeltaOrderedRowSource source,
    FreshSchemaPlan schemaPlan) : IDeltaOrderedRowSource
{
    private readonly Dictionary<string, QuotationDeltaExecutionMapping> _bindings = schemaPlan.Databases
        .ToDictionary(schema => schema.Database, schema => new QuotationDeltaExecutionMapping(schema), StringComparer.Ordinal);

    public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(
        string database,
        TableCopyPlan table,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (!_bindings.TryGetValue(database, out QuotationDeltaExecutionMapping? binding))
        {
            throw new DeltaExecutionException("delta_execution_disposition_database_invalid",
                "The requested database is absent from the signed schema plan.");
        }
        TableCopyPlan sourceTable = binding.SourceTableFor(table);
        await foreach (MigrationRow row in source.ReadOrderedAsync(database, sourceTable, cancellationToken)
            .WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            yield return binding.MapRow(table, row);
        }
    }
}
