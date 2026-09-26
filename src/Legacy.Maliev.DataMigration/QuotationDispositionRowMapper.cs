namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Converts the two reviewed Quotation source outboxes to their signed PostgreSQL
/// target shapes. This is a row transformation only; it cannot authorize DDL or
/// bypass the exact-23 planner's disposition gate.
/// </summary>
internal sealed class QuotationDispositionRowMapper
{
    private readonly TableCopyPlan _analyticsSource;
    private readonly TableCopyPlan _outcomeSource;

    internal QuotationDispositionRowMapper(DatabaseSchemaPlan schema)
    {
        ArgumentNullException.ThrowIfNull(schema);
        ApprovedSourceDispositionManifest.Validate(schema);
        if (schema.SourceDispositionProfile != ApprovedSourceDispositionManifest.QuotationOutboxesV1)
        {
            throw Invalid();
        }

        _analyticsSource = schema.Tables.Single(table =>
            table.SourceSchema == "dbo" && table.SourceTable == "GoogleAnalyticsOutbox");
        _outcomeSource = schema.Tables.Single(table =>
            table.SourceSchema == "dbo" && table.SourceTable == "QuotationOutcomeOutbox");
        IReadOnlyList<TableCopyPlan> targets = ApprovedSourceDispositionManifest.TargetTablesFor(schema);
        AnalyticsArchive = targets.Single(table => table.TargetSchema == "legacy_compatibility" &&
            table.TargetTable == "GoogleAnalyticsOutbox");
        AcceptedOutcome = targets.Single(table => table.TargetSchema == "public" &&
            table.TargetTable == "QuotationAcceptedOutcome");
    }

    internal TableCopyPlan AnalyticsArchive { get; }

    internal TableCopyPlan AcceptedOutcome { get; }

    internal MigrationRow MapAnalytics(MigrationRow source)
    {
        ValidateSourceRow(_analyticsSource, source);
        var values = new Dictionary<string, object?>(source.Values, StringComparer.Ordinal);
        foreach (string column in ApprovedSourceDispositionManifest.AnalyticsTimestampColumns)
        {
            string remainder = $"{column}SubMicrosecondTicks";
            object? value = source.Values[column];
            if (value is null or DBNull)
            {
                if (!_analyticsSource.NullableColumns.Contains(column, StringComparer.Ordinal))
                {
                    throw Invalid();
                }
                values[column] = null;
                values.Add(remainder, null);
                continue;
            }

            if (value is not DateTime date || date.Kind != DateTimeKind.Unspecified)
            {
                throw Invalid();
            }
            values[column] = date.AddTicks(-(date.Ticks % TimeSpan.TicksPerMicrosecond));
            values.Add(remainder, checked((short)(date.Ticks % TimeSpan.TicksPerMicrosecond)));
        }

        var mapped = new MigrationRow(values);
        CanonicalDeltaPlanner.ValidateRow(AnalyticsArchive, mapped, "analytics archive");
        return mapped;
    }

    internal MigrationRow MapOutcome(MigrationRow source)
    {
        ValidateSourceRow(_outcomeSource, source);
        if (source.Values["ID"] is not long id || source.Values["EventKey"] is not string eventKey ||
            source.Values["QuotationID"] is not int quotationId ||
            source.Values["AcceptedUtc"] is not DateTime acceptedUtc ||
            source.Values["AcceptanceOrigin"] is not string acceptanceOrigin)
        {
            throw Invalid();
        }

        int? requestId = NullableValue<int>(source.Values["SourceRequestID"]);
        Guid? journeyId = NullableValue<Guid>(source.Values["SourceJourneyID"]);
        QuotationAcceptedOutcomeImportRow outcome;
        try
        {
            outcome = QuotationOutcomeTransformPlanner.Map(new(id, eventKey, quotationId,
                requestId, journeyId, acceptedUtc, acceptanceOrigin));
        }
        catch (QuotationOutcomeTransformException exception)
        {
            throw new MigrationExecutionException(exception.Code, exception.Message);
        }

        var values = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ID"] = outcome.ID,
            ["EventKey"] = outcome.EventKey,
            ["QuotationID"] = outcome.QuotationID,
            ["SourceRequestID"] = outcome.SourceRequestID,
            ["SourceJourneyID"] = outcome.SourceJourneyID,
            ["AcceptedUtc"] = outcome.AcceptedUtc.AddTicks(-(outcome.AcceptedUtc.Ticks % TimeSpan.TicksPerMicrosecond)),
            ["AcceptanceOrigin"] = outcome.AcceptanceOrigin,
            ["AcceptedUtcSubMicrosecondTicks"] = checked((short)(outcome.AcceptedUtc.Ticks % TimeSpan.TicksPerMicrosecond)),
        };
        var mapped = new MigrationRow(values);
        CanonicalDeltaPlanner.ValidateRow(AcceptedOutcome, mapped, "accepted outcome");
        return mapped;
    }

    private static T? NullableValue<T>(object? value) where T : struct
    {
        return value switch
        {
            null or DBNull => null,
            T typed => typed,
            _ => throw Invalid(),
        };
    }

    private static void ValidateSourceRow(TableCopyPlan table, MigrationRow? source)
    {
        if (source is null)
        {
            throw Invalid();
        }
        try
        {
            CanonicalDeltaPlanner.ValidateRow(table, source, "disposition source");
        }
        catch (DeltaPlanningException)
        {
            throw Invalid();
        }
    }

    private static MigrationExecutionException Invalid()
    {
        return new("quotation_disposition_row_invalid",
            "A Quotation outbox row does not match its signed source disposition.");
    }
}
