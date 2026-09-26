namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Binds known source-only transformation decisions to the signed schema plan.
/// This does not authorize row copying or relax the exact-23 delta planner's outbox guard.
/// </summary>
internal static class ApprovedSourceDispositionManifest
{
    internal const string QuotationOutboxesV1 = "quotation-outboxes-v1";

    internal static string? ProfileForDatabase(string database, IReadOnlyList<TableCopyPlan> tables)
    {
        ArgumentNullException.ThrowIfNull(tables);
        if (!string.Equals(database, "Quotation", StringComparison.Ordinal))
        {
            return null;
        }

        bool hasOutbox = tables.Any(IsOutbox);
        if (!hasOutbox)
        {
            return null;
        }

        ValidateQuotationOutboxes(tables);
        return QuotationOutboxesV1;
    }

    internal static void Validate(DatabaseSchemaPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (plan.SourceDispositionProfile is null)
        {
            if (string.Equals(plan.Database, "Quotation", StringComparison.Ordinal) && plan.Tables.Any(IsOutbox))
            {
                throw Invalid();
            }

            return;
        }

        if (!string.Equals(plan.Database, "Quotation", StringComparison.Ordinal) ||
            !string.Equals(plan.SourceDispositionProfile, QuotationOutboxesV1, StringComparison.Ordinal))
        {
            throw Invalid();
        }

        ValidateQuotationOutboxes(plan.Tables);
    }

    private static bool IsOutbox(TableCopyPlan table)
    {
        return string.Equals(table.SourceSchema, "dbo", StringComparison.Ordinal) &&
            (string.Equals(table.SourceTable, "GoogleAnalyticsOutbox", StringComparison.Ordinal) ||
             string.Equals(table.SourceTable, "QuotationOutcomeOutbox", StringComparison.Ordinal));
    }

    private static void ValidateQuotationOutboxes(IReadOnlyList<TableCopyPlan> tables)
    {
        ValidateOutbox(tables, CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
            "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true);
        ValidateOutbox(tables, CurrentQuotationSourceContract.QuotationOutcomeOutbox,
            "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false);
    }

    private static void ValidateOutbox(
        IReadOnlyList<TableCopyPlan> tables,
        SourceTableContract contract,
        string primaryKeyName,
        string eventKeyName,
        bool uniqueIndex)
    {
        string sourceTable = contract.Name["dbo.".Length..];
        TableCopyPlan[] matches = [.. tables.Where(candidate =>
            string.Equals(candidate.SourceSchema, "dbo", StringComparison.Ordinal) &&
            string.Equals(candidate.SourceTable, sourceTable, StringComparison.Ordinal))];
        if (matches.Length != 1)
        {
            throw Invalid();
        }

        TableCopyPlan table = matches[0];
        if (
            !string.Equals(table.TargetSchema, "public", StringComparison.Ordinal) ||
            !string.Equals(table.TargetTable, sourceTable, StringComparison.Ordinal) ||
            !table.OrderedColumns.SequenceEqual(contract.Columns.Select(column => column.Name), StringComparer.Ordinal) ||
            table.SourceColumnTypes.Count != contract.Columns.Count ||
            contract.Columns.Any(column => !table.SourceColumnTypes.TryGetValue(column.Name, out string? type) ||
                !string.Equals(type, column.StoreType, StringComparison.OrdinalIgnoreCase)) ||
            !table.NullableColumns.Order(StringComparer.Ordinal).SequenceEqual(
                contract.Columns.Where(column => column.Nullable).Select(column => column.Name).Order(StringComparer.Ordinal),
                StringComparer.Ordinal) ||
            !table.IdentityColumns.SequenceEqual(contract.Columns.Where(column => column.Identity is not null)
                .Select(column => column.Name), StringComparer.Ordinal) ||
            table.PrimaryKey is null ||
            !string.Equals(table.PrimaryKey.Name, primaryKeyName, StringComparison.Ordinal) ||
            !table.PrimaryKey.Columns.SequenceEqual(["ID"], StringComparer.Ordinal) ||
            !(uniqueIndex
                ? table.Indexes.Any(index => string.Equals(index.Name, eventKeyName, StringComparison.Ordinal) &&
                    index.Unique && index.Columns.SequenceEqual(["EventKey"], StringComparer.Ordinal))
                : table.UniqueConstraints.Any(unique => string.Equals(unique.Name, eventKeyName, StringComparison.Ordinal) &&
                    unique.Columns.SequenceEqual(["EventKey"], StringComparer.Ordinal))))
        {
            throw Invalid();
        }
    }

    private static MigrationExecutionException Invalid()
    {
        return new("source_disposition_profile_invalid",
            "Quotation outbox source tables do not match the reviewed transformation disposition.");
    }
}
