namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Binds known source-only transformation decisions to the signed schema plan.
/// This does not authorize row copying or relax the exact-23 delta planner's outbox guard.
/// </summary>
internal static class ApprovedSourceDispositionManifest
{
    internal const string QuotationOutboxesV1 = "quotation-outboxes-v1";

    internal static IReadOnlyList<SourceTableDisposition> DispositionsForDatabase(
        string database, IReadOnlyList<TableCopyPlan> tables)
    {
        if (ProfileForDatabase(database, tables) is null)
        {
            return [];
        }

        string contractSha = CurrentQuotationSourceContract.SourceContractSha256;
        return
        [
            new("dbo", "GoogleAnalyticsOutbox", "read-only-archive", "legacy_compatibility",
                "GoogleAnalyticsOutbox", contractSha, "1.1"),
            new("dbo", "QuotationOutcomeOutbox", "canonical-adoption", "public",
                "QuotationAcceptedOutcome", contractSha, "1.0"),
        ];
    }

    internal static IReadOnlyList<TableCopyPlan> TargetTablesFor(DatabaseSchemaPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        Validate(plan);
        if (plan.SourceDispositionProfile is null)
        {
            return plan.Tables;
        }

        TableCopyPlan analytics = plan.Tables.Single(table =>
            string.Equals(table.SourceSchema, "dbo", StringComparison.Ordinal) &&
            string.Equals(table.SourceTable, "GoogleAnalyticsOutbox", StringComparison.Ordinal));
        return
        [
            .. plan.Tables.Where(table => !IsOutbox(table)),
            AnalyticsArchive(analytics),
            AcceptedOutcome(),
        ];
    }

    internal static IReadOnlyList<string> AnalyticsTimestampColumns { get; } =
        ["OccurredUtc", "NextAttemptUtc", "LeaseUntilUtc", "SentUtc", "FailedUtc"];

    private static TableCopyPlan AnalyticsArchive(TableCopyPlan source)
    {
        string[] remainders = [.. AnalyticsTimestampColumns.Select(column => $"{column}SubMicrosecondTicks")];
        var types = new Dictionary<string, string>(source.ColumnTypes, StringComparer.Ordinal);
        var defaults = new Dictionary<string, string>(source.DefaultExpressions, StringComparer.Ordinal);
        var nullable = new List<string>(source.NullableColumns);
        foreach (string column in AnalyticsTimestampColumns)
        {
            string remainder = $"{column}SubMicrosecondTicks";
            types[column] = "timestamp without time zone";
            types.Add(remainder, "smallint");
            if (source.NullableColumns.Contains(column, StringComparer.Ordinal))
            {
                nullable.Add(remainder);
            }
            else
            {
                defaults.Add(remainder, "0");
            }
        }

        return source with
        {
            SourceSchema = "disposition",
            TargetSchema = "legacy_compatibility",
            OrderedColumns = [.. source.OrderedColumns, .. remainders],
            ColumnTypes = types,
            NullableColumns = nullable,
            DefaultExpressions = defaults,
            CheckConstraints =
            [
                .. source.CheckConstraints,
                .. remainders.Select(column => new CheckConstraintCopyPlan(
                    $"CK_GoogleAnalyticsOutbox_{column}",
                    $"\"{column}\" >= 0 AND \"{column}\" <= 9") { Columns = [column] }),
            ],
        };
    }

    internal static void RequireOrdinarySchemaApplication(DatabaseSchemaPlan plan)
    {
        Validate(plan);
        if (plan.SourceDispositionProfile is not null)
        {
            throw new MigrationExecutionException("source_disposition_schema_application_not_ready",
                "Quotation outboxes require archive/adoption execution; an ordinary shadow copy cannot create their target schema.");
        }
    }

    private static TableCopyPlan AcceptedOutcome()
    {
        return new("disposition", "QuotationOutcomeOutbox", "public", "QuotationAcceptedOutcome",
            ["ID", "EventKey", "QuotationID", "SourceRequestID", "SourceJourneyID", "AcceptedUtc",
                "AcceptanceOrigin", "AcceptedUtcSubMicrosecondTicks"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ID"] = "bigint",
                ["EventKey"] = "character varying(128)",
                ["QuotationID"] = "integer",
                ["SourceRequestID"] = "integer",
                ["SourceJourneyID"] = "uuid",
                ["AcceptedUtc"] = "timestamp without time zone",
                ["AcceptanceOrigin"] = "character varying(16)",
                ["AcceptedUtcSubMicrosecondTicks"] = "smallint",
            },
            NullableColumns = ["SourceRequestID", "SourceJourneyID"],
            Identities = [new IdentityCopyPlan("ID", 1, 1, 1, false)],
            PrimaryKey = new PrimaryKeyCopyPlan("PK_QuotationAcceptedOutcome", ["ID"]),
            Indexes =
            [
                new("IX_QuotationAcceptedOutcome_AcceptedUtc", ["AcceptedUtc"], false),
                new("IX_QuotationAcceptedOutcome_EventKey", ["EventKey"], true),
                new("IX_QuotationAcceptedOutcome_QuotationID", ["QuotationID"], false),
                new("IX_QuotationAcceptedOutcome_SourceJourneyID", ["SourceJourneyID"], false),
                new("IX_QuotationAcceptedOutcome_SourceRequestID", ["SourceRequestID"], false),
            ],
            DefaultExpressions = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["AcceptedUtcSubMicrosecondTicks"] = "0",
            },
        };
    }

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
            if (plan.SourceTableDispositions.Count != 0 ||
                (string.Equals(plan.Database, "Quotation", StringComparison.Ordinal) && plan.Tables.Any(IsOutbox)))
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
        if (!plan.SourceTableDispositions.SequenceEqual(
            DispositionsForDatabase(plan.Database, plan.Tables)))
        {
            throw Invalid();
        }
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
