using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record ConsumerColumnBootstrapOperand(string Database, string Schema, string Table, string Column,
    string PostgreSqlType, int AppendOrdinal, bool Nullable, string? DefaultExpression, string OwnerDefinitionProfile);

/// <summary>Fixed pure preparation only. No executor, permit, signed receipt or persistent-write authority.</summary>
internal sealed class ConsumerColumnBootstrapContract
{
    private static readonly ConsumerColumnBootstrapOperand[] Fixed =
    [
        new("CustomerIdentity", "public", "AspNetUsers", "PasswordSetupRequired", "boolean", 19, false, "false", ApprovedConsumerColumnOverlayManifest.CustomerV2),
        new("Quotation", "public", "Quotation", "DecisionOrderVersion", "timestamp without time zone", 24, true, null, ApprovedConsumerColumnOverlayManifest.QuotationV1),
    ];
    private readonly DatabaseSchemaPlan[] _before, _after;
    internal string LogicalSourcePlanSha256 { get; }
    internal string SourceCommitSha { get; }
    internal DateTimeOffset SourceCapturedAtUtc { get; }
    private readonly string _digest;

    private ConsumerColumnBootstrapContract(FreshSchemaPlan logical, DatabaseSchemaPlan[] before, DatabaseSchemaPlan[] after)
    {
        _before = before; _after = after;
        LogicalSourcePlanSha256 = SchemaPlanCanonicalizer.ComputeSha256(logical);
        SourceCommitSha = logical.SourceCommitSha; SourceCapturedAtUtc = logical.CapturedAtUtc;
        _digest = Hash([.. "Legacy.Maliev.ConsumerColumnBootstrap.Preparation.v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(new
            {
                LogicalSourcePlanSha256, SourceCommitSha, SourceCapturedAtUtc, Operands = Fixed,
                OwnerDefinitions = ApprovedCurrentConsumerSchemaManifest.ServiceContractsSha256,
                Before = before.Select(x => new { x.Database, x.TargetSchemaSha256 }).ToArray(),
                After = after.Select(x => new { x.Database, x.TargetSchemaSha256 }).ToArray(),
                Statements = Fixed.Select(x => Hash(Encoding.UTF8.GetBytes(CandidateSql(x.Database)))).ToArray(),
                Scope = "pure-preparation-and-disposable-characterization-no-execution-authority",
            })]);
    }

    internal static ConsumerColumnBootstrapContract Create(FreshSchemaPlan logical, string independentlyExpectedSourceCommitSha, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(logical);
        logical = Clone(logical);
        if (independentlyExpectedSourceCommitSha is not { Length: 40 } || !independentlyExpectedSourceCommitSha.All(char.IsAsciiHexDigitLower) ||
            logical.SourceCommitSha != independentlyExpectedSourceCommitSha ||
            SchemaPlanCanonicalizer.Validate(logical, new(logical.SourceCommitSha, new string('0', 64)), nowUtc, TimeSpan.FromHours(2)).Count != 0)
        { throw Invalid(); }
        ProductionSchemaCatalogInspector.ValidatePlan(logical, nowUtc);
        if (!ApprovedConsumerOverlaySelection.IsApproved(logical) || logical.Databases.Sum(x => x.Tables.Count) != 100 ||
            logical.Databases.Single(x => x.Database == "Quotation").SourceDispositionProfile != ApprovedSourceDispositionManifest.QuotationOutboxesV1)
        { throw Invalid(); }
        var before = new List<DatabaseSchemaPlan>(); var after = new List<DatabaseSchemaPlan>();
        foreach (ConsumerColumnBootstrapOperand operand in Fixed)
        {
            DatabaseSchemaPlan database = logical.Databases.Single(x => x.Database == operand.Database);
            DatabaseSchemaPlan oldPhase = database with
            {
                TargetExtensionProfile = ApprovedConsumerOverlaySelection.ProfileForDatabase(
                database.Database, ConsumerOverlaySelection.HistoricalDefaults)
            };
            DatabaseSchemaPlan newPhase = database with
            {
                TargetExtensionProfile = ApprovedConsumerOverlaySelection.ProfileForDatabase(
                database.Database, ConsumerOverlaySelection.CurrentConsumerColumnsV1)
            };
            TableCopyPlan[] oldTables = [.. ApprovedConsumerColumnOverlayManifest.ComposePhysical(oldPhase)];
            TableCopyPlan[] newTables = [.. ApprovedConsumerColumnOverlayManifest.ComposePhysical(newPhase)];
            TableCopyPlan root = oldTables.Single(x => x.TargetSchema == operand.Schema && x.TargetTable == operand.Table);
            TableCopyPlan added = newTables.Single(x => x.TargetSchema == operand.Schema && x.TargetTable == operand.Table);
            if (root.SourceSchema != "dbo" || root.SourceTable != operand.Table || root.OrderedColumns.Count != operand.AppendOrdinal - 1 ||
                added.OrderedColumns.Count != operand.AppendOrdinal || added.OrderedColumns[^1] != operand.Column ||
                added.ColumnTypes.GetValueOrDefault(operand.Column) != operand.PostgreSqlType ||
                added.NullableColumns.Contains(operand.Column, StringComparer.Ordinal) != operand.Nullable ||
                added.DefaultExpressions.GetValueOrDefault(operand.Column) != operand.DefaultExpression || added.Collations.ContainsKey(operand.Column) ||
                !oldTables.Select(x => (x.TargetSchema, x.TargetTable)).SequenceEqual(newTables.Select(x => (x.TargetSchema, x.TargetTable))))
            { throw Invalid(); }
            foreach ((TableCopyPlan oldTable, TableCopyPlan newTable) in oldTables.Zip(newTables))
            {
                TableCopyPlan retained = newTable.TargetSchema == operand.Schema && newTable.TargetTable == operand.Table
                    ? newTable with
                    {
                        OrderedColumns = root.OrderedColumns,
                        ColumnTypes = newTable.ColumnTypes.Where(x => x.Key != operand.Column).ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal),
                        NullableColumns = newTable.NullableColumns.Where(x => x != operand.Column).ToArray(),
                        DefaultExpressions = newTable.DefaultExpressions.Where(x => x.Key != operand.Column).ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal),
                    } : newTable;
                if (JsonSerializer.Serialize(oldTable) != JsonSerializer.Serialize(retained)) { throw Invalid(); }
            }
            // Detached physical views only. They are never relabelled as fresh source inventories or passed to source projection.
            before.Add(PhysicalView(database, oldTables)); after.Add(PhysicalView(database, newTables));
        }
        return new(logical, before.ToArray(), after.ToArray());
    }

    internal static IReadOnlyList<ConsumerColumnBootstrapOperand> Operands()
    {
        return Array.AsReadOnly(Fixed.ToArray());
    }

    internal DatabaseSchemaPlan Before(string database)
    {
        return Clone(_before.SingleOrDefault(x => x.Database == database) ?? throw Invalid());
    }

    internal DatabaseSchemaPlan After(string database)
    {
        return Clone(_after.SingleOrDefault(x => x.Database == database) ?? throw Invalid());
    }

    internal string ComputeSha256()
    {
        return _digest;
    }

    internal static string CandidateSql(string database)
    {
        return database switch
        {
            "CustomerIdentity" => """
            SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='30s';
            LOCK TABLE public."AspNetUsers" IN ACCESS EXCLUSIVE MODE;
            ALTER TABLE public."AspNetUsers" ADD COLUMN "PasswordSetupRequired" boolean NOT NULL DEFAULT false;
            """,
            "Quotation" => """
            SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='30s';
            LOCK TABLE public."Quotation" IN ACCESS EXCLUSIVE MODE;
            ALTER TABLE public."Quotation" ADD COLUMN "DecisionOrderVersion" timestamp without time zone NULL;
            """,
            _ => throw Invalid(),
        };
    }

    private static DatabaseSchemaPlan PhysicalView(DatabaseSchemaPlan logicalDatabase, TableCopyPlan[] tables)
    {
        var view = logicalDatabase with { Tables = tables, TargetExtensionProfile = null, SourceDispositionProfile = null, SourceTableDispositions = [] };
        return Clone(view with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(view) });
    }
    private static T Clone<T>(T value)
    {
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value))!;
    }

    private static string Hash(byte[] value)
    {
        return Convert.ToHexStringLower(SHA256.HashData(value));
    }

    private static MigrationExecutionException Invalid()
    {
        return new("consumer_column_bootstrap_preparation_invalid",
            "Only the fixed two-column planning contract and unchanged reviewed source inventory are supported.");
    }
}
