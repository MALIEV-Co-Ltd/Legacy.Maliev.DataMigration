using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SchemaPlanSemanticsTests
{
    [Fact]
    public void ComputeSha256_SchemaObjectSemanticsChange_ChangesSignedPlan()
    {
        FreshSchemaPlan baseline = CreatePlan(CreateTable());
        TableCopyPlan changedTable = CreateTable() with
        {
            CheckConstraints =
            [
                new CheckConstraintCopyPlan("CK_orders_quantity", "\"Quantity\" >= 1")
                {
                    Columns = ["Quantity"],
                },
            ],
        };

        Assert.NotEqual(
            SchemaPlanCanonicalizer.ComputeSha256(baseline),
            SchemaPlanCanonicalizer.ComputeSha256(CreatePlan(changedTable)));
    }

    [Fact]
    public void ComputeSha256_EverySchemaObjectKind_IsBoundIntoSignature()
    {
        TableCopyPlan baseline = CreateTable() with
        {
            PrimaryKey = null,
            UniqueConstraints = [],
            Indexes = [],
            DefaultExpressions = new Dictionary<string, string>(StringComparer.Ordinal),
            CheckConstraints = [],
            GeneratedColumns = [],
            Collations = new Dictionary<string, string>(StringComparer.Ordinal),
        };
        TableCopyPlan[] variants =
        [
            baseline,
            baseline with { PrimaryKey = new PrimaryKeyCopyPlan("PK_orders", ["Id"]) },
            baseline with { UniqueConstraints = [new UniqueConstraintCopyPlan("UQ_orders_created", ["CreatedAt"])] },
            baseline with { Indexes = [new IndexCopyPlan("IX_orders_quantity", ["Quantity"], false)] },
            baseline with
            {
                DefaultExpressions = new Dictionary<string, string>(StringComparer.Ordinal) { ["Quantity"] = "1" },
            },
            baseline with
            {
                CheckConstraints =
                [
                    new CheckConstraintCopyPlan("CK_orders_quantity", "\"Quantity\" > 0")
                    {
                        Columns = ["Quantity"],
                    },
                ],
            },
            baseline with { GeneratedColumns = [new GeneratedColumnCopyPlan("Quantity", "1")] },
            baseline with
            {
                Collations = new Dictionary<string, string>(StringComparer.Ordinal) { ["CreatedAt"] = "C" },
            },
        ];

        string[] hashes = [.. variants.Select(table => SchemaPlanCanonicalizer.ComputeSha256(CreatePlan(table)))];

        Assert.Equal(hashes.Length, hashes.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void Validate_MissingExplicitSourceTypes_FailsClosed()
    {
        TableCopyPlan table = CreateTable() with
        {
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal),
        };
        FreshSchemaPlan plan = CreatePlan(table);

        IReadOnlyList<PreflightError> errors = SchemaPlanCanonicalizer.Validate(
            plan,
            new GuardedRunnerPolicy(SourceCommit, RunnerDigest),
            CapturedAt.AddMinutes(1),
            TimeSpan.FromHours(1));

        Assert.Contains(errors, error => error.Code == "table_plan_invalid");
    }

    [Fact]
    public void Validate_Datetime2MappedToTimestampWithTimeZone_FailsClosed()
    {
        TableCopyPlan table = CreateTable() with
        {
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "int",
                ["Quantity"] = "int",
                ["CreatedAt"] = "datetime2",
            },
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "integer",
                ["Quantity"] = "integer",
                ["CreatedAt"] = "timestamp with time zone",
            },
        };

        IReadOnlyList<PreflightError> errors = SchemaPlanCanonicalizer.Validate(
            CreatePlan(table),
            new GuardedRunnerPolicy(SourceCommit, RunnerDigest),
            CapturedAt.AddMinutes(1),
            TimeSpan.FromHours(1));

        Assert.Contains(errors, error => error.Code == "temporal_mapping_invalid");
    }

    [Fact]
    public void Validate_SchemaObjectsReferenceUnknownColumns_FailsClosed()
    {
        TableCopyPlan table = CreateTable() with
        {
            Indexes = [new IndexCopyPlan("IX_orders_missing", ["Missing"], false)],
        };

        IReadOnlyList<PreflightError> errors = SchemaPlanCanonicalizer.Validate(
            CreatePlan(table),
            new GuardedRunnerPolicy(SourceCommit, RunnerDigest),
            CapturedAt.AddMinutes(1),
            TimeSpan.FromHours(1));

        Assert.Contains(errors, error => error.Code == "table_plan_invalid");
    }

    [Fact]
    public void Validate_SignedExpressionContainsSecondStatement_FailsClosed()
    {
        TableCopyPlan table = CreateTable() with
        {
            DefaultExpressions = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Quantity"] = "1; DROP TABLE sales.orders",
            },
        };

        IReadOnlyList<PreflightError> errors = SchemaPlanCanonicalizer.Validate(
            CreatePlan(table),
            new GuardedRunnerPolicy(SourceCommit, RunnerDigest),
            CapturedAt.AddMinutes(1),
            TimeSpan.FromHours(1));

        Assert.Contains(errors, error => error.Code == "table_plan_invalid");
    }

    [Fact]
    public void ComputeSha256_IndexForeignKeyAndIdentitySemanticsChange_ChangesSignature()
    {
        TableCopyPlan baseline = CreateTable() with
        {
            Identities = [new IdentityCopyPlan("Id", 100, 5, 145, true)],
            Indexes =
            [
                new IndexCopyPlan("IX_orders_quantity", ["Quantity"], false)
                {
                    DescendingColumns = ["Quantity"],
                    IncludedColumns = ["CreatedAt"],
                    FilterPredicate = "\"Quantity\" > 0",
                },
            ],
            ForeignKeys =
            [
                new ForeignKeyCopyPlan("FK_orders_parent", ["Id"], "sales", "orders", ["Id"])
                {
                    OnDelete = ReferentialAction.Cascade,
                    OnUpdate = ReferentialAction.Restrict,
                },
            ],
        };

        string original = SchemaPlanCanonicalizer.ComputeSha256(CreatePlan(baseline));
        Assert.NotEqual(original, SchemaPlanCanonicalizer.ComputeSha256(CreatePlan(
            baseline with { Identities = [baseline.Identities[0] with { CurrentValue = 150 }] })));
        Assert.NotEqual(original, SchemaPlanCanonicalizer.ComputeSha256(CreatePlan(
            baseline with { Indexes = [baseline.Indexes[0] with { FilterPredicate = "\"Quantity\" >= 0" }] })));
        Assert.NotEqual(original, SchemaPlanCanonicalizer.ComputeSha256(CreatePlan(
            baseline with { ForeignKeys = [baseline.ForeignKeys[0] with { OnDelete = ReferentialAction.NoAction }] })));
    }

    [Fact]
    public void Validate_OrderByDoesNotContainNonNullableUniqueKey_FailsClosed()
    {
        TableCopyPlan table = CreateTable() with { OrderByColumns = ["Quantity"], PrimaryKey = null };

        IReadOnlyList<PreflightError> errors = SchemaPlanCanonicalizer.Validate(
            CreatePlan(table),
            new GuardedRunnerPolicy(SourceCommit, RunnerDigest),
            CapturedAt.AddMinutes(1),
            TimeSpan.FromHours(1));

        Assert.Contains(errors, error => error.Code == "order_by_not_total");
    }

    [Fact]
    public void Validate_DisabledOrUntrustedForeignKey_FailsClosed()
    {
        TableCopyPlan table = CreateTable() with
        {
            ForeignKeys =
            [
                new ForeignKeyCopyPlan("FK_orders_parent", ["Id"], "sales", "orders", ["Id"])
                {
                    SourceEnabled = false,
                    SourceTrusted = false,
                },
            ],
        };

        IReadOnlyList<PreflightError> errors = SchemaPlanCanonicalizer.Validate(
            CreatePlan(table),
            new GuardedRunnerPolicy(SourceCommit, RunnerDigest),
            CapturedAt.AddMinutes(1),
            TimeSpan.FromHours(1));

        Assert.Contains(errors, error => error.Code == "foreign_key_disposition_unsupported");
    }

    internal static TableCopyPlan CreateTable()
    {
        return new TableCopyPlan(
            "dbo",
            "Orders",
            "sales",
            "orders",
            ["Id", "Quantity", "CreatedAt"],
            ["Id"])
        {
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "int",
                ["Quantity"] = "int",
                ["CreatedAt"] = "datetime2",
            },
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "integer",
                ["Quantity"] = "integer",
                ["CreatedAt"] = "timestamp without time zone",
            },
            PrimaryKey = new PrimaryKeyCopyPlan("PK_orders", ["Id"]),
            UniqueConstraints = [new UniqueConstraintCopyPlan("UQ_orders_created", ["CreatedAt"])],
            Indexes = [new IndexCopyPlan("IX_orders_quantity", ["Quantity"], false)],
            DefaultExpressions = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Quantity"] = "1",
            },
            CheckConstraints =
            [
                new CheckConstraintCopyPlan("CK_orders_quantity", "\"Quantity\" > 0")
                {
                    Columns = ["Quantity"],
                },
            ],
            Collations = new Dictionary<string, string>(StringComparer.Ordinal),
        };
    }

    private static FreshSchemaPlan CreatePlan(TableCopyPlan table)
    {
        return new FreshSchemaPlan(
            "2.0",
            CapturedAt,
            SourceCommit,
            [.. DatabaseInventory.ActiveDatabases.Select(database => new DatabaseSchemaPlan(
                database,
                "1.0",
                Hash($"source:{database}"),
                Hash($"target:{database}"),
                [table]))]);
    }

    private static string Hash(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    private static readonly DateTimeOffset CapturedAt = new(2026, 8, 29, 4, 0, 0, TimeSpan.Zero);
    private const string SourceCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static readonly string RunnerDigest = new('b', 64);
}
