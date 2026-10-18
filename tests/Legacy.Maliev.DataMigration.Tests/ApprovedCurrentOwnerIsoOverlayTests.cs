using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ApprovedCurrentOwnerIsoOverlayTests
{
    internal static readonly DateTimeOffset Now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(ConsumerOverlaySelection.HistoricalDefaults)]
    [InlineData(ConsumerOverlaySelection.CurrentConsumerColumnsV1)]
    [InlineData(ConsumerOverlaySelection.CurrentConsumerSchemaV2)]
    [InlineData(ConsumerOverlaySelection.CurrentConsumerSchemaV3)]
    public void Explicit_overlay_changes_only_four_types_without_mutating_any_historical_profile(ConsumerOverlaySelection profile)
    {
        FreshSchemaPlan schema = Schema(profile);
        string original = JsonSerializer.Serialize(schema);
        var contract = Create(schema);
        Assert.Equal(4, ApprovedCurrentOwnerIsoOverlay.Operands().Length);
        Assert.Equal(64, contract.ComputeSha256().Length);
        Assert.Equal(contract.ComputeSha256(), Create(schema).ComputeSha256());
        foreach (DatabaseSchemaPlan database in schema.Databases)
        {
            TableCopyPlan[] before = contract.PhysicalTables(database.Database, false);
            TableCopyPlan[] after = contract.PhysicalTables(database.Database, true);
            foreach ((TableCopyPlan left, TableCopyPlan right) in before.Zip(after))
            {
                bool changed = (database.Database is "Country" or "Material") && left.TargetTable == "Country";
                if (changed)
                {
                    Assert.Equal("character varying(2)", right.ColumnTypes["ISO2"]);
                    Assert.Equal("character varying(3)", right.ColumnTypes["ISO3"]);
                    Assert.Equal(JsonSerializer.Serialize(left), JsonSerializer.Serialize(right with { ColumnTypes = left.ColumnTypes }));
                }
                else { Assert.Equal(JsonSerializer.Serialize(left), JsonSerializer.Serialize(right)); }
                contract.RequirePhysicalTable(database.Database, left, false);
                contract.RequirePhysicalTable(database.Database, right, true);
            }
        }
        Assert.Equal(original, JsonSerializer.Serialize(schema));
        Assert.Equal(23, schema.Databases.Count);
        Assert.Equal(100, schema.Databases.Sum(x => x.Tables.Count));
        // Returned graphs and operand arrays cannot mutate the preparation contract.
        var returned = contract.PhysicalTables("Country", true);
        ((Dictionary<string, string>)returned[0].ColumnTypes)["ISO2"] = "text";
        Assert.Equal("character varying(2)", contract.PhysicalTables("Country", true)[0].ColumnTypes["ISO2"]);
        Assert.Equal(contract.ComputeSha256(), Create(schema).ComputeSha256());
    }

    [Theory]
    [InlineData("partial")]
    [InlineData("type")]
    [InlineData("column")]
    [InlineData("null")]
    [InlineData("default")]
    [InlineData("collation")]
    [InlineData("index")]
    [InlineData("check")]
    [InlineData("generated")]
    [InlineData("primary")]
    [InlineData("ordinal")]
    [InlineData("named-type")]
    [InlineData("named-null")]
    public void Rejects_unknown_shapes_and_dependencies_even_with_recomputed_schema_hash(string fault)
    {
        FreshSchemaPlan schema = Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2);
        DatabaseSchemaPlan database = schema.Databases.Single(x => x.Database == "Country");
        TableCopyPlan table = database.Tables[0];
        var types = new Dictionary<string, string>(table.ColumnTypes);
        if (fault == "partial") { types["ISO2"] = "character varying(2)"; }
        if (fault == "type") { types["ISO3"] = "text"; }
        if (fault == "column") { types.Add("Unknown", "text"); }
        table = table with { ColumnTypes = types };
        if (fault == "null") { table = table with { NullableColumns = [.. table.NullableColumns.Where(x => x != "ISO2")] }; }
        if (fault == "default") { table = table with { DefaultExpressions = new Dictionary<string, string>(table.DefaultExpressions) { ["ISO2"] = "'XX'" } }; }
        if (fault == "collation") { table = table with { Collations = new Dictionary<string, string>(table.Collations) { ["ISO2"] = "C" } }; }
        if (fault == "index") { table = table with { Indexes = [new("unknown", ["ISO2"], false)] }; }
        if (fault == "check") { table = table with { CheckConstraints = [new("unknown", "length(\"ISO2\") > 0") { Columns = ["ISO2"] }] }; }
        if (fault == "generated") { table = table with { GeneratedColumns = [new("Name", "\"ISO2\"::text")] }; }
        if (fault == "primary") { table = table with { PrimaryKey = new("other", ["ID"]) }; }
        if (fault == "ordinal") { table = table with { OrderedColumns = ["ID", "Name", "Continent", "CountryCode", "ISO2", "ISO3", "CreatedDate", "ModifiedDate"] }; }
        if (fault == "named-type") { table = table with { ColumnTypes = new Dictionary<string, string>(table.ColumnTypes) { ["ID"] = "timestamp without time zone" } }; }
        if (fault == "named-null") { table = table with { NullableColumns = [.. table.NullableColumns.Where(x => x != "Continent"), "Name"] }; }
        database = database with { Tables = [table, .. database.Tables.Skip(1)] };
        database = database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
        schema = schema with { Databases = [.. schema.Databases.Select(x => x.Database == "Country" ? database : x)] };
        _ = Assert.Throws<MigrationExecutionException>(() => Create(schema));
    }

    [Theory]
    [InlineData("source")]
    [InlineData("stale")]
    [InlineData("dirty")]
    [InlineData("owner-head")]
    [InlineData("owner-pin")]
    [InlineData("owner-missing")]
    [InlineData("owner-stale")]
    [InlineData("mixed-profile")]
    [InlineData("selection")]
    public void Rejects_unpinned_stale_partial_or_implicit_selection(string fault)
    {
        FreshSchemaPlan schema = Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2);
        CurrentOwnerIsoSourceObservation[] owners = Owners();
        if (fault == "stale") { schema = schema with { CapturedAtUtc = Now.AddHours(-3) }; }
        if (fault == "dirty") { owners[0] = owners[0] with { Clean = false }; }
        if (fault == "owner-head") { owners[0] = owners[0] with { Head = new('f', 40) }; }
        if (fault == "owner-pin") { owners[0] = owners[0] with { Files = new Dictionary<string, string>() }; }
        if (fault == "owner-missing") { owners = [owners[0]]; }
        if (fault == "owner-stale") { owners[0] = owners[0] with { ObservedAtUtc = Now.AddHours(-3) }; }
        if (fault == "mixed-profile")
        {
            DatabaseSchemaPlan database = schema.Databases.Single(x => x.Database == "Upload") with { TargetExtensionProfile = null };
            database = database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
            schema = schema with { Databases = [.. schema.Databases.Select(x => x.Database == "Upload" ? database : x)] };
        }
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentOwnerIsoOverlay.Create(schema,
            fault == "source" ? new('f', 40) : schema.SourceCommitSha,
            fault == "selection" ? 0 : CurrentOwnerIsoSelection.LiteralWidthV1, owners, Now));
    }

    [Theory]
    [InlineData(ConsumerOverlaySelection.CurrentConsumerSchemaV2)]
    [InlineData(ConsumerOverlaySelection.CurrentConsumerSchemaV3)]
    public void Exact_database_specific_ordinals_preserve_named_types_and_source_alignment(ConsumerOverlaySelection selection)
    {
        FreshSchemaPlan schema = Schema(selection);
        var contract = Create(schema);
        TableCopyPlan country = schema.Databases.Single(x => x.Database == "Country").Tables[0];
        Assert.Equal(country.OrderedColumns, country.SourceColumns.Select(x => x.Column));
        foreach (string database in new[] { "Country", "Material" })
        {
            TableCopyPlan before = contract.PhysicalTables(database, false).Single(x => x.TargetTable == "Country");
            TableCopyPlan after = contract.PhysicalTables(database, true).Single(x => x.TargetTable == "Country");
            Assert.Equal(database == "Country" ? 4 : 1, before.OrderedColumns.ToList().IndexOf("ID") + 1);
            Assert.Equal(before.OrderedColumns, after.OrderedColumns);
            Assert.Equal("integer", after.ColumnTypes["ID"]);
            Assert.Equal("timestamp without time zone", after.ColumnTypes["CreatedDate"]);
            Assert.Equal(JsonSerializer.Serialize(before.SourceColumns), JsonSerializer.Serialize(after.SourceColumns));
            Assert.Equal(JsonSerializer.Serialize(before.SourceColumnTypes), JsonSerializer.Serialize(after.SourceColumnTypes));
        }
    }
    [Theory]
    [InlineData("Country")]
    [InlineData("Material")]
    public void Physical_order_cannot_be_rebound_to_a_different_database_or_arbitrary_permutation(string database)
    {
        var contract = Create(Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3));
        foreach (bool selected in new[] { false, true })
        {
            TableCopyPlan table = contract.PhysicalTables(database, selected).Single(x => x.TargetTable == "Country");
            TableCopyPlan changed = table with { OrderedColumns = [.. table.OrderedColumns.Reverse()] };
            _ = Assert.Throws<MigrationExecutionException>(() => contract.RequirePhysicalTable(database, changed, selected));
        }
    }
    internal static ApprovedCurrentOwnerIsoOverlay Create(FreshSchemaPlan schema)
    {
        return ApprovedCurrentOwnerIsoOverlay.Create(schema, schema.SourceCommitSha, CurrentOwnerIsoSelection.LiteralWidthV1, Owners(), Now);
    }

    internal static FreshSchemaPlan Schema(ConsumerOverlaySelection selection)
    {
        FreshSchemaPlan schema = CurrentConsumerSchemaV2Tests.Schema(selection);
        DatabaseSchemaPlan material = schema.Databases.Single(x => x.Database == "Material");
        string[] order = ["Continent", "CountryCode", "CreatedDate", "ID", "ISO2", "ISO3", "ModifiedDate", "Name"];
        var sqlTypes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Continent"] = "nvarchar(50)",
            ["CountryCode"] = "nvarchar(30)",
            ["CreatedDate"] = "datetime2",
            ["ID"] = "int",
            ["ISO2"] = "char(2)",
            ["ISO3"] = "char(3)",
            ["ModifiedDate"] = "datetime2",
            ["Name"] = "nvarchar(50)",
        };
        TableCopyPlan country = ApprovedTargetExtensionManifest.TablesFor(material).Single(x => x.TargetTable == "Country") with
        {
            SourceSchema = "dbo",
            OrderedColumns = order,
            SourceColumnTypes = sqlTypes,
            SourceColumns = [.. order.Select(column => new SourceColumnInventory(column, sqlTypes[column], new string('a', 64), null))],
        };
        DatabaseSchemaPlan database = schema.Databases.Single(x => x.Database == "Country");
        database = database with { Tables = [country, .. database.Tables.Skip(1)] };
        database = database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
        return schema with { Databases = [.. schema.Databases.Select(x => x.Database == "Country" ? database : x)] };
    }

    internal static CurrentOwnerIsoSourceObservation[] Owners()
    {
        return [
        new("Legacy.Maliev.CountryService", ApprovedCurrentOwnerIsoOverlay.CountryHead, true, Now, new Dictionary<string, string>
        {
            ["Legacy.Maliev.CountryService.Data/CountryDbContext.cs"] = "227179944b54b1c4c3f60858aea67736a41ffd02633730b84d24add7f724a90d",
            ["Legacy.Maliev.CountryService.Data/Migrations/CountryDbContextModelSnapshot.cs"] = "1ea420f1cee1122ad05fb984a7d3e6a44cb65e22ee3241fdba68e3ee46160736",
        }),
        new("Legacy.Maliev.CatalogService", ApprovedCurrentOwnerIsoOverlay.CatalogHead, true, Now, new Dictionary<string, string>
        {
            ["Legacy.Maliev.CatalogService.Data/CatalogDbContext.cs"] = "1b4bbf883fea2227143b974ae0af621ea40b28b6a7913850fad8c3914493ced3",
            ["Legacy.Maliev.CatalogService.Data/LookupDbContexts.cs"] = "e05ac3c1af79e0f06ec36f366ae1abaf6f91b3664ec3b8179630eec5d4ed54d9",
            ["Legacy.Maliev.CatalogService.Data/Migrations/20261006202000_PreserveLiteralCountryIsoCodes.cs"] = "76322593e2bf0da6d9fc25ee0057bb8bd16567bbca6017ab13ed29eb0ddccab8",
            ["Legacy.Maliev.CatalogService.Data/Migrations/CatalogDbContextModelSnapshot.cs"] = "828bc5cd5ad7a5d8e44ee1915f864ecb938c638f426bf7c8abd7234f6778e8df",
        }),
    ];
    }
}
