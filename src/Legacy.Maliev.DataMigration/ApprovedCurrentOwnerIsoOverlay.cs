using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal enum CurrentOwnerIsoSelection { LiteralWidthV1 = 1 }

internal sealed record CurrentOwnerIsoOperand(string Database, string Schema, string Table, string Column,
    string BeforeType, string AfterType, int CharacterWidth);

internal sealed record CurrentOwnerIsoSourceObservation(string Repository, string Head, bool Clean,
    DateTimeOffset ObservedAtUtc, IReadOnlyDictionary<string, string> Files);

/// <summary>Pure preparation only: four physical type overlays; no source profile, permission or DDL provider.</summary>
internal sealed class ApprovedCurrentOwnerIsoOverlay
{
    private static readonly string[] DefaultColumnNames = ["CreatedDate", "ModifiedDate"];
    private static readonly string[] CollatedColumnNames = ["Name", "Continent", "CountryCode", "ISO2", "ISO3"];
    internal const string CountryHead = "0e4565e9affc4e16587996d4cb95c327c3f94b18";
    internal const string CatalogHead = "7da867238630564d1f275b7f1beef822804414f5";
    private readonly FreshSchemaPlan _source;
    private readonly string _digest;
    private static readonly CurrentOwnerIsoOperand[] FixedOperands =
    [
        new("Country", "public", "Country", "ISO2", "character(2)", "character varying(2)", 2),
        new("Country", "public", "Country", "ISO3", "character(3)", "character varying(3)", 3),
        new("Material", "public", "Country", "ISO2", "character(2)", "character varying(2)", 2),
        new("Material", "public", "Country", "ISO3", "character(3)", "character varying(3)", 3),
    ];

    private static readonly Dictionary<string, string> CountryPins = new(StringComparer.Ordinal)
    {
        ["Legacy.Maliev.CountryService.Data/CountryDbContext.cs"] = "227179944b54b1c4c3f60858aea67736a41ffd02633730b84d24add7f724a90d",
        ["Legacy.Maliev.CountryService.Data/Migrations/CountryDbContextModelSnapshot.cs"] = "1ea420f1cee1122ad05fb984a7d3e6a44cb65e22ee3241fdba68e3ee46160736",
    };
    private static readonly Dictionary<string, string> CatalogPins = new(StringComparer.Ordinal)
    {
        ["Legacy.Maliev.CatalogService.Data/CatalogDbContext.cs"] = "1b4bbf883fea2227143b974ae0af621ea40b28b6a7913850fad8c3914493ced3",
        ["Legacy.Maliev.CatalogService.Data/LookupDbContexts.cs"] = "e05ac3c1af79e0f06ec36f366ae1abaf6f91b3664ec3b8179630eec5d4ed54d9",
        ["Legacy.Maliev.CatalogService.Data/Migrations/20261006202000_PreserveLiteralCountryIsoCodes.cs"] = "76322593e2bf0da6d9fc25ee0057bb8bd16567bbca6017ab13ed29eb0ddccab8",
        ["Legacy.Maliev.CatalogService.Data/Migrations/CatalogDbContextModelSnapshot.cs"] = "828bc5cd5ad7a5d8e44ee1915f864ecb938c638f426bf7c8abd7234f6778e8df",
    };

    private ApprovedCurrentOwnerIsoOverlay(FreshSchemaPlan source)
    {
        _source = source;
        string canonical = JsonSerializer.Serialize(new
        {
            Domain = "Legacy.Maliev.CurrentOwnerIso.LiteralWidth.v1",
            SourcePlan = SchemaPlanCanonicalizer.ComputeSha256(source),
            CountryHead,
            CatalogHead,
            CountryPins,
            CatalogPins,
            Operands = FixedOperands,
            Physical = source.Databases.Select(database => new
            {
                database.Database,
                Before = ApprovedConsumerColumnOverlayManifest.ComposePhysical(database),
                After = Overlay(database),
            }),
        });
        _digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    internal static ApprovedCurrentOwnerIsoOverlay Create(FreshSchemaPlan source, string expectedSourceCommit,
        CurrentOwnerIsoSelection selection, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(owners);
        if (selection != CurrentOwnerIsoSelection.LiteralWidthV1 || expectedSourceCommit.Length != 40 ||
            !expectedSourceCommit.All(char.IsAsciiHexDigit) || source.SourceCommitSha != expectedSourceCommit)
        { throw Invalid(); }
        source = Clone(source);
        ProductionSchemaCatalogInspector.ValidatePlan(source, nowUtc);
        if (!ApprovedConsumerOverlaySelection.IsApproved(source) || source.Databases.Sum(x => x.Tables.Count) != 100 ||
            source.Databases.Any(x => x.SourceSchemaSha256.Length != 64 || !x.SourceSchemaSha256.All(char.IsAsciiHexDigit)) ||
            owners.Count != 2)
        { throw Invalid(); }
        RequireOwner(owners, "Legacy.Maliev.CountryService", CountryHead, CountryPins, nowUtc);
        RequireOwner(owners, "Legacy.Maliev.CatalogService", CatalogHead, CatalogPins, nowUtc);
        foreach (string database in new[] { "Country", "Material" })
        {
            TableCopyPlan[] tables = [.. ApprovedConsumerColumnOverlayManifest.ComposePhysical(
                source.Databases.Single(x => x.Database == database)).Where(x => x.TargetSchema == "public" && x.TargetTable == "Country")];
            if (tables.Length != 1) { throw Invalid(); }
            RequireBefore(database, tables[0]);
        }
        return new(source);
    }

    internal string ComputeSha256()
    {
        return _digest;
    }

    internal static CurrentOwnerIsoOperand[] Operands()
    {
        return FixedOperands.ToArray();
    }

    // Physical consumption is explicitly separate from the immutable signed source plan.
    // No FreshSchemaPlan with an invented historical target hash is returned.
    internal TableCopyPlan[] PhysicalTables(string database, bool selected)
    {
        DatabaseSchemaPlan plan = _source.Databases.SingleOrDefault(x => x.Database == database) ?? throw Invalid();
        return Clone(selected ? Overlay(plan) : ApprovedConsumerColumnOverlayManifest.ComposePhysical(plan).ToArray());
    }

    internal void RequirePhysicalTable(string database, TableCopyPlan observed, bool selected)
    {
        TableCopyPlan[] expected = [.. PhysicalTables(database, selected).Where(x =>
            x.TargetSchema == observed.TargetSchema && x.TargetTable == observed.TargetTable)];
        if (expected.Length != 1 || JsonSerializer.Serialize(expected[0]) != JsonSerializer.Serialize(observed))
        { throw Invalid(); }
    }

    private static TableCopyPlan[] Overlay(DatabaseSchemaPlan database)
    {
        return [.. ApprovedConsumerColumnOverlayManifest.ComposePhysical(database).Select(table =>
        {
            CurrentOwnerIsoOperand[] operands = [.. FixedOperands.Where(x => x.Database == database.Database &&
                x.Schema == table.TargetSchema && x.Table == table.TargetTable)];
            if (operands.Length == 0) { return table; }
            var types = new Dictionary<string, string>(table.ColumnTypes, StringComparer.Ordinal);
            foreach (CurrentOwnerIsoOperand operand in operands) { types[operand.Column] = operand.AfterType; }
            return table with { ColumnTypes = types };
        })];
    }

    private static void RequireBefore(string database, TableCopyPlan table)
    {
        string[] columns = database == "Country"
            ? ["Continent", "CountryCode", "CreatedDate", "ID", "ISO2", "ISO3", "ModifiedDate", "Name"]
            : ["ID", "Name", "Continent", "CountryCode", "ISO2", "ISO3", "CreatedDate", "ModifiedDate"];
        string[] typedColumns = ["ID", "Name", "Continent", "CountryCode", "ISO2", "ISO3", "CreatedDate", "ModifiedDate"];
        string[] types = ["integer", "character varying(50)", "character varying(50)", "character varying(30)",
            "character(2)", "character(3)", "timestamp without time zone", "timestamp without time zone"];
        if (table.SourceSchema != (database == "Country" ? "dbo" : "target-only") || table.SourceTable != "Country" ||
            !table.OrderedColumns.SequenceEqual(columns, StringComparer.Ordinal) || table.ColumnTypes.Count != columns.Length ||
            typedColumns.Zip(types).Any(x => table.ColumnTypes.GetValueOrDefault(x.First) != x.Second) ||
            !table.OrderByColumns.SequenceEqual(["ID"], StringComparer.Ordinal) || table.PrimaryKey is not { } primary || primary.Name != "PK_Country" ||
            !primary.Columns.SequenceEqual(["ID"], StringComparer.Ordinal) ||
            !table.NullableColumns.ToHashSet(StringComparer.Ordinal).SetEquals(["Continent", "CountryCode", "ISO2", "ISO3", "CreatedDate", "ModifiedDate"]) ||
            table.NullableColumns.Count != 6 || table.Identities.Count != 1 || table.Identities[0].Column != "ID" ||
            table.DefaultExpressions.Count != 2 || DefaultColumnNames.Any(column =>
                PostgreSqlDefaultExpressionCanonicalizer.Canonicalize(table.DefaultExpressions.GetValueOrDefault(column, "")) != "utc-current-timestamp") ||
            table.Collations.Count != 5 || CollatedColumnNames.Any(column =>
                table.Collations.GetValueOrDefault(column) != ApprovedProductionCollationManifest.Collation) ||
            table.UniqueConstraints.Count != 0 || table.Indexes.Count != 0 || table.ForeignKeys.Count != 0 ||
            table.CheckConstraints.Count != 0 || table.GeneratedColumns.Count != 0)
        { throw Invalid(); }
    }

    private static void RequireOwner(IReadOnlyList<CurrentOwnerIsoSourceObservation> owners, string repository,
        string head, Dictionary<string, string> pins, DateTimeOffset nowUtc)
    {
        CurrentOwnerIsoSourceObservation[] matches = [.. owners.Where(x => x.Repository == repository)];
        if (matches.Length != 1) { throw Invalid(); }
        CurrentOwnerIsoSourceObservation owner = matches[0];
        if (!owner.Clean || owner.Head != head || owner.ObservedAtUtc.Offset != TimeSpan.Zero ||
            owner.ObservedAtUtc > nowUtc || nowUtc - owner.ObservedAtUtc > TimeSpan.FromHours(2) ||
            owner.Files.Count != pins.Count || pins.Any(x => owner.Files.GetValueOrDefault(x.Key) != x.Value))
        { throw Invalid(); }
    }

    private static T Clone<T>(T value)
    {
        return JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(value)) ?? throw Invalid();
    }

    private static MigrationExecutionException Invalid()
    {
        return new("current_owner_iso_preparation_invalid",
            "The fixed current owner ISO preparation contract is invalid; no execution authority is granted.");
    }
}
