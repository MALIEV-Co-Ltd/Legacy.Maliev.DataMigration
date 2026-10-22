using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentOwnerIsoDefinitionPrecursorTests
{
    [Fact]
    public void Required_definition_cases_distinguish_sixteen_native_from_one_pure_case()
    {
        Assert.Equal(17, IsoDefinitionCases.Required.Length);
        Assert.Equal(17, IsoDefinitionCases.Required.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal("Physical_storage_does_not_accept_invented_file_sizes_counts_or_visibility", IsoDefinitionCases.Method("pure-storage"));
        Assert.Equal(16, IsoDefinitionCases.Required.Count(x => x != "pure-storage"));
    }
    [Theory]
    [InlineData("CREATE INDEX unknown_iso ON public.\"Country\"(\"ISO2\"); DELETE FROM public.\"Country\";")]
    [InlineData("CREATE INDEX unknown_iso ON public.\"Country\"(\"ISO3\");")]
    [InlineData("ALTER TABLE public.\"Country\" ALTER COLUMN \"ISO2\" TYPE varchar(3);")]
    public void Fault_identity_rejects_appended_effect_or_changed_operand(string sql)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => IsoDefinitionCases.Fault(sql, false));
        _ = Assert.Throws<MigrationExecutionException>(() => IsoDefinitionCases.Fault(sql, true));
    }
    [Theory]
    [InlineData("CREATE INDEX unknown_iso ON public.\"Country\"(\"ISO2\");", "unsupported-index")]
    [InlineData("ANALYZE public.\"Country\";", "unsupported-analyze")]
    [InlineData("ALTER TABLE public.\"Country\" ALTER COLUMN \"ISO2\" TYPE varchar(2);", "unsupported-partial")]
    public void Exact_source_faults_have_distinct_definition_case_identity(string sql, string expected)
    {
        Assert.Equal(expected, IsoDefinitionCases.Fault(sql, false));
    }

    [Fact]
    public void Committed_readback_allows_only_observed_horizon_and_rejects_changed_raw_fact_or_storage()
    {
        var snapshot = new CurrentAppOwnedDatabaseSnapshot("Country", [], [], []);
        var literal = new CurrentOwnerIsoLiteralRows(0, new string('a', 64), true);
        var catalog = new Dictionary<string, string[]> { ["pg_class"] = [/*lang=json,strict*/ "{\"oid\":42,\"relfilenode\":77}"] };
        var storage = new Dictionary<string, CurrentOwnerIsoStorage> { ["42"] = new(77, 1, 0) };
        var committed = new CurrentOwnerIsoNativeObservation(snapshot, new string('b', 64), true, literal, catalog, storage, 100);
        var fresh = new CurrentOwnerIsoNativeObservation(snapshot, new string('b', 64), true, literal, catalog, storage, 101);
        IsoDefinitionPrecursor.RequireCommittedReadback(committed, fresh);
        var changedCatalog = new Dictionary<string, string[]> { ["pg_class"] = [/*lang=json,strict*/ "{\"oid\":42,\"relfilenode\":78}"] };
        var changed = new CurrentOwnerIsoNativeObservation(snapshot, new string('b', 64), true, literal, changedCatalog, storage, 101);
        _ = Assert.Throws<MigrationExecutionException>(() => IsoDefinitionPrecursor.RequireCommittedReadback(committed, changed));
        var changedStorage = new Dictionary<string, CurrentOwnerIsoStorage> { ["42"] = new(78, 1, 0) };
        var wrongStorage = new CurrentOwnerIsoNativeObservation(snapshot, new string('b', 64), true, literal, catalog, changedStorage, 101);
        _ = Assert.Throws<MigrationExecutionException>(() => IsoDefinitionPrecursor.RequireCommittedReadback(committed, wrongStorage));
    }
}
