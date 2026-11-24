using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthSnapshotCohortBudgetTests
{
    private static readonly string[] Pair = ["Auth", "postgres"];
    private static readonly string[] One = ["Auth"];
    private static readonly string[] Excess = ["Auth", "postgres", "foreign"];
    private static readonly string[] Duplicates = ["Auth", "Auth"];
    private static CurrentAppOwnedCatalogFact Fact(string key = "1")
    {
        return new("pg_type", key, new string('a', 64), "1247", "1");
    }

    private static CurrentAppOwnedDatabaseSnapshot Snapshot(string database, params CurrentAppOwnedCatalogFact[] facts)
    {
        return new(database, facts, [], []);
    }

    [Fact]
    public void Repeated_complete_cohorts_keep_all_occurrences_and_share_records_without_spending_the_next_cohorts_budget()
    {
        var pool = new CurrentAppOwnedSnapshotInternPool(new(MaximumDatabases: 2, MaximumFacts: 4));
        CurrentAppOwnedCatalogFact? retained = null;
        for (int capture = 0; capture < 100; capture++)
        {
            var cohort = pool.BeginCohort(Pair);
            foreach (string database in cohort.Databases)
            {
                var original = Snapshot(database, Fact(), Fact()); var actual = cohort.Intern(original);
                Assert.Equal(JsonSerializer.SerializeToUtf8Bytes(original), JsonSerializer.SerializeToUtf8Bytes(actual));
                Assert.Equal(original.Sha256, actual.Sha256); Assert.Equal(2, actual.Catalog.Count);
                Assert.Same(actual.Catalog[0], actual.Catalog[1]);
                if (retained is not null) { Assert.Same(retained, actual.Catalog[0]); }
                retained = actual.Catalog[0];
            }
            cohort.Complete(); Assert.Equal(4, cohort.TotalFactCount);
        }
        Assert.Equal(1, pool.UniqueRecordCount);
    }

    [Fact]
    public void All_three_fact_types_keep_exact_field_bytes_and_shared_identity_across_complete_cohorts()
    {
        var pool = new CurrentAppOwnedSnapshotInternPool(new(MaximumFacts: 4));
        var snapshot = new CurrentAppOwnedDatabaseSnapshot("Auth", [Fact(), Fact()],
            [new("private", "synthetic ไทย <>&", 2, new string('b', 64))], [new("private", "sequence", "owner", new string('c', 64))]);
        var first = pool.BeginCohort(One); var original = first.Intern(snapshot); first.Complete();
        var second = pool.BeginCohort(One); var repeated = second.Intern(snapshot); second.Complete();
        Assert.Equal(JsonSerializer.SerializeToUtf8Bytes(snapshot), JsonSerializer.SerializeToUtf8Bytes(repeated));
        Assert.Same(original.Catalog[0], repeated.Catalog[1]);
        Assert.Same(original.Relations[0], repeated.Relations[0]); Assert.Same(original.Sequences[0], repeated.Sequences[0]);
        Assert.Equal(3, pool.UniqueRecordCount); Assert.Equal(4, second.TotalFactCount);
    }

    [Fact]
    public void Each_cohort_still_has_the_unchanged_database_and_fact_limits_and_exact_inventory()
    {
        var pool = new CurrentAppOwnedSnapshotInternPool(new(MaximumDatabases: 2, MaximumFacts: 2));
        _ = Assert.Throws<JsonException>(() => pool.BeginCohort(Excess));
        _ = Assert.Throws<JsonException>(() => pool.BeginCohort(Duplicates));
        var tooManyFacts = pool.BeginCohort(One);
        _ = Assert.Throws<JsonException>(() => tooManyFacts.Intern(Snapshot("Auth", Fact(), Fact(), Fact())));
        _ = Assert.Throws<JsonException>(tooManyFacts.Complete);
        var order = pool.BeginCohort(Pair);
        _ = Assert.Throws<JsonException>(() => order.Intern(Snapshot("postgres", Fact())));
        _ = Assert.Throws<JsonException>(() => order.Intern(Snapshot("Auth", Fact())));
        var incomplete = pool.BeginCohort(Pair); _ = incomplete.Intern(Snapshot("Auth", Fact()));
        _ = Assert.Throws<JsonException>(incomplete.Complete);
        var complete = pool.BeginCohort(One); _ = complete.Intern(Snapshot("Auth", Fact())); complete.Complete();
        _ = Assert.Throws<JsonException>(complete.Complete);
        _ = Assert.Throws<JsonException>(() => complete.Intern(Snapshot("Auth", Fact())));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void New_cohorts_do_not_reset_retained_unique_record_or_string_budgets(bool strings)
    {
        var limits = strings ? new CurrentAppOwnedSnapshotLimits(MaximumUniqueStringCharacters: 80) : new(MaximumUniqueRecords: 1);
        var pool = new CurrentAppOwnedSnapshotInternPool(limits);
        var first = pool.BeginCohort(One); var original = first.Intern(Snapshot("Auth", Fact())); first.Complete();
        long retainedCharacters = pool.UniqueStringCharacterCount;
        var repeated = pool.BeginCohort(One); var shared = repeated.Intern(Snapshot("Auth", Fact())); repeated.Complete();
        Assert.Same(original.Catalog[0], shared.Catalog[0]); Assert.Equal(retainedCharacters, pool.UniqueStringCharacterCount);
        var changed = pool.BeginCohort(One);
        _ = Assert.Throws<JsonException>(() => changed.Intern(Snapshot("Auth", Fact("2"))));
        _ = Assert.Throws<JsonException>(changed.Complete);
        Assert.Equal(1, pool.UniqueRecordCount); Assert.Equal(retainedCharacters, pool.UniqueStringCharacterCount);
    }

    [Fact]
    public void Fact_limit_counts_enumerated_occurrences_even_if_a_list_reports_a_false_count()
    {
        var pool = new CurrentAppOwnedSnapshotInternPool(new(MaximumFacts: 2));
        var cohort = pool.BeginCohort(One);
        var invalid = new CurrentAppOwnedDatabaseSnapshot("Auth", new MiscountedFacts(), [], []);
        _ = Assert.Throws<JsonException>(() => cohort.Intern(invalid));
        Assert.Equal(2, cohort.TotalFactCount); _ = Assert.Throws<JsonException>(cohort.Complete);
    }
    private sealed class MiscountedFacts : IReadOnlyList<CurrentAppOwnedCatalogFact>
    {
        public int Count => 1;
        public CurrentAppOwnedCatalogFact this[int index] => Fact();
        public IEnumerator<CurrentAppOwnedCatalogFact> GetEnumerator() { yield return Fact(); yield return Fact(); yield return Fact(); }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }

    [Fact]
    public void Per_string_UTF8_limit_and_default_single_baseline_counters_are_unchanged()
    {
        var pool = new CurrentAppOwnedSnapshotInternPool(new(MaximumFacts: 2, MaximumStringUtf8Bytes: 64));
        _ = pool.Intern(Fact()); _ = pool.Intern(Fact());
        var cohort = pool.BeginCohort(One); _ = cohort.Intern(Snapshot("Auth", Fact(), Fact())); cohort.Complete();
        Assert.Equal(2, pool.TotalFactCount);
        _ = Assert.Throws<JsonException>(() => pool.Intern(Fact()));
        var utf8 = pool.BeginCohort(One);
        _ = Assert.Throws<JsonException>(() => utf8.Intern(Snapshot("Auth", Fact() with { Key = new string('ท', 32) })));
        _ = Assert.Throws<JsonException>(utf8.Complete);
    }
}
