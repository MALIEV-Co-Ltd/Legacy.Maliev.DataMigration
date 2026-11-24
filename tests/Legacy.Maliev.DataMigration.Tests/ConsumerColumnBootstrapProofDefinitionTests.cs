namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ConsumerColumnBootstrapProofDefinitionTests
{
    [Fact]
    public void Target_only_identity_definitions_are_bound_without_inventing_SQL_source_metadata()
    {
        var source = ConsumerColumnBootstrapTestData.Logical();
        var contract = ConsumerColumnBootstrapContract.Create(source, source.SourceCommitSha, ConsumerColumnBootstrapTestData.Now.AddMinutes(2));
        var table = ConsumerColumnBootstrapOperationalContract.Databases.SelectMany(database => contract.Before(database).Tables)
            .First(candidate => candidate.Identities.Any(identity => !candidate.SourceColumnTypes.ContainsKey(identity.Column)));
        var identity = table.Identities.First(value => !table.SourceColumnTypes.ContainsKey(value.Column));
        static string Project(TableCopyPlan value)
        {
            return System.Text.Json.JsonSerializer.Serialize(ConsumerColumnBootstrapProofDefinition.ProjectPhysicalTable(value));
        }

        string baseline = Project(table);
        Assert.NotEqual(baseline, Project(table with { Identities = table.Identities.Select(value => value != identity ? value : value with { SeedValue = value.SeedValue + 1 }).ToArray() }));
        Assert.NotEqual(baseline, Project(table with { Identities = table.Identities.Select(value => value != identity ? value : value with { IncrementValue = value.IncrementValue + 1 }).ToArray() }));
        Assert.Equal(baseline, Project(table with { Identities = table.Identities.Select(value => value != identity ? value : value with { CurrentValue = value.CurrentValue + 1, IsCalled = !value.IsCalled }).ToArray() }));
    }

    [Fact]
    public void Definition_keeps_full_capture_hash_separate_and_does_not_mutate_source()
    {
        var source = ConsumerColumnBootstrapTestData.Logical();
        string original = SchemaPlanCanonicalizer.ComputeSha256(source);
        var later = source with { CapturedAtUtc = source.CapturedAtUtc.AddMinutes(1) };
        Assert.NotEqual(original, SchemaPlanCanonicalizer.ComputeSha256(later));
        Assert.Equal(Definition(source), Definition(later));
        Assert.Equal(original, SchemaPlanCanonicalizer.ComputeSha256(source));
    }

    [Fact]
    public void Provider184_and187_are_distinct_definition_cohorts()
    {
        var source = ConsumerColumnBootstrapTestData.Logical();
        Assert.NotEqual(Definition(source), ConsumerColumnBootstrapProofDefinition.Compute(source, new string('a', 64), new string('b', 64),
            ConsumerColumnBootstrapProofCohort.PostgreSql187, ConsumerColumnBootstrapTestData.Now.AddMinutes(2)));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapProofDefinition.Compute(source, new string('a', 64), new string('b', 64),
            new(180004, ConsumerColumnBootstrapProofCohort.PostgreSql187.ImageReference), ConsumerColumnBootstrapTestData.Now.AddMinutes(2)));
    }

    [Fact]
    public void Source_identity_and_runner_are_bound()
    {
        var source = ConsumerColumnBootstrapTestData.Logical();
        string expected = Definition(source);
        Assert.NotEqual(expected, ConsumerColumnBootstrapProofDefinition.Compute(source, new string('c', 64), new string('b', 64),
            ConsumerColumnBootstrapProofCohort.PostgreSql184, ConsumerColumnBootstrapTestData.Now.AddMinutes(2)));
        Assert.NotEqual(expected, ConsumerColumnBootstrapProofDefinition.Compute(source, new string('a', 64), new string('c', 64),
            ConsumerColumnBootstrapProofCohort.PostgreSql184, ConsumerColumnBootstrapTestData.Now.AddMinutes(2)));
    }

    [Fact]
    public void Mutable_identity_tuple_is_retained_by_full_plan_but_not_definition()
    {
        var source = ConsumerColumnBootstrapTestData.Logical();
        DatabaseSchemaPlan database = source.Databases.First(item => item.Tables.Any(table => table.Identities.Count != 0));
        TableCopyPlan table = database.Tables.First(item => item.Identities.Count != 0);
        IdentityCopyPlan identity = table.Identities[0];
        var altered = source with
        {
            Databases = source.Databases.Select(item => item.Database != database.Database ? item : item with
            {
                Tables = item.Tables.Select(candidate => candidate != table ? candidate : candidate with
                {
                    Identities = candidate.Identities.Select(value => value != identity ? value : value with
                    { CurrentValue = value.CurrentValue + 1, IsCalled = true }).ToArray(),
                }).ToArray(),
            }).ToArray(),
        };
        Assert.NotEqual(SchemaPlanCanonicalizer.ComputeSha256(source), SchemaPlanCanonicalizer.ComputeSha256(altered));
        Assert.Equal(Definition(source), Definition(altered));
    }

    [Fact]
    public void Eligibility_and_sizing_fields_are_retained_in_definition_projection()
    {
        var source = ConsumerColumnBootstrapTestData.Logical();
        TableCopyPlan table = source.Databases.SelectMany(database => database.Tables).First(candidate => candidate.SourceColumns.Count != 0);
        string before = System.Text.Json.JsonSerializer.Serialize(SourceCatalogDefinitionFingerprintV1.ProjectTable(table));
        string emptyChanged = System.Text.Json.JsonSerializer.Serialize(SourceCatalogDefinitionFingerprintV1.ProjectTable(table with { SourceKnownEmpty = !table.SourceKnownEmpty }));
        var first = table.SourceColumns[0];
        string sizingChanged = System.Text.Json.JsonSerializer.Serialize(SourceCatalogDefinitionFingerprintV1.ProjectTable(table with
        { SourceColumns = table.SourceColumns.Select(column => column != first ? column : column with { MaxObservedDataLength = (column.MaxObservedDataLength ?? 0) + 1 }).ToArray() }));
        Assert.NotEqual(before, emptyChanged); Assert.NotEqual(before, sizingChanged);
    }

    private static string Definition(FreshSchemaPlan source)
    {
        return ConsumerColumnBootstrapProofDefinition.Compute(source,
        new string('a', 64), new string('b', 64), ConsumerColumnBootstrapProofCohort.PostgreSql184, ConsumerColumnBootstrapTestData.Now.AddMinutes(2));
    }
}
