using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SourceCatalogDefinitionFingerprintV1Tests
{
    [Fact]
    public void Capture_clock_changes_preserve_definition_without_rewriting_full_plans()
    {
        var source = ConsumerColumnBootstrapTestData.Logical();
        string original = SchemaPlanCanonicalizer.ComputeSha256(source);
        var later = source with { CapturedAtUtc = source.CapturedAtUtc.AddMinutes(1) };
        Assert.NotEqual(original, SchemaPlanCanonicalizer.ComputeSha256(later));
        Assert.Equal(Definition(source), Definition(later));
        Assert.Equal(original, SchemaPlanCanonicalizer.ComputeSha256(source));
    }

    [Fact]
    public void Current_identity_state_stays_in_full_evidence_but_not_definition()
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
    public void Source_identity_and_accepted_commit_cannot_be_substituted()
    {
        var source = ConsumerColumnBootstrapTestData.Logical();
        Assert.NotEqual(Definition(source), SourceCatalogDefinitionFingerprintV1.Compute(source,
            source.SourceCommitSha, new string('c', 64), ConsumerColumnBootstrapTestData.Now.AddMinutes(2)));
        _ = Assert.Throws<MigrationExecutionException>(() => SourceCatalogDefinitionFingerprintV1.Compute(source,
            new string('d', 40), new string('a', 64), ConsumerColumnBootstrapTestData.Now.AddMinutes(2)));
    }

    [Fact]
    public void Incomplete_source_catalog_is_refused()
    {
        var source = ConsumerColumnBootstrapTestData.Logical();
        _ = Assert.Throws<MigrationExecutionException>(() => Definition(source with { Databases = source.Databases.Skip(1).ToArray() }));
    }

    [Fact]
    public void Eligibility_and_observed_sizing_remain_bound()
    {
        var source = ConsumerColumnBootstrapTestData.Logical();
        TableCopyPlan table = source.Databases.SelectMany(database => database.Tables).First(candidate => candidate.SourceColumns.Count != 0);
        string before = JsonSerializer.Serialize(SourceCatalogDefinitionFingerprintV1.ProjectTable(table));
        Assert.NotEqual(before, JsonSerializer.Serialize(SourceCatalogDefinitionFingerprintV1.ProjectTable(
            table with { SourceKnownEmpty = !table.SourceKnownEmpty })));
        var first = table.SourceColumns[0];
        Assert.NotEqual(before, JsonSerializer.Serialize(SourceCatalogDefinitionFingerprintV1.ProjectTable(table with
        {
            SourceColumns = table.SourceColumns.Select(column => column != first ? column : column with
            { MaxObservedDataLength = (column.MaxObservedDataLength ?? 0) + 1 }).ToArray(),
        })));
    }

    private static string Definition(FreshSchemaPlan source)
    {
        return SourceCatalogDefinitionFingerprintV1.Compute(source,
        source.SourceCommitSha, new string('a', 64), ConsumerColumnBootstrapTestData.Now.AddMinutes(2));
    }
}
