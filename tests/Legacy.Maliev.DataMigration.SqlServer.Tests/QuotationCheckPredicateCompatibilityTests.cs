namespace Legacy.Maliev.DataMigration.Tests;

public sealed class QuotationCheckPredicateCompatibilityTests
{
    [Fact]
    public void CheckColumnInventory_ContainsOnlyReferencedIdentifiersInTableOrder()
    {
        Assert.Equal(["NewState", "Reason"], SqlServerMigrationSource.ReferencedCheckColumns(
            ["ID", "NewState", "ChangedUtc", "Reason"],
            "(\"NewState\"='qualified' OR nullif(ltrim(rtrim(\"Reason\")),'') IS NOT NULL)"));
        Assert.Equal(["Quoted\"Name"], SqlServerMigrationSource.ReferencedCheckColumns(
            ["Other", "Quoted\"Name"], "(\"Quoted\"\"Name\" IS NOT NULL)"));
    }

    [Theory]
    [InlineData("Request", "CK_Request_QualificationState",
        "(\"QualificationState\"='incomplete' OR \"QualificationState\"='stale' OR \"QualificationState\"='duplicate' OR \"QualificationState\"='not_qualified' OR \"QualificationState\"='qualified' OR \"QualificationState\"='unreviewed')",
        "(((\"QualificationState\")::text = 'incomplete'::text) OR ((\"QualificationState\")::text = 'stale'::text) OR ((\"QualificationState\")::text = 'duplicate'::text) OR ((\"QualificationState\")::text = 'not_qualified'::text) OR ((\"QualificationState\")::text = 'qualified'::text) OR ((\"QualificationState\")::text = 'unreviewed'::text))")]
    [InlineData("RequestQualificationAudit", "CK_RequestQualificationAudit_DuplicateCount",
        "(\"DuplicateCount\">=(0))", "(\"DuplicateCount\" >= 0)")]
    [InlineData("RequestQualificationAudit", "CK_RequestQualificationAudit_NewState",
        "(\"NewState\"='incomplete' OR \"NewState\"='stale' OR \"NewState\"='duplicate' OR \"NewState\"='not_qualified' OR \"NewState\"='qualified' OR \"NewState\"='unreviewed')",
        "(((\"NewState\")::text = 'incomplete'::text) OR ((\"NewState\")::text = 'stale'::text) OR ((\"NewState\")::text = 'duplicate'::text) OR ((\"NewState\")::text = 'not_qualified'::text) OR ((\"NewState\")::text = 'qualified'::text) OR ((\"NewState\")::text = 'unreviewed'::text))")]
    [InlineData("RequestQualificationAudit", "CK_RequestQualificationAudit_Reason",
        "(\"NewState\"='qualified' OR nullif(ltrim(rtrim(\"Reason\")),'') IS NOT NULL)",
        "(((\"NewState\")::text = 'qualified'::text) OR (NULLIF(ltrim(rtrim((\"Reason\")::text)), ''::text) IS NOT NULL))")]
    public void ReviewedSqlServerAndPostgreSqlCheckForms_MatchWithoutAcceptingLoosenedRule(
        string table, string name, string source, string catalog)
    {
        string Expected(string expression)
        {
            return PostgreSqlSchemaFingerprint.Compute(
                [new("public", table)], [],
                [new("public", table, name, 'c', [], expression)], [], []);
        }

        Assert.Equal(Expected(source), Expected(catalog));
        Assert.NotEqual(Expected(source), Expected("TRUE"));
        Assert.NotEqual(Expected(source), Expected($"({source} AND FALSE)"));
    }
}
