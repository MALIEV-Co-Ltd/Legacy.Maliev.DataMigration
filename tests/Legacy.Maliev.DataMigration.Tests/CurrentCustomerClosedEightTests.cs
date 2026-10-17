using System.Xml.Linq;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentCustomerClosedEightTests
{
    private static readonly XNamespace Ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
    [Theory]
    [InlineData("terminal-publication")]
    [InlineData("final-fleet")]
    public void Durable_terminal_fault_requires_all_three_actual_receipts(string caseId)
    {
        CurrentCustomerClosedEightReadback.RequireClassifications(caseId, [CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.CommittedAndReadback, CurrentAppOwnedCommitClassification.Uncertain]);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerClosedEightReadback.RequireClassifications(caseId, [CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.Uncertain]));
    }
    [Fact]
    public void Lost_physical_commit_ack_does_not_adopt_an_acknowledged_terminal()
    {
        CurrentCustomerClosedEightReadback.RequireClassifications("lost-commit-ack", [CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.Uncertain]);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerClosedEightReadback.RequireClassifications("lost-commit-ack", [CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.CommittedAndReadback]));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerClosedEightReadback.RequireClassifications("lost-commit-ack", [CurrentAppOwnedCommitClassification.Prepared, (CurrentAppOwnedCommitClassification)999]));
    }
    [Fact]
    public void Review_policy_refusal_has_no_fabricated_prepared_slot()
    {
        CurrentCustomerClosedEightReadback.RequireClassifications("host-unprobed-sdk", []);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerClosedEightReadback.RequireClassifications("host-unprobed-sdk", [CurrentAppOwnedCommitClassification.Prepared]));
    }
    [Fact]
    public void Exact_eight_actual_trx_bindings_are_required()
    { var (document, cases, image) = Trx(); CurrentCustomerClosedEightReadback.RequireTrx(document, cases, image); }
    [Theory]
    [InlineData("failed")]
    [InlineData("notExecuted")]
    [InlineData("passed")]
    public void Nonpassing_or_incomplete_actual_counters_reject(string field)
    {
        var (document, cases, image) = Trx(); document.Descendants(Ns + "Counters").Single().SetAttributeValue(field, "1");
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerClosedEightReadback.RequireTrx(document, cases, image));
    }
    [Theory]
    [InlineData("className")]
    [InlineData("name")]
    [InlineData("codeBase")]
    public void Changed_actual_executing_method_or_image_rejects(string field)
    {
        var (document, cases, image) = Trx(); document.Descendants(Ns + "TestMethod").First().SetAttributeValue(field, "unreviewed");
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerClosedEightReadback.RequireTrx(document, cases, image));
    }
    [Fact]
    public void Case_identity_cannot_adopt_another_execution_or_timestamp()
    {
        var (document, cases, image) = Trx();
        var changed = cases.ToArray(); changed[0] = changed[0] with { TestExitedAtUtc = changed[0].TestExitedAtUtc.AddSeconds(1) };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerClosedEightReadback.RequireTrx(document, changed, image));
    }
    [Theory]
    [InlineData("native")]
    [InlineData("provider")]
    [InlineData("maintenance")]
    public void Named_host_never_selects_component_filters(string group)
    { _ = Assert.Throws<MigrationExecutionException>(() => CustomerNamedClosedHostLauncher.Filter(group)); }
    [Fact]
    public void Named_host_has_fixed_filter_and_finite_lease()
    {
        Assert.Equal("FullyQualifiedName=Legacy.Maliev.DataMigration.Tests.CurrentCustomerClosedConsoleExecutionTests.Genuine_named_closed_customer_console", CustomerNamedClosedHostLauncher.Filter("closed-console"));
        Assert.Equal(TimeSpan.FromMinutes(80), CustomerNamedClosedHostLauncher.Lease("closed-console"));
    }
    // Pure XML fixtures are not signed/native evidence and cannot enter the
    // body reader or issuer. No directories, files, keys or resources are made.
    private static (XDocument, IReadOnlyList<CustomerClosedEightCase>, string) Trx()
    {
        string image = Path.Combine(Path.GetTempPath(), "Legacy.Maliev.DataMigration.Tests.dll");
        DateTimeOffset began = new(2026, 10, 13, 0, 0, 0, TimeSpan.Zero), ended = began.AddSeconds(1);
        var artifact = new CustomerDefinitionArtifact(image, new string('a', 64), image);
        var cases = CurrentCustomerSequenceClosedBootstrap.Cases.Select((id, i) => new CustomerClosedEightCase(id, Guid.NewGuid(),
            "Genuine_named_closed_customer_console(caseId: \"" + id + "\")", "test-" + i, "execution-" + i, Path.GetTempPath(), artifact, artifact, [], began, ended)).ToArray();
        var document = new XDocument(new XElement(Ns + "TestRun",
            new XElement(Ns + "ResultSummary", new XElement(Ns + "Counters", new XAttribute("total", 8), new XAttribute("executed", 8), new XAttribute("passed", 8), new XAttribute("failed", 0), new XAttribute("notExecuted", 0))),
            new XElement(Ns + "Results", cases.Select(x => new XElement(Ns + "UnitTestResult", new XAttribute("testId", x.TestId), new XAttribute("executionId", x.ExecutionId), new XAttribute("testName", x.TestName), new XAttribute("outcome", "Passed"), new XAttribute("startTime", began.ToString("O")), new XAttribute("endTime", ended.ToString("O"))))),
            new XElement(Ns + "TestDefinitions", cases.Select(x => new XElement(Ns + "UnitTest", new XAttribute("id", x.TestId), new XAttribute("storage", image),
                new XElement(Ns + "TestMethod", new XAttribute("className", "Legacy.Maliev.DataMigration.Tests.CurrentCustomerClosedConsoleExecutionTests"), new XAttribute("name", "Genuine_named_closed_customer_console"), new XAttribute("codeBase", image)))))));
        return (document, cases, image);
    }
}
