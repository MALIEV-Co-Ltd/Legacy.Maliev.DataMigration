namespace Legacy.Maliev.DataMigration.Tests;

public sealed class WorkflowContractTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [Fact]
    public void RequiredValidationWorkflows_ArePresentAndContainNoDeliveryPath()
    {
        string[] required =
        [
            "_build-and-test.yml",
            "ci-develop.yml",
            "ci-staging.yml",
            "ci-main.yml",
            "pr-validation.yml",
        ];

        foreach (string workflow in required)
        {
            string path = Path.Combine(RepositoryRoot, ".github", "workflows", workflow);
            Assert.True(File.Exists(path), $"Missing required workflow: {workflow}");
            string source = File.ReadAllText(path);
            Assert.Contains("permissions:\n  contents: read", Normalize(source), StringComparison.Ordinal);
            Assert.DoesNotContain("packages: write", source, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("id-token: write", source, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("docker/", source, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("kubectl", source, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("gcloud", source, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("gitops", source, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ReusableValidationWorkflow_IsPinnedFailClosedAndRunsRealDatabaseFixtures()
    {
        string source = ReadWorkflow("_build-and-test.yml");

        Assert.Contains("LEGACY_DEPLOY_ENABLED: 'false'", source, StringComparison.Ordinal);
        Assert.Contains("MALIEV_RUN_SQLSERVER_INTEGRATION: '1'", source, StringComparison.Ordinal);
        Assert.Contains(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            source,
            StringComparison.Ordinal);
        Assert.Contains("persist-credentials: false", source, StringComparison.Ordinal);
        Assert.Contains(
            "MALIEV-Co-Ltd/Legacy.Maliev.Workflows/actions/dotnet-validate@6017816fa67f369d785ed30794f002cfd6299af7",
            source,
            StringComparison.Ordinal);
        Assert.Contains("solution: Legacy.Maliev.DataMigration.slnx", source, StringComparison.Ordinal);
        Assert.DoesNotContain("secrets: inherit", source, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("ci-develop.yml", "branches: [develop]")]
    [InlineData("ci-staging.yml", "tags: [release/v*]")]
    [InlineData("ci-main.yml", "branches: [main]")]
    [InlineData("pr-validation.yml", "branches: [main]")]
    public void EntryWorkflow_HasExactTriggerConcurrencyAndOnlyCallsValidation(string file, string trigger)
    {
        string source = ReadWorkflow(file);

        Assert.Contains(trigger, source, StringComparison.Ordinal);
        Assert.Contains("cancel-in-progress: true", source, StringComparison.Ordinal);
        Assert.Contains("uses: ./.github/workflows/_build-and-test.yml", source, StringComparison.Ordinal);
        Assert.DoesNotContain("run:", source, StringComparison.Ordinal);
        Assert.DoesNotContain("LEGACY_DEPLOY_ENABLED == 'true'", source, StringComparison.Ordinal);
    }

    [Fact]
    public void Dependabot_UpdatesNuGetAndPinnedActionsWithoutOpeningUnboundedPullRequests()
    {
        string source = File.ReadAllText(Path.Combine(RepositoryRoot, ".github", "dependabot.yml"));

        Assert.Contains("package-ecosystem: nuget", source, StringComparison.Ordinal);
        Assert.Contains("package-ecosystem: github-actions", source, StringComparison.Ordinal);
        Assert.Contains("open-pull-requests-limit: 10", source, StringComparison.Ordinal);
        Assert.Contains("open-pull-requests-limit: 5", source, StringComparison.Ordinal);
    }

    private static string ReadWorkflow(string file)
    {
        return File.ReadAllText(Path.Combine(RepositoryRoot, ".github", "workflows", file));
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Legacy.Maliev.DataMigration.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate the DataMigration repository root.");
    }

    private static string Normalize(string value)
    {
        return value.Replace("\r\n", "\n", StringComparison.Ordinal);
    }
}
