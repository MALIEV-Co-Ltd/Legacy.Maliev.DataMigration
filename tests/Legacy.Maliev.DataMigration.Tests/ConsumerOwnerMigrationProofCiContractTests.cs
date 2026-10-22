using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration.Tests;

/// <summary>Required CI cannot run the owning-EF proof without its immutable preparation.</summary>
public sealed class ConsumerOwnerMigrationProofCiContractTests
{
    private static readonly string[] ExpectedSteps =
    [
        "Check out DataMigration",
        "Validate production exec-tunnel admission",
        "Set up .NET for owner migration proof",
        "Prepare exact-pinned consumer owner migrations",
        "Validate .NET solution",
        "Prepare PostgreSQL 18 client wrappers",
        "Verify PostgreSQL 18 snapshot producer compatibility",
    ];
    private static readonly string[] MinimumPermissions = ["contents: read"];

    [Fact]
    public void RequiredValidation_PreparesOwnerProofAfterAdmissionWithoutAnOptionalOrPrivilegedPath()
    {
        ValidateWorkflow(ReadWorkflow());
        RequiredValidation_RejectsPreviousSetupDotnetPin();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RequiredValidation_AllowsIndependentJobsWithoutBorrowingTheirSteps(bool beforeValidation)
    {
        const string independent = "  independent-proof:\n    runs-on: ubuntu-24.04\n    steps:\n      - name: Validate .NET solution\n        run: echo fixture\n";
        string source = ReadWorkflow().ReplaceLineEndings("\n");
        ValidateWorkflow(beforeValidation
            ? source.Replace("  validate:\n", independent + "  validate:\n", StringComparison.Ordinal)
            : source + "\n# Another job remains in the jobs mapping.\n" + independent);
    }

    [Theory]
    [InlineData("if: always()")]
    [InlineData("continue-on-error: true")]
    [InlineData("permissions:\n      contents: write")]
    [InlineData("permissions:\n      id-token: write")]
    [InlineData("env:\n      TOKEN: ${{ secrets.FIXTURE }}")]
    public void RequiredValidation_RejectsWeakeningInIndependentJobs(string directive)
    {
        string source = ReadWorkflow().ReplaceLineEndings("\n")
            + "\n  independent-proof:\n    " + directive + "\n    runs-on: ubuntu-24.04\n    steps:\n      - name: Independent proof\n        run: echo fixture\n";
        _ = Assert.ThrowsAny<Xunit.Sdk.XunitException>(() => ValidateWorkflow(source));
    }

    [Theory]
    [InlineData("if: always()")]
    [InlineData("continue-on-error: true")]
    [InlineData("env:\n          SKIP_PROOF: '1'")]
    public void RequiredValidation_RejectsOptionalOwnerPreparation(string directive)
    {
        string source = ReadWorkflow().ReplaceLineEndings("\n");
        string changed = source.Replace("      - name: Prepare exact-pinned consumer owner migrations\n",
            "      - name: Prepare exact-pinned consumer owner migrations\n        " + directive + "\n", StringComparison.Ordinal);
        Assert.NotEqual(source, changed);
        _ = Assert.ThrowsAny<Xunit.Sdk.XunitException>(() => ValidateWorkflow(changed));
    }

    [Fact]
    public void RequiredValidation_RejectsMissingOrDuplicateValidationJobsAndRootWritePermission()
    {
        string source = ReadWorkflow().ReplaceLineEndings("\n");
        foreach (string changed in new[]
        {
            source.Replace("  validate:\n", "  renamed-validation:\n", StringComparison.Ordinal),
            source + "\n# Duplicate validation must still be rejected after a comment.\n  validate:\n    steps:\n      - name: Duplicate validation\n        run: echo fixture\n",
            source.Replace("  contents: read\n", "  contents: write\n", StringComparison.Ordinal),
            source.Replace("      - name: Validate production exec-tunnel admission\n", "      - name: Missing admission\n", StringComparison.Ordinal),
            source.Replace("      LEGACY_DEPLOY_ENABLED: 'false'\n", "      LEGACY_DEPLOY_ENABLED: 'true'\n", StringComparison.Ordinal)
                + "\n  independent-proof:\n    env:\n      LEGACY_DEPLOY_ENABLED: 'false'\n    steps:\n      - name: Independent proof\n        run: echo fixture\n",
        })
        {
            Assert.NotEqual(source, changed);
            _ = Assert.ThrowsAny<Xunit.Sdk.XunitException>(() => ValidateWorkflow(changed));
        }
    }

    private static void RequiredValidation_RejectsPreviousSetupDotnetPin()
    {
        string source = ReadWorkflow();
        string previousPin = source.Replace("actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68", "actions/setup-dotnet@26b0ec14cb23fa6904739307f278c14f94c95bf1", StringComparison.Ordinal);
        Assert.NotEqual(source, previousPin);
        _ = Assert.ThrowsAny<Xunit.Sdk.XunitException>(() => ValidateWorkflow(previousPin));
    }

    private static string ReadWorkflow()
    {
        DirectoryInfo? root = new(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, ".github", "workflows", "_build-and-test.yml")))
        { root = root.Parent; }
        Assert.NotNull(root);
        return File.ReadAllText(Path.Combine(root.FullName, ".github", "workflows", "_build-and-test.yml"));
    }

    private static void ValidateWorkflow(string source)
    {
        Assert.InRange(source.Length, 1, 65536);
        Match jobsRoot = Assert.Single(Regex.Matches(source, "^jobs:\\r?$", RegexOptions.Multiline, TimeSpan.FromSeconds(1)).Cast<Match>());
        string jobs = source[(jobsRoot.Index + jobsRoot.Length)..];
        Match nextSection = Regex.Match(jobs, "^[^\\s#][^\\r\\n]*:", RegexOptions.Multiline, TimeSpan.FromSeconds(1));
        if (nextSection.Success) jobs = jobs[..nextSection.Index];
        Match[] jobHeaders = [.. Regex.Matches(jobs, "^  (?<name>[A-Za-z_][A-Za-z0-9_-]*):\\r?$", RegexOptions.Multiline, TimeSpan.FromSeconds(1)).Cast<Match>()];
        Match validationHeader = Assert.Single(jobHeaders.Where(header => header.Groups["name"].Value == "validate"));
        int validationIndex = Array.IndexOf(jobHeaders, validationHeader);
        string validation = jobs[(validationHeader.Index + validationHeader.Length)..(validationIndex + 1 < jobHeaders.Length ? jobHeaders[validationIndex + 1].Index : jobs.Length)];
        Match[] headers = [.. Regex.Matches(validation, "^      - name: (?<name>[^\\r\\n]+)\\r?$", RegexOptions.Multiline, TimeSpan.FromSeconds(1)).Cast<Match>()];
        Assert.Equal(ExpectedSteps, headers.Select(header => header.Groups["name"].Value));
        string Body(int index)
        {
            return validation[(headers[index].Index + headers[index].Length)..(index + 1 < headers.Length ? headers[index + 1].Index : validation.Length)];
        }

        Assert.Equal("actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68", Scalar(Body(2), "uses"));
        Assert.Equal("10.0.x", Scalar(Body(2), "dotnet-version"));
        Assert.Equal("pwsh", Scalar(Body(3), "shell"));
        Assert.Equal("./scripts/prepare-consumer-owner-migration-proof.ps1", Scalar(Body(3), "run"));
        foreach (int index in new[] { 2, 3 })
        {
            Assert.False(Regex.IsMatch(Body(index), "^ +(?:if|continue-on-error|permissions|env):", RegexOptions.Multiline, TimeSpan.FromSeconds(1)));
        }
        Match permissions = Regex.Match(source, "^permissions:\\r?\\n(?<body>(?:^  [^\\r\\n]*\\r?\\n)+)", RegexOptions.Multiline, TimeSpan.FromSeconds(1));
        Assert.True(permissions.Success);
        Assert.Equal(MinimumPermissions, permissions.Groups["body"].Value.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.Trim()));
        Assert.DoesNotContain("id-token:", source, StringComparison.Ordinal);
        Assert.DoesNotContain("secrets.", source, StringComparison.Ordinal);
        Assert.False(Regex.IsMatch(source, "^ {4}(?:if|continue-on-error|permissions):", RegexOptions.Multiline, TimeSpan.FromSeconds(1)));
        Assert.Contains("LEGACY_DEPLOY_ENABLED: 'false'", validation, StringComparison.Ordinal);
        Assert.Equal("MALIEV-Co-Ltd/Legacy.Maliev.Workflows/actions/dotnet-validate@e3a6093324a24968876782153286f52db8b29fd8", Scalar(Body(4), "uses"));
    }

    private static string Scalar(string body, string name)
    {
        Match value = Assert.Single(Regex.Matches(body, "^ +" + Regex.Escape(name) + ": (?<value>[^\\r\\n]+)\\r?$", RegexOptions.Multiline, TimeSpan.FromSeconds(1)).Cast<Match>());
        return value.Groups["value"].Value;
    }
}
