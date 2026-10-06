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
        DirectoryInfo? root = new(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, ".github", "workflows", "_build-and-test.yml")))
        { root = root.Parent; }
        Assert.NotNull(root);
        string source = File.ReadAllText(Path.Combine(root.FullName, ".github", "workflows", "_build-and-test.yml"));
        Assert.InRange(source.Length, 1, 65536);
        Match[] headers = [.. Regex.Matches(source, "^      - name: (?<name>[^\\r\\n]+)\\r?$", RegexOptions.Multiline, TimeSpan.FromSeconds(1)).Cast<Match>()];
        Assert.Equal(ExpectedSteps, headers.Select(header => header.Groups["name"].Value));
        string Body(int index)
        {
            return source[(headers[index].Index + headers[index].Length)..(index + 1 < headers.Length ? headers[index + 1].Index : source.Length)];
        }

        Assert.Equal("actions/setup-dotnet@26b0ec14cb23fa6904739307f278c14f94c95bf1", Scalar(Body(2), "uses"));
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
        Assert.False(Regex.IsMatch(source, "^ {4}(?:if|continue-on-error):", RegexOptions.Multiline, TimeSpan.FromSeconds(1)));
        Assert.Contains("LEGACY_DEPLOY_ENABLED: 'false'", source, StringComparison.Ordinal);
        Assert.Equal("MALIEV-Co-Ltd/Legacy.Maliev.Workflows/actions/dotnet-validate@e3a6093324a24968876782153286f52db8b29fd8", Scalar(Body(4), "uses"));
    }

    private static string Scalar(string body, string name)
    {
        Match value = Assert.Single(Regex.Matches(body, "^ +" + Regex.Escape(name) + ": (?<value>[^\\r\\n]+)\\r?$", RegexOptions.Multiline, TimeSpan.FromSeconds(1)).Cast<Match>());
        return value.Groups["value"].Value;
    }
}
