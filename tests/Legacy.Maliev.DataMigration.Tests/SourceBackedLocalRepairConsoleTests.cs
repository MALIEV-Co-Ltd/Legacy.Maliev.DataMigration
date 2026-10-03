using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SourceBackedLocalRepairConsoleTests
{
    private const string Head = "0123456789abcdef0123456789abcdef01234567";

    [Fact]
    public void LiveConsoleComposition_RequiresConcreteMaintenanceAndHasNoConfigurableProvider()
    {
        var method = typeof(MigrationConsole).GetMethod(nameof(MigrationConsole.ComposeSourceBackedLocalRepairRuntime),
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!;
        Assert.Equal(typeof(SourceBackedLocalRepairMaintenance), method.GetParameters()[1].ParameterType);
        Assert.DoesNotContain(typeof(SourceBackedLocalRepairCommandConfiguration).GetProperties(),
            property => typeof(ISourceBackedLocalRepairMaintenance).IsAssignableFrom(property.PropertyType));
        Assert.Empty(typeof(SourceBackedLocalRepairRuntime).GetConstructors());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task PairedQuotationCapture_AcceptsOnlyTheSameObservedReviewedVariant(int variantValue)
    {
        var variant = (ReviewedQuotationPhysicalVariant)variantValue;
        var schema = new DatabaseSchemaPlan("Quotation", "1.0", new string('a', 64), new string('b', 64), []);
        int observations = 0;
        Task<ReviewedQuotationPhysicalVariant> Observe(DatabaseSchemaPlan _, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            observations++;
            return Task.FromResult(variant);
        }
        Assert.Equal(variant, await PairedDeltaTargetPhysicalSchemaFence.ObserveQuotationVariantAsync(
            schema, Observe, Observe, null, CancellationToken.None));
        Assert.Equal(2, observations);
    }

    [Theory]
    [InlineData(0, 1, null)]
    [InlineData(99, 99, null)]
    [InlineData(1, 1, 0)]
    [InlineData(0, 0, 1)]
    public async Task PairedQuotationCapture_RejectsMixedUnknownAndBothTargetsChangingAfterCapture(
        int leftValue, int rightValue, int? expectedValue)
    {
        var left = (ReviewedQuotationPhysicalVariant)leftValue;
        var right = (ReviewedQuotationPhysicalVariant)rightValue;
        ReviewedQuotationPhysicalVariant? expected = expectedValue.HasValue ? (ReviewedQuotationPhysicalVariant)expectedValue.Value : null;
        var schema = new DatabaseSchemaPlan("Quotation", "1.0", new string('a', 64), new string('b', 64), []);
        DeltaExecutionException error = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            PairedDeltaTargetPhysicalSchemaFence.ObserveQuotationVariantAsync(schema,
                (_, _) => Task.FromResult(left), (_, _) => Task.FromResult(right), expected, CancellationToken.None));
        Assert.Equal("delta_paired_quotation_physical_mismatch", error.Code);
    }

    [Theory]
    [InlineData("stage-source-backed-local-repair")]
    [InlineData("prepare-source-backed-local-repair-authority")]
    [InlineData("authorize-source-backed-local-repair")]
    [InlineData("admit-source-backed-local-repair")]
    [InlineData("apply-source-backed-local-repair-next")]
    [InlineData("reconcile-source-backed-local-repair")]
    [InlineData("renew-source-backed-local-repair")]
    public void OperatorCommands_AcceptOnlyProtectedConfigurationReferences(string command)
    {
        Assert.Equal(command, ConsoleInvocation.Parse([command, "--config", "protected.json"]).Command);
        Assert.Equal("secret_cli_argument_forbidden", Assert.Throws<CommandLineException>(() =>
            ConsoleInvocation.Parse([command, "--password", "do-not-disclose"])).Code);
    }

    [Fact]
    public void ExactHeadCi_RequiresItsActualGithubActionsSuiteAndRequiredCheck()
    {
        using JsonDocument runs = Runs("success");
        using JsonDocument checks = Checks(42, Head, "github-actions", "success");
        SourceBackedLocalRepairSourceAcceptance.RequireCi(runs.RootElement, checks.RootElement, Head);
    }

    [Theory]
    [InlineData("1.0.0")]
    [InlineData("1.0.0+0123456789abcdef0123456789abcdef01234567.dirty")]
    [InlineData("1.0.0+0123456789abcdef0123456789abcdef01234567+extra")]
    [InlineData("1.0.0+0123456")]
    public void CompiledSource_UnknownDirtyOrAmbiguousRevision_Rejects(string version)
    {
        Assert.Equal(Head, SourceBackedLocalRepairSourceAcceptance.RequireCompiledSourceRevision("1.0.0+" + Head));
        _ = Assert.Throws<MigrationConsoleException>(() => SourceBackedLocalRepairSourceAcceptance.RequireCompiledSourceRevision(version));
    }

    [Theory]
    [InlineData(43, Head, "github-actions", "success")]
    [InlineData(42, "1123456789abcdef0123456789abcdef01234567", "github-actions", "success")]
    [InlineData(42, Head, "different-app", "success")]
    [InlineData(42, Head, "github-actions", "failure")]
    public void ExactHeadCi_ForgedSuiteDifferentHeadAppOrFailedCheck_Rejects(long suite, string head, string app, string conclusion)
    {
        using JsonDocument runs = Runs("success");
        using JsonDocument checks = Checks(suite, head, app, conclusion);
        Assert.Equal("delta_source_repair_source_unaccepted", Assert.Throws<MigrationConsoleException>(() =>
            SourceBackedLocalRepairSourceAcceptance.RequireCi(runs.RootElement, checks.RootElement, Head)).Code);
    }

    [Fact]
    public void ExactHeadCi_OlderSuccessDoesNotOverrideNewFailedRerun()
    {
        using JsonDocument runs = Runs("failure", includeOlderSuccess: true);
        using JsonDocument checks = Checks(42, Head, "github-actions", "success");
        _ = Assert.Throws<MigrationConsoleException>(() =>
            SourceBackedLocalRepairSourceAcceptance.RequireCi(runs.RootElement, checks.RootElement, Head));
    }

    [Fact]
    public void ExactHeadCi_DuplicateOldSuccessAndNewFailureInSameSuite_Rejects()
    {
        using JsonDocument runs = Runs("success");
        using JsonDocument success = Checks(42, Head, "github-actions", "success");
        using JsonDocument failure = Checks(42, Head, "github-actions", "failure");
        using JsonDocument checks = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            check_runs = new[] { success.RootElement.GetProperty("check_runs")[0], failure.RootElement.GetProperty("check_runs")[0] }
        }));
        _ = Assert.Throws<MigrationConsoleException>(() =>
            SourceBackedLocalRepairSourceAcceptance.RequireCi(runs.RootElement, checks.RootElement, Head));
    }

    private static JsonDocument Runs(string conclusion, bool includeOlderSuccess = false)
    {
        static object Run(string result, string updated)
        {
            return new
            {
                head_sha = Head,
                head_branch = "main",
                path = ".github/workflows/ci-main.yml",
                name = "CI - Main",
                status = "completed",
                conclusion = result,
                @event = "push",
                check_suite_id = 42,
                updated_at = updated
            };
        }

        object[] runs = includeOlderSuccess ? [Run("success", "2026-10-02T00:00:00Z"), Run(conclusion, "2026-10-02T00:01:00Z")]
            : [Run(conclusion, "2026-10-02T00:01:00Z")];
        return JsonDocument.Parse(JsonSerializer.Serialize(new { workflow_runs = runs }));
    }

    private static JsonDocument Checks(long suite, string head, string app, string conclusion)
    {
        return JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            check_runs = new[] { new {
            head_sha = head, name = "validate / validate", check_suite = new { id = suite },
            app = new { slug = app }, status = "completed", conclusion } }
        }));
    }
}
