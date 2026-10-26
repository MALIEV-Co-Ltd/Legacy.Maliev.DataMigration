using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAppOwnedRetained31ConsoleConfigurationTests
{
    [Theory]
    [InlineData((int)CurrentAppOwnedCommitClassification.Prepared, "prepared")]
    [InlineData((int)CurrentAppOwnedCommitClassification.CommittedAndReadback, "committed-readback")]
    [InlineData((int)CurrentAppOwnedCommitClassification.RolledBackBeforeCommit, "failed-or-uncertain")]
    [InlineData((int)CurrentAppOwnedCommitClassification.FailedBeforeCommit, "failed-or-uncertain")]
    [InlineData((int)CurrentAppOwnedCommitClassification.Uncertain, "failed-or-uncertain")]
    public void Both_closed_evidence_paths_retain_every_defined_classification(int value, string suffix)
    {
        var classification = (CurrentAppOwnedCommitClassification)value;
        Assert.Equal(suffix, CurrentAppOwnedRetained31ConsoleEnvironment.ReceiptSuffix(classification));
        Assert.Equal(suffix, CurrentAppOwnedV3RepairConsoleEnvironment.ReceiptSuffix(classification));
    }

    [Fact]
    public void Both_closed_evidence_paths_reject_unknown_classifications()
    {
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31ConsoleEnvironment.ReceiptSuffix((CurrentAppOwnedCommitClassification)999));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedV3RepairConsoleEnvironment.ReceiptSuffix((CurrentAppOwnedCommitClassification)999));
    }

    [Theory]
    [InlineData(/*lang=json,strict*/ "{\"Path\":\"a\",\"path\":\"b\",\"Sha256\":\"c\"}")]
    [InlineData(/*lang=json,strict*/ "{\"Nested\":{\"Key\":1,\"key\":2}}")]
    [InlineData(/*lang=json,strict*/ "[{\"Key\":1,\"Key\":2}]")]
    public void Duplicate_properties_are_rejected_at_every_depth(string json)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.DecodeRetained31<JsonElement>(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void Unknown_configuration_members_are_rejected()
    {
        CurrentAppOwnedRetained31RepairConfiguration configuration = Configuration();
        string json = JsonSerializer.Serialize(configuration);
        string unknown = json[..^1] + ",\"environmentCallback\":\"unsafe\"}";
        _ = Assert.Throws<JsonException>(() => MigrationConsole.DecodeRetained31<CurrentAppOwnedRetained31RepairConfiguration>(Encoding.UTF8.GetBytes(unknown)));
    }

    [Fact]
    public void Distinct_configuration_roundtrips_review_issuer_and_scope_fields()
    {
        CurrentAppOwnedRetained31RepairConfiguration expected = Configuration();
        CurrentAppOwnedRetained31RepairConfiguration actual = MigrationConsole.DecodeRetained31<CurrentAppOwnedRetained31RepairConfiguration>(JsonSerializer.SerializeToUtf8Bytes(expected));
        Assert.Equal(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(actual));
        Assert.Equal("scope.json", actual.ScopePath);
        Assert.Equal("review.pem", actual.ReviewPrivateKeyPath);
        Assert.Equal("review-output.json", actual.ReviewOutputPath);
        Assert.Equal(expected.ReviewExpiresAtUtc, actual.ReviewExpiresAtUtc);
    }

    private static CurrentAppOwnedRetained31RepairConfiguration Configuration()
    {
        var artifact = new CurrentAppOwnedRepairArtifact("proof.json", new string('a', 64));
        return new("before.json", "after.json", "scope.json", "review.json", "authorization.json", "pins.json", "binding.json",
            "operator.txt", "ordinary.txt", "baseline.json", "target.json", [], "receipt.pem", artifact, artifact, artifact,
            "review.pem", "review-output.json", new DateTimeOffset(2031, 1, 1, 1, 0, 0, TimeSpan.Zero), "authorization.pem", "authorization-output.json");
    }
}
