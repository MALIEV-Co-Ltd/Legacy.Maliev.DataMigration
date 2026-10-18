using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentCustomerSequenceRepairConsoleConfigurationTests
{
    [Theory]
    [InlineData(/*lang=json,strict*/ "{\"Path\":\"a\",\"path\":\"b\"}")]
    [InlineData(/*lang=json,strict*/ "{\"Nested\":{\"Key\":1,\"key\":2}}")]
    [InlineData(/*lang=json,strict*/ "[{\"Key\":1,\"Key\":2}]")]
    public void Duplicate_properties_fail_at_every_depth(string json)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.DecodeCustomerSequence<JsonElement>(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void Unknown_callbacks_cannot_enter_closed_configuration()
    {
        string json = JsonSerializer.Serialize(Configuration());
        _ = Assert.Throws<JsonException>(() => MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceRepairConfiguration>(
            Encoding.UTF8.GetBytes(json[..^1] + ",\"environmentCallback\":\"unsafe\"}")));
    }
    [Fact]
    public void Distinct_closed_configuration_roundtrips_source_and_issuer_custody()
    {
        var expected = Configuration();
        var actual = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceRepairConfiguration>(JsonSerializer.SerializeToUtf8Bytes(expected));
        Assert.Equal(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(actual));
        Assert.Equal("catalog.json", actual.SourceInputs.AcceptedCatalogReportPath);
        Assert.Equal("source-connection.txt", actual.SourceInputs.SourceConnectionPath);
    }
    [Theory]
    [InlineData((int)CurrentAppOwnedCommitClassification.Prepared, "prepared")]
    [InlineData((int)CurrentAppOwnedCommitClassification.CommittedAndReadback, "committed-readback")]
    [InlineData((int)CurrentAppOwnedCommitClassification.RolledBackBeforeCommit, "failed-or-uncertain")]
    [InlineData((int)CurrentAppOwnedCommitClassification.FailedBeforeCommit, "failed-or-uncertain")]
    [InlineData((int)CurrentAppOwnedCommitClassification.Uncertain, "failed-or-uncertain")]
    public void Receipt_names_cover_every_defined_classification(int value, string suffix)
    {
        Assert.Equal(suffix, CurrentCustomerSequenceRepairConsoleEnvironment.ReceiptSuffix((CurrentAppOwnedCommitClassification)value));
    }

    [Fact]
    public void Unknown_receipt_classification_fails()
    {
        _ = Assert.Throws<MigrationExecutionException>(() =>
        CurrentCustomerSequenceRepairConsoleEnvironment.ReceiptSuffix((CurrentAppOwnedCommitClassification)99));
    }

    [Theory]
    [InlineData("digest")]
    [InlineData("stale")]
    [InlineData("write")]
    [InlineData("service")]
    [InlineData("seed")]
    [InlineData("increment")]
    [InlineData("current")]
    [InlineData("coverage")]
    [InlineData("window")]
    public void Held_catalog_is_metadata_provenance_with_strict_shape_and_freshness(string fault)
    {
        var schema = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
        DateTimeOffset now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var facts = new List<object>
        {
            new { kind = "source", serverNameSha256 = new string('a', 64), productVersion = "15.0.1", loginName = "KubernetesAccess" }
        };
        foreach (var database in schema.Databases)
        {
            facts.Add(new { kind = "begin", database = database.Database, capturedUtc = (fault == "window" ? now : now.AddMinutes(-2)).ToString("o") });
            facts.Add(new { kind = "end", database = database.Database, capturedUtc = now.AddMinutes(-1).ToString("o") });
            foreach (var table in database.Tables)
            { facts.Add(new { kind = "schema", database = database.Database, schema = table.SourceSchema, table = table.SourceTable }); }
        }
        facts.Add(new
        {
            kind = "identity-definition",
            database = "Customer",
            schema = "dbo",
            table = "Customer",
            column = "ID",
            seed = fault == "seed" ? 1 : 1000,
            increment = fault == "increment" ? 2 : 1,
            currentValue = fault == "current" ? 998 : 69831,
            notForReplication = false
        });
        if (fault == "coverage") { facts.RemoveAt(1); }
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            kind = "fresh-readonly-source-catalog-and-counts",
            observedAtUtc = (fault == "stale" ? now.AddHours(-13) : now).ToString("o"),
            serviceUid = fault == "service" ? "wrong" : "71cf80cc-ec33-11e8-8f70-42010a8000ce",
            databaseWrites = fault == "write",
            atomicAcrossDatabases = false,
            facts
        });
        string pin = fault == "digest" ? new string('f', 64) : CurrentCustomerSequenceRepairPermit.Hash(bytes);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceRepairSourceObservation.ReadCatalog(bytes, schema, pin, schema.SourceCommitSha, now));
    }
    [Theory]
    [InlineData("review-current-customer-sequence-repair")]
    [InlineData("authorize-current-customer-sequence-repair")]
    [InlineData("verify-current-customer-sequence-repair")]
    [InlineData("apply-current-customer-sequence-repair")]
    public void Exactly_four_Customer_commands_parse_through_fixed_config_route(string command)
    {
        var invocation = ConsoleInvocation.Parse([command, "--config", "fixture.json"]);
        Assert.Equal(command, invocation.Command);
        Assert.Equal("fixture.json", invocation.ConfigPath);
    }
    private static CurrentCustomerSequenceRepairConfiguration Configuration()
    {
        var artifact = new CurrentAppOwnedRepairArtifact("proof.json", new string('a', 64));
        return new("source.json", new("catalog.json", "source-connection.txt", new(new Uri("https://kubernetes.default.svc"), "token", "ca.crt")),
            "scope.json", "review.json", "authorization.json", "pins.json", "binding.json", "operator.txt", "ordinary.txt", "baseline.json", "target.json", [],
            "receipt.pem", artifact, artifact, artifact, "review.pem", "review-output.json", new DateTimeOffset(2031, 1, 1, 1, 0, 0, TimeSpan.Zero), "authorization.pem", "authorization-output.json");
    }
}
