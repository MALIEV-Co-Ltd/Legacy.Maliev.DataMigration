using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentOwnerIsoRepairConsoleConfigurationTests
{
    [Theory]
    [InlineData(/*lang=json,strict*/ "{\"Path\":\"a\",\"path\":\"b\"}")]
    [InlineData(/*lang=json,strict*/ "{\"Nested\":{\"Key\":1,\"key\":2}}")]
    [InlineData(/*lang=json,strict*/ "[{\"Key\":1,\"Key\":2}]")]
    public void Duplicate_properties_fail_closed_at_every_depth(string json)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.DecodeOwnerIso<JsonElement>(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void Distinct_configuration_rejects_environment_callbacks_and_roundtrips_custody()
    {
        var artifact = new CurrentAppOwnedRepairArtifact("proof.json", new('a', 64));
        var expected = new CurrentOwnerIsoRepairConfiguration("source.json",
            new("catalog.json", "source-connection.txt", new(new Uri("https://kubernetes.default.svc"), "token", "ca.crt")),
            "owners.json", "scope.json", "review.json", "authorization.json", "pins.json", "binding.json", "operator.txt", "ordinary.txt",
            "baseline.json", "target.json", [], "receipt.pem", artifact, artifact, artifact,
            new("maintenance-proof.json", new('b', 64)), "maintenance-validator.cs");
        string json = JsonSerializer.Serialize(expected);
        Assert.Equal(json, JsonSerializer.Serialize(MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairConfiguration>(Encoding.UTF8.GetBytes(json))));
        _ = Assert.Throws<JsonException>(() => MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairConfiguration>(Encoding.UTF8.GetBytes(
            json[..^1] + ",\"environmentCallback\":\"unsafe\"}")));
    }

    [Theory]
    [InlineData("prepared", (int)CurrentAppOwnedCommitClassification.Prepared)]
    [InlineData("committed-readback", (int)CurrentAppOwnedCommitClassification.CommittedAndReadback)]
    [InlineData("failed-or-uncertain", (int)CurrentAppOwnedCommitClassification.Uncertain)]
    public void Fixed_receipt_slots_match_provider(string suffix, int classification)
    {
        Assert.Equal(suffix, CurrentOwnerIsoRepairConsoleEnvironment.ReceiptSuffix((CurrentAppOwnedCommitClassification)classification));
    }

    [Fact]
    public void Unknown_receipt_slot_fails_closed()
    {
        _ = Assert.Throws<MigrationExecutionException>(() =>
        CurrentOwnerIsoRepairConsoleEnvironment.ReceiptSuffix((CurrentAppOwnedCommitClassification)99));
    }

    [Fact]
    public void Canonical_helper_normalizes_only_CRLF_without_BOM_or_space_removal()
    {
        static string Hash(string text)
        {
            return MigrationConsole.CanonicalOwnerIsoHelperSha256(Encoding.UTF8.GetBytes(text));
        }

        Assert.Equal(Hash("synthetic\n"), Hash("synthetic\r\n"));
        Assert.NotEqual(Hash("synthetic"), Hash("\ufeffsynthetic"));
        Assert.NotEqual(Hash("synthetic"), Hash(" synthetic "));
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequireCanonicalHelper(Encoding.UTF8.GetBytes("synthetic"),
            CurrentOwnerIsoRepairPermit.MaintenanceValidator));
    }
    [Theory]
    [InlineData(3221225472UL, 0UL, true, true)]
    [InlineData(3221225471UL, 0UL, true, false)]
    [InlineData(1073741824UL, 5368709120UL, false, true)]
    [InlineData(1073741823UL, 0UL, false, false)]
    [InlineData(3221225472UL, 5368709121UL, true, false)]
    public void Fixed_capacity_boundaries_match_unchanged_admission_floor_and_owned_RSS(ulong available, ulong owned, bool admission, bool pass)
    {
        if (pass) { CurrentOwnerIsoCapacity.RequireValues(available, owned, admission); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoCapacity.RequireValues(available, owned, admission)); }
    }

    [Fact]
    public void ISO_reservation_slot_is_distinct_and_unknown_or_replayed_slots_fail()
    {
        Guid operation = Guid.NewGuid();
        string expected = CurrentOwnerIsoRepairConsoleEnvironment.ReservationName(operation);
        Assert.Equal($"{operation:D}-owner-iso-operation-start.json", expected);
        Assert.NotEqual($"{operation:D}-customer-sequence-operation-start.json", expected);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoRepairConsoleEnvironment.RequireSlotInventory([expected], []));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoRepairConsoleEnvironment.RequireSlotInventory(
            [$"{operation:D}-customer-sequence-operation-start.json"], [expected]));
    }

    [Theory]
    [InlineData("Prepared_receipt_publication_failure_rolls_back_without_commit", "prepared-publication-before-ack")]
    [InlineData("Dropped_commit_ack_stops_without_Material_apply", "commit-ack-lost")]
    [InlineData("Terminal_publication_uncertainty_stops_without_Material_apply", "terminal-publication")]
    [InlineData("Full_fleet_drift_after_Country_stops_Material", "fleet-after-country")]
    public void Empty_effects_and_unchanged_fleet_cannot_prove_post_DDL_failures(string name, string boundary)
    {
        var hashes = new Dictionary<string, string>(StringComparer.Ordinal) { ["Country"] = new('a', 64), ["Material"] = new('b', 64), ["Upload"] = new('c', 64) };
        var scenario = new CurrentOwnerIsoProofScenario("current-owner-iso-proof-scenario-v1", Guid.NewGuid(), new('d', 64), boundary,
            "injected-boundary", DateTimeOffset.UtcNow, [], [], false, false, false);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoClosedProofReader.RequireCaseEffects(name, scenario, [], hashes, hashes));
    }

    [Fact]
    public void Maintenance_success_requires_all_database_probes_and_semantic_acceptance()
    {
        var hashes = new Dictionary<string, string>(StringComparer.Ordinal) { ["Country"] = new('a', 64), ["Material"] = new('b', 64), ["Upload"] = new('c', 64) };
        var scenario = new CurrentOwnerIsoProofScenario("current-owner-iso-proof-scenario-v1", Guid.NewGuid(), new('d', 64), "maintenance-probes",
            null, DateTimeOffset.UtcNow, [], ["Country"], true, false, false);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoClosedProofReader.RequireCaseEffects(
            "Ordinary_client_rejected_in_all_26_databases", scenario, [], hashes, hashes));
    }
    private static CurrentOwnerIsoRepairReceipt Shape(CurrentAppOwnedCommitClassification classification, string after, string previous, DateTimeOffset at)
    {
        return new("current-owner-iso-receipt-v1", Guid.NewGuid(), "Country", new('a', 64), new('b', 64), new('c', 64), after, new('d', 64), previous, classification, at, "test", null);
    }

    [Fact]
    public void Terminal_after_image_must_match_its_database_prepared_receipt()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var prepared = Shape(CurrentAppOwnedCommitClassification.Prepared, new('a', 64), new('0', 64), now);
        var terminal = Shape(CurrentAppOwnedCommitClassification.CommittedAndReadback, new('b', 64), new('f', 64), now);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoClosedProofReader.RequireAcknowledgedAfterImages([prepared, terminal]));
    }
    [Fact]
    public void Unacknowledged_terminal_cannot_borrow_an_unrelated_predecessor_or_after_image()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var prepared = Shape(CurrentAppOwnedCommitClassification.Prepared, new('a', 64), new('0', 64), now);
        var failure = Shape(CurrentAppOwnedCommitClassification.Uncertain, new('a', 64), new('f', 64), now.AddSeconds(2));
        var unrelated = Shape(CurrentAppOwnedCommitClassification.CommittedAndReadback, new('b', 64), new('e', 64), now.AddSeconds(1));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoClosedProofReader.RequireUnacknowledgedLink(unrelated,
            [prepared, failure], [new('f', 64), new('d', 64)], "terminal-publication"));
    }
    [Fact]
    public void Unrelated_TRX_class_and_executed_binary_path_are_rejected()
    {
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoClosedProofReader.RequireTrxMethod(
            "Dropped_commit_ack_stops_without_Material_apply", "Unrelated.Tests", "Dropped_commit_ack_stops_without_Material_apply"));
        string executed = Path.GetFullPath("approved-tests.dll"), unrelated = Path.GetFullPath("unrelated-tests.dll");
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoClosedProofReader.RequireExecutedAssemblyPath(executed, executed, unrelated, executed));
    }
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public void Cleanup_claims_cannot_substitute_for_successful_absence_inventories(bool success, bool listenerPresent)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow; Guid run = Guid.NewGuid();
        var absence = new CurrentOwnerIsoProofAbsence("current-owner-iso-cleanup-absence-v1", run, now, [], [], [],
            listenerPresent ? [54321] : [], success, success, success);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoClosedProofReader.RequireAbsence(absence, run, new('a', 64),
            "legacy-delta-proof-fixture", ["legacy-delta-proof-fixture"], [54321], now, now));
    }
}
