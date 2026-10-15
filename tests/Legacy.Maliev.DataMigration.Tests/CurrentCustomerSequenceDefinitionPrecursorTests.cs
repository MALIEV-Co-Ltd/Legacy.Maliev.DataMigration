using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentCustomerSequenceDefinitionPrecursorTests
{
    [Fact]
    public void Flat_imported_image_keeps_exact_executed_TRX_path_and_held_content_binding()
    {
        string original = Path.GetFullPath(Path.Combine("actual-images", "native-tests.dll"));
        string flat = Path.GetFullPath(Path.Combine("flat-authority-root", "held-native-tests.dll"));
        var image = new CustomerDefinitionArtifact(flat, new('a', 64), original);
        CustomerDefinitionPrecursorReader.RequireImageProvenance(original, image, original, original);
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerDefinitionPrecursorReader.RequireImageProvenance(flat, image, original, original));
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerDefinitionPrecursorReader.RequireImageProvenance(original, image with { SourcePath = null }, original, original));
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerDefinitionPrecursorReader.RequireImageProvenance(original, image with { SourcePath = "relative.dll" }, original, original));
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerDefinitionPrecursorReader.RequireImageProvenance(original, image with { Sha256 = "marker" }, original, original));
        Assert.NotEqual(JsonSerializer.Serialize(image), JsonSerializer.Serialize(image with { SourcePath = flat }));
    }

    [Fact]
    public void Assembler_rejects_unrelated_output_or_multiple_run_ownership()
    {
        Guid run = Guid.NewGuid();
        static string Actual(Guid id)
        {
            return JsonSerializer.Serialize(new { run = id, Purpose = "current-customer-sequence-definition-feasibility" });
        }

        Assert.Equal(run, CustomerDefinitionPrecursorAssembler.RequireReportedRun(Actual(run) + "\n" + Actual(run)));
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerDefinitionPrecursorAssembler.RequireReportedRun("passed"));
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerDefinitionPrecursorAssembler.RequireReportedRun(Actual(run) + "\n" + Actual(Guid.NewGuid())));
    }
    [Fact]
    public void Assembler_never_adopts_an_unreviewed_negative_SQL_case()
    {
        Assert.Equal("reject-cache", CustomerDefinitionPrecursorAssembler.NegativeCase("ALTER SEQUENCE public.\"Customer_ID_seq\" CACHE 2;"));
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerDefinitionPrecursorAssembler.NegativeCase("ALTER SEQUENCE public.\"Customer_ID_seq\" RESTART WITH 1000;"));
    }
    [Fact]
    public void Definition_subject_has_no_recursive_operational_proof_or_claim_fields()
    {
        var subject = new CustomerDefinitionSubject(ApprovedCurrentCustomerSequenceDefinitionTests.Source(), ApprovedCurrentCustomerSequenceDefinitionTests.Owner(),
            new('a', 64), ApprovedCurrentCustomerSequenceDefinitionTests.Contract().ComputeSha256(), new('b', 64), new('c', 64), new('d', 64), new('e', 64), new('f', 64));
        string json = JsonSerializer.Serialize(subject);
        Assert.DoesNotContain("OperationSha256", json, StringComparison.Ordinal);
        Assert.DoesNotContain("DefinitionProofSha256", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Authorization", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Maintenance", json, StringComparison.Ordinal);
    }
    [Theory]
    [InlineData("exit")]
    [InlineData("removal")]
    [InlineData("disposal")]
    [InlineData("lease")]
    [InlineData("absence_lease")]
    [InlineData("exit_lease")]
    [InlineData("nonutc")]
    public void Definition_cleanup_requires_real_exit_removal_absence_disposal_order(string fault)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow, removed = now.AddSeconds(1), absence = now.AddSeconds(2), disposed = now.AddSeconds(3), lease = now.AddMinutes(1);
        CustomerDefinitionPrecursorReader.RequireCleanup(now, removed, absence, disposed, lease);
        if (fault == "exit") { removed = now.AddTicks(-1); }
        if (fault == "removal") { absence = now; }
        if (fault == "disposal") { disposed = now; }
        if (fault == "lease") { disposed = lease.AddMinutes(2); }
        if (fault == "absence_lease") { absence = lease.AddTicks(1); disposed = absence; }
        if (fault == "exit_lease") { now = lease.AddTicks(1); removed = now; absence = now; disposed = now; }
        if (fault == "nonutc") { absence = absence.ToOffset(TimeSpan.FromHours(7)); }
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerDefinitionPrecursorReader.RequireCleanup(now, removed, absence, disposed, lease));
    }
    [Fact]
    public void Negative_definition_case_requires_the_actual_validator_rejection_code()
    {
        var state = ApprovedCurrentCustomerSequenceDefinitionTests.State() with { Owner = "postgres", Cache = 2 };
        var observation = ApprovedCurrentCustomerSequenceDefinitionTests.Observation(state);
        CustomerDefinitionPrecursorReader.RequireNativeCase("reject-cache", observation, observation, observation, null, false,
            "current_customer_sequence_definition_preparation_invalid");
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerDefinitionPrecursorReader.RequireNativeCase("reject-cache",
            observation, observation, observation, null, false, "unrelated"));
    }
    [Fact]
    public void Definition_native_case_cannot_label_an_unchanged_state_as_committed_repair()
    {
        var state = ApprovedCurrentCustomerSequenceDefinitionTests.State() with { Owner = "postgres" };
        var before = ApprovedCurrentCustomerSequenceDefinitionTests.Observation(state);
        string id = $"start-{state.LastValue}-{state.IsCalled.ToString().ToLowerInvariant()}-{state.AttributeNumber}";
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerDefinitionPrecursorReader.RequireNativeCase(id, before, before, before, before, true, null));
    }
    [Theory]
    [InlineData(1, false, 1)]
    [InlineData(69831, true, 9)]
    [InlineData(2000000000, true, 1)]
    [InlineData(2000000000, false, 9)]
    public void Exact_definition_case_preserves_allocation_ordinal_catalog_and_rows(long last, bool called, short ordinal)
    {
        var state = ApprovedCurrentCustomerSequenceDefinitionTests.State() with { Owner = "postgres", LastValue = last, IsCalled = called, AttributeNumber = ordinal };
        var before = ApprovedCurrentCustomerSequenceDefinitionTests.Observation(state);
        var after = ApprovedCurrentCustomerSequenceDefinitionTests.Observation(ApprovedCurrentCustomerSequenceDefinitionTests.Final(state));
        string id = $"start-{last}-{called.ToString().ToLowerInvariant()}-{ordinal}";
        CustomerDefinitionPrecursorReader.RequireNativeCase(id, before, after, after, before, true, null);
        var allocated = ApprovedCurrentCustomerSequenceDefinitionTests.Observation(after.State with { LastValue = last + 1 });
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerDefinitionPrecursorReader.RequireNativeCase(id, before, after, allocated, before, true, null));
    }
}
