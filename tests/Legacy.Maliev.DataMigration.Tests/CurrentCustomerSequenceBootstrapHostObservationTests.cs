using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentCustomerSequenceBootstrapHostObservationTests
{
    [Fact]
    public void Flat_import_path_binding_rejects_aliases_and_relative_inputs_before_read()
    {
        string root = Path.GetFullPath("held-customer-proof"), source = Path.GetFullPath(Path.Combine("actual-case", "receipt.json"));
        CustomerGuardedBootstrapProofAssembler.RequireFlatImportPaths([source], root);
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerGuardedBootstrapProofAssembler.RequireFlatImportPaths([source], "relative"));
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerGuardedBootstrapProofAssembler.RequireFlatImportPaths(["relative.json"], root));
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerGuardedBootstrapProofAssembler.RequireFlatImportPaths([source, Path.Combine(Path.GetDirectoryName(source)!, "RECEIPT.JSON")], root));
    }
    [Fact]
    public void Copied_held_test_image_requires_original_executed_provenance()
    {
        string original = Path.GetFullPath(Path.Combine("actual-bin", "proof-tests.dll")), held = Path.GetFullPath(Path.Combine("held-root", "proof-tests.dll"));
        var image = new CustomerDefinitionArtifact(held, new('a', 64), original);
        CustomerDefinitionPrecursorReader.RequireImageProvenance(original, image, original, original);
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerDefinitionPrecursorReader.RequireImageProvenance(original, image with { SourcePath = null }, original, original));
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerDefinitionPrecursorReader.RequireImageProvenance(original, image, held, original));
    }
    // These reject malformed provenance shapes only; none asserts that synthetic evidence is actual.
    [Theory]
    [InlineData("no-member")]
    [InlineData("job-not-empty")]
    [InlineData("no-exit")]
    [InlineData("wrong-runs")]
    [InlineData("exit-before-start")]
    [InlineData("wrong-nonce")]
    [InlineData("failed-host")]
    public void Host_provenance_defects_fail_closed(string fault)
    {
        DateTimeOffset began = new(2026, 10, 13, 0, 0, 0, TimeSpan.Zero); Guid[] runs = [Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid()];
        var host = new CustomerGuardedBootstrapHostExit("current-customer-sequence-actual-testhost-exit-v1", 123, began.AddSeconds(-2),
            @"C:\Program Files\dotnet\dotnet.exe", new('a', 64), new('b', 64), began.AddSeconds(3), 0, runs, true, Guid.NewGuid().ToString("N"), began.AddSeconds(-1), true, true);
        host = fault switch
        {
            "no-member" => host with { NativeMembershipObserved = false },
            "job-not-empty" => host with { EmptyJobObservedAfterExit = false },
            "no-exit" => host with { ProcessExitObserved = false },
            "wrong-runs" => host with { RunIds = [Guid.NewGuid()] },
            "exit-before-start" => host with { ExitedAtUtc = began.AddSeconds(-3) },
            "wrong-nonce" => host with { JobNonce = "caller-marker" },
            "failed-host" => host with { ExitCode = 1 },
            _ => throw new InvalidOperationException()
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerGuardedBootstrapProofReader.RequireHostExit(host, began, began.AddSeconds(4), runs));
    }
}
