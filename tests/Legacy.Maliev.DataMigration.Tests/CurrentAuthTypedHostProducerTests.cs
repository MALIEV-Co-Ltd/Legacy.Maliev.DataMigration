using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

/// <summary>Source candidate tests; no test starts a native proof, process, job or container.</summary>
public sealed class CurrentAuthTypedHostProducerTests
{
    [Fact]
    public void Filters_accept_only_the_fixed_definition_component_and_closed_case_methods()
    {
        Assert.Contains("Fixed_transition_preserves_populated_rows_private_state_and_independent_history", CurrentAuthTypedHostProducer.Filter("definition"));
        Assert.Contains("Unsupported_preimage_fails_before_candidate", CurrentAuthTypedHostProducer.Filter("definition"));
        Assert.Equal("FullyQualifiedName~CurrentAuthGuardedNativeExecutionTests.Genuine_auth_provider_preserves_fleet_and_receipts_or_stops",
            CurrentAuthTypedHostProducer.Filter("provider"));
        Assert.Equal("FullyQualifiedName~CurrentAuthClosedConsoleExecutionTests.Genuine_named_closed_auth_console_preserves_or_stops",
            CurrentAuthTypedHostProducer.Filter("closed"));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthTypedHostProducer.Filter("closed|arbitrary"));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthTypedHostProducer.Filter("provider|arbitrary"));
    }
    [WindowsLocalRunFact]
    public void Fixed_child_launch_clears_environment_and_preserves_unchanged_heap_cap()
    {
        var start = CurrentAuthTypedHostProducer.FixedStart(@"D:\synthetic-unit-fixture-not-authority");
        Assert.False(start.UseShellExecute); Assert.True(start.CreateNoWindow);
        Assert.Equal(CurrentAuthTypedHostProducer.Dotnet, start.FileName); Assert.Empty(start.ArgumentList);
        Assert.Equal("0x20000000", start.Environment["DOTNET_GCHeapHardLimit"]);
        Assert.Equal("true", start.Environment["TESTCONTAINERS_RYUK_DISABLED"]);
        Assert.DoesNotContain("DOCKER_HOST", start.Environment.Keys);
        Assert.DoesNotContain("PGPASSWORD", start.Environment.Keys);
        Assert.DoesNotContain("DOTNET_STARTUP_HOOKS", start.Environment.Keys);
        Assert.DoesNotContain("COMPlus_Profiler", start.Environment.Keys);
    }
}
