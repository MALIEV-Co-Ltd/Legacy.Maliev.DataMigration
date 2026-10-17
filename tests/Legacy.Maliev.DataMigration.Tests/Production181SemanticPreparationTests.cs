using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Production181SemanticPreparationTests
{
    [WindowsLocalRunTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Sdk_disposal_records_actual_settlement_and_does_not_claim_fault_success(bool fail)
    {
        var disposable = new ObservedDisposable(fail);
        var actual = await Production181SdkDisposal.ObserveAsync(disposable, "pure-disposal-test");
        Assert.Equal(1, disposable.Calls); Assert.True(actual.Settled); Assert.Equal(!fail, actual.Disposed);
        Assert.Equal(fail ? "sdk_dispose_failed" : null, actual.Failure);
        Assert.True(actual.ProcessId > 0); Assert.True(actual.TaskId > 0); Assert.Equal(TimeSpan.FromSeconds(10), actual.DeadlineAtUtc - actual.BeganAtUtc);
        Assert.Equal(64, actual.ExecutableSha256.Length);
    }
    private sealed class ObservedDisposable(bool fail) : IDisposable
    {
        internal int Calls { get; private set; }
        public void Dispose() { Calls++; if (fail) { throw new InvalidOperationException("Expected disposable fault"); } }
    }
    [Fact]
    public void Actual_guarded_entry_uses_entered_time_and_rejects_definition_frame()
    {
        using var actual = JsonDocument.Parse("""{"enteredAtUtc":"2026-10-13T00:00:00+00:00"}""");
        using var wrong = JsonDocument.Parse("""{"beganAtUtc":"2026-10-13T00:00:00+00:00"}""");
        Assert.Equal(DateTimeOffset.Parse("2026-10-13T00:00:00+00:00", System.Globalization.CultureInfo.InvariantCulture), Production181SemanticEnvelopeReader.GuardedInvocationBegin(actual.RootElement));
        _ = Assert.Throws<KeyNotFoundException>(() => Production181SemanticEnvelopeReader.GuardedInvocationBegin(wrong.RootElement));
    }
    [Theory]
    [InlineData(-1)]
    [InlineData(11)]
    public void Real_capture_must_be_within_actual_invocation(int seconds)
    {
        DateTimeOffset began = new(2026, 10, 13, 0, 0, 0, TimeSpan.Zero);
        _ = Assert.Throws<MigrationExecutionException>(() => Production181SemanticEnvelopeReader.RequireCaptureChronology(began.AddSeconds(seconds), began, began.AddSeconds(10)));
        Production181SemanticEnvelopeReader.RequireCaptureChronology(began.AddSeconds(1), began, began.AddSeconds(10));
    }
    [Theory]
    [InlineData("production181-customer-components", true)]
    [InlineData("production181-initialize-input-root", true)]
    [InlineData("production181-customer-host-child", true)]
    [InlineData("apply", false)]
    [InlineData("production181-apply", false)]
    public void Only_three_fixed_disposable_routes_exist(string route, bool expected)
    { Assert.Equal(expected, Production181PipelineCommand.IsCommand(route)); }
    [Theory]
    [InlineData("../escape")]
    [InlineData("nested/../escape")]
    [InlineData("CON.dll")]
    [InlineData("nested/.run.lock")]
    public void Actual_bundle_paths_reject_aliases(string path)
    { _ = Assert.Throws<MigrationExecutionException>(() => Production181ProtectedBundle.Relative(path)); }
    [Theory]
    [InlineData("Bad checksums: 0\n", true)]
    [InlineData("Bad checksums:  0\n", true)]
    [InlineData("Bad checksums: 1\n", false)]
    [InlineData("Bad checksums: 0\nBad checksums: 1\n", false)]
    [InlineData("Bad checksums: 0\nBad checksums: 0\n", false)]
    [InlineData("not actual checksum output", false)]
    public void Checksum_count_must_be_one_exact_successful_actual_result(string output, bool expected)
    { Assert.Equal(expected, Production181SemanticEnvelopeReader.NoBadChecksums(output)); }
    [Fact]
    public void Offline_checker_has_same_owned_volume_no_ports_fixed_engine_and_command()
    {
        Guid run = Guid.NewGuid(); var checker = Production181DisposablePlans.Checksum(run, new('a', 64));
        Assert.Equal(Production181EngineContract.Image, checker.Image); Assert.Equal("26:102", checker.User);
        Assert.Equal(Production181EngineContract.Name(run) + "-checksum", checker.Name);
        var host = checker.HostConfig ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        var mounts = host.Mounts ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        var options = mounts.Single().VolumeOptions ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        Assert.Null(checker.ExposedPorts); Assert.Null(host.PortBindings);
        Assert.Equal(4, checker.Labels.Count); Assert.True(options.NoCopy);
        Assert.Equal("export LC_ALL=C; exec /usr/lib/postgresql/18/bin/pg_checksums --check --pgdata=/var/lib/postgresql/18/docker", checker.Cmd.Single());
    }
    [Theory]
    [InlineData("production")]
    [InlineData("closed-console")]
    [InlineData("all")]
    public void Host_accepts_only_fixed_component_groups(string group)
    { _ = Assert.Throws<MigrationExecutionException>(() => Production181HostLauncher.Filter(group)); }
    [Fact]
    public void Fixed_native_host_filters_target_engine_specific_algorithms_only()
    {
        string definition = Production181HostLauncher.Filter("definition-component");
        Assert.Contains("Production181CustomerDefinitionNativeTests", definition); Assert.DoesNotContain("CurrentCustomerSequenceNativeFeasibilityTests", definition);
        Assert.Equal(6, Production181HostLauncher.Filter("native-component").Split('|').Length);
        Assert.Equal(4, Production181HostLauncher.Filter("maintenance-component").Split('|').Length);
    }
    [Fact]
    public void Declared_named_mount_rejects_copying_and_alternate_sources()
    {
        using var valid = JsonDocument.Parse("""{"Mounts":[{"Type":"volume","Source":"owned","Target":"/var/lib/postgresql","ReadOnly":false,"VolumeOptions":{"NoCopy":true}}]}""");
        using var copying = JsonDocument.Parse("""{"Mounts":[{"Type":"volume","Source":"owned","Target":"/var/lib/postgresql","ReadOnly":false,"VolumeOptions":{"NoCopy":false}}]}""");
        Assert.True(Production181SemanticResource.DeclaredMount(valid.RootElement, "owned"));
        Assert.False(Production181SemanticResource.DeclaredMount(valid.RootElement, "persistent"));
        Assert.False(Production181SemanticResource.DeclaredMount(copying.RootElement, "owned"));
    }
}
