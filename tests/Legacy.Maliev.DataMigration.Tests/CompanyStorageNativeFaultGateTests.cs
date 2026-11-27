using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CompanyStorageNativeFaultGateTests
{
    [Fact]
    public async Task Observation_cannot_sign_or_open_credentials_from_a_testhost()
    {
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CompanyStorageRepairInputs.ObserveAndSignAsync("not-a-configuration", default));
    }
    [Fact]
    public async Task Fault_suite_refuses_testhost_before_configuration_or_resource_access()
    {
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CompanyStorageRuntime.RunNativeFaultSuiteAsync(new("not-a-configuration", "not-a-root"), default));
    }
    [Fact]
    public async Task Fault_console_does_not_treat_testhost_refusal_as_native_fault_acceptance()
    {
        using var output = new StringWriter(); using var error = new StringWriter();
        Assert.Equal(1, await MigrationConsole.RunCompanyStorageNativeFaultsAsync("not-a-configuration", output, error, default));
        Assert.Equal(string.Empty, output.ToString());
    }
    [Fact]
    public async Task Cancellation_precedes_fault_configuration_or_source_access()
    {
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => MigrationConsole.RunCompanyStorageNativeFaultsAsync("not-a-configuration", TextWriter.Null, TextWriter.Null, cancelled.Token));
    }
}
