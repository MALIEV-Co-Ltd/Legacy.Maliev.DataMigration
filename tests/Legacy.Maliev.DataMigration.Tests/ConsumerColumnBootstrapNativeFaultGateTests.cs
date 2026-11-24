using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ConsumerColumnBootstrapNativeFaultGateTests
{
    [Fact]
    public async Task Native_suite_cannot_create_resources_from_a_testhost_or_read_caller_paths()
    {
        var config = new ConsumerColumnBootstrapNativeFaultConfiguration("not-a-source-path", new string('a', 64), "not-a-suite-root");
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => ConsumerColumnBootstrapRehearsalProducer.RunNativeFaultSuiteAsync(config, default));
    }

    [Fact]
    public async Task Native_console_entry_refuses_the_unaccepted_testhost_before_configuration_access()
    {
        using var output = new StringWriter(); using var error = new StringWriter();
        int code = await MigrationConsole.RunConsumerColumnBootstrapNativeFaultsAsync("not-a-path", output, error, default);
        Assert.Equal(1, code); Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task Cancellation_precedes_native_suite_configuration_or_source_access()
    {
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => MigrationConsole.RunConsumerColumnBootstrapNativeFaultsAsync(
            "not-a-path", TextWriter.Null, TextWriter.Null, cancelled.Token));
    }
}
