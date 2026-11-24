using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ConsumerColumnBootstrapOperationalNativeTests
{
    [Fact]
    public async Task Reviewed_orchestration_cancellation_precedes_configuration_or_rehearsal_access()
    {
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => MigrationConsole.RunConsumerColumnBootstrapReviewedAsync(
            "not-a-path", TextWriter.Null, TextWriter.Null, cancelled.Token));
    }

    [Fact]
    public async Task Cancellation_precedes_configuration_source_or_target_access()
    {
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => MigrationConsole.RunConsumerColumnBootstrapOperationalAsync(
            "apply-consumer-column-bootstrap-proof", "not-a-path", TextWriter.Null, TextWriter.Null, cancelled.Token));
    }

    [Fact]
    public async Task Configuration_cannot_adopt_a_target_without_an_actual_in_process_creation_lease()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        using var output = new StringWriter(); using var error = new StringWriter();
        int result = await MigrationConsole.RunConsumerColumnBootstrapOperationalAsync("apply-consumer-column-bootstrap-proof", "not-a-path", output, error, deadline.Token);
        Assert.Equal(1, result);
        Assert.Equal(string.Empty, output.ToString());
    }
}
