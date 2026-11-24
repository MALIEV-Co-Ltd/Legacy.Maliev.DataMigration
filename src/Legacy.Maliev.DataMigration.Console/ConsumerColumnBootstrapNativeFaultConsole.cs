namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    // The accepted-head workflow runs this separately and retains all five actual results
    // before invoking reviewed persistent apply. This is not a proof-token loading endpoint.
    internal static async Task<int> RunConsumerColumnBootstrapNativeFaultsAsync(string configurationPath,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            if (System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            var config = await ReadConsumerBootstrapProtectedAsync<ConsumerColumnBootstrapNativeFaultConfiguration>(configurationPath,
                "consumer_bootstrap_native_fault_configuration_unprotected", ct).ConfigureAwait(false);
            await ConsumerColumnBootstrapRehearsalProducer.RunNativeFaultSuiteAsync(config, ct).ConfigureAwait(false);
            await output.WriteLineAsync("consumer_column_bootstrap_five_actual_native_faults_complete").ConfigureAwait(false); return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or System.Text.Json.JsonException or FormatException or AggregateException or IOException or Npgsql.NpgsqlException or UnauthorizedAccessException or OperationCanceledException)
        { await error.WriteLineAsync("consumer_column_bootstrap_actual_native_faults_unfinished").ConfigureAwait(false); return 1; }
    }
}
