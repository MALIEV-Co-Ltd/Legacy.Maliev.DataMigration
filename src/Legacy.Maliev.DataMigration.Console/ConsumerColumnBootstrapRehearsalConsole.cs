namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    internal static async Task<int> RunConsumerColumnBootstrapRehearsalAsync(string configurationPath,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            var config = await ReadProtectedJsonAsync<ConsumerColumnBootstrapRehearsalConfiguration>(configurationPath,
                "consumer_bootstrap_rehearsal_configuration_unprotected", ct, maximumByteLength: 65536).ConfigureAwait(false);
            var completion = await ConsumerColumnBootstrapRehearsalProducer.ProduceAsync(config, ct).ConfigureAwait(false);
            _ = ConsumerColumnBootstrapRehearsalAcceptance.Read(completion);
            await output.WriteLineAsync("consumer_column_bootstrap_rehearsal_reconciled_persistent_authorization_required").ConfigureAwait(false); return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or System.Text.Json.JsonException or FormatException or AggregateException)
        { await error.WriteLineAsync("consumer_column_bootstrap_rehearsal_failed").ConfigureAwait(false); return 1; }
    }
}
