namespace Legacy.Maliev.DataMigration.Console;

internal sealed record ConsumerColumnBootstrapReviewedConfiguration(ConsumerColumnBootstrapRehearsalConfiguration Rehearsal,
    IReadOnlyList<string> TargetConfigurationPaths);

public static partial class MigrationConsole
{
    internal static Task<T> ReadConsumerBootstrapProtectedAsync<T>(string path, string code, CancellationToken ct)
    {
        return ReadProtectedJsonAsync<T>(path, code, ct, maximumByteLength: 65536);
    }

    // One process owns the actual rehearsal and nonserializable token through all target steps.
    // A JSON proof supplied by a caller is deliberately not an alternate entry point.
    internal static async Task<int> RunConsumerColumnBootstrapReviewedAsync(string configurationPath,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct); lifetime.CancelAfter(TimeSpan.FromMinutes(25)); ct = lifetime.Token;
        try
        {
            var config = await ReadProtectedJsonAsync<ConsumerColumnBootstrapReviewedConfiguration>(configurationPath,
                "consumer_bootstrap_reviewed_configuration_unprotected", ct, maximumByteLength: 65536).ConfigureAwait(false);
            if (config.TargetConfigurationPaths.Count is < 1 or > 2 ||
                config.TargetConfigurationPaths.Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).Count() != config.TargetConfigurationPaths.Count)
            { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            var completion = await ConsumerColumnBootstrapRehearsalProducer.ProduceAsync(config.Rehearsal, ct).ConfigureAwait(false);
            foreach (string targetInput in config.TargetConfigurationPaths)
            {
                using var invocation = await ConsumerColumnBootstrapReviewedInvocation.CreateAsync(targetInput, completion, ct).ConfigureAwait(false);
                foreach (string command in new[] { "review-consumer-column-bootstrap-reviewed", "authorize-consumer-column-bootstrap-reviewed", "apply-consumer-column-bootstrap-reviewed" })
                {
                    if (await RunConsumerColumnBootstrapOperationalAsync(command, invocation.ConfigurationPath, TextWriter.Null, error, ct,
                        reviewed: invocation).ConfigureAwait(false) != 0)
                    { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
                }
            }
            await output.WriteLineAsync("consumer_column_bootstrap_reviewed_targets_reconciled").ConfigureAwait(false); return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or System.Text.Json.JsonException or FormatException or AggregateException)
        { await error.WriteLineAsync("consumer_column_bootstrap_reviewed_run_unfinished").ConfigureAwait(false); return 1; }
    }
}
