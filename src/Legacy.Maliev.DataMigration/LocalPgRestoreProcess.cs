using System.Diagnostics;

namespace Legacy.Maliev.DataMigration;

internal static class LocalPgRestoreProcess
{
    internal static async Task RestoreAsync(ProcessStartInfo start, Stream plaintext, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var process = new Process { StartInfo = start };
        try { if (!process.Start()) { throw Failed(); } }
        catch (System.ComponentModel.Win32Exception) { throw Failed(); }
        using var inputCancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        Task output = Task.WhenAll(process.StandardOutput.BaseStream.CopyToAsync(Stream.Null, CancellationToken.None),
            process.StandardError.BaseStream.CopyToAsync(Stream.Null, CancellationToken.None));
        Task exit = process.WaitForExitAsync(CancellationToken.None);
        Task input = CopyAsync(plaintext, process.StandardInput.BaseStream, inputCancellation.Token);
        Exception? primary = null;
        try
        {
            Task first = await Task.WhenAny(input, exit).WaitAsync(token).ConfigureAwait(false);
            if (first == exit && !input.IsCompletedSuccessfully) { throw Failed(); }
            await input.ConfigureAwait(false);
            await exit.WaitAsync(token).ConfigureAwait(false);
            await output.WaitAsync(token).ConfigureAwait(false);
            if (process.ExitCode != 0) { throw Failed(); }
        }
        catch (Exception error) { primary = error; }
        Exception? cleanup = null;
        if (primary is not null)
        {
            await inputCancellation.CancelAsync().ConfigureAwait(false);
            try { await PgDumpProcessTermination.TerminateAndObserveAsync(process, TimeSpan.FromSeconds(10)).ConfigureAwait(false); }
            catch (Exception error) { cleanup = error; }
            try { await input.ConfigureAwait(false); }
            catch (Exception error) when (error is OperationCanceledException or IOException or ObjectDisposedException) { }
            catch (Exception error) { cleanup = Combine(cleanup, error); }
            try { await PgDumpProcessTermination.AwaitDrainAsync(output, TimeSpan.FromSeconds(10)).ConfigureAwait(false); }
            catch (Exception error) { cleanup = Combine(cleanup, error); }
            // WaitForExitAsync has no cancellation: observe its terminal result too.
            try { await exit.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false); }
            catch (Exception error) { cleanup = Combine(cleanup, error); }
        }
        PgDumpProcessTermination.ThrowPrimaryOrAggregate(primary, cleanup, "Local archive restore and process cleanup both failed.");
    }

    private static async Task CopyAsync(Stream plaintext, Stream input, CancellationToken token)
    {
        try { await plaintext.CopyToAsync(input, token).ConfigureAwait(false); }
        finally { await input.DisposeAsync().ConfigureAwait(false); }
    }

    private static Exception Combine(Exception? first, Exception second)
    {
        return first is null ? second : new AggregateException(first, second);
    }

    private static MigrationExecutionException Failed()
    {
        return new("local_archive_restore_failed", "The local PostgreSQL restore did not fully consume and restore the archive successfully.");
    }
}
