using System.Diagnostics;

namespace Legacy.Maliev.DataMigration;

internal sealed class ReadOnlyDockerProcess : IReadOnlyDockerProcess
{
    public async Task<BackupProcessResult> RunAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo("docker") { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in arguments) { start.ArgumentList.Add(argument); }
        // Explicit --host is pinned after context inspection. Environment overrides must never redirect it.
        foreach (string variable in new[] { "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION" })
        {
            if (arguments[0] == "--host") { _ = start.Environment.Remove(variable); }
        }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        return await ExecuteAsync(start, deadline.Token).ConfigureAwait(false);
    }

    internal static async Task<BackupProcessResult> ExecuteAsync(ProcessStartInfo start, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var process = new Process { StartInfo = start };
        try { if (!process.Start()) { throw LocalDockerResourceObserver.Reject("docker_start"); } }
        catch (System.ComponentModel.Win32Exception) { throw LocalDockerResourceObserver.Reject("docker_start"); }
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
        Task<string> stderr = process.StandardError.ReadToEndAsync(CancellationToken.None);
        try
        {
            await process.WaitForExitAsync(token).ConfigureAwait(false);
            _ = await Task.WhenAll(stdout, stderr).WaitAsync(token).ConfigureAwait(false);
            return new(process.ExitCode, stdout.Result, stderr.Result);
        }
        catch (Exception primary)
        {
            Exception? cleanup = null;
            try { await PgDumpProcessTermination.TerminateAndObserveAsync(process, TimeSpan.FromSeconds(5)).ConfigureAwait(false); }
            catch (Exception error) { cleanup = error; }
            try { await PgDumpProcessTermination.AwaitDrainAsync(Task.WhenAll(stdout, stderr), TimeSpan.FromSeconds(5)).ConfigureAwait(false); }
            catch (Exception error) { cleanup = cleanup is null ? error : new AggregateException(cleanup, error); }
            PgDumpProcessTermination.ThrowPrimaryOrAggregate(primary, cleanup, "Docker observation failed and process termination or drain also failed.");
            throw;
        }
    }
}
