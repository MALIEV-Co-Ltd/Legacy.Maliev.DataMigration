namespace Legacy.Maliev.DataMigration.Tests;

// Test-fixture publication only. No serialized callback or timeout setting enters an operational command.
internal static class CurrentAuthArchiveFixtureFrame
{
    internal static async Task RunAsync(Func<CancellationToken, Task> publish, TimeSpan budget, CancellationToken ct)
    {
        if (budget <= TimeSpan.Zero || budget > TimeSpan.FromSeconds(5)) { throw new ArgumentOutOfRangeException(nameof(budget)); }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(budget);
        deadline.Token.ThrowIfCancellationRequested();
        Task publication = publish(deadline.Token);
        try
        {
            await publication.WaitAsync(deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            await deadline.CancelAsync().ConfigureAwait(false);
            try { await publication.WaitAsync(TimeSpan.FromSeconds(1), CancellationToken.None).ConfigureAwait(false); }
            catch (OperationCanceledException) when (publication.IsCompleted) { }
            catch (TimeoutException failure)
            { throw new InvalidOperationException("archive_fixture_frame_publication_unsettled", failure); }
            if (ct.IsCancellationRequested) { throw; }
            throw new TimeoutException("archive_fixture_frame_publication_timed_out");
        }
    }
}
