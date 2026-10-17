namespace Legacy.Maliev.DataMigration.Console;

internal sealed record Production181SdkDisposalEvidence(string Owner, int ProcessId, DateTimeOffset ProcessStartTimeUtc,
    string Executable, string ExecutableSha256, int TaskId, DateTimeOffset BeganAtUtc, DateTimeOffset DeadlineAtUtc,
    DateTimeOffset ObservedAtUtc, bool Settled, bool Disposed, string? Failure);

internal static class Production181SdkDisposal
{
    // One disposal attempt only. A timed-out managed task remains owned by the exact finite host job;
    // the caller must retain this failure frame and cannot publish successful component evidence.
    internal static async Task<Production181SdkDisposalEvidence> ObserveAsync(IDisposable client, string owner)
    {
        using var image = Production181ActualExecutableImage.OpenCurrent();
        DateTimeOffset began = DateTimeOffset.UtcNow, deadline = began.AddSeconds(10);
        Task task = Task.Run(client.Dispose, CancellationToken.None);
        string? failure = null; bool disposed = false;
        try { await task.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false); disposed = true; }
        catch (TimeoutException) { failure = "sdk_dispose_outstanding"; }
        catch (Exception) { failure = "sdk_dispose_failed"; }
        if (!task.IsCompleted)
        {
            // Observe a later fault without another worker or a false cleanup claim.
            _ = task.ContinueWith(t => { _ = t.Exception; }, CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
        image.Require();
        return new(owner, image.ProcessId, image.ProcessStartTimeUtc, image.Path, image.Sha256, task.Id,
            began, deadline, DateTimeOffset.UtcNow, task.IsCompleted, disposed, failure);
    }
}
