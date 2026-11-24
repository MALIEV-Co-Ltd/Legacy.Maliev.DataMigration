namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CurrentAuthArchiveGenuineExecutionIssuer
{
    private int _driftStarted;
    internal async Task<CurrentAuthArchiveGenuineDriftApplied> ApplyDriftAsync(Guid id, CancellationToken ct)
    {
        _ = await RequireExecutionAsync(id, false, ct);
        if (Interlocked.CompareExchange(ref _driftStarted, 1, 0) != 0) { throw Invalid(); }
        try
        {
            var result = await _lease.ApplyDriftAsync(ct);
            if (!CurrentAuthArchiveGenuineDrift.IsCase(result.Case)) { throw Invalid(); }
            Check(id, false); _bundle.Require(); return result;
        }
        catch { lock (_gate) { _failed = true; } throw; }
    }

    internal async Task<CurrentAuthArchiveGenuineDualArtifacts> RetainDriftFailureAsync(Guid id,
        CurrentAuthArchiveGenuineDriftFailure facts, CancellationToken ct)
    {
        Check(id, false); _bundle.Require();
        if (Volatile.Read(ref _driftStarted) != 1 || !CurrentAuthArchiveGenuineDrift.IsCase(facts.Case)) { throw Invalid(); }
        try
        {
            var result = await _lease.RetainDriftFailureAsync(facts, ct);
            lock (_gate) { if (_disposed || _failed || _closed || id != _id) { throw Invalid(); } _closed = true; }
            _bundle.Require(); return result;
        }
        catch { lock (_gate) { _failed = true; } throw; }
    }
}
