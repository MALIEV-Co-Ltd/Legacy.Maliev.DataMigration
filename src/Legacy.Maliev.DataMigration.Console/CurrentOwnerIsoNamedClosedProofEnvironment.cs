using System.Data;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

// Created exclusively by the closed Console enum4 branch, after the real precursor reader.
// This delegates every authority check to the closed environment; it observes no connections
// from the provider and cannot supply a preservation digest or a publication acknowledgment.
internal sealed class CurrentOwnerIsoNamedClosedProofEnvironment : ICurrentOwnerIsoRepairEnvironment, ICurrentOwnerIsoNativeProofObserver
{
    private readonly CurrentOwnerIsoRepairConsoleEnvironment _actual;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly CurrentOwnerIsoRepairScope _scope;
    private readonly ApprovedCurrentOwnerIsoOverlay _contract;
    private readonly string _operator, _root;
    private readonly Dictionary<string, CurrentAppOwnedDatabaseSnapshot> _phase;
    private readonly Dictionary<string, CurrentOwnerIsoNativeObservation> _candidates = new(StringComparer.Ordinal);
    private CurrentOwnerIsoNamedClosedCommitProxy? _proxy;
    private bool _fleetFaultUsed;
    private int _ordinal;

    internal CurrentOwnerIsoNamedClosedProofEnvironment(CurrentOwnerIsoRepairConsoleEnvironment actual,
        CurrentAppOwnedRepairCustody files, CurrentOwnerIsoRepairScope scope, FreshSchemaPlan source,
        IReadOnlyList<CurrentOwnerIsoSourceObservation> owners, IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> baseline, string operatorConnection, LocalExecutionBinding binding)
    {
        if (scope.ProofAdmission != CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap || scope.BootstrapSubject?.ClosedPrecursorPins is null ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) || DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(scope.Target) ||
            baseline.Count != 26 || baseline.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != 26 ||
            baseline.Any(x => !scope.BeforeDatabaseSha256.TryGetValue(x.Database, out string? hash) || hash != x.Sha256)) { throw Invalid(); }
        if (binding.ComputeSha256() != scope.RunBindingSha256 || !Path.IsPathFullyQualified(binding.ArtifactRootCanonicalPath)) { throw Invalid(); }
        _actual = actual; _files = files; _scope = scope; _operator = operatorConnection; _root = binding.ArtifactRootCanonicalPath;
        _contract = ApprovedCurrentOwnerIsoOverlay.Create(source, scope.SourceCommitSha, scope.Operation, owners, DateTimeOffset.UtcNow);
        _phase = baseline.ToDictionary(x => x.Database, x => x, StringComparer.Ordinal);
    }

    internal void Attach(CurrentOwnerIsoNamedClosedCommitProxy proxy)
    {
        if (_proxy is not null || proxy.Operation != _scope.OperationId || _scope.BootstrapSubject!.CaseId != "lost-commit-ack") { throw Invalid(); }
        _proxy = proxy;
    }
    public Task RequireSourceAsync(string sha, CancellationToken ct)
    {
        return _actual.RequireSourceAsync(sha, ct);
    }

    public Task RequireOwnerSourcesAsync(string sha, CancellationToken ct)
    {
        return _actual.RequireOwnerSourcesAsync(sha, ct);
    }

    public Task RequireResourceAndCustodyAsync(CurrentOwnerIsoRepairScope scope, CancellationToken ct)
    {
        return _actual.RequireResourceAndCustodyAsync(scope, ct);
    }

    public Task<string> InspectGlobalPreservationAsync(CancellationToken ct)
    {
        return _actual.InspectGlobalPreservationAsync(ct);
    }

    public Task RequireFreshOperationAsync(CurrentOwnerIsoRepairScope scope, CancellationToken ct)
    {
        return _actual.RequireFreshOperationAsync(scope, ct);
    }

    public Task ReserveFreshOperationAsync(CurrentOwnerIsoRepairScope scope, string authorization, CancellationToken ct)
    {
        return _actual.ReserveFreshOperationAsync(scope, authorization, ct);
    }

    public async Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken ct)
    {
        await _actual.RetainNewEvidenceAsync(name, payload, ct).ConfigureAwait(false);
        if (!name.Contains("-Country-", StringComparison.Ordinal)) { return; }
        var receipt = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairReceipt>(payload);
        if (receipt.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback || _scope.BootstrapSubject!.CaseId != "fleet-drift" || _fleetFaultUsed) { return; }
        _fleetFaultUsed = true;
        await using var connection = Connection("Upload"); await connection.OpenAsync(ct).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);
        await using var command = new NpgsqlCommand("UPDATE private.owner_iso_closed_sentinel SET evidence='changed-after-Country-ACK' WHERE id=1 AND evidence='unchanged';", connection, tx);
        if (await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false) != 1) { throw Invalid(); }
        await tx.CommitAsync(ct).ConfigureAwait(false);
        await RecordAsync("fleet-drift", new { _scope.OperationId, Database = "Upload", ObservedAtUtc = DateTimeOffset.UtcNow }, ct).ConfigureAwait(false);
    }
    public async Task ObserveCommittedDatabaseAsync(CurrentOwnerIsoRepairReceipt prepared, CancellationToken ct)
    {
        await _actual.ObserveCommittedDatabaseAsync(prepared, ct).ConfigureAwait(false);
        await using var connection = Connection(prepared.Database); await connection.OpenAsync(ct).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
        await ReadOnlyAsync(connection, tx, ct).ConfigureAwait(false);
        var native = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, _contract, true, ct).ConfigureAwait(false);
        if (!_candidates.TryGetValue(prepared.Database, out var candidate) || native.Snapshot.Sha256 != prepared.AfterSha256) { throw Invalid(); }
        // No raw catalog, storage, literal, row or sequence omissions. Only the separately
        // observed transaction horizon may differ across independent transactions.
        RequireReadback(candidate, native);
        await RecordAsync("readback-" + prepared.Database, IsoCapturedNative.Capture(native), ct).ConfigureAwait(false);
        _phase[prepared.Database] = native.Snapshot; await tx.RollbackAsync(ct).ConfigureAwait(false);
    }
    public async Task ObserveCandidateAsync(CurrentOwnerIsoNativeObservation locked, CurrentOwnerIsoNativeObservation candidate, CancellationToken ct)
    {
        string database = candidate.Snapshot.Database;
        if (database is not ("Country" or "Material") || locked.Snapshot.Sha256 != _phase[database].Sha256 || !_candidates.TryAdd(database, candidate)) { throw Invalid(); }
        CurrentOwnerIsoNativePreservation.RequirePreserved(locked, candidate, _contract);
        await RecordAsync("locked-" + database, IsoCapturedNative.Capture(locked), ct).ConfigureAwait(false);
        await RecordAsync("candidate-" + database, IsoCapturedNative.Capture(candidate), ct).ConfigureAwait(false);
        var fleet = new List<CurrentAppOwnedDatabaseSnapshot>();
        foreach (var expected in _phase.Values.OrderBy(x => x.Database, StringComparer.Ordinal))
        {
            if (expected.Database == database) { fleet.Add(candidate.Snapshot); continue; }
            await using var connection = Connection(expected.Database); await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ReadOnlyAsync(connection, tx, ct).ConfigureAwait(false);
            await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, tx, _scope.Maintenance.Role, _scope.Target.Kind, ct).ConfigureAwait(false);
            var observed = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false);
            if (observed.Sha256 != expected.Sha256) { throw Invalid(); }
            fleet.Add(observed); await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        _files.Require();
        await _files.WriteBaselineNewAsync(PathFor("candidate-fleet-" + database), fleet.ToArray(), ct).ConfigureAwait(false);
        _proxy?.Arm();
    }
    internal static void RequireReadback(CurrentOwnerIsoNativeObservation candidate, CurrentOwnerIsoNativeObservation after)
    {
        if (candidate.Snapshot.Sha256 != after.Snapshot.Sha256 || candidate.OverlaySha256 != after.OverlaySha256 || candidate.Selected != after.Selected ||
            candidate.LiteralRows != after.LiteralRows || CurrentAppOwnedSnapshotSerialization.Sha256(candidate.CopyCatalog()) != CurrentAppOwnedSnapshotSerialization.Sha256(after.CopyCatalog()) ||
            CurrentAppOwnedSnapshotSerialization.Sha256(candidate.CopyStorage()) != CurrentAppOwnedSnapshotSerialization.Sha256(after.CopyStorage())) { throw Invalid(); }
    }
    private NpgsqlConnection Connection(string database)
    {
        return new(new NpgsqlConnectionStringBuilder(_operator) { Database = database, Pooling = false, Timeout = 5, CommandTimeout = 30, IncludeErrorDetail = false }.ConnectionString);
    }

    private string PathFor(string phase)
    {
        return Path.Combine(_root, $"iso-closed-native-{_scope.OperationId:N}-{Interlocked.Increment(ref _ordinal):D5}-{phase}.json");
    }

    private Task RecordAsync<T>(string phase, T value, CancellationToken ct)
    {
        return _files.WriteNewAsync(PathFor(phase), JsonSerializer.SerializeToUtf8Bytes(value), ct);
    }

    private static async Task ReadOnlyAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken ct)
    { await using var command = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx); _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
    private static MigrationExecutionException Invalid()
    {
        return CurrentOwnerIsoRepairPermit.Invalid();
    }
}
