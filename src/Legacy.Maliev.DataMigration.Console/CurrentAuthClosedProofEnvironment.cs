using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

// This source proposal is reachable only through enum3's exact owned named-disposable Console branch.
// Every permission/policy/source/custody/fleet/reservation operation delegates to the real closed environment.
internal sealed class CurrentAuthClosedProofEnvironment : ICurrentAuthRepairEnvironment, ICurrentAuthNativeProofObserver
{
    private readonly CurrentAuthRepairEnvironment _actual;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly CurrentAuthRepairScope _scope;
    private readonly string _root, _operator;
    private int _ordinal;
    private bool _faultUsed;
    private CurrentAuthClosedCommitProxy? _commitProxy;
    internal CurrentAuthClosedProofEnvironment(CurrentAuthRepairEnvironment actual, CurrentAppOwnedRepairCustody files,
        CurrentAuthRepairScope scope, string root, string operatorConnection)
    {
        if (scope.ProofAdmission != CurrentAuthProofAdmission.DisposableClosedConsoleBootstrap || scope.ClosedBootstrapSubject is null ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) || !Path.IsPathFullyQualified(root))
        { throw CurrentAuthRepairPermit.Invalid(); }
        var endpoint = new NpgsqlConnectionStringBuilder(operatorConnection);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 || endpoint.Username != scope.Maintenance.Role ||
            endpoint.Pooling || string.IsNullOrEmpty(endpoint.Password) || !string.IsNullOrEmpty(endpoint.Options))
        { throw CurrentAuthRepairPermit.Invalid(); }
        _actual = actual; _files = files; _scope = scope; _root = root; _operator = operatorConnection;
    }
    internal void AttachCommitProxy(CurrentAuthClosedCommitProxy proxy)
    {
        if (_commitProxy is not null || proxy.Operation != _scope.OperationId || _scope.ClosedBootstrapSubject!.CaseId != "lost-commit-ack")
        { throw CurrentAuthRepairPermit.Invalid(); }
        _commitProxy = proxy;
    }
    public Task RequireSourceAsync(string sourceCommitSha, CancellationToken ct) => _actual.RequireSourceAsync(sourceCommitSha, ct);
    public Task RequireAuthOwnerSourceAsync(CurrentAuthRepairScope scope, CancellationToken ct) => _actual.RequireAuthOwnerSourceAsync(scope, ct);
    public Task RequireSource23PhysicalBaselineAsync(FreshSchemaPlan source, CancellationToken ct) => _actual.RequireSource23PhysicalBaselineAsync(source, ct);
    public Task RequireResourceAndCustodyAsync(CurrentAuthRepairScope scope, CancellationToken ct) => _actual.RequireResourceAndCustodyAsync(scope, ct);
    public Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CurrentAuthRepairScope scope, CancellationToken ct) => _actual.InspectFleetAsync(scope, ct);
    public Task RequireFreshOperationAsync(CurrentAuthRepairScope scope, CancellationToken ct) => _actual.RequireFreshOperationAsync(scope, ct);
    public async Task ReserveFreshOperationAsync(CurrentAuthRepairScope scope, string authorizationSha256, CancellationToken ct)
    {
        await _actual.ReserveFreshOperationAsync(scope, authorizationSha256, ct).ConfigureAwait(false);
        await RecordAsync("reservation-returned", new { scope.OperationId, authorizationSha256 }, ct).ConfigureAwait(false);
    }
    public async Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken ct)
    {
        // The original closed publisher performs signature/chain/slot validation, durable write and held byte readback.
        await _actual.RetainNewEvidenceAsync(name, payload, ct).ConfigureAwait(false);
        bool receiptSlot = name.Contains("-Auth-", StringComparison.Ordinal);
        CurrentAuthRepairReceipt? receipt = receiptSlot ? MigrationConsole.DecodeAuthRepair<CurrentAuthRepairReceipt>(payload) : null;
        await RecordAsync("publication-return", new
        {
            name, sha256 = Convert.ToHexStringLower(SHA256.HashData(payload)),
            acknowledged = true, classification = receipt?.Classification, observedAtUtc = DateTimeOffset.UtcNow
        }, ct).ConfigureAwait(false);
        if (receipt?.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback)
        { await MutateFinalFleetAsync(ct).ConfigureAwait(false); }
    }
    public async Task ObserveCandidateAsync(CurrentAuthNativeObservation locked, CurrentAuthNativeObservation candidate, CancellationToken ct)
    {
        CurrentAuthNativePreservation.RequirePreserved(locked, candidate);
        await RecordAsync("locked-before", Native(locked), ct).ConfigureAwait(false);
        await RecordAsync("native-candidate", Native(candidate), ct).ConfigureAwait(false);
        _commitProxy?.Arm();
    }
    private async Task MutateFinalFleetAsync(CancellationToken ct)
    {
        if (_scope.ClosedBootstrapSubject!.CaseId == "final-fleet" && !_faultUsed)
        {
            _faultUsed = true;
            // A deliberately changed sentinel exists only in this owned disposable fixture's postgres database.
            // Real closed fleet inspection must detect this committed mutation and prevent terminal acceptance.
            var endpoint = new NpgsqlConnectionStringBuilder(_operator)
            { Database = "postgres", Pooling = false, Timeout = 5, CommandTimeout = 5, IncludeErrorDetail = false };
            await using var connection = new NpgsqlConnection(endpoint.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);
            await using var command = new NpgsqlCommand("""
                UPDATE private.auth_closed_sentinel SET evidence='changed-during-candidate'
                WHERE id=1 AND evidence='unchanged';
                """, connection, tx);
            if (await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false) != 1) { throw CurrentAuthRepairPermit.Invalid(); }
            await tx.CommitAsync(ct).ConfigureAwait(false);
            await using var capture = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, capture))
            { _ = await readOnly.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
            var snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, capture, ct).ConfigureAwait(false);
            await capture.RollbackAsync(ct).ConfigureAwait(false);
            await RecordAsync("final-fleet-mutated", snapshot, ct).ConfigureAwait(false);
        }
    }
    private static CurrentAuthProofNative Native(CurrentAuthNativeObservation value) => new(value.Snapshot, value.CopyTuples(),
        value.CopyStorage().ToDictionary(x => x.Key, x => new CurrentAuthProofStorage(x.Value.FileNode, x.Value.Blocks), StringComparer.Ordinal), value.CopyExpressions());
    private async Task RecordAsync<T>(string phase, T value, CancellationToken ct)
    {
        _files.Require();
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        if (bytes.Length is < 1 or > 32 * 1024 * 1024) { throw CurrentAuthRepairPermit.Invalid(); }
        string path = Path.Combine(_root, $"auth-closed-observation-{_scope.OperationId:N}-{Interlocked.Increment(ref _ordinal):D5}-{phase}.json");
        await _files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
        _files.Require();
    }
}
