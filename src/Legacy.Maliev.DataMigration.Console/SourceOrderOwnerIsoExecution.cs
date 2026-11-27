using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class SourceOrderOwnerIsoRuntime
{
    private readonly Dictionary<string, SourceOrderOwnerIsoNativeWitness> _candidateReadbacks = new(StringComparer.Ordinal);
    internal async Task ExecuteAsync(CancellationToken ct)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct); lifetime.CancelAfter(TimeSpan.FromMinutes(8)); ct = lifetime.Token;
        await RefuseReplayAsync(ct); await VerifyAsync(ct);
        var proof = await Rehearsal.RunAsync(this, ct); proof.Require(this); await VerifyAsync(ct);
        Guid operation = Guid.NewGuid(); DateTimeOffset now = DateTimeOffset.UtcNow;
        var pending = SourceOrderOwnerIsoProtocol.Databases.Where(x => !_input.Intent.Selected[x]).ToArray();
        var scope = new SourceOrderOwnerIsoScope(_owned is null ? "source-order-owner-iso-scope-v1" : "source-order-owner-iso-owned-scope-v1", operation,
            SourceOrderOwnerIsoProtocol.Hash(_input.IntentClaim), _input.Intent, Source.FullPlanSha256, Contract.ComputeSha256(), proof.Artifact.Sha256, _code.RunnerDigestSha256,
            pending, await OwnersAsync(_input, ct), now, now.AddMinutes(2) < _input.Intent.ExpiresAtUtc ? now.AddMinutes(2) : _input.Intent.ExpiresAtUtc);
        if (_fault is not null) { await _fault.BindAsync(_input, scope, ct); }
        var pins = _input.Configuration.SigningPins;
        using var reviewer = _input.Signer(_input.Configuration.ReviewPrivateKey, pins.ReviewKeyId, pins.ReviewFingerprint);
        using var authorizer = _input.Signer(_input.Configuration.AuthorizationPrivateKey, pins.AuthorizationKeyId, pins.AuthorizationFingerprint);
        using var evidence = _input.Signer(_input.Configuration.EvidencePrivateKey, pins.ReceiptKeyId, pins.ReceiptFingerprint);
        var review = CurrentAuthLocalSessionArchivePolicy.Sign(SourceOrderOwnerIsoProtocol.ReviewDomain, scope, reviewer);
        var auth = CurrentAuthLocalSessionArchivePolicy.Sign(SourceOrderOwnerIsoProtocol.AuthorizationDomain,
            new SourceOrderOwnerIsoAuthorization(operation, SourceOrderOwnerIsoProtocol.Hash(review), now, scope.ExpiresAtUtc), authorizer);
        _ = await _input.PublishAsync("scope", scope, operation, ct); _ = await _input.PublishAsync("review", review, operation, ct);
        _ = await _input.PublishAsync("authorization", auth, operation, ct); _ = await _input.PublishAsync("source-capture", Source, operation, ct);
        _ = await _input.PublishAsync("reservation", new { OperationId = operation, ScopeSha256 = SourceOrderOwnerIsoProtocol.Hash(scope), AuthorizationSha256 = SourceOrderOwnerIsoProtocol.Hash(auth) }, _input.Intent.IntentId, ct);
        string previous = new('0', 64); var committed = new Dictionary<string, string>(StringComparer.Ordinal);
        var terminallyRetained = new Dictionary<string, string>(StringComparer.Ordinal);
        var observedEffects = new Dictionary<string, string>(StringComparer.Ordinal); var selected = _input.Intent.Selected.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        string? active = null; bool commitStarted = false, acknowledged = false, rollbackAcknowledged = false; string? afterNative = null;
        NpgsqlConnection? connection = null; NpgsqlTransaction? transaction = null;
        try
        {
            await LeaseAsync();
            foreach (string database in pending)
            {
                active = database; commitStarted = false; acknowledged = false; rollbackAcknowledged = false; afterNative = null;
                RequireFleet(await FleetAsync(selected, ct), committed);
                connection = Connect(database); await connection.OpenAsync(ct); transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct);
                var reviewed = _input.Baseline(database);
                await CurrentAppOwnedRepairPreservation.LockAsync(connection, transaction, reviewed, ct);
                await PolicyAsync(connection, transaction, ct); await LeaseAsync();
                var locked = await SourceOrderOwnerIsoNativeWitness.CaptureAsync(connection, transaction, Contract, false, ct);
                if (locked.Sha256 != _input.Intent.NativePreimageSha256[database] || locked.Native.Snapshot.Sha256 != reviewed.Sha256) { throw Invalid(); }
                string owner = await OwnerAsync(connection, transaction, locked, ct);
                await using (var ddl = new NpgsqlCommand(PostgreSqlCurrentOwnerIsoRepair.Sql, connection, transaction)) { _ = await ddl.ExecuteNonQueryAsync(ct); }
                var candidate = await SourceOrderOwnerIsoNativeWitness.CaptureAsync(connection, transaction, Contract, true, ct);
                SourceOrderOwnerIsoNativeWitness.RequirePreserved(locked, candidate, Contract);
                if (await OwnerAsync(connection, transaction, candidate, ct) != owner) { throw Invalid(); }
                _candidateReadbacks.Add(database, candidate); afterNative = candidate.Sha256;
                await PolicyAsync(connection, transaction, ct); await LeaseAsync();
                await ReceiptAsync(database, CurrentAppOwnedCommitClassification.Prepared, "prepared", ct); _fault?.Prepared(operation, database);
                await LeaseAsync(); commitStarted = true; await transaction.CommitAsync(ct); acknowledged = true;
                await transaction.DisposeAsync(); transaction = null; await connection.DisposeAsync(); connection = null;
                var actual = await NativeAsync(database, true, ct);
                SourceOrderOwnerIsoNativeWitness.RequirePreserved(locked, actual, Contract);
                if (actual.Sha256 != candidate.Sha256) { throw Invalid(); }
                observedEffects.Add(database, actual.Sha256); committed.Add(database, actual.Native.Snapshot.Sha256); selected[database] = true;
                RequireFleet(await FleetAsync(selected, ct), committed); await LeaseAsync();
                await ReceiptAsync(database, CurrentAppOwnedCommitClassification.CommittedAndReadback, "committed-readback", ct);
                terminallyRetained.Add(database, committed[database]);
                active = null;
            }
            if (_fault is not null) { await _fault.BeforeFinalFleetAsync(_input, ct); }
            RequireFleet(await FleetAsync(selected, ct), committed); await LeaseAsync(); await RunAsync(true, null, ct);
        }
        catch (Exception primary)
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            if (!commitStarted && transaction is not null)
            { try { await transaction.RollbackAsync(cleanup.Token); rollbackAcknowledged = true; } catch (Exception failure) when (failure is NpgsqlException or OperationCanceledException) { } }
            try
            {
                if (active is not null)
                {
                    var classification = commitStarted || acknowledged ? CurrentAppOwnedCommitClassification.Uncertain : rollbackAcknowledged ?
                        CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.FailedBeforeCommit;
                    await ReceiptAsync(active, classification, "failed-or-uncertain", cleanup.Token);
                }
                await RunAsync(false, primary.GetType().FullName, cleanup.Token);
            }
            catch (Exception retention) { throw new AggregateException(primary, retention); }
            throw;
        }
        finally
        { try { if (transaction is not null) { await transaction.DisposeAsync(); } } finally { if (connection is not null) { await connection.DisposeAsync(); } } }
        async Task LeaseAsync()
        { if (DateTimeOffset.UtcNow >= scope.ExpiresAtUtc) { throw Invalid(); } proof.Require(this); await RequireAsync(ct); }
        async Task ReceiptAsync(string database, CurrentAppOwnedCommitClassification classification, string slot, CancellationToken token)
        {
            var receipt = new SourceOrderOwnerIsoReceipt("source-order-owner-iso-receipt-v1", operation, database, SourceOrderOwnerIsoProtocol.Hash(scope), SourceOrderOwnerIsoProtocol.Hash(auth),
                previous, _input.Intent.NativePreimageSha256[database], afterNative, classification, DateTimeOffset.UtcNow);
            var claim = CurrentAuthLocalSessionArchivePolicy.Sign(SourceOrderOwnerIsoProtocol.ReceiptDomain, receipt, evidence);
            try { _ = await _input.PublishAsync(database + "-" + slot, claim, operation, token); }
            catch (IOException failure) when (_fault is not null && slot is "prepared" or "committed-readback") { _fault.PublicationFailed(database, slot, failure); throw; }
            previous = SourceOrderOwnerIsoProtocol.Hash(claim);
        }
        async Task RunAsync(bool completed, string? failure, CancellationToken token)
        {
            _ = await _input.PublishAsync(completed ? "run-completed" : "run-unfinished", CurrentAuthLocalSessionArchivePolicy.Sign(SourceOrderOwnerIsoProtocol.ReceiptDomain, new
            {
                Kind = "source-order-owner-iso-run-v1",
                OperationId = operation,
                ScopeSha256 = SourceOrderOwnerIsoProtocol.Hash(scope),
                AuthorizationSha256 = SourceOrderOwnerIsoProtocol.Hash(auth),
                PreviousSha256 = previous,
                Completed = completed,
                ProofSha256 = proof.Artifact.Sha256,
                RuntimeOperationCount = pending.Length,
                ProofOperationCount = 2,
                TerminallyReadbackDatabaseSha256 = terminallyRetained,
                ActualReadbackDatabaseSha256 = committed,
                IndependentlyObservedNativeSha256 = observedEffects,
                ActiveDatabase = active,
                CommitStarted = commitStarted,
                CommitAcknowledged = acknowledged,
                FailureType = failure,
                ObservedAtUtc = DateTimeOffset.UtcNow,
            }, evidence), operation, token);
        }
    }
    private async Task RefuseReplayAsync(CancellationToken ct)
    {
        string path = Path.Combine(_input.Authority.Binding.ArtifactRootCanonicalPath, $"{_input.Intent.IntentId:D}-SourceOrderIso-reservation.json");
        if (!File.Exists(path)) { return; }
        try { _ = await _input.PublishAsync("reservation", new { IntentSha256 = SourceOrderOwnerIsoProtocol.Hash(_input.IntentClaim), Replay = true }, _input.Intent.IntentId, ct); }
        catch (IOException failure)
        {
            var pins = _input.Configuration.SigningPins; using var evidence = _input.Signer(_input.Configuration.EvidencePrivateKey, pins.ReceiptKeyId, pins.ReceiptFingerprint);
            _ = await _input.PublishAsync("replay-refused", CurrentAuthLocalSessionArchivePolicy.Sign(SourceOrderOwnerIsoProtocol.ReceiptDomain,
                new { _input.Intent.IntentId, failure.HResult, MutationAttempted = false }, evidence), Guid.NewGuid(), ct); throw;
        }
        throw Invalid();
    }
}
