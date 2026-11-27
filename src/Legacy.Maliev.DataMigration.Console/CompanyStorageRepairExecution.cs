using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CompanyStorageRuntime
{
    private CompanyStorageNativeWitness? _candidateReadback;
    internal async Task VerifyAsync(CancellationToken ct)
    {
        await RequireAsync(ct); var fleet = await FleetAsync(_inputs.Intent.SchemaAlreadyCorrect, ct);
        RequireFleet(fleet, null); var native = await ReadNativeAsync(_inputs.Intent.SchemaAlreadyCorrect, ct);
        if (native.Sha256 != _inputs.Intent.NativePreimageSha256 || native.OwnerName != _inputs.Intent.CompanyOwnerName) { throw Invalid(); }
    }

    internal async Task ExecuteAsync(CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromMinutes(8)); ct = deadline.Token;
        await RefuseReservedIntentAsync(ct);
        await VerifyAsync(ct);
        var before = await ReadNativeAsync(_inputs.Intent.SchemaAlreadyCorrect, ct);
        var proof = await Rehearsal.RunAsync(this, ct); proof.Require(this, before);
        await VerifyAsync(ct);
        var pins = _inputs.Configuration.SigningPins;
        using var reviewer = _inputs.Signer(_inputs.Configuration.ReviewPrivateKey, pins.ReviewKeyId, pins.ReviewFingerprint);
        using var authorizer = _inputs.Signer(_inputs.Configuration.AuthorizationPrivateKey, pins.AuthorizationKeyId, pins.AuthorizationFingerprint);
        using var evidence = _inputs.Signer(_inputs.Configuration.EvidencePrivateKey, pins.ReceiptKeyId, pins.ReceiptFingerprint);
        DateTimeOffset now = DateTimeOffset.UtcNow; Guid operation = Guid.NewGuid();
        if (_fault is not null) { await _fault.BindAsync(_inputs, operation, ct); }
        var scope = new CompanyStorageRepairScope(_owned is null ? CompanyStorageRepairProtocol.ScopeKind : CompanyStorageRepairProtocol.OwnedScopeKind, operation, CompanyStorageRepairProtocol.Hash(_inputs.IntentClaim),
            Source.FullPlanSha256, _inputs.Intent.SourceDefinitionSha256, Contract.ComputeSha256(), proof.Artifact.Sha256, _code.RunnerDigestSha256, _inputs.Intent, now,
            now.AddMinutes(2) < _inputs.Intent.ExpiresAtUtc ? now.AddMinutes(2) : _inputs.Intent.ExpiresAtUtc);
        var review = CurrentAuthLocalSessionArchivePolicy.Sign(CompanyStorageRepairProtocol.ReviewDomain, scope, reviewer);
        var authorization = CurrentAuthLocalSessionArchivePolicy.Sign(CompanyStorageRepairProtocol.AuthorizationDomain,
            new CompanyStorageRepairAuthorization(operation, CompanyStorageRepairProtocol.Hash(review), now, scope.ExpiresAtUtc), authorizer);
        _ = await _inputs.PublishAsync("scope", scope, operation, ct); _ = await _inputs.PublishAsync("review", review, operation, ct);
        _ = await _inputs.PublishAsync("authorization", authorization, operation, ct); _ = await _inputs.PublishAsync("source-capture", Source, operation, ct);
        string auth = CompanyStorageRepairProtocol.Hash(authorization), previous = new('0', 64);
        // The reviewed intent, not this newly generated invocation, is the durable replay identity.
        _ = await _inputs.PublishAsync("reservation", new { OperationId = operation, Scope = CompanyStorageRepairProtocol.Hash(scope), Authorization = auth }, _inputs.Intent.IntentId, ct);
        bool commitStarted = false, commitAcknowledged = false, rollbackAcknowledged = false, independentlyObservedCommit = false;
        string? afterNative = null, afterSnapshot = null; NpgsqlConnection? connection = null; NpgsqlTransaction? transaction = null;
        try
        {
            await RequireLeaseAsync();
            if (_inputs.Intent.SchemaAlreadyCorrect)
            {
                var current = await ReadNativeAsync(true, ct);
                if (current.Sha256 != before.Sha256) { throw Invalid(); }
                RequireFleet(await FleetAsync(true, ct), null);
                await RunAsync(true, "SchemaAlreadyCorrectNoMutation", null, ct); return;
            }
            connection = Connect("Customer"); await connection.OpenAsync(ct);
            transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct);
            var candidate = await CandidateAsync(connection, transaction, Contract, before, _inputs.Intent.Maintenance, _inputs.Intent.Target, _inputs.Intent.CompanyOwnerName, ct);
            _candidateReadback = candidate;
            afterNative = candidate.Sha256; afterSnapshot = candidate.Observation.Native.Snapshot.Sha256;
            await RequireLeaseAsync(); await RequirePolicyAsync(connection, transaction, _inputs.Intent.Maintenance, _inputs.Intent.Target, ct);
            await ReceiptAsync(CurrentAppOwnedCommitClassification.Prepared, "prepared", ct);
            _fault?.Prepared(operation);
            await RequireLeaseAsync(); commitStarted = true; await transaction.CommitAsync(ct); commitAcknowledged = true;
            await transaction.DisposeAsync(); transaction = null; await connection.DisposeAsync(); connection = null;
            var observed = await ReadNativeAsync(true, ct);
            CompanyStorageNativeWitness.RequirePreserved(before, observed, Contract);
            if (observed.Sha256 != afterNative) { throw Invalid(); }
            independentlyObservedCommit = true;
            RequireFleet(await FleetAsync(true, ct), afterSnapshot);
            await RequireLeaseAsync(); await ReceiptAsync(CurrentAppOwnedCommitClassification.CommittedAndReadback, "committed-readback", ct);
            RequireFleet(await FleetAsync(true, ct), afterSnapshot); await RequireLeaseAsync();
            await RunAsync(true, "CommittedAndReadback", null, ct);
        }
        catch (Exception primary)
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            if (!commitStarted && transaction is not null)
            { try { await transaction.RollbackAsync(cleanup.Token); rollbackAcknowledged = true; } catch (Exception failure) when (failure is NpgsqlException or OperationCanceledException) { } }
            var classification = commitStarted || commitAcknowledged ? CurrentAppOwnedCommitClassification.Uncertain :
                rollbackAcknowledged ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.FailedBeforeCommit;
            try { await ReceiptAsync(classification, "failed-or-uncertain", cleanup.Token); await RunAsync(false, "Unfinished", primary.GetType().Name, cleanup.Token); }
            catch (Exception retention) { throw new AggregateException(primary, retention); }
            throw;
        }
        finally
        { try { if (transaction is not null) { await transaction.DisposeAsync(); } } finally { if (connection is not null) { await connection.DisposeAsync(); } } }
        async Task RequireLeaseAsync()
        {
            if (DateTimeOffset.UtcNow >= scope.ExpiresAtUtc) { throw Invalid(); }
            proof.Require(this, before); await RequireAsync(ct);
        }
        async Task ReceiptAsync(CurrentAppOwnedCommitClassification classification, string slot, CancellationToken token)
        {
            var receipt = new CompanyStorageRepairReceipt("current-company-storage-receipt-v1", operation, CompanyStorageRepairProtocol.Hash(scope), auth,
                previous, before.Sha256, afterNative, proof.Artifact.Sha256, classification, DateTimeOffset.UtcNow);
            var signed = CurrentAuthLocalSessionArchivePolicy.Sign(CompanyStorageRepairProtocol.ReceiptDomain, receipt, evidence);
            try { _ = await _inputs.PublishAsync(slot, signed, operation, token); }
            catch (IOException failure) when (_fault is not null && slot is "prepared" or "committed-readback")
            { _fault.PublicationFailed(slot, operation, failure); throw; }
            previous = CompanyStorageRepairProtocol.Hash(signed);
        }
        async Task RunAsync(bool completed, string outcome, string? failure, CancellationToken token)
        {
            _ = await _inputs.PublishAsync(completed ? "run-completed" : "run-unfinished", CurrentAuthLocalSessionArchivePolicy.Sign(CompanyStorageRepairProtocol.ReceiptDomain, new
            {
                Kind = "current-company-storage-run-v1",
                OperationId = operation,
                ScopeSha256 = CompanyStorageRepairProtocol.Hash(scope),
                AuthorizationSha256 = auth,
                PreviousSha256 = previous,
                ActualDisposableProofSha256 = proof.Artifact.Sha256,
                Completed = completed,
                Outcome = outcome,
                RuntimeOperationCount = _inputs.Intent.SchemaAlreadyCorrect ? 0 : 1,
                ProofOperationCount = 1,
                CommitStarted = commitStarted,
                CommitAcknowledged = commitAcknowledged,
                IndependentlyObservedCommit = independentlyObservedCommit,
                ActualObservedAfterNativeSha256 = independentlyObservedCommit ? afterNative : null,
                FailureType = failure,
                ObservedAtUtc = DateTimeOffset.UtcNow,
            }, evidence), operation, token);
        }
    }
    private async Task RefuseReservedIntentAsync(CancellationToken ct)
    {
        string path = Path.Combine(_inputs.Authority.Binding.ArtifactRootCanonicalPath, $"{_inputs.Intent.IntentId:D}-Company-storage-reservation.json");
        if (!File.Exists(path)) { return; }
        // A new runtime and held input set must hit actual CreateNew, not an in-memory stopped flag.
        string retained = CompanyStorageRepairProtocol.Hash(_inputs.Files.Read(path, sharedReader: true, maximumBytes: 65536));
        try { _ = await _inputs.PublishAsync("reservation", new { IntentSha256 = CompanyStorageRepairProtocol.Hash(_inputs.IntentClaim), Replay = true }, _inputs.Intent.IntentId, ct); }
        catch (IOException failure)
        {
            var pins = _inputs.Configuration.SigningPins;
            using var signer = _inputs.Signer(_inputs.Configuration.EvidencePrivateKey, pins.ReceiptKeyId, pins.ReceiptFingerprint);
            _ = await _inputs.PublishAsync("replay-refused", CurrentAuthLocalSessionArchivePolicy.Sign(CompanyStorageRepairProtocol.ReceiptDomain,
                new
                {
                    Kind = "company-storage-durable-replay-refusal-v1",
                    _inputs.Intent.IntentId,
                    RetainedReservationSha256 = retained,
                    ActualHResult = failure.HResult,
                    MutationAttempted = false,
                    ObservedAtUtc = DateTimeOffset.UtcNow
                }, signer), Guid.NewGuid(), ct);
            throw;
        }
        throw Invalid();
    }
    private void RequireFleet(IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> fleet, string? changedCustomer)
    {
        if (fleet.Count != _inputs.Intent.BeforeDatabaseSha256.Count || fleet.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != fleet.Count ||
            fleet.Any(x => !_inputs.Intent.BeforeDatabaseSha256.TryGetValue(x.Database, out string? expected) || x.Sha256 != (x.Database == "Customer" && changedCustomer is not null ? changedCustomer : expected)))
        { throw Invalid(); }
    }
    private async Task<CompanyStorageNativeWitness> ReadNativeAsync(bool after, CancellationToken ct)
    {
        await using var connection = Connect("Customer"); await connection.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await ReadOnlyAsync(connection, transaction, ct); await RequirePolicyAsync(connection, transaction, _inputs.Intent.Maintenance, _inputs.Intent.Target, ct);
        var result = await CompanyStorageNativeWitness.CaptureAsync(connection, transaction, Contract, after, ct);
        await transaction.RollbackAsync(ct); return result;
    }
}

public static partial class MigrationConsole
{
    private static async Task<int> RunCompanyStorageRepairAsync(string command, string configuration, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            CurrentAuthRepairCapacity.Require(admission: true); _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
            if (command == "observe-current-company-storage")
            {
                var ready = await CompanyStorageRepairInputs.ObserveAndSignAsync(configuration, ct);
                await output.WriteLineAsync(ready.Path); return 0;
            }
            using var inputs = CompanyStorageRepairInputs.Open(configuration);
            using var runtime = await CompanyStorageRuntime.OpenAsync(inputs, ct);
            if (command == "verify-current-company-storage") { await runtime.VerifyAsync(ct); }
            else if (command == "apply-current-company-storage") { await runtime.ExecuteAsync(ct); }
            else { throw CompanyStorageRepairProtocol.Invalid(); }
            await output.WriteLineAsync("company_storage_boundary_completed_no_data_parity_claim"); return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or
            System.Data.Common.DbException or System.Text.Json.JsonException or ArgumentException or InvalidOperationException or OperationCanceledException or AggregateException or System.Reflection.TargetInvocationException or System.Security.Cryptography.CryptographicException)
        { await error.WriteLineAsync("company_storage_boundary_failed_or_uncertain"); return 1; }
    }
}
