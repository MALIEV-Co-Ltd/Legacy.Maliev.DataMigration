using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class OrderSubtotalRuntime
{
    private int _executed;
    // The private same-process permit cannot be imported, deserialized or returned to a caller.
    private sealed class ExecutionPermit
    {
        private readonly OrderSubtotalRuntime _runtime;
        internal OrderSubtotalStorageProfile Profile { get; }
        internal OrderSubtotalRepairScope Scope { get; }
        private int _used;
        private ExecutionPermit(OrderSubtotalRuntime runtime, OrderSubtotalStorageProfile profile, OrderSubtotalRepairScope scope)
        { _runtime = runtime; Profile = profile; Scope = scope; }
        internal static ExecutionPermit Mint(OrderSubtotalRuntime runtime, OrderSubtotalStorageProfile profile, OrderSubtotalRepairScope scope)
        {
            return new(runtime, profile, scope);
        }

        internal async Task ConsumeAsync(CancellationToken ct)
        { if (Interlocked.CompareExchange(ref _used, 1, 0) != 0) { throw Invalid(); } await RequireAsync(ct).ConfigureAwait(false); }
        internal async Task RequireAsync(CancellationToken ct)
        { if (DateTimeOffset.UtcNow >= Scope.ExpiresAtUtc || Scope.IntentSha256 != OrderSubtotalRepairProtocol.Hash(_runtime.Inputs.IntentClaim)) { throw Invalid(); } Profile.RequireLive(); await _runtime.RequireAsync(ct).ConfigureAwait(false); }
    }
    internal async Task ExecuteAsync(CancellationToken ct)
    {
        if (_observing || Interlocked.CompareExchange(ref _executed, 1, 0) != 0) { throw Invalid(); }
        using var life = CancellationTokenSource.CreateLinkedTokenSource(ct); life.CancelAfter(TimeSpan.FromMinutes(8)); ct = life.Token;
        string replayPath = Path.Combine(Inputs.Authority.Binding.ArtifactRootCanonicalPath, $"{Inputs.Intent.IntentId:D}-Order-subtotal-reservation.json");
        if (File.Exists(replayPath))
        { _ = await Inputs.PublishAsync("reservation", new { Replay = true }, Inputs.Intent.IntentId, ct).ConfigureAwait(false); throw Invalid(); }
        await VerifyAsync(ct).ConfigureAwait(false); var before = await NativeAsync(false, ct).ConfigureAwait(false);
        Rehearsal proof = await Rehearsal.RunAsync(this, before, ct).ConfigureAwait(false);
        OrderSubtotalStorageProfile profile = await proof.ProfileAsync(before, ct).ConfigureAwait(false);
        await VerifyAsync(ct).ConfigureAwait(false);
        DateTimeOffset issued = DateTimeOffset.UtcNow;
        var scope = new OrderSubtotalRepairScope("current-order-subtotal-target-scope-v1", Guid.NewGuid(), OrderSubtotalRepairProtocol.Hash(Inputs.IntentClaim),
            Source.FullPlanSha256, Contract.ComputeSha256(), proof.Artifact.Sha256, _code.RunnerDigestSha256, Inputs.Intent, issued,
            issued.AddMinutes(5) < Inputs.Intent.ExpiresAtUtc ? issued.AddMinutes(5) : Inputs.Intent.ExpiresAtUtc);
        var pins = Inputs.Configuration.SigningPins;
        using var reviewer = Inputs.Signer(Inputs.Configuration.ReviewPrivateKey, pins.ReviewKeyId, pins.ReviewFingerprint);
        using var authorizer = Inputs.Signer(Inputs.Configuration.AuthorizationPrivateKey, pins.AuthorizationKeyId, pins.AuthorizationFingerprint);
        using var evidence = Inputs.Signer(Inputs.Configuration.EvidencePrivateKey, pins.ReceiptKeyId, pins.ReceiptFingerprint);
        var review = CurrentAuthLocalSessionArchivePolicy.Sign(OrderSubtotalRepairProtocol.ReviewDomain, scope, reviewer);
        var allowed = CurrentAuthLocalSessionArchivePolicy.Sign(OrderSubtotalRepairProtocol.AuthorizationDomain,
            new OrderSubtotalRepairAuthorization(scope.OperationId, OrderSubtotalRepairProtocol.Hash(review), issued, scope.ExpiresAtUtc), authorizer);
        _ = await Inputs.PublishAsync("review", review, scope.OperationId, ct).ConfigureAwait(false);
        _ = await Inputs.PublishAsync("authorization", allowed, scope.OperationId, ct).ConfigureAwait(false);
        string authorization = OrderSubtotalRepairProtocol.Hash(allowed), previous = new('0', 64);
        var permit = ExecutionPermit.Mint(this, profile, scope); await permit.ConsumeAsync(ct).ConfigureAwait(false);
        _ = await Inputs.PublishAsync("reservation", new { scope.OperationId, ScopeSha256 = OrderSubtotalRepairProtocol.Hash(scope), AuthorizationSha256 = authorization }, Inputs.Intent.IntentId, ct).ConfigureAwait(false);
        bool commitStarted = false, committed = false, rolledBack = false; string? afterNative = null, afterSnapshot = null, afterFullNative = null;
        NpgsqlConnection? connection = null; NpgsqlTransaction? tx = null;
        try
        {
            connection = Connect("Order"); await connection.OpenAsync(ct).ConfigureAwait(false);
            tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);
            await RequirePolicyAsync(connection, tx, Inputs.Intent.Maintenance, Inputs.Intent.Target, ct).ConfigureAwait(false);
            await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, tx, "SET LOCAL search_path=pg_catalog,public; LOCK TABLE public.\"Order\" IN ACCESS EXCLUSIVE MODE;", ct).ConfigureAwait(false);
            var locked = await OrderSubtotalExpressionRepairNativePreservation.CaptureAsync(connection, tx, Contract, false, ct).ConfigureAwait(false);
            if (OrderSubtotalRepairProtocol.NativeSha(locked) != OrderSubtotalRepairProtocol.NativeSha(before)) { throw Invalid(); }
            string sequences = await SequenceStorageAsync(connection, tx, ct).ConfigureAwait(false);
            await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, tx, OrderSubtotalExpressionRepairContract.CandidateSql(), ct).ConfigureAwait(false);
            var after = await OrderSubtotalExpressionRepairNativePreservation.CaptureAsync(connection, tx, Contract, true, ct).ConfigureAwait(false);
            OrderSubtotalExpressionRepairNativePreservation.RequireOperationalPreserved(before, after, Contract, permit.Profile);
            if (await SequenceStorageAsync(connection, tx, ct).ConfigureAwait(false) != sequences) { throw Invalid(); }
            await using (var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false))
            { var shape = Contract.AfterPhysical(); if (await inspector.InspectSchemaAsync(shape, ct).ConfigureAwait(false) != shape.TargetSchemaSha256) { throw Invalid(); } }
            afterNative = OrderSubtotalRepairProtocol.NativeSha(after); afterSnapshot = after.Native.Snapshot.Sha256;
            afterFullNative = await DualTargetCapturedDeltaNativeGuard.CapturePreimageAsync(connection, tx, ct).ConfigureAwait(false);
            await RequireOtherNativeBeforeCommitAsync(connection, tx, ct).ConfigureAwait(false); await permit.RequireAsync(ct).ConfigureAwait(false);
            await ReceiptAsync(CurrentAppOwnedCommitClassification.Prepared, "prepared", ct).ConfigureAwait(false);
            await permit.RequireAsync(ct).ConfigureAwait(false);
            await RequirePolicyAsync(connection, tx, Inputs.Intent.Maintenance, Inputs.Intent.Target, ct).ConfigureAwait(false);
            commitStarted = true; await tx.CommitAsync(ct).ConfigureAwait(false); committed = true;
            await tx.DisposeAsync().ConfigureAwait(false); tx = null; await connection.DisposeAsync().ConfigureAwait(false); connection = null;
            var independent = await NativeAsync(true, ct).ConfigureAwait(false);
            OrderSubtotalExpressionRepairNativePreservation.RequireOperationalPreserved(before, independent, Contract, permit.Profile);
            if (OrderSubtotalRepairProtocol.NativeSha(independent) != afterNative) { throw Invalid(); }
            RequireFleet(await FleetAsync(true, ct).ConfigureAwait(false), afterSnapshot);
            RequireNativeFleetAfter(await NativeFleetAsync(ct).ConfigureAwait(false), afterFullNative);
            await permit.RequireAsync(ct).ConfigureAwait(false); await ReceiptAsync(CurrentAppOwnedCommitClassification.CommittedAndReadback, "committed-readback", ct).ConfigureAwait(false);
            RequireJournal();
        }
        catch (Exception primary)
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            if (!commitStarted && tx is not null)
            { try { await tx.RollbackAsync(cleanup.Token).ConfigureAwait(false); rolledBack = true; } catch (Exception rollback) when (rollback is NpgsqlException or OperationCanceledException) { primary.Data["OrderRollback"] = rollback; } }
            try
            {
                string path = Path.Combine(Inputs.Authority.Binding.ArtifactRootCanonicalPath, $"{scope.OperationId:D}-Order-subtotal-committed-readback.json");
                if (File.Exists(path))
                {
                    var retained = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(Inputs.Files.Read(path, sharedReader: true, maximumBytes: 65536));
                    var terminal = CurrentAuthLocalSessionArchivePolicy.Verify<OrderSubtotalRepairReceipt>(retained, OrderSubtotalRepairProtocol.ReceiptDomain,
                        pins.ReceiptKeyId, pins.ReceiptFingerprint, Inputs.Trust);
                    string hash = OrderSubtotalRepairProtocol.Hash(retained);
                    if (terminal.OperationId != scope.OperationId || terminal.ScopeSha256 != OrderSubtotalRepairProtocol.Hash(scope) || terminal.AuthorizationSha256 != authorization ||
                        terminal.BeforeNativeSha256 != OrderSubtotalRepairProtocol.NativeSha(before) || terminal.AfterNativeSha256 != afterNative ||
                        terminal.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback || (hash != previous && terminal.PreviousSha256 != previous)) { throw Invalid(); }
                    previous = hash;
                }
            }
            catch (Exception readback) { primary.Data["OrderTerminalRetentionReadback"] = readback; }
            try
            {
                await ReceiptAsync(commitStarted || committed ? CurrentAppOwnedCommitClassification.Uncertain : rolledBack ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.FailedBeforeCommit,
                "failed-or-uncertain", cleanup.Token).ConfigureAwait(false);
            }
            catch (Exception retention) { primary.Data["OrderReceiptRetention"] = retention; }
            throw;
        }
        finally { try { if (tx is not null) { await tx.DisposeAsync().ConfigureAwait(false); } } finally { if (connection is not null) { await connection.DisposeAsync().ConfigureAwait(false); } } }
        async Task ReceiptAsync(CurrentAppOwnedCommitClassification classification, string slot, CancellationToken token)
        {
            var receipt = new OrderSubtotalRepairReceipt("current-order-subtotal-receipt-v1", scope.OperationId, OrderSubtotalRepairProtocol.Hash(scope), authorization, previous,
                OrderSubtotalRepairProtocol.NativeSha(before), afterNative, proof.Artifact.Sha256, classification, DateTimeOffset.UtcNow);
            var claim = CurrentAuthLocalSessionArchivePolicy.Sign(OrderSubtotalRepairProtocol.ReceiptDomain, receipt, evidence);
            _ = await Inputs.PublishAsync(slot, claim, scope.OperationId, token).ConfigureAwait(false); previous = OrderSubtotalRepairProtocol.Hash(claim);
        }
        void RequireJournal()
        {
            CurrentAuthArchiveClaim Read(string suffix)
            {
                return MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(Inputs.Files.Read(
                Path.Combine(Inputs.Authority.Binding.ArtifactRootCanonicalPath, $"{scope.OperationId:D}-Order-subtotal-{suffix}.json"), sharedReader: true, maximumBytes: 65536));
            }

            OrderSubtotalRepairJournal.RequirePersistent(Read("review"), Read("authorization"), [Read("prepared"), Read("committed-readback")],
                OrderSubtotalRepairInputs.ArchivePins(pins), Inputs.Trust);
        }
    }
}
