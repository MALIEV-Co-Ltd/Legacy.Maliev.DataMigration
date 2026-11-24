using System.Data;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal enum OrderSubtotalFaultCase { PreparedPublication = 1, LostCommitAcknowledgement = 2, TerminalPublication = 3 }

internal sealed partial class OrderSubtotalRuntime
{
    internal async Task CharacterizeFaultsAsync(CancellationToken ct)
    {
        await VerifyAsync(ct).ConfigureAwait(false);
        using var source = await OrderSubtotalCloneSource.CreateAsync(this, ct).ConfigureAwait(false);
        var results = new List<OrderSubtotalArtifact>();
        foreach (OrderSubtotalFaultCase fault in Enum.GetValues<OrderSubtotalFaultCase>())
        { results.Add(await RunOwnedFaultAsync(source, fault, ct).ConfigureAwait(false)); }
        await VerifyAsync(ct).ConfigureAwait(false);
        var pins = Inputs.Configuration.SigningPins;
        using var signer = Inputs.Signer(Inputs.Configuration.EvidencePrivateKey, pins.ReceiptKeyId, pins.ReceiptFingerprint);
        _ = await Inputs.PublishAsync("actual-three-owned-faults", CurrentAuthLocalSessionArchivePolicy.Sign("Legacy.Maliev.OrderSubtotal.ThreeOwnedFaults.v1",
            new
            {
                Kind = "order-subtotal-three-actual-owned-faults-v1",
                Results = results,
                ObservedAtUtc = DateTimeOffset.UtcNow,
                PositiveRehearsalAuthority = false,
                PersistentExecutionPerformed = false,
                OperatingSystemChildExitCode = (int?)null
            }, signer), Guid.NewGuid(), ct).ConfigureAwait(false);
    }
    private async Task<OrderSubtotalArtifact> RunOwnedFaultAsync(OrderSubtotalCloneSource source, OrderSubtotalFaultCase fault, CancellationToken ct)
    {
        if (!Enum.IsDefined(fault)) { throw Invalid(); }
        CancellationToken caller = ct;
        string originalIntent = OrderSubtotalRepairProtocol.Hash(Inputs.Intent);
        DateTimeOffset originalIntentExpiry = Inputs.Intent.ExpiresAtUtc;
        string root = Path.Combine(Inputs.Configuration.ProofParent, "order-fault-" + Guid.NewGuid().ToString("N"));
        SecureSnapshotFileCreation.CreateRestrictedDirectory(root);
        using var authority = WindowsLocalRunAuthority.AcquireFresh(root); using var files = new CurrentAppOwnedRepairCustody(authority);
        var pins = Inputs.Configuration.SigningPins;
        using var reviewer = Inputs.Signer(Inputs.Configuration.ReviewPrivateKey, pins.ReviewKeyId, pins.ReviewFingerprint);
        using var authorizer = Inputs.Signer(Inputs.Configuration.AuthorizationPrivateKey, pins.AuthorizationKeyId, pins.AuthorizationFingerprint);
        using var signer = Inputs.Signer(Inputs.Configuration.EvidencePrivateKey, pins.ReceiptKeyId, pins.ReceiptFingerprint);
        OrderCommitProxy? proxy = null; FileStream? denial = null;
        Exception? primary = null, cleanupFailure = null;
        object? retained = null; Guid operation = Guid.NewGuid();
        // Finish fallible local setup before creating the live owned clone.
        var (Clone, Maintenance, LogicalSha256) = await source.CreateCloneAsync(ct).ConfigureAwait(false); var clone = Clone;
        DateTimeOffset originalCloneExpiry = clone.ExpiresAtUtc;
        try
        {
            using var life = CancellationTokenSource.CreateLinkedTokenSource(ct, clone.Token); ct = life.Token;
            var actualTarget = await NativeAsync(false, ct).ConfigureAwait(false);
            var beforeFleet = await CaptureCloneFleetAsync(clone, Inputs.Intent.BeforeDatabaseSha256.Keys, Maintenance, ct).ConfigureAwait(false);
            var nativeFleet = await CaptureOtherCloneNativeAsync(clone, Maintenance, ct).ConfigureAwait(false);
            OrderSubtotalExpressionRepairNativeObservation before;
            await using (var connection = CloneConnection(clone, "Order"))
            {
                await connection.OpenAsync(ct).ConfigureAwait(false); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
                await ReadOnlyAsync(connection, tx, ct).ConfigureAwait(false); await RequireClonePolicyAsync(clone, connection, tx, Maintenance, ct).ConfigureAwait(false);
                before = await OrderSubtotalExpressionRepairNativePreservation.CaptureAsync(connection, tx, Contract, false, ct).ConfigureAwait(false);
                OrderSubtotalExpressionRepairNativePreservation.RequireMatchingCharacterizationPreimage(actualTarget, before, Contract);
                await tx.RollbackAsync(ct).ConfigureAwait(false);
            }
            var scope = new OrderSubtotalOwnedScope("order-subtotal-owned-fault-scope-v1", operation, OrderSubtotalRepairProtocol.Hash(Inputs.IntentClaim),
                Source.FullPlanSha256, Inputs.Intent.SourceDefinitionSha256, Contract.ComputeSha256(), clone.ContainerId, clone.Name,
                await CloneSystemAsync(clone, ct).ConfigureAwait(false), OrderSubtotalRepairProtocol.NativeSha(before), fault.ToString(), DateTimeOffset.UtcNow, clone.ExpiresAtUtc);
            var review = CurrentAuthLocalSessionArchivePolicy.Sign("Legacy.Maliev.OrderSubtotal.OwnedFaultReview.v1", scope, reviewer);
            var auth = CurrentAuthLocalSessionArchivePolicy.Sign("Legacy.Maliev.OrderSubtotal.OwnedFaultAuthorization.v1",
                new OrderSubtotalRepairAuthorization(operation, OrderSubtotalRepairProtocol.Hash(review), DateTimeOffset.UtcNow, clone.ExpiresAtUtc), authorizer);
            await WriteAsync("review", review, ct).ConfigureAwait(false); await WriteAsync("authorization", auth, ct).ConfigureAwait(false);
            await WriteAsync("reservation", new { operation, AuthorizationSha256 = OrderSubtotalRepairProtocol.Hash(auth) }, ct).ConfigureAwait(false);
            string deniedSlot = fault == OrderSubtotalFaultCase.TerminalPublication ? "committed-readback" : "prepared";
            if (fault is OrderSubtotalFaultCase.PreparedPublication or OrderSubtotalFaultCase.TerminalPublication)
            { await files.WriteNewAsync(Slot(deniedSlot), [], ct).ConfigureAwait(false); denial = SecureLocalFile.OpenRead(Slot(deniedSlot)); }
            if (fault == OrderSubtotalFaultCase.LostCommitAcknowledgement)
            { proxy = new(new NpgsqlConnectionStringBuilder(clone.Connection).Port, clone.ExpiresAtUtc); }
            bool commitStarted = false, acknowledged = false, rollbackAcknowledged = false;
            int denied = 0; string previous = new('0', 64); Exception? actualFailure = null;
            OrderSubtotalExpressionRepairNativeObservation? candidate = null;
            NpgsqlConnection? writer = null; NpgsqlTransaction? transaction = null;
            DateTimeOffset began = default;
            int actualExit = await InvokeCandidateAsync().ConfigureAwait(false);
            async Task<int> InvokeCandidateAsync()
            {
                began = DateTimeOffset.UtcNow;
                try
                {
                    var endpoint = new NpgsqlConnectionStringBuilder(clone.Connection) { Database = "Order", Pooling = false, SslMode = SslMode.Disable, GssEncryptionMode = GssEncryptionMode.Disable };
                    if (proxy is not null) { endpoint.Port = proxy.Port; }
                    writer = new(endpoint.ConnectionString); await writer.OpenAsync(ct).ConfigureAwait(false);
                    transaction = await writer.BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);
                    await RequireClonePolicyAsync(clone, writer, transaction, Maintenance, ct).ConfigureAwait(false);
                    string sequenceStorage = await SequenceStorageAsync(writer, transaction, ct).ConfigureAwait(false);
                    await DualTargetNativeProofLogicalCapture.ExecuteAsync(writer, transaction, OrderSubtotalExpressionRepairContract.CandidateSql(), ct).ConfigureAwait(false);
                    candidate = await OrderSubtotalExpressionRepairNativePreservation.CaptureAsync(writer, transaction, Contract, true, ct).ConfigureAwait(false);
                    _ = OrderSubtotalExpressionRepairNativePreservation.CharacterizeOwnedTransition(before, candidate, Contract);
                    if (await SequenceStorageAsync(writer, transaction, ct).ConfigureAwait(false) != sequenceStorage) { throw Invalid(); }
                    await ReceiptAsync(CurrentAppOwnedCommitClassification.Prepared, "prepared", ct).ConfigureAwait(false);
                    await RequireClonePolicyAsync(clone, writer, transaction, Maintenance, ct).ConfigureAwait(false);
                    if (proxy is not null) { await proxy.ArmAsync(writer, transaction, ct).ConfigureAwait(false); }
                    commitStarted = true; await transaction.CommitAsync(ct).ConfigureAwait(false); acknowledged = true;
                    await transaction.DisposeAsync().ConfigureAwait(false); transaction = null; await writer.DisposeAsync().ConfigureAwait(false); writer = null;
                    await using (var independent = CloneConnection(clone, "Order"))
                    {
                        await independent.OpenAsync(ct).ConfigureAwait(false); await using var read = await independent.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
                        await ReadOnlyAsync(independent, read, ct).ConfigureAwait(false); await RequireClonePolicyAsync(clone, independent, read, Maintenance, ct).ConfigureAwait(false);
                        var actual = await OrderSubtotalExpressionRepairNativePreservation.CaptureAsync(independent, read, Contract, true, ct).ConfigureAwait(false);
                        _ = OrderSubtotalExpressionRepairNativePreservation.CharacterizeOwnedTransition(before, actual, Contract);
                        if (OrderSubtotalRepairProtocol.NativeSha(actual) != OrderSubtotalRepairProtocol.NativeSha(candidate)) { throw Invalid(); }
                        await read.RollbackAsync(ct).ConfigureAwait(false);
                    }
                    await ReceiptAsync(CurrentAppOwnedCommitClassification.CommittedAndReadback, "committed-readback", ct).ConfigureAwait(false);
                    return 0;
                }
                catch (Exception failure) when (failure is IOException or NpgsqlException)
                {
                    actualFailure = failure;
                    if (!commitStarted && transaction is not null) { await transaction.RollbackAsync(ct).ConfigureAwait(false); rollbackAcknowledged = true; }
                    await ReceiptAsync(commitStarted || acknowledged ? CurrentAppOwnedCommitClassification.Uncertain : CurrentAppOwnedCommitClassification.RolledBackBeforeCommit,
                        "failed-or-uncertain", ct).ConfigureAwait(false);
                    return 1;
                }
                finally
                { try { if (transaction is not null) { await transaction.DisposeAsync().ConfigureAwait(false); } } finally { if (writer is not null) { await writer.DisposeAsync().ConfigureAwait(false); } } }
            }
            DateTimeOffset ended = DateTimeOffset.UtcNow;
            // Success cannot be converted to an expected error by this guard: it is outside the catch.
            if (actualExit != 1 || actualFailure is null || candidate is null || (fault == OrderSubtotalFaultCase.LostCommitAcknowledgement ? proxy?.DroppedCommits != 1 || !commitStarted || acknowledged : denied != 1) ||
                (fault == OrderSubtotalFaultCase.PreparedPublication ? commitStarted || !rollbackAcknowledged : !commitStarted)) { throw Invalid(); }
            denial?.Dispose(); denial = null;
            if (proxy is not null) { await proxy.DisposeAsync().ConfigureAwait(false); }
            var otherNative = await CaptureOtherCloneNativeAsync(clone, Maintenance, ct).ConfigureAwait(false);
            if (!nativeFleet.OrderBy(x => x.Key, StringComparer.Ordinal).SequenceEqual(otherNative.OrderBy(x => x.Key, StringComparer.Ordinal))) { throw Invalid(); }
            string independentNative;
            await using (var independent = CloneConnection(clone, "Order"))
            {
                await independent.OpenAsync(ct).ConfigureAwait(false); await using var tx = await independent.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
                await ReadOnlyAsync(independent, tx, ct).ConfigureAwait(false); await RequireClonePolicyAsync(clone, independent, tx, Maintenance, ct).ConfigureAwait(false);
                bool applied = fault != OrderSubtotalFaultCase.PreparedPublication;
                var after = await OrderSubtotalExpressionRepairNativePreservation.CaptureAsync(independent, tx, Contract, applied, ct).ConfigureAwait(false);
                if (applied) { _ = OrderSubtotalExpressionRepairNativePreservation.CharacterizeOwnedTransition(before, after, Contract); if (OrderSubtotalRepairProtocol.NativeSha(after) != OrderSubtotalRepairProtocol.NativeSha(candidate)) { throw Invalid(); } }
                else { OrderSubtotalExpressionRepairNativePreservation.RequireOwnedRollback(before, after, candidate); }
                independentNative = OrderSubtotalRepairProtocol.NativeSha(after);
                await tx.RollbackAsync(ct).ConfigureAwait(false);
            }
            var afterFleet = await CaptureCloneFleetAsync(clone, Inputs.Intent.BeforeDatabaseSha256.Keys, Maintenance, ct).ConfigureAwait(false);
            if (beforeFleet.Where(x => x.Database != "Order").Any(x => afterFleet.Single(y => y.Database == x.Database).Sha256 != x.Sha256)) { throw Invalid(); }
            retained = new
            {
                scope,
                MethodBeganAtUtc = began,
                MethodCompletedAtUtc = ended,
                ActualMethodExitCode = actualExit,
                ActualExceptionType = actualFailure.GetType().Name,
                commitStarted,
                acknowledged,
                rollbackAcknowledged,
                PublicationDenials = denied,
                DroppedCommits = proxy?.DroppedCommits ?? 0,
                ProxyCleanup = proxy?.Cleanup,
                PreviousJournalSha256 = previous,
                ActualRowsAndNativeReadbackVerified = true,
                IndependentNativeSha256 = independentNative,
                OtherNativeBeforeSha256 = OrderSubtotalRepairProtocol.Hash(nativeFleet.OrderBy(x => x.Key, StringComparer.Ordinal)),
                OtherNativeAfterSha256 = OrderSubtotalRepairProtocol.Hash(otherNative.OrderBy(x => x.Key, StringComparer.Ordinal)),
                OriginalDumpLogicalSha256 = source.LogicalSha256,
                ActualCloneLogicalSha256 = LogicalSha256,
                OperatingSystemChildExitCode = (int?)null
            };
            var journal = new List<CurrentAuthArchiveClaim>();
            if (fault != OrderSubtotalFaultCase.PreparedPublication) { journal.Add(MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(files.Read(Slot("prepared"), sharedReader: true, maximumBytes: 65536))); }
            journal.Add(MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(files.Read(Slot("failed-or-uncertain"), sharedReader: true, maximumBytes: 65536)));
            OrderSubtotalRepairJournal.RequireOwned(MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(files.Read(Slot("review"), sharedReader: true, maximumBytes: 65536)),
                MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(files.Read(Slot("authorization"), sharedReader: true, maximumBytes: 65536)), journal,
                source.LogicalSha256, OrderSubtotalRepairInputs.ArchivePins(pins), Inputs.Trust);
            async Task ReceiptAsync(CurrentAppOwnedCommitClassification classification, string slot, CancellationToken token)
            {
                var receipt = new OrderSubtotalOwnedFaultReceipt("order-subtotal-owned-fault-receipt-v1", operation, OrderSubtotalRepairProtocol.Hash(scope), OrderSubtotalRepairProtocol.Hash(auth), previous,
                    OrderSubtotalRepairProtocol.NativeSha(before), candidate is null ? null : OrderSubtotalRepairProtocol.NativeSha(candidate), source.LogicalSha256, classification, DateTimeOffset.UtcNow);
                var signed = CurrentAuthLocalSessionArchivePolicy.Sign("Legacy.Maliev.OrderSubtotal.OwnedFaultReceipt.v1", receipt, signer);
                try { await WriteAsync(slot, signed, token).ConfigureAwait(false); }
                catch (IOException) when (denial is not null && slot == deniedSlot) { denied++; throw; }
                previous = OrderSubtotalRepairProtocol.Hash(signed);
            }
        }
        catch (Exception failure) { primary = failure; }
        finally
        {
            denial?.Dispose();
            try { if (proxy is not null) { await proxy.DisposeAsync().ConfigureAwait(false); } } catch (Exception cleanup) { cleanupFailure = cleanup; }
            try { await clone.DisposeAsync().ConfigureAwait(false); } catch (Exception cleanup) { cleanupFailure = cleanupFailure is null ? cleanup : new AggregateException(cleanupFailure, cleanup); }
        }
        if (cleanupFailure is not null) { if (primary is not null) { throw new AggregateException(primary, cleanupFailure); } throw cleanupFailure; }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
        if (retained is null) { throw Invalid(); }
        var final = CurrentAuthLocalSessionArchivePolicy.Sign("Legacy.Maliev.OrderSubtotal.OwnedFaultResult.v1", new
        { Kind = "order-subtotal-actual-owned-fault-result-v1", Retained = retained, CleanupVerified = true, CompletedAtUtc = DateTimeOffset.UtcNow }, signer);
        RequirePublication();
        await WriteAsync("completed-after-cleanup", final, caller).ConfigureAwait(false);
        RequirePublication();
        return await Inputs.PublishAsync("owned-fault-reference", new
        {
            Root = root,
            authority.Binding,
            ResultPath = Slot("completed-after-cleanup"),
            ResultSha256 = OrderSubtotalRepairProtocol.Hash(final)
        }, operation, caller).ConfigureAwait(false);
        void RequirePublication()
        {
            caller.ThrowIfCancellationRequested(); Inputs.Files.Require(); Inputs.Authority.ValidateHeld();
            if (OrderSubtotalRepairProtocol.Hash(Inputs.Intent) != originalIntent || Inputs.Intent.ExpiresAtUtc != originalIntentExpiry ||
                clone.ExpiresAtUtc != originalCloneExpiry || DateTimeOffset.UtcNow >= originalIntentExpiry || DateTimeOffset.UtcNow >= originalCloneExpiry)
            { throw Invalid(); }
        }
        string Slot(string suffix)
        {
            return Path.Combine(root, operation.ToString("D") + "-Order-subtotal-" + suffix + ".json");
        }

        Task WriteAsync<T>(string suffix, T value, CancellationToken token)
        {
            return files.WriteNewAsync(Slot(suffix), JsonSerializer.SerializeToUtf8Bytes(value), token);
        }
    }
    private static async Task<string> CloneSystemAsync(DualTargetNativeProofClone clone, CancellationToken ct)
    { await using var connection = CloneConnection(clone, "postgres"); await connection.OpenAsync(ct).ConfigureAwait(false); return await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, null, "SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex') FROM pg_control_system();", ct).ConfigureAwait(false); }
    private async Task<IReadOnlyDictionary<string, string>> CaptureOtherCloneNativeAsync(DualTargetNativeProofClone clone, CurrentAppOwnedMaintenancePin maintenance, CancellationToken ct)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string database in Inputs.Intent.BeforeDatabaseSha256.Keys.Where(x => x != "Order").Order(StringComparer.Ordinal))
        {
            await using var connection = CloneConnection(clone, database); await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ReadOnlyAsync(connection, tx, ct).ConfigureAwait(false); await RequireClonePolicyAsync(clone, connection, tx, maintenance, ct).ConfigureAwait(false);
            result.Add(database, await DualTargetCapturedDeltaNativeGuard.CapturePreimageAsync(connection, tx, ct).ConfigureAwait(false)); await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        return result;
    }
}
