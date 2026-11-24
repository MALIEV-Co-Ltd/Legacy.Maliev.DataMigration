using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class OrderSubtotalRuntime
{
    private sealed class Rehearsal
    {
        private readonly OrderSubtotalRuntime _runtime;
        private readonly OrderSubtotalCharacterization _facts;
        internal OrderSubtotalArtifact Artifact { get; }
        private Rehearsal(OrderSubtotalRuntime runtime, OrderSubtotalCharacterization facts, OrderSubtotalArtifact artifact)
        { _runtime = runtime; _facts = facts; Artifact = artifact; }

        internal async Task<OrderSubtotalCharacterization> GetCharacterizationAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            await _runtime.VerifyAsync(ct).ConfigureAwait(false);
            OrderSubtotalRepairProtocol.RequireCharacterization(_facts, _runtime.Contract.ComputeSha256(),
                _runtime.Inputs.Intent.NativePreimageSha256, _runtime.Source.FullPlanSha256,
                _runtime._code.RunnerDigestSha256, DateTimeOffset.UtcNow);
            ct.ThrowIfCancellationRequested();
            return OrderSubtotalRepairProtocol.Copy(_facts);
        }

        internal Task<OrderSubtotalStorageProfile> ProfileAsync(OrderSubtotalExpressionRepairNativeObservation target, CancellationToken ct)
        {
            return OrderSubtotalStorageProfile.AuthenticateAsync(this, _runtime.Contract.ComputeSha256(), OrderSubtotalRepairProtocol.NativeSha(target),
                _runtime.Source.FullPlanSha256, _runtime._code.RunnerDigestSha256, ct);
        }

        internal static async Task<Rehearsal> RunAsync(OrderSubtotalRuntime runtime, OrderSubtotalExpressionRepairNativeObservation target, CancellationToken ct)
        {
            await runtime.VerifyAsync(ct).ConfigureAwait(false);
            using var original = await OrderSubtotalCloneSource.CreateAsync(runtime, ct).ConfigureAwait(false);
            var rollback = await RunCloneAsync(runtime, original, target, rollback: true, ct).ConfigureAwait(false);
            var committed = await RunCloneAsync(runtime, original, target, rollback: false, ct).ConfigureAwait(false);
            DateTimeOffset completed = DateTimeOffset.UtcNow;
            var facts = new OrderSubtotalCharacterization(Guid.NewGuid(), runtime.Contract.ComputeSha256(), OrderSubtotalRepairProtocol.NativeSha(target),
                original.LogicalSha256, committed.LogicalSha256, runtime.Source.FullPlanSha256, runtime._code.RunnerDigestSha256,
                committed.Id, committed.Volume, rollback.Id, rollback.Before, rollback.After, target.ProviderVersion,
                IsAlphabetical(target, runtime.Contract), committed.Storage, committed.Before, committed.After, true, true, true, completed,
                runtime.Inputs.Intent.ExpiresAtUtc < completed.AddMinutes(5) ? runtime.Inputs.Intent.ExpiresAtUtc : completed.AddMinutes(5));
            OrderSubtotalRepairProtocol.RequireCharacterization(facts, runtime.Contract.ComputeSha256(), OrderSubtotalRepairProtocol.NativeSha(target),
                runtime.Source.FullPlanSha256, runtime._code.RunnerDigestSha256, DateTimeOffset.UtcNow);
            await runtime.VerifyAsync(ct).ConfigureAwait(false);
            var pins = runtime.Inputs.Configuration.SigningPins;
            using var signer = runtime.Inputs.Signer(runtime.Inputs.Configuration.EvidencePrivateKey, pins.ReceiptKeyId, pins.ReceiptFingerprint);
            var artifact = await runtime.Inputs.PublishAsync("actual-target-characterization",
                CurrentAuthLocalSessionArchivePolicy.Sign(OrderSubtotalRepairProtocol.ProofDomain, facts, signer), facts.OperationId, ct).ConfigureAwait(false);
            return new(runtime, facts, artifact);
        }
        private sealed record Run(string Id, string Volume, string Before, string After, IReadOnlyDictionary<string, OrderSubtotalStorageTransition> Storage, string LogicalSha256);
        private static async Task<Run> RunCloneAsync(OrderSubtotalRuntime runtime, OrderSubtotalCloneSource original,
            OrderSubtotalExpressionRepairNativeObservation target, bool rollback, CancellationToken ct)
        {
            var (Clone, Maintenance, LogicalSha256) = await original.CreateCloneAsync(ct).ConfigureAwait(false); var clone = Clone;
            Run? result = null; Exception? primary = null;
            try
            {
                using var life = CancellationTokenSource.CreateLinkedTokenSource(ct, clone.Token); ct = life.Token;
                var fleetBefore = await runtime.CaptureCloneFleetAsync(clone, runtime.Inputs.Intent.BeforeDatabaseSha256.Keys, Maintenance, ct).ConfigureAwait(false);
                var otherNativeBefore = await runtime.CaptureOtherCloneNativeAsync(clone, Maintenance, ct).ConfigureAwait(false);
                await using var connection = CloneConnection(clone, "Order"); await connection.OpenAsync(ct).ConfigureAwait(false);
                OrderSubtotalExpressionRepairNativeObservation before, candidate;
                IReadOnlyDictionary<string, OrderSubtotalStorageTransition> storage;
                await using (var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false))
                {
                    await RequireClonePolicyAsync(clone, connection, tx, Maintenance, ct).ConfigureAwait(false);
                    before = await OrderSubtotalExpressionRepairNativePreservation.CaptureAsync(connection, tx, runtime.Contract, false, ct).ConfigureAwait(false);
                    OrderSubtotalExpressionRepairNativePreservation.RequireMatchingCharacterizationPreimage(target, before, runtime.Contract);
                    string sequences = await SequenceStorageAsync(connection, tx, ct).ConfigureAwait(false);
                    await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, tx, OrderSubtotalExpressionRepairContract.CandidateSql(), ct).ConfigureAwait(false);
                    candidate = await OrderSubtotalExpressionRepairNativePreservation.CaptureAsync(connection, tx, runtime.Contract, true, ct).ConfigureAwait(false);
                    storage = OrderSubtotalExpressionRepairNativePreservation.CharacterizeOwnedTransition(before, candidate, runtime.Contract);
                    if (await SequenceStorageAsync(connection, tx, ct).ConfigureAwait(false) != sequences) { throw Invalid(); }
                    await RequireClonePolicyAsync(clone, connection, tx, Maintenance, ct).ConfigureAwait(false);
                    if (rollback) { await tx.RollbackAsync(ct).ConfigureAwait(false); } else { await tx.CommitAsync(ct).ConfigureAwait(false); }
                }
                OrderSubtotalExpressionRepairNativeObservation actual;
                await using (var independent = CloneConnection(clone, "Order"))
                {
                    await independent.OpenAsync(ct).ConfigureAwait(false); await using var tx = await independent.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
                    await ReadOnlyAsync(independent, tx, ct).ConfigureAwait(false);
                    // Close the original reader before the exact zero-other-clients policy check.
                    await connection.DisposeAsync().ConfigureAwait(false);
                    await RequireClonePolicyAsync(clone, independent, tx, Maintenance, ct).ConfigureAwait(false);
                    actual = await OrderSubtotalExpressionRepairNativePreservation.CaptureAsync(independent, tx, runtime.Contract, !rollback, ct).ConfigureAwait(false);
                    if (rollback) { OrderSubtotalExpressionRepairNativePreservation.RequireOwnedRollback(before, actual, candidate); }
                    else
                    {
                        _ = OrderSubtotalExpressionRepairNativePreservation.CharacterizeOwnedTransition(before, actual, runtime.Contract);
                        if (OrderSubtotalRepairProtocol.NativeSha(actual) != OrderSubtotalRepairProtocol.NativeSha(candidate)) { throw Invalid(); }
                    }
                    await tx.RollbackAsync(ct).ConfigureAwait(false);
                }
                var fleetAfter = await runtime.CaptureCloneFleetAsync(clone, runtime.Inputs.Intent.BeforeDatabaseSha256.Keys, Maintenance, ct).ConfigureAwait(false);
                var otherNativeAfter = await runtime.CaptureOtherCloneNativeAsync(clone, Maintenance, ct).ConfigureAwait(false);
                if (!otherNativeBefore.OrderBy(x => x.Key, StringComparer.Ordinal).SequenceEqual(otherNativeAfter.OrderBy(x => x.Key, StringComparer.Ordinal))) { throw Invalid(); }
                if (fleetBefore.Count != fleetAfter.Count || fleetBefore.Where(x => rollback || x.Database != "Order").Any(x =>
                    fleetAfter.Single(y => y.Database == x.Database).Sha256 != x.Sha256)) { throw Invalid(); }
                result = new(clone.ContainerId, clone.Name, OrderSubtotalRepairProtocol.NativeSha(before), OrderSubtotalRepairProtocol.NativeSha(actual), storage, LogicalSha256);
            }
            catch (Exception failure) { primary = failure; }
            try { await clone.DisposeAsync().ConfigureAwait(false); }
            catch (Exception cleanup) { if (primary is null) { throw; } primary.Data["OrderRehearsalCleanup"] = cleanup; }
            if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
            return result ?? throw Invalid();
        }
        private static bool IsAlphabetical(OrderSubtotalExpressionRepairNativeObservation observed, OrderSubtotalExpressionRepairContract contract)
        {
            string ns = observed.Native.Read("pg_namespace").Single(x => x["nspname"]!.ToString() == "public")["oid"]!.ToString();
            string oid = observed.Native.Read("pg_class").Single(x => x["relnamespace"]!.ToString() == ns && x["relname"]!.ToString() == "Order")["oid"]!.ToString();
            string[] order = [.. observed.Native.Read("pg_attribute").Where(x => x["attrelid"]!.ToString() == oid && int.Parse(x["attnum"]!.ToString(), System.Globalization.CultureInfo.InvariantCulture) > 0)
                .OrderBy(x => int.Parse(x["attnum"]!.ToString(), System.Globalization.CultureInfo.InvariantCulture)).Select(x => x["attname"]!.ToString())];
            return order.SequenceEqual(contract.BeforePhysical().Tables.Single(x => x.TargetTable == "Order").OrderedColumns.Order(StringComparer.Ordinal), StringComparer.Ordinal);
        }
    }
    private static NpgsqlConnection CloneConnection(DualTargetNativeProofClone clone, string database)
    {
        return new(new NpgsqlConnectionStringBuilder(clone.Connection) { Database = database }.ConnectionString);
    }

    private static async Task RequireClonePolicyAsync(DualTargetNativeProofClone clone, NpgsqlConnection connection, NpgsqlTransaction tx, CurrentAppOwnedMaintenancePin maintenance, CancellationToken ct)
    {
        string system = await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, tx, "SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex') FROM pg_control_system();", ct).ConfigureAwait(false);
        await RequirePolicyAsync(connection, tx, maintenance, new(DeltaTargetAuthorityKind.LocalAspire,
            "aspire://legacy-postgres-main-local/disposable-" + clone.ContainerId[..12], system), ct).ConfigureAwait(false);
    }
    private async Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> CaptureCloneFleetAsync(DualTargetNativeProofClone clone,
        IEnumerable<string> names, CurrentAppOwnedMaintenancePin maintenance, CancellationToken ct)
    {
        await clone.RequireOwnedAsync(ct).ConfigureAwait(false); var result = new List<CurrentAppOwnedDatabaseSnapshot>();
        var cohort = _pool.BeginCohort(names.Order(StringComparer.Ordinal));
        foreach (string database in names.Order(StringComparer.Ordinal))
        {
            await using var connection = CloneConnection(clone, database); await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ReadOnlyAsync(connection, tx, ct).ConfigureAwait(false); await RequireClonePolicyAsync(clone, connection, tx, maintenance, ct).ConfigureAwait(false);
            result.Add(cohort.Intern(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false))); await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        cohort.Complete(); return result;
    }
}
