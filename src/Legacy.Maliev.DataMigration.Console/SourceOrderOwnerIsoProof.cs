using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class SourceOrderOwnerIsoRuntime
{
    private sealed record ProofFacts(Guid OperationId, string SourceFullSha256, string SourceDefinitionSha256, string ContractSha256,
        string CandidateSha256, string RunnerSha256, string SystemIdentifierSha256, string ContainerId, string Volume,
        IReadOnlyDictionary<string, string> BeforeNativeSha256, IReadOnlyDictionary<string, string> AfterNativeSha256,
        string BeforeFleetSha256, string AfterFleetSha256, string NativeEvidenceSha256, DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc,
        bool RollbackReadback, bool IndependentReadback, bool CleanupVerified);

    // No public constructor, deserializer, callback, caller clock, or token loader.
    private sealed class Rehearsal
    {
        private readonly ProofFacts _facts;
        internal CompanyStorageArtifact Artifact { get; }
        private Rehearsal(ProofFacts facts, CompanyStorageArtifact artifact) { _facts = facts; Artifact = artifact; }
        internal static async Task<Rehearsal> RunAsync(SourceOrderOwnerIsoRuntime runtime, CancellationToken ct)
        {
            await runtime.RequireAsync(ct); SourceOrderOwnerIsoOwnedSession? session = null;
            ProofFacts? facts = null; Exception? primary = null, cleanup = null;
            try
            {
                session = await SourceOrderOwnerIsoOwnedSession.CreateAsync(runtime._input, runtime.Source, runtime._input.Configuration.ProofParent, ct);
                var lease = session.Lease; DateTimeOffset began = DateTimeOffset.UtcNow;
                if (lease.Target.SystemIdentifierSha256 == runtime._input.Intent.Target.SystemIdentifierSha256) { throw Invalid(); }
                var fleetBefore = await lease.CaptureFleetAsync(ct);
                var before = new Dictionary<string, SourceOrderOwnerIsoNativeWitness>(StringComparer.Ordinal);
                var after = new Dictionary<string, SourceOrderOwnerIsoNativeWitness>(StringComparer.Ordinal);
                foreach (string database in SourceOrderOwnerIsoProtocol.Databases)
                {
                    var original = await CaptureOwnedAsync(session, runtime.Contract, database, false, ct);
                    await using (var connection = OwnedConnection(session, database))
                    {
                        await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct);
                        _ = await ApplyOwnedCandidateAsync(session, runtime.Contract, original, connection, tx, ct);
                        await tx.RollbackAsync(ct);
                    }
                    var restored = await CaptureOwnedAsync(session, runtime.Contract, database, false, ct);
                    RequireExactRollback(original, restored);
                    before.Add(database, restored);
                    SourceOrderOwnerIsoNativeWitness candidate;
                    await using (var connection = OwnedConnection(session, database))
                    {
                        await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct);
                        candidate = await ApplyOwnedCandidateAsync(session, runtime.Contract, restored, connection, tx, ct);
                        await tx.CommitAsync(ct);
                    }
                    var readback = await CaptureOwnedAsync(session, runtime.Contract, database, true, ct);
                    SourceOrderOwnerIsoNativeWitness.RequirePreserved(restored, readback, runtime.Contract);
                    if (readback.Sha256 != candidate.Sha256) { throw Invalid(); }
                    after.Add(database, readback);
                }
                var fleetAfter = await lease.CaptureFleetAsync(ct);
                RequireOwnedFleet(fleetBefore.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal), after, fleetAfter);
                // Snapshot catalog facts are hashes, not raw pg_authid/password material or row values.
                var nativeEvidence = await runtime._input.PublishAsync("disposable-native-observations", new
                {
                    Kind = "source-order-owner-iso-owned-native-observations-v1",
                    lease.OperationId,
                    Before = before.ToDictionary(x => x.Key, x => SafeEvidence(x.Value), StringComparer.Ordinal),
                    After = after.ToDictionary(x => x.Key, x => SafeEvidence(x.Value), StringComparer.Ordinal),
                    FleetBefore = fleetBefore,
                    FleetAfter = fleetAfter,
                }, lease.OperationId, ct);
                facts = new(lease.OperationId, runtime.Source.FullPlanSha256, runtime._input.Intent.SourceDefinitionSha256,
                    runtime.Contract.ComputeSha256(), SourceOrderOwnerIsoProtocol.SqlSha256, runtime._code.RunnerDigestSha256,
                    lease.Target.SystemIdentifierSha256, lease.ContainerId, lease.Volume,
                    before.ToDictionary(x => x.Key, x => x.Value.Sha256, StringComparer.Ordinal), after.ToDictionary(x => x.Key, x => x.Value.Sha256, StringComparer.Ordinal),
                    SourceOrderOwnerIsoProtocol.Hash(fleetBefore), SourceOrderOwnerIsoProtocol.Hash(fleetAfter), nativeEvidence.Sha256, began, DateTimeOffset.UtcNow, true, true, false);
            }
            catch (Exception failure) { primary = failure; }
            finally
            {
                try { if (session is not null) { await session.DisposeAsync(); } }
                catch (Exception failure) { cleanup = failure; }
            }
            if (cleanup is not null) { throw new AggregateException("Source-order ISO proof/cleanup failed.", primary is null ? [cleanup] : [primary, cleanup]); }
            if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
            facts = (facts ?? throw Invalid()) with { CleanupVerified = true, CompletedAtUtc = DateTimeOffset.UtcNow };
            await runtime.RequireAsync(ct);
            var pin = runtime._input.Configuration.SigningPins;
            using var signer = runtime._input.Signer(runtime._input.Configuration.EvidencePrivateKey, pin.ReceiptKeyId, pin.ReceiptFingerprint);
            var artifact = await runtime._input.PublishAsync("disposable-proof", CurrentAuthLocalSessionArchivePolicy.Sign(SourceOrderOwnerIsoProtocol.ProofDomain, facts, signer), facts.OperationId, ct);
            return new(facts, artifact);
        }
        internal void Require(SourceOrderOwnerIsoRuntime runtime)
        {
            if (!_facts.CleanupVerified || !_facts.RollbackReadback || !_facts.IndependentReadback ||
                _facts.SourceFullSha256 != runtime.Source.FullPlanSha256 || _facts.SourceDefinitionSha256 != runtime._input.Intent.SourceDefinitionSha256 ||
                _facts.ContractSha256 != runtime.Contract.ComputeSha256() || _facts.CandidateSha256 != SourceOrderOwnerIsoProtocol.SqlSha256 ||
                _facts.RunnerSha256 != runtime._code.RunnerDigestSha256 || _facts.SystemIdentifierSha256 == runtime._input.Intent.Target.SystemIdentifierSha256 ||
                _facts.BeforeNativeSha256.Count != 2 || _facts.AfterNativeSha256.Count != 2 ||
                _facts.CompletedAtUtc > DateTimeOffset.UtcNow || DateTimeOffset.UtcNow - _facts.BeganAtUtc > TimeSpan.FromMinutes(5)) { throw Invalid(); }
        }
    }
    private static NpgsqlConnection OwnedConnection(SourceOrderOwnerIsoOwnedSession session, string database)
    {
        return new(new NpgsqlConnectionStringBuilder(session.Lease.ConnectionString) { Database = database, Pooling = false }.ConnectionString);
    }

    private static object SafeEvidence(SourceOrderOwnerIsoNativeWitness witness)
    {
        return new
        {
            witness.Sha256,
            witness.Native.Snapshot,
            witness.Native.LiteralRows,
            witness.Native.Selected,
            witness.Native.SnapshotXmin,
            Storage = witness.Native.CopyStorage(),
            witness.Physical,
        };
    }

    private static async Task<SourceOrderOwnerIsoNativeWitness> CaptureOwnedAsync(SourceOrderOwnerIsoOwnedSession session,
        SourceOrderOwnerIsoContract contract, string database, bool after, CancellationToken ct)
    {
        await session.RequireAsync(ct); await using var connection = OwnedConnection(session, database); await connection.OpenAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct); await ReadOnlyAsync(connection, tx, ct);
        await CompanyStorageRuntime.RequirePolicyAsync(connection, tx, session.Lease.Maintenance, session.Lease.Target, ct);
        var result = await SourceOrderOwnerIsoNativeWitness.CaptureAsync(connection, tx, contract, after, ct);
        _ = await OwnedOwnerAsync(session, connection, tx, result, ct); await tx.RollbackAsync(ct); return result;
    }
    private static Task<string> OwnedOwnerAsync(SourceOrderOwnerIsoOwnedSession session, NpgsqlConnection connection, NpgsqlTransaction tx,
        SourceOrderOwnerIsoNativeWitness value, CancellationToken ct)
    {
        return CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx,
            connection.Database == "Country" ? CurrentRepairOperandOwnerPurpose.CountryIsoLiteral : CurrentRepairOperandOwnerPurpose.MaterialCountryIsoLiteral,
            session.Lease.Target, value.Native.Snapshot, ct);
    }

    private static async Task<SourceOrderOwnerIsoNativeWitness> ApplyOwnedCandidateAsync(SourceOrderOwnerIsoOwnedSession session,
        SourceOrderOwnerIsoContract contract, SourceOrderOwnerIsoNativeWitness before, NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken ct)
    {
        await CurrentAppOwnedRepairPreservation.LockAsync(connection, tx, before.Native.Snapshot, ct);
        await CompanyStorageRuntime.RequirePolicyAsync(connection, tx, session.Lease.Maintenance, session.Lease.Target, ct);
        var locked = await SourceOrderOwnerIsoNativeWitness.CaptureAsync(connection, tx, contract, false, ct);
        if (locked.Sha256 != before.Sha256) { throw Invalid(); }
        string owner = await OwnedOwnerAsync(session, connection, tx, locked, ct);
        await using (var command = new NpgsqlCommand(PostgreSqlCurrentOwnerIsoRepair.Sql, connection, tx)) { _ = await command.ExecuteNonQueryAsync(ct); }
        var candidate = await SourceOrderOwnerIsoNativeWitness.CaptureAsync(connection, tx, contract, true, ct);
        SourceOrderOwnerIsoNativeWitness.RequirePreserved(locked, candidate, contract);
        if (owner != await OwnedOwnerAsync(session, connection, tx, candidate, ct)) { throw Invalid(); }
        await session.RequireAsync(ct); return candidate;
    }
    private static void RequireExactRollback(SourceOrderOwnerIsoNativeWitness before, SourceOrderOwnerIsoNativeWitness after)
    {
        // No uncharacterized physical-growth exception. A refusal needs retained native evidence.
        if (before.Sha256 != after.Sha256) { throw Invalid(); }
    }
    private static void RequireOwnedFleet(IReadOnlyDictionary<string, string> baseline,
        Dictionary<string, SourceOrderOwnerIsoNativeWitness> operands, IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> actual)
    {
        if (actual.Count != baseline.Count || actual.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != actual.Count ||
            actual.Any(x => !baseline.TryGetValue(x.Database, out string? expected) || x.Sha256 !=
                (operands.TryGetValue(x.Database, out var native) ? native.Native.Snapshot.Sha256 : expected))) { throw Invalid(); }
    }
}
