using System.Data;
using System.Reflection;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal interface ICompanyStorageOwnedProofLease : IAsyncDisposable
{
    Guid OperationId { get; }
    string SourceFullSha256 { get; }
    string ConnectionString { get; }
    string OrdinaryConnectionString { get; }
    string TargetGeneration { get; }
    CurrentAppOwnedRepairTargetPins TargetPins { get; }
    CurrentAppOwnedMaintenancePin Maintenance { get; }
    DeltaTargetAuthority Target { get; }
    string ContainerId { get; }
    string Volume { get; }
    Task RequireAsync(CancellationToken ct);
    Task RequireAbsentAsync(CancellationToken ct);
    Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> CaptureFleetAsync(CancellationToken ct);
}

internal sealed partial class CompanyStorageRuntime
{
    private sealed record ProofFacts(Guid OperationId, string SourceFullSha256, string SourceDefinitionSha256, string CandidateSha256, string RunnerDigestSha256,
        string BeforePhysicalSha256, string AfterPhysicalSha256, int ProviderVersion, string CompositeDefense,
        string BeforeNativeSha256, string AfterNativeSha256, string SystemIdentifierSha256, string ContainerId, string Volume,
        string RollbackBeforeNativeSha256, string RollbackAfterNativeSha256, string BeforeFleetSha256, string AfterFleetSha256,
        DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, bool RollbackReadback, bool IndependentCommittedReadback, bool CleanupVerified);
    private sealed class Rehearsal
    {
        internal ProofFacts Facts { get; }
        internal CompanyStorageArtifact Artifact { get; }
        private Rehearsal(ProofFacts facts, CompanyStorageArtifact artifact) { Facts = facts; Artifact = artifact; }
        internal static async Task<Rehearsal> RunAsync(CompanyStorageRuntime runtime, CancellationToken ct)
        {
            await runtime.RequireAsync(ct); var input = runtime._inputs;
            var image = input.Configuration.TestsImage;
            if (!Path.IsPathFullyQualified(image.Path) || Path.GetFileName(image.Path) != "Legacy.Maliev.DataMigration.Tests.dll") { throw Invalid(); }
            using var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(Path.GetDirectoryName(image.Path)!, ct);
            using (var heldImage = SecureLocalFile.OpenReadShared(image.Path))
            {
                if (!SecureLocalFile.HandleResolvesToApprovedPath(heldImage, image.Path) ||
                    Convert.ToHexStringLower(await System.Security.Cryptography.SHA256.HashDataAsync(heldImage, ct)) != image.Sha256) { throw Invalid(); }
            }
            using var loader = new CurrentAuthArchiveInitialProducer.FixedNativeBundle(image.Path);
            ICompanyStorageOwnedProofLease? lease = null; Exception? primary = null;
            ProofFacts? facts = null;
            try
            {
                if (CurrentAuthTypedHostProducer.ImageHash(image.Path) != image.Sha256) { throw Invalid(); }
                bundle.Require(); Assembly tests = loader.LoadFromAssemblyPath(image.Path);
                Type exact = tests.GetType("Legacy.Maliev.DataMigration.Tests.CompanyStorageOwnedProofLease", throwOnError: true)!;
                if (!exact.IsSealed || exact.GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length != 0) { throw Invalid(); }
                MethodInfo factory = exact.GetMethod("CreateAsync", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.DeclaredOnly,
                    binder: null, types: [typeof(string), typeof(FreshSchemaPlan), typeof(CancellationToken)], modifiers: null) ?? throw Invalid();
                if (factory.ReturnType != typeof(Task<ICompanyStorageOwnedProofLease>)) { throw Invalid(); }
                lease = await (factory.Invoke(null, [input.Configuration.ProofParent, runtime.Source.Plan, ct]) as Task<ICompanyStorageOwnedProofLease> ?? throw Invalid());
                if (lease.GetType() != exact || lease.SourceFullSha256 != runtime.Source.FullPlanSha256) { throw Invalid(); }
                await lease.RequireAsync(ct); bundle.Require();
                DateTimeOffset began = DateTimeOffset.UtcNow; CompanyStorageNativeWitness before;
                CompanyStorageNativeWitness rollbackCandidate;
                string rollbackBefore, rollbackAfter;
                var fleetBefore = await lease.CaptureFleetAsync(ct);
                await using (var connection = new NpgsqlConnection(lease.ConnectionString))
                {
                    await connection.OpenAsync(ct);
                    await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct))
                    {
                        await RequirePolicyAsync(connection, transaction, lease.Maintenance, lease.Target, ct);
                        before = await CompanyStorageNativeWitness.CaptureAsync(connection, transaction, runtime.Contract, false, ct);
                        rollbackBefore = before.Sha256;
                        rollbackCandidate = await CandidateAsync(connection, transaction, runtime.Contract, before, lease.Maintenance, lease.Target, before.OwnerName, ct);
                        await transaction.RollbackAsync(ct);
                    }
                    await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct))
                    {
                        await ReadOnlyAsync(connection, transaction, ct);
                        var rolledBack = await CompanyStorageNativeWitness.CaptureAsync(connection, transaction, runtime.Contract, false, ct);
                        RequireRolledBack(before, rolledBack, rollbackCandidate);
                        rollbackAfter = rolledBack.Sha256;
                        // Retain both actual physical states; catalog btree allocation need not shrink on rollback.
                        before = rolledBack;
                        await transaction.RollbackAsync(ct);
                    }
                    await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct))
                    {
                        _ = await CandidateAsync(connection, transaction, runtime.Contract, before, lease.Maintenance, lease.Target, before.OwnerName, ct);
                        await transaction.CommitAsync(ct);
                    }
                }
                CompanyStorageNativeWitness after;
                await using (var independent = new NpgsqlConnection(lease.ConnectionString))
                {
                    await independent.OpenAsync(ct); await using var transaction = await independent.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
                    await ReadOnlyAsync(independent, transaction, ct);
                    await RequirePolicyAsync(independent, transaction, lease.Maintenance, lease.Target, ct);
                    after = await CompanyStorageNativeWitness.CaptureAsync(independent, transaction, runtime.Contract, true, ct);
                    CompanyStorageNativeWitness.RequirePreserved(before, after, runtime.Contract); await transaction.RollbackAsync(ct);
                }
                await lease.RequireAsync(ct);
                var fleetAfter = await lease.CaptureFleetAsync(ct);
                if (!fleetBefore.Select(x => x.Database).SequenceEqual(fleetAfter.Select(x => x.Database), StringComparer.Ordinal) ||
                    fleetBefore.Any(x => x.Database != "Customer" && x.Sha256 != fleetAfter.Single(y => y.Database == x.Database).Sha256)) { throw Invalid(); }
                facts = new(lease.OperationId, runtime.Source.FullPlanSha256, input.Intent.SourceDefinitionSha256, CompanyStorageRepairProtocol.CandidateSha256, runtime._code.RunnerDigestSha256,
                    runtime.Contract.Before().TargetSchemaSha256, runtime.Contract.After().TargetSchemaSha256,
                    before.Observation.ProviderVersion, before.Observation.CompositeDefense, before.Sha256, after.Sha256, lease.Target.SystemIdentifierSha256, lease.ContainerId, lease.Volume,
                    rollbackBefore, rollbackAfter, CompanyStorageRepairProtocol.Hash(fleetBefore), CompanyStorageRepairProtocol.Hash(fleetAfter),
                    began, DateTimeOffset.UtcNow, true, true, false);
            }
            catch (Exception failure) { primary = failure; }
            Exception? cleanupFailure = null;
            if (lease is not null)
            {
                try { await lease.DisposeAsync(); using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30)); await lease.RequireAbsentAsync(cleanup.Token); }
                catch (Exception cleanup) { cleanupFailure = cleanup; }
            }
            loader.Unload();
            if (cleanupFailure is not null) { throw new AggregateException("Company proof or exact cleanup failed.", primary is null ? [cleanupFailure] : [primary, cleanupFailure]); }
            if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
            if (facts is null) { throw Invalid(); }
            facts = facts with { CleanupVerified = true, CompletedAtUtc = DateTimeOffset.UtcNow };
            await runtime.RequireAsync(ct);
            var pins = input.Configuration.SigningPins;
            using var signer = input.Signer(input.Configuration.EvidencePrivateKey, pins.ReceiptKeyId, pins.ReceiptFingerprint);
            var artifact = await input.PublishAsync("disposable-proof", CurrentAuthLocalSessionArchivePolicy.Sign(CompanyStorageRepairProtocol.ProofDomain, facts, signer), facts.OperationId, ct);
            return new(facts, artifact);
        }
        internal void Require(CompanyStorageRuntime runtime, CompanyStorageNativeWitness target)
        {
            if (!Facts.CleanupVerified || !Facts.RollbackReadback || !Facts.IndependentCommittedReadback ||
                Facts.SourceFullSha256 != runtime.Source.FullPlanSha256 || Facts.SourceDefinitionSha256 != runtime._inputs.Intent.SourceDefinitionSha256 ||
                Facts.CandidateSha256 != CompanyStorageRepairProtocol.CandidateSha256 ||
                Facts.RunnerDigestSha256 != runtime._code.RunnerDigestSha256 ||
                Facts.BeforePhysicalSha256 != runtime.Contract.Before().TargetSchemaSha256 || Facts.AfterPhysicalSha256 != runtime.Contract.After().TargetSchemaSha256 ||
                Facts.ProviderVersion != target.Observation.ProviderVersion || Facts.CompositeDefense != target.Observation.CompositeDefense ||
                Facts.SystemIdentifierSha256 == runtime._inputs.Intent.Target.SystemIdentifierSha256 || Facts.BeforeNativeSha256 == target.Sha256 || Facts.CompletedAtUtc > DateTimeOffset.UtcNow || DateTimeOffset.UtcNow - Facts.BeganAtUtc > TimeSpan.FromMinutes(5))
            { throw Invalid(); }
        }
    }

    private static async Task<CompanyStorageNativeWitness> CandidateAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        ApprovedCustomerCompanyStorageRepair contract, CompanyStorageNativeWitness expected, CurrentAppOwnedMaintenancePin maintenance,
        DeltaTargetAuthority target, string owner, CancellationToken ct)
    {
        await CurrentAppOwnedRepairPreservation.LockAsync(connection, transaction, expected.Observation.Native.Snapshot, ct);
        await RequirePolicyAsync(connection, transaction, maintenance, target, ct);
        var locked = await CompanyStorageNativeWitness.CaptureAsync(connection, transaction, contract, false, ct);
        if (locked.Sha256 != expected.Sha256 || locked.OwnerName != owner) { throw Invalid(); }
        await using (var allowed = new NpgsqlCommand("SELECT has_schema_privilege($1,'public','CREATE');", connection, transaction))
        { _ = allowed.Parameters.AddWithValue(owner); if (await allowed.ExecuteScalarAsync(ct) is not true) { throw Invalid(); } }
        await using (var role = new NpgsqlCommand("SET LOCAL ROLE " + PostgreSqlShadowTarget.QuoteIdentifier(owner) + ";", connection, transaction)) { _ = await role.ExecuteNonQueryAsync(ct); }
        await using (var ddl = new NpgsqlCommand(ApprovedCustomerCompanyStorageRepair.CandidateSql, connection, transaction)) { _ = await ddl.ExecuteNonQueryAsync(ct); }
        await using (var reset = new NpgsqlCommand("RESET ROLE;", connection, transaction)) { _ = await reset.ExecuteNonQueryAsync(ct); }
        var candidate = await CompanyStorageNativeWitness.CaptureAsync(connection, transaction, contract, true, ct);
        CompanyStorageNativeWitness.RequirePreserved(locked, candidate, contract);
        await RequirePolicyAsync(connection, transaction, maintenance, target, ct);
        return candidate;
    }
}
