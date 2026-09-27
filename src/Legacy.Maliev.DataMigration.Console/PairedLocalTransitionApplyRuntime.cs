using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record PairedLocalTransitionApplyRequest(
    PairedLocalTransitionPreflightRequest Preflight,
    string SourceConnectionString,
    P256MigrationEvidenceSigner EvidenceSigner);

internal interface IGuardedPairedLocalTransitionApplyRuntime
{
    Task<Exact23DeltaReconciliationResult> ApplyPairedLocalTransitionAsync(
        PairedLocalTransitionApplyRequest request, CancellationToken cancellationToken);
}

internal sealed partial class DefaultGuardedDeltaConsoleRuntime :
    IGuardedPairedLocalTransitionApplyRuntime
{
    public async Task<Exact23DeltaReconciliationResult> ApplyPairedLocalTransitionAsync(
        PairedLocalTransitionApplyRequest request, CancellationToken cancellationToken)
    {
        PairedLocalTransitionPreflightRequest input = request.Preflight;
        DeltaSynchronizationPlan plan = input.Plans.Persistent;
        DeltaTargetAuthority authority = plan.TargetAuthority ?? throw new DeltaExecutionException(
            "delta_paired_local_preflight_authority_invalid", "The LOCAL target authority is missing.");
        var permit = PairedLocalTransitionExecutionPermit.Admit(input.Plans, input.Proof,
            input.Authorization, input.Schema, input.Trust, authority,
            plan.TargetObservationSha256, TimeProvider.System);
        await LocalDockerGenerationGuard.VerifyAsync(plan, input.TargetConnectionString,
            cancellationToken).ConfigureAwait(false);
        await VerifyLiveSourceAsync(plan, request.SourceConnectionString, cancellationToken)
            .ConfigureAwait(false);
        _ = await PreflightPairedLocalTransitionAsync(input, cancellationToken).ConfigureAwait(false);
        permit.Require(plan, input.Schema.Databases[0], TimeProvider.System.GetUtcNow());
        using DeltaCapturedTableRowSource captured = DeltaCapturedTableRowSource.FromSignedPlan(
            new DeltaCapturedTableArchive(input.CaptureDirectory), plan, input.Trust,
            TimeProvider.System.GetUtcNow(), input.CaptureKey);
        var targetRows = new PostgreSqlDeltaRowSource(new(input.TargetConnectionString));
        var gate = new PairedLocalTransitionExecutionGate(permit, input.Schema,
            token => LocalDockerGenerationGuard.VerifyAsync(plan, input.TargetConnectionString, token));
        await using IMigrationSourceSession source = _sourceFactory.Create(request.SourceConnectionString);
        DeltaExecutionCoordinator Executor(string database)
        {
            string connection = new NpgsqlConnectionStringBuilder(input.TargetConnectionString)
            {
                Database = database,
                Pooling = false,
            }.ConnectionString;
            return new DeltaExecutionCoordinator(
                new PostgreSqlDeltaCanonicalTarget(new(connection, database, plan.TargetGeneration)
                {
                    LocalTransitionPermit = permit,
                }),
                new CapturedDeltaExecutionRowSessionProvider(captured, targetRows),
                gate,
                new SignedCapturedSourceReconciliationInspector(plan, input.Schema,
                    input.Trust, TimeProvider.System),
                input.Trust, TimeProvider.System, permit);
        }
        _ = await new Exact23DeltaExecutionCoordinator(source, Executor,
            capturedSourceReplay: true, localPermit: permit)
            .ExecuteAsync(plan, input.Schema, cancellationToken).ConfigureAwait(false);
        await VerifyLiveSourceAsync(plan, request.SourceConnectionString, cancellationToken)
            .ConfigureAwait(false);
        await LocalDockerGenerationGuard.VerifyAsync(plan, input.TargetConnectionString,
            cancellationToken).ConfigureAwait(false);
        await VerifyTargetAuthorityAsync(input.TargetConnectionString, authority, cancellationToken)
            .ConfigureAwait(false);
        var coordinator = new Exact23DeltaReconciliationCoordinator(
            new SignedCapturedSourceReconciliationInspector(plan, input.Schema,
                input.Trust, TimeProvider.System),
            new PostgreSqlDeltaReconciliationInspector(new(input.TargetConnectionString)
            {
                Plan = plan,
                LocalTransitionPermit = permit,
            }),
            new PostgreSqlExact23DeltaCheckpointReader(new(input.TargetConnectionString)),
            TimeProvider.System, request.EvidenceSigner, localPermit: permit);
        Exact23DeltaReconciliationResult result = await coordinator.ReconcileAsync(plan, input.Schema,
            cancellationToken).ConfigureAwait(false);
        await VerifyLiveSourceAsync(plan, request.SourceConnectionString, cancellationToken)
            .ConfigureAwait(false);
        await LocalDockerGenerationGuard.VerifyAsync(plan, input.TargetConnectionString,
            cancellationToken).ConfigureAwait(false);
        await VerifyTargetAuthorityAsync(input.TargetConnectionString, authority, cancellationToken)
            .ConfigureAwait(false);
        return result;
    }
}
