namespace Legacy.Maliev.DataMigration.Console;

internal sealed record PairedLocalTransitionPreflightRequest(
    FreshSchemaPlan Schema,
    PairedCapturedDeltaPlans Plans,
    Exact23DeltaReconciliationResult Proof,
    PairedLocalTransitionAuthorization Authorization,
    ReceiptAttestationTrustStore Trust,
    string TargetConnectionString,
    string CaptureDirectory,
    byte[] CaptureKey);

internal interface IGuardedPairedLocalTransitionPreflightRuntime
{
    Task<PairedLocalTransitionPreflightResult> PreflightPairedLocalTransitionAsync(
        PairedLocalTransitionPreflightRequest request, CancellationToken cancellationToken);
}

internal sealed partial class DefaultGuardedDeltaConsoleRuntime :
    IGuardedPairedLocalTransitionPreflightRuntime
{
    public async Task<PairedLocalTransitionPreflightResult> PreflightPairedLocalTransitionAsync(
        PairedLocalTransitionPreflightRequest request, CancellationToken cancellationToken)
    {
        DeltaSynchronizationPlan local = request.Plans.Persistent;
        DeltaTargetAuthority authority = local.TargetAuthority ?? throw new DeltaExecutionException(
            "delta_paired_local_preflight_authority_invalid", "The persistent local authority is missing.");
        var inspector = new PostgreSqlDeltaReconciliationInspector(new(request.TargetConnectionString));
        var metadata = new PairedLocalTransitionMetadataInspector(request.TargetConnectionString);
        var targetRows = new PostgreSqlDeltaRowSource(new(request.TargetConnectionString));
        return await PairedLocalTransitionPreflight.VerifyAsync(request.Plans, request.Proof,
            request.Authorization, request.Schema, request.Trust, authority,
            local.TargetObservationSha256,
            token => VerifyTargetAuthorityAsync(request.TargetConnectionString, authority, token),
            (schema, transition, token) => transition
                ? inspector.ValidateQuotationTransitionSchemaAsync(schema, token)
                : inspector.ValidateSchemaAsync(schema, token),
            metadata.InspectAsync,
            request.CaptureDirectory, request.CaptureKey, targetRows, TimeProvider.System,
            cancellationToken).ConfigureAwait(false);
    }
}
