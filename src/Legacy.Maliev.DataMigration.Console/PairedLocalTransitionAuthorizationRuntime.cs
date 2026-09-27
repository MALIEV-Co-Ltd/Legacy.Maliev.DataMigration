namespace Legacy.Maliev.DataMigration.Console;

internal sealed record PairedLocalTransitionAuthorizationRequest(
    FreshSchemaPlan Schema,
    PairedCapturedDeltaPlans Plans,
    Exact23DeltaReconciliationResult Proof,
    ReceiptAttestationTrustStore Trust,
    string TargetConnectionString,
    string CaptureDirectory,
    byte[] CaptureKey,
    DateTimeOffset ExpiresAtUtc,
    P256MigrationEvidenceSigner Signer);

internal interface IGuardedPairedLocalTransitionAuthorizationRuntime
{
    Task<PairedLocalTransitionAuthorization> AuthorizePairedLocalTransitionAsync(
        PairedLocalTransitionAuthorizationRequest request, CancellationToken cancellationToken);
}

internal sealed partial class DefaultGuardedDeltaConsoleRuntime :
    IGuardedPairedLocalTransitionAuthorizationRuntime
{
    public async Task<PairedLocalTransitionAuthorization> AuthorizePairedLocalTransitionAsync(
        PairedLocalTransitionAuthorizationRequest request, CancellationToken cancellationToken)
    {
        DeltaSynchronizationPlan local = request.Plans.Persistent;
        DeltaTargetAuthority authority = local.TargetAuthority ?? throw new DeltaExecutionException(
            "delta_paired_local_authority_invalid", "The signed persistent LOCAL authority is missing.");
        await VerifyTargetAuthorityAsync(request.TargetConnectionString, authority, cancellationToken)
            .ConfigureAwait(false);
        var inspector = new PostgreSqlDeltaReconciliationInspector(new(request.TargetConnectionString));
        foreach (DatabaseSchemaPlan database in request.Schema.Databases)
        {
            if (database.Database == "Quotation")
            {
                await inspector.ValidateQuotationTransitionSchemaAsync(database, cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                await inspector.ValidateSchemaAsync(database, cancellationToken).ConfigureAwait(false);
            }
        }
        DateTimeOffset issuedAtUtc = TimeProvider.System.GetUtcNow();
        PairedLocalTransitionAuthorization authorization = PairedLocalTransitionAuthorizationPolicy.Produce(
            request.Plans, request.Proof, request.Schema, request.Trust, authority,
            local.TargetObservationSha256, local.QuotationTransitionSchemaSha256 ?? string.Empty,
            issuedAtUtc, request.ExpiresAtUtc, request.Signer);
        _ = await PreflightPairedLocalTransitionAsync(new(request.Schema, request.Plans, request.Proof,
            authorization, request.Trust, request.TargetConnectionString, request.CaptureDirectory,
            request.CaptureKey), cancellationToken).ConfigureAwait(false);
        return authorization;
    }
}
