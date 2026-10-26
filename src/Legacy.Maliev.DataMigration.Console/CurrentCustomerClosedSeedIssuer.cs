namespace Legacy.Maliev.DataMigration.Console;

internal static class CurrentCustomerClosedSeedIssuer
{
    // A genuine host creates its ephemeral review key only during the actual run.
    // No staged/generated proof is treated as completed by this producer.
    internal static async Task<CurrentCustomerSequenceRepairScope> IssueAfterActualCaptureAsync(
        CustomerClosedSeedEvidence evidence, CurrentCustomerSequenceRepairScope unsignedScope,
        CurrentCustomerClosedTemplateCapture capture, FreshSchemaPlan source,
        IReceiptAttestationTrustStore trust, CurrentCustomerSequenceRepairSigningPins pins,
        IMigrationEvidenceSigner signer, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        var seed = unsignedScope.ClosedConsoleSeed ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        if (seed.Signature is not null || signer.KeyId != pins.ReviewKeyId || seed.OperationId != capture.State.OperationId ||
            seed.RunBindingSha256 != capture.State.BindingSha256 || unsignedScope.Target != capture.Target ||
            seed.TargetObservationSha256 != CurrentAppOwnedSnapshotSerialization.Sha256(capture.TargetPins) || seed.TargetGeneration != capture.State.TargetGeneration ||
            unsignedScope.Maintenance != capture.Maintenance || seed.FleetBeforeSha256 != capture.FleetSha256 ||
            !unsignedScope.BeforeDatabaseSha256.OrderBy(x => x.Key, StringComparer.Ordinal).SequenceEqual(capture.BeforeDatabaseSha256.OrderBy(x => x.Key, StringComparer.Ordinal)))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        await CurrentCustomerSequenceClosedSeedReadback.RequireUnsignedForProducerAsync(evidence, unsignedScope, source, trust, pins, ct).ConfigureAwait(false);
        byte[] signature = signer.Sign(CurrentCustomerSequenceClosedBootstrap.Payload(seed));
        var signed = seed with { Signature = Convert.ToBase64String(signature) };
        var result = unsignedScope with { ClosedConsoleSeed = signed };
        CurrentCustomerSequenceClosedBootstrap.Require(signed, result, trust, pins.ReviewKeyId, pins.ReviewFingerprint, DateTimeOffset.UtcNow);
        // This authenticates a disposable preparation subject only. Actual live
        // source/native/fullfleet/HBA/custody checks still precede public review.
        return result;
    }
}
