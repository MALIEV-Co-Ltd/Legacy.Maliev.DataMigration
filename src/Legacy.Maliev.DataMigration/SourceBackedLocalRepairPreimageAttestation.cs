using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Signed observed preimage evidence. This is neither a lock proof nor a write permit.</summary>
internal sealed record SourceBackedLocalRepairPreimageAttestation(
    string SchemaVersion, Guid AttestationId, string PersistentPlanSha256,
    string DisposablePlanSha256, string DisposableReceiptSha256, string SourceCaptureSha256,
    Guid AuthorizationId, HistoricalCurrentLocalObservation TargetIdentity,
    IReadOnlyList<SourceBackedLocalRepairDatabasePreimage> Databases,
    DateTimeOffset ObservedAtUtc, DateTimeOffset ExpiresAtUtc, string AttestationKeyId,
    string? AttestationSignature)
{
    internal static bool AuthorizesExecution => false;
}

internal static class SourceBackedLocalRepairPreimageAttestationPolicy
{
    internal static byte[] CreatePayload(SourceBackedLocalRepairPreimageAttestation attestation)
    {
        return [.. "legacy-maliev-source-repair-observed-preimage-v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(attestation with { AttestationSignature = null })];
    }

    internal static string ComputeSha256(SourceBackedLocalRepairPreimageAttestation attestation)
    {
        return Convert.ToHexString(SHA256.HashData(CreatePayload(attestation))).ToLowerInvariant();
    }

    internal static SourceBackedLocalRepairPreimageAttestation Produce(
        PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof,
        FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization,
        HistoricalCurrentLocalObservation identity,
        IReadOnlyList<SourceBackedLocalRepairDatabasePreimage> databases,
        IReceiptAttestationTrustStore trust, DateTimeOffset observedAtUtc,
        DateTimeOffset expiresAtUtc, P256MigrationEvidenceSigner signer)
    {
        RequireEvidence(plans, proof, schema, authorization, identity, databases, trust, observedAtUtc);
        if (expiresAtUtc.Offset != TimeSpan.Zero || expiresAtUtc <= observedAtUtc || expiresAtUtc > authorization.ExpiresAtUtc ||
            expiresAtUtc - observedAtUtc > TimeSpan.FromMinutes(15) ||
            !trust.TryGetPublicKeyFingerprintSha256(proof.AttestationKeyId, out string proofKey) ||
            !Fixed(proofKey, signer.PublicKeyFingerprintSha256) ||
            !trust.TryGetPublicKeyFingerprintSha256(signer.KeyId, out string signingKey) ||
            !Fixed(signingKey, signer.PublicKeyFingerprintSha256))
        {
            throw Invalid();
        }
        var unsigned = new SourceBackedLocalRepairPreimageAttestation("1.0", Guid.NewGuid(),
            DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plans.Persistent),
            DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plans.Disposable),
            Exact23DeltaReconciliationCoordinator.ComputeSha256(proof), CaptureHash(plans.Persistent),
            authorization.AuthorizationId, identity, databases, observedAtUtc, expiresAtUtc, signer.KeyId, null);
        return unsigned with { AttestationSignature = Convert.ToBase64String(signer.Sign(CreatePayload(unsigned))) };
    }

    internal static void Verify(SourceBackedLocalRepairPreimageAttestation attestation,
        PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof,
        FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization,
        HistoricalCurrentLocalObservation identity,
        IReadOnlyList<SourceBackedLocalRepairDatabasePreimage> databases,
        IReceiptAttestationTrustStore trust, DateTimeOffset nowUtc)
    {
        RequireEvidence(plans, proof, schema, authorization, identity, databases, trust, nowUtc);
        if (attestation is null || attestation.SchemaVersion != "1.0" || attestation.AttestationId == Guid.Empty ||
            !Fixed(attestation.PersistentPlanSha256, DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plans.Persistent)) ||
            !Fixed(attestation.DisposablePlanSha256, DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plans.Disposable)) ||
            !Fixed(attestation.DisposableReceiptSha256, Exact23DeltaReconciliationCoordinator.ComputeSha256(proof)) ||
            !Fixed(attestation.SourceCaptureSha256, CaptureHash(plans.Persistent)) ||
            attestation.AuthorizationId != authorization.AuthorizationId || attestation.TargetIdentity != identity ||
            attestation.ObservedAtUtc.Offset != TimeSpan.Zero || attestation.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            attestation.ObservedAtUtc < authorization.IssuedAtUtc || nowUtc < attestation.ObservedAtUtc ||
            nowUtc >= attestation.ExpiresAtUtc || attestation.ExpiresAtUtc > authorization.ExpiresAtUtc ||
            attestation.ExpiresAtUtc - attestation.ObservedAtUtc > TimeSpan.FromMinutes(15) ||
            attestation.Databases is null || attestation.Databases.Count != databases.Count ||
            !trust.TryGetPublicKeyFingerprintSha256(attestation.AttestationKeyId, out string signer) ||
            !trust.TryGetPublicKeyFingerprintSha256(proof.AttestationKeyId, out string proofSigner) ||
            !Fixed(signer, proofSigner) || !VerifySignature(attestation, trust))
        {
            throw Invalid();
        }
        foreach (var (signed, observed) in attestation.Databases.Zip(databases))
        {
            SourceBackedLocalRepairPreimage.RequireMatches(signed, observed);
        }
    }

    private static void RequireEvidence(PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        PairedLocalTransitionAuthorization authorization, HistoricalCurrentLocalObservation identity,
        IReadOnlyList<SourceBackedLocalRepairDatabasePreimage> databases,
        IReceiptAttestationTrustStore trust, DateTimeOffset nowUtc)
    {
        PairedLocalTransitionAuthorizationPolicy.Verify(authorization, plans, proof, schema, trust,
            plans.Persistent.TargetAuthority!, plans.Persistent.TargetObservationSha256,
            plans.Persistent.QuotationTransitionSchemaSha256!, nowUtc);
        string[] generation = identity.DockerGeneration.Split(':');
        if (generation.Length != 5 || generation[0] != "docker" || !Hash(identity.ContainerId) ||
            generation[1] != identity.ContainerId || identity.DockerGeneration != plans.Persistent.TargetGeneration ||
            identity.VolumeName != "legacy-maliev-exact23-postgres-data" ||
            identity.VolumeCreatedAtUtc.Offset != TimeSpan.Zero ||
            generation[4] != identity.VolumeCreatedAtUtc.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture) ||
            !Fixed(identity.SystemIdentifierSha256, plans.Persistent.TargetAuthority!.SystemIdentifierSha256) ||
            string.IsNullOrWhiteSpace(identity.VolumeMountpoint) || identity.VolumeDestination != "/var/lib/postgresql" ||
            string.IsNullOrWhiteSpace(identity.PgData) || !(identity.PgData == identity.VolumeDestination ||
                identity.PgData.StartsWith(identity.VolumeDestination + "/", StringComparison.Ordinal)) ||
            databases is null || !databases.Select(item => item?.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            databases.Any(item => item is null || !Hash(item.ObservedPhysicalSchemaSha256) ||
                !Hash(item.CatalogObjectsSha256) || item.Relations is null || item.Sequences is null ||
                item.Relations.Any(table => table.Rows < 0 || !Hash(table.RowMultisetSha256) || !Hash(table.CatalogSha256)) ||
                item.Sequences.Any(sequence => !Hash(sequence.CatalogSha256))))
        {
            throw Invalid();
        }
    }

    private static string CaptureHash(DeltaSynchronizationPlan plan)
    {
        return Convert.ToHexString(SHA256.HashData([.. "legacy-maliev-source-repair-capture-binding-v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(plan.SourceCaptureManifest)])).ToLowerInvariant();
    }

    private static bool VerifySignature(SourceBackedLocalRepairPreimageAttestation attestation,
        IReceiptAttestationTrustStore trust)
    {
        try
        {
            return trust.Verify(attestation.AttestationKeyId, CreatePayload(attestation),
                Convert.FromBase64String(attestation.AttestationSignature ?? string.Empty));
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException)
        {
            return false;
        }
    }

    private static bool Hash(string? value)
    {
        return value is { Length: 64 } && value.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }

    private static bool Fixed(string? left, string? right)
    {
        return Hash(left) && Hash(right) && CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left!), Convert.FromHexString(right!));
    }

    private static DeltaExecutionException Invalid()
    {
        return new("delta_source_repair_preimage_attestation_invalid",
            "Observed source-repair preimages require fresh matched capture/proof, identity and separate trusted signatures.");
    }
}
