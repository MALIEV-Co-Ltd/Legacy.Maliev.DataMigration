using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record SourceBackedLocalRepairSigningPins(string PersistentPlanFingerprint,
    string DisposablePlanFingerprint, string AuthorizationFingerprint, string EvidenceFingerprint);

/// <summary>Fresh signed source repair admission evidence, never a database write permit.</summary>
internal sealed record SourceBackedLocalRepairAdmission(string SchemaVersion, Guid AdmissionId, Guid ClaimId,
    string PreimageSha256, string SourceCaptureSha256, string PersistentPlanSha256, string DisposablePlanSha256,
    string DisposableReceiptSha256, string SchemaPlanSha256, Guid AuthorizationId, string AuthorizationSha256,
    HistoricalCurrentLocalObservation TargetIdentity, IReadOnlyList<HistoricalLocalMetadataBinding> InitialMetadata,
    DateTimeOffset ClaimCreatedAtUtc, DateTimeOffset ClaimExpiresAtUtc, DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc, string AttestationKeyId, string? AttestationSignature)
{
    internal static bool AuthorizesExecution => false;
}

internal sealed record SourceBackedLocalRepairAdmissionBundle(SourceBackedLocalRepairAdmission Admission,
    SourceBackedLocalRepairPreimageAttestation Capsule, SourceBackedLocalRepairClaim VerifiedClaim)
{
    internal static bool AuthorizesExecution => false;
}

internal static class SourceBackedLocalRepairAdmissionPolicy
{
    internal static byte[] Payload(SourceBackedLocalRepairAdmission value)
    {
        return [.. "legacy-maliev-source-repair-admission-v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(value with { AttestationSignature = null })];
    }

    internal static string ComputeSha256(SourceBackedLocalRepairAdmission value)
    {
        return HashBytes(Payload(value));
    }

    /// <summary>
    /// Source-repair internal relation binding: complete signed internal row multisets and
    /// catalogs, including fence, journal, effects and adoption records. SettledPrior is only
    /// the existing record shape; this hash is not a historical inspector fingerprint or authority.
    /// </summary>
    internal static IReadOnlyList<HistoricalLocalMetadataBinding> Metadata(
        IReadOnlyList<SourceBackedLocalRepairDatabasePreimage> databases)
    {
        return databases is null || !databases.Select(item => item?.Database)
            .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal)
            ? throw Invalid()
            : (IReadOnlyList<HistoricalLocalMetadataBinding>)databases.Select(database =>
        {
            if (database.Relations is null) { throw Invalid(); }
            SourceRepairRelationPreimage[] internalRelations = [.. database.Relations
                .Where(item => item.Schema == "legacy_migration_internal")
                .OrderBy(item => item.Table, StringComparer.Ordinal)];
            if (internalRelations.Any(item => item.Rows < 0 || !Hash(item.RowMultisetSha256) || !Hash(item.CatalogSha256)) ||
                internalRelations.Select(item => item.Table).Distinct(StringComparer.Ordinal).Count() != internalRelations.Length ||
                !internalRelations.Any(item => item.Table == "delta_fence" && item.Rows == 1) ||
                !internalRelations.Any(item => item.Table == "delta_journal")) { throw Invalid(); }
            string fingerprint = HashBytes([.. "legacy-maliev-source-repair-internal-relations-v1\0"u8,
                .. JsonSerializer.SerializeToUtf8Bytes(new { database.Database, Relations = internalRelations })]);
            return new HistoricalLocalMetadataBinding(database.Database, PairedLocalTransitionMetadataState.SettledPrior, fingerprint);
        }).ToArray();
    }

    internal static void Verify(SourceBackedLocalRepairAdmission admission,
        SourceBackedLocalRepairPreimageAttestation capsule, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization,
        HistoricalCurrentLocalObservation identity, IReceiptAttestationTrustStore trust,
        SourceBackedLocalRepairSigningPins pins, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(trust);
        if (admission is null || capsule is null || plans is null || proof is null || authorization is null || pins is null ||
            admission.SchemaVersion != "1.0" || admission.AdmissionId == Guid.Empty || admission.ClaimId == Guid.Empty ||
            admission.TargetIdentity != identity ||
            admission.PreimageSha256 != SourceBackedLocalRepairPreimageAttestationPolicy.ComputeSha256(capsule) ||
            admission.SourceCaptureSha256 != capsule.SourceCaptureSha256 ||
            admission.PersistentPlanSha256 != DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plans.Persistent) ||
            admission.DisposablePlanSha256 != DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plans.Disposable) ||
            admission.DisposableReceiptSha256 != Exact23DeltaReconciliationCoordinator.ComputeSha256(proof) ||
            admission.SchemaPlanSha256 != plans.Persistent.SchemaPlanSha256 ||
            admission.AuthorizationId != authorization.AuthorizationId ||
            admission.AuthorizationSha256 != SourceBackedLocalRepairContinuationStore.AuthorizationHash(authorization) ||
            admission.ClaimCreatedAtUtc.Offset != TimeSpan.Zero || admission.ClaimExpiresAtUtc.Offset != TimeSpan.Zero ||
            admission.ClaimExpiresAtUtc - admission.ClaimCreatedAtUtc != ImmutableRolloverClaimStore.MaximumClaimAge ||
            admission.IssuedAtUtc != admission.ClaimCreatedAtUtc ||
            !Fresh(admission.IssuedAtUtc, admission.ExpiresAtUtc, nowUtc) ||
            admission.IssuedAtUtc < capsule.ObservedAtUtc || admission.ExpiresAtUtc > capsule.ExpiresAtUtc ||
            admission.ExpiresAtUtc > authorization.ExpiresAtUtc || admission.ExpiresAtUtc > admission.ClaimExpiresAtUtc ||
            !Role(plans.Persistent.AttestationKeyId, pins.PersistentPlanFingerprint, trust) ||
            !Role(plans.Disposable.AttestationKeyId, pins.DisposablePlanFingerprint, trust) ||
            !Role(authorization.AttestationKeyId, pins.AuthorizationFingerprint, trust) ||
            !Role(capsule.AttestationKeyId, pins.EvidenceFingerprint, trust) ||
            !Role(proof.AttestationKeyId, pins.EvidenceFingerprint, trust) ||
            !Role(admission.AttestationKeyId, pins.EvidenceFingerprint, trust) ||
            !Distinct(pins) || !Signature(admission, trust) || admission.InitialMetadata is null ||
            !admission.InitialMetadata.SequenceEqual(Metadata(capsule.Databases))) { throw Invalid(); }
        SourceBackedLocalRepairPreimageAttestationPolicy.Verify(capsule, plans, proof, schema, authorization,
            identity, capsule.Databases, trust, nowUtc);
    }

    internal static SourceBackedLocalRepairClaim ExpectedClaim(SourceBackedLocalRepairAdmission admission)
    {
        HistoricalCurrentLocalObservation identity = admission.TargetIdentity;
        return new("1.0", admission.ClaimId, ComputeSha256(admission), admission.PreimageSha256,
            admission.SourceCaptureSha256, admission.PersistentPlanSha256, identity.DockerGeneration,
            identity.VolumeName, identity.VolumeCreatedAtUtc, identity.SystemIdentifierSha256,
            admission.InitialMetadata, admission.ClaimCreatedAtUtc, admission.ClaimExpiresAtUtc);
    }

    private static bool Fresh(DateTimeOffset issued, DateTimeOffset expires, DateTimeOffset now)
    {
        return issued.Offset == TimeSpan.Zero && expires.Offset == TimeSpan.Zero && now.Offset == TimeSpan.Zero &&
            issued <= now && now < expires && expires > issued && expires - issued <= TimeSpan.FromMinutes(15);
    }

    private static bool Distinct(SourceBackedLocalRepairSigningPins pins)
    {
        string[] values = [pins.PersistentPlanFingerprint, pins.DisposablePlanFingerprint,
            pins.AuthorizationFingerprint, pins.EvidenceFingerprint];
        return values.All(Hash) && values.Distinct(StringComparer.Ordinal).Count() == values.Length;
    }

    private static bool Role(string keyId, string fingerprint, IReceiptAttestationTrustStore trust)
    {
        return Hash(fingerprint) && trust.TryGetPublicKeyFingerprintSha256(keyId, out string actual) && actual == fingerprint;
    }

    private static bool Signature(SourceBackedLocalRepairAdmission value, IReceiptAttestationTrustStore trust)
    {
        try { return trust.Verify(value.AttestationKeyId, Payload(value), Convert.FromBase64String(value.AttestationSignature ?? string.Empty)); }
        catch (Exception exception) when (exception is FormatException or CryptographicException) { return false; }
    }

    private static bool Hash(string? value)
    {
        return value is { Length: 64 } && value.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }

    private static string HashBytes(byte[] value)
    {
        return Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
    }

    internal static DeltaExecutionException Invalid()
    {
        return new("delta_source_repair_admission_invalid", "Source-backed repair admission requires fresh locked evidence and authenticated retained bindings.");
    }
}

/// <summary>Trusted composition only. No public factory, execution permit, CLI or cloud gateway construction.</summary>
internal sealed class SourceBackedLocalRepairAdmissionStore(SourceBackedLocalRepairClaimStore claims,
    IReceiptAttestationTrustStore trust, SourceBackedLocalRepairSigningPins pins,
    Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observeTarget, TimeProvider clock,
    SourceBackedLocalRepairRenewalStore? renewals = null,
    ISourceBackedLocalRepairSourceAcceptance? sourceAcceptance = null,
    SourceBackedLocalRepairTerminalSigningPin? terminalPin = null)
{
    private readonly SourceBackedLocalRepairRenewalStore? _renewals = renewals ?? (terminalPin is null ? null : new(claims.Gateway,
        claims, new SourceBackedLocalRepairContinuationStore(claims.Gateway, claims, trust,
            pins.AuthorizationFingerprint, pins.EvidenceFingerprint), trust, pins, terminalPin, observeTarget, clock, sourceAcceptance));
    internal SourceBackedLocalRepairRenewalStore Renewals => _renewals ?? throw SourceBackedLocalRepairAdmissionPolicy.Invalid();
    internal async Task<SourceBackedLocalRepairAdmissionBundle> CreateAsync(SourceBackedLocalRepairLockedIssuer issuer,
        PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        PairedLocalTransitionAuthorization authorization, IReadOnlyList<SourceBackedLocalRepairDatabasePreimage> expectedPreimages,
        DateTimeOffset expiresAtUtc, P256MigrationEvidenceSigner signer, CancellationToken cancellationToken)
    {
        plans = Snapshot(plans); proof = Snapshot(proof); schema = Snapshot(schema); authorization = Snapshot(authorization);
        expectedPreimages = Snapshot(expectedPreimages.ToArray());
        SourceBackedLocalRepairPreimageAttestation capsule = await issuer.IssueAsync(plans, proof, schema,
            authorization, expectedPreimages, trust, expiresAtUtc, signer, cancellationToken).ConfigureAwait(false);
        HistoricalCurrentLocalObservation identity = await observeTarget(cancellationToken).ConfigureAwait(false);
        DateTimeOffset issued = clock.GetUtcNow();
        var unsigned = new SourceBackedLocalRepairAdmission("1.0", Guid.NewGuid(), Guid.NewGuid(),
            SourceBackedLocalRepairPreimageAttestationPolicy.ComputeSha256(capsule), capsule.SourceCaptureSha256,
            capsule.PersistentPlanSha256, capsule.DisposablePlanSha256, capsule.DisposableReceiptSha256,
            plans.Persistent.SchemaPlanSha256, authorization.AuthorizationId,
            SourceBackedLocalRepairContinuationStore.AuthorizationHash(authorization), identity,
            SourceBackedLocalRepairAdmissionPolicy.Metadata(capsule.Databases), issued,
            issued.Add(ImmutableRolloverClaimStore.MaximumClaimAge), issued, expiresAtUtc, signer.KeyId, null);
        SourceBackedLocalRepairAdmission admission = unsigned with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(SourceBackedLocalRepairAdmissionPolicy.Payload(unsigned))),
        };
        SourceBackedLocalRepairAdmissionPolicy.Verify(admission, capsule, plans, proof, schema, authorization,
            identity, trust, pins, issued);
        await Renewals.RetainOriginalAsync(admission, capsule, authorization, plans, proof, schema,
            cancellationToken).ConfigureAwait(false);
        if (sourceAcceptance is not null)
        {
            await sourceAcceptance.RequireAsync(plans.Persistent.SourceCommitSha, cancellationToken).ConfigureAwait(false);
        }
        HistoricalCurrentLocalObservation beforeReservation = await observeTarget(cancellationToken).ConfigureAwait(false);
        DateTimeOffset reservationNow = clock.GetUtcNow();
        SourceBackedLocalRepairAdmissionPolicy.Verify(admission, capsule, plans, proof, schema, authorization,
            beforeReservation, trust, pins, reservationNow);
        _ = await claims.ReserveAsync(SourceBackedLocalRepairAdmissionPolicy.ExpectedClaim(admission), reservationNow,
            cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairClaim claim = await VerifyRetainedAsync(admission, capsule, plans, proof, schema,
            authorization, cancellationToken).ConfigureAwait(false);
        return new(admission, capsule, claim);
    }

    internal async Task<SourceBackedLocalRepairClaim> VerifyRetainedAsync(SourceBackedLocalRepairAdmission admission,
        SourceBackedLocalRepairPreimageAttestation capsule, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization,
        CancellationToken cancellationToken)
    {
        admission = Snapshot(admission); capsule = Snapshot(capsule); plans = Snapshot(plans);
        proof = Snapshot(proof); schema = Snapshot(schema); authorization = Snapshot(authorization);
        HistoricalCurrentLocalObservation identity = await observeTarget(cancellationToken).ConfigureAwait(false);
        DateTimeOffset now = clock.GetUtcNow();
        SourceBackedLocalRepairAdmissionPolicy.Verify(admission, capsule, plans, proof, schema, authorization,
            identity, trust, pins, now);
        SourceBackedLocalRepairClaim retained = await claims.ReadAsync(admission.ClaimId,
            SourceBackedLocalRepairAdmissionPolicy.ComputeSha256(admission), now, cancellationToken).ConfigureAwait(false);
        _ = await Renewals.VerifyOriginalRetainedAsync(new(admission, capsule, retained), plans, proof, schema,
            cancellationToken).ConfigureAwait(false);
        await Renewals.RequireNoRenewalAsync(admission.ClaimId, cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairClaim expected = SourceBackedLocalRepairAdmissionPolicy.ExpectedClaim(admission);
        if (JsonSerializer.Serialize(expected) != JsonSerializer.Serialize(retained) ||
            !expected.InitialMetadata.SequenceEqual(retained.InitialMetadata)) { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        HistoricalCurrentLocalObservation after = await observeTarget(cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairAdmissionPolicy.Verify(admission, capsule, plans, proof, schema, authorization,
            after, trust, pins, clock.GetUtcNow());
        await Renewals.RequireNoRenewalAsync(admission.ClaimId, cancellationToken).ConfigureAwait(false);
        return retained;
    }

    internal async Task<SourceBackedLocalRepairClaim> VerifyRetainedAsync(SourceBackedLocalRepairAdmission admission,
        SourceBackedLocalRepairPreimageAttestation capsule, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization,
        SourceBackedLocalRepairRenewalStore.ActiveGrant activeGrant, CancellationToken cancellationToken)
    {
        admission = Snapshot(admission); capsule = Snapshot(capsule); plans = Snapshot(plans);
        proof = Snapshot(proof); schema = Snapshot(schema); authorization = Snapshot(authorization);
        HistoricalCurrentLocalObservation identity = await observeTarget(cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairClaim verified = await activeGrant.RequireFreshAsync(admission, capsule, plans,
            proof, schema, authorization, identity, cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairClaim own = await claims.ReadAsync(admission.ClaimId,
            SourceBackedLocalRepairAdmissionPolicy.ComputeSha256(admission), clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
        if (JsonSerializer.Serialize(verified) != JsonSerializer.Serialize(own) || identity != await observeTarget(cancellationToken).ConfigureAwait(false))
        {
            throw SourceBackedLocalRepairAdmissionPolicy.Invalid();
        }
        return own;
    }

    private static T Snapshot<T>(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value)) ?? throw SourceBackedLocalRepairAdmissionPolicy.Invalid();
    }
}
