using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Retained original signed provenance. Its lifetime never extends execution authority.</summary>
internal sealed record SourceBackedLocalRepairOriginalAuthority(SourceBackedLocalRepairAdmission Admission,
    SourceBackedLocalRepairPreimageAttestation Capsule, PairedLocalTransitionAuthorization Authorization,
    PairedCapturedDeltaPlans Plans, Exact23DeltaReconciliationResult Proof, FreshSchemaPlan Schema,
    SourceBackedLocalRepairSigningPins SigningPins, SourceBackedLocalRepairTerminalSigningPin TerminalPin,
    IReadOnlyList<TrustedAttestationKey> PublicTrustMaterial)
{
    internal static bool AuthorizesExecution => false;
}

/// <summary>A separate short-lived authorization epoch, preserving the original claim and progress.</summary>
internal sealed record SourceBackedLocalRepairRenewalGrant(string SchemaVersion, Guid ClaimId,
    string OriginalAuthoritySha256, long OriginalAuthorityGeneration, string AdmissionSha256,
    string PreimageSha256, string SourceCaptureSha256, string PersistentPlanSha256, long Counter,
    string? PreviousGrantSha256, long BasisContinuationOrdinal, string BasisContinuationSha256,
    IReadOnlyList<SourceBackedLocalRepairState> Databases, PairedLocalTransitionAuthorization Authorization,
    HistoricalCurrentLocalObservation TargetIdentity, DateTimeOffset ObservedAtUtc,
    DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc, string AttestationKeyId,
    string? AttestationSignature)
{
    internal static bool AuthorizesExecution => false;
}

/// <summary>
/// Signature and scope checks for retained renewal evidence. Actual database inspection remains
/// mandatory; neither this policy nor a retained grant constitutes a row execution permit.
/// </summary>
internal static class SourceBackedLocalRepairRenewalPolicy
{
    internal static byte[] Payload(SourceBackedLocalRepairRenewalGrant value)
    {
        return [.. "legacy-maliev-source-repair-renewal-v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(value with { AttestationSignature = null })];
    }

    internal static string ComputeSha256(SourceBackedLocalRepairRenewalGrant value)
    {
        return HashBytes(Payload(value));
    }

    internal static string OriginalSha256(SourceBackedLocalRepairOriginalAuthority value)
    {
        return HashBytes([.. "legacy-maliev-source-repair-original-authority-v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(value)]);
    }

    /// <summary>
    /// Only authenticated signature provenance is checked at its own signed issuance instant.
    /// This method deliberately returns no fresh admission, grant, observation or execution permit.
    /// </summary>
    internal static void VerifyOriginalProvenance(SourceBackedLocalRepairOriginalAuthority original,
        PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        HistoricalCurrentLocalObservation identity, IReceiptAttestationTrustStore trust,
        SourceBackedLocalRepairSigningPins pins)
    {
        if (original is null || original.Admission is null || original.Capsule is null || original.Authorization is null ||
            JsonSerializer.Serialize(original.Plans) != JsonSerializer.Serialize(plans) ||
            JsonSerializer.Serialize(original.Proof) != JsonSerializer.Serialize(proof) ||
            JsonSerializer.Serialize(original.Schema) != JsonSerializer.Serialize(schema) || original.SigningPins != pins ||
            original.TerminalPin is null || !trust.TryGetPublicKeyFingerprintSha256(original.TerminalPin.KeyId, out string terminalFingerprint) ||
            terminalFingerprint != original.TerminalPin.PublicKeyFingerprintSha256 ||
            new[] { pins.PersistentPlanFingerprint, pins.DisposablePlanFingerprint, pins.AuthorizationFingerprint, pins.EvidenceFingerprint }
                .Contains(terminalFingerprint, StringComparer.Ordinal) ||
            original.PublicTrustMaterial is null || !original.PublicTrustMaterial.Select(item => item?.KeyId)
                .SequenceEqual(RelevantKeyIds(original.Admission, original.Capsule, original.Authorization, plans, proof, original.TerminalPin), StringComparer.Ordinal))
        {
            throw Invalid();
        }
        foreach (TrustedAttestationKey key in original.PublicTrustMaterial)
        {
            if (!trust.TryGetPublicKeyFingerprintSha256(key.KeyId, out string current) || key.SubjectPublicKeyInfo is null ||
                current != HashBytes(key.SubjectPublicKeyInfo)) { throw Invalid(); }
        }
        // A stored public key is provenance, never a replacement for current approved trust.
        try { _ = new ReceiptAttestationTrustStore(original.PublicTrustMaterial); }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException) { throw Invalid(); }
        SourceBackedLocalRepairAdmissionPolicy.Verify(original.Admission, original.Capsule, plans, proof,
            schema, original.Authorization, identity, trust, pins, original.Admission.IssuedAtUtc);
    }

    internal static void Verify(SourceBackedLocalRepairRenewalGrant value,
        SourceBackedLocalRepairOriginalAuthority original, long originalGeneration,
        SourceBackedLocalRepairClaim claim, SourceBackedLocalRepairContinuation? basis,
        SourceBackedLocalRepairRenewalGrant? previous, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        HistoricalCurrentLocalObservation identity, IReceiptAttestationTrustStore trust,
        SourceBackedLocalRepairSigningPins pins, DateTimeOffset nowUtc)
    {
        if (value is null || original is null || claim is null || identity is null ||
            plans is null || proof is null || schema is null || trust is null || pins is null)
        {
            throw Invalid();
        }
        VerifyOriginalProvenance(original, plans, proof, schema, identity, trust, pins);
        SourceBackedLocalRepairClaim expected = SourceBackedLocalRepairAdmissionPolicy.ExpectedClaim(original.Admission);
        if (basis is not null && (basis.Databases is null || basis.Databases.Count != DatabaseInventory.ActiveDatabases.Count ||
            !basis.Databases.Select(item => item?.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal)))
        {
            throw Invalid();
        }
        IReadOnlyList<SourceBackedLocalRepairState> basisStates = basis?.Databases ?? claim.InitialMetadata.Select(item =>
            new SourceBackedLocalRepairState(item.Database, SourceBackedLocalRepairPhase.Prior,
                item.FingerprintSha256, null, null, null)).ToArray();
        if (value is null || value.Authorization is null || value.SchemaVersion != "1.0" ||
            JsonSerializer.Serialize(claim) != JsonSerializer.Serialize(expected) ||
            value.ClaimId != claim.ClaimId || value.OriginalAuthoritySha256 != OriginalSha256(original) ||
            originalGeneration <= 0 || value.OriginalAuthorityGeneration != originalGeneration ||
            value.AdmissionSha256 != claim.AdmissionSha256 || value.PreimageSha256 != claim.PreimageSha256 ||
            value.SourceCaptureSha256 != claim.SourceCaptureSha256 || value.PersistentPlanSha256 != claim.FuturePlanSha256 ||
            value.TargetIdentity != identity || value.Counter < 1 ||
            value.BasisContinuationOrdinal != (basis?.Ordinal ?? 0) || value.BasisContinuationOrdinal is < 0 or > 24 ||
            value.BasisContinuationSha256 != (basis is null ? claim.AdmissionSha256 : SourceBackedLocalRepairContinuationStore.ComputeSha256(basis)) ||
            (basis is not null && (basis.ClaimId != claim.ClaimId || basis.AdmissionSha256 != claim.AdmissionSha256 ||
                basis.InitialPreimageSha256 != claim.PreimageSha256 || basis.SourceCaptureSha256 != claim.SourceCaptureSha256 ||
                basis.FuturePlanSha256 != claim.FuturePlanSha256 || basis.TargetGeneration != claim.TargetGeneration ||
                !Role(basis.AttestationKeyId, pins.EvidenceFingerprint, trust) ||
                !Signature(basis.AttestationKeyId, basis.AttestationSignature, SourceBackedLocalRepairContinuationStore.Payload(basis), trust))) ||
            value.Databases is null || value.Databases.Count != basisStates.Count ||
            !value.Databases.Select(item => item?.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            value.ObservedAtUtc.Offset != TimeSpan.Zero || value.IssuedAtUtc.Offset != TimeSpan.Zero ||
            value.ExpiresAtUtc.Offset != TimeSpan.Zero || nowUtc.Offset != TimeSpan.Zero ||
            value.ObservedAtUtc < (basis?.IssuedAtUtc ?? original.Admission.IssuedAtUtc) || value.ObservedAtUtc > value.IssuedAtUtc || value.IssuedAtUtc - value.ObservedAtUtc > TimeSpan.FromMinutes(1) ||
            value.IssuedAtUtc > nowUtc || nowUtc >= value.ExpiresAtUtc || value.ExpiresAtUtc <= value.IssuedAtUtc ||
            value.ExpiresAtUtc - value.IssuedAtUtc > TimeSpan.FromMinutes(15) ||
            value.IssuedAtUtc < value.Authorization.IssuedAtUtc || value.ExpiresAtUtc > value.Authorization.ExpiresAtUtc ||
            value.ExpiresAtUtc > claim.ExpiresAtUtc ||
            value.Authorization.AuthorizationId == original.Authorization.AuthorizationId ||
            !Role(value.Authorization.AttestationKeyId, pins.AuthorizationFingerprint, trust) ||
            !Role(value.AttestationKeyId, pins.EvidenceFingerprint, trust) ||
            !Signature(value, trust))
        {
            throw Invalid();
        }
        int applied = value.Databases.Count(item => item.Phase == SourceBackedLocalRepairPhase.Applied);
        if (applied < Math.Max(value.BasisContinuationOrdinal - 1, 0) || applied > Math.Min(value.BasisContinuationOrdinal, 23))
        {
            throw Invalid();
        }
        for (int index = 0; index < value.Databases.Count; index++)
        {
            SourceBackedLocalRepairState state = value.Databases[index];
            if (state.PriorMetadataSha256 != claim.InitialMetadata[index].FingerprintSha256 ||
                state.Phase != (index < applied ? SourceBackedLocalRepairPhase.Applied : SourceBackedLocalRepairPhase.Prior) ||
                (index != value.BasisContinuationOrdinal - 1 && state != basisStates[index]) ||
                !(state.Phase == SourceBackedLocalRepairPhase.Prior ? state.RepairMarkerSha256 is null &&
                    state.CheckpointSha256 is null && state.ReconciliationSha256 is null :
                    Hash(state.RepairMarkerSha256) && Hash(state.CheckpointSha256) && Hash(state.ReconciliationSha256)))
            {
                throw Invalid();
            }
        }
        if (previous is null ? value.Counter != 1 || value.PreviousGrantSha256 is not null :
            value.Counter != previous.Counter + 1 || value.PreviousGrantSha256 != ComputeSha256(previous) ||
            value.ClaimId != previous.ClaimId || value.AdmissionSha256 != previous.AdmissionSha256 ||
            value.IssuedAtUtc < previous.IssuedAtUtc || value.BasisContinuationOrdinal < previous.BasisContinuationOrdinal ||
            value.Authorization.AuthorizationId == previous.Authorization.AuthorizationId)
        {
            throw Invalid();
        }
        if (previous is not null)
        {
            for (int index = 0; index < previous.Databases.Count; index++)
            {
                if (previous.Databases[index].Phase == SourceBackedLocalRepairPhase.Applied &&
                    previous.Databases[index] != value.Databases[index]) { throw Invalid(); }
            }
        }
        // Fresh execution authority is independently verified at NOW. In particular, the source
        // plans retain their existing maximum age, zero-delete policy and captured proof gates.
        PairedLocalTransitionAuthorizationPolicy.Verify(value.Authorization, plans, proof, schema, trust,
            plans.Persistent.TargetAuthority!, plans.Persistent.TargetObservationSha256,
            plans.Persistent.QuotationTransitionSchemaSha256!, nowUtc);
    }

    private static bool Role(string keyId, string fingerprint, IReceiptAttestationTrustStore trust)
    {
        return trust.TryGetPublicKeyFingerprintSha256(keyId, out string actual) && actual == fingerprint;
    }

    private static bool Signature(SourceBackedLocalRepairRenewalGrant value, IReceiptAttestationTrustStore trust)
    {
        return Signature(value.AttestationKeyId, value.AttestationSignature, Payload(value), trust);
    }

    private static bool Signature(string keyId, string? signature, byte[] payload, IReceiptAttestationTrustStore trust)
    {
        try { return trust.Verify(keyId, payload, Convert.FromBase64String(signature ?? string.Empty)); }
        catch (Exception exception) when (exception is FormatException or CryptographicException) { return false; }
    }

    private static string HashBytes(byte[] bytes)
    {
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static bool Hash(string? value)
    {
        return value is { Length: 64 } && value.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }

    internal static IReadOnlyList<string> RelevantKeyIds(SourceBackedLocalRepairAdmission admission,
        SourceBackedLocalRepairPreimageAttestation capsule, PairedLocalTransitionAuthorization authorization,
        PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof,
        SourceBackedLocalRepairTerminalSigningPin terminalPin)
    {
        return new[] { admission.AttestationKeyId, capsule.AttestationKeyId, authorization.AttestationKeyId,
            plans.Persistent.AttestationKeyId, plans.Disposable.AttestationKeyId, proof.AttestationKeyId, terminalPin.KeyId }
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
    }

    internal static DeltaExecutionException Invalid()
    {
        return new("delta_source_repair_renewal_invalid", "A fresh retained renewal requires original signed provenance and actual maintained target progress.");
    }
}

internal sealed record SourceBackedLocalRepairAuthorizationEpoch(PairedLocalTransitionAuthorization Authorization,
    long BasisOrdinal, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);

/// <summary>
/// Create-only original provenance and monotonic short-lived renewal epochs. No update, delete,
/// list or database mutation is exposed. An active grant still requires an actual mixed-state
/// observation and the guarded execution factory before it can support any row transaction.
/// </summary>
internal sealed class SourceBackedLocalRepairRenewalStore(IRolloverClaimObjectGateway gateway,
    SourceBackedLocalRepairClaimStore claims, SourceBackedLocalRepairContinuationStore continuations,
    IReceiptAttestationTrustStore trust, SourceBackedLocalRepairSigningPins pins,
    SourceBackedLocalRepairTerminalSigningPin terminalPin,
    Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observeTarget, TimeProvider clock,
    ISourceBackedLocalRepairSourceAcceptance? sourceAcceptance = null)
{
    private static readonly object GrantToken = new();

    internal sealed class ActiveGrant
    {
        private readonly SourceBackedLocalRepairRenewalStore _store;
        private readonly SourceBackedLocalRepairAdmissionBundle _bundle;
        private readonly PairedCapturedDeltaPlans _plans;
        private readonly Exact23DeltaReconciliationResult _proof;
        private readonly FreshSchemaPlan _schema;
        private readonly SourceBackedLocalRepairRenewalGrant _grant;

        internal ActiveGrant(object token, SourceBackedLocalRepairRenewalStore store,
            SourceBackedLocalRepairAdmissionBundle bundle, PairedCapturedDeltaPlans plans,
            Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
            SourceBackedLocalRepairRenewalGrant grant,
            IReadOnlyList<SourceBackedLocalRepairAuthorizationEpoch> epochs)
        {
            if (!ReferenceEquals(token, GrantToken)) { throw Invalid(); }
            _store = store; _bundle = Snapshot(bundle); _plans = Snapshot(plans);
            _proof = Snapshot(proof); _schema = Snapshot(schema); _grant = Snapshot(grant);
            Epochs = Snapshot(epochs.ToArray());
        }

        internal SourceBackedLocalRepairRenewalGrant SignedGrant => Snapshot(_grant);
        internal PairedLocalTransitionAuthorization Authorization => Snapshot(_grant.Authorization);
        internal string OriginalAdmissionSha256 => _grant.AdmissionSha256;
        internal long Counter => _grant.Counter;
        internal HistoricalCurrentLocalObservation Identity => _grant.TargetIdentity;
        internal DateTimeOffset ExpiresAtUtc => _grant.ExpiresAtUtc;
        internal IReadOnlyList<SourceBackedLocalRepairAuthorizationEpoch> Epochs => Snapshot(field.ToArray());
        internal static bool AuthorizesExecution => false;

        internal async Task<SourceBackedLocalRepairClaim> RequireFreshAsync(
            SourceBackedLocalRepairAdmission admission, SourceBackedLocalRepairPreimageAttestation capsule,
            PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
            PairedLocalTransitionAuthorization authorization, HistoricalCurrentLocalObservation identity,
            CancellationToken cancellationToken)
        {
            // Caller arguments cannot substitute different signed artifacts into a sealed epoch.
            if (SourceBackedLocalRepairAdmissionPolicy.ComputeSha256(admission) != OriginalAdmissionSha256 ||
                SourceBackedLocalRepairPreimageAttestationPolicy.ComputeSha256(capsule) != _grant.PreimageSha256 ||
                JsonSerializer.Serialize(plans) != JsonSerializer.Serialize(_plans) ||
                JsonSerializer.Serialize(proof) != JsonSerializer.Serialize(_proof) ||
                JsonSerializer.Serialize(schema) != JsonSerializer.Serialize(_schema) ||
                SourceBackedLocalRepairContinuationStore.AuthorizationHash(authorization) !=
                    SourceBackedLocalRepairContinuationStore.AuthorizationHash(_grant.Authorization) || identity != Identity)
            {
                throw Invalid();
            }
            ActiveGrant current = await _store.ReadAsync(_bundle, _plans, _proof, _schema, Counter,
                cancellationToken).ConfigureAwait(false);
            return SourceBackedLocalRepairRenewalPolicy.ComputeSha256(current.SignedGrant) !=
                SourceBackedLocalRepairRenewalPolicy.ComputeSha256(_grant)
                ? throw Invalid()
                : await _store.ReadCurrentClaimAsync(_grant.ClaimId, OriginalAdmissionSha256,
                cancellationToken).ConfigureAwait(false);
        }

        internal async Task RequireFreshAsync(PairedLocalTransitionAuthorization authorization,
            CancellationToken cancellationToken)
        {
            _ = await RequireFreshAsync(_bundle.Admission, _bundle.Capsule, _plans, _proof, _schema,
                authorization, Identity, cancellationToken).ConfigureAwait(false);
        }
    }

    internal async Task RetainOriginalAsync(SourceBackedLocalRepairAdmission admission,
        SourceBackedLocalRepairPreimageAttestation capsule, PairedLocalTransitionAuthorization authorization,
        PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        plans = Snapshot(plans); proof = Snapshot(proof); schema = Snapshot(schema);
        if (trust is not ReceiptAttestationTrustStore concrete || terminalPin is null) { throw Invalid(); }
        var original = Snapshot(new SourceBackedLocalRepairOriginalAuthority(admission, capsule, authorization,
            plans, proof, schema, pins, terminalPin, concrete.ExportTrustedPublicKeys(SourceBackedLocalRepairRenewalPolicy
                .RelevantKeyIds(admission, capsule, authorization, plans, proof, terminalPin))));
        SourceBackedLocalRepairRenewalPolicy.VerifyOriginalProvenance(original, plans, proof, schema,
            original.Admission.TargetIdentity, trust, pins);
        HistoricalCurrentLocalObservation identity = await observeTarget(cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairAdmissionPolicy.Verify(original.Admission, original.Capsule, plans, proof,
            schema, original.Authorization, identity, trust, pins, clock.GetUtcNow());
        await RequirePolicyAsync(cancellationToken).ConfigureAwait(false);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(original);
        string name = OriginalName(admission.ClaimId);
        if (sourceAcceptance is not null)
        {
            await sourceAcceptance.RequireAsync(plans.Persistent.SourceCommitSha, cancellationToken).ConfigureAwait(false);
        }
        RolloverClaimObject created = await gateway.CreateOnlyAsync(name, bytes, cancellationToken).ConfigureAwait(false);
        RolloverClaimObject read = await RequiredAsync(name, cancellationToken).ConfigureAwait(false);
        RequireObject(created, admission.ClaimExpiresAtUtc);
        RequireObject(read, admission.ClaimExpiresAtUtc);
        if (created.Generation != read.Generation || !created.Content.AsSpan().SequenceEqual(bytes) ||
            !read.Content.AsSpan().SequenceEqual(bytes) || read.CreatedAtUtc < admission.IssuedAtUtc ||
            read.CreatedAtUtc >= admission.ExpiresAtUtc) { throw Invalid(); }
        await MigrationAuthorizationReservation.ReserveAsync(gateway, authorization.AuthorizationId,
            admission.ClaimId, 0, SourceBackedLocalRepairRenewalPolicy.OriginalSha256(original),
            admission.ClaimExpiresAtUtc, cancellationToken).ConfigureAwait(false);
        HistoricalCurrentLocalObservation after = await observeTarget(cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairAdmissionPolicy.Verify(original.Admission, original.Capsule, plans, proof,
            schema, original.Authorization, after, trust, pins, clock.GetUtcNow());
    }

    internal async Task<SourceBackedLocalRepairOriginalAuthority> VerifyOriginalRetainedAsync(
        SourceBackedLocalRepairAdmissionBundle bundle, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, CancellationToken cancellationToken)
    {
        return (await ReadOriginalAsync(Snapshot(bundle), Snapshot(plans), Snapshot(proof), Snapshot(schema),
            cancellationToken).ConfigureAwait(false)).Original;
    }

    internal async Task<SourceBackedLocalRepairClaim> VerifyRenewalInputsAsync(
        SourceBackedLocalRepairAdmissionBundle bundle, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization,
        CancellationToken cancellationToken)
    {
        bundle = Snapshot(bundle); plans = Snapshot(plans); proof = Snapshot(proof); schema = Snapshot(schema);
        authorization = Snapshot(authorization);
        var origin = await ReadOriginalAsync(bundle, plans, proof, schema, cancellationToken).ConfigureAwait(false);
        if (!trust.TryGetPublicKeyFingerprintSha256(authorization.AttestationKeyId, out string fingerprint) ||
            fingerprint != pins.AuthorizationFingerprint) { throw Invalid(); }
        PairedLocalTransitionAuthorizationPolicy.Verify(authorization, plans, proof, schema, trust,
            plans.Persistent.TargetAuthority!, plans.Persistent.TargetObservationSha256,
            plans.Persistent.QuotationTransitionSchemaSha256!, clock.GetUtcNow());
        return origin.Claim;
    }

    internal Task RequireNoRenewalAsync(Guid claim, CancellationToken cancellationToken)
    {
        return RequireLatestAsync(claim, 0, cancellationToken);
    }

    internal async Task<ActiveGrant> CreateAsync(SourceBackedLocalRepairMixedStateReader.RenewalObservation observed,
        SourceBackedLocalRepairAdmissionBundle bundle, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        PairedLocalTransitionAuthorization authorization, long previousCounter,
        P256MigrationEvidenceSigner signer, CancellationToken cancellationToken)
    {
        if (observed is null || previousCounter < 0) { throw Invalid(); }
        bundle = Snapshot(bundle); plans = Snapshot(plans); proof = Snapshot(proof); schema = Snapshot(schema);
        authorization = Snapshot(authorization);
        var origin = await ReadOriginalAsync(bundle, plans, proof, schema, cancellationToken).ConfigureAwait(false);
        if (observed.AdmissionSha256 != origin.Claim.AdmissionSha256 || observed.Identity != origin.Identity)
        {
            throw Invalid();
        }
        SourceBackedLocalRepairRenewalGrant? previous = previousCounter == 0 ? null :
            (await ReadChainAsync(origin, plans, proof, schema, previousCounter,
                cancellationToken).ConfigureAwait(false)).Grants[^1];
        if (await gateway.ReadAsync(GrantName(origin.Claim.ClaimId, checked(previousCounter + 1)), cancellationToken).ConfigureAwait(false) is not null)
        {
            ActiveGrant existing = await ReadAsync(bundle, plans, proof, schema, previousCounter + 1, cancellationToken).ConfigureAwait(false);
            return SourceBackedLocalRepairContinuationStore.AuthorizationHash(existing.Authorization) !=
                SourceBackedLocalRepairContinuationStore.AuthorizationHash(authorization) ||
                !existing.SignedGrant.Databases.SequenceEqual(observed.Databases) ||
                existing.SignedGrant.BasisContinuationSha256 != (observed.Basis is null ? origin.Claim.AdmissionSha256 :
                    SourceBackedLocalRepairContinuationStore.ComputeSha256(observed.Basis))
                ? throw Invalid()
                : existing;
        }
        await RequireLatestAsync(origin.Claim.ClaimId, previousCounter, cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairContinuation? basis = observed.Basis is null ? null :
            await continuations.ReadProvenanceAsync(origin.Claim.ClaimId, origin.Claim.AdmissionSha256,
                observed.Basis.Ordinal, origin.Original.Authorization, clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
        if (basis is not null && SourceBackedLocalRepairContinuationStore.ComputeSha256(basis) !=
            SourceBackedLocalRepairContinuationStore.ComputeSha256(observed.Basis!)) { throw Invalid(); }
        DateTimeOffset issued = clock.GetUtcNow();
        DateTimeOffset expires = new[] { issued.AddMinutes(15), authorization.ExpiresAtUtc, origin.Claim.ExpiresAtUtc }.Min();
        var unsigned = new SourceBackedLocalRepairRenewalGrant("1.0", origin.Claim.ClaimId,
            SourceBackedLocalRepairRenewalPolicy.OriginalSha256(origin.Original), origin.Object.Generation,
            origin.Claim.AdmissionSha256, origin.Claim.PreimageSha256, origin.Claim.SourceCaptureSha256,
            origin.Claim.FuturePlanSha256, checked(previousCounter + 1), previous is null ? null :
                SourceBackedLocalRepairRenewalPolicy.ComputeSha256(previous), basis?.Ordinal ?? 0,
            basis is null ? origin.Claim.AdmissionSha256 : SourceBackedLocalRepairContinuationStore.ComputeSha256(basis), observed.Databases.ToArray(),
            authorization, origin.Identity, observed.VerifiedAtUtc, issued, expires, signer.KeyId, null);
        var signed = unsigned with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(SourceBackedLocalRepairRenewalPolicy.Payload(unsigned))),
        };
        SourceBackedLocalRepairRenewalPolicy.Verify(signed, origin.Original, origin.Object.Generation, origin.Claim,
            basis, previous, plans, proof, schema, origin.Identity, trust, pins, issued);
        await MigrationAuthorizationReservation.ReserveAsync(gateway, authorization.AuthorizationId,
            origin.Claim.ClaimId, signed.Counter, SourceBackedLocalRepairRenewalPolicy.ComputeSha256(signed),
            origin.Claim.ExpiresAtUtc, cancellationToken).ConfigureAwait(false);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(signed);
        string name = GrantName(origin.Claim.ClaimId, signed.Counter);
        if (sourceAcceptance is not null)
        {
            await sourceAcceptance.RequireAsync(plans.Persistent.SourceCommitSha, cancellationToken).ConfigureAwait(false);
        }
        SourceBackedLocalRepairRenewalPolicy.Verify(signed, origin.Original, origin.Object.Generation, origin.Claim,
            basis, previous, plans, proof, schema, origin.Identity, trust, pins, clock.GetUtcNow());
        RolloverClaimObject created = await gateway.CreateOnlyAsync(name, bytes, cancellationToken).ConfigureAwait(false);
        RolloverClaimObject read = await RequiredAsync(name, cancellationToken).ConfigureAwait(false);
        RequireObject(created, origin.Claim.ExpiresAtUtc); RequireObject(read, origin.Claim.ExpiresAtUtc);
        return created.Generation != read.Generation || !created.Content.AsSpan().SequenceEqual(bytes) ||
            !read.Content.AsSpan().SequenceEqual(bytes)
            ? throw Invalid()
            : await ReadAsync(bundle, plans, proof, schema, signed.Counter, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<ActiveGrant> ReadAsync(SourceBackedLocalRepairAdmissionBundle bundle,
        PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        long counter, CancellationToken cancellationToken)
    {
        bundle = Snapshot(bundle); plans = Snapshot(plans); proof = Snapshot(proof); schema = Snapshot(schema);
        var origin = await ReadOriginalAsync(bundle, plans, proof, schema, cancellationToken).ConfigureAwait(false);
        var (Grants, Epochs) = await ReadChainAsync(origin, plans, proof, schema, counter, cancellationToken).ConfigureAwait(false);
        await RequireLatestAsync(origin.Claim.ClaimId, counter, cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairRenewalGrant grant = Grants[^1];
        SourceBackedLocalRepairContinuation? basis = grant.BasisContinuationOrdinal == 0 ? null :
            await continuations.ReadProvenanceAsync(origin.Claim.ClaimId, origin.Claim.AdmissionSha256,
                grant.BasisContinuationOrdinal, origin.Original.Authorization, clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairRenewalPolicy.Verify(grant, origin.Original, origin.Object.Generation, origin.Claim,
            basis, Grants.Count == 1 ? null : Grants[^2], plans, proof, schema, origin.Identity,
            trust, pins, clock.GetUtcNow());
        return await observeTarget(cancellationToken).ConfigureAwait(false) != origin.Identity
            ? throw Invalid()
            : new(GrantToken, this, bundle, plans, proof, schema, grant, Epochs);
    }

    internal async Task<ActiveGrant?> TryReadPublishedAsync(SourceBackedLocalRepairAdmissionBundle bundle,
        PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        long counter, CancellationToken cancellationToken)
    {
        bundle = Snapshot(bundle); plans = Snapshot(plans); proof = Snapshot(proof); schema = Snapshot(schema);
        return counter < 1
            ? throw Invalid()
            : await gateway.ReadAsync(GrantName(bundle.Admission.ClaimId, counter), cancellationToken).ConfigureAwait(false) is null
            ? null
            : await ReadAsync(bundle, plans, proof, schema, counter, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<IReadOnlyList<SourceBackedLocalRepairAuthorizationEpoch>> ReadEpochsProvenanceAsync(
        SourceBackedLocalRepairAdmissionBundle bundle, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, long counter,
        CancellationToken cancellationToken)
    {
        bundle = Snapshot(bundle); plans = Snapshot(plans); proof = Snapshot(proof); schema = Snapshot(schema);
        var origin = await ReadOriginalAsync(bundle, plans, proof, schema, cancellationToken).ConfigureAwait(false);
        if (counter == 0)
        {
            await RequireLatestAsync(origin.Claim.ClaimId, 0, cancellationToken).ConfigureAwait(false);
            return [OriginalEpoch(origin.Original)];
        }

        var (_, Epochs) = await ReadChainAsync(origin, plans, proof, schema, counter, cancellationToken).ConfigureAwait(false);
        await RequireLatestAsync(origin.Claim.ClaimId, counter, cancellationToken).ConfigureAwait(false);
        return Epochs;
    }

    private async Task<(IReadOnlyList<SourceBackedLocalRepairRenewalGrant> Grants,
        IReadOnlyList<SourceBackedLocalRepairAuthorizationEpoch> Epochs)> ReadChainAsync(OriginalContext origin,
        PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, long counter, CancellationToken cancellationToken)
    {
        if (counter < 1) { throw Invalid(); }
        // Probe the requested retained object before walking its bounded actual chain.
        _ = await RequiredAsync(GrantName(origin.Claim.ClaimId, counter), cancellationToken).ConfigureAwait(false);
        var grants = new List<SourceBackedLocalRepairRenewalGrant>();
        var epochs = new List<SourceBackedLocalRepairAuthorizationEpoch> { OriginalEpoch(origin.Original) };
        SourceBackedLocalRepairRenewalGrant? previous = null;
        for (long index = 1; index <= counter; index++)
        {
            RolloverClaimObject retained = await RequiredAsync(GrantName(origin.Claim.ClaimId, index), cancellationToken).ConfigureAwait(false);
            RequireObject(retained, origin.Claim.ExpiresAtUtc);
            SourceBackedLocalRepairRenewalGrant value;
            try { value = JsonSerializer.Deserialize<SourceBackedLocalRepairRenewalGrant>(retained.Content) ?? throw Invalid(); }
            catch (JsonException) { throw Invalid(); }
            if (value.Counter != index || retained.CreatedAtUtc < value.IssuedAtUtc ||
                retained.CreatedAtUtc >= value.ExpiresAtUtc) { throw Invalid(); }
            SourceBackedLocalRepairContinuation? basis = value.BasisContinuationOrdinal == 0 ? null :
                await continuations.ReadProvenanceAsync(origin.Claim.ClaimId, origin.Claim.AdmissionSha256,
                    value.BasisContinuationOrdinal, origin.Original.Authorization, clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
            // This authenticated historical check is signature provenance, never current authority.
            SourceBackedLocalRepairRenewalPolicy.Verify(value, origin.Original, origin.Object.Generation,
                origin.Claim, basis, previous, plans, proof, schema, origin.Identity, trust, pins, value.IssuedAtUtc);
            await MigrationAuthorizationReservation.RequireAsync(gateway, value.Authorization.AuthorizationId,
                origin.Claim.ClaimId, value.Counter, SourceBackedLocalRepairRenewalPolicy.ComputeSha256(value),
                origin.Claim.ExpiresAtUtc, cancellationToken).ConfigureAwait(false);
            grants.Add(value);
            epochs.Add(new(value.Authorization, value.BasisContinuationOrdinal, value.IssuedAtUtc, value.ExpiresAtUtc));
            previous = value;
        }
        return (grants, epochs);
    }

    private async Task<OriginalContext> ReadOriginalAsync(SourceBackedLocalRepairAdmissionBundle bundle,
        PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        await RequirePolicyAsync(cancellationToken).ConfigureAwait(false);
        HistoricalCurrentLocalObservation identity = await observeTarget(cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairClaim claim = await claims.ReadAsync(bundle.Admission.ClaimId,
            SourceBackedLocalRepairAdmissionPolicy.ComputeSha256(bundle.Admission), clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
        RolloverClaimObject retained = await RequiredAsync(OriginalName(claim.ClaimId), cancellationToken).ConfigureAwait(false);
        RequireObject(retained, claim.ExpiresAtUtc);
        SourceBackedLocalRepairOriginalAuthority original;
        try { original = JsonSerializer.Deserialize<SourceBackedLocalRepairOriginalAuthority>(retained.Content) ?? throw Invalid(); }
        catch (JsonException) { throw Invalid(); }
        if (JsonSerializer.Serialize(original.Admission) != JsonSerializer.Serialize(bundle.Admission) ||
            JsonSerializer.Serialize(original.Capsule) != JsonSerializer.Serialize(bundle.Capsule) ||
            JsonSerializer.Serialize(SourceBackedLocalRepairAdmissionPolicy.ExpectedClaim(original.Admission)) != JsonSerializer.Serialize(claim) ||
            original.TerminalPin != terminalPin ||
            retained.CreatedAtUtc < original.Admission.IssuedAtUtc || retained.CreatedAtUtc >= original.Admission.ExpiresAtUtc)
        {
            throw Invalid();
        }
        SourceBackedLocalRepairRenewalPolicy.VerifyOriginalProvenance(original, plans, proof, schema, identity, trust, pins);
        await MigrationAuthorizationReservation.RequireAsync(gateway, original.Authorization.AuthorizationId,
            claim.ClaimId, 0, SourceBackedLocalRepairRenewalPolicy.OriginalSha256(original), claim.ExpiresAtUtc,
            cancellationToken).ConfigureAwait(false);
        return await observeTarget(cancellationToken).ConfigureAwait(false) != identity
            ? throw Invalid()
            : new(original, retained, claim, identity);
    }

    private static SourceBackedLocalRepairAuthorizationEpoch OriginalEpoch(SourceBackedLocalRepairOriginalAuthority original)
    {
        return new(original.Authorization, 1, original.Admission.IssuedAtUtc,
            new[] { original.Admission.ExpiresAtUtc, original.Capsule.ExpiresAtUtc, original.Authorization.ExpiresAtUtc }.Min());
    }

    private async Task RequireLatestAsync(Guid claim, long counter, CancellationToken cancellationToken)
    {
        if (await gateway.ReadAsync(GrantName(claim, checked(counter + 1)), cancellationToken).ConfigureAwait(false) is not null)
        {
            throw Invalid();
        }
    }

    private async Task<SourceBackedLocalRepairClaim> ReadCurrentClaimAsync(Guid claimId, string admissionSha256,
        CancellationToken cancellationToken)
    {
        return await claims.ReadAsync(claimId, admissionSha256,
            clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
    }

    private async Task RequirePolicyAsync(CancellationToken cancellationToken)
    {
        RolloverClaimBucketPolicy policy = await gateway.ReadPolicyAsync(cancellationToken).ConfigureAwait(false);
        if (!policy.RetentionLocked || policy.RetentionSeconds < ImmutableRolloverClaimStore.MinimumRetentionSeconds ||
            !policy.UniformBucketAccess || policy.VersioningEnabled) { throw Invalid(); }
    }

    private async Task<RolloverClaimObject> RequiredAsync(string name, CancellationToken cancellationToken)
    {
        return await gateway.ReadAsync(name, cancellationToken).ConfigureAwait(false) ?? throw Invalid();
    }

    private static void RequireObject(RolloverClaimObject value, DateTimeOffset expires)
    {
        if (value.Generation <= 0 || value.CreatedAtUtc.Offset != TimeSpan.Zero || value.RetentionExpiresAtUtc.Offset != TimeSpan.Zero ||
            value.RetentionExpiresAtUtc < expires || value.Content.Length == 0) { throw Invalid(); }
    }

    private static string OriginalName(Guid claim)
    {
        return "source-backed-local-repair/v1/original-authority/" + claim.ToString("D");
    }

    private static string GrantName(Guid claim, long counter)
    {
        return "source-backed-local-repair/v1/renewals/" + claim.ToString("D") + "/" +
            counter.ToString("D8", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static T Snapshot<T>(T value)
    {
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value)) ?? throw Invalid();
    }

    private static DeltaExecutionException Invalid()
    {
        return SourceBackedLocalRepairRenewalPolicy.Invalid();
    }

    private sealed record OriginalContext(SourceBackedLocalRepairOriginalAuthority Original,
        RolloverClaimObject Object, SourceBackedLocalRepairClaim Claim, HistoricalCurrentLocalObservation Identity);
}

/// <summary>
/// Global create-only reservation for newly issued source-repair authorizations. This does not
/// assert that older historical authorizations, issued before this protocol, were reserved.
/// </summary>
internal static class MigrationAuthorizationReservation
{
    internal static async Task ReserveAsync(IRolloverClaimObjectGateway gateway, Guid authorizationId,
        Guid claimId, long counter, string authoritySha256, DateTimeOffset expires, CancellationToken cancellationToken)
    {
        byte[] expected = Bytes(authorizationId, claimId, counter, authoritySha256);
        RolloverClaimObject? created = null;
        try { created = await gateway.CreateOnlyAsync(Name(authorizationId), expected, cancellationToken).ConfigureAwait(false); }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            // Exact same-epoch readback is the sole permitted idempotent retry.
            await RequireAsync(gateway, authorizationId, claimId, counter, authoritySha256, expires,
                cancellationToken).ConfigureAwait(false);
        }
        RolloverClaimObject read = await RequiredAsync(gateway, authorizationId, cancellationToken).ConfigureAwait(false);
        Require(read, expected, expires);
        if (created is not null)
        {
            Require(created, expected, expires);
            if (created.Generation != read.Generation) { throw SourceBackedLocalRepairRenewalPolicy.Invalid(); }
        }
    }

    internal static async Task RequireAsync(IRolloverClaimObjectGateway gateway, Guid authorizationId,
        Guid claimId, long counter, string authoritySha256, DateTimeOffset expires, CancellationToken cancellationToken)
    {
        Require(await RequiredAsync(gateway, authorizationId, cancellationToken).ConfigureAwait(false),
            Bytes(authorizationId, claimId, counter, authoritySha256), expires);
    }

    private static byte[] Bytes(Guid authorizationId, Guid claimId, long counter, string authoritySha256)
    {
        return authorizationId == Guid.Empty || claimId == Guid.Empty || counter < 0 ||
            authoritySha256 is not { Length: 64 } || !authoritySha256.All(char.IsAsciiHexDigit)
            ? throw SourceBackedLocalRepairRenewalPolicy.Invalid()
            : JsonSerializer.SerializeToUtf8Bytes(new Reservation("1.0", "source-backed-local-repair",
            authorizationId, claimId, counter, authoritySha256));
    }

    private static string Name(Guid authorizationId)
    {
        return "migration-authorization/v1/reservations/" + authorizationId.ToString("D");
    }

    private static async Task<RolloverClaimObject> RequiredAsync(IRolloverClaimObjectGateway gateway,
            Guid authorizationId, CancellationToken cancellationToken)
    {
        return await gateway.ReadAsync(Name(authorizationId), cancellationToken).ConfigureAwait(false) ??
                throw SourceBackedLocalRepairRenewalPolicy.Invalid();
    }

    private static void Require(RolloverClaimObject value, byte[] expected, DateTimeOffset expires)
    {
        if (value.Generation <= 0 || value.CreatedAtUtc.Offset != TimeSpan.Zero || value.RetentionExpiresAtUtc.Offset != TimeSpan.Zero ||
            value.RetentionExpiresAtUtc < expires || !value.Content.AsSpan().SequenceEqual(expected))
        {
            throw SourceBackedLocalRepairRenewalPolicy.Invalid();
        }
    }
    private sealed record Reservation(string SchemaVersion, string Kind, Guid AuthorizationId,
        Guid ClaimId, long Counter, string AuthoritySha256);
}
