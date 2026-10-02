using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal enum SourceBackedLocalRepairPhase { Prior, Applied }

/// <summary>PII-free source repair state; marker hashes are evidence, never row authority.</summary>
internal sealed record SourceBackedLocalRepairState(string Database, SourceBackedLocalRepairPhase Phase,
    string PriorMetadataSha256, string? RepairMarkerSha256, string? CheckpointSha256, string? ReconciliationSha256);

/// <summary>Signed prospective source repair progress. No historical receipt continuity or write permission.</summary>
internal sealed record SourceBackedLocalRepairContinuation(string SchemaVersion, Guid ClaimId,
    string AdmissionSha256, string InitialPreimageSha256, string SourceCaptureSha256, string FuturePlanSha256,
    string TargetGeneration, Guid AuthorizationId, string AuthorizationSha256, long Ordinal, string? PreviousContinuationSha256,
    IReadOnlyList<SourceBackedLocalRepairState> Databases, DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc, string AttestationKeyId, string? AttestationSignature)
{
    internal static bool AuthorizesExecution => false;
}

/// <summary>Create-only retained evidence. Inputs require future trusted locked observations before any executor integration.</summary>
internal sealed class SourceBackedLocalRepairContinuationStore(IRolloverClaimObjectGateway gateway,
    SourceBackedLocalRepairClaimStore claims, IReceiptAttestationTrustStore trust,
    string authorizationKeyFingerprintSha256, string evidenceKeyFingerprintSha256)
{
    internal static byte[] Payload(SourceBackedLocalRepairContinuation value)
    {
        return [.. "legacy-maliev-source-repair-continuation-v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(value with { AttestationSignature = null })];
    }

    internal static string ComputeSha256(SourceBackedLocalRepairContinuation value)
    {
        return Convert.ToHexString(SHA256.HashData(Payload(value))).ToLowerInvariant();
    }

    internal async Task<SourceBackedLocalRepairContinuation> AppendAsync(
        SourceBackedLocalRepairContinuation continuation, PairedLocalTransitionAuthorization authorization,
        IReadOnlyList<SourceBackedLocalRepairState> observed, DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        if (continuation is null || authorization is null || observed is null) { throw Invalid(); }
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(continuation);
        continuation = JsonSerializer.Deserialize<SourceBackedLocalRepairContinuation>(bytes) ?? throw Invalid();
        observed = observed.ToArray();
        SourceBackedLocalRepairClaim claim = await claims.ReadAsync(continuation.ClaimId,
            continuation.AdmissionSha256, nowUtc, cancellationToken).ConfigureAwait(false);
        RequirePolicy(await gateway.ReadPolicyAsync(cancellationToken).ConfigureAwait(false));
        Verify(continuation, claim, authorization, nowUtc, true);
        if (!continuation.Databases.SequenceEqual(observed)) { throw Invalid(); }
        SourceBackedLocalRepairContinuation? previous = continuation.Ordinal == 1 ? null :
            await ReadAsync(continuation.ClaimId, continuation.AdmissionSha256, continuation.Ordinal - 1,
                authorization, nowUtc, cancellationToken).ConfigureAwait(false);
        RequireProgress(continuation, previous);
        string name = Name(continuation.ClaimId, continuation.Ordinal);
        RolloverClaimObject created = await gateway.CreateOnlyAsync(name, bytes, cancellationToken).ConfigureAwait(false);
        RolloverClaimObject read = await RequiredAsync(name, cancellationToken).ConfigureAwait(false);
        RequireRetained(created, claim);
        RequireRetained(read, claim);
        return created.Generation != read.Generation || !created.Content.AsSpan().SequenceEqual(bytes) ||
            !read.Content.AsSpan().SequenceEqual(bytes)
            ? throw Invalid()
            : await ReadAsync(continuation.ClaimId, continuation.AdmissionSha256, continuation.Ordinal,
            authorization, nowUtc, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<SourceBackedLocalRepairContinuation> ReadAsync(Guid claimId, string admissionSha256,
        long ordinal, PairedLocalTransitionAuthorization authorization, DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        if (ordinal is < 1 or > 24) { throw Invalid(); }
        SourceBackedLocalRepairClaim claim = await claims.ReadAsync(claimId, admissionSha256, nowUtc,
            cancellationToken).ConfigureAwait(false);
        RequirePolicy(await gateway.ReadPolicyAsync(cancellationToken).ConfigureAwait(false));
        SourceBackedLocalRepairContinuation? previous = null;
        for (long index = 1; index <= ordinal; index++)
        {
            RolloverClaimObject retained = await RequiredAsync(Name(claimId, index), cancellationToken).ConfigureAwait(false);
            RequireRetained(retained, claim);
            SourceBackedLocalRepairContinuation value;
            try { value = JsonSerializer.Deserialize<SourceBackedLocalRepairContinuation>(retained.Content) ?? throw Invalid(); }
            catch (JsonException) { throw Invalid(); }
            if (value.Ordinal != index || value.ClaimId != claimId) { throw Invalid(); }
            Verify(value, claim, authorization, nowUtc, index == ordinal);
            RequireProgress(value, previous);
            previous = value;
        }
        return previous!;
    }

    private void Verify(SourceBackedLocalRepairContinuation value, SourceBackedLocalRepairClaim claim,
        PairedLocalTransitionAuthorization authorization, DateTimeOffset now, bool requireFresh)
    {
        if (value.SchemaVersion != "1.0" || value.ClaimId != claim.ClaimId ||
            value.AdmissionSha256 != claim.AdmissionSha256 || value.InitialPreimageSha256 != claim.PreimageSha256 ||
            value.SourceCaptureSha256 != claim.SourceCaptureSha256 || value.FuturePlanSha256 != claim.FuturePlanSha256 ||
            value.TargetGeneration != claim.TargetGeneration || value.Ordinal is < 1 or > 24 ||
            authorization.SchemaVersion != "1.0" || authorization.AuthorizationId == Guid.Empty ||
            value.AuthorizationId != authorization.AuthorizationId || value.AuthorizationSha256 != AuthorizationHash(authorization) ||
            authorization.PersistentPlanSha256 != claim.FuturePlanSha256 ||
            authorization.TargetAuthority is null || authorization.TargetAuthority.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            authorization.TargetAuthority.SystemIdentifierSha256 != claim.SystemIdentifierSha256 ||
            !Time(authorization.IssuedAtUtc, authorization.ExpiresAtUtc, now, true) ||
            !Time(value.IssuedAtUtc, value.ExpiresAtUtc, now, requireFresh) ||
            value.IssuedAtUtc < authorization.IssuedAtUtc || value.ExpiresAtUtc > authorization.ExpiresAtUtc ||
            value.IssuedAtUtc < claim.CreatedAtUtc || value.ExpiresAtUtc > claim.ExpiresAtUtc ||
            !Hash(authorizationKeyFingerprintSha256) || !Hash(evidenceKeyFingerprintSha256) ||
            authorizationKeyFingerprintSha256 == evidenceKeyFingerprintSha256 ||
            !Signer(authorization.AttestationKeyId, authorizationKeyFingerprintSha256) ||
            !Signer(value.AttestationKeyId, evidenceKeyFingerprintSha256) ||
            !Signature(authorization.AttestationKeyId, authorization.AttestationSignature,
                PairedLocalTransitionAuthorizationCanonicalizer.CreatePayload(authorization)) ||
            !Signature(value.AttestationKeyId, value.AttestationSignature, Payload(value)) ||
            value.Databases is null || !value.Databases.Select(item => item?.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal)) { throw Invalid(); }
        for (int index = 0; index < value.Databases.Count; index++)
        {
            SourceBackedLocalRepairState state = value.Databases[index];
            if (state.PriorMetadataSha256 != claim.InitialMetadata[index].FingerprintSha256 ||
                !(state.Phase switch
                {
                    SourceBackedLocalRepairPhase.Prior => state.RepairMarkerSha256 is null && state.CheckpointSha256 is null && state.ReconciliationSha256 is null,
                    SourceBackedLocalRepairPhase.Applied => Hash(state.RepairMarkerSha256) && Hash(state.CheckpointSha256) && Hash(state.ReconciliationSha256),
                    _ => false,
                })) { throw Invalid(); }
        }
    }

    private static void RequireProgress(SourceBackedLocalRepairContinuation current, SourceBackedLocalRepairContinuation? prior)
    {
        int applied = checked((int)current.Ordinal - 1);
        if (prior is null ? current.Ordinal != 1 || current.PreviousContinuationSha256 is not null :
            current.Ordinal != prior.Ordinal + 1 || current.PreviousContinuationSha256 != ComputeSha256(prior) ||
            current.IssuedAtUtc < prior.IssuedAtUtc || current.AuthorizationId != prior.AuthorizationId)
        { throw Invalid(); }
        for (int index = 0; index < current.Databases.Count; index++)
        {
            SourceBackedLocalRepairState state = current.Databases[index];
            if (state.Phase != (index < applied ? SourceBackedLocalRepairPhase.Applied : SourceBackedLocalRepairPhase.Prior) ||
                (prior is not null && index != applied - 1 && state != prior.Databases[index])) { throw Invalid(); }
        }
    }

    internal static string AuthorizationHash(PairedLocalTransitionAuthorization authorization)
    {
        return Convert.ToHexString(SHA256.HashData(PairedLocalTransitionAuthorizationCanonicalizer.CreatePayload(authorization))).ToLowerInvariant();
    }

    private bool Signer(string keyId, string fingerprint)
    {
        return trust.TryGetPublicKeyFingerprintSha256(keyId, out string actual) && actual == fingerprint;
    }

    private bool Signature(string keyId, string? signature, byte[] payload)
    {
        try { return trust.Verify(keyId, payload, Convert.FromBase64String(signature ?? string.Empty)); }
        catch (Exception exception) when (exception is FormatException or CryptographicException) { return false; }
    }

    private static bool Time(DateTimeOffset issued, DateTimeOffset expires, DateTimeOffset now, bool fresh)
    {
        return issued.Offset == TimeSpan.Zero && expires.Offset == TimeSpan.Zero && now.Offset == TimeSpan.Zero &&
            issued <= now && expires > issued && expires - issued <= TimeSpan.FromMinutes(15) && (!fresh || now < expires);
    }

    private static bool Hash(string? value)
    {
        return value is { Length: 64 } && value.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }

    private static string Name(Guid claim, long ordinal)
    {
        return "source-backed-local-repair/v1/continuations/" + claim.ToString("D") + "/" +
            ordinal.ToString("D2", System.Globalization.CultureInfo.InvariantCulture);
    }

    private async Task<RolloverClaimObject> RequiredAsync(string name, CancellationToken cancellationToken)
    {
        return await gateway.ReadAsync(name, cancellationToken).ConfigureAwait(false) ?? throw Invalid();
    }

    private static void RequireRetained(RolloverClaimObject value, SourceBackedLocalRepairClaim claim)
    {
        if (value.Generation <= 0 || value.CreatedAtUtc.Offset != TimeSpan.Zero ||
            value.RetentionExpiresAtUtc.Offset != TimeSpan.Zero || value.RetentionExpiresAtUtc < claim.ExpiresAtUtc ||
            value.Content.Length == 0) { throw Invalid(); }
    }

    private static void RequirePolicy(RolloverClaimBucketPolicy value)
    {
        if (!value.RetentionLocked || value.RetentionSeconds < ImmutableRolloverClaimStore.MinimumRetentionSeconds ||
            !value.UniformBucketAccess || value.VersioningEnabled) { throw Invalid(); }
    }

    private static DeltaExecutionException Invalid()
    {
        return new("delta_source_repair_continuation_invalid", "The retained source-backed repair continuation is incomplete or untrusted.");
    }
}
