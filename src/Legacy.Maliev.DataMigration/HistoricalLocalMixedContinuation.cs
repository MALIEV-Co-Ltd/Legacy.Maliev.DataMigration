using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>
/// A read-only projection that a future durable claim reader must authenticate.
/// Caller-created instances are not execution authority.
/// </summary>
public sealed record HistoricalLocalRolloverClaimSnapshot(
    Guid ClaimId,
    string InitialAttestationSha256,
    string FuturePlanSha256,
    string TargetGeneration,
    long NextContinuationOrdinal,
    IReadOnlyList<HistoricalLocalMetadataBinding> InitialMetadata);

public enum HistoricalLocalRolloverDatabasePhase
{
    Prior,
    Adopted,
}

/// <summary>PII-free observed metadata; an adopted journal hash is not a row receipt.</summary>
public sealed record HistoricalLocalRolloverDatabaseState(
    string Database,
    HistoricalLocalRolloverDatabasePhase Phase,
    string PriorMetadataSha256,
    string? AdoptionJournalSha256);

/// <summary>
/// Signed prospective evidence for a mixed 23-database state. It never grants
/// fence adoption, DML, replay, or completion authority.
/// </summary>
public sealed record HistoricalLocalMixedContinuation(
    string SchemaVersion,
    Guid ClaimId,
    string InitialAttestationSha256,
    string FuturePlanSha256,
    string TargetGeneration,
    Guid AuthorizationId,
    long ContinuationOrdinal,
    IReadOnlyList<HistoricalLocalRolloverDatabaseState> Databases,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string AttestationKeyId,
    string? AttestationSignature)
{
    public static bool AuthorizesExecution => false;
}

public sealed record HistoricalLocalMixedContinuationReview(
    Guid ClaimId,
    long ContinuationOrdinal,
    int PriorDatabases,
    int AdoptedDatabases,
    string ContinuationSha256)
{
    public static bool AuthorizesExecution => false;
}

public static class HistoricalLocalMixedContinuationCanonicalizer
{
    public static byte[] CreatePayload(HistoricalLocalMixedContinuation continuation)
    {
        ArgumentNullException.ThrowIfNull(continuation);
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(continuation with { AttestationSignature = null });
        return [.. "legacy-maliev-historical-local-mixed-continuation-v1\0"u8, .. json];
    }

    public static string ComputeSha256(HistoricalLocalMixedContinuation continuation)
    {
        return Convert.ToHexString(SHA256.HashData(CreatePayload(continuation))).ToLowerInvariant();
    }
}

/// <summary>
/// Pure comparison only. The claim snapshot and database observations must later
/// come from authenticated durable/read-only readers; this method does not read them.
/// </summary>
public static class HistoricalLocalMixedContinuationVerifier
{
    public static HistoricalLocalMixedContinuationReview Verify(
        HistoricalLocalMixedContinuation? continuation,
        HistoricalLocalRolloverClaimSnapshot? knownClaim,
        IReadOnlyList<HistoricalLocalRolloverDatabaseState>? observedDatabases,
        PairedLocalTransitionAuthorization? authorization,
        IReceiptAttestationTrustStore trust,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(trust);
        if (continuation is null || knownClaim is null || observedDatabases is null ||
            authorization is null || continuation.SchemaVersion != "1.0" ||
            knownClaim.ClaimId == Guid.Empty || continuation.ClaimId != knownClaim.ClaimId ||
            !Fixed(continuation.InitialAttestationSha256, knownClaim.InitialAttestationSha256) ||
            !Fixed(continuation.FuturePlanSha256, knownClaim.FuturePlanSha256) ||
            !Fixed(authorization.PersistentPlanSha256, knownClaim.FuturePlanSha256) ||
            continuation.TargetGeneration != knownClaim.TargetGeneration ||
            continuation.AuthorizationId == Guid.Empty ||
            continuation.AuthorizationId != authorization.AuthorizationId ||
            continuation.ContinuationOrdinal <= 0 ||
            continuation.ContinuationOrdinal != knownClaim.NextContinuationOrdinal ||
            !ValidTime(continuation.IssuedAtUtc, continuation.ExpiresAtUtc, nowUtc) ||
            !ValidTime(authorization.IssuedAtUtc, authorization.ExpiresAtUtc, nowUtc) ||
            continuation.IssuedAtUtc < authorization.IssuedAtUtc ||
            continuation.ExpiresAtUtc > authorization.ExpiresAtUtc ||
            !VerifySignature(continuation.AttestationKeyId, continuation.AttestationSignature,
                HistoricalLocalMixedContinuationCanonicalizer.CreatePayload(continuation), trust) ||
            !VerifySignature(authorization.AttestationKeyId, authorization.AttestationSignature,
                PairedLocalTransitionAuthorizationCanonicalizer.CreatePayload(authorization), trust) ||
            !DistinctSigner(continuation.AttestationKeyId, authorization.AttestationKeyId, trust) ||
            !ValidDatabases(knownClaim.InitialMetadata, continuation.Databases, observedDatabases))
        {
            throw Invalid();
        }

        int adopted = continuation.Databases.Count(database =>
            database.Phase == HistoricalLocalRolloverDatabasePhase.Adopted);
        return new(knownClaim.ClaimId, continuation.ContinuationOrdinal,
            DatabaseInventory.ActiveDatabases.Count - adopted, adopted,
            HistoricalLocalMixedContinuationCanonicalizer.ComputeSha256(continuation));
    }

    private static bool ValidDatabases(
        IReadOnlyList<HistoricalLocalMetadataBinding>? initial,
        IReadOnlyList<HistoricalLocalRolloverDatabaseState>? signed,
        IReadOnlyList<HistoricalLocalRolloverDatabaseState> observed)
    {
        if (initial is null || signed is null ||
            !initial.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !signed.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !observed.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            return false;
        }
        for (int index = 0; index < initial.Count; index++)
        {
            HistoricalLocalRolloverDatabaseState state = signed[index];
            if (initial[index].State != PairedLocalTransitionMetadataState.SettledPrior ||
                state != observed[index] ||
                !Fixed(initial[index].FingerprintSha256, state.PriorMetadataSha256) ||
                !(state.Phase switch
                {
                    HistoricalLocalRolloverDatabasePhase.Prior => state.AdoptionJournalSha256 is null,
                    HistoricalLocalRolloverDatabasePhase.Adopted => Hash(state.AdoptionJournalSha256),
                    _ => false,
                }))
            {
                return false;
            }
        }
        return true;
    }

    private static bool ValidTime(DateTimeOffset issued, DateTimeOffset expires, DateTimeOffset now)
    {
        return issued.Offset == TimeSpan.Zero && expires.Offset == TimeSpan.Zero && now.Offset == TimeSpan.Zero &&
        issued <= now && now < expires && expires > issued &&
        expires - issued <= TimeSpan.FromMinutes(15);
    }

    private static bool DistinctSigner(string continuationKey, string authorizationKey,
        IReceiptAttestationTrustStore trust)
    {
        return trust.TryGetPublicKeyFingerprintSha256(continuationKey, out string continuation) &&
        trust.TryGetPublicKeyFingerprintSha256(authorizationKey, out string authorization) &&
        !Fixed(continuation, authorization);
    }

    private static bool VerifySignature(string keyId, string? signature, byte[] payload,
        IReceiptAttestationTrustStore trust)
    {
        try
        {
            return !string.IsNullOrWhiteSpace(keyId) && !string.IsNullOrWhiteSpace(signature) &&
                trust.Verify(keyId, payload, Convert.FromBase64String(signature));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool Fixed(string? left, string? right)
    {
        return Hash(left) && Hash(right) &&
        CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(left!.ToLowerInvariant()), Encoding.ASCII.GetBytes(right!.ToLowerInvariant()));
    }

    private static bool Hash(string? value)
    {
        return value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
    }

    private static DeltaExecutionException Invalid()
    {
        return new(
        "delta_historical_local_mixed_continuation_invalid",
        "The read-only mixed LOCAL continuation evidence is incomplete or untrusted.");
    }
}
