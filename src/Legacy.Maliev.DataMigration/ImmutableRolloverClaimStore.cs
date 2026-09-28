using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Google.Cloud.Storage.V1;

namespace Legacy.Maliev.DataMigration;

internal sealed record RolloverClaimBucketPolicy(
    bool RetentionLocked, long RetentionSeconds, bool UniformBucketAccess, bool VersioningEnabled);

internal sealed record RolloverClaimObject(
    long Generation, DateTimeOffset CreatedAtUtc, DateTimeOffset RetentionExpiresAtUtc, byte[] Content);

internal interface IRolloverClaimObjectGateway
{
    Task<RolloverClaimBucketPolicy> ReadPolicyAsync(CancellationToken cancellationToken);
    Task<RolloverClaimObject> CreateOnlyAsync(string name, byte[] content, CancellationToken cancellationToken);
    Task<RolloverClaimObject?> ReadAsync(string name, CancellationToken cancellationToken);
}

/// <summary>Immutable, PII-free global claim; never an execution permit.</summary>
public sealed record ImmutableRolloverClaim(
    string SchemaVersion,
    Guid ClaimId,
    string InitialAttestationSha256,
    string HistoricalPlanSha256,
    string HistoricalReceiptSha256,
    string FuturePlanSha256,
    string TargetGeneration,
    string VolumeName,
    DateTimeOffset VolumeCreatedAtUtc,
    string SystemIdentifierSha256,
    IReadOnlyList<HistoricalLocalMetadataBinding> InitialMetadata,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc)
{
    public static bool AuthorizesExecution => false;
}

/// <summary>
/// Append-only, one-use claim reservations. Creation verifies fresh signed and
/// independently observed evidence. Internal reads verify retained object
/// bodies, but do not revalidate the signed attestation. This store is not a
/// database write permit or a complete authenticated continuation reader.
/// </summary>
public sealed class ImmutableRolloverClaimStore
{
    internal const long MinimumRetentionSeconds = 31_557_600;
    internal static readonly TimeSpan MaximumClaimAge = TimeSpan.FromDays(364);
    private const string Prefix = "claims/v1/";
    private readonly IRolloverClaimObjectGateway _gateway;

    internal ImmutableRolloverClaimStore(IRolloverClaimObjectGateway gateway)
    {
        _gateway = gateway ?? throw new ArgumentNullException(nameof(gateway));
    }

    public static async Task<ImmutableRolloverClaimStore> CreateWithApplicationDefaultCredentialsAsync(
        string bucket, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(bucket))
        {
            throw Invalid("delta_rollover_claim_bucket_invalid");
        }
        StorageClient client = await StorageClient.CreateAsync().ConfigureAwait(false);
        var store = new ImmutableRolloverClaimStore(new GoogleCloudRolloverClaimGateway(client, bucket));
        await store.RequirePolicyAsync(cancellationToken).ConfigureAwait(false);
        return store;
    }

    public async Task<ImmutableRolloverClaim> CreateFromFreshEvidenceAsync(
        HistoricalLocalContinuityAttestation attestation,
        DeltaSynchronizationPlan historicalPlan,
        Exact23DeltaReconciliationResult historicalReceipt,
        FreshSchemaPlan historicalSchema,
        HistoricalPairedLocalCurrentTargetReview signedReview,
        Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observeCurrentTarget,
        IDeltaReconciliationInspector currentTarget,
        Func<CancellationToken, Task<IReadOnlyList<HistoricalLocalMetadataBinding>>> observePriorMetadata,
        HistoricalCurrentLocalObservation expectedObservation,
        string futurePlanSha256,
        Guid futureAuthorizationId,
        IReceiptAttestationTrustStore trust,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clock);
        HistoricalLocalContinuityReview review = await HistoricalLocalContinuityAttestationVerifier
            .VerifyFreshAsync(attestation, historicalPlan, historicalReceipt, historicalSchema,
                signedReview, observeCurrentTarget, currentTarget, observePriorMetadata,
                futurePlanSha256, futureAuthorizationId, trust, clock, cancellationToken)
            .ConfigureAwait(false);
        HistoricalCurrentLocalObservation finalObservation = await observeCurrentTarget(cancellationToken)
            .ConfigureAwait(false);
        if (finalObservation != expectedObservation ||
            attestation.CurrentDockerGeneration != expectedObservation.DockerGeneration ||
            !Fixed(expectedObservation.SystemIdentifierSha256,
                historicalPlan.TargetAuthority?.SystemIdentifierSha256))
        {
            throw Invalid("delta_rollover_claim_identity_changed");
        }
        DateTimeOffset nowUtc = clock.GetUtcNow();
        var claim = new ImmutableRolloverClaim("1.0", attestation.AttestationId,
            review.AttestationSha256, attestation.HistoricalPlanSha256,
            attestation.HistoricalReceiptSha256, futurePlanSha256,
            expectedObservation.DockerGeneration, expectedObservation.VolumeName,
            expectedObservation.VolumeCreatedAtUtc, expectedObservation.SystemIdentifierSha256,
            attestation.PriorMetadata, nowUtc, nowUtc.Add(MaximumClaimAge));
        return await ReserveVerifiedAsync(claim, nowUtc, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<ImmutableRolloverClaim> ReserveVerifiedAsync(
        ImmutableRolloverClaim claim, DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        await RequirePolicyAsync(cancellationToken).ConfigureAwait(false);
        RequireClaimShape(claim, nowUtc);
        byte[] claimBytes = JsonSerializer.SerializeToUtf8Bytes(claim);
        string claimSha256 = Sha256(claimBytes);
        byte[] reservation = JsonSerializer.SerializeToUtf8Bytes(new ClaimReservation(
            "1.0", claim.ClaimId, claimSha256));
        await CreateAndVerifyAsync(OldReceiptName(claim), reservation, claim.ExpiresAtUtc,
            cancellationToken).ConfigureAwait(false);
        await CreateAndVerifyAsync(TargetGenerationName(claim), reservation, claim.ExpiresAtUtc,
            cancellationToken).ConfigureAwait(false);
        await CreateAndVerifyAsync(FuturePlanName(claim), reservation, claim.ExpiresAtUtc,
            cancellationToken).ConfigureAwait(false);
        await CreateAndVerifyAsync(ActiveName(claim.ClaimId), claimBytes, claim.ExpiresAtUtc,
            cancellationToken).ConfigureAwait(false);
        return await ReadAsync(claim.ClaimId, claim.InitialAttestationSha256, nowUtc,
            cancellationToken).ConfigureAwait(false);
    }

    internal async Task<ImmutableRolloverClaim> ReadAsync(Guid claimId,
        string expectedAttestationSha256, DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        await RequirePolicyAsync(cancellationToken).ConfigureAwait(false);
        if (claimId == Guid.Empty || !Hash(expectedAttestationSha256))
        {
            throw Invalid("delta_rollover_claim_identity_invalid");
        }
        RolloverClaimObject active = await ReadRequiredAsync(ActiveName(claimId),
            cancellationToken).ConfigureAwait(false);
        ImmutableRolloverClaim claim;
        try
        {
            claim = JsonSerializer.Deserialize<ImmutableRolloverClaim>(active.Content)
                ?? throw Invalid("delta_rollover_claim_object_invalid");
        }
        catch (JsonException)
        {
            throw Invalid("delta_rollover_claim_object_invalid");
        }
        RequireClaimShape(claim, nowUtc);
        if (claim.ClaimId != claimId || !Fixed(claim.InitialAttestationSha256, expectedAttestationSha256))
        {
            throw Invalid("delta_rollover_claim_identity_invalid");
        }
        RequireRetained(active, claim.ExpiresAtUtc);
        byte[] reservation = JsonSerializer.SerializeToUtf8Bytes(new ClaimReservation(
            "1.0", claimId, Sha256(active.Content)));
        foreach (string name in new[]
        {
            OldReceiptName(claim), TargetGenerationName(claim), FuturePlanName(claim),
        })
        {
            RolloverClaimObject observed = await ReadRequiredAsync(name, cancellationToken)
                .ConfigureAwait(false);
            RequireRetained(observed, claim.ExpiresAtUtc);
            if (!observed.Content.AsSpan().SequenceEqual(reservation))
            {
                throw Invalid("delta_rollover_claim_reservation_invalid");
            }
        }
        return claim;
    }

    /// <summary>Storage-level one-use ordinal; this does not verify a signed continuation.</summary>
    internal async Task ReserveOrdinalAsync(ImmutableRolloverClaim claim, long ordinal,
        string continuationSha256, Guid authorizationId, DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        ImmutableRolloverClaim observed = await ReadAsync(claim.ClaimId,
            claim.InitialAttestationSha256, nowUtc, cancellationToken).ConfigureAwait(false);
        if (!JsonSerializer.SerializeToUtf8Bytes(observed).AsSpan()
                .SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(claim)) ||
            ordinal is < 1 or > 999_999 ||
            !Hash(continuationSha256) || authorizationId == Guid.Empty)
        {
            throw Invalid("delta_rollover_claim_ordinal_invalid");
        }
        if (ordinal > 1)
        {
            RolloverClaimObject previous = await ReadRequiredAsync(OrdinalName(claim.ClaimId,
                ordinal - 1), cancellationToken).ConfigureAwait(false);
            RequireRetained(previous, claim.ExpiresAtUtc);
            ClaimOrdinal? prior;
            try { prior = JsonSerializer.Deserialize<ClaimOrdinal>(previous.Content); }
            catch (JsonException) { throw Invalid("delta_rollover_claim_ordinal_invalid"); }
            if (prior is null || prior.SchemaVersion != "1.0" ||
                prior.ClaimId != claim.ClaimId || prior.Ordinal != ordinal - 1 ||
                !Hash(prior.ContinuationSha256) || prior.AuthorizationId == Guid.Empty ||
                prior.CreatedAtUtc.Offset != TimeSpan.Zero || prior.CreatedAtUtc > nowUtc)
            {
                throw Invalid("delta_rollover_claim_ordinal_invalid");
            }
        }
        byte[] content = JsonSerializer.SerializeToUtf8Bytes(new ClaimOrdinal(
            "1.0", claim.ClaimId, ordinal, continuationSha256,
            authorizationId, nowUtc));
        await CreateAndVerifyAsync(OrdinalName(claim.ClaimId, ordinal), content,
            claim.ExpiresAtUtc, cancellationToken).ConfigureAwait(false);
    }

    private async Task CreateAndVerifyAsync(string name, byte[] bytes,
        DateTimeOffset expiresAtUtc, CancellationToken cancellationToken)
    {
        RolloverClaimObject created = await _gateway.CreateOnlyAsync(name, bytes, cancellationToken)
            .ConfigureAwait(false);
        RolloverClaimObject readback = await ReadRequiredAsync(name, cancellationToken)
            .ConfigureAwait(false);
        RequireRetained(created, expiresAtUtc);
        RequireRetained(readback, expiresAtUtc);
        if (created.Generation != readback.Generation ||
            !readback.Content.AsSpan().SequenceEqual(bytes))
        {
            throw Invalid("delta_rollover_claim_readback_invalid");
        }
    }

    private async Task<RolloverClaimObject> ReadRequiredAsync(string name,
        CancellationToken cancellationToken)
    {
        return await _gateway.ReadAsync(name, cancellationToken).ConfigureAwait(false)
        ?? throw Invalid("delta_rollover_claim_object_missing");
    }

    private async Task RequirePolicyAsync(CancellationToken cancellationToken)
    {
        RolloverClaimBucketPolicy policy = await _gateway.ReadPolicyAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!policy.RetentionLocked || policy.RetentionSeconds < MinimumRetentionSeconds ||
            !policy.UniformBucketAccess || policy.VersioningEnabled)
        {
            throw Invalid("delta_rollover_claim_bucket_policy_invalid");
        }
    }

    private static void RequireClaimShape(ImmutableRolloverClaim claim, DateTimeOffset nowUtc)
    {
        if (claim.SchemaVersion != "1.0" || claim.ClaimId == Guid.Empty ||
            !Hash(claim.InitialAttestationSha256) || !Hash(claim.HistoricalPlanSha256) ||
            !Hash(claim.HistoricalReceiptSha256) || !Hash(claim.FuturePlanSha256) ||
            !Hash(claim.SystemIdentifierSha256) || claim.VolumeName !=
                "legacy-maliev-exact23-postgres-data" ||
            !ValidTargetGeneration(claim.TargetGeneration, claim.VolumeCreatedAtUtc) ||
            claim.VolumeCreatedAtUtc.Offset != TimeSpan.Zero ||
            claim.CreatedAtUtc.Offset != TimeSpan.Zero || claim.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            nowUtc.Offset != TimeSpan.Zero || nowUtc < claim.CreatedAtUtc ||
            nowUtc >= claim.ExpiresAtUtc ||
            claim.ExpiresAtUtc - claim.CreatedAtUtc != MaximumClaimAge ||
            claim.InitialMetadata is null ||
            !claim.InitialMetadata.Select(item => item.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            claim.InitialMetadata.Any(item => item.State !=
                PairedLocalTransitionMetadataState.SettledPrior || !Hash(item.FingerprintSha256)))
        {
            throw Invalid("delta_rollover_claim_shape_invalid");
        }
    }

    private static void RequireRetained(RolloverClaimObject value, DateTimeOffset expiresAtUtc)
    {
        if (value.Generation <= 0 || value.CreatedAtUtc.Offset != TimeSpan.Zero ||
            value.RetentionExpiresAtUtc.Offset != TimeSpan.Zero ||
            value.RetentionExpiresAtUtc < expiresAtUtc || value.Content.Length == 0)
        {
            throw Invalid("delta_rollover_claim_retention_invalid");
        }
    }

    private static string OldReceiptName(ImmutableRolloverClaim claim)
    {
        return Prefix + "old-receipts/" + claim.HistoricalReceiptSha256;
    }

    private static string FuturePlanName(ImmutableRolloverClaim claim)
    {
        return Prefix + "future-plans/" + claim.FuturePlanSha256 + "/" +
        Sha256(Encoding.UTF8.GetBytes(claim.TargetGeneration));
    }

    private static string TargetGenerationName(ImmutableRolloverClaim claim)
    {
        return Prefix + "target-generations/" +
            Sha256(Encoding.UTF8.GetBytes(claim.TargetGeneration));
    }

    private static string ActiveName(Guid claimId)
    {
        return Prefix + "active/" + claimId.ToString("D");
    }

    private static string OrdinalName(Guid claimId, long ordinal)
    {
        return Prefix + "ordinals/" + claimId.ToString("D") + "/" +
        ordinal.ToString("D20", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string Sha256(byte[] bytes)
    {
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static bool Hash(string? value)
    {
        return value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
    }

    private static bool ValidTargetGeneration(string? generation, DateTimeOffset volumeCreatedAtUtc)
    {
        string[] parts = generation?.Split(':') ?? [];
        return parts.Length == 5 && parts[0] == "docker" && Hash(parts[1]) &&
            parts.Skip(2).All(value => long.TryParse(value,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out long milliseconds) &&
                milliseconds > 0) &&
            volumeCreatedAtUtc.Offset == TimeSpan.Zero &&
            parts[4] == volumeCreatedAtUtc.ToUnixTimeMilliseconds().ToString(
                System.Globalization.CultureInfo.InvariantCulture);
    }

    private static bool Fixed(string? left, string? right)
    {
        return Hash(left) && Hash(right) && CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(left!.ToLowerInvariant()),
            Encoding.ASCII.GetBytes(right!.ToLowerInvariant()));
    }

    private static DeltaExecutionException Invalid(string code)
    {
        return new(code, "The immutable LOCAL rollover claim is incomplete or untrusted.");
    }

    private sealed record ClaimReservation(string SchemaVersion, Guid ClaimId, string ClaimSha256);
    private sealed record ClaimOrdinal(string SchemaVersion, Guid ClaimId, long Ordinal,
        string ContinuationSha256, Guid AuthorizationId, DateTimeOffset CreatedAtUtc);
}

internal sealed class GoogleCloudRolloverClaimGateway(StorageClient client, string bucket)
    : IRolloverClaimObjectGateway
{
    private readonly StorageClient _client = client ?? throw new ArgumentNullException(nameof(client));
    private readonly string _bucket = bucket;

    public async Task<RolloverClaimBucketPolicy> ReadPolicyAsync(CancellationToken cancellationToken)
    {
        Google.Apis.Storage.v1.Data.Bucket state = await _client.GetBucketAsync(_bucket,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return new(state.RetentionPolicy?.IsLocked == true,
            checked(state.RetentionPolicy?.RetentionPeriod ?? 0),
            state.IamConfiguration?.UniformBucketLevelAccess?.Enabled == true,
            state.Versioning?.Enabled == true);
    }

    public async Task<RolloverClaimObject> CreateOnlyAsync(string name, byte[] content,
        CancellationToken cancellationToken)
    {
        using var source = new MemoryStream(content, writable: false);
        Google.Apis.Storage.v1.Data.Object created;
        try
        {
            created = await _client.UploadObjectAsync(new Google.Apis.Storage.v1.Data.Object
            {
                Bucket = _bucket,
                Name = name,
                ContentType = "application/json",
            }, source, new UploadObjectOptions { IfGenerationMatch = 0 },
                cancellationToken).ConfigureAwait(false);
        }
        catch (Google.GoogleApiException error) when (error.HttpStatusCode == HttpStatusCode.PreconditionFailed)
        {
            throw new DeltaExecutionException("delta_rollover_claim_conflict",
                "The immutable rollover claim or ordinal was already consumed.", error);
        }
        return State(created, content);
    }

    public async Task<RolloverClaimObject?> ReadAsync(string name,
        CancellationToken cancellationToken)
    {
        Google.Apis.Storage.v1.Data.Object metadata;
        try
        {
            metadata = await _client.GetObjectAsync(_bucket, name,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Google.GoogleApiException error) when (error.HttpStatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }
        if (metadata.Generation is null or > long.MaxValue)
        {
            throw new DeltaExecutionException("delta_rollover_claim_object_invalid",
                "The immutable rollover object has no valid generation.");
        }
        using var destination = new MemoryStream();
        _ = await _client.DownloadObjectAsync(_bucket, name, destination,
            new DownloadObjectOptions { Generation = checked(metadata.Generation.Value) },
            cancellationToken).ConfigureAwait(false);
        return State(metadata, destination.ToArray());
    }

    private static RolloverClaimObject State(Google.Apis.Storage.v1.Data.Object metadata,
        byte[] content)
    {
        return metadata.Generation is null || metadata.Generation > long.MaxValue ||
            metadata.TimeCreatedDateTimeOffset is null ||
            metadata.RetentionExpirationTimeDateTimeOffset is null
            ? throw new DeltaExecutionException("delta_rollover_claim_object_invalid",
                "The immutable rollover object lacks generation or retention metadata.")
            : new(checked(metadata.Generation.Value),
            metadata.TimeCreatedDateTimeOffset.Value.ToUniversalTime(),
            metadata.RetentionExpirationTimeDateTimeOffset.Value.ToUniversalTime(), content);
    }
}
