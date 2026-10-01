using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Retained source repair reservation; not historical continuity or execution authority.</summary>
public sealed record SourceBackedLocalRepairClaim(
    string SchemaVersion, Guid ClaimId, string AdmissionSha256, string PreimageSha256,
    string SourceCaptureSha256, string FuturePlanSha256, string TargetGeneration,
    string VolumeName, DateTimeOffset VolumeCreatedAtUtc, string SystemIdentifierSha256,
    IReadOnlyList<HistoricalLocalMetadataBinding> InitialMetadata,
    DateTimeOffset CreatedAtUtc, DateTimeOffset ExpiresAtUtc)
{
    public static bool AuthorizesExecution => false;
}

internal sealed class SourceBackedLocalRepairClaimStore(IRolloverClaimObjectGateway gateway)
{
    private const string Prefix = "source-backed-local-repair/v1/";
    private readonly IRolloverClaimObjectGateway _gateway = gateway ?? throw new ArgumentNullException(nameof(gateway));

    internal async Task<SourceBackedLocalRepairClaim> ReserveAsync(
        SourceBackedLocalRepairClaim claim, DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        await RequirePolicyAsync(cancellationToken).ConfigureAwait(false);
        RequireShape(claim, nowUtc);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(claim);
        byte[] reservation = JsonSerializer.SerializeToUtf8Bytes(
            new Reservation("1.0", claim.ClaimId, Sha256(bytes)));
        foreach (string name in ReservationNames(claim))
        {
            await CreateAsync(name, reservation, claim.ExpiresAtUtc, cancellationToken).ConfigureAwait(false);
        }
        await CreateAsync(ActiveName(claim.ClaimId), bytes, claim.ExpiresAtUtc, cancellationToken).ConfigureAwait(false);
        return await ReadAsync(claim.ClaimId, claim.AdmissionSha256, nowUtc, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<SourceBackedLocalRepairClaim> ReadAsync(Guid claimId, string admissionSha256,
        DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        await RequirePolicyAsync(cancellationToken).ConfigureAwait(false);
        if (claimId == Guid.Empty || !Hash(admissionSha256)) { throw Invalid("delta_source_repair_claim_identity_invalid"); }
        RolloverClaimObject active = await RequiredAsync(ActiveName(claimId), cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairClaim claim;
        try
        {
            claim = JsonSerializer.Deserialize<SourceBackedLocalRepairClaim>(active.Content)
                ?? throw Invalid("delta_source_repair_claim_object_invalid");
        }
        catch (JsonException) { throw Invalid("delta_source_repair_claim_object_invalid"); }
        RequireShape(claim, nowUtc);
        if (claim.ClaimId != claimId || claim.AdmissionSha256 != admissionSha256)
        {
            throw Invalid("delta_source_repair_claim_identity_invalid");
        }
        RequireRetained(active, claim.ExpiresAtUtc);
        byte[] reservation = JsonSerializer.SerializeToUtf8Bytes(
            new Reservation("1.0", claimId, Sha256(active.Content)));
        foreach (string name in ReservationNames(claim))
        {
            RolloverClaimObject observed = await RequiredAsync(name, cancellationToken).ConfigureAwait(false);
            RequireRetained(observed, claim.ExpiresAtUtc);
            if (!observed.Content.AsSpan().SequenceEqual(reservation))
            {
                throw Invalid("delta_source_repair_claim_reservation_invalid");
            }
        }
        return claim;
    }

    private async Task CreateAsync(string name, byte[] bytes, DateTimeOffset expiresAtUtc,
        CancellationToken cancellationToken)
    {
        RolloverClaimObject created = await _gateway.CreateOnlyAsync(name, bytes, cancellationToken).ConfigureAwait(false);
        RolloverClaimObject read = await RequiredAsync(name, cancellationToken).ConfigureAwait(false);
        RequireRetained(created, expiresAtUtc);
        RequireRetained(read, expiresAtUtc);
        if (created.Generation != read.Generation || !read.Content.AsSpan().SequenceEqual(bytes))
        {
            throw Invalid("delta_source_repair_claim_readback_invalid");
        }
    }

    private async Task<RolloverClaimObject> RequiredAsync(string name, CancellationToken cancellationToken)
    {
        return await _gateway.ReadAsync(name, cancellationToken).ConfigureAwait(false)
        ?? throw Invalid("delta_source_repair_claim_object_missing");
    }

    private async Task RequirePolicyAsync(CancellationToken cancellationToken)
    {
        RolloverClaimBucketPolicy policy = await _gateway.ReadPolicyAsync(cancellationToken).ConfigureAwait(false);
        if (!policy.RetentionLocked || policy.RetentionSeconds < ImmutableRolloverClaimStore.MinimumRetentionSeconds ||
            !policy.UniformBucketAccess || policy.VersioningEnabled)
        {
            throw Invalid("delta_source_repair_claim_policy_invalid");
        }
    }

    private static void RequireShape(SourceBackedLocalRepairClaim claim, DateTimeOffset nowUtc)
    {
        if (claim is null || claim.SchemaVersion != "1.0" || claim.ClaimId == Guid.Empty ||
            !Hash(claim.AdmissionSha256) || !Hash(claim.PreimageSha256) || !Hash(claim.SourceCaptureSha256) ||
            !Hash(claim.FuturePlanSha256) || !Hash(claim.SystemIdentifierSha256) ||
            claim.VolumeName != "legacy-maliev-exact23-postgres-data" ||
            !ValidTargetGeneration(claim.TargetGeneration, claim.VolumeCreatedAtUtc) ||
            claim.VolumeCreatedAtUtc.Offset != TimeSpan.Zero || claim.CreatedAtUtc.Offset != TimeSpan.Zero ||
            claim.ExpiresAtUtc.Offset != TimeSpan.Zero || nowUtc.Offset != TimeSpan.Zero ||
            nowUtc < claim.CreatedAtUtc || nowUtc >= claim.ExpiresAtUtc ||
            claim.ExpiresAtUtc - claim.CreatedAtUtc != ImmutableRolloverClaimStore.MaximumClaimAge ||
            claim.InitialMetadata is null || !claim.InitialMetadata.Select(item => item?.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            claim.InitialMetadata.Any(item => item is null || item.State != PairedLocalTransitionMetadataState.SettledPrior ||
                !Hash(item.FingerprintSha256)))
        {
            throw Invalid("delta_source_repair_claim_shape_invalid");
        }
    }

    private static void RequireRetained(RolloverClaimObject value, DateTimeOffset expiresAtUtc)
    {
        if (value.Generation <= 0 || value.CreatedAtUtc.Offset != TimeSpan.Zero ||
            value.RetentionExpiresAtUtc.Offset != TimeSpan.Zero || value.RetentionExpiresAtUtc < expiresAtUtc ||
            value.Content.Length == 0)
        {
            throw Invalid("delta_source_repair_claim_retention_invalid");
        }
    }

    private static string[] ReservationNames(SourceBackedLocalRepairClaim claim)
    {
        return [
        Prefix + "preimages/" + claim.PreimageSha256,
        "claims/v1/target-generations/" + Sha256(Encoding.UTF8.GetBytes(claim.TargetGeneration)),
        "claims/v1/future-plans/" + claim.FuturePlanSha256 + "/" + Sha256(Encoding.UTF8.GetBytes(claim.TargetGeneration)),
    ];
    }

    private static bool ValidTargetGeneration(string? generation, DateTimeOffset volumeCreatedAtUtc)
    {
        string[] parts = generation?.Split(':') ?? [];
        return parts.Length == 5 && parts[0] == "docker" && Hash(parts[1]) &&
            parts.Skip(2).All(value => long.TryParse(value, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out long milliseconds) && milliseconds > 0) &&
            parts[4] == volumeCreatedAtUtc.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
    private static string ActiveName(Guid id)
    {
        return Prefix + "active/" + id.ToString("D");
    }

    private static bool Hash(string? value)
    {
        return value is { Length: 64 } && value.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }

    private static string Sha256(byte[] value)
    {
        return Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
    }

    private static DeltaExecutionException Invalid(string code)
    {
        return new(code, "The retained source-backed LOCAL repair claim is incomplete or untrusted.");
    }

    private sealed record Reservation(string SchemaVersion, Guid ClaimId, string ClaimSha256);
}
