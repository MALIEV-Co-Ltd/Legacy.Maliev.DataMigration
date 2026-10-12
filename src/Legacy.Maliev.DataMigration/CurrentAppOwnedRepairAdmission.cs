using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAppOwnedMaintenancePin(string Role, string RoleComment, DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc, DateTimeOffset Postmaster, DateTimeOffset ConfigLoaded,
    string HbaSha256, string HbaRulesSha256, string HbaPath);

internal sealed record CurrentAppOwnedRepairScope(Guid OperationId, CurrentAppOwnedRepairOperation Operation,
    string SourceCommitSha, string BeforeSchemaPlanSha256, string AfterSchemaPlanSha256,
    string OperationSha256, DeltaTargetAuthority Target, string TargetNamespace, string TargetCluster,
    string TargetGeneration, string TargetObservationSha256, string RunBindingSha256,
    IReadOnlyDictionary<string, string> BeforeDatabaseSha256, string GlobalPreservationSha256,
    string NativeProofSha256, string RecoveryReviewSha256, string ExactRoleTransitionReviewSha256,
    CurrentAppOwnedMaintenancePin Maintenance);

internal sealed record CurrentAppOwnedRepairSignedClaim(string Kind, CurrentAppOwnedRepairScope Scope,
    Guid Nonce, string? ReviewSha256, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc,
    string KeyId, string? Signature);

internal sealed record CurrentAppOwnedRepairSigningPins(string ReviewKeyId, string ReviewFingerprint,
    string AuthorizationKeyId, string AuthorizationFingerprint, string ReceiptKeyId, string ReceiptFingerprint);

internal interface ICurrentAppOwnedRepairEnvironment
{
    // Implemented by the closed Console composition, not supplied by serialized configuration callbacks.
    Task RequireSourceAsync(string sourceCommitSha, CancellationToken cancellationToken);
    Task RequireResourceAndCustodyAsync(CurrentAppOwnedRepairScope scope, CancellationToken cancellationToken);
    Task<string> InspectGlobalPreservationAsync(CancellationToken cancellationToken);
    Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken cancellationToken);
}

internal sealed class CurrentAppOwnedRepairPermit
{
    private readonly CurrentAppOwnedRepairSignedClaim _review;
    private readonly CurrentAppOwnedRepairSignedClaim _authorization;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly CurrentAppOwnedRepairSigningPins _pins;
    private readonly ICurrentAppOwnedRepairEnvironment _environment;
    private readonly TimeProvider _clock;

    private CurrentAppOwnedRepairPermit(CurrentAppOwnedRepairSignedClaim review,
        CurrentAppOwnedRepairSignedClaim authorization, IReceiptAttestationTrustStore trust,
        CurrentAppOwnedRepairSigningPins pins, ICurrentAppOwnedRepairEnvironment environment, TimeProvider clock)
    { _review = review; _authorization = authorization; _trust = trust; _pins = pins; _environment = environment; _clock = clock; }

    internal CurrentAppOwnedRepairScope Scope => Clone(_authorization.Scope);
    internal ICurrentAppOwnedRepairEnvironment Environment => _environment;
    internal string AuthorizationSha256 => Hash(JsonSerializer.SerializeToUtf8Bytes(_authorization));

    internal static async Task<CurrentAppOwnedRepairPermit> AdmitAsync(CurrentAppOwnedRepairSignedClaim review,
        CurrentAppOwnedRepairSignedClaim authorization, FreshSchemaPlan before, FreshSchemaPlan after,
        IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins,
        ICurrentAppOwnedRepairEnvironment environment, TimeProvider clock, CancellationToken cancellationToken)
    {
        CurrentAppOwnedRepairManifest.RequireSchemaPair(before, after, clock.GetUtcNow());
        ValidateClaims(review, authorization, trust, pins, clock.GetUtcNow());
        CurrentAppOwnedRepairScope scope = authorization.Scope;
        if (scope.BeforeSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(before) ||
            scope.AfterSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(after) ||
            scope.SourceCommitSha != before.SourceCommitSha) { throw Invalid(); }
        var permit = new CurrentAppOwnedRepairPermit(Clone(review), Clone(authorization), trust, pins, environment, clock);
        await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
        return permit;
    }

    internal static async Task<CurrentAppOwnedRepairSignedClaim> AuthorizeAsync(
        CurrentAppOwnedRepairSignedClaim review, FreshSchemaPlan before, FreshSchemaPlan after,
        IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins,
        ICurrentAppOwnedRepairEnvironment environment, P256MigrationEvidenceSigner signer,
        TimeProvider clock, CancellationToken cancellationToken)
    {
        if (signer.KeyId != pins.AuthorizationKeyId) { throw Invalid(); }
        DateTimeOffset now = clock.GetUtcNow();
        DateTimeOffset expires = new[] { now.AddMinutes(15), review.ExpiresAtUtc, review.Scope.Maintenance.ExpiresAtUtc }.Min();
        var unsigned = new CurrentAppOwnedRepairSignedClaim("current-app-owned-eight-authorization-v1", Clone(review.Scope),
            Guid.NewGuid(), Hash(JsonSerializer.SerializeToUtf8Bytes(review)), now, expires, signer.KeyId, null);
        var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(Payload(unsigned))) };
        CurrentAppOwnedRepairPermit permit = await AdmitAsync(review, signed, before, after, trust, pins,
            environment, clock, cancellationToken).ConfigureAwait(false);
        if (await environment.InspectGlobalPreservationAsync(cancellationToken).ConfigureAwait(false) != review.Scope.GlobalPreservationSha256)
        { throw Invalid(); }
        await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
        return signed;
    }
    internal async Task RequireAsync(CancellationToken cancellationToken)
    {
        ValidateClaims(_review, _authorization, _trust, _pins, _clock.GetUtcNow());
        await _environment.RequireSourceAsync(_authorization.Scope.SourceCommitSha, cancellationToken).ConfigureAwait(false);
        await _environment.RequireResourceAndCustodyAsync(_authorization.Scope, cancellationToken).ConfigureAwait(false);
    }

    internal static void ValidateClaims(CurrentAppOwnedRepairSignedClaim review,
        CurrentAppOwnedRepairSignedClaim authorization, IReceiptAttestationTrustStore trust,
        CurrentAppOwnedRepairSigningPins pins, DateTimeOffset now)
    {
        CurrentAppOwnedRepairScope scope = authorization.Scope;
        if (scope.OperationId == Guid.Empty || scope.Operation != CurrentAppOwnedRepairOperation.CreateEightTables ||
            scope.OperationSha256 != CurrentAppOwnedRepairManifest.OperationSha256(scope.Operation) ||
            scope.SourceCommitSha.Length != 40 || !scope.SourceCommitSha.All(char.IsAsciiHexDigit) ||
            !HashShape(scope.BeforeSchemaPlanSha256) || !HashShape(scope.AfterSchemaPlanSha256) ||
            !HashShape(scope.GlobalPreservationSha256) || !HashShape(scope.NativeProofSha256) ||
            !HashShape(scope.RecoveryReviewSha256) || !HashShape(scope.ExactRoleTransitionReviewSha256) ||
            !HashShape(scope.TargetObservationSha256) || !HashShape(scope.RunBindingSha256) ||
            string.IsNullOrWhiteSpace(scope.TargetGeneration) ||
            !scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal)
                .SequenceEqual(CurrentAppOwnedRepairManifest.Databases(scope.Operation), StringComparer.Ordinal) ||
            scope.BeforeDatabaseSha256.Values.Any(x => !HashShape(x)) ||
            !(DeltaSynchronizationPlanProducer.ValidAuthority(scope.Target, "local-aspire", "legacy-postgres-main-local") &&
                  scope.TargetNamespace == "local-aspire" && scope.TargetCluster == "legacy-postgres-main-local" ||
              DeltaSynchronizationPlanProducer.ValidAuthority(scope.Target, "maliev-legacy", "legacy-postgres-main") &&
                  scope.TargetNamespace == "maliev-legacy" && scope.TargetCluster == "legacy-postgres-main") ||
            pins.ReviewKeyId == pins.AuthorizationKeyId || pins.ReviewKeyId == pins.ReceiptKeyId ||
            pins.AuthorizationKeyId == pins.ReceiptKeyId || pins.ReviewFingerprint == pins.AuthorizationFingerprint ||
            pins.ReviewFingerprint == pins.ReceiptFingerprint || pins.AuthorizationFingerprint == pins.ReceiptFingerprint ||
            JsonSerializer.Serialize(review.Scope) != JsonSerializer.Serialize(scope) ||
            authorization.ReviewSha256 != Hash(JsonSerializer.SerializeToUtf8Bytes(review)) ||
            review.Kind != "current-app-owned-eight-review-v1" || authorization.Kind != "current-app-owned-eight-authorization-v1" ||
            review.Nonce == Guid.Empty || authorization.Nonce == Guid.Empty || review.Nonce == authorization.Nonce ||
            review.KeyId != pins.ReviewKeyId || authorization.KeyId != pins.AuthorizationKeyId ||
            !Verify(review, trust, pins.ReviewFingerprint, now, TimeSpan.FromHours(12)) ||
            !Verify(authorization, trust, pins.AuthorizationFingerprint, now, TimeSpan.FromMinutes(15)) ||
            !trust.TryGetPublicKeyFingerprintSha256(pins.ReceiptKeyId, out string receiptFingerprint) ||
            receiptFingerprint != pins.ReceiptFingerprint)
        { throw Invalid(); }
        CurrentAppOwnedMaintenancePin maintenance = scope.Maintenance;
        if (string.IsNullOrWhiteSpace(maintenance.Role) || maintenance.RoleComment !=
                "legacy-maliev-current-app-owned-eight-v1:" + scope.RunBindingSha256 ||
            maintenance.IssuedAtUtc.Offset != TimeSpan.Zero || maintenance.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            maintenance.IssuedAtUtc > now || maintenance.ExpiresAtUtc <= now ||
            maintenance.ExpiresAtUtc - maintenance.IssuedAtUtc > TimeSpan.FromHours(4) ||
            !HashShape(maintenance.HbaSha256) || !HashShape(maintenance.HbaRulesSha256) ||
            string.IsNullOrWhiteSpace(maintenance.HbaPath) || maintenance.Postmaster.Offset != TimeSpan.Zero ||
            maintenance.ConfigLoaded.Offset != TimeSpan.Zero || maintenance.Postmaster > now || maintenance.ConfigLoaded > now)
        { throw Invalid(); }
    }

    internal static byte[] Payload(CurrentAppOwnedRepairSignedClaim claim) =>
        [.. Encoding.UTF8.GetBytes("Legacy.Maliev.CurrentAppOwnedEight." + claim.Kind + "\0"),
            .. JsonSerializer.SerializeToUtf8Bytes(claim with { Signature = null })];

    private static bool Verify(CurrentAppOwnedRepairSignedClaim claim, IReceiptAttestationTrustStore trust,
        string fingerprint, DateTimeOffset now, TimeSpan maximum)
    {
        if (claim.IssuedAtUtc.Offset != TimeSpan.Zero || claim.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            claim.IssuedAtUtc > now || claim.ExpiresAtUtc <= now || claim.ExpiresAtUtc <= claim.IssuedAtUtc ||
            claim.ExpiresAtUtc - claim.IssuedAtUtc > maximum || string.IsNullOrWhiteSpace(claim.Signature) ||
            !trust.TryGetPublicKeyFingerprintSha256(claim.KeyId, out string actual) || actual != fingerprint) { return false; }
        try { return trust.Verify(claim.KeyId, Payload(claim), Convert.FromBase64String(claim.Signature)); }
        catch (FormatException) { return false; }
    }

    internal static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    internal static bool HashShape(string value) => value.Length == 64 && value.All(x => x is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static T Clone<T>(T value) => JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value)) ?? throw Invalid();
    internal static MigrationExecutionException Invalid() =>
        new("current_app_owned_eight_admission_invalid", "The distinct guarded eight-table repair admission failed.");
}