using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal enum CurrentAppOwnedV3RepairOperation { AppendFourNullableColumnsAndCreateThreeTables = 1 }

internal sealed record CurrentAppOwnedV3RepairScope(Guid OperationId, CurrentAppOwnedV3RepairOperation Operation,
    string SourceCommitSha, string BeforeSchemaPlanSha256, string AfterSchemaPlanSha256,
    string OperationSha256, DeltaTargetAuthority Target, string TargetNamespace, string TargetCluster,
    string TargetGeneration, string TargetObservationSha256, string RunBindingSha256,
    IReadOnlyDictionary<string, string> BeforeDatabaseSha256, string GlobalPreservationSha256,
    string NativeProofSha256, string RecoveryReviewSha256, string ExactRoleTransitionReviewSha256,
    CurrentAppOwnedMaintenancePin Maintenance);

internal sealed record CurrentAppOwnedV3RepairSignedClaim(string Kind, CurrentAppOwnedV3RepairScope Scope,
    Guid Nonce, string? ReviewSha256, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc,
    string KeyId, string? Signature);

internal interface ICurrentAppOwnedV3RepairEnvironment
{
    // Implemented by the closed Console composition, not supplied by serialized configuration callbacks.
    Task RequireSourceAsync(string sourceCommitSha, CancellationToken cancellationToken);
    Task RequireResourceAndCustodyAsync(CurrentAppOwnedV3RepairScope scope, CancellationToken cancellationToken);
    Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CurrentAppOwnedV3RepairScope scope, CancellationToken cancellationToken);
    // Enumerate every exact operation-prefixed slot, including unknown names, and reject any presence.
    Task RequireFreshOperationAsync(CurrentAppOwnedV3RepairScope scope, CancellationToken cancellationToken);
    // Under a held operation lock: atomically re-enumerate all slots and CREATE_NEW the bound reservation.
    // A lost acknowledgment consumes the operation; never erase or adopt any prior slot.
    Task ReserveFreshOperationAsync(CurrentAppOwnedV3RepairScope scope, string authorizationSha256, CancellationToken cancellationToken);
    Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken cancellationToken);
}

internal sealed class CurrentAppOwnedV3RepairPermit
{
    private readonly CurrentAppOwnedV3RepairSignedClaim _review;
    private readonly CurrentAppOwnedV3RepairSignedClaim _authorization;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly TimeProvider _clock;

    private CurrentAppOwnedV3RepairPermit(CurrentAppOwnedV3RepairSignedClaim review,
        CurrentAppOwnedV3RepairSignedClaim authorization, IReceiptAttestationTrustStore trust,
        CurrentAppOwnedRepairSigningPins pins, ICurrentAppOwnedV3RepairEnvironment environment, TimeProvider clock)
    { _review = review; _authorization = authorization; _trust = trust; SigningPins = pins; Environment = environment; _clock = clock; }

    internal CurrentAppOwnedV3RepairScope Scope => Clone(_authorization.Scope);
    internal ICurrentAppOwnedV3RepairEnvironment Environment { get; }
    internal CurrentAppOwnedRepairSigningPins SigningPins { get; }
    private int _executionState; // 0 fresh, 3 reserving, 1 running, 2 permanently stopped.
    internal string AuthorizationSha256 => CurrentAppOwnedSnapshotSerialization.Sha256(_authorization);

    internal static async Task<CurrentAppOwnedV3RepairPermit> AdmitAsync(CurrentAppOwnedV3RepairSignedClaim review,
        CurrentAppOwnedV3RepairSignedClaim authorization, FreshSchemaPlan before, FreshSchemaPlan after,
        IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins,
        ICurrentAppOwnedV3RepairEnvironment environment, TimeProvider clock, CancellationToken cancellationToken)
    {
        review = Clone(review); authorization = Clone(authorization); before = Clone(before); after = Clone(after);
        CurrentAppOwnedV3AdditiveContract contract = CurrentAppOwnedV3AdditiveContract.Create(before, after, authorization.Scope.SourceCommitSha, clock.GetUtcNow());
        RequireReview(review, before, after, trust, pins, clock.GetUtcNow());
        ValidateClaims(review, authorization, trust, pins, clock.GetUtcNow());
        CurrentAppOwnedV3RepairScope scope = authorization.Scope;
        if (scope.BeforeSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(before) ||
            scope.AfterSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(after) ||
            scope.SourceCommitSha != before.SourceCommitSha || scope.OperationSha256 != contract.ComputeSha256()) { throw Invalid(); }
        var permit = new CurrentAppOwnedV3RepairPermit(Clone(review), Clone(authorization), trust, pins, environment, clock);
        await environment.RequireFreshOperationAsync(permit.Scope, cancellationToken).ConfigureAwait(false);
        await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
        await permit.RequireFleetAsync(scope.BeforeDatabaseSha256, cancellationToken).ConfigureAwait(false);
        await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
        await environment.RequireFreshOperationAsync(permit.Scope, cancellationToken).ConfigureAwait(false);
        return permit;
    }

    internal static async Task<CurrentAppOwnedV3RepairSignedClaim> AuthorizeAsync(
        CurrentAppOwnedV3RepairSignedClaim review, FreshSchemaPlan before, FreshSchemaPlan after,
        IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins,
        ICurrentAppOwnedV3RepairEnvironment environment, P256MigrationEvidenceSigner signer,
        TimeProvider clock, CancellationToken cancellationToken)
    {
        review = Clone(review); before = Clone(before); after = Clone(after);
        RequireReview(review, before, after, trust, pins, clock.GetUtcNow());
        if (signer.KeyId != pins.AuthorizationKeyId) { throw Invalid(); }
        DateTimeOffset now = clock.GetUtcNow();
        DateTimeOffset expires = new[] { now.AddMinutes(15), review.ExpiresAtUtc, review.Scope.Maintenance.ExpiresAtUtc }.Min();
        var unsigned = new CurrentAppOwnedV3RepairSignedClaim("current-app-owned-v3-authorization-v1", Clone(review.Scope),
            Guid.NewGuid(), Hash(JsonSerializer.SerializeToUtf8Bytes(review)), now, expires, signer.KeyId, null);
        var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(Payload(unsigned))) };
        CurrentAppOwnedV3RepairPermit permit = await AdmitAsync(review, signed, before, after, trust, pins,
            environment, clock, cancellationToken).ConfigureAwait(false);
        await permit.RequireFleetAsync(review.Scope.BeforeDatabaseSha256, cancellationToken).ConfigureAwait(false);
        await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
        return signed;
    }
    internal async Task RequireAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (Volatile.Read(ref _executionState) == 2) { throw Invalid(); }
            ValidateClaims(_review, _authorization, _trust, SigningPins, _clock.GetUtcNow());
            await Environment.RequireSourceAsync(_authorization.Scope.SourceCommitSha, cancellationToken).ConfigureAwait(false);
            await Environment.RequireResourceAndCustodyAsync(Scope, cancellationToken).ConfigureAwait(false);
            if (Volatile.Read(ref _executionState) == 2) { throw Invalid(); }
        }
        catch { Stop(); throw; }
    }

    internal async Task StartAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.CompareExchange(ref _executionState, 3, 0) != 0) { Stop(); throw Invalid(); }
        try
        {
            await RequireAsync(cancellationToken).ConfigureAwait(false);
            await Environment.RequireFreshOperationAsync(Scope, cancellationToken).ConfigureAwait(false);
            await RequireFleetAsync(_authorization.Scope.BeforeDatabaseSha256, cancellationToken).ConfigureAwait(false);
            await Environment.ReserveFreshOperationAsync(Scope, AuthorizationSha256, cancellationToken).ConfigureAwait(false);
            await RequireAsync(cancellationToken).ConfigureAwait(false);
            if (Interlocked.CompareExchange(ref _executionState, 1, 3) != 3) { throw Invalid(); }
        }
        catch { Stop(); throw; }
    }

    internal void Stop() { _ = Interlocked.Exchange(ref _executionState, 2); }
    internal async Task RequireFleetAsync(IReadOnlyDictionary<string, string> expected, CancellationToken ct)
    {
        try
        {
            if (Volatile.Read(ref _executionState) == 2) { throw Invalid(); }
            expected = expected.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
            if (!expected.Keys.Order(StringComparer.Ordinal).SequenceEqual(_authorization.Scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal)) ||
                expected.Values.Any(x => !HashShape(x))) { throw Invalid(); }
            IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> actual = await Environment.InspectFleetAsync(Scope, ct).ConfigureAwait(false);
            if (actual.Count != expected.Count || actual.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != actual.Count ||
                actual.Any(x => !expected.TryGetValue(x.Database, out string? hash) || hash != CurrentAppOwnedSnapshotSerialization.Sha256(x)) ||
                Volatile.Read(ref _executionState) == 2) { throw Invalid(); }
        }
        catch { Stop(); throw; }
    }
    private static bool ValidFleet(CurrentAppOwnedV3RepairScope scope)
    {
        int expected = scope.Target.Kind == DeltaTargetAuthorityKind.LocalAspire ? 26 : 53;
        return scope.BeforeDatabaseSha256.Count == expected &&
            DatabaseInventory.ActiveDatabases.All(scope.BeforeDatabaseSha256.ContainsKey) &&
            (scope.Target.Kind != DeltaTargetAuthorityKind.LocalAspire || scope.BeforeDatabaseSha256.ContainsKey("legacy_local")) &&
            scope.BeforeDatabaseSha256.ContainsKey("Auth") && scope.BeforeDatabaseSha256.ContainsKey("postgres") &&
            scope.BeforeDatabaseSha256.Keys.All(x => !string.IsNullOrWhiteSpace(x)) &&
            scope.GlobalPreservationSha256 == FleetSha256(scope.BeforeDatabaseSha256);
    }

    internal static string FleetSha256(IReadOnlyDictionary<string, string> databases)
    {
        return Hash(JsonSerializer.SerializeToUtf8Bytes(databases.OrderBy(x => x.Key, StringComparer.Ordinal)
            .Select(x => new { Database = x.Key, Sha256 = x.Value }).ToArray()));
    }
    internal static void ValidateClaims(CurrentAppOwnedV3RepairSignedClaim review,
        CurrentAppOwnedV3RepairSignedClaim authorization, IReceiptAttestationTrustStore trust,
        CurrentAppOwnedRepairSigningPins pins, DateTimeOffset now)
    {
        CurrentAppOwnedV3RepairScope scope = authorization.Scope;
        RequireScopeShape(scope, now);
        if (pins.ReviewKeyId == pins.AuthorizationKeyId || pins.ReviewKeyId == pins.ReceiptKeyId ||
            pins.AuthorizationKeyId == pins.ReceiptKeyId || pins.ReviewFingerprint == pins.AuthorizationFingerprint ||
            pins.ReviewFingerprint == pins.ReceiptFingerprint || pins.AuthorizationFingerprint == pins.ReceiptFingerprint ||
            JsonSerializer.Serialize(review.Scope) != JsonSerializer.Serialize(scope) ||
            authorization.ReviewSha256 != Hash(JsonSerializer.SerializeToUtf8Bytes(review)) ||
            review.Kind != "current-app-owned-v3-review-v1" || authorization.Kind != "current-app-owned-v3-authorization-v1" ||
            review.ReviewSha256 is not null || authorization.IssuedAtUtc < review.IssuedAtUtc || authorization.ExpiresAtUtc > review.ExpiresAtUtc ||
            authorization.ExpiresAtUtc > scope.Maintenance.ExpiresAtUtc ||
            review.Nonce == Guid.Empty || authorization.Nonce == Guid.Empty || review.Nonce == authorization.Nonce ||
            review.KeyId != pins.ReviewKeyId || authorization.KeyId != pins.AuthorizationKeyId ||
            !Verify(review, trust, pins.ReviewFingerprint, now, TimeSpan.FromHours(12)) ||
            !Verify(authorization, trust, pins.AuthorizationFingerprint, now, TimeSpan.FromMinutes(15)) ||
            !trust.TryGetPublicKeyFingerprintSha256(pins.ReceiptKeyId, out string receiptFingerprint) ||
            receiptFingerprint != pins.ReceiptFingerprint)
        { throw Invalid(); }
    }

    private static void RequireScopeShape(CurrentAppOwnedV3RepairScope scope, DateTimeOffset now)
    {
        if (scope.OperationId == Guid.Empty || scope.Operation != CurrentAppOwnedV3RepairOperation.AppendFourNullableColumnsAndCreateThreeTables ||
            scope.SourceCommitSha.Length != 40 || !scope.SourceCommitSha.All(x => x is (>= '0' and <= '9') or (>= 'a' and <= 'f')) ||
            !HashShape(scope.OperationSha256) || !HashShape(scope.BeforeSchemaPlanSha256) || !HashShape(scope.AfterSchemaPlanSha256) ||
            !HashShape(scope.TargetObservationSha256) || !HashShape(scope.RunBindingSha256) || !HashShape(scope.NativeProofSha256) ||
            !HashShape(scope.RecoveryReviewSha256) || !HashShape(scope.ExactRoleTransitionReviewSha256) || !ValidFleet(scope) ||
            scope.BeforeDatabaseSha256.Values.Any(x => !HashShape(x)) || string.IsNullOrWhiteSpace(scope.TargetGeneration) ||
            !((DeltaSynchronizationPlanProducer.ValidAuthority(scope.Target, "local-aspire", "legacy-postgres-main-local") &&
                scope.TargetNamespace == "local-aspire" && scope.TargetCluster == "legacy-postgres-main-local") ||
              (DeltaSynchronizationPlanProducer.ValidAuthority(scope.Target, "maliev-legacy", "legacy-postgres-main") &&
                scope.TargetNamespace == "maliev-legacy" && scope.TargetCluster == "legacy-postgres-main"))) { throw Invalid(); }
        CurrentAppOwnedMaintenancePin m = scope.Maintenance;
        if (string.IsNullOrWhiteSpace(m.Role) || m.RoleComment != "legacy-maliev-current-app-owned-v3-v1:" + scope.RunBindingSha256 ||
            m.IssuedAtUtc.Offset != TimeSpan.Zero || m.ExpiresAtUtc.Offset != TimeSpan.Zero || m.IssuedAtUtc > now || m.ExpiresAtUtc <= now ||
            m.ExpiresAtUtc - m.IssuedAtUtc > TimeSpan.FromHours(4) || !HashShape(m.HbaSha256) || !HashShape(m.HbaRulesSha256) ||
            string.IsNullOrWhiteSpace(m.HbaPath) || m.Postmaster.Offset != TimeSpan.Zero || m.ConfigLoaded.Offset != TimeSpan.Zero ||
            m.Postmaster > now || m.ConfigLoaded > now) { throw Invalid(); }
    }

    // Pure preconstruction gate: no environment, custody, target observer or network callback.
    internal static void ValidateReview(CurrentAppOwnedV3RepairSignedClaim review, FreshSchemaPlan before, FreshSchemaPlan after,
        IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins, DateTimeOffset now)
    {
        RequireReview(review, before, after, trust, pins, now);
    }

    private static void RequireReview(CurrentAppOwnedV3RepairSignedClaim review, FreshSchemaPlan before, FreshSchemaPlan after,
        IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins, DateTimeOffset now)
    {
        RequireScopeShape(review.Scope, now);
        CurrentAppOwnedV3AdditiveContract contract = CurrentAppOwnedV3AdditiveContract.Create(before, after, review.Scope.SourceCommitSha, now);
        if (review.Scope.OperationSha256 != contract.ComputeSha256() ||
            review.Scope.BeforeSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(before) ||
            review.Scope.AfterSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(after) ||
            review.Kind != "current-app-owned-v3-review-v1" || review.KeyId != pins.ReviewKeyId ||
            review.ReviewSha256 is not null || review.Nonce == Guid.Empty || review.ExpiresAtUtc > review.Scope.Maintenance.ExpiresAtUtc ||
            pins.ReviewKeyId == pins.AuthorizationKeyId || pins.ReviewKeyId == pins.ReceiptKeyId || pins.AuthorizationKeyId == pins.ReceiptKeyId ||
            pins.ReviewFingerprint == pins.AuthorizationFingerprint || pins.ReviewFingerprint == pins.ReceiptFingerprint ||
            pins.AuthorizationFingerprint == pins.ReceiptFingerprint ||
            !trust.TryGetPublicKeyFingerprintSha256(pins.AuthorizationKeyId, out string authorization) || authorization != pins.AuthorizationFingerprint ||
            !trust.TryGetPublicKeyFingerprintSha256(pins.ReceiptKeyId, out string receipt) || receipt != pins.ReceiptFingerprint ||
            !Verify(review, trust, pins.ReviewFingerprint, now, TimeSpan.FromHours(12))) { throw Invalid(); }
    }

    internal static async Task<CurrentAppOwnedV3RepairSignedClaim> IssueReviewAsync(CurrentAppOwnedV3RepairScope scope,
        FreshSchemaPlan before, FreshSchemaPlan after, IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> baseline,
        IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins, ICurrentAppOwnedV3RepairEnvironment environment,
        P256MigrationEvidenceSigner signer, DateTimeOffset expiresAtUtc, TimeProvider clock, CancellationToken ct)
    {
        scope = Clone(scope); before = Clone(before); after = Clone(after);
        baseline = baseline.Select(CopySnapshot).ToArray();
        DateTimeOffset now = clock.GetUtcNow();
        RequireScopeShape(scope, now);
        _ = CurrentAppOwnedV3AdditiveContract.Create(before, after, scope.SourceCommitSha, now);
        if (signer.KeyId != pins.ReviewKeyId || baseline.Count != scope.BeforeDatabaseSha256.Count ||
            baseline.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != baseline.Count ||
            baseline.Any(x => !scope.BeforeDatabaseSha256.TryGetValue(x.Database, out string? hash) ||
                CurrentAppOwnedSnapshotSerialization.Sha256(x) != hash)) { throw Invalid(); }
        var unsigned = new CurrentAppOwnedV3RepairSignedClaim("current-app-owned-v3-review-v1", scope,
            Guid.NewGuid(), null, now, expiresAtUtc, signer.KeyId, null);
        var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(Payload(unsigned))) };
        // Validate the real signature, all pins and full pair before any environment/network access.
        RequireReview(signed, before, after, trust, pins, now);
        await environment.RequireFreshOperationAsync(Clone(scope), ct).ConfigureAwait(false);
        await environment.RequireSourceAsync(scope.SourceCommitSha, ct).ConfigureAwait(false);
        await environment.RequireResourceAndCustodyAsync(Clone(scope), ct).ConfigureAwait(false);
        IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> actual = await environment.InspectFleetAsync(Clone(scope), ct).ConfigureAwait(false);
        if (actual.Count != baseline.Count || actual.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != actual.Count ||
            actual.Any(x => !scope.BeforeDatabaseSha256.TryGetValue(x.Database, out string? hash) || CurrentAppOwnedSnapshotSerialization.Sha256(x) != hash))
        { throw Invalid(); }
        await environment.RequireSourceAsync(scope.SourceCommitSha, ct).ConfigureAwait(false);
        await environment.RequireResourceAndCustodyAsync(Clone(scope), ct).ConfigureAwait(false);
        await environment.RequireFreshOperationAsync(Clone(scope), ct).ConfigureAwait(false);
        RequireReview(signed, before, after, trust, pins, clock.GetUtcNow());
        return Clone(signed);
    }

    internal static CurrentAppOwnedDatabaseSnapshot CopySnapshot(CurrentAppOwnedDatabaseSnapshot value)
    {
        return new(value.Database,
            Array.AsReadOnly(value.Catalog.Select(x => x with { }).ToArray()),
            Array.AsReadOnly(value.Relations.Select(x => x with { }).ToArray()),
            Array.AsReadOnly(value.Sequences.Select(x => x with { }).ToArray()));
    }
    internal static byte[] Payload(CurrentAppOwnedV3RepairSignedClaim claim)
    {
        return [.. Encoding.UTF8.GetBytes("Legacy.Maliev.CurrentAppOwnedV3." + claim.Kind + "\0"),
            .. JsonSerializer.SerializeToUtf8Bytes(claim with { Signature = null })];
    }

    private static bool Verify(CurrentAppOwnedV3RepairSignedClaim claim, IReceiptAttestationTrustStore trust,
        string fingerprint, DateTimeOffset now, TimeSpan maximum)
    {
        if (claim.IssuedAtUtc.Offset != TimeSpan.Zero || claim.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            claim.IssuedAtUtc > now || claim.ExpiresAtUtc <= now || claim.ExpiresAtUtc <= claim.IssuedAtUtc ||
            claim.ExpiresAtUtc - claim.IssuedAtUtc > maximum || string.IsNullOrWhiteSpace(claim.Signature) ||
            !trust.TryGetPublicKeyFingerprintSha256(claim.KeyId, out string actual) || actual != fingerprint) { return false; }
        try { return trust.Verify(claim.KeyId, Payload(claim), Convert.FromBase64String(claim.Signature)); }
        catch (FormatException) { return false; }
    }

    internal static string Hash(byte[] bytes)
    {
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    internal static bool HashShape(string value)
    {
        return value.Length == 64 && value.All(x => x is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }

    private static T Clone<T>(T value)
    {
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value)) ?? throw Invalid();
    }

    internal static MigrationExecutionException Invalid()
    {
        return new("current_app_owned_v3_admission_invalid", "The distinct guarded V3 additive repair admission failed.");
    }
}