using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAuthArchiveSession(Guid Id, Guid FamilyId, string IdentityId, int IdentityKind,
    string? SecurityStamp, string TokenHash, DateTime CreatedAt, DateTime ExpiresAt,
    DateTime? RotatedAt, DateTime? RevokedAt, Guid? ReplacedById);
internal sealed record CurrentAuthArchivePaths(string FirstCiphertext, string SecondCiphertext, string RecoveryPrivateKey, string SecondRecoveryPrivateKey);
internal enum CurrentAuthArchiveProofAdmission { PersistentWithClosedConsoleProof = 1, DisposableNativeBootstrap = 2 }
internal sealed record CurrentAuthArchivePins(string ReviewKeyId, string ReviewFingerprint,
    string AuthorizationKeyId, string AuthorizationFingerprint, string EvidenceKeyId, string EvidenceFingerprint);
internal sealed record CurrentAuthArchiveClaim(string Domain, string KeyId, string Fingerprint, string PayloadBase64, string SignatureBase64);
internal sealed record CurrentAuthArchiveScope(Guid OperationId, CurrentAuthRepairScope LocalObservationPolicy,
    CurrentAuthRepairScope ProductionObservationPolicy, string DeleteSetSha256, int DeleteCount,
    string ApplicationComparisonSha256, CurrentAuthArchivePaths Paths, string RecoveryDeviceProofSha256,
    string ArchiveHelperProofSha256, string ArchiveNativeProofSha256, string ExactDeleteReviewSha256, string RecoveryReviewSha256, DateTimeOffset CapturedAtUtc,
    DateTimeOffset ExpiresAtUtc, CurrentAuthArchiveProofAdmission ProofAdmission = CurrentAuthArchiveProofAdmission.PersistentWithClosedConsoleProof,
    CurrentAuthArchiveComponentBootstrapSubject? ComponentSubject = null);
internal sealed record CurrentAuthArchiveAuthorization(Guid OperationId, string ReviewSha256, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record CurrentAuthArchiveReceipt(Guid OperationId, string AuthorizationSha256, string PreviousSha256,
    string BeforeAuthSha256, string? AfterAuthSha256, string RecoveryManifestSha256,
    CurrentAppOwnedCommitClassification Classification, DateTimeOffset ObservedAtUtc);
internal sealed record CurrentAuthArchiveFleet(CurrentAuthLocalSessionArchiveObservation Auth,
    IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> Databases, DateTimeOffset BeganAtUtc, DateTimeOffset EndedAtUtc,
    CurrentAuthArchiveFleetCatalogs? Catalogs = null);
internal sealed record CurrentAuthArchiveCatalogObservation(string RunBindingSha256, string TargetObservationSha256,
    string SystemIdentifierSha256, bool ReadOnly, IReadOnlyList<ReviewedRepairDatabaseFlag> Databases,
    DateTimeOffset BeganAtUtc, DateTimeOffset EndedAtUtc);
internal sealed record CurrentAuthArchiveFleetCatalogs(CurrentAuthArchiveCatalogObservation Before,
    CurrentAuthArchiveCatalogObservation After, DateTimeOffset CaptureBeganAtUtc, DateTimeOffset CaptureEndedAtUtc);

// Implementations must be genuinely closed and source/custody accepted. No implementation
// or Console route is supplied by this preparation; callbacks alone are not execution authority.
internal interface ICurrentAuthLocalSessionArchiveEnvironment
{
    Task RequireAcceptedSourceOwnerCustodyAndTargetsAsync(CurrentAuthArchiveScope scope, CancellationToken ct);
    Task<CurrentAuthArchiveFleet> CaptureLocalFleetAsync(CurrentAuthArchiveScope scope, CancellationToken ct);
    Task<CurrentAuthArchiveFleet> CaptureProductionFleetAsync(CurrentAuthArchiveScope scope, CancellationToken ct);
    Task ReserveCreateNewAsync(Guid operationId, string authorizationSha256, CancellationToken ct);
    Task RetainCreateNewAsync(string name, byte[] canonicalSignedBytes, CancellationToken ct);
    Task RetainRecoveryManifestAsync(byte[] canonicalSignedBytes, CancellationToken ct);
    ICurrentAuthLocalSessionArchiveStorage RecoveryStorage { get; }
}

internal interface ICurrentAuthLocalSessionArchiveStorage
{
    // Actual implementation must hold owner-only, non-link, locked Windows handles,
    // prove separate failure domains, Flush(true), bound reads and revalidate custody.
    Task RequireFreshIndependentRecoveryPathsAsync(CurrentAuthArchivePaths paths, CancellationToken ct);
    Task WriteCreateNewDurableAsync(string path, byte[] bytes, CancellationToken ct);
    Task<byte[]> ReadHeldAsync(string path, int maximumBytes, CancellationToken ct);
    Task RequireCustodyAsync(CancellationToken ct);
    Task<byte[]> ReadDomainHeldAsync(bool firstDomain, string path, int maximumBytes, CancellationToken ct);
}

internal static class CurrentAuthLocalSessionArchivePolicy
{
    internal const string ReviewDomain = "Legacy.Maliev.CurrentAuth.LocalSessionArchive.Review.v1";
    internal const string AuthorizationDomain = "Legacy.Maliev.CurrentAuth.LocalSessionArchive.Authorization.v1";
    internal const string ReceiptDomain = "Legacy.Maliev.CurrentAuth.LocalSessionArchive.Receipt.v1";
    internal const string RecoveryDomain = "Legacy.Maliev.CurrentAuth.LocalSessionArchive.RecoveryManifest.v1";
    internal const int MaximumRows = 8192, MaximumPlaintextBytes = 8 * 1024 * 1024;
    private static readonly JsonSerializerOptions Strict = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    internal static string Hash<T>(T value)
    {
        return CurrentAppOwnedSnapshotSerialization.Sha256(value);
    }

    internal static string HashBytes(byte[] value)
    {
        return Convert.ToHexStringLower(SHA256.HashData(value));
    }

    internal static MigrationExecutionException Invalid()
    {
        return new("current_auth_local_archive_invalid", "The fixed current Auth session archive guard failed.");
    }

    internal static byte[] EncodeRows(IReadOnlyList<CurrentAuthArchiveSession> rows)
    {
        if (rows.Count > MaximumRows || rows.Select(x => x.Id).Distinct().Count() != rows.Count) { throw Invalid(); }
        foreach (CurrentAuthArchiveSession row in rows)
        {
            if (row.IdentityId is null || row.IdentityId.Length > 450 || row.TokenHash is null || row.TokenHash.Length > 64 ||
                !ExactTime(row.CreatedAt) || !ExactTime(row.ExpiresAt) ||
                (row.RotatedAt is { } rotated && !ExactTime(rotated)) || (row.RevokedAt is { } revoked && !ExactTime(revoked))) { throw Invalid(); }
        }
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(rows.OrderBy(x => x.Id.ToString("D"), StringComparer.Ordinal).ToArray());
        if (bytes.Length > MaximumPlaintextBytes) { CryptographicOperations.ZeroMemory(bytes); throw Invalid(); }
        return bytes;
    }
    private static bool ExactTime(DateTime time)
    {
        return time.Kind == DateTimeKind.Utc && time.Ticks % 10 == 0;
    }

    internal static void RequireRows(IReadOnlyList<CurrentAuthArchiveSession> actual, IReadOnlyList<CurrentAuthArchiveSession> expected)
    {
        byte[] left = EncodeRows(actual), right = EncodeRows(expected);
        try { if (!left.AsSpan().SequenceEqual(right)) { throw Invalid(); } }
        finally { CryptographicOperations.ZeroMemory(left); CryptographicOperations.ZeroMemory(right); }
    }
    internal static void RequirePins(CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust)
    {
        string[] ids = [pins.ReviewKeyId, pins.AuthorizationKeyId, pins.EvidenceKeyId];
        string[] hashes = [pins.ReviewFingerprint, pins.AuthorizationFingerprint, pins.EvidenceFingerprint];
        if (ids.Distinct(StringComparer.Ordinal).Count() != 3 || hashes.Distinct(StringComparer.Ordinal).Count() != 3) { throw Invalid(); }
        for (int i = 0; i < ids.Length; i++)
        { if (!CurrentAuthRepairPermit.HashShape(hashes[i]) || !trust.TryGetPublicKeyFingerprintSha256(ids[i], out string actual) || actual != hashes[i]) { throw Invalid(); } }
    }
    internal static CurrentAuthArchiveClaim Sign<T>(string domain, T value, P256MigrationEvidenceSigner signer)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(value);
        return payload.Length > 1024 * 1024
            ? throw Invalid()
            : new(domain, signer.KeyId, signer.PublicKeyFingerprintSha256, Convert.ToBase64String(payload),
            Convert.ToBase64String(signer.Sign(Payload(domain, payload))));
    }
    internal static T Verify<T>(CurrentAuthArchiveClaim claim, string domain, string keyId, string fingerprint, IReceiptAttestationTrustStore trust)
    {
        if (claim.Domain != domain || claim.KeyId != keyId || claim.Fingerprint != fingerprint || claim.PayloadBase64.Length > 1400000 || claim.SignatureBase64.Length > 1024 ||
            !trust.TryGetPublicKeyFingerprintSha256(keyId, out string actual) || actual != fingerprint) { throw Invalid(); }
        byte[] bytes = Convert.FromBase64String(claim.PayloadBase64);
        if (bytes.Length > 1024 * 1024 || !trust.Verify(keyId, Payload(domain, bytes), Convert.FromBase64String(claim.SignatureBase64))) { throw Invalid(); }
        T value = JsonSerializer.Deserialize<T>(bytes, Strict) ?? throw Invalid();
        return !JsonSerializer.SerializeToUtf8Bytes(value).AsSpan().SequenceEqual(bytes) ? throw Invalid() : value;
    }
    private static byte[] Payload(string domain, byte[] bytes)
    {
        return [.. Encoding.UTF8.GetBytes(domain + "\0"), .. bytes];
    }

    internal static void RequireScope(CurrentAuthArchiveScope scope, DateTimeOffset now)
    {
        if (scope.LocalObservationPolicy is null || scope.ProductionObservationPolicy is null || scope.Paths is null) { throw Invalid(); }
        CurrentAuthRepairScope local = scope.LocalObservationPolicy, production = scope.ProductionObservationPolicy;
        if (scope.OperationId == Guid.Empty || local.OperationId != scope.OperationId || production.OperationId != scope.OperationId ||
            local.Target.Kind != DeltaTargetAuthorityKind.LocalAspire || !Enum.IsDefined(scope.ProofAdmission) ||
            (scope.ProofAdmission == CurrentAuthArchiveProofAdmission.PersistentWithClosedConsoleProof ?
                !DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(local.Target) || production.Target.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg :
                !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(local.Target) || production.Target.Kind != DeltaTargetAuthorityKind.LocalAspire ||
                !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(production.Target)) ||
            local.Target.SystemIdentifierSha256 == production.Target.SystemIdentifierSha256 || local.RunBindingSha256 == production.RunBindingSha256 ||
            local.SourceCommitSha != production.SourceCommitSha || local.AuthOwnerCommitSha != ApprovedCurrentAuthSchema.AuthServiceCommit ||
            local.SourceCommitSha.Length != 40 || local.SourceCommitSha.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')) ||
            local.SourceSchemaPlanSha256 != production.SourceSchemaPlanSha256 || !CurrentAuthRepairPermit.HashShape(local.SourceSchemaPlanSha256) ||
            production.AuthOwnerCommitSha != ApprovedCurrentAuthSchema.AuthServiceCommit || local.AuthOwnerSourcePinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 ||
            production.AuthOwnerSourcePinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 || local.AuthClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 ||
            production.AuthClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 || local.AuthAfterSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(true) ||
            production.AuthAfterSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(true) || scope.DeleteCount is < 1 or > MaximumRows ||
            !CurrentAuthRepairPermit.HashShape(scope.DeleteSetSha256) || !CurrentAuthRepairPermit.HashShape(scope.ApplicationComparisonSha256) ||
            !CurrentAuthRepairPermit.HashShape(scope.RecoveryDeviceProofSha256) ||
            scope.CapturedAtUtc.Offset != TimeSpan.Zero || scope.ExpiresAtUtc.Offset != TimeSpan.Zero || scope.CapturedAtUtc > now ||
            now - scope.CapturedAtUtc > TimeSpan.FromMinutes(5) || scope.ExpiresAtUtc <= now || scope.ExpiresAtUtc - scope.CapturedAtUtc > TimeSpan.FromMinutes(5)) { throw Invalid(); }
        RequireFleetMap(local, false); RequireFleetMap(production, true);
        string[] reports = [scope.ArchiveHelperProofSha256, scope.ArchiveNativeProofSha256, scope.ExactDeleteReviewSha256, scope.RecoveryReviewSha256];
        if (scope.ProofAdmission == CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap)
        {
            if (reports.Any(x => x != string.Empty)) { throw Invalid(); }
            CurrentAuthArchiveComponentBootstrap.RequireStructure(scope, now);
        }
        else if (scope.ComponentSubject is not null || reports.Any(x => x is null || !CurrentAuthRepairPermit.HashShape(x))) { throw Invalid(); }
        string[] paths = [scope.Paths.FirstCiphertext, scope.Paths.SecondCiphertext, scope.Paths.RecoveryPrivateKey, scope.Paths.SecondRecoveryPrivateKey];
        if (paths.Any(string.IsNullOrWhiteSpace) || paths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != 4 ||
            string.Equals(Path.GetDirectoryName(paths[0]), Path.GetDirectoryName(paths[1]), StringComparison.OrdinalIgnoreCase)) { throw Invalid(); }
    }
    internal static string InventoryProfile(bool comparison)
    {
        return comparison ? DeltaTargetAuthorityKind.ProductionCloudNativePg : DeltaTargetAuthorityKind.LocalAspire;
    }
    private static void RequireFleetMap(CurrentAuthRepairScope policy, bool comparison)
    {
        if (!ReviewedProductionRepairInventory.MatchesKeys(InventoryProfile(comparison), policy.BeforeDatabaseSha256.Keys) ||
            policy.BeforeDatabaseSha256.Values.Any(x => !CurrentAuthRepairPermit.HashShape(x)) ||
            CurrentAuthRepairPermit.FleetSha256(policy.BeforeDatabaseSha256) != policy.GlobalPreservationSha256) { throw Invalid(); }
    }
    internal static void RequireCatalogs(CurrentAuthArchiveFleetCatalogs? catalogs, CurrentAuthRepairScope policy,
        bool comparison, IEnumerable<string> snapshotNames, DateTimeOffset earliest, DateTimeOffset latest)
    {
        if (catalogs is null || catalogs.Before is null || catalogs.After is null ||
            !ReviewedProductionRepairInventory.MatchesKeys(InventoryProfile(comparison), snapshotNames) ||
            catalogs.CaptureBeganAtUtc.Offset != TimeSpan.Zero || catalogs.CaptureEndedAtUtc.Offset != TimeSpan.Zero ||
            catalogs.Before.EndedAtUtc > catalogs.CaptureBeganAtUtc || catalogs.CaptureBeganAtUtc > catalogs.CaptureEndedAtUtc ||
            catalogs.CaptureEndedAtUtc > catalogs.After.BeganAtUtc) { throw Invalid(); }
        foreach (CurrentAuthArchiveCatalogObservation catalog in new[] { catalogs.Before, catalogs.After })
        {
            if (catalog.RunBindingSha256 != policy.RunBindingSha256 || catalog.TargetObservationSha256 != policy.TargetObservationSha256 ||
                !CurrentAuthRepairPermit.HashShape(catalog.SystemIdentifierSha256) || catalog.SystemIdentifierSha256 != policy.Target.SystemIdentifierSha256 || !catalog.ReadOnly || catalog.Databases is null ||
                catalog.BeganAtUtc.Offset != TimeSpan.Zero || catalog.EndedAtUtc.Offset != TimeSpan.Zero ||
                catalog.BeganAtUtc < earliest || catalog.BeganAtUtc > catalog.EndedAtUtc || catalog.EndedAtUtc > latest) { throw Invalid(); }
            ReviewedProductionRepairInventory.RequireComplete(InventoryProfile(comparison), catalog.Databases, policy.BeforeDatabaseSha256.Keys);
        }
    }
    internal static void RequireFleet(CurrentAuthArchiveFleet fleet, CurrentAuthRepairScope policy, DateTimeOffset now,
        bool allowEmptyLocalSessions = false, bool comparison = false)
    {
        RequireFleetMap(policy, comparison);
        RequireCatalogs(fleet.Catalogs, policy, comparison, fleet.Databases.Select(x => x.Database), now.AddMinutes(-5), now);
        if (fleet.BeganAtUtc.Offset != TimeSpan.Zero || fleet.EndedAtUtc.Offset != TimeSpan.Zero || fleet.BeganAtUtc > fleet.EndedAtUtc ||
            fleet.Catalogs!.CaptureBeganAtUtc != fleet.BeganAtUtc || fleet.Catalogs.CaptureEndedAtUtc != fleet.EndedAtUtc ||
            fleet.EndedAtUtc > now || now - fleet.BeganAtUtc > TimeSpan.FromMinutes(5) ||
            fleet.Databases.Count != policy.BeforeDatabaseSha256.Count || fleet.Databases.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != fleet.Databases.Count ||
            fleet.Auth.TargetBindingSha256 != policy.RunBindingSha256 || fleet.Auth.Native.Snapshot.Database != "Auth") { throw Invalid(); }
        foreach (CurrentAppOwnedDatabaseSnapshot db in fleet.Databases)
        {
            if (!policy.BeforeDatabaseSha256.TryGetValue(db.Database, out string? hash) ||
                (!(allowEmptyLocalSessions && db.Database == "Auth") && db.Sha256 != hash) ||
                (db.Database == "Auth" && db.Sha256 != fleet.Auth.Native.Snapshot.Sha256)) { throw Invalid(); }
        }
    }
    internal static string RequireComparison(CurrentAuthLocalSessionArchiveObservation local, CurrentAuthLocalSessionArchiveObservation production)
    {
        if (production.Sessions.Count != 0 || local.TargetBindingSha256 == production.TargetBindingSha256) { throw Invalid(); }
        static CurrentAppOwnedRelationFact[] Application(CurrentAuthLocalSessionArchiveObservation value)
        {
            return [.. value.Native.Snapshot.Relations
            .Where(x => x.Schema == "public" && x.Name is "google_identity_nonces" or "identity_action_tokens").OrderBy(x => x.Name, StringComparer.Ordinal)];
        }

        CurrentAppOwnedRelationFact[] left = Application(local), right = Application(production);
        if (left.Length != 2 || !left.SequenceEqual(right)) { throw Invalid(); }
        // EF history is deliberately absent from CROSS-TARGET comparison; full per-target
        // native snapshot retains it and checks it independently before/after.
        return Hash(new { LocalBinding = local.TargetBindingSha256, ProductionBinding = production.TargetBindingSha256, Application = left });
    }
}

/// <summary>Unrouted preparation guard. Genuine closed environment/storage is a prerequisite.</summary>
internal sealed class CurrentAuthLocalSessionArchivePermit
{
    private readonly CurrentAuthArchiveClaim _review, _authorization;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly CurrentAuthArchivePins _pins;
    private readonly TimeProvider _clock;
    private int _state; // fresh0/reserving1/running2/stopped3; no restart/adoption.
    private string _previousSha256 = new('0', 64);
    private CurrentAuthArchiveReceipt? _prepared;
    private bool _terminal;
    internal CurrentAuthArchiveScope Scope { get; }
    internal ICurrentAuthLocalSessionArchiveEnvironment Environment { get; }
    internal string AuthorizationSha256 => CurrentAuthLocalSessionArchivePolicy.Hash(_authorization);
    private CurrentAuthLocalSessionArchivePermit(CurrentAuthArchiveClaim review, CurrentAuthArchiveClaim authorization,
        CurrentAuthArchiveScope scope, IReceiptAttestationTrustStore trust, CurrentAuthArchivePins pins,
        ICurrentAuthLocalSessionArchiveEnvironment environment, TimeProvider clock)
    { _review = review; _authorization = authorization; Scope = scope; _trust = trust; _pins = pins; Environment = environment; _clock = clock; }
    internal static async Task<CurrentAuthLocalSessionArchivePermit> AdmitAsync(CurrentAuthArchiveClaim review,
        CurrentAuthArchiveClaim authorization, IReceiptAttestationTrustStore trust, CurrentAuthArchivePins pins,
        ICurrentAuthLocalSessionArchiveEnvironment environment, TimeProvider clock, CancellationToken ct)
    {
        CurrentAuthArchiveScope scope = Claims(review, authorization, trust, pins, clock.GetUtcNow()); // pure before target contact
        // The concrete independent precursor/image/parent observer is not integrated yet.
        if (scope.ProofAdmission == CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        var permit = new CurrentAuthLocalSessionArchivePermit(review, authorization, scope, trust, pins, environment, clock);
        try { await permit.RequireAsync(ct).ConfigureAwait(false); _ = await permit.RequireOriginalFleetsAsync(ct).ConfigureAwait(false); return permit; }
        catch { permit.Stop(); throw; }
    }
    private static CurrentAuthArchiveScope Claims(CurrentAuthArchiveClaim review, CurrentAuthArchiveClaim authorization,
        IReceiptAttestationTrustStore trust, CurrentAuthArchivePins pins, DateTimeOffset now)
    {
        CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        CurrentAuthArchiveScope scope = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveScope>(review,
            CurrentAuthLocalSessionArchivePolicy.ReviewDomain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        CurrentAuthLocalSessionArchivePolicy.RequireScope(scope, now);
        if (scope.ProofAdmission == CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap)
        { CurrentAuthArchiveComponentBootstrap.RequireClaims(scope, trust, pins, now); }
        CurrentAuthArchiveAuthorization permission = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveAuthorization>(authorization,
            CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain, pins.AuthorizationKeyId, pins.AuthorizationFingerprint, trust);
        return permission.OperationId != scope.OperationId || permission.ReviewSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(review) ||
            permission.IssuedAtUtc.Offset != TimeSpan.Zero || permission.ExpiresAtUtc.Offset != TimeSpan.Zero || permission.IssuedAtUtc < scope.CapturedAtUtc ||
            permission.IssuedAtUtc > now || permission.ExpiresAtUtc <= now || permission.ExpiresAtUtc > scope.ExpiresAtUtc
            ? throw CurrentAuthLocalSessionArchivePolicy.Invalid()
            : scope;
    }
    internal async Task RequireAsync(CancellationToken ct)
    {
        if (Volatile.Read(ref _state) == 3) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        try
        {
            if (CurrentAuthLocalSessionArchivePolicy.Hash(Claims(_review, _authorization, _trust, _pins, _clock.GetUtcNow())) != CurrentAuthLocalSessionArchivePolicy.Hash(Scope))
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            await Environment.RequireAcceptedSourceOwnerCustodyAndTargetsAsync(Scope, ct).ConfigureAwait(false);
            if (Volatile.Read(ref _state) == 3) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
        catch { Stop(); throw; }
    }
    internal async Task<CurrentAuthLocalSessionArchiveObservation> RequireOriginalFleetsAsync(CancellationToken ct)
    {
        await RequireAsync(ct).ConfigureAwait(false);
        CurrentAuthArchiveFleet local = await Environment.CaptureLocalFleetAsync(Scope, ct).ConfigureAwait(false);
        CurrentAuthArchiveFleet production = await Environment.CaptureProductionFleetAsync(Scope, ct).ConfigureAwait(false);
        DateTimeOffset now = _clock.GetUtcNow();
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(local, Scope.LocalObservationPolicy, now);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(production, Scope.ProductionObservationPolicy, now, comparison: true);
        byte[] rows = CurrentAuthLocalSessionArchivePolicy.EncodeRows(local.Auth.Sessions);
        try
        {
            if (local.Auth.Sessions.Count != Scope.DeleteCount || CurrentAuthLocalSessionArchivePolicy.HashBytes(rows) != Scope.DeleteSetSha256 ||
                CurrentAuthLocalSessionArchivePolicy.RequireComparison(local.Auth, production.Auth) != Scope.ApplicationComparisonSha256) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
        finally { CryptographicOperations.ZeroMemory(rows); }
        await RequireAsync(ct).ConfigureAwait(false); return local.Auth;
    }
    internal async Task ReserveAsync(CancellationToken ct)
    {
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        try
        {
            await RequireAsync(ct).ConfigureAwait(false);
            await Environment.ReserveCreateNewAsync(Scope.OperationId, AuthorizationSha256, ct).ConfigureAwait(false);
            if (Interlocked.CompareExchange(ref _state, 2, 1) != 1) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
        catch { Stop(); throw; }
    }
    internal void RequireEvidenceSigner(P256MigrationEvidenceSigner signer)
    { if (signer.KeyId != _pins.EvidenceKeyId || signer.PublicKeyFingerprintSha256 != _pins.EvidenceFingerprint) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); } }
    internal async Task RetainRecoveryManifestAsync(CurrentAuthArchiveRecoveryManifest manifest, P256MigrationEvidenceSigner signer, CancellationToken ct)
    {
        RequireEvidenceSigner(signer);
        if (Volatile.Read(ref _state) != 2 || manifest.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(Scope) || manifest.AuthorizationSha256 != AuthorizationSha256)
        { Stop(); throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        var signed = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.RecoveryDomain, manifest, signer);
        await Environment.RetainRecoveryManifestAsync(JsonSerializer.SerializeToUtf8Bytes(signed), ct).ConfigureAwait(false);
    }
    internal async Task<string> RetainAsync(CurrentAuthArchiveReceipt receipt, P256MigrationEvidenceSigner signer, CancellationToken ct)
    {
        RequireEvidenceSigner(signer);
        bool successPhase = receipt.Classification is CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback;
        DateTimeOffset now = _clock.GetUtcNow();
        if (receipt.OperationId != Scope.OperationId || receipt.AuthorizationSha256 != AuthorizationSha256 || receipt.PreviousSha256 != _previousSha256 ||
            receipt.BeforeAuthSha256 != Scope.LocalObservationPolicy.BeforeDatabaseSha256["Auth"] || !CurrentAuthRepairPermit.HashShape(receipt.RecoveryManifestSha256) ||
            receipt.ObservedAtUtc.Offset != TimeSpan.Zero || receipt.ObservedAtUtc > now || now - receipt.ObservedAtUtc > TimeSpan.FromMinutes(5) ||
            (successPhase && (Volatile.Read(ref _state) != 2 || !CurrentAuthRepairPermit.HashShape(receipt.AfterAuthSha256 ?? ""))) ||
            (receipt.Classification == CurrentAppOwnedCommitClassification.Prepared && (_prepared is not null || _terminal)) ||
            (receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback && (_prepared is null || _terminal || receipt.AfterAuthSha256 != _prepared.AfterAuthSha256)))
        { Stop(); throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        CurrentAuthArchiveClaim claim = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReceiptDomain, receipt, signer);
        _ = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveReceipt>(claim, CurrentAuthLocalSessionArchivePolicy.ReceiptDomain,
            _pins.EvidenceKeyId, _pins.EvidenceFingerprint, _trust);
        string suffix = receipt.Classification switch
        {
            CurrentAppOwnedCommitClassification.Prepared => "prepared",
            CurrentAppOwnedCommitClassification.CommittedAndReadback => "committed-readback",
            CurrentAppOwnedCommitClassification.FailedBeforeCommit or CurrentAppOwnedCommitClassification.RolledBackBeforeCommit or CurrentAppOwnedCommitClassification.Uncertain => "failed-or-uncertain",
            _ => throw CurrentAuthLocalSessionArchivePolicy.Invalid(),
        };
        await Environment.RetainCreateNewAsync($"{Scope.OperationId:D}-Auth-session-archive-{suffix}.json", JsonSerializer.SerializeToUtf8Bytes(claim), ct).ConfigureAwait(false);
        _previousSha256 = CurrentAuthLocalSessionArchivePolicy.Hash(claim);
        if (receipt.Classification == CurrentAppOwnedCommitClassification.Prepared) { _prepared = receipt; }
        else if (receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback) { _terminal = true; }
        else { Stop(); }
        return _previousSha256;
    }
    internal void Stop()
    {
        _ = Interlocked.Exchange(ref _state, 3);
    }
}
