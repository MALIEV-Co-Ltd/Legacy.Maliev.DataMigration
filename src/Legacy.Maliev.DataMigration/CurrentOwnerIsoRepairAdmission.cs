using System.Text.Json;
using System.Text.Json.Serialization;

namespace Legacy.Maliev.DataMigration;

internal enum CurrentOwnerIsoProofAdmission
{
    PersistentWithClosedConsoleProof = 1, DisposableNativeBootstrap = 2,
    DisposableNativeComponent = 3, DisposableClosedConsoleBootstrap = 4
}
internal sealed record CurrentOwnerIsoRepairScope(Guid OperationId, CurrentOwnerIsoSelection Operation,
    string SourceCommitSha, string BeforeSchemaPlanSha256, string OwnerSourcesSha256, string ContractSha256,
    string OperationSha256, DeltaTargetAuthority Target, string TargetNamespace, string TargetCluster,
    string TargetGeneration, string TargetObservationSha256, string RunBindingSha256,
    IReadOnlyDictionary<string, string> BeforeDatabaseSha256, string GlobalPreservationSha256,
    string NativeProofSha256, string RecoveryReviewSha256, string ExactRoleTransitionReviewSha256,
    CurrentAppOwnedMaintenancePin Maintenance, string RecoveryPolicy,
    string SourceCatalogSha256, string MaintenanceValidatorSha256, string MaintenanceProofSha256,
    CurrentOwnerIsoProofAdmission ProofAdmission = CurrentOwnerIsoProofAdmission.PersistentWithClosedConsoleProof,
    CurrentOwnerIsoExecutionBootstrap? BootstrapSubject = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OwnerPolicySha256 = null);

internal sealed record CurrentOwnerIsoRepairSignedClaim(string Kind, CurrentOwnerIsoRepairScope Scope,
    Guid Nonce, string? ReviewSha256, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc,
    string KeyId, string? Signature);

internal sealed record CurrentOwnerIsoRepairSigningPins(string ReviewKeyId, string ReviewFingerprint,
    string AuthorizationKeyId, string AuthorizationFingerprint, string ReceiptKeyId, string ReceiptFingerprint);

// Internal closed Console implementation only. These methods must observe native target/source,
// protected custody and the complete fleet; serialized configuration cannot implement this interface.
// This interface alone supplies neither a storage-completeness proof nor execution authority.
internal interface ICurrentOwnerIsoRepairEnvironment
{
    Task RequireSourceAsync(string sourceCommitSha, CancellationToken cancellationToken);
    Task RequireOwnerSourcesAsync(string evidenceSha256, CancellationToken cancellationToken);
    // Authenticate exact target/owner/native-proof/role-transition/recovery evidence under protected
    // custody and reobserve capacity. Hash-shaped markers or a serialized callback never satisfy this.
    Task RequireResourceAndCustodyAsync(CurrentOwnerIsoRepairScope scope, CancellationToken cancellationToken);
    // Independently inventory every connectable non-template DB; compare complete snapshot phase
    // hashes AND the contract-derived physical phase for all active application databases. Only
    // authentic committed readback may advance an affected database. Return the original global
    // baseline digest after these checks, never a hash supplied by a configuration callback.
    Task<string> InspectGlobalPreservationAsync(CancellationToken cancellationToken);
    // Enumerate all exact operation-prefixed receipt slots and reject any retained receipt/reservation.
    Task RequireFreshOperationAsync(CurrentOwnerIsoRepairScope scope, CancellationToken cancellationToken);
    // Atomically recheck absence and create/hold an immutable operation reservation bound to this hash.
    // Any unknown result fails closed; never erase a reservation or adopt historical receipt evidence.
    Task ReserveFreshOperationAsync(CurrentOwnerIsoRepairScope scope, string authorizationSha256,
        CancellationToken cancellationToken);
    Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken cancellationToken);
    // After the executor connection closes: authenticate the prepared receipt, independently
    // read the complete current database and compare its full hash before advancing fleet phase.
    Task ObserveCommittedDatabaseAsync(CurrentOwnerIsoRepairReceipt prepared, CancellationToken cancellationToken);
}

/// <summary>Distinct fixed owner ISO permission; no conversion from an eight-table scope or historical transcript.</summary>
internal sealed class CurrentOwnerIsoRepairPermit
{
    internal const string MaintenanceValidator = "5fc4d018d7ecfec6517db497d1bc8e06dc204be91d1ae2a421f5d41f34d72324";
    internal const string FreshOnlyPolicy = "fresh-operation-only-stop-on-any-failure-v1";
    private static string ReviewKind(CurrentOwnerIsoRepairScope scope)
    {
        return OwnerClaimKind(scope, scope.ProofAdmission switch
        {
            CurrentOwnerIsoProofAdmission.DisposableNativeComponent => "current-owner-iso-component-review-v1",
            CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap => "current-owner-iso-closed-bootstrap-review-v1",
            CurrentOwnerIsoProofAdmission.PersistentWithClosedConsoleProof => "current-owner-iso-review-v1",
            CurrentOwnerIsoProofAdmission.DisposableNativeBootstrap => "current-owner-iso-review-v1",
            _ => "current-owner-iso-review-v1"
        });
    }

    private static string AuthorizationKind(CurrentOwnerIsoRepairScope scope)
    {
        return OwnerClaimKind(scope, scope.ProofAdmission switch
        {
            CurrentOwnerIsoProofAdmission.DisposableNativeComponent => "current-owner-iso-component-authorization-v1",
            CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap => "current-owner-iso-closed-bootstrap-authorization-v1",
            CurrentOwnerIsoProofAdmission.PersistentWithClosedConsoleProof => "current-owner-iso-authorization-v1",
            CurrentOwnerIsoProofAdmission.DisposableNativeBootstrap => "current-owner-iso-authorization-v1",
            _ => "current-owner-iso-authorization-v1"
        });
    }

    private static string OwnerClaimKind(CurrentOwnerIsoRepairScope scope, string kind)
    {
        return scope.OwnerPolicySha256 is null ? kind : kind[..^1] + "2";
    }

    private readonly CurrentOwnerIsoRepairSignedClaim _review;
    private readonly CurrentOwnerIsoRepairSignedClaim _authorization;
    private readonly FreshSchemaPlan _before;
    private readonly IReadOnlyList<CurrentOwnerIsoSourceObservation> _owners;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly CurrentOwnerIsoRepairSigningPins _pins;
    private readonly TimeProvider _clock;
    private int _executionState; // 0: unreserved, 1: running, 2: stopped, 3: reserving; never reset.
    private readonly Lock _databaseGate = new();
    private int _nextDatabase;
    private string? _activeDatabase;
    private string _previousReceipt = new('0', 64);

    private CurrentOwnerIsoRepairPermit(CurrentOwnerIsoRepairSignedClaim review,
        CurrentOwnerIsoRepairSignedClaim authorization, FreshSchemaPlan before, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners,
        IReceiptAttestationTrustStore trust, CurrentOwnerIsoRepairSigningPins pins,
        ICurrentOwnerIsoRepairEnvironment environment, TimeProvider clock)
    {
        _review = Clone(review); _authorization = Clone(authorization); _before = Clone(before); _owners = Clone(owners);
        _trust = trust; _pins = pins; Environment = environment; _clock = clock;
    }

    internal CurrentOwnerIsoRepairScope Scope => Clone(_authorization.Scope);
    internal ICurrentOwnerIsoRepairEnvironment Environment { get; }
    internal string AuthorizationSha256 => Hash(JsonSerializer.SerializeToUtf8Bytes(_authorization));

    internal static async Task<CurrentOwnerIsoRepairSignedClaim> IssueReviewAsync(
        CurrentOwnerIsoRepairScope scope, FreshSchemaPlan before, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners,
        IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> baseline, IReceiptAttestationTrustStore trust,
        CurrentOwnerIsoRepairSigningPins pins, ICurrentOwnerIsoRepairEnvironment environment,
        P256MigrationEvidenceSigner signer, DateTimeOffset expiresAtUtc, TimeProvider clock, CancellationToken ct)
    {
        scope = Clone(scope); before = Clone(before); owners = Clone(owners);
        baseline = baseline.Select(snapshot => snapshot with
        {
            Catalog = Array.AsReadOnly(snapshot.Catalog.ToArray()),
            Relations = Array.AsReadOnly(snapshot.Relations.ToArray()),
            Sequences = Array.AsReadOnly(snapshot.Sequences.ToArray()),
        }).ToArray();
        DateTimeOffset now = clock.GetUtcNow();
        RequireScope(scope, before, owners, trust, now);
        RequirePins(pins, trust);
        if (signer.KeyId != pins.ReviewKeyId || baseline.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != baseline.Count ||
            !baseline.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
            baseline.Any(x => CurrentAppOwnedSnapshotSerialization.Sha256(x) != scope.BeforeDatabaseSha256[x.Database]) ||
            CurrentAppOwnedSnapshotSerialization.Sha256(baseline) != scope.GlobalPreservationSha256)
        { throw Invalid(); }
        var unsigned = new CurrentOwnerIsoRepairSignedClaim(ReviewKind(scope), scope, Guid.NewGuid(), null,
            now, expiresAtUtc, signer.KeyId, null);
        RequireWindow(unsigned, now, TimeSpan.FromHours(12));
        var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(Payload(unsigned))) };
        RequireReview(signed, before, owners, trust, pins, now);
        await environment.RequireFreshOperationAsync(Clone(scope), ct).ConfigureAwait(false);
        await RequireEnvironmentAsync(environment, scope, ct).ConfigureAwait(false);
        if (await environment.InspectGlobalPreservationAsync(ct).ConfigureAwait(false) != scope.GlobalPreservationSha256)
        { throw Invalid(); }
        await RequireEnvironmentAsync(environment, scope, ct).ConfigureAwait(false);
        await environment.RequireFreshOperationAsync(Clone(scope), ct).ConfigureAwait(false);
        RequireReview(signed, before, owners, trust, pins, clock.GetUtcNow());
        return Clone(signed);
    }

    internal static async Task<CurrentOwnerIsoRepairSignedClaim> AuthorizeAsync(
        CurrentOwnerIsoRepairSignedClaim review, FreshSchemaPlan before, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners,
        IReceiptAttestationTrustStore trust, CurrentOwnerIsoRepairSigningPins pins,
        ICurrentOwnerIsoRepairEnvironment environment, P256MigrationEvidenceSigner signer,
        TimeProvider clock, CancellationToken ct)
    {
        review = Clone(review);
        DateTimeOffset now = clock.GetUtcNow();
        RequireReview(review, before, owners, trust, pins, now);
        if (signer.KeyId != pins.AuthorizationKeyId) { throw Invalid(); }
        DateTimeOffset expires = new[] { now.AddMinutes(15), review.ExpiresAtUtc, review.Scope.Maintenance.ExpiresAtUtc }.Min();
        var unsigned = new CurrentOwnerIsoRepairSignedClaim(AuthorizationKind(review.Scope), Clone(review.Scope), Guid.NewGuid(),
            Hash(JsonSerializer.SerializeToUtf8Bytes(review)), now, expires, signer.KeyId, null);
        var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(Payload(unsigned))) };
        _ = await AdmitAsync(review, signed, before, owners, trust, pins, environment, clock, ct).ConfigureAwait(false);
        return Clone(signed);
    }

    internal static async Task<CurrentOwnerIsoRepairPermit> AdmitAsync(CurrentOwnerIsoRepairSignedClaim review,
        CurrentOwnerIsoRepairSignedClaim authorization, FreshSchemaPlan before, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners,
        IReceiptAttestationTrustStore trust, CurrentOwnerIsoRepairSigningPins pins,
        ICurrentOwnerIsoRepairEnvironment environment, TimeProvider clock, CancellationToken ct)
    {
        var permit = new CurrentOwnerIsoRepairPermit(review, authorization, before, owners, trust, pins, environment, clock);
        await permit.RequireAsync(ct).ConfigureAwait(false);
        await environment.RequireFreshOperationAsync(permit.Scope, ct).ConfigureAwait(false);
        if (await environment.InspectGlobalPreservationAsync(ct).ConfigureAwait(false) != permit.Scope.GlobalPreservationSha256)
        { throw Invalid(); }
        await permit.RequireAsync(ct).ConfigureAwait(false);
        await environment.RequireFreshOperationAsync(permit.Scope, ct).ConfigureAwait(false);
        return permit;
    }

    // Called exactly once by the real executor/Console before any DDL. Verify-only does not consume it.
    internal async Task BeginExecutionAsync(CancellationToken ct)
    {
        if (Interlocked.CompareExchange(ref _executionState, 3, 0) != 0) { throw Invalid(); }
        try
        {
            await RequireAsync(ct).ConfigureAwait(false);
            await Environment.RequireFreshOperationAsync(Scope, ct).ConfigureAwait(false);
            if (await Environment.InspectGlobalPreservationAsync(ct).ConfigureAwait(false) != Scope.GlobalPreservationSha256)
            { throw Invalid(); }
            await Environment.ReserveFreshOperationAsync(Scope, AuthorizationSha256, ct).ConfigureAwait(false);
            await RequireAsync(ct).ConfigureAwait(false);
            if (Interlocked.CompareExchange(ref _executionState, 1, 3) != 3) { throw Invalid(); }
        }
        catch { Stop(); throw; }
    }

    // Executor catch/finally must stop on any failure, including uncertain commit or receipt publication.
    internal void Stop() { _ = Interlocked.Exchange(ref _executionState, 2); }

    internal async Task RequireExecutionAsync(CancellationToken ct)
    {
        if (Volatile.Read(ref _executionState) != 1) { throw Invalid(); }
        await RequireAsync(ct).ConfigureAwait(false);
        if (Volatile.Read(ref _executionState) != 1) { throw Invalid(); }
    }

    internal async Task ClaimDatabaseAsync(string database, string previousReceiptSha256, CancellationToken ct)
    {
        await RequireExecutionAsync(ct).ConfigureAwait(false);
        lock (_databaseGate)
        {
            string[] databases = PostgreSqlCurrentOwnerIsoRepair.Databases();
            if (Volatile.Read(ref _executionState) != 1 || _activeDatabase is not null || _nextDatabase >= databases.Length ||
                database != databases[_nextDatabase] || previousReceiptSha256 != _previousReceipt) { throw Invalid(); }
            _activeDatabase = database;
        }
    }

    internal void CompleteDatabase(string database, string terminalReceiptSha256)
    {
        lock (_databaseGate)
        {
            if (Volatile.Read(ref _executionState) != 1 || database != _activeDatabase || !HashShape(terminalReceiptSha256)) { throw Invalid(); }
            _previousReceipt = terminalReceiptSha256; _activeDatabase = null; _nextDatabase++;
        }
    }

    internal async Task RequireAsync(CancellationToken ct)
    {
        if (Volatile.Read(ref _executionState) == 2) { throw Invalid(); }
        ValidateClaims(_review, _authorization, _before, _owners, _trust, _pins, _clock.GetUtcNow());
        await RequireEnvironmentAsync(Environment, _authorization.Scope, ct).ConfigureAwait(false);
        if (Volatile.Read(ref _executionState) == 2) { throw Invalid(); }
    }

    internal static void ValidateClaims(CurrentOwnerIsoRepairSignedClaim review, CurrentOwnerIsoRepairSignedClaim authorization,
        FreshSchemaPlan before, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners, IReceiptAttestationTrustStore trust,
        CurrentOwnerIsoRepairSigningPins pins, DateTimeOffset now)
    {
        RequireReview(review, before, owners, trust, pins, now);
        if (authorization.Kind != AuthorizationKind(review.Scope) || authorization.KeyId != pins.AuthorizationKeyId ||
            authorization.Nonce == Guid.Empty || authorization.Nonce == review.Nonce ||
            authorization.IssuedAtUtc < review.IssuedAtUtc || authorization.ExpiresAtUtc > review.ExpiresAtUtc ||
            authorization.ExpiresAtUtc > review.Scope.Maintenance.ExpiresAtUtc ||
            authorization.ReviewSha256 != Hash(JsonSerializer.SerializeToUtf8Bytes(review)) ||
            JsonSerializer.Serialize(authorization.Scope) != JsonSerializer.Serialize(review.Scope))
        { throw Invalid(); }
        RequireSignature(authorization, trust, pins.AuthorizationFingerprint, now, TimeSpan.FromMinutes(15));
    }

    internal static void ValidateClosedBootstrapScope(CurrentOwnerIsoRepairScope scope, FreshSchemaPlan before,
        IReadOnlyList<CurrentOwnerIsoSourceObservation> owners, IReceiptAttestationTrustStore trust,
        CurrentOwnerIsoRepairSigningPins pins, DateTimeOffset now)
    {
        if (scope.ProofAdmission != CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap) { throw Invalid(); }
        RequireScope(scope, before, owners, trust, now); RequirePins(pins, trust);
        var subject = scope.BootstrapSubject ?? throw Invalid();
        if (new[] { pins.ReviewKeyId, pins.AuthorizationKeyId, pins.ReceiptKeyId }.Contains(subject.BootstrapKeyId, StringComparer.Ordinal) ||
            new[] { pins.ReviewFingerprint, pins.AuthorizationFingerprint, pins.ReceiptFingerprint }.Contains(subject.BootstrapFingerprint, StringComparer.Ordinal)) { throw Invalid(); }
    }
    internal static void ValidateComponentScope(CurrentOwnerIsoRepairScope scope, FreshSchemaPlan before,
        IReadOnlyList<CurrentOwnerIsoSourceObservation> owners, IReceiptAttestationTrustStore trust,
        CurrentOwnerIsoRepairSigningPins pins, DateTimeOffset now)
    {
        if (scope.ProofAdmission != CurrentOwnerIsoProofAdmission.DisposableNativeComponent) { throw Invalid(); }
        RequireScope(scope, before, owners, trust, now); RequirePins(pins, trust);
        var subject = scope.BootstrapSubject ?? throw Invalid();
        if (new[] { pins.ReviewKeyId, pins.AuthorizationKeyId, pins.ReceiptKeyId }.Contains(subject.BootstrapKeyId, StringComparer.Ordinal) ||
            new[] { pins.ReviewFingerprint, pins.AuthorizationFingerprint, pins.ReceiptFingerprint }.Contains(subject.BootstrapFingerprint, StringComparer.Ordinal)) { throw Invalid(); }
    }
    internal static void ValidateReview(CurrentOwnerIsoRepairSignedClaim review, FreshSchemaPlan before, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners,
        IReceiptAttestationTrustStore trust, CurrentOwnerIsoRepairSigningPins pins, DateTimeOffset now)
    {
        RequireReview(review, before, owners, trust, pins, now);
    }

    private static void RequireReview(CurrentOwnerIsoRepairSignedClaim review, FreshSchemaPlan before, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners,
        IReceiptAttestationTrustStore trust, CurrentOwnerIsoRepairSigningPins pins, DateTimeOffset now)
    {
        RequireScope(review.Scope, before, owners, trust, now);
        RequirePins(pins, trust);
        if (review.Scope.BootstrapSubject is { } subject && (new[] { pins.ReviewKeyId, pins.AuthorizationKeyId, pins.ReceiptKeyId }.Contains(subject.BootstrapKeyId, StringComparer.Ordinal) ||
            new[] { pins.ReviewFingerprint, pins.AuthorizationFingerprint, pins.ReceiptFingerprint }.Contains(subject.BootstrapFingerprint, StringComparer.Ordinal))) { throw Invalid(); }
        if (review.Kind != ReviewKind(review.Scope) || review.KeyId != pins.ReviewKeyId || review.Nonce == Guid.Empty || review.ReviewSha256 is not null)
        { throw Invalid(); }
        RequireSignature(review, trust, pins.ReviewFingerprint, now, TimeSpan.FromHours(12));
    }

    private static void RequireScope(CurrentOwnerIsoRepairScope scope, FreshSchemaPlan before, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners,
        IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        if ((scope.Target.Kind == DeltaTargetAuthorityKind.ProductionCloudNativePg && scope.OwnerPolicySha256 is null) ||
            (scope.OwnerPolicySha256 is not null && scope.OwnerPolicySha256 != CurrentOwnerIsoNativePreservation.OwnerPolicySha256(scope.Target))) { throw Invalid(); }
        ApprovedCurrentOwnerIsoOverlay contract = ApprovedCurrentOwnerIsoOverlay.Create(before, scope.SourceCommitSha, scope.Operation, owners, now);
        bool local = scope.Target.Kind == DeltaTargetAuthorityKind.LocalAspire;
        bool production = scope.Target.Kind == DeltaTargetAuthorityKind.ProductionCloudNativePg;
        bool component = scope.ProofAdmission == CurrentOwnerIsoProofAdmission.DisposableNativeComponent;
        bool closedBootstrap = scope.ProofAdmission == CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap;
        if ((component || closedBootstrap) != (scope.BootstrapSubject is not null)) { throw Invalid(); }
        if (component || closedBootstrap) { CurrentOwnerIsoExecutionBootstrapValidator.Require(scope.BootstrapSubject!, scope, before, trust, now); }
        if (!Enum.IsDefined(scope.ProofAdmission) ||
            ((scope.ProofAdmission is CurrentOwnerIsoProofAdmission.DisposableNativeBootstrap or CurrentOwnerIsoProofAdmission.DisposableNativeComponent or CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap) &&
                (!local || !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) ||
                 DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(scope.Target))) ||
            scope.OperationId == Guid.Empty || scope.Operation != CurrentOwnerIsoSelection.LiteralWidthV1 ||
            !HashShape(scope.SourceCatalogSha256) || scope.MaintenanceValidatorSha256 != MaintenanceValidator ||
            (!component && (!HashShape(scope.MaintenanceProofSha256) || scope.MaintenanceProofSha256 == scope.NativeProofSha256)) ||
            scope.RecoveryPolicy != FreshOnlyPolicy || scope.ContractSha256 != contract.ComputeSha256() ||
            scope.OperationSha256 != PostgreSqlCurrentOwnerIsoRepair.OperationSha256 ||
            scope.BeforeSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(before) ||
            scope.OwnerSourcesSha256 != CurrentAppOwnedSnapshotSerialization.Sha256(owners) ||
            scope.SourceCommitSha.Length != 40 || !scope.SourceCommitSha.All(char.IsAsciiHexDigit) ||
            !HashShape(scope.GlobalPreservationSha256) || (!component && !HashShape(scope.NativeProofSha256)) ||
            (!(component || closedBootstrap) && (!HashShape(scope.RecoveryReviewSha256) || !HashShape(scope.ExactRoleTransitionReviewSha256))) ||
            !HashShape(scope.TargetObservationSha256) || !HashShape(scope.RunBindingSha256) ||
            !HashShape(scope.Target.SystemIdentifierSha256) || string.IsNullOrWhiteSpace(scope.TargetGeneration) ||
            !ReviewedProductionRepairInventory.MatchesKeys(scope.Target.Kind, scope.BeforeDatabaseSha256.Keys) ||
            scope.BeforeDatabaseSha256.Keys.Any(string.IsNullOrWhiteSpace) || scope.BeforeDatabaseSha256.Values.Any(x => !HashShape(x)) ||
            !DatabaseInventory.ActiveDatabases.All(scope.BeforeDatabaseSha256.ContainsKey) ||
            !scope.BeforeDatabaseSha256.ContainsKey("postgres") || !scope.BeforeDatabaseSha256.ContainsKey("Auth") ||
            !((local && scope.TargetNamespace == "local-aspire" && scope.TargetCluster == "legacy-postgres-main-local" &&
                DeltaSynchronizationPlanProducer.ValidAuthority(scope.Target, scope.TargetNamespace, scope.TargetCluster)) ||
              (production && scope.TargetNamespace == "maliev-legacy" && scope.TargetCluster == "legacy-postgres-main" &&
                DeltaSynchronizationPlanProducer.ValidAuthority(scope.Target, scope.TargetNamespace, scope.TargetCluster))))
        { throw Invalid(); }
        CurrentAppOwnedMaintenancePin m = scope.Maintenance;
        if (string.IsNullOrWhiteSpace(m.Role) || m.RoleComment != "legacy-maliev-current-owner-iso-v1:" + scope.RunBindingSha256 ||
            m.IssuedAtUtc.Offset != TimeSpan.Zero || m.ExpiresAtUtc.Offset != TimeSpan.Zero || m.Postmaster.Offset != TimeSpan.Zero ||
            m.ConfigLoaded.Offset != TimeSpan.Zero || m.IssuedAtUtc > now || m.ExpiresAtUtc <= now || m.ExpiresAtUtc <= m.IssuedAtUtc ||
            m.ExpiresAtUtc - m.IssuedAtUtc > TimeSpan.FromHours(4) || m.Postmaster > now || m.ConfigLoaded > now ||
            !HashShape(m.HbaSha256) || !HashShape(m.HbaRulesSha256) || string.IsNullOrWhiteSpace(m.HbaPath))
        { throw Invalid(); }
    }

    private static void RequirePins(CurrentOwnerIsoRepairSigningPins pins, IReceiptAttestationTrustStore trust)
    {
        string[] ids = [pins.ReviewKeyId, pins.AuthorizationKeyId, pins.ReceiptKeyId];
        string[] fingerprints = [pins.ReviewFingerprint, pins.AuthorizationFingerprint, pins.ReceiptFingerprint];
        if (ids.Any(string.IsNullOrWhiteSpace) || ids.Distinct(StringComparer.Ordinal).Count() != 3 ||
            fingerprints.Any(x => !HashShape(x)) || fingerprints.Distinct(StringComparer.Ordinal).Count() != 3)
        { throw Invalid(); }
        for (int i = 0; i < ids.Length; i++)
        { if (!trust.TryGetPublicKeyFingerprintSha256(ids[i], out string actual) || actual != fingerprints[i]) { throw Invalid(); } }
    }

    private static void RequireSignature(CurrentOwnerIsoRepairSignedClaim claim, IReceiptAttestationTrustStore trust,
        string fingerprint, DateTimeOffset now, TimeSpan maximum)
    {
        RequireWindow(claim, now, maximum);
        if (string.IsNullOrWhiteSpace(claim.Signature) || !trust.TryGetPublicKeyFingerprintSha256(claim.KeyId, out string actual) || actual != fingerprint)
        { throw Invalid(); }
        try { if (!trust.Verify(claim.KeyId, Payload(claim), Convert.FromBase64String(claim.Signature))) { throw Invalid(); } }
        catch (FormatException) { throw Invalid(); }
    }

    private static void RequireWindow(CurrentOwnerIsoRepairSignedClaim claim, DateTimeOffset now, TimeSpan maximum)
    {
        if (claim.IssuedAtUtc.Offset != TimeSpan.Zero || claim.ExpiresAtUtc.Offset != TimeSpan.Zero || claim.IssuedAtUtc > now ||
            claim.ExpiresAtUtc <= now || claim.ExpiresAtUtc <= claim.IssuedAtUtc || claim.ExpiresAtUtc - claim.IssuedAtUtc > maximum)
        { throw Invalid(); }
    }

    private static async Task RequireEnvironmentAsync(ICurrentOwnerIsoRepairEnvironment environment,
        CurrentOwnerIsoRepairScope scope, CancellationToken ct)
    {
        await environment.RequireSourceAsync(scope.SourceCommitSha, ct).ConfigureAwait(false);
        await environment.RequireOwnerSourcesAsync(scope.OwnerSourcesSha256, ct).ConfigureAwait(false);
        await environment.RequireResourceAndCustodyAsync(Clone(scope), ct).ConfigureAwait(false);
    }

    internal static byte[] Payload(CurrentOwnerIsoRepairSignedClaim claim)
    {
        return [.. System.Text.Encoding.UTF8.GetBytes(claim.Scope.OwnerPolicySha256 is null
            ? "Legacy.Maliev.CurrentOwnerIsoRepair.Claim.v1\0" : "Legacy.Maliev.CurrentOwnerIsoRepair.Claim.v2\0"),
            .. JsonSerializer.SerializeToUtf8Bytes(claim with { Signature = null })];
    }

    private static string Hash(byte[] value)
    {
        return CurrentAppOwnedRepairPermit.Hash(value);
    }

    private static bool HashShape(string value)
    {
        return CurrentAppOwnedRepairPermit.HashShape(value);
    }

    private static T Clone<T>(T value)
    {
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value)) ?? throw Invalid();
    }

    internal static MigrationExecutionException Invalid()
    {
        return new("current_owner_iso_admission_invalid",
            "The distinct fresh owner ISO admission failed; retained operations cannot be replayed.");
    }
}
