using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Legacy.Maliev.DataMigration;

internal enum CurrentAuthRepairOperation { SixteenSameTypeTextCollations = 1 }
internal enum CurrentAuthProofAdmission { ClosedConsole = 0, DisposableNativeBootstrap = 1, DisposableNativeComponent = 2, DisposableClosedConsoleBootstrap = 3 }
internal sealed record CurrentAuthRepairScope(Guid OperationId, CurrentAuthRepairOperation Operation,
    string SourceCommitSha, string SourceSchemaPlanSha256, string AuthOwnerCommitSha,
    string AuthOwnerSourcePinsSha256, string AuthClosureSha256, string AuthBeforeSchemaSha256,
    string AuthAfterSchemaSha256, string OperationSha256, string AuthHelperProofSha256,
    string MaintenanceValidatorSha256, DeltaTargetAuthority Target, string TargetNamespace, string TargetCluster,
    string TargetGeneration, string TargetObservationSha256, string RunBindingSha256,
    IReadOnlyDictionary<string, string> BeforeDatabaseSha256, string GlobalPreservationSha256,
    string NativeProofSha256, string RecoveryReviewSha256, string ExactRoleTransitionReviewSha256,
    CurrentAppOwnedMaintenancePin Maintenance,
    CurrentAuthProofAdmission ProofAdmission = CurrentAuthProofAdmission.ClosedConsole,
    CurrentAuthComponentBootstrapSubject? ComponentSubject = null,
    CurrentAuthClosedBootstrapSeed? ClosedBootstrapSubject = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OwnerPolicySha256 = null);
internal sealed record CurrentAuthRepairSignedClaim(string Kind, CurrentAuthRepairScope Scope,
    Guid Nonce, string? ReviewSha256, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc, string KeyId, string? Signature);
internal sealed record CurrentAuthRepairSigningPins(string ReviewKeyId, string ReviewFingerprint,
    string AuthorizationKeyId, string AuthorizationFingerprint, string ReceiptKeyId, string ReceiptFingerprint);

// Future closed Console only; serialized callback configuration grants no authority.
internal interface ICurrentAuthRepairEnvironment
{
    Task RequireSourceAsync(string sourceCommitSha, CancellationToken ct);
    Task RequireAuthOwnerSourceAsync(CurrentAuthRepairScope scope, CancellationToken ct);
    Task RequireSource23PhysicalBaselineAsync(FreshSchemaPlan sourceBaseline, CancellationToken ct);
    Task RequireResourceAndCustodyAsync(CurrentAuthRepairScope scope, CancellationToken ct);
    Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CurrentAuthRepairScope scope, CancellationToken ct);
    Task RequireFreshOperationAsync(CurrentAuthRepairScope scope, CancellationToken ct);
    Task ReserveFreshOperationAsync(CurrentAuthRepairScope scope, string authorizationSha256, CancellationToken ct);
    Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken ct);
}

internal sealed class CurrentAuthRepairPermit
{
    internal const string MaintenanceValidator = "5fc4d018d7ecfec6517db497d1bc8e06dc204be91d1ae2a421f5d41f34d72324";
    private readonly CurrentAuthRepairSignedClaim _review, _authorization;
    private readonly FreshSchemaPlan _sourceBaseline;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly TimeProvider _clock;
    private int _state; // unreserved0, running1, stopped2, reserving3; never reset.
    internal CurrentAuthRepairScope Scope => Clone(_authorization.Scope);
    internal CurrentAuthRepairSigningPins SigningPins { get; }
    internal ICurrentAuthRepairEnvironment Environment { get; }
    internal string AuthorizationSha256 => Hash(JsonSerializer.SerializeToUtf8Bytes(_authorization));
    private CurrentAuthRepairPermit(CurrentAuthRepairSignedClaim review, CurrentAuthRepairSignedClaim authorization,
        FreshSchemaPlan baseline, IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins,
        ICurrentAuthRepairEnvironment environment, TimeProvider clock)
    {
        _review = Clone(review); _authorization = Clone(authorization); _sourceBaseline = Clone(baseline);
        _trust = trust; SigningPins = pins; Environment = environment; _clock = clock;
    }

    internal static string OwnerPinsSha256 => Hash(JsonSerializer.SerializeToUtf8Bytes(ApprovedCurrentAuthSchema.SourcePins()
        .OrderBy(x => x.RelativePath, StringComparer.Ordinal).ToArray()));
    internal static string OperationSha256(FreshSchemaPlan source, string helperProof)
    {
        return Hash(JsonSerializer.SerializeToUtf8Bytes(new
        {
            Domain = "Legacy.Maliev.CurrentAuth.FixedSixteenCollations.v1",
            Source = SchemaPlanCanonicalizer.ComputeSha256(source),
            ApprovedCurrentAuthSchema.AuthServiceCommit,
            OwnerPins = OwnerPinsSha256,
            ApprovedCurrentAuthSchema.ClosureSha256,
            Before = ApprovedCurrentAuthSchema.PhysicalSha256(false),
            After = ApprovedCurrentAuthSchema.PhysicalSha256(true),
            Operands = ApprovedCurrentAuthSchema.CollationOperands(),
            HelperProof = helperProof,
            MaintenanceValidator,
        }));
    }

    internal static string FleetSha256(IReadOnlyDictionary<string, string> fleet)
    {
        return Hash(JsonSerializer.SerializeToUtf8Bytes(
            fleet.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new { Database = x.Key, Sha256 = x.Value }).ToArray()));
    }

    internal static void ValidateReview(CurrentAuthRepairSignedClaim review, FreshSchemaPlan source,
        IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins, DateTimeOffset now)
    {
        RequireScope(review.Scope, source, trust, now); RequirePins(trust, pins);
        if (review.Kind != ReviewKind(review.Scope) || review.KeyId != pins.ReviewKeyId || review.ReviewSha256 is not null ||
            review.Nonce == Guid.Empty || review.ExpiresAtUtc > review.Scope.Maintenance.ExpiresAtUtc ||
            !Verify(review, trust, pins.ReviewFingerprint, now, TimeSpan.FromHours(12))) { throw Invalid(); }
    }
    internal static void ValidateClaims(CurrentAuthRepairSignedClaim review, CurrentAuthRepairSignedClaim authorization,
        FreshSchemaPlan source, IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins, DateTimeOffset now)
    {
        ValidateReview(review, source, trust, pins, now);
        if (authorization.Kind != AuthorizationKind(review.Scope) || authorization.KeyId != pins.AuthorizationKeyId ||
            JsonSerializer.Serialize(review.Scope) != JsonSerializer.Serialize(authorization.Scope) ||
            authorization.ReviewSha256 != Hash(JsonSerializer.SerializeToUtf8Bytes(review)) || authorization.Nonce == Guid.Empty ||
            authorization.Nonce == review.Nonce || authorization.IssuedAtUtc < review.IssuedAtUtc || authorization.ExpiresAtUtc > review.ExpiresAtUtc ||
            authorization.ExpiresAtUtc > authorization.Scope.Maintenance.ExpiresAtUtc ||
            !Verify(authorization, trust, pins.AuthorizationFingerprint, now, TimeSpan.FromMinutes(15))) { throw Invalid(); }
    }
    internal static async Task<CurrentAuthRepairSignedClaim> IssueReviewAsync(CurrentAuthRepairScope scope, FreshSchemaPlan source,
        IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> baseline, IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins,
        ICurrentAuthRepairEnvironment environment, P256MigrationEvidenceSigner signer, DateTimeOffset expiresAtUtc, TimeProvider clock, CancellationToken ct)
    {
        scope = Clone(scope); source = Clone(source); baseline = baseline.Select(CopySnapshot).ToArray();
        if (signer.KeyId != pins.ReviewKeyId || !Matches(baseline, scope.BeforeDatabaseSha256)) { throw Invalid(); }
        var unsigned = new CurrentAuthRepairSignedClaim(ReviewKind(scope), scope, Guid.NewGuid(), null,
            clock.GetUtcNow(), expiresAtUtc, signer.KeyId, null);
        var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(Payload(unsigned))) };
        ValidateReview(signed, source, trust, pins, clock.GetUtcNow()); // pure signature/shape before any callback
        await environment.RequireFreshOperationAsync(Clone(scope), ct).ConfigureAwait(false);
        await RequireEnvironmentAsync(environment, scope, source, ct).ConfigureAwait(false);
        if (!Matches(await environment.InspectFleetAsync(Clone(scope), ct).ConfigureAwait(false), scope.BeforeDatabaseSha256)) { throw Invalid(); }
        await RequireEnvironmentAsync(environment, scope, source, ct).ConfigureAwait(false);
        await environment.RequireFreshOperationAsync(Clone(scope), ct).ConfigureAwait(false);
        ValidateReview(signed, source, trust, pins, clock.GetUtcNow()); return Clone(signed);
    }
    internal static async Task<CurrentAuthRepairSignedClaim> AuthorizeAsync(CurrentAuthRepairSignedClaim review, FreshSchemaPlan source,
        IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins, ICurrentAuthRepairEnvironment environment,
        P256MigrationEvidenceSigner signer, TimeProvider clock, CancellationToken ct)
    {
        review = Clone(review); source = Clone(source); DateTimeOffset now = clock.GetUtcNow();
        ValidateReview(review, source, trust, pins, now);
        if (signer.KeyId != pins.AuthorizationKeyId) { throw Invalid(); }
        var unsigned = new CurrentAuthRepairSignedClaim(AuthorizationKind(review.Scope), Clone(review.Scope), Guid.NewGuid(),
            Hash(JsonSerializer.SerializeToUtf8Bytes(review)), now, new[] { now.AddMinutes(15), review.ExpiresAtUtc, review.Scope.Maintenance.ExpiresAtUtc }.Min(), signer.KeyId, null);
        var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(Payload(unsigned))) };
        _ = await AdmitAsync(review, signed, source, trust, pins, environment, clock, ct).ConfigureAwait(false); return Clone(signed);
    }
    internal static async Task<CurrentAuthRepairPermit> AdmitAsync(CurrentAuthRepairSignedClaim review, CurrentAuthRepairSignedClaim authorization,
        FreshSchemaPlan source, IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins,
        ICurrentAuthRepairEnvironment environment, TimeProvider clock, CancellationToken ct)
    {
        review = Clone(review); authorization = Clone(authorization); source = Clone(source);
        ValidateClaims(review, authorization, source, trust, pins, clock.GetUtcNow());
        var permit = new CurrentAuthRepairPermit(review, authorization, source, trust, pins, environment, clock);
        try
        {
            await environment.RequireFreshOperationAsync(permit.Scope, ct).ConfigureAwait(false);
            await permit.RequireAsync(ct).ConfigureAwait(false);
            await permit.RequireFleetAsync(permit.Scope.BeforeDatabaseSha256, ct).ConfigureAwait(false);
            await permit.RequireAsync(ct).ConfigureAwait(false);
            await environment.RequireFreshOperationAsync(permit.Scope, ct).ConfigureAwait(false); return permit;
        }
        catch { permit.Stop(); throw; }
    }
    internal async Task StartAsync(CancellationToken ct)
    {
        if (Interlocked.CompareExchange(ref _state, 3, 0) != 0) { Stop(); throw Invalid(); }
        try
        {
            await RequireAsync(ct).ConfigureAwait(false);
            await Environment.RequireFreshOperationAsync(Scope, ct).ConfigureAwait(false);
            await RequireFleetAsync(Scope.BeforeDatabaseSha256, ct).ConfigureAwait(false);
            await Environment.ReserveFreshOperationAsync(Scope, AuthorizationSha256, ct).ConfigureAwait(false);
            await RequireAsync(ct).ConfigureAwait(false);
            if (Interlocked.CompareExchange(ref _state, 1, 3) != 3) { throw Invalid(); }
        }
        catch { Stop(); throw; }
    }
    internal async Task RequireAsync(CancellationToken ct)
    {
        try
        {
            if (Volatile.Read(ref _state) == 2) { throw Invalid(); }
            ValidateClaims(_review, _authorization, _sourceBaseline, _trust, SigningPins, _clock.GetUtcNow());
            await RequireEnvironmentAsync(Environment, Scope, Clone(_sourceBaseline), ct).ConfigureAwait(false);
            if (Volatile.Read(ref _state) == 2) { throw Invalid(); }
        }
        catch { Stop(); throw; }
    }
    internal async Task RequireFleetAsync(IReadOnlyDictionary<string, string> expected, CancellationToken ct)
    {
        try
        {
            if (Volatile.Read(ref _state) == 2 || !expected.Keys.Order(StringComparer.Ordinal).SequenceEqual(Scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))) { throw Invalid(); }
            if (!Matches(await Environment.InspectFleetAsync(Scope, ct).ConfigureAwait(false), expected) || Volatile.Read(ref _state) == 2) { throw Invalid(); }
        }
        catch { Stop(); throw; }
    }
    internal void Stop()
    {
        _ = Interlocked.Exchange(ref _state, 2);
    }

    private static async Task RequireEnvironmentAsync(ICurrentAuthRepairEnvironment environment, CurrentAuthRepairScope scope, FreshSchemaPlan source, CancellationToken ct)
    {
        await environment.RequireSourceAsync(scope.SourceCommitSha, ct).ConfigureAwait(false);
        await environment.RequireAuthOwnerSourceAsync(Clone(scope), ct).ConfigureAwait(false);
        await environment.RequireSource23PhysicalBaselineAsync(Clone(source), ct).ConfigureAwait(false);
        await environment.RequireResourceAndCustodyAsync(Clone(scope), ct).ConfigureAwait(false);
    }
    private static bool Matches(IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> snapshots, IReadOnlyDictionary<string, string> expected)
    {
        return snapshots.Count == expected.Count && snapshots.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() == snapshots.Count &&
        snapshots.All(x => expected.TryGetValue(x.Database, out string? hash) && x.Sha256 == hash);
    }

    private static void RequireScope(CurrentAuthRepairScope scope, FreshSchemaPlan source, IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        RequireProofAdmission(scope);
        if ((scope.Target.Kind == DeltaTargetAuthorityKind.ProductionCloudNativePg && scope.OwnerPolicySha256 is null) ||
            (scope.OwnerPolicySha256 is not null && scope.OwnerPolicySha256 != CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.AuthCollation16, scope.Target))) { throw Invalid(); }
        bool component = scope.ProofAdmission == CurrentAuthProofAdmission.DisposableNativeComponent;
        if (component) { CurrentAuthComponentBootstrap.RequireSubject(scope, source, trust, now); }
        bool closedBootstrap = scope.ProofAdmission == CurrentAuthProofAdmission.DisposableClosedConsoleBootstrap;
        if (closedBootstrap)
        {
            var seed = scope.ClosedBootstrapSubject ?? throw Invalid();
            if (!trust.TryGetPublicKeyFingerprintSha256(seed.KeyId, out string fingerprint)) { throw Invalid(); }
            CurrentAuthClosedBootstrap.RequireScope(seed, scope, source, trust, seed.KeyId, fingerprint, now);
        }
        ProductionSchemaCatalogInspector.ValidatePlan(source, now);
        if (!ApprovedConsumerOverlaySelection.IsApproved(source) || source.Databases.Sum(x => x.Tables.Count) != 100 ||
            !source.Databases.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases.Order(StringComparer.Ordinal)) ||
            source.Databases.Any(x => x.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(x.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3)) ||
            source.Databases.Single(x => x.Database == "Quotation").SourceDispositionProfile != ApprovedSourceDispositionManifest.QuotationOutboxesV1 ||
            scope.OperationId == Guid.Empty || scope.Operation != CurrentAuthRepairOperation.SixteenSameTypeTextCollations ||
            scope.SourceCommitSha != source.SourceCommitSha || scope.SourceCommitSha.Length != 40 || !scope.SourceCommitSha.All(x => x is (>= '0' and <= '9') or (>= 'a' and <= 'f')) ||
            scope.SourceSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(source) || scope.AuthOwnerCommitSha != ApprovedCurrentAuthSchema.AuthServiceCommit ||
            scope.AuthOwnerSourcePinsSha256 != OwnerPinsSha256 || scope.AuthClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 ||
            scope.AuthBeforeSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(false) || scope.AuthAfterSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(true) ||
            !HashShape(scope.AuthHelperProofSha256) || scope.MaintenanceValidatorSha256 != MaintenanceValidator ||
            ApprovedCurrentAuthSchema.SourcePins().Length != 13 || ApprovedCurrentAuthSchema.CollationOperands().Length != 16 ||
            (component ? scope.OperationSha256 != CurrentAuthComponentBootstrap.SubjectSha256(scope.ComponentSubject!) : closedBootstrap ?
                scope.OperationSha256 != CurrentAuthClosedBootstrap.SubjectSha256(scope.ClosedBootstrapSubject!) : scope.OperationSha256 != OperationSha256(source, scope.AuthHelperProofSha256)) ||
            !HashShape(scope.TargetObservationSha256) || !HashShape(scope.RunBindingSha256) || (!component && (!HashShape(scope.NativeProofSha256) || !HashShape(scope.RecoveryReviewSha256) || !HashShape(scope.ExactRoleTransitionReviewSha256))) ||
            scope.GlobalPreservationSha256 != FleetSha256(scope.BeforeDatabaseSha256) || scope.BeforeDatabaseSha256.Values.Any(x => !HashShape(x)) ||
            !DatabaseInventory.ActiveDatabases.All(scope.BeforeDatabaseSha256.ContainsKey) || !scope.BeforeDatabaseSha256.ContainsKey("Auth") || !scope.BeforeDatabaseSha256.ContainsKey("postgres") ||
            string.IsNullOrWhiteSpace(scope.TargetGeneration) ||
            !((DeltaSynchronizationPlanProducer.ValidAuthority(scope.Target, "local-aspire", "legacy-postgres-main-local") && scope.TargetNamespace == "local-aspire" && scope.TargetCluster == "legacy-postgres-main-local" &&
                scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]).Order(StringComparer.Ordinal))) ||
              (DeltaSynchronizationPlanProducer.ValidAuthority(scope.Target, "maliev-legacy", "legacy-postgres-main") && scope.TargetNamespace == "maliev-legacy" && scope.TargetCluster == "legacy-postgres-main" && ReviewedProductionRepairInventory.MatchesKeys(scope.Target.Kind, scope.BeforeDatabaseSha256.Keys)))) { throw Invalid(); }
        CurrentAppOwnedMaintenancePin m = scope.Maintenance;
        if (string.IsNullOrWhiteSpace(m.Role) || m.RoleComment != "legacy-maliev-current-auth-v1:" + scope.RunBindingSha256 ||
            m.IssuedAtUtc.Offset != TimeSpan.Zero || m.ExpiresAtUtc.Offset != TimeSpan.Zero || m.Postmaster.Offset != TimeSpan.Zero || m.ConfigLoaded.Offset != TimeSpan.Zero ||
            m.IssuedAtUtc > now || m.ExpiresAtUtc <= now || m.ExpiresAtUtc <= m.IssuedAtUtc || m.ExpiresAtUtc - m.IssuedAtUtc > TimeSpan.FromHours(4) ||
            m.Postmaster > now || m.ConfigLoaded > now || !HashShape(m.HbaSha256) || !HashShape(m.HbaRulesSha256) || string.IsNullOrWhiteSpace(m.HbaPath)) { throw Invalid(); }
    }
    private static string ReviewKind(CurrentAuthRepairScope scope)
    {
        return OwnerClaimKind(scope, scope.ProofAdmission == CurrentAuthProofAdmission.DisposableNativeComponent ? "current-auth-component-review-v1" : scope.ProofAdmission == CurrentAuthProofAdmission.DisposableClosedConsoleBootstrap ? "current-auth-named-bootstrap-review-v1" : "current-auth-repair-review-v1");
    }

    private static string AuthorizationKind(CurrentAuthRepairScope scope)
    {
        return OwnerClaimKind(scope, scope.ProofAdmission == CurrentAuthProofAdmission.DisposableNativeComponent ? "current-auth-component-authorization-v1" : scope.ProofAdmission == CurrentAuthProofAdmission.DisposableClosedConsoleBootstrap ? "current-auth-named-bootstrap-authorization-v1" : "current-auth-repair-authorization-v1");
    }

    private static string OwnerClaimKind(CurrentAuthRepairScope scope, string kind)
    {
        return scope.OwnerPolicySha256 is null ? kind : kind[..^1] + "2";
    }

    internal static void RequireProofAdmission(CurrentAuthRepairScope scope)
    {
        if (scope.ProofAdmission == CurrentAuthProofAdmission.DisposableNativeComponent != (scope.ComponentSubject is not null)) { throw Invalid(); }
        if (scope.ProofAdmission == CurrentAuthProofAdmission.DisposableClosedConsoleBootstrap != (scope.ClosedBootstrapSubject is not null)) { throw Invalid(); }
        if (scope.ProofAdmission is not (CurrentAuthProofAdmission.ClosedConsole or CurrentAuthProofAdmission.DisposableNativeBootstrap or CurrentAuthProofAdmission.DisposableNativeComponent or CurrentAuthProofAdmission.DisposableClosedConsoleBootstrap) ||
            ((scope.ProofAdmission is CurrentAuthProofAdmission.DisposableNativeBootstrap or CurrentAuthProofAdmission.DisposableNativeComponent or CurrentAuthProofAdmission.DisposableClosedConsoleBootstrap) &&
                !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target))) { throw Invalid(); }
    }
    private static void RequirePins(IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins)
    {
        string[] ids = [pins.ReviewKeyId, pins.AuthorizationKeyId, pins.ReceiptKeyId], hashes = [pins.ReviewFingerprint, pins.AuthorizationFingerprint, pins.ReceiptFingerprint];
        if (ids.Any(string.IsNullOrWhiteSpace) || ids.Distinct(StringComparer.Ordinal).Count() != 3 || hashes.Any(x => !HashShape(x)) || hashes.Distinct(StringComparer.Ordinal).Count() != 3) { throw Invalid(); }
        for (int i = 0; i < 3; i++) { if (!trust.TryGetPublicKeyFingerprintSha256(ids[i], out string actual) || actual != hashes[i]) { throw Invalid(); } }
    }
    internal static byte[] Payload(CurrentAuthRepairSignedClaim claim)
    {
        return [.. Encoding.UTF8.GetBytes("Legacy.Maliev.CurrentAuth." + claim.Kind + "\0"), .. JsonSerializer.SerializeToUtf8Bytes(claim with { Signature = null })];
    }

    private static bool Verify(CurrentAuthRepairSignedClaim claim, IReceiptAttestationTrustStore trust, string fingerprint, DateTimeOffset now, TimeSpan maximum)
    {
        if (claim.IssuedAtUtc.Offset != TimeSpan.Zero || claim.ExpiresAtUtc.Offset != TimeSpan.Zero || claim.IssuedAtUtc > now || claim.ExpiresAtUtc <= now || claim.ExpiresAtUtc <= claim.IssuedAtUtc || claim.ExpiresAtUtc - claim.IssuedAtUtc > maximum || string.IsNullOrWhiteSpace(claim.Signature) || !trust.TryGetPublicKeyFingerprintSha256(claim.KeyId, out string actual) || actual != fingerprint) { return false; }
        try { return trust.Verify(claim.KeyId, Payload(claim), Convert.FromBase64String(claim.Signature)); } catch (FormatException) { return false; }
    }
    internal static CurrentAppOwnedDatabaseSnapshot CopySnapshot(CurrentAppOwnedDatabaseSnapshot value)
    {
        return new(value.Database, Array.AsReadOnly(value.Catalog.ToArray()), Array.AsReadOnly(value.Relations.ToArray()), Array.AsReadOnly(value.Sequences.ToArray()));
    }

    internal static string Hash(byte[] bytes)
    {
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
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
        return new("current_auth_repair_admission_invalid", "Current Auth repair admission refused.");
    }
}
