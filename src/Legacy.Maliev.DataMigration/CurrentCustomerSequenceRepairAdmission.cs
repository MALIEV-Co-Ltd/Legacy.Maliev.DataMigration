using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Legacy.Maliev.DataMigration;

internal enum CurrentCustomerSequenceProofAdmission { PersistentWithClosedConsoleProof = 1, DisposableNativeBootstrap = 2, DisposableClosedConsoleBootstrap = 3 }
internal enum CurrentCustomerSequenceRepairOperation { FixedStartDefinitionOnly = 1 }
// Signed into the exact case scope. This component subject grants no persistent authority.
internal sealed record CurrentCustomerSequenceBootstrapSubject(string Kind, string SourceCommitSha, string SourceSchemaPlanSha256,
    string CatalogReportSha256, string OwnerHead, string OwnerContextSha256, string OwnerSnapshotSha256, string DefinitionSha256,
    string DefinitionPrecursorSha256, string NativeBeforeStateSha256, string TargetObservationSha256, string RunBindingSha256,
    string ConsoleAssemblySha256, string CoreAssemblySha256, string TestAssemblySha256);
internal sealed record CurrentCustomerSequenceRepairScope(Guid OperationId, CurrentCustomerSequenceRepairOperation Operation,
    string SourceCommitSha, string SourceSchemaPlanSha256, string CatalogReportSha256,
    CurrentCustomerSequenceSource SourceObservation, CurrentCustomerSequenceOwner OwnerObservation,
    string DefinitionSha256, string NativeBeforeStateSha256, string OperationSha256, string DefinitionProofSha256,
    string MaintenanceValidatorSha256, DeltaTargetAuthority Target, string TargetNamespace, string TargetCluster,
    string TargetGeneration, string TargetObservationSha256, string RunBindingSha256,
    IReadOnlyDictionary<string, string> BeforeDatabaseSha256, string GlobalPreservationSha256,
    string NativeProofSha256, string RecoveryReviewSha256, string ExactRoleTransitionReviewSha256,
    CurrentAppOwnedMaintenancePin Maintenance, string MaintenanceProofSha256 = "",
    CurrentCustomerSequenceProofAdmission ProofAdmission = CurrentCustomerSequenceProofAdmission.PersistentWithClosedConsoleProof,
    CurrentCustomerSequenceBootstrapSubject? BootstrapSubject = null, CurrentCustomerSequenceClosedSeed? ClosedConsoleSeed = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OwnerPolicySha256 = null);
internal sealed record CurrentCustomerSequenceRepairSignedClaim(string Kind, CurrentCustomerSequenceRepairScope Scope,
    Guid Nonce, string? ReviewSha256, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc, string KeyId, string? Signature);
internal sealed record CurrentCustomerSequenceRepairSigningPins(string ReviewKeyId, string ReviewFingerprint,
    string AuthorizationKeyId, string AuthorizationFingerprint, string ReceiptKeyId, string ReceiptFingerprint);

// Future closed Console only; serialized callback configuration grants no authority.
internal interface ICurrentCustomerSequenceRepairEnvironment
{
    Task RequireSourceAsync(string sourceCommitSha, CancellationToken ct);
    // Observations must be read independently from current approved SQL catalog evidence and the exact clean owner checkout.
    Task<CurrentCustomerSequenceSource> ObserveCurrentCatalogAsync(string acceptedMigrationSourceSha, CancellationToken ct);
    Task<CurrentCustomerSequenceOwner> ObserveOwnerAsync(CancellationToken ct);
    Task<CurrentCustomerSequenceObservation> ObserveNativeBeforeAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct);
    Task RequireSource23PhysicalBaselineAsync(FreshSchemaPlan sourceBaseline, CurrentCustomerSequenceRepairScope scope, CancellationToken ct);
    Task RequireResourceAndCustodyAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct);
    Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct);
    Task RequireFreshOperationAsync(CurrentCustomerSequenceRepairScope scope, CancellationToken ct);
    Task ReserveFreshOperationAsync(CurrentCustomerSequenceRepairScope scope, string authorizationSha256, CancellationToken ct);
    Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken ct);
}

internal sealed class CurrentCustomerSequenceRepairPermit
{
    internal const string MaintenanceValidator = "5fc4d018d7ecfec6517db497d1bc8e06dc204be91d1ae2a421f5d41f34d72324";
    private readonly CurrentCustomerSequenceRepairSignedClaim _review, _authorization;
    private readonly FreshSchemaPlan _sourceBaseline;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly TimeProvider _clock;
    private int _state; // unreserved0, running1, stopped2, reserving3; never reset.
    internal CurrentCustomerSequenceRepairScope Scope => Clone(_authorization.Scope);
    internal CurrentCustomerSequenceRepairSigningPins SigningPins { get; }
    internal ICurrentCustomerSequenceRepairEnvironment Environment { get; }
    internal string AuthorizationSha256 => Hash(JsonSerializer.SerializeToUtf8Bytes(_authorization));
    private CurrentCustomerSequenceRepairPermit(CurrentCustomerSequenceRepairSignedClaim review, CurrentCustomerSequenceRepairSignedClaim authorization,
        FreshSchemaPlan baseline, IReceiptAttestationTrustStore trust, CurrentCustomerSequenceRepairSigningPins pins,
        ICurrentCustomerSequenceRepairEnvironment environment, TimeProvider clock)
    {
        _review = Clone(review); _authorization = Clone(authorization); _sourceBaseline = Clone(baseline);
        _trust = trust; SigningPins = pins; Environment = environment; _clock = clock;
    }

    internal static string OperationSha256(FreshSchemaPlan source, ApprovedCurrentCustomerSequenceDefinition definition,
        string definitionProof, string nativeBeforeStateSha256)
    {
        return Hash(JsonSerializer.SerializeToUtf8Bytes(new
        {
            Domain = "Legacy.Maliev.CurrentCustomerSequence.FixedDefinitionOperation.v1",
            Source = SchemaPlanCanonicalizer.ComputeSha256(source),
            Definition = definition.ComputeSha256(),
            ApprovedCurrentCustomerSequenceDefinition.CandidateSql,
            OwnerHead = ApprovedCurrentCustomerSequenceDefinition.CustomerOwnerHead,
            ContextPin = ApprovedCurrentCustomerSequenceDefinition.ContextSha256,
            SnapshotPin = ApprovedCurrentCustomerSequenceDefinition.OwnerSnapshotSha256,
            DefinitionProof = definitionProof,
            NativeBeforeState = nativeBeforeStateSha256,
            MaintenanceValidator,
        }));
    }

    internal static string FleetSha256(IReadOnlyDictionary<string, string> fleet)
    {
        return Hash(JsonSerializer.SerializeToUtf8Bytes(
            fleet.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new { Database = x.Key, Sha256 = x.Value }).ToArray()));
    }

    internal static void ValidateReview(CurrentCustomerSequenceRepairSignedClaim review, FreshSchemaPlan source,
        IReceiptAttestationTrustStore trust, CurrentCustomerSequenceRepairSigningPins pins, DateTimeOffset now)
    {
        RequireScope(review.Scope, source, now); RequirePins(trust, pins);
        if (review.Kind != ReviewKind(review.Scope) || review.KeyId != pins.ReviewKeyId || review.ReviewSha256 is not null ||
            review.Nonce == Guid.Empty || review.ExpiresAtUtc > review.Scope.Maintenance.ExpiresAtUtc ||
            !Verify(review, trust, pins.ReviewFingerprint, now, TimeSpan.FromHours(12))) { throw Invalid(); }
    }
    internal static void ValidateClaims(CurrentCustomerSequenceRepairSignedClaim review, CurrentCustomerSequenceRepairSignedClaim authorization,
        FreshSchemaPlan source, IReceiptAttestationTrustStore trust, CurrentCustomerSequenceRepairSigningPins pins, DateTimeOffset now)
    {
        ValidateReview(review, source, trust, pins, now);
        if (authorization.Kind != AuthorizationKind(review.Scope) || authorization.KeyId != pins.AuthorizationKeyId ||
            JsonSerializer.Serialize(review.Scope) != JsonSerializer.Serialize(authorization.Scope) ||
            authorization.ReviewSha256 != Hash(JsonSerializer.SerializeToUtf8Bytes(review)) || authorization.Nonce == Guid.Empty ||
            authorization.Nonce == review.Nonce || authorization.IssuedAtUtc < review.IssuedAtUtc || authorization.ExpiresAtUtc > review.ExpiresAtUtc ||
            authorization.ExpiresAtUtc > authorization.Scope.Maintenance.ExpiresAtUtc ||
            !Verify(authorization, trust, pins.AuthorizationFingerprint, now, TimeSpan.FromMinutes(15))) { throw Invalid(); }
    }
    internal static async Task<CurrentCustomerSequenceRepairSignedClaim> IssueReviewAsync(CurrentCustomerSequenceRepairScope scope, FreshSchemaPlan source,
        IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> baseline, IReceiptAttestationTrustStore trust, CurrentCustomerSequenceRepairSigningPins pins,
        ICurrentCustomerSequenceRepairEnvironment environment, P256MigrationEvidenceSigner signer, DateTimeOffset expiresAtUtc, TimeProvider clock, CancellationToken ct)
    {
        scope = Clone(scope); source = Clone(source); baseline = baseline.Select(CopySnapshot).ToArray();
        if (signer.KeyId != pins.ReviewKeyId || !Matches(baseline, scope.BeforeDatabaseSha256)) { throw Invalid(); }
        var unsigned = new CurrentCustomerSequenceRepairSignedClaim(ReviewKind(scope), scope, Guid.NewGuid(), null,
            clock.GetUtcNow(), expiresAtUtc, signer.KeyId, null);
        var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(Payload(unsigned))) };
        ValidateReview(signed, source, trust, pins, clock.GetUtcNow()); // pure signature/shape before any callback
        await environment.RequireFreshOperationAsync(Clone(scope), ct).ConfigureAwait(false);
        await RequireNativeBeforeAsync(environment, scope, source, clock.GetUtcNow(), ct).ConfigureAwait(false);
        await RequireEnvironmentAsync(environment, scope, source, clock.GetUtcNow(), ct).ConfigureAwait(false);
        if (!Matches(await environment.InspectFleetAsync(Clone(scope), ct).ConfigureAwait(false), scope.BeforeDatabaseSha256)) { throw Invalid(); }
        await RequireEnvironmentAsync(environment, scope, source, clock.GetUtcNow(), ct).ConfigureAwait(false);
        await environment.RequireFreshOperationAsync(Clone(scope), ct).ConfigureAwait(false);
        ValidateReview(signed, source, trust, pins, clock.GetUtcNow()); return Clone(signed);
    }
    internal static async Task<CurrentCustomerSequenceRepairSignedClaim> AuthorizeAsync(CurrentCustomerSequenceRepairSignedClaim review, FreshSchemaPlan source,
        IReceiptAttestationTrustStore trust, CurrentCustomerSequenceRepairSigningPins pins, ICurrentCustomerSequenceRepairEnvironment environment,
        P256MigrationEvidenceSigner signer, TimeProvider clock, CancellationToken ct)
    {
        review = Clone(review); source = Clone(source); DateTimeOffset now = clock.GetUtcNow();
        ValidateReview(review, source, trust, pins, now);
        if (signer.KeyId != pins.AuthorizationKeyId) { throw Invalid(); }
        var unsigned = new CurrentCustomerSequenceRepairSignedClaim(AuthorizationKind(review.Scope), Clone(review.Scope), Guid.NewGuid(),
            Hash(JsonSerializer.SerializeToUtf8Bytes(review)), now, new[] { now.AddMinutes(15), review.ExpiresAtUtc, review.Scope.Maintenance.ExpiresAtUtc }.Min(), signer.KeyId, null);
        var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(Payload(unsigned))) };
        _ = await AdmitAsync(review, signed, source, trust, pins, environment, clock, ct).ConfigureAwait(false); return Clone(signed);
    }
    internal static async Task<CurrentCustomerSequenceRepairPermit> AdmitAsync(CurrentCustomerSequenceRepairSignedClaim review, CurrentCustomerSequenceRepairSignedClaim authorization,
        FreshSchemaPlan source, IReceiptAttestationTrustStore trust, CurrentCustomerSequenceRepairSigningPins pins,
        ICurrentCustomerSequenceRepairEnvironment environment, TimeProvider clock, CancellationToken ct)
    {
        review = Clone(review); authorization = Clone(authorization); source = Clone(source);
        ValidateClaims(review, authorization, source, trust, pins, clock.GetUtcNow());
        var permit = new CurrentCustomerSequenceRepairPermit(review, authorization, source, trust, pins, environment, clock);
        try
        {
            await environment.RequireFreshOperationAsync(permit.Scope, ct).ConfigureAwait(false);
            await permit.RequireAsync(ct).ConfigureAwait(false);
            await RequireNativeBeforeAsync(environment, permit.Scope, source, clock.GetUtcNow(), ct).ConfigureAwait(false);
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
            await RequireNativeBeforeAsync(Environment, Scope, _sourceBaseline, _clock.GetUtcNow(), ct).ConfigureAwait(false);
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
            await RequireEnvironmentAsync(Environment, Scope, Clone(_sourceBaseline), _clock.GetUtcNow(), ct).ConfigureAwait(false);
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

    private static async Task RequireEnvironmentAsync(ICurrentCustomerSequenceRepairEnvironment environment, CurrentCustomerSequenceRepairScope scope, FreshSchemaPlan source, DateTimeOffset now, CancellationToken ct)
    {
        await environment.RequireSourceAsync(scope.SourceCommitSha, ct).ConfigureAwait(false);
        CurrentCustomerSequenceSource observedSource = await environment.ObserveCurrentCatalogAsync(scope.SourceCommitSha, ct).ConfigureAwait(false);
        CurrentCustomerSequenceOwner observedOwner = await environment.ObserveOwnerAsync(ct).ConfigureAwait(false);
        ApprovedCurrentCustomerSequenceDefinition actual = ApprovedCurrentCustomerSequenceDefinition.Create(observedSource, observedOwner,
            scope.SourceCommitSha, scope.CatalogReportSha256, now);
        if (actual.ComputeSha256() != scope.DefinitionSha256) { throw Invalid(); }
        await environment.RequireSource23PhysicalBaselineAsync(Clone(source), Clone(scope), ct).ConfigureAwait(false);
        await environment.RequireResourceAndCustodyAsync(Clone(scope), ct).ConfigureAwait(false);
    }
    internal static void RequireNativePreimage(CurrentCustomerSequenceObservation observation, CurrentCustomerSequenceRepairScope scope,
        DateTimeOffset now)
    {
        RequireOwnerPolicy(scope);
        _ = ApprovedCurrentCustomerSequenceDefinition.Create(scope.SourceObservation, scope.OwnerObservation,
            scope.SourceCommitSha, scope.CatalogReportSha256, now);
        string owner = CurrentRepairOperandOwnerProfile.ExpectedOwnerName(CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, scope.Target);
        ApprovedCurrentCustomerSequenceDefinition.RequireBefore(observation, owner);
        if (ApprovedCurrentCustomerSequenceDefinition.NativeStateSha256(observation.State) != scope.NativeBeforeStateSha256 ||
            observation.Snapshot.Sha256 != scope.BeforeDatabaseSha256["Customer"]) { throw Invalid(); }
    }
    private static async Task RequireNativeBeforeAsync(ICurrentCustomerSequenceRepairEnvironment environment,
        CurrentCustomerSequenceRepairScope scope, FreshSchemaPlan source, DateTimeOffset now, CancellationToken ct)
    {
        _ = source; // The separately held source physical plan is checked by RequireEnvironmentAsync.
        RequireNativePreimage(await environment.ObserveNativeBeforeAsync(Clone(scope), ct).ConfigureAwait(false), scope, now);
    }
    private static bool Matches(IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> snapshots, IReadOnlyDictionary<string, string> expected)
    {
        return snapshots.Count == expected.Count && snapshots.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() == snapshots.Count &&
        snapshots.All(x => expected.TryGetValue(x.Database, out string? hash) && x.Sha256 == hash);
    }

    internal static void RequireOwnerPolicy(CurrentCustomerSequenceRepairScope scope)
    {
        if ((scope.Target.Kind == DeltaTargetAuthorityKind.ProductionCloudNativePg && scope.OwnerPolicySha256 is null) ||
            (scope.OwnerPolicySha256 is not null && scope.OwnerPolicySha256 != CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, scope.Target))) { throw Invalid(); }
    }
    private static string ReviewKind(CurrentCustomerSequenceRepairScope scope)
    {
        return scope.OwnerPolicySha256 is null ? "current-customer-sequence-repair-review-v1" : "current-customer-sequence-repair-review-v2";
    }
    private static string AuthorizationKind(CurrentCustomerSequenceRepairScope scope)
    {
        return scope.OwnerPolicySha256 is null ? "current-customer-sequence-repair-authorization-v1" : "current-customer-sequence-repair-authorization-v2";
    }

    private static void RequireScope(CurrentCustomerSequenceRepairScope scope, FreshSchemaPlan source, DateTimeOffset now)
    {
        ProductionSchemaCatalogInspector.ValidatePlan(source, now);
        RequireProofAdmission(scope);
        RequireOwnerPolicy(scope);
        bool componentBootstrap = scope.ProofAdmission == CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap && scope.BootstrapSubject is not null;
        bool namedBootstrap = scope.ProofAdmission == CurrentCustomerSequenceProofAdmission.DisposableClosedConsoleBootstrap;
        bool bootstrap = componentBootstrap || namedBootstrap;
        if ((!componentBootstrap && (!HashShape(scope.MaintenanceProofSha256) || !HashShape(scope.NativeProofSha256) ||
            scope.MaintenanceProofSha256 == scope.NativeProofSha256 || scope.DefinitionProofSha256 == scope.NativeProofSha256 ||
            scope.DefinitionProofSha256 == scope.MaintenanceProofSha256)) ||
            (componentBootstrap && (scope.NativeProofSha256 != string.Empty || scope.MaintenanceProofSha256 != string.Empty ||
                scope.RecoveryReviewSha256 != string.Empty || scope.ExactRoleTransitionReviewSha256 != string.Empty)) ||
            (namedBootstrap && (scope.RecoveryReviewSha256 != string.Empty || scope.ExactRoleTransitionReviewSha256 != string.Empty)) ||
            !ApprovedConsumerOverlaySelection.IsApproved(source) || source.Databases.Sum(x => x.Tables.Count) != 100 ||
            !source.Databases.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases.Order(StringComparer.Ordinal)) ||
            source.Databases.Any(x => x.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(x.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3)) ||
            source.Databases.Single(x => x.Database == "Quotation").SourceDispositionProfile != ApprovedSourceDispositionManifest.QuotationOutboxesV1 ||
            scope.OperationId == Guid.Empty || scope.Operation != CurrentCustomerSequenceRepairOperation.FixedStartDefinitionOnly ||
            scope.SourceCommitSha != source.SourceCommitSha || scope.SourceCommitSha.Length != 40 || !scope.SourceCommitSha.All(x => x is (>= '0' and <= '9') or (>= 'a' and <= 'f')) ||
            scope.SourceSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(source) || !HashShape(scope.CatalogReportSha256) ||
            !HashShape(scope.DefinitionProofSha256) || !HashShape(scope.NativeBeforeStateSha256) || scope.MaintenanceValidatorSha256 != MaintenanceValidator ||
            scope.DefinitionSha256 != ApprovedCurrentCustomerSequenceDefinition.Create(scope.SourceObservation, scope.OwnerObservation,
                scope.SourceCommitSha, scope.CatalogReportSha256, now).ComputeSha256() ||
            scope.OperationSha256 != OperationSha256(source, ApprovedCurrentCustomerSequenceDefinition.Create(scope.SourceObservation, scope.OwnerObservation,
                scope.SourceCommitSha, scope.CatalogReportSha256, now), scope.DefinitionProofSha256, scope.NativeBeforeStateSha256) ||
            !HashShape(scope.TargetObservationSha256) || !HashShape(scope.RunBindingSha256) ||
            (!bootstrap && (!HashShape(scope.RecoveryReviewSha256) || !HashShape(scope.ExactRoleTransitionReviewSha256))) ||
            scope.GlobalPreservationSha256 != FleetSha256(scope.BeforeDatabaseSha256) || scope.BeforeDatabaseSha256.Values.Any(x => !HashShape(x)) ||
            !DatabaseInventory.ActiveDatabases.All(scope.BeforeDatabaseSha256.ContainsKey) || !scope.BeforeDatabaseSha256.ContainsKey("Auth") || !scope.BeforeDatabaseSha256.ContainsKey("postgres") ||
            string.IsNullOrWhiteSpace(scope.TargetGeneration) ||
            !((DeltaSynchronizationPlanProducer.ValidAuthority(scope.Target, "local-aspire", "legacy-postgres-main-local") && scope.TargetNamespace == "local-aspire" && scope.TargetCluster == "legacy-postgres-main-local" &&
                scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]).Order(StringComparer.Ordinal))) ||
              (DeltaSynchronizationPlanProducer.ValidAuthority(scope.Target, "maliev-legacy", "legacy-postgres-main") && scope.TargetNamespace == "maliev-legacy" && scope.TargetCluster == "legacy-postgres-main" && ReviewedProductionRepairInventory.MatchesKeys(scope.Target.Kind, scope.BeforeDatabaseSha256.Keys)))) { throw Invalid(); }
        CurrentAppOwnedMaintenancePin m = scope.Maintenance;
        if (string.IsNullOrWhiteSpace(m.Role) || m.RoleComment != "legacy-maliev-current-customer-sequence-v1:" + scope.RunBindingSha256 ||
            m.IssuedAtUtc.Offset != TimeSpan.Zero || m.ExpiresAtUtc.Offset != TimeSpan.Zero || m.Postmaster.Offset != TimeSpan.Zero || m.ConfigLoaded.Offset != TimeSpan.Zero ||
            m.IssuedAtUtc > now || m.ExpiresAtUtc <= now || m.ExpiresAtUtc <= m.IssuedAtUtc || m.ExpiresAtUtc - m.IssuedAtUtc > TimeSpan.FromHours(4) ||
            m.Postmaster > now || m.ConfigLoaded > now || !HashShape(m.HbaSha256) || !HashShape(m.HbaRulesSha256) || string.IsNullOrWhiteSpace(m.HbaPath)) { throw Invalid(); }
    }
    internal static void RequireProofAdmission(CurrentCustomerSequenceRepairScope scope)
    {
        if (scope.ProofAdmission == CurrentCustomerSequenceProofAdmission.DisposableClosedConsoleBootstrap)
        { CurrentCustomerSequenceClosedBootstrap.RequireBinding(scope.ClosedConsoleSeed ?? throw Invalid(), scope); }
        if ((scope.ProofAdmission != CurrentCustomerSequenceProofAdmission.DisposableClosedConsoleBootstrap && scope.ClosedConsoleSeed is not null) ||
            !Enum.IsDefined(scope.ProofAdmission) ||
            (scope.ProofAdmission == CurrentCustomerSequenceProofAdmission.PersistentWithClosedConsoleProof && scope.BootstrapSubject is not null) ||
            (scope.ProofAdmission == CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap &&
             (scope.Target.Kind != DeltaTargetAuthorityKind.LocalAspire ||
              !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) ||
              DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(scope.Target))))
        { throw Invalid(); }
        if (scope.BootstrapSubject is { } subject)
        {
            if (scope.ProofAdmission != CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap ||
                subject.Kind != "current-customer-sequence-disposable-component-subject-v1" ||
                subject.SourceCommitSha != scope.SourceCommitSha || subject.SourceSchemaPlanSha256 != scope.SourceSchemaPlanSha256 ||
                subject.CatalogReportSha256 != scope.CatalogReportSha256 || subject.OwnerHead != scope.OwnerObservation.Head ||
                subject.OwnerContextSha256 != scope.OwnerObservation.ContextSha256 || subject.OwnerSnapshotSha256 != scope.OwnerObservation.SnapshotSha256 ||
                subject.DefinitionSha256 != scope.DefinitionSha256 || subject.DefinitionPrecursorSha256 != scope.DefinitionProofSha256 ||
                subject.NativeBeforeStateSha256 != scope.NativeBeforeStateSha256 || subject.TargetObservationSha256 != scope.TargetObservationSha256 ||
                subject.RunBindingSha256 != scope.RunBindingSha256 || !HashShape(subject.ConsoleAssemblySha256) ||
                !HashShape(subject.CoreAssemblySha256) || !HashShape(subject.TestAssemblySha256)) { throw Invalid(); }
        }
    }
    private static void RequirePins(IReceiptAttestationTrustStore trust, CurrentCustomerSequenceRepairSigningPins pins)
    {
        string[] ids = [pins.ReviewKeyId, pins.AuthorizationKeyId, pins.ReceiptKeyId], hashes = [pins.ReviewFingerprint, pins.AuthorizationFingerprint, pins.ReceiptFingerprint];
        if (ids.Any(string.IsNullOrWhiteSpace) || ids.Distinct(StringComparer.Ordinal).Count() != 3 || hashes.Any(x => !HashShape(x)) || hashes.Distinct(StringComparer.Ordinal).Count() != 3) { throw Invalid(); }
        for (int i = 0; i < 3; i++) { if (!trust.TryGetPublicKeyFingerprintSha256(ids[i], out string actual) || actual != hashes[i]) { throw Invalid(); } }
    }
    internal static byte[] Payload(CurrentCustomerSequenceRepairSignedClaim claim)
    {
        return [.. Encoding.UTF8.GetBytes("Legacy.Maliev.CurrentCustomerSequence." + claim.Kind + "\0"), .. JsonSerializer.SerializeToUtf8Bytes(claim with { Signature = null })];
    }

    private static bool Verify(CurrentCustomerSequenceRepairSignedClaim claim, IReceiptAttestationTrustStore trust, string fingerprint, DateTimeOffset now, TimeSpan maximum)
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
        return new("current_customer_sequence_repair_admission_invalid", "Current Customer sequence definition repair admission refused.");
    }
}
