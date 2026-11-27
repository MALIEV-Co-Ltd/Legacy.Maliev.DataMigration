namespace Legacy.Maliev.DataMigration.Console;

// Constructible only from the sealed holder returned by the actual fixed intended-target observer.
internal sealed class CurrentAuthArchivePersistentV2Baselines
{
    private readonly CurrentAuthArchiveFleet _local, _comparison;
    private readonly CurrentAuthArchivePersistentIntentV2 _intent;
    private readonly string _scopeSha256;
    private CurrentAuthArchivePersistentV2Baselines(CurrentAuthArchivePersistentIntentV2 intent, CurrentAuthArchiveIntendedObservationRuntimeV2 observed)
    { _intent = intent; _scopeSha256 = CurrentAuthLocalSessionArchivePolicy.Hash(intent.Scope); _local = observed.Local; _comparison = observed.Comparison; }
    internal static CurrentAuthArchivePersistentV2Baselines Create(CurrentAuthArchiveClaim review, CurrentAuthArchiveClaim authorization,
        CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, CurrentAuthArchiveIntendedObservationRuntimeV2 observed)
    {
        // The environment's appended mode is available only with authentic V2 claims and actual independently observed native baselines.
        var intent = CurrentAuthArchivePersistentV2Policy.Claims(review, authorization, pins, trust, DateTimeOffset.UtcNow);
        CurrentAuthArchivePersistentV2Policy.RequireFleets(intent, observed.Local, observed.Comparison);
        return intent.Scope.DeleteSetSha256 != observed.Evidence.LocalAuthRowsSha256 || intent.Scope.DeleteCount != observed.Evidence.LocalAuthRows ||
            intent.Scope.LocalObservationPolicy.RunBindingSha256 != observed.Evidence.LocalPolicy.RunBindingSha256 ||
            intent.Scope.ProductionObservationPolicy.RunBindingSha256 != observed.Evidence.ComparisonPolicy.RunBindingSha256
            ? throw CurrentAuthArchivePersistentV2Policy.Invalid()
            : new(intent, observed);
    }
    internal void RequireScope(CurrentAuthArchiveScope scope, DateTimeOffset now)
    {
        if (CurrentAuthLocalSessionArchivePolicy.Hash(_intent.Scope) != _scopeSha256) { throw CurrentAuthArchivePersistentV2Policy.Invalid(); }
        RequireSameScope(_intent, scope, now);
    }
    // Pure congruence only; calling this cannot construct a baseline holder or admit an environment.
    internal static void RequireSameScope(CurrentAuthArchivePersistentIntentV2 intent, CurrentAuthArchiveScope scope, DateTimeOffset now)
    {
        CurrentAuthArchivePersistentV2Policy.RequireIntent(intent, now);
        if (CurrentAuthLocalSessionArchivePolicy.Hash(scope) != CurrentAuthLocalSessionArchivePolicy.Hash(intent.Scope))
        { throw CurrentAuthArchivePersistentV2Policy.Invalid(); }
    }
    internal void Require(CurrentAuthArchiveFleet observed, bool local, bool prepared)
    {
        var original = local ? _local : _comparison;
        if (observed.Databases.Count != original.Databases.Count || observed.Databases.Select(item => item.Database).Distinct(StringComparer.Ordinal).Count() != original.Databases.Count ||
            original.Databases.Where(item => !local || item.Database != "Auth").Any(item => observed.Databases.Single(other => other.Database == item.Database).Sha256 != item.Sha256))
        { throw CurrentAuthArchivePersistentV2Policy.Invalid(); }
        if (local && prepared && observed.Auth.Sessions.Count == 0) { CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(original.Auth, observed.Auth); }
        else { CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(observed.Auth, original.Auth); }
    }
}

internal sealed partial class CurrentAuthLocalSessionArchiveEnvironment
{
    private CurrentAuthArchivePersistentV2Baselines? _persistentV2Baselines;
    internal void AttachPersistentV2Baselines(CurrentAuthArchivePersistentV2Baselines baselines)
    {
        if (_persistentV2Baselines is not null || _final6PersistentBaselines is not null || _final6Case is not null ||
            _scope.ProofAdmission != CurrentAuthArchivePersistentV2Policy.Mode || _reserved || _failed)
        { throw CurrentAuthArchivePersistentV2Policy.Invalid(); }
        baselines.RequireScope(_scope, DateTimeOffset.UtcNow);
        _persistentV2Baselines = baselines;
    }
}
