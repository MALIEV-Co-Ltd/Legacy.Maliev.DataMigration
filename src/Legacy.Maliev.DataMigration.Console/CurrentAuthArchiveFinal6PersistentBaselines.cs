namespace Legacy.Maliev.DataMigration.Console;

// Constructible only from the sealed holder returned by the actual fixed intended-target observer.
internal sealed class CurrentAuthArchiveFinal6PersistentBaselines
{
    private readonly CurrentAuthArchiveFleet _local, _comparison;
    private readonly CurrentAuthArchiveFinal6PersistentIntent _intent;
    private readonly string _scopeSha256;
    private CurrentAuthArchiveFinal6PersistentBaselines(CurrentAuthArchiveFinal6PersistentIntent intent, CurrentAuthArchiveFinal6IntendedObservationRuntime observed)
    { _intent = intent; _scopeSha256 = CurrentAuthLocalSessionArchivePolicy.Hash(intent.Scope); _local = observed.Local; _comparison = observed.Comparison; }
    internal static CurrentAuthArchiveFinal6PersistentBaselines Create(CurrentAuthArchiveClaim review, CurrentAuthArchiveClaim authorization,
        CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, CurrentAuthArchiveFinal6IntendedObservationRuntime observed)
    {
        // The environment's appended mode is available only with authentic V2 claims and actual independently observed native baselines.
        var intent = CurrentAuthArchiveFinal6PersistentPolicy.Claims(review, authorization, pins, trust, DateTimeOffset.UtcNow);
        CurrentAuthArchiveFinal6PersistentPolicy.RequireFleets(intent, observed.Local, observed.Comparison);
        return intent.Scope.DeleteSetSha256 != observed.Evidence.LocalAuthRowsSha256 || intent.Scope.DeleteCount != observed.Evidence.LocalAuthRows ||
            intent.Scope.LocalObservationPolicy.RunBindingSha256 != observed.Evidence.LocalPolicy.RunBindingSha256 ||
            intent.Scope.ProductionObservationPolicy.RunBindingSha256 != observed.Evidence.ComparisonPolicy.RunBindingSha256
            ? throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid()
            : new(intent, observed);
    }
    internal void RequireScope(CurrentAuthArchiveScope scope, DateTimeOffset now)
    {
        if (CurrentAuthLocalSessionArchivePolicy.Hash(_intent.Scope) != _scopeSha256) { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
        RequireSameScope(_intent, scope, now);
    }
    // Pure congruence only; calling this cannot construct a baseline holder or admit an environment.
    internal static void RequireSameScope(CurrentAuthArchiveFinal6PersistentIntent intent, CurrentAuthArchiveScope scope, DateTimeOffset now)
    {
        CurrentAuthArchiveFinal6PersistentPolicy.RequireIntent(intent, now);
        if (CurrentAuthLocalSessionArchivePolicy.Hash(scope) != CurrentAuthLocalSessionArchivePolicy.Hash(intent.Scope))
        { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
    }
    internal void Require(CurrentAuthArchiveFleet observed, bool local, bool prepared)
    {
        var original = local ? _local : _comparison;
        if (observed.Databases.Count != original.Databases.Count || observed.Databases.Select(item => item.Database).Distinct(StringComparer.Ordinal).Count() != original.Databases.Count ||
            original.Databases.Where(item => !local || item.Database != "Auth").Any(item => observed.Databases.Single(other => other.Database == item.Database).Sha256 != item.Sha256))
        { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
        if (local && prepared && observed.Auth.Sessions.Count == 0) { CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(original.Auth, observed.Auth); }
        else { CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(observed.Auth, original.Auth); }
    }
}

internal sealed partial class CurrentAuthLocalSessionArchiveEnvironment
{
    private CurrentAuthArchiveFinal6PersistentBaselines? _final6PersistentBaselines;
    internal void AttachFinal6PersistentBaselines(CurrentAuthArchiveFinal6PersistentBaselines baselines)
    {
        if (_final6PersistentBaselines is not null || _persistentV2Baselines is not null || _final6Case is not null ||
            _scope.ProofAdmission != CurrentAuthArchiveFinal6PersistentPolicy.Mode || _reserved || _failed)
        { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
        baselines.RequireScope(_scope, DateTimeOffset.UtcNow);
        _final6PersistentBaselines = baselines;
    }
}
