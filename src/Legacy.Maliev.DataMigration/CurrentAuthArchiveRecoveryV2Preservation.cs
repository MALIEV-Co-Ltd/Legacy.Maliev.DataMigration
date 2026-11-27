using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration;

internal static class CurrentAuthArchiveRecoveryV2Preservation
{
    internal static string NativeSha(CurrentAuthNativeObservation value)
    {
        return CurrentAuthLocalSessionArchivePolicy.Hash(new
        {
            Kind = "current-auth-native-commitment-v2",
            value.Snapshot.Sha256,
            Tuples = value.CopyTuples().OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new
            { pair.Key, Values = pair.Value.Select(text => CurrentAuthLocalSessionArchivePolicy.HashBytes(System.Text.Encoding.UTF8.GetBytes(text))).Order(StringComparer.Ordinal) }),
            Storage = value.CopyStorage().OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, pair.Value.FileNode, pair.Value.Blocks }),
            Expressions = value.CopyExpressions().OrderBy(pair => pair.Key, StringComparer.Ordinal),
        });
    }

    internal static void RequireSetup(CurrentAuthArchiveGenuineExecutionFacts setup, CurrentAuthArchiveScope original)
    {
        if (setup.Case is not (CurrentAuthArchiveGenuineExecutionCase.FirstOnlyDecryptInsertReadback or CurrentAuthArchiveGenuineExecutionCase.SecondOnlyDecryptInsertReadback) ||
            original.ComponentSubject?.Seed.CaseId != CurrentAuthArchiveGenuineExecutionCases.Identity(setup.Case).CaseId || setup.Terminal is null ||
            setup.Terminal.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback || setup.Terminal.BeforeAuthSha256 != setup.LocalBefore.Auth.Native.Snapshot.Sha256 ||
            setup.Terminal.AfterAuthSha256 != setup.LocalAfter.Auth.Native.Snapshot.Sha256) { throw Invalid(); }
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(setup.LocalBefore, original.LocalObservationPolicy, DateTimeOffset.UtcNow);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(setup.LocalAfter, original.LocalObservationPolicy, DateTimeOffset.UtcNow, allowEmptyLocalSessions: true);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(setup.ComparisonBefore, original.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(setup.ComparisonAfter, original.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
        CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(setup.LocalBefore.Auth, setup.LocalAfter.Auth);
        CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(setup.ComparisonAfter.Auth, setup.ComparisonBefore.Auth);
    }
    internal static void RequireRestored(CurrentAuthArchiveFleet original, CurrentAuthArchiveFleet empty, CurrentAuthArchiveFleet restored,
        CurrentAuthArchiveFleet comparisonBefore, CurrentAuthArchiveFleet comparisonAfter, CurrentAuthArchiveScope scope)
    {
        CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(original.Auth, empty.Auth);
        CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(restored.Auth, original.Auth);
        CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(comparisonAfter.Auth, comparisonBefore.Auth);
        if (!original.Databases.Select(item => item.Database).SequenceEqual(restored.Databases.Select(item => item.Database), StringComparer.Ordinal) ||
            original.Databases.Any(item => item.Sha256 != restored.Databases.Single(row => row.Database == item.Database).Sha256) ||
            !comparisonBefore.Databases.Select(item => item.Database).SequenceEqual(comparisonAfter.Databases.Select(item => item.Database), StringComparer.Ordinal) ||
            comparisonBefore.Databases.Any(item => item.Sha256 != comparisonAfter.Databases.Single(row => row.Database == item.Database).Sha256)) { throw Invalid(); }
        byte[] bytes = CurrentAuthLocalSessionArchivePolicy.EncodeRows(restored.Auth.Sessions);
        try { if (restored.Auth.Sessions.Count != scope.DeleteCount || CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != scope.DeleteSetSha256) { throw Invalid(); } }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static void RequireScope(CurrentAuthArchiveRestoreScopeV2 scope, CurrentAuthArchiveScope original, DateTimeOffset now)
    {
        if (scope.Kind != "current-auth-owned-disposable-restore-scope-v2" || scope.OperationId == Guid.Empty || scope.OperationId == original.OperationId ||
            scope.SetupOperationId != original.OperationId || scope.SetupScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(original) ||
            scope.LocalRunBindingSha256 != original.LocalObservationPolicy.RunBindingSha256 || scope.ComparisonRunBindingSha256 != original.ProductionObservationPolicy.RunBindingSha256 ||
            scope.LocalTargetSha256 != original.LocalObservationPolicy.TargetObservationSha256 || scope.ComparisonTargetSha256 != original.ProductionObservationPolicy.TargetObservationSha256 ||
            scope.OriginalRowsSha256 != original.DeleteSetSha256 || scope.OriginalRows != original.DeleteCount || scope.DeviceProofSha256 != original.RecoveryDeviceProofSha256 ||
            scope.CapturedAtUtc.Offset != TimeSpan.Zero || scope.ExpiresAtUtc.Offset != TimeSpan.Zero || scope.CapturedAtUtc > now || scope.ExpiresAtUtc <= now ||
            scope.ExpiresAtUtc <= scope.CapturedAtUtc || scope.ExpiresAtUtc > original.ExpiresAtUtc || scope.ExpiresAtUtc - scope.CapturedAtUtc > TimeSpan.FromMinutes(2) ||
            string.IsNullOrWhiteSpace(scope.SelectedCipherIdentity) || string.IsNullOrWhiteSpace(scope.SelectedKeyIdentity) ||
            new[] { scope.AudienceSha256, scope.SetupManifestSha256, scope.SetupJournalsSha256, scope.SourceFullSha256, scope.SourceIdentitySha256,
                scope.SourceDefinitionSha256, scope.EmptyFleetSha256, scope.ComparisonFleetSha256, scope.EmptyAuthSha256, scope.EmptyNativeSha256,
                scope.SelectedCipherSha256, scope.SelectedKeySha256, scope.UnavailableDomainSha256 }.Any(hash => !CurrentAuthRepairPermit.HashShape(hash))) { throw Invalid(); }
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveRecoveryV2.Invalid();
    }
}
