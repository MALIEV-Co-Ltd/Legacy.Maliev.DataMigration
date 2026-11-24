using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal enum ConsumerColumnBootstrapOperationalMode { DisposableClosedProof = 1, PersistentReviewed = 2, OwnedForwardRecoveryCharacterization = 4 }

internal sealed record ConsumerColumnBootstrapOperationalScope(Guid OperationId, ConsumerColumnBootstrapOperationalMode Mode,
    string SourceCommitSha, string LogicalSourcePlanSha256, string ContractSha256,
    IReadOnlyDictionary<string, string> BeforePhysicalSha256, IReadOnlyDictionary<string, string> AfterPhysicalSha256,
    DeltaTargetAuthority Target, string TargetNamespace, string TargetCluster, string TargetGeneration, string TargetObservationSha256,
    string RunBindingSha256, IReadOnlyDictionary<string, string> BeforeDatabaseSha256, string GlobalPreservationSha256,
    string NativeCharacterizationSha256, string RecoveryReviewSha256, string RoleTransitionReviewSha256, CurrentAppOwnedMaintenancePin Maintenance)
{
    public IReadOnlyList<ConsumerColumnBootstrapNativePreimagePin> NativePreimages { get; init; } = [];
    public string SourceIdentitySha256 { get; init; } = string.Empty;
    public IReadOnlyList<string> PendingDatabases { get; init; } = ConsumerColumnBootstrapOperationalContract.Databases;
    // Means only that the schema is already correct. Attribution to a previous operation requires
    // its independently validated receipt and is never inferred from this map.
    public IReadOnlyDictionary<string, string> PreviouslyCompletedDatabaseSha256 { get; init; } = new Dictionary<string, string>(StringComparer.Ordinal);
}
internal sealed record ConsumerColumnBootstrapOperationalClaim(string Kind, ConsumerColumnBootstrapOperationalScope Scope,
    Guid Nonce, string? ReviewSha256, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc, string KeyId, string? Signature);
internal sealed record ConsumerColumnBootstrapOperationalReceipt(string Kind, Guid OperationId, string Database,
    string ContractSha256, string AuthorizationSha256, string BeforeSha256, string? AfterSha256, string PreviousReceiptSha256,
    CurrentAppOwnedCommitClassification Classification, DateTimeOffset ObservedAtUtc, string KeyId, string? Signature);
// The map and last receipt describe ACKNOWLEDGED terminal publications, not an exhaustive claim
// about database effects after lost commit/publication acknowledgements. Unfinished runs require
// independent native reconciliation; a populated map never makes the run complete.
internal sealed record ConsumerColumnBootstrapOperationalRunReceipt(string Kind, Guid OperationId, string AuthorizationSha256,
    string LogicalSourcePlanSha256, string ContractSha256, string LastDatabaseReceiptSha256, bool Completed,
    IReadOnlyDictionary<string, string> CommittedDatabaseSha256, IReadOnlyDictionary<string, string> IndependentlyVerifiedReadbackSha256, string? FinalFleetSha256,
    DateTimeOffset ObservedAtUtc, string KeyId, string? Signature);

internal static class ConsumerColumnBootstrapOperationalContract
{
    internal static IReadOnlyList<string> Databases { get; } = Array.AsReadOnly(["CustomerIdentity", "Quotation"]);
    internal const string Purpose = "consumer-column-bootstrap-operational-proof";
    internal static string Hash(byte[] bytes)
    {
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }

    internal static bool IsHash(string? value)
    {
        return value is { Length: 64 } && value.All(char.IsAsciiHexDigitLower);
    }

    internal static T Copy<T>(T value)
    {
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value))!;
    }

    internal static string FleetHash(IReadOnlyDictionary<string, string> fleet)
    {
        return Hash(JsonSerializer.SerializeToUtf8Bytes(
            fleet.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new { Database = x.Key, Sha256 = x.Value }).ToArray()));
    }

    internal static void RequireScope(ConsumerColumnBootstrapOperationalScope scope, FreshSchemaPlan source, DateTimeOffset now)
    {
        bool disposable = (scope.Mode is ConsumerColumnBootstrapOperationalMode.DisposableClosedProof or ConsumerColumnBootstrapOperationalMode.OwnedForwardRecoveryCharacterization) &&
            DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) && scope.TargetNamespace == "local-aspire" && scope.TargetCluster == "legacy-postgres-main-local";
        bool persistent = scope.Mode == ConsumerColumnBootstrapOperationalMode.PersistentReviewed &&
            DeltaSynchronizationPlanProducer.ValidAuthority(scope.Target, scope.TargetNamespace, scope.TargetCluster) &&
            (scope.Target.Kind == DeltaTargetAuthorityKind.ProductionCloudNativePg || DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(scope.Target));
        // This validates claim shape only. Persistent execution additionally requires the private
        // genuine-rehearsal token and the closed live environment at admission and every fence.
        if ((!disposable && !persistent) || scope.OperationId == Guid.Empty || string.IsNullOrWhiteSpace(scope.TargetGeneration) ||
            !IsHash(scope.Target.SystemIdentifierSha256) || !IsHash(scope.TargetObservationSha256) || !IsHash(scope.RunBindingSha256) || !IsHash(scope.SourceIdentitySha256) ||
            !IsHash(scope.NativeCharacterizationSha256) || !IsHash(scope.RecoveryReviewSha256) || !IsHash(scope.RoleTransitionReviewSha256) ||
            !ReviewedProductionRepairInventory.MatchesKeys(scope.Target.Kind, scope.BeforeDatabaseSha256.Keys) ||
            scope.BeforeDatabaseSha256.Values.Any(x => !IsHash(x)) || scope.GlobalPreservationSha256 != FleetHash(scope.BeforeDatabaseSha256)) { throw Invalid(); }
        RequireOperationSubset(scope);
        var contract = ConsumerColumnBootstrapContract.Create(source, scope.SourceCommitSha, now);
        if (source.Databases.Any(database => database.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(database.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3)))
        { throw Invalid(); }
        if (!scope.NativePreimages.Select(pin => pin.Database).Order(StringComparer.Ordinal).SequenceEqual(scope.PendingDatabases, StringComparer.Ordinal) ||
            scope.NativePreimages.Any(pin => !IsHash(pin.Sha256) || pin.ObservedWalUpper == 0 || pin.ObservedAtUtc.Offset != TimeSpan.Zero ||
                pin.ObservedAtUtc > now || now - pin.ObservedAtUtc > TimeSpan.FromMinutes(15) ||
                (pin.ProviderVersion != 180004 && pin.ProviderVersion != 180007) ||
                pin.CompositeDefense != (pin.ProviderVersion == 180007 ? "error" : string.Empty))) { throw Invalid(); }
        foreach (var pin in scope.NativePreimages)
        {
            ConsumerColumnBootstrapProviderCompatibility.RequireObservation(pin.Provider);
            if (pin.Provider.EngineVersion != pin.ProviderVersion || pin.Provider.CompositeDefense != pin.CompositeDefense) { throw Invalid(); }
        }
        if (scope.LogicalSourcePlanSha256 != contract.LogicalSourcePlanSha256 || scope.ContractSha256 != contract.ComputeSha256() ||
            !scope.BeforePhysicalSha256.Keys.Order(StringComparer.Ordinal).SequenceEqual(Databases) ||
            !scope.AfterPhysicalSha256.Keys.Order(StringComparer.Ordinal).SequenceEqual(Databases) ||
            Databases.Any(x => scope.BeforePhysicalSha256[x] != contract.Before(x).TargetSchemaSha256 || scope.AfterPhysicalSha256[x] != contract.After(x).TargetSchemaSha256)) { throw Invalid(); }
        var role = scope.Maintenance;
        if (now.Offset != TimeSpan.Zero || role.IssuedAtUtc.Offset != TimeSpan.Zero || role.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            role.IssuedAtUtc > now || role.ExpiresAtUtc <= now || role.ExpiresAtUtc - role.IssuedAtUtc > TimeSpan.FromHours(4) ||
            string.IsNullOrWhiteSpace(role.Role) || role.RoleComment != "legacy-maliev-consumer-column-bootstrap-v1:" + scope.RunBindingSha256 ||
            !IsHash(role.HbaSha256) || !IsHash(role.HbaRulesSha256) || string.IsNullOrWhiteSpace(role.HbaPath) ||
            role.Postmaster.Offset != TimeSpan.Zero || role.ConfigLoaded.Offset != TimeSpan.Zero || role.Postmaster > now || role.ConfigLoaded > now) { throw Invalid(); }
    }

    internal static void RequireOperationSubset(ConsumerColumnBootstrapOperationalScope scope)
    {
        if (scope.PendingDatabases.Count is < 1 or > 2 ||
            !scope.PendingDatabases.SequenceEqual(Databases.Where(database => scope.PendingDatabases.Contains(database, StringComparer.Ordinal)), StringComparer.Ordinal) ||
            !scope.PreviouslyCompletedDatabaseSha256.Keys.Order(StringComparer.Ordinal).SequenceEqual(Databases.Except(scope.PendingDatabases, StringComparer.Ordinal), StringComparer.Ordinal) ||
            scope.PreviouslyCompletedDatabaseSha256.Any(pair => !IsHash(pair.Value) || !scope.BeforeDatabaseSha256.TryGetValue(pair.Key, out string? baseline) || pair.Value != baseline) ||
            (scope.Mode == ConsumerColumnBootstrapOperationalMode.DisposableClosedProof && (scope.PendingDatabases.Count != 2 || scope.PreviouslyCompletedDatabaseSha256.Count != 0)))
        { throw Invalid(); }
        if (scope.Mode == ConsumerColumnBootstrapOperationalMode.OwnedForwardRecoveryCharacterization &&
            (scope.PendingDatabases.Count != 1 || scope.PendingDatabases[0] != "Quotation" || scope.PreviouslyCompletedDatabaseSha256.Count != 1 ||
                !scope.PreviouslyCompletedDatabaseSha256.ContainsKey("CustomerIdentity"))) { throw Invalid(); }
    }

    internal static MigrationExecutionException Invalid()
    {
        return new("consumer_column_bootstrap_operational_invalid",
        "The fixed two-column source, proof, target or authorization boundary failed.");
    }
}
