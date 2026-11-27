using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record OrderSubtotalRepairIntent(string Kind, Guid IntentId, string SourceCommitSha,
    string ReviewedSourceFullSha256, string SourceIdentitySha256, string SourceDefinitionSha256,
    string BeforePhysicalSha256, string AfterPhysicalSha256, string CandidateSqlSha256,
    DeltaTargetAuthority Target, string TargetNamespace, string TargetCluster, string TargetGeneration,
    string TargetObservationSha256, string RunBindingSha256, IReadOnlyDictionary<string, string> BeforeDatabaseSha256, IReadOnlyDictionary<string, string> BeforeNativeDatabaseSha256,
    string NativePreimageSha256, string OrderOwnerName, string HistoricalExpression,
    CurrentAppOwnedMaintenancePin Maintenance, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record OrderSubtotalRepairScope(string Kind, Guid OperationId, string IntentSha256,
    string SourceFullSha256, string ContractSha256, string CharacterizationSha256, string RunnerSha256,
    OrderSubtotalRepairIntent Intent, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record OrderSubtotalRepairAuthorization(Guid OperationId, string ReviewSha256, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record OrderSubtotalRepairReceipt(string Kind, Guid OperationId, string ScopeSha256,
    string AuthorizationSha256, string PreviousSha256, string BeforeNativeSha256, string? AfterNativeSha256,
    string CharacterizationSha256, CurrentAppOwnedCommitClassification Classification, DateTimeOffset ObservedAtUtc);
internal sealed record OrderSubtotalStorageTransition(long BeforeBlocks, long AfterBlocks);
internal sealed record OrderSubtotalCharacterization(Guid OperationId, string ContractSha256, string TargetBeforeNativeSha256,
    string TargetLogicalPreimageSha256, string CloneLogicalPreimageSha256, string SourceFullSha256, string RunnerSha256,
    string CloneContainerId, string CloneVolume, string RollbackCloneContainerId, string RollbackBeforeNativeSha256, string RollbackAfterNativeSha256, int ProviderVersion, bool Alphabetical,
    IReadOnlyDictionary<string, OrderSubtotalStorageTransition> Storage, string BeforeNativeSha256, string AfterNativeSha256,
    bool RollbackVerified, bool CommittedIndependentReadback, bool CleanupVerified, DateTimeOffset CompletedAtUtc, DateTimeOffset ExpiresAtUtc);

internal static class OrderSubtotalRepairProtocol
{
    internal const string IntentKind = "current-order-subtotal-reviewed-intent-v1";
    internal const string IntentDomain = "Legacy.Maliev.OrderSubtotal.Intent.v1";
    internal const string ReviewDomain = "Legacy.Maliev.OrderSubtotal.Review.v1";
    internal const string AuthorizationDomain = "Legacy.Maliev.OrderSubtotal.Authorization.v1";
    internal const string ReceiptDomain = "Legacy.Maliev.OrderSubtotal.Receipt.v1";
    internal const string ProofDomain = "Legacy.Maliev.OrderSubtotal.TargetCharacterization.v1";
    internal static string CandidateSha256 => Hash(Encoding.UTF8.GetBytes(OrderSubtotalExpressionRepairContract.CandidateSql().Replace("\r\n", "\n", StringComparison.Ordinal)));
    internal static string Hash(byte[] value)
    {
        return Convert.ToHexStringLower(SHA256.HashData(value));
    }

    internal static string Hash<T>(T value)
    {
        return Hash(JsonSerializer.SerializeToUtf8Bytes(value));
    }

    internal static T Copy<T>(T value)
    {
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value))!;
    }

    internal static OrderSubtotalExpressionRepairContract RequireIntent(OrderSubtotalRepairIntent intent, FreshSchemaPlan source, DateTimeOffset now)
    {
        ProductionSchemaCatalogInspector.ValidatePlan(source, now);
        if (intent.Kind != IntentKind || intent.IntentId == Guid.Empty || source.SourceCommitSha != intent.SourceCommitSha ||
            SourceCatalogDefinitionFingerprintV1.Compute(source, intent.SourceCommitSha, intent.SourceIdentitySha256, now) != intent.SourceDefinitionSha256 ||
            intent.CandidateSqlSha256 != CandidateSha256 || !IsHash(intent.ReviewedSourceFullSha256) || !IsHash(intent.NativePreimageSha256) ||
            !IsHash(intent.TargetObservationSha256) || !IsHash(intent.RunBindingSha256) || string.IsNullOrWhiteSpace(intent.TargetGeneration) ||
            intent.OrderOwnerName is not ("legacy_local" or "postgres" or "legacy_order_owner") ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(intent.Target, intent.TargetNamespace, intent.TargetCluster) ||
            (intent.Target.Kind == DeltaTargetAuthorityKind.LocalAspire ? !DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(intent.Target) ||
                intent.TargetNamespace != "local-aspire" || intent.TargetCluster != "legacy-postgres-main-local" :
                intent.Target.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg || intent.TargetNamespace != "maliev-legacy" || intent.TargetCluster != "legacy-postgres-main") ||
            !ReviewedProductionRepairInventory.MatchesKeys(intent.Target.Kind, intent.BeforeDatabaseSha256.Keys) || intent.BeforeDatabaseSha256.Values.Any(x => !IsHash(x)) ||
            !ReviewedProductionRepairInventory.MatchesKeys(intent.Target.Kind, intent.BeforeNativeDatabaseSha256.Keys) || intent.BeforeNativeDatabaseSha256.Values.Any(x => !IsHash(x)) ||
            intent.IssuedAtUtc.Offset != TimeSpan.Zero || intent.ExpiresAtUtc.Offset != TimeSpan.Zero || intent.IssuedAtUtc > now || intent.ExpiresAtUtc <= now ||
            intent.ExpiresAtUtc > intent.IssuedAtUtc.AddMinutes(15) || intent.ExpiresAtUtc > intent.Maintenance.ExpiresAtUtc)
        { throw Invalid(); }
        var contract = OrderSubtotalExpressionRepairContract.Create(source, intent.SourceCommitSha, intent.HistoricalExpression, now);
        return contract.BeforePhysical().TargetSchemaSha256 != intent.BeforePhysicalSha256 || contract.AfterPhysical().TargetSchemaSha256 != intent.AfterPhysicalSha256
            ? throw Invalid()
            : contract;
    }
    internal static DatabaseSchemaPlan PhysicalBefore(FreshSchemaPlan source, string database)
    {
        if (database == "Order") { throw Invalid(); } // Order's observed expression belongs to its bound contract.
        DatabaseSchemaPlan logical = source.Databases.Single(x => x.Database == database);
        var historical = logical with { TargetExtensionProfile = ApprovedConsumerOverlaySelection.ProfileForDatabase(database, ConsumerOverlaySelection.HistoricalDefaults) };
        var detached = historical with
        {
            Tables = ApprovedConsumerColumnOverlayManifest.ComposePhysical(historical),
            TargetExtensionProfile = null,
            SourceDispositionProfile = null,
            SourceTableDispositions = []
        };
        return Copy(detached with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(detached) });
    }
    internal static string NativeSha(OrderSubtotalExpressionRepairNativeObservation value)
    {
        return Hash(new
        {
            Domain = "order-subtotal-complete-native-preimage-v1",
            value.Native.Snapshot.Sha256,
            value.ProviderVersion,
            value.CompositeDefense,
            value.Expression,
            value.ExpressionTree,
            Catalogs = OrderSubtotalExpressionRepairNativePreservation.CatalogNames.Select(name => new
            { Name = name, Rows = value.Native.Read(name).Select(x => Hash(Encoding.UTF8.GetBytes(x.ToJsonString()))).Order(StringComparer.Ordinal) }),
            Storage = value.Storage.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new { x.Key, x.Value.FileNode, x.Value.Blocks })
        });
    }

    internal static void RequireCharacterization(OrderSubtotalCharacterization facts, string contract, string target, string source, string runner, DateTimeOffset now)
    {
        if (facts.OperationId == Guid.Empty || facts.ContractSha256 != contract || facts.TargetBeforeNativeSha256 != target || facts.SourceFullSha256 != source ||
            facts.RunnerSha256 != runner || !IsHash(facts.TargetLogicalPreimageSha256) || facts.TargetLogicalPreimageSha256 != facts.CloneLogicalPreimageSha256 ||
            !IsHash(facts.BeforeNativeSha256) || !IsHash(facts.AfterNativeSha256) || facts.CloneContainerId.Length != 64 || !facts.CloneContainerId.All(char.IsAsciiHexDigitLower) ||
            !IsHash(facts.RollbackBeforeNativeSha256) || !IsHash(facts.RollbackAfterNativeSha256) || facts.RollbackCloneContainerId.Length != 64 ||
            !facts.RollbackCloneContainerId.All(char.IsAsciiHexDigitLower) || facts.RollbackCloneContainerId == facts.CloneContainerId ||
            !facts.CloneVolume.StartsWith("legacy-delta-proof-", StringComparison.Ordinal) || !facts.RollbackVerified || !facts.CommittedIndependentReadback || !facts.CleanupVerified ||
            facts.ProviderVersion != 180004 || facts.CompletedAtUtc.Offset != TimeSpan.Zero || facts.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            facts.CompletedAtUtc > now || now >= facts.ExpiresAtUtc || facts.ExpiresAtUtc > facts.CompletedAtUtc.AddMinutes(5) ||
            facts.Storage.Count == 0 || facts.Storage.Values.Any(x => x.BeforeBlocks < 0 || x.AfterBlocks < 0)) { throw Invalid(); }
    }
    internal static bool IsHash(string? value)
    {
        return value is { Length: 64 } && value.All(char.IsAsciiHexDigitLower);
    }

    internal static MigrationExecutionException Invalid()
    {
        return new("order_subtotal_operational_unavailable",
            "The fixed historical Order target, live source, actual clone characterization, code or maintenance custody is unavailable or changed.");
    }
}
