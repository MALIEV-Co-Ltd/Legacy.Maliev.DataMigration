using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record CompanyStorageRepairIntent(string Kind, Guid IntentId, string SourceCommitSha,
    string ReviewedSourceFullSha256, string SourceIdentitySha256, string SourceDefinitionSha256,
    string CustomerBeforeSchemaSha256, string CustomerAfterSchemaSha256, string CandidateSqlSha256,
    bool OwnerIsoAlreadyApplied, bool SchemaAlreadyCorrect, DeltaTargetAuthority Target, string TargetNamespace, string TargetCluster,
    string TargetGeneration, string TargetObservationSha256, string RunBindingSha256,
    IReadOnlyDictionary<string, string> BeforeDatabaseSha256, string NativePreimageSha256,
    string CompanyOwnerName, CurrentAppOwnedMaintenancePin Maintenance, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record CompanyStorageRepairScope(string Kind, Guid OperationId, string IntentSha256,
    string FreshSourceFullSha256, string SourceDefinitionSha256, string ContractSha256,
    string ActualDisposableProofSha256, string RunnerDigestSha256, CompanyStorageRepairIntent Intent, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record CompanyStorageRepairAuthorization(Guid OperationId, string ReviewSha256,
    DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record CompanyStorageRepairReceipt(string Kind, Guid OperationId, string ScopeSha256,
    string AuthorizationSha256, string PreviousSha256, string BeforeNativeSha256, string? AfterNativeSha256,
    string ActualDisposableProofSha256, CurrentAppOwnedCommitClassification Classification, DateTimeOffset ObservedAtUtc);

/// <summary>One fixed Company operation. Neither these wire records nor old repair permits grant execution.</summary>
internal static class CompanyStorageRepairProtocol
{
    internal const string IntentKind = "current-company-storage-reviewed-intent-v1";
    internal const string ScopeKind = "current-company-storage-target-scope-v1";
    internal const string OwnedIntentKind = "current-company-storage-owned-fault-intent-v1";
    internal const string OwnedScopeKind = "current-company-storage-owned-fault-scope-v1";
    internal const string IntentDomain = "Legacy.Maliev.CompanyStorage.Intent.v1";
    internal const string ReviewDomain = "Legacy.Maliev.CompanyStorage.Review.v1";
    internal const string AuthorizationDomain = "Legacy.Maliev.CompanyStorage.Authorization.v1";
    internal const string ReceiptDomain = "Legacy.Maliev.CompanyStorage.Receipt.v1";
    internal const string ProofDomain = "Legacy.Maliev.CompanyStorage.DisposableProof.v1";
    internal static string CandidateSha256 => Hash(Encoding.UTF8.GetBytes(ApprovedCustomerCompanyStorageRepair.CandidateSql.Replace("\r\n", "\n", StringComparison.Ordinal)));
    internal static string Hash(byte[] bytes)
    {
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }

    internal static string Hash<T>(T value)
    {
        return Hash(JsonSerializer.SerializeToUtf8Bytes(value));
    }

    internal static T Copy<T>(T value)
    {
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value))!;
    }

    internal static ApprovedCustomerCompanyStorageRepair RequireIntent(CompanyStorageRepairIntent intent, FreshSchemaPlan source,
        CustomerCompanyStorageRepairOwner owner, DateTimeOffset now)
    {
        return RequireIntentCore(intent, source, owner, now, owned: false);
    }

    // Pure validation for the separately typed owned fault lane; supplies no endpoint or execution authority.
    internal static ApprovedCustomerCompanyStorageRepair RequireOwnedIntent(CompanyStorageRepairIntent intent, FreshSchemaPlan source,
        CustomerCompanyStorageRepairOwner owner, DateTimeOffset now)
    {
        return RequireIntentCore(intent, source, owner, now, owned: true);
    }

    private static ApprovedCustomerCompanyStorageRepair RequireIntentCore(CompanyStorageRepairIntent intent, FreshSchemaPlan source,
        CustomerCompanyStorageRepairOwner owner, DateTimeOffset now, bool owned)
    {
        ProductionSchemaCatalogInspector.ValidatePlan(source, now);
        if (intent.Kind != (owned ? OwnedIntentKind : IntentKind) || intent.IntentId == Guid.Empty || source.SourceCommitSha != intent.SourceCommitSha ||
            source.Databases.Count != 23 || source.Databases.Sum(x => x.Tables.Count) != 100 ||
            source.Databases.Any(x => x.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(x.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3)) ||
            SourceCatalogDefinitionFingerprintV1.Compute(source, intent.SourceCommitSha, intent.SourceIdentitySha256, now) != intent.SourceDefinitionSha256 ||
            intent.CompanyOwnerName is not ("legacy_local" or "postgres" or "legacy_customer_owner") ||
            intent.CandidateSqlSha256 != CandidateSha256 || !IsSha256(intent.ReviewedSourceFullSha256) || !IsSha256(intent.TargetObservationSha256) ||
            !IsSha256(intent.NativePreimageSha256) || !IsSha256(intent.Target.SystemIdentifierSha256) || !IsSha256(intent.RunBindingSha256) ||
            intent.BeforeDatabaseSha256.Values.Any(x => !IsSha256(x)) ||
            intent.Target.Kind is not (DeltaTargetAuthorityKind.LocalAspire or DeltaTargetAuthorityKind.ProductionCloudNativePg) ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(intent.Target, intent.TargetNamespace, intent.TargetCluster) ||
            (owned && intent.Target.Kind != DeltaTargetAuthorityKind.LocalAspire) ||
            (intent.Target.Kind == DeltaTargetAuthorityKind.LocalAspire && (intent.TargetNamespace != "local-aspire" || intent.TargetCluster != "legacy-postgres-main-local" ||
                !LocalAuthorityShape(intent.Target, owned))) ||
            (intent.Target.Kind == DeltaTargetAuthorityKind.ProductionCloudNativePg && (intent.TargetNamespace != "maliev-legacy" || intent.TargetCluster != "legacy-postgres-main")) ||
            !ReviewedProductionRepairInventory.MatchesKeys(intent.Target.Kind, intent.BeforeDatabaseSha256.Keys) ||
            intent.IssuedAtUtc.Offset != TimeSpan.Zero || intent.ExpiresAtUtc.Offset != TimeSpan.Zero || now.Offset != TimeSpan.Zero ||
            intent.IssuedAtUtc > now || intent.ExpiresAtUtc <= now || intent.ExpiresAtUtc > intent.IssuedAtUtc.AddMinutes(15) ||
            intent.ExpiresAtUtc > intent.Maintenance.ExpiresAtUtc || intent.Maintenance.IssuedAtUtc > now)
        { throw Invalid(); }
        var contract = ApprovedCustomerCompanyStorageRepair.Create(source.Databases.Single(x => x.Database == "Customer"),
            source.SourceCommitSha, intent.SourceCommitSha, owner, now);
        return contract.Before().TargetSchemaSha256 != intent.CustomerBeforeSchemaSha256 || contract.After().TargetSchemaSha256 != intent.CustomerAfterSchemaSha256
            ? throw Invalid()
            : contract;
    }

    // Detached physical phase views only. The complete source capture and its profiles are never rewritten.
    internal static DatabaseSchemaPlan PhysicalBefore(FreshSchemaPlan source, string database, bool isoAlreadyApplied)
    {
        DatabaseSchemaPlan original = source.Databases.Single(x => x.Database == database);
        if (!isoAlreadyApplied || database is not ("Country" or "Material")) { return Copy(original); }
        IReadOnlyList<TableCopyPlan> physical = ApprovedConsumerColumnOverlayManifest.ComposePhysical(original);
        physical = database == "Country" ? CurrentConsumerSchemaV3SourceOrderIsoManifest.Apply(physical) : CurrentConsumerSchemaV3IsoManifest.Apply(database, physical);
        var detached = original with { Tables = physical, TargetExtensionProfile = null, SourceDispositionProfile = null, SourceTableDispositions = [] };
        return detached with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(detached) };
    }

    internal static string NativeSha(CustomerCompanyStorageNativePreservation.Observation observation)
    {
        return Hash(new
        {
            Kind = "current-company-storage-native-preimage-v1",
            observation.Native.Snapshot.Sha256,
            observation.ProviderVersion,
            observation.CompositeDefense,
            Tuples = CatalogNames.Select(catalog => new { Catalog = catalog, Tuples = observation.Native.Read(catalog).Select(x => Hash(Encoding.UTF8.GetBytes(x.ToJsonString()))).Order(StringComparer.Ordinal) }),
            IndexStorage = observation.Native.Read("pg_index").Select(x => x["indexrelid"]!.ToString()).Order(StringComparer.Ordinal)
            .Select(id => new { Id = id, observation.Native.Storage(id).FileNode, observation.Native.Storage(id).Blocks }),
        });
    }

    // Same retained 43-catalog inventory used by the already-reviewed observer.
    internal static IReadOnlyList<string> CatalogNames => ConsumerColumnBootstrapNativePreservation.CatalogNames;
    private static bool IsSha256(string value)
    {
        return value.Length == 64 && value.All(x => x is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }

    private static bool LocalAuthorityShape(DeltaTargetAuthority target, bool owned)
    {
        string prefix = "aspire://legacy-postgres-main-local/" + (owned ? "disposable-" : "persistent-");
        return target.AuthorityId.StartsWith(prefix, StringComparison.Ordinal) && target.AuthorityId.Length == prefix.Length + 12 &&
            target.AuthorityId[prefix.Length..].All(x => x is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }
    internal static MigrationExecutionException Invalid()
    {
        return new("company_storage_repair_unavailable", "The fixed Company operation, source, target, native preimage, maintenance lease or genuine proof is unavailable or changed.");
    }
}
