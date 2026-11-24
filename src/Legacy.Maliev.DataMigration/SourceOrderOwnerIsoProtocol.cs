using System.Text;

namespace Legacy.Maliev.DataMigration;

internal sealed record SourceOrderOwnerIsoIntent(string Kind, Guid IntentId, string SourceCommitSha, string ReviewedFullSourceSha256,
    string SourceIdentitySha256, string SourceDefinitionSha256, string OwnerDefinitionsSha256, bool CompanyAlreadyApplied,
    DeltaTargetAuthority Target, string TargetNamespace, string TargetCluster, string TargetGeneration, string TargetObservationSha256,
    string RunBindingSha256, IReadOnlyDictionary<string, string> BeforeDatabaseSha256, IReadOnlyDictionary<string, bool> Selected,
    IReadOnlyDictionary<string, string> NativePreimageSha256, CurrentAppOwnedMaintenancePin Maintenance, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record SourceOrderOwnerIsoScope(string Kind, Guid OperationId, string IntentSha256, SourceOrderOwnerIsoIntent Intent,
    string ActualFullSourceSha256, string ContractSha256, string ProofSha256, string RunnerSha256, IReadOnlyList<string> PendingDatabases,
    IReadOnlyList<CurrentOwnerIsoSourceObservation> Owners, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record SourceOrderOwnerIsoAuthorization(Guid OperationId, string ReviewSha256, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record SourceOrderOwnerIsoReceipt(string Kind, Guid OperationId, string Database, string ScopeSha256, string AuthorizationSha256,
    string PreviousSha256, string BeforeNativeSha256, string? AfterNativeSha256, CurrentAppOwnedCommitClassification Classification, DateTimeOffset ObservedAtUtc);

internal static class SourceOrderOwnerIsoProtocol
{
    internal static readonly string[] Databases = ["Country", "Material"];
    internal const string IntentKind = "source-order-owner-iso-intent-v1", OwnedIntentKind = "source-order-owner-iso-owned-intent-v1";
    internal const string IntentDomain = "Legacy.Maliev.SourceOrderOwnerIso.Intent.v1", ReviewDomain = "Legacy.Maliev.SourceOrderOwnerIso.Review.v1",
        AuthorizationDomain = "Legacy.Maliev.SourceOrderOwnerIso.Authorization.v1", ReceiptDomain = "Legacy.Maliev.SourceOrderOwnerIso.Receipt.v1",
        ProofDomain = "Legacy.Maliev.SourceOrderOwnerIso.ActualOwnedProof.v1";
    internal static string Hash<T>(T value)
    {
        return CompanyStorageRepairProtocol.Hash(value);
    }

    internal static string Hash(byte[] value)
    {
        return CompanyStorageRepairProtocol.Hash(value);
    }

    internal static T Copy<T>(T value)
    {
        return CompanyStorageRepairProtocol.Copy(value);
    }

    internal static string SqlSha256 => CompanyStorageRepairProtocol.Hash([.. "Legacy.Maliev.SourceOrderOwnerIso.FixedSql.v1\0"u8, .. Encoding.UTF8.GetBytes(PostgreSqlCurrentOwnerIsoRepair.Sql)]);
    internal static string OwnerDefinitions(IReadOnlyList<CurrentOwnerIsoSourceObservation> owners)
    {
        return Hash(owners.OrderBy(x => x.Repository, StringComparer.Ordinal)
        .Select(x => new { x.Repository, x.Head, Files = x.Files.OrderBy(p => p.Key, StringComparer.Ordinal) }));
    }

    internal static SourceOrderOwnerIsoContract Require(SourceOrderOwnerIsoIntent intent, ConsumerOverlaySelection selection, FreshSchemaPlan source,
        IReadOnlyList<CurrentOwnerIsoSourceObservation> owners, DateTimeOffset now, bool owned)
    {
        return selection != ConsumerOverlaySelection.CurrentConsumerSchemaV3 || intent.Kind != (owned ? OwnedIntentKind : IntentKind) || intent.IntentId == Guid.Empty ||
            source.SourceCommitSha != intent.SourceCommitSha || SourceCatalogDefinitionFingerprintV1.Compute(source, intent.SourceCommitSha, intent.SourceIdentitySha256, now) != intent.SourceDefinitionSha256 ||
            OwnerDefinitions(owners) != intent.OwnerDefinitionsSha256 || !DeltaSynchronizationPlanProducer.ValidAuthority(intent.Target, intent.TargetNamespace, intent.TargetCluster) ||
            (owned && intent.Target.Kind != DeltaTargetAuthorityKind.LocalAspire) ||
            (intent.Target.Kind == DeltaTargetAuthorityKind.LocalAspire && (intent.TargetNamespace != "local-aspire" || intent.TargetCluster != "legacy-postgres-main-local" || !LocalShape(intent.Target, owned))) ||
            (intent.Target.Kind == DeltaTargetAuthorityKind.ProductionCloudNativePg && (intent.TargetNamespace != "maliev-legacy" || intent.TargetCluster != "legacy-postgres-main")) ||
            !ReviewedProductionRepairInventory.MatchesKeys(intent.Target.Kind, intent.BeforeDatabaseSha256.Keys) ||
            !intent.Selected.Keys.Order(StringComparer.Ordinal).SequenceEqual(Databases, StringComparer.Ordinal) ||
            !intent.NativePreimageSha256.Keys.Order(StringComparer.Ordinal).SequenceEqual(Databases, StringComparer.Ordinal) ||
            intent.BeforeDatabaseSha256.Values.Concat(intent.NativePreimageSha256.Values).Append(intent.ReviewedFullSourceSha256).Append(intent.SourceIdentitySha256)
                .Append(intent.TargetObservationSha256).Append(intent.RunBindingSha256).Any(x => x.Length != 64 || !x.All(char.IsAsciiHexDigit)) ||
            now.Offset != TimeSpan.Zero || intent.Maintenance.IssuedAtUtc > now || intent.IssuedAtUtc.Offset != TimeSpan.Zero || intent.ExpiresAtUtc.Offset != TimeSpan.Zero || intent.IssuedAtUtc > now || intent.ExpiresAtUtc <= now ||
            intent.ExpiresAtUtc > intent.IssuedAtUtc.AddMinutes(5) || intent.ExpiresAtUtc > intent.Maintenance.ExpiresAtUtc
            ? throw Invalid()
            : SourceOrderOwnerIsoContract.Create(source, intent.SourceCommitSha, intent.CompanyAlreadyApplied, owners, now);
    }
    internal static string NativeSha(CurrentOwnerIsoNativeObservation value)
    {
        return Hash(new
        {
            Domain = "Legacy.Maliev.SourceOrderOwnerIso.NativePreimage.v1",
            value.Selected,
            value.Snapshot.Sha256,
            value.LiteralRows,
            Catalogs = value.CopyCatalog().OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new { x.Key, Rows = x.Value.Order(StringComparer.Ordinal) }),
            Storage = value.CopyStorage().OrderBy(x => x.Key, StringComparer.Ordinal),
        });
    }

    private static bool LocalShape(DeltaTargetAuthority target, bool owned)
    {
        string prefix = "aspire://legacy-postgres-main-local/" + (owned ? "disposable-" : "persistent-");
        return target.AuthorityId.StartsWith(prefix, StringComparison.Ordinal) && target.AuthorityId.Length == prefix.Length + 12 &&
            target.AuthorityId[prefix.Length..].All(x => x is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }
    internal static MigrationExecutionException Invalid()
    {
        return new("source_order_owner_iso_unavailable", "The fixed source-order owner ISO source, owner, native, target, maintenance or actual proof fence failed.");
    }
}
