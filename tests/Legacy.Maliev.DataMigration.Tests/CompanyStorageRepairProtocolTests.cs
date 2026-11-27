using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CompanyStorageRepairProtocolTests
{
    private static readonly string[] LocalExtras = ["Auth", "postgres", "legacy_local"];
    [Fact]
    public void Fixed_Company_intent_retains_the_complete_truthful_source_and_detached_physical_views()
    {
        FreshSchemaPlan source = ConsumerColumnBootstrapTestData.WithCorrectedOrder(ConsumerColumnBootstrapTestData.Logical());
        string unchanged = JsonSerializer.Serialize(source);
        var owner = Owner(); var intent = Intent(source, owner);
        var contract = CompanyStorageRepairProtocol.RequireIntent(intent, source, owner, ConsumerColumnBootstrapTestData.Now);
        Assert.Equal(100, source.Databases.Sum(x => x.Tables.Count));
        Assert.NotEqual(contract.Before().TargetSchemaSha256, contract.After().TargetSchemaSha256);
        Assert.Equal(source.Databases.Single(x => x.Database == "Customer").SourceSchemaSha256, contract.After().SourceSchemaSha256);
        foreach (DatabaseSchemaPlan database in source.Databases)
        {
            var view = CompanyStorageRepairProtocol.PhysicalBefore(source, database.Database, false);
            Assert.Equal(JsonSerializer.Serialize(database), JsonSerializer.Serialize(view));
            Assert.NotSame(database, view);
        }
        _ = CompanyStorageRepairProtocol.PhysicalBefore(source, "Country", true);
        _ = CompanyStorageRepairProtocol.PhysicalBefore(source, "Material", true);
        Assert.Equal(unchanged, JsonSerializer.Serialize(source));
    }

    [Theory]
    [InlineData("kind")]
    [InlineData("source-definition")]
    [InlineData("reviewed-source")]
    [InlineData("candidate")]
    [InlineData("owner")]
    [InlineData("native")]
    [InlineData("before")]
    [InlineData("after")]
    [InlineData("expiry")]
    [InlineData("inventory")]
    [InlineData("production-namespace")]
    [InlineData("local-namespace")]
    [InlineData("local-cluster")]
    [InlineData("disposable-label")]
    [InlineData("owned-kind")]
    [InlineData("local-suffix")]
    public void Wrong_definition_authority_phase_or_native_binding_is_rejected(string fault)
    {
        FreshSchemaPlan source = ConsumerColumnBootstrapTestData.Logical(); var owner = Owner(); var intent = Intent(source, owner);
        intent = fault switch
        {
            "kind" => intent with { Kind = "old-or-generic-repair" },
            "source-definition" => intent with { SourceDefinitionSha256 = new('f', 64) },
            "reviewed-source" => intent with { ReviewedSourceFullSha256 = "unbound" },
            "candidate" => intent with { CandidateSqlSha256 = new('f', 64) },
            "owner" => intent with { CompanyOwnerName = "caller_selected_owner" },
            "native" => intent with { NativePreimageSha256 = "opaque" },
            "before" => intent with { CustomerBeforeSchemaSha256 = intent.CustomerAfterSchemaSha256 },
            "after" => intent with { CustomerAfterSchemaSha256 = intent.CustomerBeforeSchemaSha256 },
            "expiry" => intent with { ExpiresAtUtc = ConsumerColumnBootstrapTestData.Now },
            "inventory" => intent with { BeforeDatabaseSha256 = new Dictionary<string, string>() },
            "local-namespace" => intent with { TargetNamespace = "maliev-legacy" },
            "local-cluster" => intent with { TargetCluster = "legacy-postgres-main" },
            "disposable-label" => intent with { Target = intent.Target with { AuthorityId = "aspire://legacy-postgres-main-local/disposable-0123456789ab" } },
            "owned-kind" => intent with { Kind = CompanyStorageRepairProtocol.OwnedIntentKind },
            "local-suffix" => intent with { Target = intent.Target with { AuthorityId = "aspire://legacy-postgres-main-local/persistent-not-a-container" } },
            "production-namespace" => intent with
            {
                Target = intent.Target with { Kind = DeltaTargetAuthorityKind.ProductionCloudNativePg },
                TargetNamespace = "maliev",
                BeforeDatabaseSha256 = ReviewedProductionRepairInventory.ExportProductionNames().ToDictionary(x => x, _ => new string('d', 64), StringComparer.Ordinal),
            },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CompanyStorageRepairProtocol.RequireIntent(intent, source, owner, ConsumerColumnBootstrapTestData.Now));
    }

    [Fact]
    public void Complete_source_definition_is_not_just_the_Company_operand()
    {
        FreshSchemaPlan source = ConsumerColumnBootstrapTestData.Logical(); var owner = Owner(); var intent = Intent(source, owner);
        FreshSchemaPlan changed = ConsumerColumnBootstrapTestData.WithCorrectedOrder(source);
        Assert.NotEqual(SchemaPlanCanonicalizer.ComputeSha256(source), SchemaPlanCanonicalizer.ComputeSha256(changed));
        _ = Assert.Throws<MigrationExecutionException>(() => CompanyStorageRepairProtocol.RequireIntent(intent, changed, owner, ConsumerColumnBootstrapTestData.Now));
    }

    private static CustomerCompanyStorageRepairOwner Owner()
    {
        return CustomerCompanyStorageRepairContractTests.Owner() with { ObservedAtUtc = ConsumerColumnBootstrapTestData.Now };
    }

    private static CompanyStorageRepairIntent Intent(FreshSchemaPlan source, CustomerCompanyStorageRepairOwner owner)
    {
        DateTimeOffset now = ConsumerColumnBootstrapTestData.Now; string identity = new('b', 64);
        var contract = ApprovedCustomerCompanyStorageRepair.Create(source.Databases.Single(x => x.Database == "Customer"), source.SourceCommitSha, source.SourceCommitSha, owner, now);
        var fleet = source.Databases.Select(x => x.Database).Concat(LocalExtras)
            .ToDictionary(x => x, _ => new string('d', 64), StringComparer.Ordinal);
        return new(CompanyStorageRepairProtocol.IntentKind, Guid.NewGuid(), source.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(source), identity,
            SourceCatalogDefinitionFingerprintV1.Compute(source, source.SourceCommitSha, identity, now), contract.Before().TargetSchemaSha256, contract.After().TargetSchemaSha256,
            CompanyStorageRepairProtocol.CandidateSha256, false, false,
            new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/persistent-0123456789ab", new('c', 64)), "local-aspire", "legacy-postgres-main-local", "synthetic-unit-generation",
            new('e', 64), new('f', 64), fleet, new('a', 64), "postgres",
            new("synthetic_role", "synthetic_comment", now, now.AddMinutes(10), now.AddHours(-1), now.AddMinutes(-1), new('a', 64), new('b', 64), "/synthetic/pg_hba.conf"),
            now, now.AddMinutes(5));
    }
}
