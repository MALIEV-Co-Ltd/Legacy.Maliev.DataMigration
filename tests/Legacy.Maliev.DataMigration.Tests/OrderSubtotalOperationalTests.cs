using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class OrderSubtotalOperationalTests
{
    private static readonly string[] FleetExtensions = ["Auth", "postgres", "legacy_local"];
    [Fact]
    public void Actual_rehearsal_implements_the_fixed_Core_characterization_contract()
    {
        var issuer = typeof(MigrationConsole).Assembly.GetType(
            "Legacy.Maliev.DataMigration.Console.OrderSubtotalRuntime+Rehearsal", throwOnError: true)!;
        Assert.True(issuer.IsSealed && issuer.IsNestedPrivate);
        Assert.Empty(issuer.GetConstructors(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance));
        var method = issuer.GetMethod("GetCharacterizationAsync",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.DeclaredOnly,
            null, [typeof(CancellationToken)], null);
        Assert.NotNull(method);
        Assert.Equal(issuer, method.DeclaringType);
        Assert.True(method.IsAssembly);
        Assert.False(method.IsStatic || method.IsGenericMethod);
        Assert.Equal(typeof(Task<OrderSubtotalCharacterization>), method.ReturnType);
    }

    [Fact]
    public void Complete_truthful_source_is_immutable_and_historical_views_are_detached()
    {
        var source = ConsumerColumnBootstrapTestData.WithCorrectedOrder(ConsumerColumnBootstrapTestData.Logical());
        string original = JsonSerializer.Serialize(source); var intent = Intent(source);
        var contract = OrderSubtotalRepairProtocol.RequireIntent(intent, source, ConsumerColumnBootstrapTestData.Now);
        Assert.Equal(100, source.Databases.Sum(x => x.Tables.Count));
        Assert.NotEqual(contract.BeforePhysical().TargetSchemaSha256, contract.AfterPhysical().TargetSchemaSha256);
        foreach (var database in source.Databases.Where(x => x.Database != "Order"))
        {
            var physical = OrderSubtotalRepairProtocol.PhysicalBefore(source, database.Database);
            Assert.Null(physical.TargetExtensionProfile); Assert.Equal(database.SourceSchemaSha256, physical.SourceSchemaSha256);
            Assert.NotSame(database, physical);
        }
        _ = Assert.Throws<MigrationExecutionException>(() => OrderSubtotalRepairProtocol.PhysicalBefore(source, "Order"));
        Assert.Equal(original, JsonSerializer.Serialize(source));
    }
    [Theory]
    [InlineData("kind")]
    [InlineData("definition")]
    [InlineData("candidate")]
    [InlineData("native")]
    [InlineData("before")]
    [InlineData("owner")]
    [InlineData("namespace")]
    [InlineData("inventory")]
    [InlineData("native-inventory")]
    [InlineData("disposable")]
    [InlineData("expression")]
    [InlineData("expiry")]
    public void Signed_descriptions_cannot_widen_the_fixed_historical_Order_target(string fault)
    {
        var source = ConsumerColumnBootstrapTestData.WithCorrectedOrder(ConsumerColumnBootstrapTestData.Logical()); var intent = Intent(source);
        var changed = fault switch
        {
            "kind" => intent with { Kind = "current-company-storage-reviewed-intent-v1" },
            "definition" => intent with { SourceDefinitionSha256 = Hash('f') },
            "candidate" => intent with { CandidateSqlSha256 = Hash('f') },
            "native" => intent with { NativePreimageSha256 = "not-a-hash" },
            "before" => intent with { BeforePhysicalSha256 = Hash('f') },
            "owner" => intent with { OrderOwnerName = "arbitrary_owner" },
            "namespace" => intent with { TargetNamespace = "maliev" },
            "inventory" => intent with { BeforeDatabaseSha256 = intent.BeforeDatabaseSha256.Where(x => x.Key != "Auth").ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal) },
            "native-inventory" => intent with { BeforeNativeDatabaseSha256 = new Dictionary<string, string>(StringComparer.Ordinal) },
            "disposable" => intent with { Target = intent.Target with { AuthorityId = "aspire://legacy-postgres-main-local/disposable-0123456789ab" } },
            "expression" => intent with { HistoricalExpression = OrderSubtotalExpressionRepairContract.CorrectedExpression },
            "expiry" => intent with { ExpiresAtUtc = intent.IssuedAtUtc.AddHours(1) },
            _ => throw new InvalidOperationException()
        };
        _ = Assert.Throws<MigrationExecutionException>(() => OrderSubtotalRepairProtocol.RequireIntent(changed, source, ConsumerColumnBootstrapTestData.Now));
    }
    [Fact]
    public async Task JSON_and_other_issuer_objects_never_mint_a_storage_profile_or_open_targets()
    {
        _ = Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<OrderSubtotalStorageProfile>("{\"CleanupVerified\":true}"));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => OrderSubtotalStorageProfile.AuthenticateAsync(new { Verified = true }, Hash('a'), Hash('b'), Hash('c'), Hash('d'), CancellationToken.None));
        using var output = new StringWriter(); using var error = new StringWriter();
        Assert.Equal(1, await MigrationConsole.RunOrderSubtotalOperationalAsync("apply-current-order-subtotal", "not-a-config", output, error, CancellationToken.None));
        Assert.Equal(string.Empty, output.ToString());
    }
    [Fact]
    public void Old_synthetic_storage_fence_is_not_a_generic_operational_allowance()
    {
        OrderSubtotalExpressionRepairNativePreservation.RequireCharacterizedStorage("root", 348, 384, 180004, false);
        _ = Assert.Throws<MigrationExecutionException>(() => OrderSubtotalExpressionRepairNativePreservation.RequireCharacterizedStorage("root", 349, 384, 180004, false));
        _ = Assert.Throws<MigrationExecutionException>(() => OrderSubtotalExpressionRepairNativePreservation.RequireCharacterizedStorage("index:other", 38, 38, 180004, false));
    }
    [Theory]
    [InlineData("logical")]
    [InlineData("target")]
    [InlineData("rollback")]
    [InlineData("readback")]
    [InlineData("cleanup")]
    [InlineData("same-clone")]
    [InlineData("provider")]
    [InlineData("expiry")]
    public void Characterization_requires_actual_distinct_clone_outcomes_and_exact_target_binding(string fault)
    {
        var now = ConsumerColumnBootstrapTestData.Now;
        var facts = new OrderSubtotalCharacterization(Guid.NewGuid(), Hash('a'), Hash('b'), Hash('c'), Hash('c'), Hash('d'), Hash('e'),
            new('a', 64), "legacy-delta-proof-synthetic", new('b', 64), Hash('a'), Hash('b'), 180004, false,
            new Dictionary<string, OrderSubtotalStorageTransition>(StringComparer.Ordinal) { ["root"] = new(1, 2) }, Hash('a'), Hash('b'), true, true, true, now, now.AddMinutes(1));
        OrderSubtotalRepairProtocol.RequireCharacterization(facts, Hash('a'), Hash('b'), Hash('d'), Hash('e'), now);
        var changed = fault switch
        {
            "logical" => facts with { CloneLogicalPreimageSha256 = Hash('f') },
            "target" => facts with { TargetBeforeNativeSha256 = Hash('f') },
            "rollback" => facts with { RollbackVerified = false },
            "readback" => facts with { CommittedIndependentReadback = false },
            "cleanup" => facts with { CleanupVerified = false },
            "same-clone" => facts with { RollbackCloneContainerId = facts.CloneContainerId },
            "provider" => facts with { ProviderVersion = 180007 },
            "expiry" => facts with { ExpiresAtUtc = now },
            _ => throw new InvalidOperationException()
        };
        _ = Assert.Throws<MigrationExecutionException>(() => OrderSubtotalRepairProtocol.RequireCharacterization(changed, Hash('a'), Hash('b'), Hash('d'), Hash('e'), now));
    }
    internal static OrderSubtotalRepairIntent Intent(FreshSchemaPlan source)
    {
        var now = ConsumerColumnBootstrapTestData.Now; string identity = Hash('b');
        var contract = OrderSubtotalExpressionRepairContract.Create(source, source.SourceCommitSha, OrderSubtotalExpressionRepairContract.HistoricalExpression, now);
        var map = DatabaseInventory.ActiveDatabases.Concat(FleetExtensions).ToDictionary(x => x, _ => Hash('d'), StringComparer.Ordinal);
        return new(OrderSubtotalRepairProtocol.IntentKind, Guid.NewGuid(), source.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(source), identity,
            SourceCatalogDefinitionFingerprintV1.Compute(source, source.SourceCommitSha, identity, now), contract.BeforePhysical().TargetSchemaSha256, contract.AfterPhysical().TargetSchemaSha256,
            OrderSubtotalRepairProtocol.CandidateSha256, new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/persistent-0123456789ab", Hash('c')),
            "local-aspire", "legacy-postgres-main-local", "synthetic-generation", Hash('e'), Hash('f'), map, new Dictionary<string, string>(map, StringComparer.Ordinal), Hash('a'), "postgres",
            OrderSubtotalExpressionRepairContract.HistoricalExpression,
            new("synthetic_role", "synthetic_comment", now, now.AddMinutes(10), now.AddHours(-1), now.AddMinutes(-1), Hash('a'), Hash('b'), "/synthetic/pg_hba.conf"), now, now.AddMinutes(5));
    }
    private static string Hash(char value)
    {
        return new(value, 64);
    }
}
