namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DualTargetCapturedDeltaContractTests
{
    [Theory]
    [InlineData((int)DualTargetCapturedDeltaPurpose.Production, "production-cloudnativepg", "gke://maliev-website/cluster", "maliev-legacy", "legacy-postgres-main")]
    [InlineData((int)DualTargetCapturedDeltaPurpose.PersistentLocal, "local-aspire", "aspire://legacy-postgres-main-local/persistent-test", "local-aspire", "legacy-postgres-main-local")]
    [InlineData((int)DualTargetCapturedDeltaPurpose.ProductionProof, "local-aspire", "aspire://legacy-postgres-main-local/disposable-prod", "local-aspire", "legacy-postgres-main-local")]
    [InlineData((int)DualTargetCapturedDeltaPurpose.LocalProof, "local-aspire", "aspire://legacy-postgres-main-local/disposable-local", "local-aspire", "legacy-postgres-main-local")]
    public void Exact_target_purposes_are_supported(int purpose, string kind, string id, string space, string cluster)
    {
        DualTargetCapturedDeltaContract.RequirePurpose((DualTargetCapturedDeltaPurpose)purpose, new(kind, id, new string('a', 64)), space, cluster);
    }

    [Theory]
    [InlineData((int)DualTargetCapturedDeltaPurpose.Production, "local-aspire", "aspire://legacy-postgres-main-local/persistent-test", "local-aspire", "legacy-postgres-main-local")]
    [InlineData((int)DualTargetCapturedDeltaPurpose.PersistentLocal, "local-aspire", "aspire://legacy-postgres-main-local/disposable-test", "local-aspire", "legacy-postgres-main-local")]
    [InlineData((int)DualTargetCapturedDeltaPurpose.ProductionProof, "production-cloudnativepg", "gke://maliev-website/cluster", "maliev-legacy", "legacy-postgres-main")]
    [InlineData((int)DualTargetCapturedDeltaPurpose.Production, "production-cloudnativepg", "gke://another-project/cluster", "maliev-legacy", "legacy-postgres-main")]
    [InlineData((int)DualTargetCapturedDeltaPurpose.Production, "production-cloudnativepg", "gke://maliev-website/cluster", "maliev", "legacy-postgres-main")]
    [InlineData(99, "local-aspire", "aspire://legacy-postgres-main-local/persistent-test", "local-aspire", "legacy-postgres-main-local")]
    public void Target_substitution_and_unknown_purposes_are_rejected(int purpose, string kind, string id, string space, string cluster)
    {
        _ = Assert.Throws<DeltaExecutionException>(() => DualTargetCapturedDeltaContract.RequirePurpose((DualTargetCapturedDeltaPurpose)purpose,
            new(kind, id, new string('a', 64)), space, cluster));
    }

    [Fact]
    public void Ordinary_inserts_and_updates_are_supported_but_delete_is_refused_even_with_false_count()
    {
        DatabaseSchemaPlan schema = Schema("dbo");
        DualTargetCapturedDeltaContract.RequireZeroDeleteAndEffects(schema, [Plan(DeltaOperationKind.Insert), Plan(DeltaOperationKind.Update)]);
        _ = Assert.Throws<DeltaExecutionException>(() => DualTargetCapturedDeltaContract.RequireZeroDeleteAndEffects(schema,
            [Plan(DeltaOperationKind.Delete) with { DeleteCount = 0 }]));
    }

    [Theory]
    [InlineData(DeltaOperationKind.Insert)]
    [InlineData(DeltaOperationKind.Update)]
    [InlineData(DeltaOperationKind.Delete)]
    [InlineData((DeltaOperationKind)99)]
    public void Immutable_disposition_effects_are_refused(DeltaOperationKind operation)
    {
        _ = Assert.Throws<DeltaExecutionException>(() => DualTargetCapturedDeltaContract.RequireZeroDeleteAndEffects(Schema("disposition"), [Plan(operation)]));
    }

    [Fact]
    public void Unchanged_immutable_disposition_is_supported()
    {
        DualTargetCapturedDeltaContract.RequireZeroDeleteAndEffects(Schema("disposition"),
            [new("public.items", 0, 0, 0, 1, new string('a', 64), [])]);
    }

    [Theory]
    [InlineData((int)DualTargetCapturedDeltaPurpose.ProductionProof)]
    [InlineData((int)DualTargetCapturedDeltaPurpose.LocalProof)]
    [InlineData(99)]
    public void Proof_targets_cannot_be_reviewed_as_persistent_targets(int purpose)
    {
        _ = Assert.Throws<DeltaExecutionException>(() => DualTargetCapturedDeltaAdmission.ProofPurpose((DualTargetCapturedDeltaPurpose)purpose));
    }

    private static DatabaseSchemaPlan Schema(string sourceSchema)
    {
        return new("Customer", "1.0", new string('a', 64), new string('b', 64),
        [new(sourceSchema, "items", "public", "items", ["Id"], ["Id"]) { ColumnTypes = new Dictionary<string, string> { ["Id"] = "integer" } }]);
    }

    private static DeltaTablePlan Plan(DeltaOperationKind operation)
    {
        return new("public.items", operation == DeltaOperationKind.Insert ? 1 : 0,
            operation == DeltaOperationKind.Update ? 1 : 0, operation == DeltaOperationKind.Delete ? 1 : 0, 0, new string('a', 64),
            [new(operation, new string('b', 64), operation == DeltaOperationKind.Delete ? null : new string('c', 64),
            operation == DeltaOperationKind.Insert ? null : new string('d', 64))]);
    }
}
