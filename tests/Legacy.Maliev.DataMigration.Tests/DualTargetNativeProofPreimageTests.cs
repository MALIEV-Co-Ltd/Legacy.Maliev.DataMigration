namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DualTargetNativeProofPreimageTests
{
    [Fact]
    public void Identical_complete_logical_clone_is_admitted_without_physical_OID_claims()
    {
        DualTargetNativeProofDatabase source = Example();
        DualTargetNativeProofPreimage.RequireClone(source, source with
        { Tables = source.Tables.Reverse().ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal) });
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    public void Full_definition_rows_duplicates_private_journals_and_sequence_state_are_bound(int mutation)
    {
        DualTargetNativeProofDatabase source = Example();
        var tables = source.Tables.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        var sequences = source.Sequences.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        var changed = source with { Tables = tables, Sequences = sequences };
        switch (mutation)
        {
            case 0: changed = changed with { Database = "Other" }; break;
            case 1: changed = changed with { DefinitionSha256 = Hash('c') }; break;
            case 2: tables["items"] = tables["items"] with { Count = 3 }; break;
            case 3: tables["items"] = tables["items"] with { MultisetSha256 = Hash('c') }; break;
            case 4: _ = tables.Remove("private.journal"); break;
            case 5: tables.Add("unrelated", new(0, Hash('d'))); break;
            case 6: sequences["items_id_seq"] = sequences["items_id_seq"] with { LastValue = 9 }; break;
            case 7: sequences["items_id_seq"] = sequences["items_id_seq"] with { IsCalled = false }; break;
            case 8: sequences["items_id_seq"] = sequences["items_id_seq"] with { Increment = 2 }; break;
            case 9: sequences["items_id_seq"] = sequences["items_id_seq"] with { Cache = 2 }; break;
            case 10: sequences["items_id_seq"] = sequences["items_id_seq"] with { Cycle = true }; break;
            default: throw new InvalidOperationException();
        }
        _ = Assert.Throws<MigrationExecutionException>(() => DualTargetNativeProofPreimage.RequireClone(source, changed));
    }

    [Fact]
    public void Full_production49_and_local26_are_required_without_missing_or_duplicate_databases()
    {
        string[] production = [.. ReviewedProductionRepairInventory.ExportProductionNames()];
        string[] local = [.. DatabaseInventory.ActiveDatabases, "Auth", "postgres", "legacy_local"];
        Assert.Equal(49, production.Length); Assert.Equal(26, local.Length);
        DualTargetNativeProofPreimage.RequireInventory(DualTargetCapturedDeltaPurpose.Production, production);
        DualTargetNativeProofPreimage.RequireInventory(DualTargetCapturedDeltaPurpose.PersistentLocal, local);
        _ = Assert.Throws<MigrationExecutionException>(() => DualTargetNativeProofPreimage.RequireInventory(DualTargetCapturedDeltaPurpose.Production, local));
        _ = Assert.Throws<MigrationExecutionException>(() => DualTargetNativeProofPreimage.RequireInventory(DualTargetCapturedDeltaPurpose.PersistentLocal, local.Append(local[0])));
        _ = Assert.Throws<MigrationExecutionException>(() => DualTargetNativeProofPreimage.RequireInventory((DualTargetCapturedDeltaPurpose)99, local));
        _ = Assert.Throws<MigrationExecutionException>(() => DualTargetNativeProofPreimage.RequireInventory(DualTargetCapturedDeltaPurpose.ProductionProof, production));
        _ = Assert.Throws<MigrationExecutionException>(() => DualTargetNativeProofPreimage.RequireInventory(DualTargetCapturedDeltaPurpose.LocalProof, local));
    }

    [Fact]
    public void Role_mapping_rejects_admin_collision_duplicate_and_builtin_role_injection()
    {
        DualTargetNativeProofPreimage.RequireRoleNames(["postgres", "app_owner"], "clone_admin");
        _ = Assert.Throws<MigrationExecutionException>(() => DualTargetNativeProofPreimage.RequireRoleNames(["clone_admin"], "clone_admin"));
        _ = Assert.Throws<MigrationExecutionException>(() => DualTargetNativeProofPreimage.RequireRoleNames(["app_owner", "app_owner"], "clone_admin"));
        _ = Assert.Throws<MigrationExecutionException>(() => DualTargetNativeProofPreimage.RequireRoleNames(["pg_read_all_data"], "clone_admin"));
    }
    [Fact]
    public void Owner_ACL_collation_definition_or_private_table_omission_rejects()
    {
        var before = Example();
        var changedDefinition = before with { DefinitionSha256 = Hash('d') };
        var missingPrivate = before with { Tables = before.Tables.Where(x => x.Key != "private.journal").ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal) };
        _ = Assert.Throws<MigrationExecutionException>(() => DualTargetNativeProofPreimage.RequireClone(before, changedDefinition));
        _ = Assert.Throws<MigrationExecutionException>(() => DualTargetNativeProofPreimage.RequireClone(before, missingPrivate));
        var reverse = before with { Tables = before.Tables.Reverse().ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal) };
        DualTargetNativeProofPreimage.RequireClone(before, reverse);
    }
    private static DualTargetNativeProofDatabase Example()
    {
        return new("Customer", Hash('a'),
        new Dictionary<string, DualTargetNativeProofRows>(StringComparer.Ordinal) { ["items"] = new(2, Hash('b')), ["private.journal"] = new(1, Hash('c')) },
        new Dictionary<string, DualTargetNativeProofSequence>(StringComparer.Ordinal) { ["items_id_seq"] = new("bigint", 1, 1, 1, long.MaxValue, 1, false, 8, true) });
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }
}
