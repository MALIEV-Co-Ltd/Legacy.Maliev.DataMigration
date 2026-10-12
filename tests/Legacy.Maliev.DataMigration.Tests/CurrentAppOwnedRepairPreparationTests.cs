namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAppOwnedRepairPreparationTests
{
    [Fact]
    public void Fixed_operations_reject_unknowns_and_have_distinct_reproducible_digests()
    {
        string create = CurrentAppOwnedRepairManifest.OperationSha256(CurrentAppOwnedRepairOperation.CreateEightTables);
        string collate = CurrentAppOwnedRepairManifest.OperationSha256(CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations);
        Assert.NotEqual(create, collate);
        Assert.Equal(create, CurrentAppOwnedRepairManifest.OperationSha256(CurrentAppOwnedRepairOperation.CreateEightTables));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairManifest.OperationSha256((CurrentAppOwnedRepairOperation)2));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairManifest.CreateEightSql("Auth"));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairManifest.CollationSql("Upload"));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairManifest.NewTables("Material"));
    }

    [Fact]
    public void Closed_eight_shapes_and_literal_DDL_retain_counts_constraints_and_C_policy()
    {
        string[] databases = CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.CreateEightTables);
        TableCopyPlan[] tables = [.. databases.SelectMany(ApprovedCurrentConsumerTargetShapes.ForDatabase)];
        Assert.Equal(8, tables.Length);
        Assert.Equal(76, tables.Sum(x => x.OrderedColumns.Count));
        Assert.Equal(8, tables.Count(x => x.PrimaryKey is not null));
        Assert.Equal(14, tables.Sum(x => x.CheckConstraints.Count));
        Assert.Equal(2, tables.Sum(x => x.ForeignKeys.Count));
        Assert.Equal(7, tables.Sum(x => x.Indexes.Count));
        Assert.Equal(3, tables.Sum(x => x.Indexes.Count(index => index.Unique)));
        Assert.Equal(27, tables.Sum(x => x.Collations.Count));
        foreach (string database in databases)
        {
            string sql = CurrentAppOwnedRepairManifest.CreateEightSql(database);
            Assert.DoesNotContain("COMMIT", sql, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("DROP ", sql, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("IF NOT EXISTS", sql, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("__EFMigrationsHistory", sql, StringComparison.Ordinal);
            foreach (TableCopyPlan table in tables.Where(x => CurrentAppOwnedRepairManifest.NewTables(database).Contains(x.TargetTable, StringComparer.Ordinal)))
            {
                Assert.Contains($"CREATE TABLE public.\"{table.TargetTable}\"", sql, StringComparison.Ordinal);
                Assert.Contains($"CONSTRAINT \"{table.PrimaryKey!.Name}\"", sql, StringComparison.Ordinal);
                foreach (string column in table.Collations.Keys)
                { Assert.Contains($"\"{column}\" {table.ColumnTypes[column]} COLLATE \"C\"", sql, StringComparison.Ordinal); }
            }
        }
    }

    [Fact]
    public void Retained_operands_are_exact31_unique_and_defensive_with_two_mapped_outcome_fields()
    {
        CurrentAppOwnedCollationOperand[] first = CurrentAppOwnedRepairManifest.RetainedOperands();
        Assert.Equal(31, first.Length);
        Assert.Equal(31, first.Select(x => $"{x.Database}/{x.Schema}/{x.Table}/{x.Column}").Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(2, first.Count(x => x.Database == "Quotation" && x.Table == "QuotationAcceptedOutcome"));
        Assert.Equal(6, first.Select(x => $"{x.Database}/{x.Table}").Distinct(StringComparer.Ordinal).Count());
        first[0] = first[0] with { Column = "Unapproved" };
        Assert.DoesNotContain(CurrentAppOwnedRepairManifest.RetainedOperands(), x => x.Column == "Unapproved");
        foreach (string database in CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations))
        {
            string sql = CurrentAppOwnedRepairManifest.CollationSql(database);
            Assert.DoesNotContain("UPDATE", sql, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("DELETE", sql, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("USING", sql, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void Creation_classification_rejects_partial_extra_duplicate_and_case_changes()
    {
        foreach (string database in CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.CreateEightTables))
        {
            string[] names = CurrentAppOwnedRepairManifest.NewTables(database);
            Assert.Equal(CurrentAppOwnedCreationState.MissingExactSet, CurrentAppOwnedRepairPreflight.ClassifyInventory(database, []));
            Assert.Equal(CurrentAppOwnedCreationState.AlreadyCurrent, CurrentAppOwnedRepairPreflight.ClassifyInventory(database, names));
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairPreflight.ClassifyInventory(database, [.. names, "Unapproved"]));
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairPreflight.ClassifyInventory(database, [.. names, names[0]]));
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairPreflight.ClassifyInventory(database, [.. names.Select(x => x.ToLowerInvariant())]));
            if (names.Length > 1)
            { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairPreflight.ClassifyInventory(database, [.. names.Skip(1)])); }
        }
    }

    [Fact]
    public void Complete_schema_pair_requires_V1_to_V2_identical_source_contracts()
    {
        FreshSchemaPlan before = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerColumnsV1);
        FreshSchemaPlan after = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2);
        CurrentAppOwnedRepairManifest.RequireSchemaPair(before, after, before.CapturedAtUtc);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairManifest.RequireSchemaPair(after, before, before.CapturedAtUtc));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairManifest.RequireSchemaPair(before, after with { SourceCommitSha = new string('b', 40) }, before.CapturedAtUtc));
        DatabaseSchemaPlan first = after.Databases[0];
        FreshSchemaPlan wrongSource = after with { Databases = [first with { SourceSchemaSha256 = new string('e', 64) }, .. after.Databases.Skip(1)] };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairManifest.RequireSchemaPair(before, wrongSource, before.CapturedAtUtc));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairManifest.RequireSchemaPair(before, after, before.CapturedAtUtc.AddHours(3)));
    }
}