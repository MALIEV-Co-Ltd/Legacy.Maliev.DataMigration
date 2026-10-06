using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlPhysicalAdmissionTests(PostgreSqlAdapterFixture fixture)
{
    [Theory]
    [InlineData("unvalidated-check", "target_schema_unvalidated_check")]
    [InlineData("partitioned-relation", "target_schema_relation_unsupported")]
    [InlineData("rewrite-rule", "target_schema_rewrite_rule_unsupported")]
    [InlineData("nondefault-opclass", "target_schema_index_semantics_unsupported")]
    [InlineData("index-collation", "target_schema_index_semantics_unsupported")]
    public async Task UnsupportedPhysicalBehavior_IsRejectedBeforeFingerprintAdmission(string mutation, string code)
    {
        var plan = Plan(mutation is "nondefault-opclass" or "index-collation");
        var target = fixture.CreateShadowTarget();
        var shadow = await target.CreateUniqueEmptyShadowAsync("Invoice", $"legacy_shadow_physical_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), default);
        try
        {
            await using (var create = await target.BeginWholeDatabaseTransactionAsync(shadow, default))
            {
                await create.ApplySchemaAsync(plan, default);
                await create.FinalizeSchemaAsync(plan, default);
                Assert.Equal(plan.TargetSchemaSha256, await create.InspectSchemaAsync(plan, default));
                Assert.Equal(0, (await create.InspectTableAsync(plan.Tables[0], default)).RowCount);
                await create.CommitAsync(default);
            }

            var sql = mutation switch
            {
                "unvalidated-check" => "ALTER TABLE public.\"GuardSample\" DROP CONSTRAINT \"CK_GuardSample_Value\"; ALTER TABLE public.\"GuardSample\" ADD CONSTRAINT \"CK_GuardSample_Value\" CHECK (\"Value\" >= 0) NOT VALID;",
                "partitioned-relation" => "DROP TABLE public.\"GuardSample\"; CREATE TABLE public.\"GuardSample\" (\"ID\" integer NOT NULL, \"Value\" integer NOT NULL, \"Name\" character varying(64) NOT NULL, CONSTRAINT \"PK_GuardSample\" PRIMARY KEY (\"ID\"), CONSTRAINT \"CK_GuardSample_Value\" CHECK (\"Value\" >= 0)) PARTITION BY HASH (\"ID\");",
                "rewrite-rule" => "CREATE RULE discard_insert AS ON INSERT TO public.\"GuardSample\" DO INSTEAD NOTHING;",
                "nondefault-opclass" => "DROP INDEX public.\"IX_GuardSample_Name\"; CREATE UNIQUE INDEX \"IX_GuardSample_Name\" ON public.\"GuardSample\" (\"Name\" varchar_pattern_ops);",
                "index-collation" => "CREATE COLLATION public.guard_case_insensitive (provider = icu, locale = 'und-u-ks-level2', deterministic = false); DROP INDEX public.\"IX_GuardSample_Name\"; CREATE UNIQUE INDEX \"IX_GuardSample_Name\" ON public.\"GuardSample\" (\"Name\" COLLATE public.guard_case_insensitive);",
                _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
            };
            await ExecuteAsync(shadow, sql);
            await using var inspection = await target.BeginWholeDatabaseTransactionAsync(shadow, default);
            var failure = await Assert.ThrowsAsync<MigrationExecutionException>(async () =>
                await inspection.InspectSchemaAsync(plan, default));
            Assert.Equal(code, failure.Code);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, default);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OrdinaryReviewedSchema_PreservesExistingFingerprintAndNamedRowRoundtrip(bool uniqueIndex)
    {
        var plan = Plan(uniqueIndex);
        var target = fixture.CreateShadowTarget();
        var shadow = await target.CreateUniqueEmptyShadowAsync("Invoice", $"legacy_shadow_physical_control_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), default);
        try
        {
            await using (var create = await target.BeginWholeDatabaseTransactionAsync(shadow, default))
            {
                await create.ApplySchemaAsync(plan, default);
                await create.FinalizeSchemaAsync(plan, default);
                Assert.Equal(plan.TargetSchemaSha256, await create.InspectSchemaAsync(plan, default));
                Assert.Equal(0, (await create.InspectTableAsync(plan.Tables[0], default)).RowCount);
                await create.CommitAsync(default);
            }
            await ExecuteAsync(shadow, "INSERT INTO public.\"GuardSample\" (\"ID\", \"Value\", \"Name\") VALUES (1, 7, 'Thai ไทย');");
            await using var inspection = await target.BeginWholeDatabaseTransactionAsync(shadow, default);
            Assert.Equal(plan.TargetSchemaSha256, await inspection.InspectSchemaAsync(plan, default));
            Assert.Equal(1, (await inspection.InspectTableAsync(plan.Tables[0], default)).RowCount);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, default);
        }
    }

    private async Task ExecuteAsync(ShadowDatabase shadow, string sql)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString)
        {
            Database = shadow.Name,
        }.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static DatabaseSchemaPlan Plan(bool uniqueIndex)
    {
        var table = new TableCopyPlan("dbo", "GuardSample", "public", "GuardSample", ["ID", "Value", "Name"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ID"] = "integer",
                ["Value"] = "integer",
                ["Name"] = "character varying(64)",
            },
            PrimaryKey = new("PK_GuardSample", ["ID"]),
            CheckConstraints = [new("CK_GuardSample_Value", "\"Value\" >= 0") { Columns = ["Value"] }],
            Indexes = uniqueIndex ? [new("IX_GuardSample_Name", ["Name"], true)] : [],
        };
        var plan = new DatabaseSchemaPlan("Invoice", "1.0", new string('a', 64), new string('0', 64), [table]);
        return plan with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(plan) };
    }
}
