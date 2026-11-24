using System.Data;
using Npgsql;
using Xunit.Abstractions;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(CompanyStoragePreservationTestGroup.Name)]
public sealed class CustomerCompanyStorageNativePreservationTests(CompanyStoragePreservationFixture fixture, ITestOutputHelper output)
{
    private static readonly string[] RelationHintFields = ["relallvisible", "relallfrozen", "reltuples"];
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Fixed_candidate_native_transition(bool indexed, bool analyzed)
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync("Customer",
            $"legacy_shadow_company_native_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), default);
        string connectionString = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        { Database = shadow.Name, Pooling = false }.ConnectionString;
        DatabaseSchemaPlan before = CustomerCompanyStorageRepairContractTests.Before();
        if (indexed)
        {
            before = before with
            {
                Tables = [before.Tables[0] with
            { Indexes = [new("IX_Company_Name", ["Name"], false), new("IX_Company_TaxNumber", ["TaxNumber"], false)] }]
            };
        }
        before = before with
        {
            Tables = [.. before.Tables, new TableCopyPlan("dbo", "Unrelated", "public", "Unrelated", ["ID", "Payload"], ["ID"])
            {
                ColumnTypes = new Dictionary<string, string> { ["ID"] = "integer", ["Payload"] = "text" },
                PrimaryKey = new("PK_Unrelated", ["ID"]), NullableColumns = ["Payload"],
            }],
        };
        before = before with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(before) };
        var contract = CustomerCompanyStorageRepairContractTests.Create(before, CustomerCompanyStorageRepairContractTests.Owner());
        try
        {
            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync();
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable))
            {
                await using var seed = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                await seed.ApplySchemaAsync(before, default);
                await seed.FinalizeSchemaAsync(before, default);
                await ExecuteAsync(connection, transaction, """
                    INSERT INTO public."Company" ("ID","Name","TaxNumber","Registrar") VALUES
                        (100,'synthetic name  ','synthetic tax  ',NULL),(101,repeat('😀',128),NULL,'synthetic registrar');
                    INSERT INTO public."Unrelated" VALUES (1,'synthetic unrelated  ');
                    CREATE SCHEMA legacy_migration_internal;
                    CREATE TABLE legacy_migration_internal."Journal" ("ID" integer PRIMARY KEY,"Payload" text);
                    INSERT INTO legacy_migration_internal."Journal" VALUES (1,'synthetic private  ');
                    """);
                await transaction.CommitAsync();
            }
            // Stabilize fixture index statistics before the immutable baseline, including REINDEX probe inputs.
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable))
            {
                await ExecuteAsync(connection, transaction, """
                    ANALYZE public."Company" ("ID");
                    ANALYZE public."Unrelated";
                    ANALYZE legacy_migration_internal."Journal";
                    """);
                if (analyzed) { await ExecuteAsync(connection, transaction, """ANALYZE public."Company";"""); }
                await transaction.CommitAsync();
            }
            CustomerCompanyStorageNativePreservation.Observation old;
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable))
            {
                old = await CustomerCompanyStorageNativePreservation.CaptureAsync(connection, transaction, contract, false, default);
                await ExecuteAsync(connection, transaction, ApprovedCustomerCompanyStorageRepair.CandidateSql);
                var changed = await CustomerCompanyStorageNativePreservation.CaptureAsync(connection, transaction, contract, true, default);
                ReportChangedSystemIndexStorage(old.Native, changed.Native);
                CustomerCompanyStorageNativePreservation.RequirePreserved(old, changed, contract);
                await transaction.RollbackAsync();
            }
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable))
            {
                var rollback = await CustomerCompanyStorageNativePreservation.CaptureAsync(connection, transaction, contract, false, default);
                Assert.Equal(old.Native.Snapshot.Sha256, rollback.Native.Snapshot.Sha256);
                await transaction.RollbackAsync();
            }
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable))
            {
                var current = await CustomerCompanyStorageNativePreservation.CaptureAsync(connection, transaction, contract, false, default);
                if (old.Native.Snapshot.Sha256 != current.Native.Snapshot.Sha256)
                { ReportSnapshotDifference(old.Native, current.Native); }
                Assert.Equal(old.Native.Snapshot.Sha256, current.Native.Snapshot.Sha256);
                await ExecuteAsync(connection, transaction, ApprovedCustomerCompanyStorageRepair.CandidateSql);
                var changed = await CustomerCompanyStorageNativePreservation.CaptureAsync(connection, transaction, contract, true, default);
                CustomerCompanyStorageNativePreservation.RequirePreserved(old, changed, contract);
                await transaction.CommitAsync();
            }
            await connection.CloseAsync();
            await using var readback = new NpgsqlConnection(connectionString);
            await readback.OpenAsync();
            await using (var transaction = await readback.BeginTransactionAsync(IsolationLevel.RepeatableRead))
            {
                var changed = await CustomerCompanyStorageNativePreservation.CaptureAsync(readback, transaction, contract, true, default);
                CustomerCompanyStorageNativePreservation.RequirePreserved(old, changed, contract);
                await transaction.RollbackAsync();
            }
            string role = "company_native_probe_" + Guid.NewGuid().ToString("N");
            string[] mutations =
            [
                """ALTER TABLE legacy_migration_internal."Journal" ADD COLUMN "Unexpected" text;""",
                """CREATE INDEX "UnexpectedIndex" ON public."Unrelated" ("Payload");""",
                """ALTER TABLE public."Company" ADD CONSTRAINT "UnexpectedCheck" CHECK ("ID">0);""",
                """ALTER FUNCTION public."NormalizeCompanySource"() DEPENDS ON EXTENSION plpgsql;""",
                $"CREATE ROLE \"{role}\" NOLOGIN;",
                """CREATE FUNCTION public."UnexpectedFunction"() RETURNS integer LANGUAGE sql AS 'SELECT 1';""",
                """UPDATE public."Company" SET "Name"='changed' WHERE "ID"=100;""",
                """UPDATE legacy_migration_internal."Journal" SET "Payload"='changed' WHERE "ID"=1;""",
                """ALTER SEQUENCE public."Company_ID_seq" INCREMENT BY 2;""",
                """DELETE FROM pg_catalog.pg_statistic WHERE starelid='public."Unrelated"'::regclass AND staattnum=1;""",
                """UPDATE pg_catalog.pg_statistic SET stadistinct=stadistinct+1.25 WHERE starelid='public."Unrelated"'::regclass AND staattnum=1;""",
            ];
            if (indexed)
            {
                mutations = [.. mutations, """REINDEX INDEX public."IX_Company_Name";""",
                    """ALTER INDEX public."IX_Company_Name" SET (fillfactor=60);"""];
            }
            mutations = [.. mutations, """CREATE STATISTICS public."UnexpectedCompanyStatistics" ON "Name","TaxNumber" FROM public."Company";"""];
            int probeOrdinal = 0;
            foreach (string mutation in mutations)
            {
                await using var transaction = await readback.BeginTransactionAsync(IsolationLevel.Serializable);
                output.WriteLine($"PROBE-ADMISSION ordinal={probeOrdinal++}");
                var probeBefore = await CustomerCompanyStorageNativePreservation.CaptureAsync(readback, transaction, contract, true, default);
                try { CustomerCompanyStorageNativePreservation.RequirePreserved(old, probeBefore, contract); }
                catch (MigrationExecutionException)
                {
                    ReportRelationHintDifferences(old.Native, probeBefore.Native);
                    throw;
                }
                await ExecuteAsync(readback, transaction, mutation);
                _ = await Assert.ThrowsAnyAsync<MigrationExecutionException>(async () =>
                {
                    var changed = await CustomerCompanyStorageNativePreservation.CaptureAsync(readback, transaction, contract, true, default);
                    CustomerCompanyStorageNativePreservation.RequirePreserved(old, changed, contract);
                });
                await transaction.RollbackAsync();
            }
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, default); }
    }

    [Fact]
    public async Task Recreated_operand_statistics_are_rejected_in_an_isolated_indexed_fixture()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync("Customer",
            $"legacy_shadow_analyze_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), default);
        string connectionString = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        { Database = shadow.Name, Pooling = false }.ConnectionString;
        DatabaseSchemaPlan before = CustomerCompanyStorageRepairContractTests.Before();
        before = before with
        {
            Tables = [before.Tables[0] with
        { Indexes = [new("IX_Company_Name", ["Name"], false), new("IX_Company_TaxNumber", ["TaxNumber"], false)] }]
        };
        before = before with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(before) };
        var contract = CustomerCompanyStorageRepairContractTests.Create(before, CustomerCompanyStorageRepairContractTests.Owner());
        try
        {
            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync();
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable))
            {
                await using var seed = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                await seed.ApplySchemaAsync(before, default);
                await seed.FinalizeSchemaAsync(before, default);
                await ExecuteAsync(connection, transaction, """
                    INSERT INTO public."Company" ("ID","Name","TaxNumber","Registrar") VALUES
                        (100,'synthetic name','synthetic tax','synthetic registrar'),
                        (101,'second name','second tax','second registrar');
                    ANALYZE public."Company" ("ID");
                    """);
                await transaction.CommitAsync();
            }
            CustomerCompanyStorageNativePreservation.Observation original;
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable))
            {
                original = await CustomerCompanyStorageNativePreservation.CaptureAsync(connection, transaction, contract, false, default);
                await ExecuteAsync(connection, transaction, ApprovedCustomerCompanyStorageRepair.CandidateSql);
                var corrected = await CustomerCompanyStorageNativePreservation.CaptureAsync(connection, transaction, contract, true, default);
                CustomerCompanyStorageNativePreservation.RequirePreserved(original, corrected, contract);
                await transaction.CommitAsync();
            }
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable))
            {
                var admitted = await CustomerCompanyStorageNativePreservation.CaptureAsync(connection, transaction, contract, true, default);
                CustomerCompanyStorageNativePreservation.RequirePreserved(original, admitted, contract);
                await ExecuteAsync(connection, transaction, """ANALYZE public."Company";""");
                MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(async () =>
                {
                    _ = await CustomerCompanyStorageNativePreservation.CaptureAsync(connection, transaction, contract, true, default);
                });
                Assert.Equal("customer_company_native_preservation_operand_statistics", failure.Code);
                await transaction.RollbackAsync();
            }
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, default); }
    }

    [Fact]
    public async Task Analyzed_fixture_characterizes_only_three_ordinary_operand_statistics_removals()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync("Customer",
            $"legacy_shadow_company_stats_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), default);
        string connectionString = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        { Database = shadow.Name, Pooling = false }.ConnectionString;
        DatabaseSchemaPlan before = CustomerCompanyStorageRepairContractTests.Before();
        before = before with
        {
            Tables = [.. before.Tables, new TableCopyPlan("dbo", "Unrelated", "public", "Unrelated", ["ID", "Payload"], ["ID"])
            {
                ColumnTypes = new Dictionary<string, string> { ["ID"] = "integer", ["Payload"] = "text" },
                PrimaryKey = new("PK_Unrelated", ["ID"]), NullableColumns = ["Payload"],
            }],
        };
        before = before with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(before) };
        var contract = CustomerCompanyStorageRepairContractTests.Create(before, CustomerCompanyStorageRepairContractTests.Owner());
        try
        {
            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync();
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable))
            {
                await using var seed = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                await seed.ApplySchemaAsync(before, default);
                await seed.FinalizeSchemaAsync(before, default);
                await ExecuteAsync(connection, transaction, """
                    INSERT INTO public."Company" ("ID","Name","TaxNumber","Registrar") VALUES
                        (100,'synthetic name  ','synthetic tax  ','synthetic registrar  '),
                        (101,'second name','second tax','second registrar'),(102,repeat('😀',128),NULL,NULL);
                    INSERT INTO public."Unrelated" VALUES (1,'synthetic unrelated'),(2,'second unrelated');
                    CREATE SCHEMA legacy_migration_internal;
                    CREATE TABLE legacy_migration_internal."Journal" ("ID" integer PRIMARY KEY,"Payload" text);
                    INSERT INTO legacy_migration_internal."Journal" VALUES (1,'synthetic journal'),(2,'second journal');
                    ANALYZE public."Company";
                    ANALYZE public."Unrelated";
                    ANALYZE legacy_migration_internal."Journal";
                    """);
                await transaction.CommitAsync();
            }
            CurrentAppOwnedRetained31Observation baseline;
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable))
            {
                // Generic capture is used only to characterize the disposable fixture; the persistent-facing guard is untouched.
                baseline = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, default);
                await ExecuteAsync(connection, transaction, ApprovedCustomerCompanyStorageRepair.CandidateSql);
                var candidate = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, default);
                RequireStatisticsCharacterization(baseline, candidate);
                ReportSnapshotDifference(baseline, candidate);
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                Assert.Equal(contract.After().TargetSchemaSha256, await inspector.InspectSchemaAsync(contract.After(), default));
                await transaction.RollbackAsync();
            }
            await using (var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable))
            {
                var restored = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, default);
                Assert.Equal(baseline.Snapshot.Sha256, restored.Snapshot.Sha256);
                await ExecuteAsync(connection, transaction, ApprovedCustomerCompanyStorageRepair.CandidateSql);
                var candidate = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, default);
                RequireStatisticsCharacterization(baseline, candidate);
                await transaction.CommitAsync();
            }
            await connection.CloseAsync();
            await using var readback = new NpgsqlConnection(connectionString);
            await readback.OpenAsync();
            await using (var transaction = await readback.BeginTransactionAsync(IsolationLevel.RepeatableRead))
            {
                var committed = await CurrentAppOwnedRetained31Preservation.CaptureAsync(readback, transaction, default);
                RequireStatisticsCharacterization(baseline, committed);
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(readback, transaction, ownsResources: false);
                Assert.Equal(contract.After().TargetSchemaSha256, await inspector.InspectSchemaAsync(contract.After(), default));
                await transaction.RollbackAsync();
            }
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, default); }
    }

    private static void RequireStatisticsCharacterization(CurrentAppOwnedRetained31Observation before, CurrentAppOwnedRetained31Observation after)
    {
        string table = before.Read("pg_class").Single(x => x["relname"]!.ToString() == "Company")["oid"]!.ToString();
        var columns = before.Read("pg_attribute").Where(x => x["attrelid"]!.ToString() == table &&
            x["attname"]!.ToString() is "Name" or "TaxNumber" or "Registrar").ToDictionary(
                x => x["attnum"]!.ToString(), x => x["attname"]!.ToString(), StringComparer.Ordinal);
        Assert.Equal(3, columns.Count);
        var oldStatistics = before.Read("pg_statistic");
        var newStatistics = after.Read("pg_statistic");
        foreach (string number in columns.Keys)
        {
            var row = Assert.Single(oldStatistics, x => x["starelid"]!.ToString() == table && x["staattnum"]!.ToString() == number);
            Assert.False(row["stainherit"]!.GetValue<bool>());
            Assert.DoesNotContain(newStatistics, x => x["starelid"]!.ToString() == table && x["staattnum"]!.ToString() == number);
        }
        string[] expected = [.. oldStatistics.Where(x => x["starelid"]!.ToString() != table ||
            !columns.ContainsKey(x["staattnum"]!.ToString())).Select(CatalogCanonical).Order(StringComparer.Ordinal)];
        Assert.NotEmpty(expected);
        Assert.Equal(expected, newStatistics.Select(CatalogCanonical).Order(StringComparer.Ordinal));
        Assert.Equal(before.Snapshot.Relations, after.Snapshot.Relations);
        Assert.Equal(before.Snapshot.Sequences, after.Snapshot.Sequences);
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        _ = await command.ExecuteNonQueryAsync();
    }

    private void ReportRelationHintDifferences(CurrentAppOwnedRetained31Observation before, CurrentAppOwnedRetained31Observation after)
    {
        var namespaces = before.Read("pg_namespace").ToDictionary(x => x["oid"]!.ToString(), x => x["nspname"]!.ToString(), StringComparer.Ordinal);
        var current = after.Read("pg_class").ToDictionary(x => x["oid"]!.ToString(), StringComparer.Ordinal);
        foreach (var relation in before.Read("pg_class"))
        {
            string id = relation["oid"]!.ToString();
            if (!current.TryGetValue(id, out var observed)) { continue; }
            foreach (string field in RelationHintFields)
            {
                if (System.Text.Json.Nodes.JsonNode.DeepEquals(relation[field], observed[field])) { continue; }
                output.WriteLine($"RELATION-HINT schema={namespaces[relation["relnamespace"]!.ToString()]}; " +
                    $"table={relation["relname"]}; oid={id}; field={field}; before={relation[field]}; after={observed[field]}");
            }
        }
    }

    private void ReportChangedSystemIndexStorage(CurrentAppOwnedRetained31Observation before, CurrentAppOwnedRetained31Observation after)
    {
        string catalog = before.Read("pg_namespace").Single(x => x["nspname"]!.ToString() == "pg_catalog")["oid"]!.ToString();
        var oldClasses = before.Read("pg_class").ToDictionary(x => x["oid"]!.ToString(), StringComparer.Ordinal);
        var newClasses = after.Read("pg_class").ToDictionary(x => x["oid"]!.ToString(), StringComparer.Ordinal);
        foreach (var index in before.Read("pg_index"))
        {
            string oid = index["indexrelid"]!.ToString();
            var oldClass = oldClasses[oid];
            var table = oldClasses[index["indrelid"]!.ToString()];
            if (oldClass["relnamespace"]!.ToString() != catalog || table["relnamespace"]!.ToString() != catalog)
            { continue; }
            var oldStorage = before.Storage(oid);
            var newStorage = after.Storage(oid);
            if (oldStorage == newStorage) { continue; }
            var newClass = newClasses[oid];
            output.WriteLine(
                $"SYSTEM-INDEX parent={table["relname"]}; parentOid={table["oid"]}; index={oldClass["relname"]}; indexOid={oid}; " +
                $"catalogFileBefore={oldClass["relfilenode"]}; catalogFileAfter={newClass["relfilenode"]}; " +
                $"physicalFileBefore={oldStorage.FileNode}; physicalFileAfter={newStorage.FileNode}; " +
                $"blocksBefore={oldStorage.Blocks}; blocksAfter={newStorage.Blocks}");
        }
    }

    private void ReportSnapshotDifference(CurrentAppOwnedRetained31Observation before, CurrentAppOwnedRetained31Observation after)
    {
        foreach (string catalog in before.Snapshot.Catalog.Concat(after.Snapshot.Catalog).Select(x => x.Catalog).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            string[] expected = [.. before.Read(catalog).Select(CatalogCanonical).Order(StringComparer.Ordinal)];
            string[] observed = [.. after.Read(catalog).Select(CatalogCanonical).Order(StringComparer.Ordinal)];
            if (expected.SequenceEqual(observed, StringComparer.Ordinal)) { continue; }
            string[] removed = [.. expected.Except(observed, StringComparer.Ordinal)];
            string[] added = [.. observed.Except(expected, StringComparer.Ordinal)];
            output.WriteLine($"SNAPSHOT-DIFF catalog={catalog}; beforeHash={CatalogDigest(expected)}; afterHash={CatalogDigest(observed)}; removed={removed.Length}; added={added.Length}");
            foreach (string row in removed.Take(16))
            {
                var left = System.Text.Json.Nodes.JsonNode.Parse(row)!.AsObject();
                var right = added.Select(x => System.Text.Json.Nodes.JsonNode.Parse(x)!.AsObject()).FirstOrDefault(x =>
                    (left["oid"] is not null && System.Text.Json.Nodes.JsonNode.DeepEquals(left["oid"], x["oid"])) ||
                    (left["attrelid"] is not null && System.Text.Json.Nodes.JsonNode.DeepEquals(left["attrelid"], x["attrelid"]) &&
                        System.Text.Json.Nodes.JsonNode.DeepEquals(left["attnum"], x["attnum"])));
                string fields = right is null ? "tuple-membership" : string.Join(',', left.Where(x =>
                    !System.Text.Json.Nodes.JsonNode.DeepEquals(x.Value, right[x.Key])).Select(x => x.Key));
                output.WriteLine($"SNAPSHOT-FACET catalog={catalog}; fields={fields}");
            }
        }
        foreach (var relation in before.Snapshot.Relations)
        {
            var current = after.Snapshot.Relations.SingleOrDefault(x => x.Schema == relation.Schema && x.Name == relation.Name);
            if (current != relation)
            {
                output.WriteLine($"SNAPSHOT-RELATION synthetic={relation.Schema}.{relation.Name}; beforeRows={relation.Rows}; afterRows={current?.Rows}; beforeDigest={relation.RowSha256}; afterDigest={current?.RowSha256}");
            }
        }
        foreach (var sequence in before.Snapshot.Sequences)
        {
            var current = after.Snapshot.Sequences.SingleOrDefault(x => x.Schema == sequence.Schema && x.Name == sequence.Name);
            if (current != sequence)
            {
                output.WriteLine($"SNAPSHOT-SEQUENCE synthetic={sequence.Schema}.{sequence.Name}; beforeDigest={sequence.TupleSha256}; afterDigest={current?.TupleSha256}; ownerChanged={current?.Owner != sequence.Owner}");
            }
        }
    }

    private static string CatalogCanonical(System.Text.Json.Nodes.JsonObject row)
    {
        return new System.Text.Json.Nodes.JsonObject(
        row.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new KeyValuePair<string, System.Text.Json.Nodes.JsonNode?>(x.Key, x.Value?.DeepClone()))).ToJsonString();
    }

    private static string CatalogDigest(string[] rows)
    {
        return Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
        System.Text.Encoding.UTF8.GetBytes(string.Join('\n', rows))));
    }
}

public sealed class CustomerCompanyStorageNativePreservationStatisticsTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    public void Before_accepts_zero_or_one_ordinary_row_for_each_bound_operand(int count)
    {
        var rows = Enumerable.Range(2, count).Select(number => new System.Text.Json.Nodes.JsonObject
        {
            ["starelid"] = "100",
            ["staattnum"] = number,
            ["stainherit"] = false,
        }).ToArray();
        CustomerCompanyStorageNativePreservation.RequireOperandStatistics(rows, "100", new HashSet<int> { 2, 3, 4 }, false);
        CustomerCompanyStorageNativePreservation.RequireOperandStatistics([], "100", new HashSet<int> { 2, 3, 4 }, true);
    }

    [Theory]
    [InlineData("inherited")]
    [InlineData("duplicate")]
    [InlineData("after-recreated")]
    public void Unsupported_or_recreated_operand_statistics_fail_closed(string fault)
    {
        var row = new System.Text.Json.Nodes.JsonObject
        { ["starelid"] = "100", ["staattnum"] = 2, ["stainherit"] = fault == "inherited" };
        System.Text.Json.Nodes.JsonObject[] rows = fault == "duplicate" ? [row, row.DeepClone().AsObject()] : [row];
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerCompanyStorageNativePreservation.RequireOperandStatistics(
            rows, "100", new HashSet<int> { 2, 3, 4 }, fault == "after-recreated"));
    }
}

public sealed class CustomerCompanyStorageNativePreservationTriggerStorageTests
{
    [Theory]
    [InlineData("pg_trigger_tgconstraint_index", "2699", 0)]
    [InlineData("pg_trigger_tgconstraint_index", "2699", 1)]
    [InlineData("pg_trigger_tgrelid_tgname_index", "2701", 0)]
    [InlineData("pg_trigger_tgrelid_tgname_index", "2701", 1)]
    [InlineData("pg_trigger_oid_index", "2702", 0)]
    [InlineData("pg_trigger_oid_index", "2702", 1)]
    public void Only_reviewed_trigger_btrees_accept_zero_or_one_block(string name, string oid, int growth)
    {
        Probe(name, oid, growth, null);
    }

    [Theory]
    [InlineData("catalog-name")]
    [InlineData("catalog-oid")]
    [InlineData("table-name")]
    [InlineData("table-oid")]
    [InlineData("index-name")]
    [InlineData("index-oid")]
    [InlineData("index-namespace")]
    [InlineData("index-am")]
    [InlineData("index-table-binding")]
    [InlineData("file")]
    [InlineData("catalog-file")]
    [InlineData("mapped-file")]
    [InlineData("shrink")]
    [InlineData("growth")]
    [InlineData("missing-trigger")]
    [InlineData("extra-trigger")]
    [InlineData("trigger-identity")]
    [InlineData("trigger-name")]
    [InlineData("existing-trigger")]
    [InlineData("other-trigger-changed")]
    [InlineData("class-metadata")]
    [InlineData("index-metadata")]
    [InlineData("index-validity")]
    public void Every_unreviewed_trigger_index_or_insertion_fails_closed(string fault)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => Probe("pg_trigger_tgconstraint_index", "2699", 1, fault));
    }

    private static void Probe(string name, string oid, int growth, string? fault)
    {
        var ns = new System.Text.Json.Nodes.JsonObject { ["oid"] = "11", ["nspname"] = "pg_catalog" };
        var table = new System.Text.Json.Nodes.JsonObject { ["oid"] = "2620", ["relname"] = "pg_trigger", ["relnamespace"] = "11" };
        var beforeClass = new System.Text.Json.Nodes.JsonObject
        {
            ["oid"] = oid,
            ["relname"] = name,
            ["relnamespace"] = "11",
            ["relkind"] = "i",
            ["relam"] = "403",
            ["relfilenode"] = oid,
            ["relowner"] = "10",
            ["relacl"] = null,
        };
        var afterClass = beforeClass.DeepClone().AsObject();
        var beforeIndex = new System.Text.Json.Nodes.JsonObject
        {
            ["indexrelid"] = oid,
            ["indrelid"] = "2620",
            ["indisvalid"] = true,
            ["indisready"] = true,
            ["indislive"] = true,
        };
        var afterIndex = beforeIndex.DeepClone().AsObject();
        var oldTrigger = new System.Text.Json.Nodes.JsonObject { ["oid"] = "1000", ["tgname"] = "unchanged" };
        var reviewed = new System.Text.Json.Nodes.JsonObject { ["oid"] = "20000", ["tgname"] = "NormalizeCompanySource" };
        System.Text.Json.Nodes.JsonObject[] beforeTriggers = [oldTrigger];
        System.Text.Json.Nodes.JsonObject[] afterTriggers = [oldTrigger.DeepClone().AsObject(), reviewed.DeepClone().AsObject()];
        uint file = uint.Parse(oid, System.Globalization.CultureInfo.InvariantCulture);
        (uint FileNode, long Blocks) beforeStorage = (file, 1), afterStorage = (file, 1 + growth);
        switch (fault)
        {
            case "catalog-name": ns["nspname"] = "public"; break;
            case "catalog-oid": ns["oid"] = "2200"; break;
            case "table-name": table["relname"] = "pg_proc"; break;
            case "table-oid": table["oid"] = "1255"; break;
            case "index-name": beforeClass["relname"] = "pg_trigger_other_index"; break;
            case "index-oid": beforeClass["oid"] = "2701"; break;
            case "index-namespace": beforeClass["relnamespace"] = "2200"; break;
            case "index-am": beforeClass["relam"] = "405"; break;
            case "index-table-binding": beforeIndex["indrelid"] = "1255"; break;
            case "file": afterStorage = (file + 1, 2); break;
            case "catalog-file": beforeClass["relfilenode"] = "9999"; break;
            case "mapped-file": beforeClass["relfilenode"] = "0"; break;
            case "shrink": afterStorage = (file, 0); break;
            case "growth": afterStorage = (file, 3); break;
            case "missing-trigger": afterTriggers = [oldTrigger.DeepClone().AsObject()]; break;
            case "extra-trigger": afterTriggers = [.. afterTriggers, new System.Text.Json.Nodes.JsonObject { ["oid"] = "30000", ["tgname"] = "unexpected" }]; break;
            case "trigger-identity": reviewed["oid"] = "20001"; break;
            case "trigger-name": reviewed["tgname"] = "Unexpected"; break;
            case "existing-trigger": oldTrigger["oid"] = "20000"; break;
            case "other-trigger-changed": afterTriggers[0]["tgname"] = "changed"; break;
            case "class-metadata": afterClass["relowner"] = "20"; break;
            case "index-metadata": afterIndex["indisready"] = false; break;
            case "index-validity": beforeIndex["indisvalid"] = false; break;
            default:
                break;
        }
        CustomerCompanyStorageNativePreservation.RequireTriggerIndexStorage(ns, table,
            beforeClass, afterClass, beforeIndex, afterIndex, beforeStorage, afterStorage,
            beforeTriggers, afterTriggers, reviewed, "20000");
    }
}

public sealed class CustomerCompanyStorageNativePreservationStorageTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void Only_exact_reviewed_procedure_index_can_keep_file_with_zero_or_one_new_block(int growth)
    {
        Probe(growth, null);
    }

    [Theory]
    [InlineData("catalog-name")]
    [InlineData("catalog-oid")]
    [InlineData("table-name")]
    [InlineData("table-oid")]
    [InlineData("index-name")]
    [InlineData("index-oid")]
    [InlineData("index-namespace")]
    [InlineData("index-am")]
    [InlineData("index-table-binding")]
    [InlineData("file")]
    [InlineData("mapped-catalog-file")]
    [InlineData("shrink")]
    [InlineData("growth")]
    [InlineData("function-count")]
    [InlineData("function-identity")]
    [InlineData("function-name")]
    [InlineData("other-function-changed")]
    [InlineData("class-metadata")]
    [InlineData("index-metadata")]
    [InlineData("index-validity")]
    public void Every_other_storage_or_logical_facet_fails_closed(string fault)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => Probe(1, fault));
    }

    private static void Probe(int growth, string? fault)
    {
        var ns = new System.Text.Json.Nodes.JsonObject { ["oid"] = "11", ["nspname"] = "pg_catalog" };
        var table = new System.Text.Json.Nodes.JsonObject { ["oid"] = "1255", ["relname"] = "pg_proc", ["relnamespace"] = "11" };
        var beforeClass = new System.Text.Json.Nodes.JsonObject
        {
            ["oid"] = "2691",
            ["relname"] = "pg_proc_proname_args_nsp_index",
            ["relnamespace"] = "11",
            ["relkind"] = "i",
            ["relam"] = "403",
            ["relfilenode"] = "0",
            ["relowner"] = "10",
            ["relpages"] = 32,
            ["relacl"] = null,
        };
        var afterClass = beforeClass.DeepClone().AsObject();
        var beforeIndex = new System.Text.Json.Nodes.JsonObject
        {
            ["indexrelid"] = "2691",
            ["indrelid"] = "1255",
            ["indisvalid"] = true,
            ["indisready"] = true,
            ["indislive"] = true,
            ["indisunique"] = true,
        };
        var afterIndex = beforeIndex.DeepClone().AsObject();
        var oldFunction = new System.Text.Json.Nodes.JsonObject { ["oid"] = "1000", ["proname"] = "unchanged" };
        var reviewed = new System.Text.Json.Nodes.JsonObject { ["oid"] = "20000", ["proname"] = "NormalizeCompanySource" };
        System.Text.Json.Nodes.JsonObject[] beforeFunctions = [oldFunction];
        System.Text.Json.Nodes.JsonObject[] afterFunctions = [oldFunction.DeepClone().AsObject(), reviewed.DeepClone().AsObject()];
        (uint FileNode, long Blocks) beforeStorage = (2691, 33), afterStorage = (2691, 33 + growth);
        switch (fault)
        {
            case "catalog-name": ns["nspname"] = "public"; break;
            case "catalog-oid": ns["oid"] = "2200"; break;
            case "table-name": table["relname"] = "pg_trigger"; break;
            case "table-oid": table["oid"] = "2620"; break;
            case "index-name": beforeClass["relname"] = "pg_proc_oid_index"; break;
            case "index-oid": beforeClass["oid"] = "2692"; break;
            case "index-namespace": beforeClass["relnamespace"] = "2200"; break;
            case "index-am": beforeClass["relam"] = "405"; break;
            case "index-table-binding": beforeIndex["indrelid"] = "2620"; break;
            case "file": afterStorage = (2692, 34); break;
            case "mapped-catalog-file": beforeClass["relfilenode"] = "2691"; break;
            case "shrink": afterStorage = (2691, 32); break;
            case "growth": afterStorage = (2691, 35); break;
            case "function-count": afterFunctions = [oldFunction.DeepClone().AsObject()]; break;
            case "function-identity": reviewed["oid"] = "20001"; break;
            case "function-name": reviewed["proname"] = "Unexpected"; break;
            case "other-function-changed": afterFunctions[0]["proname"] = "changed"; break;
            case "class-metadata": afterClass["relowner"] = "20"; break;
            case "index-metadata": afterIndex["indisunique"] = false; break;
            case "index-validity": beforeIndex["indisvalid"] = false; break;
            default:
                break;
        }
        CustomerCompanyStorageNativePreservation.RequireProcedureIndexStorage(ns, table,
            beforeClass, afterClass, beforeIndex, afterIndex, beforeStorage, afterStorage,
            beforeFunctions, afterFunctions, reviewed, "20000");
    }
}
