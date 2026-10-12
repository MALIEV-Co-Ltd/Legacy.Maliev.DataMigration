using System.Data;
using System.Text.Json.Nodes;
using Npgsql;
using Testcontainers.PostgreSql;
using Xunit.Abstractions;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAppOwnedRetained31NativeTests(ITestOutputHelper output)
{
    private readonly ITestOutputHelper _output = output;

    [Theory]
    [InlineData(2, 0, 25)]
    [InlineData(1, 1, 25)]
    [InlineData(1, 0, 1043)]
    public void Operand_VAR_requires_exact_relation_level_and_type(int relation, int level, int type)
    {
        string expression = $"{{VAR :varno {relation} :varattno 2 :vartype {type} :varlevelsup {level} :varcollid 100 :location -1}}";
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Preservation.NormalizeExpression(expression,
            new Dictionary<int, int> { [2] = 25 }, "100"));
    }

    [Fact]
    public void Operand_VAR_normalizes_only_bound_collation_and_location()
    {
        const string expression = "{VAR :varno 1 :varattno 2 :vartype 25 :varlevelsup 0 :varcollid 100 :location -1}";
        Assert.Equal("{VAR :varno 1 :varattno 2 :vartype 25 :varlevelsup 0 :varcollid @C :location @location}",
            CurrentAppOwnedRetained31Preservation.NormalizeExpression(expression, new Dictionary<int, int> { [2] = 25 }, "100"));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Preservation.NormalizeExpression(expression,
            new Dictionary<int, int> { [2] = 25 }, "950"));
    }

    [Fact]
    public void Input_collation_is_bound_and_numeric_result_stops_propagation()
    {
        const string operand = "{VAR :varno 1 :varattno 2 :vartype 25 :varlevelsup 0 :varcollid 100 :location -1}";
        var columns = new Dictionary<int, int> { [2] = 25 };
        string length = "{FUNCEXPR :funcid 1317 :funccollid 0 :inputcollid 100 :args (" + operand + ") :location -1}";
        string comparison = "{OPEXPR :opno 521 :opcollid 0 :inputcollid 0 :args (" + length + " {CONST :consttype 23 :constcollid 0 :constvalue 4 [ 0 0 0 0 ]}) :location -1}";
        string normalized = CurrentAppOwnedRetained31Preservation.NormalizeExpression(comparison, columns, "100");
        Assert.Contains(":opno 521 :opcollid 0 :inputcollid 0", normalized, StringComparison.Ordinal);
        Assert.Contains(":constvalue 4 [ 0 0 0 0 ]", normalized, StringComparison.Ordinal);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Preservation.NormalizeExpression(
            length.Replace(":inputcollid 100", ":inputcollid 950", StringComparison.Ordinal), columns, "100"));
    }

    [Fact]
    public void Rebuilt_index_requires_exact_physical_pages_and_complete_rows()
    {
        var row = new JsonObject { ["relfilenode"] = "42", ["relpages"] = "2", ["reltuples"] = "3" };
        CurrentAppOwnedRetained31Preservation.RequireIndexStorage(row, 42, 2, 3, rebuilt: true);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Preservation.RequireIndexStorage(row, 42, 3, 3, rebuilt: true));
        row["reltuples"] = "2";
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Preservation.RequireIndexStorage(row, 42, 2, 3, rebuilt: true));
    }

    [Theory]
    [InlineData(1043, -1, 2, false)]
    [InlineData(25, 0, 2, false)]
    [InlineData(25, -1, 1, false)]
    [InlineData(25, -1, 2, true)]
    public void Operand_relabel_rejects_wrong_result_type_typmod_or_display_form(int resultType, int typmod, int format, bool after)
    {
        string expression = $"{{RELABELTYPE :arg {{VAR :varno 1 :varattno 2 :vartype 1043 :varlevelsup 0 :varcollid 100 :location -1}} :resulttype {resultType} :resulttypmod {typmod} :resultcollid 100 :relabelformat {format} :location -1}}";
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Preservation.NormalizeExpression(expression,
            new Dictionary<int, int> { [2] = 1043 }, "100", after));
    }

    [Fact]
    public void Exact_operand_varchar_to_text_display_transition_is_preserved()
    {
        const string before = "{RELABELTYPE :arg {VAR :varno 1 :varattno 2 :vartype 1043 :varlevelsup 0 :varcollid 100 :location -1} :resulttype 25 :resulttypmod -1 :resultcollid 100 :relabelformat 2 :location -1}";
        string after = before.Replace("100", "950", StringComparison.Ordinal).Replace(":relabelformat 2", ":relabelformat 1", StringComparison.Ordinal);
        var columns = new Dictionary<int, int> { [2] = 1043 };
        Assert.Equal(CurrentAppOwnedRetained31Preservation.NormalizeExpression(before, columns, "100"),
            CurrentAppOwnedRetained31Preservation.NormalizeExpression(after, columns, "950", after: true));
    }

    [Fact]
    public void Exact_array_cast_rewrite_preserves_each_constant_datum_and_order()
    {
        var columns = new Dictionary<int, int> { [2] = 1043 };
        string before = CurrentAppOwnedRetained31Preservation.NormalizeExpression(ArrayComparison(after: false), columns, "100");
        string after = CurrentAppOwnedRetained31Preservation.NormalizeExpression(ArrayComparison(after: true), columns, "950", after: true);
        Assert.Equal(before, after);
        Assert.NotEqual(before, CurrentAppOwnedRetained31Preservation.NormalizeExpression(
            ArrayComparison(after: true).Replace("[ 65 ]", "[ 66 ]", StringComparison.Ordinal), columns, "950", after: true));
        Assert.NotEqual(before, CurrentAppOwnedRetained31Preservation.NormalizeExpression(
            ArrayComparison(after: true).Replace("[ 65 ]", "@swap", StringComparison.Ordinal).Replace("[ 67 ]", "[ 65 ]", StringComparison.Ordinal)
                .Replace("@swap", "[ 67 ]", StringComparison.Ordinal), columns, "950", after: true));
    }

    [Theory]
    [InlineData(":typeId 1043", ":typeId 25")]
    [InlineData(":coerceformat 2", ":coerceformat 1")]
    [InlineData(":constcollid 100", ":constcollid 950")]
    [InlineData(":multidims false", ":multidims true")]
    [InlineData(":elements (", ":elements (junk ")]
    public void Array_cast_rewrite_rejects_unproved_type_collation_form_or_list_changes(string oldText, string newText)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Preservation.NormalizeExpression(
            ArrayComparison(after: false).Replace(oldText, newText, StringComparison.Ordinal), new Dictionary<int, int> { [2] = 1043 }, "100"));
    }

    private static string ArrayComparison(bool after)
    {
        string collation = after ? "950" : "100";
        string operand = $"{{RELABELTYPE :arg {{VAR :varno 1 :varattno 2 :vartype 1043 :varlevelsup 0 :varcollid {collation} :location -1}} :resulttype 25 :resulttypmod -1 :resultcollid {collation} :relabelformat {(after ? 1 : 2)} :location -1}}";
        const string constant = "{CONST :consttype 1043 :consttypmod -1 :constcollid 100 :constlen -1 :constbyval false :constisnull false :location -1 :constvalue 1 [ 65 ]}";
        string elements = after ? "{RELABELTYPE :arg " + constant + " :resulttype 25 :resulttypmod -1 :resultcollid 100 :relabelformat 1 :location -1}" : constant;
        elements += " " + elements.Replace("[ 65 ]", "[ 67 ]", StringComparison.Ordinal);
        string array = $"{{ARRAYEXPR :array_typeid {(after ? 1009 : 1015)} :array_collid 100 :element_typeid {(after ? 25 : 1043)} :elements ({elements}) :multidims false :list_start -1 :list_end -1 :location -1}}";
        if (!after)
        { array = "{ARRAYCOERCEEXPR :arg " + array + " :elemexpr {RELABELTYPE :arg {CASETESTEXPR :typeId 1043 :typeMod -1 :collation 0} :resulttype 25 :resulttypmod -1 :resultcollid 100 :relabelformat 2 :location -1} :resulttype 1009 :resulttypmod -1 :resultcollid 100 :coerceformat 2 :location -1}"; }
        return "{SCALARARRAYOPEXPR :opno 98 :opfuncid 67 :hashfuncid 0 :negfuncid 0 :useOr true :inputcollid " + collation + " :args (" + operand + " " + array + ") :location -1}";
    }

    [Theory]
    [InlineData("0", "2", "3", 42u, 2L)]
    [InlineData("41", "2", "3", 42u, 2L)]
    [InlineData("42", "-1", "3", 42u, 2L)]
    [InlineData("42", "3", "3", 42u, 2L)]
    [InlineData("42", "2", "NaN", 42u, 2L)]
    [InlineData("42", "2", "-2", 42u, 2L)]
    [InlineData("42", "2", "4", 42u, 2L)]
    public void Invalid_index_storage_is_rejected_before_masking(string file, string pages, string tuples, uint physicalFile, long blocks)
    {
        var row = new JsonObject { ["relfilenode"] = file, ["relpages"] = pages, ["reltuples"] = tuples };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Preservation.RequireIndexStorage(row, physicalFile, blocks, 3, rebuilt: false));
    }

    [Theory]
    [InlineData("CustomerIdentity")]
    [InlineData("EmployeeIdentity")]
    [InlineData("Invoice")]
    [InlineData("Quotation")]
    [InlineData("QuotationRequest")]
    public async Task Populated_fixed31_changes_preserve_complete_catalog_rows_sequences_and_comments(string database)
    {
        // Disposable component proof, no Console composition or execution permit.
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        CancellationToken ct = deadline.Token;
        string run = Guid.NewGuid().ToString("N");
        string name = "retained31-native-" + run;
        string observedId = "unobserved";
        DateTimeOffset attempt = DateTimeOffset.UtcNow;
        _output.WriteLine("Resource attempt: run={0}; name={1}; start={2:O}; persistent=false; expiry={3:O}", run, name, attempt, attempt.AddMinutes(4));
        var postgres = new PostgreSqlBuilder(
            "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382")
            .WithDatabase(database).WithUsername("postgres").WithPassword(Guid.NewGuid().ToString("N"))
            .WithName(name).WithLabel("codex.repair.run", run)
            .WithLabel("codex.repair.purpose", "retained31-native-component")
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 384 * 1024 * 1024;
                parameters.HostConfig.MemorySwap = 384 * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 500_000_000;
            }).Build();
        try
        {
            await postgres.StartAsync(ct);
            observedId = postgres.Id;
            _output.WriteLine("Resource observed: run={0}; id={1}; name={2}; image=postgres18.4; postgresPort={3}", run, observedId, name, postgres.GetMappedPublicPort(5432));
            var settings = new NpgsqlConnectionStringBuilder(postgres.GetConnectionString()) { Pooling = false, CommandTimeout = 30 };
            await using var connection = new NpgsqlConnection(settings.ConnectionString);
            await connection.OpenAsync(ct);
            FreshSchemaPlan old = Pair(ConsumerOverlaySelection.CurrentConsumerColumnsV1);
            FreshSchemaPlan current = Pair(ConsumerOverlaySelection.CurrentConsumerSchemaV2);
            DatabaseSchemaPlan oldDatabase = old.Databases.Single(x => x.Database == database);
            DatabaseSchemaPlan currentDatabase = current.Databases.Single(x => x.Database == database);
            TableCopyPlan[] physical = [.. ApprovedConsumerColumnOverlayManifest.ComposePhysical(oldDatabase)];
            // A fixture physical projection is never supplied as an approved source plan.
            DatabaseSchemaPlan fixture = oldDatabase with
            { Tables = physical, TargetExtensionProfile = null, SourceDispositionProfile = null, SourceTableDispositions = [] };
            await using (var setup = await connection.BeginTransactionAsync(ct))
            {
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, setup, ownsResources: false);
                await inspector.ApplySchemaAsync(fixture, ct);
                await inspector.FinalizeSchemaAsync(fixture, ct);
                await Sql("""
                CREATE SCHEMA legacy_migration_internal;
                CREATE TABLE legacy_migration_internal.journal
                    (id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, payload text NOT NULL);
                INSERT INTO legacy_migration_internal.journal(payload) VALUES ('synthetic immutable receipt'),('synthetic Thai sentinel กขค');
                SELECT setval(pg_get_serial_sequence('legacy_migration_internal.journal','id'),91,true);
                ANALYZE legacy_migration_internal.journal;
                """, setup);
                string[] changedTables = [.. CurrentAppOwnedRepairManifest.RetainedOperands().Where(x => x.Database == database).Select(x => x.Table).Distinct(StringComparer.Ordinal)];
                foreach (TableCopyPlan table in physical.Where(x => changedTables.Contains(x.TargetTable, StringComparer.Ordinal)))
                {
                    for (int row = 1; row <= 3; row++)
                    {
                        string columns = string.Join(',', table.OrderedColumns.Select(Q));
                        string values = string.Join(',', table.OrderedColumns.Select(column => Seed(table, column, row)));
                        await Sql($"INSERT INTO public.{Q(table.TargetTable)} ({columns}) VALUES ({values});", setup);
                    }
                    await Sql($"ANALYZE public.{Q(table.TargetTable)}; COMMENT ON TABLE public.{Q(table.TargetTable)} IS 'synthetic retained table comment';", setup);
                    foreach (CurrentAppOwnedCollationOperand operand in CurrentAppOwnedRepairManifest.RetainedOperands().Where(x => x.Database == database && x.Table == table.TargetTable))
                    { await Sql($"COMMENT ON COLUMN public.{Q(table.TargetTable)}.{Q(operand.Column)} IS 'synthetic retained column comment';", setup); }
                    foreach (string index in table.Indexes.Select(x => x.Name).Concat(table.UniqueConstraints.Select(x => x.Name)).Concat(table.PrimaryKey is { } pk ? [pk.Name] : []))
                    { await Sql($"COMMENT ON INDEX public.{Q(index)} IS 'synthetic retained index comment';", setup); }
                    foreach (string constraint in table.CheckConstraints.Select(x => x.Name).Concat(table.UniqueConstraints.Select(x => x.Name)).Concat(table.PrimaryKey is { } pk ? [pk.Name] : []))
                    { await Sql($"COMMENT ON CONSTRAINT {Q(constraint)} ON public.{Q(table.TargetTable)} IS 'synthetic retained constraint comment';", setup); }
                }
                await setup.CommitAsync(ct);
            }
            CurrentAppOwnedRetained31Observation baseline = await Capture();
            Assert.Contains(baseline.Snapshot.Relations, x => x.Schema == "legacy_migration_internal" && x.Rows == 2);
            CurrentAppOwnedRetained31Preservation.RequireBefore(baseline, old, current, DateTimeOffset.UtcNow);
            await using (var statistics = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct))
            {
                CurrentAppOwnedCollationOperand operand = CurrentAppOwnedRepairManifest.RetainedOperands().First(x => x.Database == database);
                await Sql($"CREATE STATISTICS retained31_expression_only_statistics ON (length({Q(operand.Column)})) FROM public.{Q(operand.Table)};", statistics);
                CurrentAppOwnedRetained31Observation withStatistics = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, statistics, ct);
                _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Preservation.RequireBefore(withStatistics, old, current, DateTimeOffset.UtcNow));
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, statistics, ownsResources: false);
                Assert.Equal(oldDatabase.TargetSchemaSha256, await inspector.InspectSchemaAsync(oldDatabase, ct));
                await statistics.RollbackAsync(ct);
            }
            Assert.Equal(baseline.Snapshot.Sha256, (await Capture()).Snapshot.Sha256);
            await using (var rollback = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct))
            {
                await CurrentAppOwnedRepairPreservation.LockAsync(connection, rollback, baseline.Snapshot, ct);
                CurrentAppOwnedRetained31Preservation.RequireBefore(await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, rollback, ct), old, current, DateTimeOffset.UtcNow);
                await Sql(CurrentAppOwnedRepairManifest.CollationSql(database), rollback);
                await Verify(rollback, baseline);
                await rollback.RollbackAsync(ct);
            }
            Assert.Equal(baseline.Snapshot.Sha256, (await Capture()).Snapshot.Sha256);
            await using (var mutation = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct))
            {
                CurrentAppOwnedRetained31Preservation.RequireBefore(await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, mutation, ct), old, current, DateTimeOffset.UtcNow);
                await Sql(CurrentAppOwnedRepairManifest.CollationSql(database), mutation);
                await Sql("UPDATE legacy_migration_internal.journal SET payload='synthetic forbidden mutation' WHERE id=1;", mutation);
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => Verify(mutation, baseline));
                await mutation.RollbackAsync(ct);
            }
            await using (var commit = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct))
            {
                await CurrentAppOwnedRepairPreservation.LockAsync(connection, commit, baseline.Snapshot, ct);
                CurrentAppOwnedRetained31Preservation.RequireBefore(await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, commit, ct), old, current, DateTimeOffset.UtcNow);
                await Sql(CurrentAppOwnedRepairManifest.CollationSql(database), commit);
                await Verify(commit, baseline);
                await commit.CommitAsync(ct);
            }
            CurrentAppOwnedRetained31Observation committed = await Capture();
            CurrentAppOwnedRetained31Preservation.RequirePreserved(baseline, committed, old, current, DateTimeOffset.UtcNow);
            Assert.Equal(baseline.Snapshot.Relations, committed.Snapshot.Relations);
            Assert.Equal(baseline.Snapshot.Sequences, committed.Snapshot.Sequences);
            await using (var readonlyTransaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct))
            {
                await Sql("SET TRANSACTION READ ONLY;", readonlyTransaction);
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, readonlyTransaction, ownsResources: false);
                Assert.Equal(currentDatabase.TargetSchemaSha256, await inspector.InspectSchemaAsync(currentDatabase, ct));
            }

            async Task Verify(NpgsqlTransaction transaction, CurrentAppOwnedRetained31Observation before)
            {
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                Assert.Equal(currentDatabase.TargetSchemaSha256, await inspector.InspectSchemaAsync(currentDatabase, ct));
                CurrentAppOwnedRetained31Observation after = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, ct);
                CurrentAppOwnedRetained31Preservation.RequirePreserved(before, after, old, current, DateTimeOffset.UtcNow);
            }
            async Task<CurrentAppOwnedRetained31Observation> Capture()
            {
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
                await Sql("SET TRANSACTION READ ONLY;", tx);
                return await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, tx, ct);
            }
            async Task Sql(string sql, NpgsqlTransaction transaction)
            { await using var command = new NpgsqlCommand(sql, connection, transaction); _ = await command.ExecuteNonQueryAsync(ct); }
        }
        finally
        {
            _output.WriteLine("Resource cleanup requested: run={0}; id={1}; name={2}", run, observedId, name);
            await postgres.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(30));
            _output.WriteLine("Resource disposal completed: run={0}; id={1}; name={2}; exact Docker absence remains a runner verification", run, observedId, name);
        }
    }

    private static string Q(string name)
    {
        return PostgreSqlShadowTarget.QuoteIdentifier(name);
    }

    private static string Seed(TableCopyPlan table, string column, int row)
    {
        if (table.NullableColumns.Contains(column, StringComparer.Ordinal)) { return "NULL"; }
        if (column == "Purpose") { return table.TargetTable == "InvoiceNotificationCorrelation" ? "'invoice-issued'" : "'employee-email-confirmation'"; }
        if (column == "SenderServiceSubject") { return "'service:legacy-accounting'"; }
        if (column == "Phase") { return "'Prepared'"; }
        if (column == "PayloadFrameVersion") { return "'notification-payload-v1'"; }
        if (column == "BindingVersion") { return "'accounting-invoice-notification-hmac-v1'"; }
        string type = table.ColumnTypes[column];
        if (type is "smallint" or "integer" or "bigint") { return row.ToString(System.Globalization.CultureInfo.InvariantCulture); }
        if (type == "uuid") { return "'" + Guid.NewGuid().ToString("D") + "'"; }
        if (type == "bytea") { return "decode('" + new string('a', 64) + "','hex')"; }
        return type.StartsWith("timestamp", StringComparison.Ordinal)
            ? "'2026-01-01T00:00:00Z'"
            : column is "TokenSha256" or "KeyHash" or "Fingerprint" or "IntentFingerprint"
            ? "'" + new string((char)('a' + row), 64) + "'"
            : "'synthetic-" + row.ToString(System.Globalization.CultureInfo.InvariantCulture) + "'";
    }
    private static FreshSchemaPlan Pair(ConsumerOverlaySelection selection)
    {
        FreshSchemaPlan schema = CurrentConsumerSchemaV2Tests.Schema(selection) with { CapturedAtUtc = DateTimeOffset.UtcNow };
        return schema with { Databases = [.. schema.Databases.Select(database => database.Database == "Quotation" ? Map(database) : database)] };
        static DatabaseSchemaPlan Map(DatabaseSchemaPlan database)
        {
            TableCopyPlan[] tables = [database.Tables[0],
                ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                    "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
                ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                    "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false), .. database.Tables.Skip(3)];
            database = database with
            {
                Tables = tables,
                SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
                SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables)
            };
            return database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
        }
    }
}
