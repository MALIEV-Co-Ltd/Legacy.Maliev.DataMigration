using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlShadowRecoveryTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task Recovery_OwnsItsAutocommitBoundaryEvenInsideAmbientTransaction()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await CreateShadowAsync(target);
        try
        {
            using var ambient = new System.Transactions.TransactionScope(System.Transactions.TransactionScopeAsyncFlowOption.Enabled);
            await using IPostgreSqlShadowRecoverySession recovery = await target.BeginReadOnlyRecoveryAsync(shadow, CancellationToken.None);
            Assert.True((await recovery.InspectAsync(Plan(), CancellationToken.None)).IsVerifiedEmpty);
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None); }
    }

    [Fact]
    public async Task Recovery_RechecksOriginalMarkerAfterWaitingForSettlement()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await CreateShadowAsync(target);
        try
        {
            await using IPostgreSqlWholeDatabaseTransaction writer = await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await PopulateAsync(writer, Plan());
            Task<IPostgreSqlShadowRecoverySession> waiting = target.BeginReadOnlyRecoveryAsync(shadow, CancellationToken.None);
            bool blocked = await WaitForGateWaiterAsync(shadow, waiting);
            await ExecuteAsync(shadow, $"COMMENT ON DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(shadow.Name)} IS 'changed-during-wait';");
            await writer.CommitAsync(CancellationToken.None);
            MigrationExecutionException rejected = await Assert.ThrowsAsync<MigrationExecutionException>(() => waiting);
            Assert.True(blocked);
            Assert.Equal("shadow_ownership_invalid", rejected.Code);
            Assert.Equal("changed-during-wait", await ScalarAsync(shadow, "SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname=current_database();"));
            Assert.Equal(2L, await ScalarAsync(shadow, "SELECT count(*) FROM sales.orders;"));
        }
        finally { await new TestcontainerShadowDatabaseProvisioner(fixture.ConnectionString).DeleteAsync(shadow, CancellationToken.None); }
    }

    [Fact]
    public async Task ReadOnlyGate_ServerRejectsMigrationWrites()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await CreateShadowAsync(target);
        try
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString)
            { Database = shadow.Name, Pooling = false }.ConnectionString);
            await using NpgsqlTransaction transaction = await PostgreSqlShadowTransactionGate.BeginAsync(
                connection, shadow.Name, readOnly: true, TimeSpan.FromSeconds(5), CancellationToken.None);
            await using var write = new NpgsqlCommand("CREATE TABLE public.forbidden(value integer);", connection, transaction);
            PostgresException error = await Assert.ThrowsAsync<PostgresException>(write.ExecuteNonQueryAsync);
            Assert.Equal(PostgresErrorCodes.ReadOnlySqlTransaction, error.SqlState);
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None); }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Recovery_WaitsForRealWriterAndObservesSettledSnapshot(bool commit)
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await CreateShadowAsync(target);
        try
        {
            DatabaseSchemaPlan plan = Plan();
            await using IPostgreSqlWholeDatabaseTransaction writer = await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await PopulateAsync(writer, plan);
            Task<IPostgreSqlShadowRecoverySession> waiting = target.BeginReadOnlyRecoveryAsync(shadow, CancellationToken.None);
            bool blocked = await WaitForGateWaiterAsync(shadow, waiting);
            if (commit) { await writer.CommitAsync(CancellationToken.None); }
            else { await writer.RollbackAsync(CancellationToken.None); }
            await using IPostgreSqlShadowRecoverySession recovery = await waiting;
            Assert.True(blocked, "Recovery must wait for the real writer before acquiring its consistent snapshot.");
            PostgreSqlShadowRecoveryInspection observed = await recovery.InspectAsync(plan, CancellationToken.None);
            Assert.Equal(shadow, observed.OriginalShadow);
            Assert.Equal(!commit, observed.IsVerifiedEmpty);
            if (commit)
            {
                Assert.Equal(plan.TargetSchemaSha256, observed.TargetSchemaSha256);
                TableReconciliationEvidence table = Assert.Single(observed.Tables);
                Assert.Equal(2, table.RowCount);
                Assert.Equal(1, table.NullCounts["Name"]);
                Assert.Equal(0, table.ForeignKeyOrphanCounts["FK_orders_self"]);
                Assert.Equal(2, table.ForeignKeyRelationshipCounts["FK_orders_self"]);
                Assert.Equal(3, observed.SequenceNextValues["sales.orders.Id"]);
                using var collector = new TableEvidenceCollector(plan.Tables[0]);
                foreach (MigrationRow row in Rows()) { collector.Append(row); }
                TableReconciliationEvidence expected = collector.Finish();
                Assert.Equal(expected.ContentSha256, table.ContentSha256);
                Assert.Equal(expected.AggregateSha256, table.AggregateSha256);
            }
            else
            {
                Assert.Null(observed.TargetSchemaSha256);
                Assert.Empty(observed.Tables);
                Assert.Empty(observed.SequenceNextValues);
            }
            Assert.False(recovery is IPostgreSqlWholeDatabaseTransaction);
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None); }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Recovery_TimeoutOrCancellationPreservesWriterAndReleasesSessionAuthority(bool cancel)
    {
        var target = new PostgreSqlShadowTarget(new(fixture.ShadowAdminConnectionString,
            new TestcontainerShadowDatabaseProvisioner(fixture.ConnectionString))
        { SettlementTimeout = TimeSpan.FromSeconds(2) });
        ShadowDatabase shadow = await CreateShadowAsync(target);
        try
        {
            await using IPostgreSqlWholeDatabaseTransaction writer = await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await PopulateAsync(writer, Plan());
            using var cancellation = new CancellationTokenSource();
            Task<IPostgreSqlShadowRecoverySession> waiting = target.BeginReadOnlyRecoveryAsync(shadow, cancellation.Token);
            Assert.True(await WaitForGateWaiterAsync(shadow, waiting));
            if (cancel)
            {
                cancellation.Cancel();
                _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
            }
            else
            {
                MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(() => waiting);
                Assert.Equal("shadow_settlement_timeout", error.Code);
                Assert.NotNull(error.InnerException);
            }
            Assert.Equal(1L, await ScalarAsync(shadow, "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid();"));
            await writer.CommitAsync(CancellationToken.None);
            await using IPostgreSqlShadowRecoverySession next = await target.BeginReadOnlyRecoveryAsync(shadow, CancellationToken.None);
            Assert.Equal(2, Assert.Single((await next.InspectAsync(Plan(), CancellationToken.None)).Tables).RowCount);
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None); }
    }

    [Fact]
    public async Task Recovery_RetainsTransactionGateUntilDisposalWithoutChangingRowsSequencesOrMarker()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await CreateShadowAsync(target);
        try
        {
            await using (IPostgreSqlWholeDatabaseTransaction writer = await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None))
            {
                await PopulateAsync(writer, Plan());
                await writer.CommitAsync(CancellationToken.None);
            }
            string before = (string)(await ScalarAsync(shadow, StateSql))!;
            IPostgreSqlShadowRecoverySession recovery = await target.BeginReadOnlyRecoveryAsync(shadow, CancellationToken.None);
            Task<IPostgreSqlWholeDatabaseTransaction>? waiting = null;
            bool blocked;
            try
            {
                _ = await recovery.InspectAsync(Plan(), CancellationToken.None);
                waiting = target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
                blocked = await WaitForGateWaiterAsync(shadow, waiting);
            }
            finally { await recovery.DisposeAsync(); }
            await using IPostgreSqlWholeDatabaseTransaction subsequent = await waiting!;
            Assert.True(blocked);
            Assert.Equal(before, await ScalarAsync(shadow, StateSql));
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None); }
    }

    [Theory]
    [InlineData("marker")]
    [InlineData("attempt")]
    [InlineData("fence")]
    [InlineData("owner")]
    [InlineData("public-connect")]
    [InlineData("public-create")]
    [InlineData("foreign-role")]
    [InlineData("superuser")]
    public async Task Recovery_RejectsUnownedOrUnreviewedBoundaryWithoutRelabeling(string mismatch)
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await CreateShadowAsync(target);
        try
        {
            ShadowDatabase requested = mismatch switch
            {
                "attempt" => shadow with { OwnerAttempt = shadow.OwnerAttempt + 1 },
                "fence" => shadow with { FencingToken = Guid.NewGuid() },
                _ => shadow,
            };
            string database = PostgreSqlShadowTarget.QuoteIdentifier(shadow.Name);
            string? sql = mismatch switch
            {
                "marker" => $"COMMENT ON DATABASE {database} IS 'wrong-owner';",
                "owner" => $"ALTER DATABASE {database} OWNER TO {fixture.AdministratorUsername}; GRANT CONNECT ON DATABASE {database} TO {fixture.ShadowAdminRole};",
                "public-connect" => $"GRANT CONNECT ON DATABASE {database} TO PUBLIC;",
                "public-create" => $"GRANT CREATE ON DATABASE {database} TO PUBLIC;",
                "foreign-role" => $"GRANT CONNECT ON DATABASE {database} TO {fixture.ControlRole};",
                _ => null,
            };
            if (sql is not null) { await ExecuteAsync(shadow, sql); }
            if (mismatch == "superuser")
            {
                target = new(new(fixture.ConnectionString, new TestcontainerShadowDatabaseProvisioner(fixture.ConnectionString)));
            }
            object? before = await ScalarAsync(shadow, "SELECT row_to_json(d)::text FROM pg_database d WHERE datname=current_database();");
            Exception? rejected = await Record.ExceptionAsync(async () =>
            {
                await using IPostgreSqlShadowRecoverySession recovery = await target.BeginReadOnlyRecoveryAsync(requested, CancellationToken.None);
                _ = await recovery.InspectAsync(Plan(), CancellationToken.None);
            });
            Assert.True(rejected is MigrationExecutionException or PostgreSqlMigrationBoundaryException, rejected?.ToString());
            Assert.Equal(before, await ScalarAsync(shadow, "SELECT row_to_json(d)::text FROM pg_database d WHERE datname=current_database();"));
            Assert.Equal(0L, await ScalarAsync(shadow, "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid <> pg_backend_pid();"));
        }
        finally { await new TestcontainerShadowDatabaseProvisioner(fixture.ConnectionString).DeleteAsync(shadow, CancellationToken.None); }
    }

    public static TheoryData<string, bool> UnexpectedObjects => new()
    {
        { "CREATE VIEW public.extra AS SELECT 1 AS value;", false },
        { "CREATE SEQUENCE public.extra;", false },
        { "CREATE FUNCTION public.extra() RETURNS integer LANGUAGE sql AS 'SELECT 1';", false },
        { "CREATE TYPE public.extra AS ENUM ('x');", false },
        { "CREATE SCHEMA extra;", false },
        { "CREATE TABLE public.extra(value integer);", false },
        { "CREATE DOMAIN public.extra AS integer;", false },
        { "SELECT lo_create(0);", false },
        { "CREATE VIEW public.extra AS SELECT 1 AS value;", true },
        { "CREATE SEQUENCE sales.extra;", true },
        { "CREATE FUNCTION sales.extra() RETURNS integer LANGUAGE sql AS 'SELECT 1';", true },
        { "CREATE TYPE sales.extra AS ENUM ('x');", true },
        { "CREATE SCHEMA extra;", true },
        { "CREATE SCHEMA pgxtempy; CREATE VIEW pgxtempy.extra AS SELECT 1 AS value;", false },
        { "CREATE SCHEMA pgxtempy; CREATE VIEW pgxtempy.extra AS SELECT 1 AS value;", true },
        { "CREATE SCHEMA pgxtoastxtempy; CREATE VIEW pgxtoastxtempy.extra AS SELECT 1 AS value;", false },
        { "CREATE SCHEMA pgxtoastxtempy; CREATE VIEW pgxtoastxtempy.extra AS SELECT 1 AS value;", true },
    };

    [Theory]
    [InlineData("MAXVALUE 2 CYCLE")]
    [InlineData("MAXVALUE 2 NO CYCLE")]
    [InlineData("MINVALUE 0")]
    [InlineData("CYCLE")]
    [InlineData("CACHE 2")]
    public async Task Recovery_RejectsUnsupportedIdentitySequenceConfigurationWithoutMutation(string configuration)
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await CreateShadowAsync(target);
        try
        {
            await using (IPostgreSqlWholeDatabaseTransaction writer = await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None))
            {
                await PopulateAsync(writer, Plan());
                await writer.CommitAsync(CancellationToken.None);
            }
            await ExecuteAsync(shadow, $"ALTER SEQUENCE sales.\"orders_Id_seq\" {configuration};");
            object? before = await ScalarAsync(shadow, SequenceStateSql);
            await using IPostgreSqlShadowRecoverySession recovery = await target.BeginReadOnlyRecoveryAsync(shadow, CancellationToken.None);
            MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(() => recovery.InspectAsync(Plan(), CancellationToken.None));
            Assert.Equal("shadow_recovery_objects_invalid", error.Code);
            Assert.Equal(before, await ScalarAsync(shadow, SequenceStateSql));
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None); }
    }

    [Theory]
    [InlineData("smallint", 1, 3L)]
    [InlineData("integer", 1, 3L)]
    [InlineData("bigint", 1, 3L)]
    [InlineData("smallint", -1, -3L)]
    [InlineData("integer", -1, -3L)]
    [InlineData("bigint", -1, -3L)]
    public async Task Recovery_AcceptsGeneratedSequenceDefaultsForEveryIdentityTypeAndDirection(string type, int increment, long expectedNext)
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await CreateShadowAsync(target);
        try
        {
            DatabaseSchemaPlan draft = Plan();
            TableCopyPlan table = draft.Tables[0] with
            {
                ColumnTypes = new Dictionary<string, string> { ["Id"] = type, ["Name"] = "text" },
                Identities = [new("Id", increment, increment, 2 * increment, true)],
            };
            draft = draft with { Tables = [table] };
            DatabaseSchemaPlan plan = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
            await using (IPostgreSqlWholeDatabaseTransaction writer = await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None))
            {
                await writer.ApplySchemaAsync(plan, CancellationToken.None);
                await writer.FinalizeSchemaAsync(plan, CancellationToken.None);
                _ = await writer.InspectSchemaAsync(plan, CancellationToken.None);
                _ = await writer.InspectTableAsync(table, CancellationToken.None);
                await writer.CommitAsync(CancellationToken.None);
            }
            object? before = await ScalarAsync(shadow, SequenceStateSql);
            await using IPostgreSqlShadowRecoverySession recovery = await target.BeginReadOnlyRecoveryAsync(shadow, CancellationToken.None);
            PostgreSqlShadowRecoveryInspection observed = await recovery.InspectAsync(plan, CancellationToken.None);
            Assert.Equal(expectedNext, observed.SequenceNextValues["sales.orders.Id"]);
            Assert.Equal(before, await ScalarAsync(shadow, SequenceStateSql));
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None); }
    }

    [Theory]
    [MemberData(nameof(UnexpectedObjects))]
    public async Task Recovery_RejectsUnexpectedUserObjectsAndPreservesThem(string sql, bool populated)
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await CreateShadowAsync(target);
        try
        {
            if (populated)
            {
                await using IPostgreSqlWholeDatabaseTransaction writer = await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
                await PopulateAsync(writer, Plan());
                await writer.CommitAsync(CancellationToken.None);
            }
            await ExecuteAsync(shadow, sql);
            object? before = await ScalarAsync(shadow, CatalogSql);
            await using IPostgreSqlShadowRecoverySession recovery = await target.BeginReadOnlyRecoveryAsync(shadow, CancellationToken.None);
            MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(() => recovery.InspectAsync(Plan(), CancellationToken.None));
            Assert.True(error.Code is "shadow_recovery_objects_invalid" or "shadow_reconciliation_failed");
            Assert.Equal(before, await ScalarAsync(shadow, CatalogSql));
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None); }
    }

    [Fact]
    public async Task Recovery_RejectsPartialSchemaAndWrongPlanDatabase()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await CreateShadowAsync(target);
        try
        {
            await ExecuteAsync(shadow, "CREATE SCHEMA sales; CREATE TABLE sales.orders(\"Id\" integer);");
            await using IPostgreSqlShadowRecoverySession recovery = await target.BeginReadOnlyRecoveryAsync(shadow, CancellationToken.None);
            MigrationExecutionException mismatch = await Assert.ThrowsAsync<MigrationExecutionException>(() => recovery.InspectAsync(Plan() with { Database = "Other" }, CancellationToken.None));
            Assert.Equal("shadow_recovery_plan_invalid", mismatch.Code);
            MigrationExecutionException partial = await Assert.ThrowsAsync<MigrationExecutionException>(() => recovery.InspectAsync(Plan(), CancellationToken.None));
            Assert.Equal("shadow_reconciliation_failed", partial.Code);
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None); }
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(300001)]
    public void SettlementTimeout_MustBePositiveAndBounded(int milliseconds)
    {
        _ = Assert.Throws<ArgumentOutOfRangeException>(() => new PostgreSqlShadowTarget(new(fixture.ShadowAdminConnectionString,
            new TestcontainerShadowDatabaseProvisioner(fixture.ConnectionString))
        { SettlementTimeout = TimeSpan.FromMilliseconds(milliseconds) }));
    }

    [Fact]
    public async Task WholeDatabaseTransactions_WaitForSettlementBeforeTakingSnapshot()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await CreateShadowAsync(target);
        try
        {
            DatabaseSchemaPlan plan = Plan();
            await using IPostgreSqlWholeDatabaseTransaction writer =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await PopulateAsync(writer, plan);
            Task<IPostgreSqlWholeDatabaseTransaction> waiting = target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            bool blocked = await WaitForGateWaiterAsync(shadow, waiting);
            await writer.CommitAsync(CancellationToken.None);
            await using IPostgreSqlWholeDatabaseTransaction reader = await waiting;
            Assert.True(blocked, "A second actual target transaction must wait on the pending writer's advisory gate.");
            Assert.Equal(2, (await reader.InspectTableAsync(plan.Tables[0], CancellationToken.None)).RowCount);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    private static Task<ShadowDatabase> CreateShadowAsync(PostgreSqlShadowTarget target)
    {
        return target.CreateUniqueEmptyShadowAsync("Order", $"legacy_shadow_order_{Guid.NewGuid():N}",
            Guid.NewGuid().ToString("D"), CancellationToken.None);
    }

    private async Task<bool> WaitForGateWaiterAsync(ShadowDatabase shadow, Task waiting)
    {
        await using var observer = new NpgsqlConnection(fixture.ConnectionString);
        await observer.OpenAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!waiting.IsCompleted && !deadline.IsCancellationRequested)
        {
            await using var command = new NpgsqlCommand("""
                SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                    WHERE datname = $1 AND wait_event_type = 'Lock' AND wait_event = 'advisory');
                """, observer);
            _ = command.Parameters.AddWithValue(shadow.Name);
            if (true.Equals(await command.ExecuteScalarAsync()))
            {
                return true;
            }
            await Task.Delay(20);
        }
        return false;
    }

    private static DatabaseSchemaPlan Plan()
    {
        var table = new TableCopyPlan("dbo", "Order", "sales", "orders", ["Id", "Name"], ["Id"])
        {
            SourceColumnTypes = new Dictionary<string, string> { ["Id"] = "int", ["Name"] = "nvarchar" },
            ColumnTypes = new Dictionary<string, string> { ["Id"] = "integer", ["Name"] = "text" },
            NullableColumns = ["Name"],
            PrimaryKey = new("PK_orders", ["Id"]),
            IdentityColumns = ["Id"],
            Identities = [new("Id", 1, 1, 2, true)],
            ForeignKeys = [new("FK_orders_self", ["Id"], "sales", "orders", ["Id"])],
        };
        var draft = new DatabaseSchemaPlan("Order", "1.0", new string('a', 64), string.Empty, [table]);
        return draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
    }

    private static async Task PopulateAsync(IPostgreSqlWholeDatabaseTransaction writer, DatabaseSchemaPlan plan)
    {
        await writer.ApplySchemaAsync(plan, CancellationToken.None);
        _ = await writer.CopyBatchAsync(plan.Tables[0], Rows(), CancellationToken.None);
        await writer.FinalizeSchemaAsync(plan, CancellationToken.None);
        Assert.Equal(plan.TargetSchemaSha256, await writer.InspectSchemaAsync(plan, CancellationToken.None));
        _ = await writer.InspectTableAsync(plan.Tables[0], CancellationToken.None);
    }

    private static IReadOnlyList<MigrationRow> Rows()
    {
        return [new(new Dictionary<string, object?> { ["Id"] = 1, ["Name"] = "ไทย" }),
         new(new Dictionary<string, object?> { ["Id"] = 2, ["Name"] = null })];
    }

    private async Task ExecuteAsync(ShadowDatabase shadow, string sql)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = shadow.Name, Pooling = false }.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private async Task<object?> ScalarAsync(ShadowDatabase shadow, string sql)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = shadow.Name, Pooling = false }.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        return await command.ExecuteScalarAsync();
    }

    private const string StateSql = """
        SELECT json_build_array(
            (SELECT json_agg(t ORDER BY "Id") FROM sales.orders t),
            (SELECT json_build_array(s.last_value, s.is_called) FROM sales."orders_Id_seq" s),
            (SELECT row_to_json(d) FROM pg_database d WHERE datname=current_database()),
            (SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname=current_database()))::text;
        """;

    private const string SequenceStateSql = """
        SELECT json_build_array(
            (SELECT json_build_array(s.last_value, s.is_called) FROM sales."orders_Id_seq" s),
            (SELECT row_to_json(s) FROM pg_sequence s WHERE seqrelid='sales."orders_Id_seq"'::regclass))::text;
        """;

    private const string CatalogSql = """
        SELECT json_build_array(
            (SELECT json_agg(n ORDER BY oid) FROM pg_namespace n),
            (SELECT json_agg(c ORDER BY oid) FROM pg_class c),
            (SELECT json_agg(p ORDER BY oid) FROM pg_proc p),
            (SELECT json_agg(t ORDER BY oid) FROM pg_type t),
            (SELECT json_agg(l ORDER BY oid) FROM pg_largeobject_metadata l))::text;
        """;
}
