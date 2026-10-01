using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

/// <summary>Disposable PostgreSQL contract probes, not a signed migration or owner baseline.</summary>
[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class ConsumerColumnOverlayContractTests(PostgreSqlAdapterFixture fixture)
{
    [Theory]
    [InlineData("CustomerIdentity", "auth-customer-create-authority-v2")]
    [InlineData("Quotation", "quotation-decision-order-version-v1")]
    public void NewProfile_FingerprintAdmitsOnlyTheOwnerColumnWithoutChangingSourceProjection(string database, string profile)
    {
        var plan = Plan(database, profile);
        string? fingerprint = null;
        var failure = Record.Exception(() => fingerprint = PostgreSqlSchemaFingerprint.ComputeExpected(plan));
        Assert.Null(failure);
        Assert.Equal(plan.TargetSchemaSha256, fingerprint);
        Assert.DoesNotContain(OverlayColumn(database), Assert.Single(plan.Tables).OrderedColumns);
    }

    [Theory]
    [InlineData("CustomerIdentity", "auth-customer-create-authority-v2")]
    [InlineData("Quotation", "quotation-decision-order-version-v1")]
    public async Task NewProfile_ActualCanonicalEntryAdmitsTheIndependentlyCreatedPhysicalOverlay(string database, string profile)
    {
        await WithDatabaseAsync(database, async cs =>
        {
            var schema = Plan(database, profile);
            await CreatePhysicalAsync(cs, database, includeReceipt: database == "CustomerIdentity");
            Assert.Equal(schema.TargetSchemaSha256, await PhysicalHashAsync(cs, schema));
            var delta = Delta(schema, []);
            await ProvisionAsync(cs, schema, delta);
            var target = new PostgreSqlDeltaCanonicalTarget(new(cs, database, delta.TargetGeneration));
            IDeltaCanonicalTransaction? opened = null;
            try
            {
                var failure = await Record.ExceptionAsync(async () => opened = await target.BeginAsync(delta, schema, database, default));
                Assert.Equal(0L, await ScalarAsync(cs, $"SELECT count(*) FROM public.{Quote(Source(database).TargetTable)};"));
                Assert.Equal(0L, await ScalarAsync(cs, "SELECT count(*) FROM legacy_migration_internal.delta_journal;"));
                if (database == "CustomerIdentity")
                {
                    Assert.Equal(0L, await ScalarAsync(cs, "SELECT count(*) FROM public.\"CustomerIdentityCreateOperations\";"));
                }
                Assert.Null(failure);
                Assert.NotNull(opened);
                Assert.Equal(DeltaExecutionDisposition.Pending, opened.Disposition);
            }
            finally
            {
                if (opened is not null)
                {
                    await opened.DisposeAsync();
                }
            }
        });
    }

    [Theory]
    [InlineData("CustomerIdentity", "auth-customer-create-authority-v2")]
    [InlineData("Quotation", "quotation-decision-order-version-v1")]
    public void NewProfile_SourceOwnedColumnCollisionMustNotBecomePreserveOnly(string database, string profile)
    {
        var plan = Plan(database, profile) with { Tables = [PhysicalRoot(database)] };
        var failure = Assert.Throws<MigrationExecutionException>(() => PostgreSqlSchemaFingerprint.ComputeExpected(plan));
        Assert.Equal("target_extension_source_overlap", failure.Code);
    }

    [Theory]
    [InlineData("CustomerIdentity", "auth-customer-create-authority-v999")]
    [InlineData("Quotation", "quotation-decision-order-version-v999")]
    [InlineData("EmployeeIdentity", "auth-customer-create-authority-v2")]
    [InlineData("QuotationRequest", "quotation-decision-order-version-v1")]
    public void UnknownOrWrongDatabaseProfile_FailsClosed(string database, string profile)
    {
        var plan = new DatabaseSchemaPlan(database, "1.0", new string('a', 64), new string('0', 64), [Source("Quotation")])
        { TargetExtensionProfile = profile };
        var failure = Assert.Throws<MigrationExecutionException>(() => PostgreSqlSchemaFingerprint.ComputeExpected(plan));
        Assert.Equal("target_extension_profile_invalid", failure.Code);
    }

    [Theory]
    [InlineData("CustomerIdentity", "auth-customer-create-authority-v1")]
    [InlineData("Quotation", null)]
    public void HistoricalProfile_DoesNotSilentlyAcquireTheOverlay(string database, string? profile)
    {
        var historical = new DatabaseSchemaPlan(database, "1.0", new string('a', 64), new string('0', 64), [Source(database)])
        { TargetExtensionProfile = profile };
        Assert.NotEqual(Plan(database, ProposedProfile(database)).TargetSchemaSha256, PostgreSqlSchemaFingerprint.ComputeExpected(historical));
        Assert.DoesNotContain(OverlayColumn(database), Assert.Single(historical.Tables).OrderedColumns);
    }

    [Fact]
    public void HistoricalCustomerReceiptState_RetainsLiteralV1Digest()
    {
        var schema = new DatabaseSchemaPlan("CustomerIdentity", "1.0", new string('a', 64), new string('b', 64), [Source("CustomerIdentity")])
        { TargetExtensionProfile = "auth-customer-create-authority-v1" };
        var table = new TableReconciliationEvidence("public.CustomerIdentityCreateOperations", 1, new string('c', 64), new string('d', 64),
            new Dictionary<string, long>(), new Dictionary<string, long>());
        var state = new ApprovedTargetExtensionState([table], new Dictionary<string, long>
        { ["public.CustomerIdentityCreateOperations.Id"] = 3000000001 });
        // Independent BinaryWriter reproduction of the accepted v1 framing, not the new overlay helper.
        Assert.Equal("c6ff812513379a12b6cbfebe71e57e11554d55c09708ec6ab635b3a6cb2a293c",
            ApprovedTargetExtensionStateInspector.ComputeSha256(schema, state));
        Assert.Null(state.Overlay);
    }

    [Theory]
    [InlineData("CustomerIdentity", "type")]
    [InlineData("CustomerIdentity", "nullable")]
    [InlineData("CustomerIdentity", "missing-default")]
    [InlineData("CustomerIdentity", "changed-default")]
    [InlineData("CustomerIdentity", "generated")]
    [InlineData("Quotation", "type")]
    [InlineData("Quotation", "nullable")]
    [InlineData("Quotation", "changed-default")]
    [InlineData("Quotation", "generated")]
    public async Task LiteralOwnerPhysicalContract_DriftChangesObservedFingerprint(string database, string change)
    {
        await WithDatabaseAsync(database, async cs =>
        {
            await CreatePhysicalAsync(cs, database, includeReceipt: database == "CustomerIdentity");
            var schema = Plan(database, ProposedProfile(database));
            Assert.Equal(schema.TargetSchemaSha256, await PhysicalHashAsync(cs, schema));
            await SqlAsync(cs, DriftSql(database, change));
            Assert.NotEqual(schema.TargetSchemaSha256, await PhysicalHashAsync(cs, schema));
            var delta = Delta(schema, []);
            await ProvisionAsync(cs, schema, delta);
            var target = new PostgreSqlDeltaCanonicalTarget(new(cs, database, delta.TargetGeneration));
            if (database == "CustomerIdentity")
            {
                var rejected = await Assert.ThrowsAsync<DeltaExecutionException>(() => target.BeginAsync(delta, schema, database, default));
                Assert.Equal("canonical_delta_local_schema_drift", rejected.Code);
            }
            else
            {
                var rejected = await Assert.ThrowsAsync<MigrationExecutionException>(() => target.BeginAsync(delta, schema, database, default));
                Assert.Equal("shadow_reconciliation_failed", rejected.Code);
                Assert.Equal("schema", rejected.Reconciliation!.Check);
            }
            Assert.Equal(0L, await ScalarAsync(cs, "SELECT count(*) FROM legacy_migration_internal.delta_journal;"));
        });
    }

    [Theory]
    [InlineData("CustomerIdentity")]
    [InlineData("Quotation")]
    public async Task ConcreteSourceOnlyStatements_RollbackCommitReplayPreserveExistingValuesAndUseOwnerInsertDefaults(string database)
    {
        // Existing concrete storage unit only: no new profile is pretended to be admitted.
        await CheckSourceStatementsAsync(database, admitted: false, tamperReplay: false);
    }

    [Theory]
    [InlineData("CustomerIdentity", false)]
    [InlineData("Quotation", false)]
    [InlineData("CustomerIdentity", true)]
    [InlineData("Quotation", true)]
    public async Task AdmittedProfile_RollbackCommitAndFreshReplayPreserveAuthorityOrRejectTampering(string database, bool tamperReplay)
    {
        await CheckSourceStatementsAsync(database, admitted: true, tamperReplay);
    }

    private async Task CheckSourceStatementsAsync(string database, bool admitted, bool tamperReplay)
    {
        await WithDatabaseAsync(database, async cs =>
        {
            await CreatePhysicalAsync(cs, database, includeReceipt: admitted && database == "CustomerIdentity");
            await SqlAsync(cs, SeedSql(database));
            if (admitted && database == "CustomerIdentity") { await SqlAsync(cs, ReceiptSeed); }
            var source = Source(database);
            var schema = admitted ? Plan(database, ProposedProfile(database)) : new DatabaseSchemaPlan(database, "1.0", new string('a', 64),
                PostgreSqlSchemaFingerprint.ComputeExpectedTables([PhysicalRoot(database)]), [source]);
            source = Assert.Single(schema.Tables);
            var previous = Row(database, 1, "Before");
            var updated = Row(database, 1, "After");
            var inserted = Row(database, 3, "New");
            var operations = CanonicalDeltaPlanner.Plan(source, [updated, inserted], [previous]).Operations;
            var delta = Delta(schema, operations);
            await ProvisionAsync(cs, schema, delta);
            var target = new PostgreSqlDeltaCanonicalTarget(new(cs, database, delta.TargetGeneration));
            await using (var rollback = await target.BeginAsync(delta, schema, database, default))
            {
                foreach (var operation in operations)
                {
                    bool update = operation.Kind == DeltaOperationKind.Update;
                    await rollback.ApplyAsync(source, operation, update ? updated : inserted, update ? previous : null, default);
                }
            }
            Assert.Equal("Before", await ScalarAsync(cs, $"SELECT {Quote(ValueColumn(database))} FROM public.{Quote(source.TargetTable)} WHERE {Quote(KeyColumn(database))}={KeyLiteral(database, 1)};"));
            Assert.Equal(2L, await ScalarAsync(cs, $"SELECT count(*) FROM public.{Quote(source.TargetTable)};"));
            await AssertExistingOverlayValuesAsync(cs, database);
            using var collector = new TableEvidenceCollector(source);
            collector.Append(updated);
            collector.Append(Row(database, 2, "Unchanged"));
            collector.Append(inserted);
            var expected = new DatabaseReconciliationEvidence(database, schema.SourceSchemaSha256, schema.TargetSchemaSha256, [collector.Finish()]);
            string reconciliation;
            await using (var commit = await target.BeginAsync(delta, schema, database, default))
            {
                foreach (var operation in operations)
                {
                    bool update = operation.Kind == DeltaOperationKind.Update;
                    await commit.ApplyAsync(source, operation, update ? updated : inserted, update ? previous : null, default);
                }
                reconciliation = await commit.ReconcileAsync(expected, default);
                await commit.CommitAsync(DeltaSynchronizationPlanCanonicalizer.ComputeSha256(delta), reconciliation, default);
            }
            await AssertExistingOverlayValuesAsync(cs, database);
            object? insertedOverlay = await ScalarAsync(cs, $"SELECT {Quote(OverlayColumn(database))} FROM public.{Quote(source.TargetTable)} WHERE {Quote(KeyColumn(database))}={KeyLiteral(database, 3)};");
            if (database == "CustomerIdentity")
            {
                Assert.Equal(false, insertedOverlay);
            }
            else
            {
                Assert.Equal(DBNull.Value, insertedOverlay);
            }

            if (admitted && database == "CustomerIdentity")
            {
                Assert.Equal(1L, await ScalarAsync(cs, "SELECT count(*) FROM public.\"CustomerIdentityCreateOperations\";"));
                Assert.Equal(3000000000L, await ScalarAsync(cs, "SELECT last_value FROM public.\"CustomerIdentityCreateOperations_Id_seq\";"));
                Assert.Equal("synthetic", await ScalarAsync(cs, "SELECT \"IdentityId\" FROM public.\"CustomerIdentityCreateOperations\";"));
            }
            if (tamperReplay)
            {
                await SqlAsync(cs, TamperSql(database));
                var failure = await Assert.ThrowsAsync<DeltaExecutionException>(() => target.BeginAsync(delta, schema, database, default));
                Assert.Equal("canonical_delta_replay_target_drift", failure.Code);
                Assert.Equal(1L, await ScalarAsync(cs, "SELECT count(*) FROM legacy_migration_internal.delta_journal;"));
                Assert.Equal(3L, await ScalarAsync(cs, $"SELECT count(*) FROM public.{Quote(source.TargetTable)};"));
                return;
            }
            await using (var replay = await target.BeginAsync(delta, schema, database, default))
            {
                Assert.Equal(DeltaExecutionDisposition.AlreadyCommitted, replay.Disposition);
                Assert.Equal(reconciliation, replay.ReconciliationSha256);
            }
            await AssertExistingOverlayValuesAsync(cs, database);
            Assert.Equal(3L, await ScalarAsync(cs, $"SELECT count(*) FROM public.{Quote(source.TargetTable)};"));
            Assert.Equal(1L, await ScalarAsync(cs, "SELECT count(*) FROM legacy_migration_internal.delta_journal;"));
        });
    }

    [Theory]
    [InlineData("CustomerIdentity", "inventory")]
    [InlineData("CustomerIdentity", "types")]
    [InlineData("Quotation", "inventory")]
    [InlineData("Quotation", "types")]
    public void SourceInventoryOnlyCollision_CannotBeHiddenByAnOmittedProjection(string database, string inventory)
    {
        var source = Source(database);
        source = inventory == "inventory" ? source with { SourceColumns = [new(OverlayColumn(database), "synthetic", new string('a', 64), null)] }
            : source with { SourceColumnTypes = new Dictionary<string, string> { [OverlayColumn(database)] = "synthetic" } };
        var schema = Plan(database, ProposedProfile(database)) with { Tables = [source] };
        var failure = Assert.Throws<MigrationExecutionException>(() => PostgreSqlSchemaFingerprint.ComputeExpected(schema));
        Assert.Equal("target_extension_source_overlap", failure.Code);
    }

    [Theory]
    [InlineData("CustomerIdentity")]
    [InlineData("Quotation")]
    public async Task RootDelete_IsRefusedAtEntryAndDefensivelyAtApplyWithoutLosingValues(string database)
    {
        await WithDatabaseAsync(database, async cs =>
        {
            await CreatePhysicalAsync(cs, database, includeReceipt: database == "CustomerIdentity");
            await SqlAsync(cs, SeedSql(database));
            var schema = Plan(database, ProposedProfile(database));
            var root = Assert.Single(schema.Tables);
            var previous = Row(database, 1, "Before");
            var operation = Assert.Single(CanonicalDeltaPlanner.Plan(root, [], [previous]).Operations);
            var prohibited = Delta(schema, [operation]);
            var target = new PostgreSqlDeltaCanonicalTarget(new(cs, database, prohibited.TargetGeneration));
            var entryFailure = await Assert.ThrowsAsync<MigrationExecutionException>(() => target.BeginAsync(prohibited, schema, database, default));
            Assert.Equal("target_extension_overlay_delete_forbidden", entryFailure.Code);
            var admitted = Delta(schema, []);
            await ProvisionAsync(cs, schema, admitted);
            await using (var tx = await target.BeginAsync(admitted, schema, database, default))
            {
                var applyFailure = await Assert.ThrowsAsync<MigrationExecutionException>(() => tx.ApplyAsync(root, operation, null, previous, default));
                Assert.Equal("target_extension_overlay_delete_forbidden", applyFailure.Code);
            }
            await AssertExistingOverlayValuesAsync(cs, database);
            Assert.Equal(2L, await ScalarAsync(cs, $"SELECT count(*) FROM public.{Quote(root.TargetTable)};"));
            Assert.Equal(0L, await ScalarAsync(cs, "SELECT count(*) FROM legacy_migration_internal.delta_journal;"));
        });
    }

    [Theory]
    [InlineData("CustomerIdentity", "existing")]
    [InlineData("CustomerIdentity", "new-default")]
    [InlineData("CustomerIdentity", "unknown")]
    [InlineData("Quotation", "existing")]
    [InlineData("Quotation", "new-default")]
    [InlineData("Quotation", "unknown")]
    public async Task CapturedOverlayState_RejectsChangedExistingUnknownKeysAndNonDefaultInsertedValues(string database, string change)
    {
        await WithDatabaseAsync(database, async cs =>
        {
            await CreatePhysicalAsync(cs, database, includeReceipt: database == "CustomerIdentity");
            await SqlAsync(cs, SeedSql(database));
            var schema = Plan(database, ProposedProfile(database));
            var root = Source(database);
            var keys = new HashSet<string>(StringComparer.Ordinal) { CanonicalDeltaPlanner.ComputeKeySha256(root, Row(database, 3, "New")) };
            await using var c = new NpgsqlConnection(cs);
            await c.OpenAsync();
            await using var tx = await c.BeginTransactionAsync();
            var before = await ApprovedTargetExtensionStateInspector.InspectAsync(c, tx, schema, default, keys);
            string table = $"public.{Quote(root.TargetTable)}";
            if (change != "new-default")
            {
                await using var insert = new NpgsqlCommand($"INSERT INTO {table} ({Quote(KeyColumn(database))}) VALUES ({KeyLiteral(database, 3)});", c, tx);
                _ = await insert.ExecuteNonQueryAsync();
            }
            string mutation = change switch
            {
                "existing" => TamperSql(database),
                "new-default" => $"INSERT INTO {table} ({Quote(KeyColumn(database))},{Quote(OverlayColumn(database))}) VALUES ({KeyLiteral(database, 3)},{(database == "CustomerIdentity" ? "true" : "'2031-01-01'::timestamp")});",
                "unknown" => $"INSERT INTO {table} ({Quote(KeyColumn(database))}) VALUES ({KeyLiteral(database, 4)});",
                _ => throw new ArgumentOutOfRangeException(nameof(change)),
            };
            await using (var mutate = new NpgsqlCommand(mutation, c, tx)) { _ = await mutate.ExecuteNonQueryAsync(); }
            var failure = await Record.ExceptionAsync(async () =>
            {
                var after = await ApprovedTargetExtensionStateInspector.InspectAsync(c, tx, schema, default, keys, afterApply: true);
                ApprovedTargetExtensionStateInspector.Compare(schema, before, after);
            });
            var rejected = Assert.IsType<MigrationExecutionException>(failure);
            Assert.Equal(change == "new-default" ? "target_extension_overlay_state_invalid" : "shadow_reconciliation_failed", rejected.Code);
            if (change != "new-default")
            {
                Assert.Equal(change == "existing" ? "ordered-content" : "row-count", rejected.Reconciliation!.Check);
            }
            await tx.RollbackAsync();
            await AssertExistingOverlayValuesAsync(cs, database);
        });
    }

    private const string ReceiptSeed = """
        ALTER SEQUENCE public."CustomerIdentityCreateOperations_Id_seq" RESTART WITH 3000000000;
        INSERT INTO public."CustomerIdentityCreateOperations" ("ServiceSubject","OperationKey","DatabaseId","IdentityId","PayloadSalt","PayloadHash")
        VALUES ('service:synthetic','11111111-1111-1111-1111-111111111111',1,'synthetic',decode(repeat('ab',16),'hex'),decode(repeat('cd',32),'hex'));
        """;
    private static string TamperSql(string database)
    {
        return $"UPDATE public.{Quote(Source(database).TargetTable)} SET {Quote(OverlayColumn(database))}={(database == "CustomerIdentity" ? "false" : "'2032-01-01'::timestamp")} WHERE {Quote(KeyColumn(database))}={KeyLiteral(database, 1)};";
    }

    private static DatabaseSchemaPlan Plan(string database, string profile)
    {
        return new(database, "1.0", new string('a', 64),
        PostgreSqlSchemaFingerprint.ComputeExpectedTables(database == "CustomerIdentity"
            ? [PhysicalRoot(database), .. ApprovedConsumerTargetExtensionShapes.CustomerIdentity()]
            : [PhysicalRoot(database)]), [Source(database)])
        { TargetExtensionProfile = profile };
    }

    private static TableCopyPlan Source(string database)
    {
        return new("dbo", database == "CustomerIdentity" ? "AspNetUsers" : "Quotation",
        "public", database == "CustomerIdentity" ? "AspNetUsers" : "Quotation", [KeyColumn(database), ValueColumn(database)], [KeyColumn(database)])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [KeyColumn(database)] = database == "CustomerIdentity" ? "character varying(450)" : "integer",
                [ValueColumn(database)] = database == "CustomerIdentity" ? "character varying(256)" : "text",
            },
            NullableColumns = [ValueColumn(database)],
            PrimaryKey = new(database == "CustomerIdentity" ? "PK_AspNetUsers" : "PK_Quotation", [KeyColumn(database)]),
        };
    }

    private static TableCopyPlan PhysicalRoot(string database)
    {
        var source = Source(database);
        var types = new Dictionary<string, string>(source.ColumnTypes, StringComparer.Ordinal)
        { [OverlayColumn(database)] = database == "CustomerIdentity" ? "boolean" : "timestamp without time zone" };
        return source with
        {
            OrderedColumns = [.. source.OrderedColumns, OverlayColumn(database)],
            ColumnTypes = types,
            NullableColumns = database == "CustomerIdentity" ? source.NullableColumns : [.. source.NullableColumns, OverlayColumn(database)],
            DefaultExpressions = database == "CustomerIdentity" ? new Dictionary<string, string> { [OverlayColumn(database)] = "false" } : source.DefaultExpressions,
        };
    }

    private async Task WithDatabaseAsync(string database, Func<string, Task> proof)
    {
        await using var admin = new NpgsqlConnection(fixture.ConnectionString);
        await admin.OpenAsync();
        await using (var create = new NpgsqlCommand($"CREATE DATABASE {Quote(database)} TEMPLATE template0;", admin))
        { _ = await create.ExecuteNonQueryAsync(); }
        string cs = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = database, Pooling = false }.ConnectionString;
        try { await proof(cs); }
        finally
        {
            await using var drop = new NpgsqlCommand($"DROP DATABASE {Quote(database)} WITH (FORCE);", admin);
            _ = await drop.ExecuteNonQueryAsync();
        }
    }

    private static async Task CreatePhysicalAsync(string cs, string database, bool includeReceipt)
    {
        await SqlAsync(cs, database == "CustomerIdentity"
            ? "CREATE TABLE public.\"AspNetUsers\" (\"Id\" varchar(450) NOT NULL, \"Email\" varchar(256), \"PasswordSetupRequired\" boolean NOT NULL DEFAULT false, CONSTRAINT \"PK_AspNetUsers\" PRIMARY KEY (\"Id\"));"
            : "CREATE TABLE public.\"Quotation\" (\"ID\" integer NOT NULL, \"Comment\" text, \"DecisionOrderVersion\" timestamp without time zone, CONSTRAINT \"PK_Quotation\" PRIMARY KEY (\"ID\"));");
        if (includeReceipt)
        {
            var receipts = new DatabaseSchemaPlan(database, "1.0", new string('a', 64), new string('0', 64), ApprovedConsumerTargetExtensionShapes.CustomerIdentity());
            await using var c = new NpgsqlConnection(cs);
            await c.OpenAsync();
            await using var tx = await c.BeginTransactionAsync();
            await using var writer = new PostgreSqlWholeDatabaseTransaction(c, tx, ownsResources: false);
            await writer.ApplySchemaAsync(receipts, default);
            await writer.FinalizeSchemaAsync(receipts, default);
            await tx.CommitAsync();
        }
    }

    private static async Task<string> PhysicalHashAsync(string cs, DatabaseSchemaPlan schema)
    {
        await using var c = new NpgsqlConnection(cs);
        await c.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(c, tx, ownsResources: false);
        return await inspector.InspectSchemaAsync(schema, default);
    }

    private static DeltaSynchronizationPlan Delta(DatabaseSchemaPlan schema, IReadOnlyList<CanonicalDeltaOperation> operations)
    {
        var now = new DateTimeOffset(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var table = new DeltaTablePlan($"public.{schema.Tables[0].TargetTable}", operations.Count(x => x.Kind == DeltaOperationKind.Insert),
            operations.Count(x => x.Kind == DeltaOperationKind.Update), 0, 0,
            DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(operations), operations);
        return new("1.1", Guid.NewGuid(), new string('b', 40), now, new string('c', 64), new string('d', 64), new string('e', 64),
            "local-test", "owned-container", "generation-test", new string('f', 64), new string('1', 64), new string('2', 64), now,
            [new DeltaDatabasePlan(schema.Database, [table])], "synthetic-unit", null);
    }

    private static async Task ProvisionAsync(string cs, DatabaseSchemaPlan schema, DeltaSynchronizationPlan delta)
    {
        await using var c = new NpgsqlConnection(cs);
        await c.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        await PostgreSqlDeltaMetadataProvisioner.ProvisionDatabaseAsync(c, tx, delta, schema, default);
        await tx.CommitAsync();
    }

    private static async Task AssertExistingOverlayValuesAsync(string cs, string database)
    {
        var table = Source(database).TargetTable;
        object? first = await ScalarAsync(cs, $"SELECT {Quote(OverlayColumn(database))} FROM public.{Quote(table)} WHERE {Quote(KeyColumn(database))}={KeyLiteral(database, 1)};");
        object? second = await ScalarAsync(cs, $"SELECT {Quote(OverlayColumn(database))} FROM public.{Quote(table)} WHERE {Quote(KeyColumn(database))}={KeyLiteral(database, 2)};");
        if (database == "CustomerIdentity") { Assert.Equal(true, first); Assert.Equal(false, second); }
        else { Assert.Equal(new DateTime(2030, 2, 3, 4, 5, 6, DateTimeKind.Unspecified).AddTicks(1234560), first); Assert.Equal(DBNull.Value, second); }
    }

    private static string SeedSql(string database)
    {
        return database == "CustomerIdentity"
        ? "INSERT INTO public.\"AspNetUsers\" VALUES ('1','Before',true),('2','Unchanged',false);"
        : "INSERT INTO public.\"Quotation\" VALUES (1,'Before','2030-02-03 04:05:06.123456'),(2,'Unchanged',NULL);";
    }

    private static string DriftSql(string database, string change)
    {
        string table = $"public.{Quote(Source(database).TargetTable)}", column = Quote(OverlayColumn(database));
        string prefix = $"ALTER TABLE {table} ALTER COLUMN {column} ";
        return change switch
        {
            "type" => database == "CustomerIdentity" ? prefix + "DROP DEFAULT; " + prefix + "TYPE integer USING 0;" : prefix + "TYPE timestamp with time zone;",
            "nullable" => prefix + (database == "CustomerIdentity" ? "DROP NOT NULL;" : "SET NOT NULL;"),
            "missing-default" => prefix + "DROP DEFAULT;",
            "changed-default" => prefix + (database == "CustomerIdentity" ? "SET DEFAULT true;" : "SET DEFAULT '2031-01-01'::timestamp;"),
            "generated" => $"ALTER TABLE {table} DROP COLUMN {column}, ADD COLUMN {column} " + (database == "CustomerIdentity"
                ? "boolean GENERATED ALWAYS AS (true) STORED NOT NULL;" : "timestamp without time zone GENERATED ALWAYS AS ('2031-01-01'::timestamp) STORED;"),
            _ => throw new ArgumentOutOfRangeException(nameof(change)),
        };
    }

    private static MigrationRow Row(string database, int id, string value)
    {
        return new(new Dictionary<string, object?>(StringComparer.Ordinal)
        { [KeyColumn(database)] = database == "CustomerIdentity" ? id.ToString(System.Globalization.CultureInfo.InvariantCulture) : id, [ValueColumn(database)] = value });
    }

    private static string KeyColumn(string database)
    {
        return database == "CustomerIdentity" ? "Id" : "ID";
    }

    private static string ValueColumn(string database)
    {
        return database == "CustomerIdentity" ? "Email" : "Comment";
    }

    private static string OverlayColumn(string database)
    {
        return database == "CustomerIdentity" ? "PasswordSetupRequired" : "DecisionOrderVersion";
    }

    private static string ProposedProfile(string database)
    {
        return database == "CustomerIdentity" ? "auth-customer-create-authority-v2" : "quotation-decision-order-version-v1";
    }

    private static string KeyLiteral(string database, int id)
    {
        return database == "CustomerIdentity" ? $"'{id}'" : id.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string Quote(string value)
    {
        return PostgreSqlShadowTarget.QuoteIdentifier(value);
    }

    private static async Task SqlAsync(string cs, string sql)
    { await using var c = new NpgsqlConnection(cs); await c.OpenAsync(); await using var cmd = new NpgsqlCommand(sql, c); _ = await cmd.ExecuteNonQueryAsync(); }
    private static async Task<object?> ScalarAsync(string cs, string sql)
    { await using var c = new NpgsqlConnection(cs); await c.OpenAsync(); await using var cmd = new NpgsqlCommand(sql, c); return await cmd.ExecuteScalarAsync(); }
}
