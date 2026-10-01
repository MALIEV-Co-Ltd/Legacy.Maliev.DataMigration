using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

/// <summary>Actual PostgreSQL canonical transactions; synthetic disposable receipts, never operator authorization.</summary>
[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class ConsumerTargetExtensionPreservationTests(PostgreSqlAdapterFixture fixture)
{
    [Theory]
    [InlineData("Invoice", "accounting-invoice-authority-v1")]
    [InlineData("CustomerIdentity", "auth-customer-create-authority-v1")]
    [InlineData("EmployeeIdentity", "auth-employee-recovery-authority-v1")]
    public async Task SourceOnlyDelta_RollbackCommitAndReplayPreserveNonemptyAuthority(string database, string profile)
    {
        var probe = new TableCopyPlan("dbo", "Probe", "public", "Probe", ["ID", "Value"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["ID"] = "integer", ["Value"] = "text" },
            PrimaryKey = new("PK_Probe", ["ID"]),
        };
        var draft = new DatabaseSchemaPlan(database, "1.0", new string('a', 64), new string('0', 64), [probe]) { TargetExtensionProfile = profile };
        var schema = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        await using var admin = new NpgsqlConnection(fixture.ConnectionString);
        await admin.OpenAsync();
        await SqlAsync(admin, null, $"CREATE DATABASE \"{database}\" TEMPLATE template0;");
        string cs = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = database, Pooling = false }.ConnectionString;
        try
        {
            await using (var c = new NpgsqlConnection(cs))
            {
                await c.OpenAsync();
                await using var tx = await c.BeginTransactionAsync();
                await using var writer = new PostgreSqlWholeDatabaseTransaction(c, tx, ownsResources: false);
                await writer.ApplySchemaAsync(schema, default);
                await writer.FinalizeSchemaAsync(schema, default);
                Assert.Equal(schema.TargetSchemaSha256, await writer.InspectSchemaAsync(schema, default));
                await SqlAsync(c, tx, SeedSql(database));
                await tx.CommitAsync();
            }
            ApprovedTargetExtensionState before = await StateAsync(cs, schema);
            Assert.All(before.Tables, t => Assert.Equal(1, t.RowCount));
            if (database == "CustomerIdentity")
            {
                Assert.Equal(3000000001L, before.SequenceNextValues["public.CustomerIdentityCreateOperations.Id"]);
            }
            string beforeHash = ApprovedTargetExtensionStateInspector.ComputeSha256(schema, before);
            var row = new MigrationRow(new Dictionary<string, object?>(StringComparer.Ordinal) { ["ID"] = 1, ["Value"] = "Source-only change" });
            var operation = Assert.Single(CanonicalDeltaPlanner.Plan(probe, [row], []).Operations);
            var tablePlan = new DeltaTablePlan("public.Probe", 1, 0, 0, 0,
                DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256([operation]), [operation]);
            var now = new DateTimeOffset(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
            // This exercises the concrete target unit, not signed operator admission/CLI.
            var plan = new DeltaSynchronizationPlan("1.1", Guid.NewGuid(), new string('b', 40), now,
                new string('c', 64), new string('d', 64), new string('e', 64), "local-test", "owned-container",
                "generation-test", new string('f', 64), new string('1', 64), new string('2', 64), now,
                [new DeltaDatabasePlan(database, [tablePlan])], "synthetic-unit", null);
            await using (var c = new NpgsqlConnection(cs))
            {
                await c.OpenAsync();
                await using var tx = await c.BeginTransactionAsync();
                await PostgreSqlDeltaMetadataProvisioner.ProvisionDatabaseAsync(c, tx, plan, schema, default);
                await tx.CommitAsync();
            }
            var target = new PostgreSqlDeltaCanonicalTarget(new(cs, database, plan.TargetGeneration));
            await using (var rollback = await target.BeginAsync(plan, schema, database, default))
            {
                await rollback.ApplyAsync(probe, operation, row, null, default);
                // Dispose without a checkpoint/commit must roll back only the source insertion.
            }
            Assert.Equal(0L, await CountAsync(cs, "public.\"Probe\""));
            Assert.Equal(beforeHash, ApprovedTargetExtensionStateInspector.ComputeSha256(schema, await StateAsync(cs, schema)));
            using var collector = new TableEvidenceCollector(probe);
            collector.Append(row);
            var expected = new DatabaseReconciliationEvidence(database, schema.SourceSchemaSha256, schema.TargetSchemaSha256, [collector.Finish()]);
            string reconciled;
            await using (var commit = await target.BeginAsync(plan, schema, database, default))
            {
                await commit.ApplyAsync(probe, operation, row, null, default);
                reconciled = await commit.ReconcileAsync(expected, default);
                await commit.CommitAsync(DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan), reconciled, default);
            }
            Assert.Equal(1L, await CountAsync(cs, "public.\"Probe\""));
            ApprovedTargetExtensionState after = await StateAsync(cs, schema);
            ApprovedTargetExtensionStateInspector.Compare(schema, before, after);
            Assert.Equal(beforeHash, ApprovedTargetExtensionStateInspector.ComputeSha256(schema, after));
            await using (var replay = await target.BeginAsync(plan, schema, database, default))
            {
                Assert.Equal(DeltaExecutionDisposition.AlreadyCommitted, replay.Disposition);
                Assert.Equal(reconciled, replay.ReconciliationSha256);
            }
            Assert.Equal(1L, await CountAsync(cs, "public.\"Probe\""));
            Assert.Equal(1L, await CountAsync(cs, "legacy_migration_internal.delta_journal"));
            ApprovedTargetExtensionStateInspector.Compare(schema, before, await StateAsync(cs, schema));
        }
        finally { await SqlAsync(admin, null, $"DROP DATABASE \"{database}\" WITH (FORCE);"); }
    }

    private static async Task<ApprovedTargetExtensionState> StateAsync(string cs, DatabaseSchemaPlan schema)
    {
        await using var c = new NpgsqlConnection(cs);
        await c.OpenAsync();
        await using var tx = await c.BeginTransactionAsync();
        var state = await ApprovedTargetExtensionStateInspector.InspectAsync(c, tx, schema, default);
        await tx.RollbackAsync();
        return state;
    }

    private static async Task<long> CountAsync(string cs, string table)
    {
        await using var c = new NpgsqlConnection(cs);
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand($"SELECT count(*) FROM {table};", c);
        return (long)(await cmd.ExecuteScalarAsync())!;
    }

    private static async Task SqlAsync(NpgsqlConnection c, NpgsqlTransaction? tx, string sql)
    {
        await using var cmd = new NpgsqlCommand(sql, c, tx);
        _ = await cmd.ExecuteNonQueryAsync();
    }

    private static string SeedSql(string database)
    {
        return database switch
        {
            "CustomerIdentity" => """
            ALTER SEQUENCE public."CustomerIdentityCreateOperations_Id_seq" RESTART WITH 3000000000;
            INSERT INTO public."CustomerIdentityCreateOperations"
                ("ServiceSubject","OperationKey","DatabaseId","IdentityId","PayloadSalt","PayloadHash")
            VALUES ('service:synthetic','11111111-1111-1111-1111-111111111111',1,'synthetic',decode(repeat('ab',16),'hex'),decode(repeat('cd',32),'hex'));
            """,
            "EmployeeIdentity" => """
            INSERT INTO public."EmployeeRecoveryEffects"
                ("ActionId","TokenSha256","Purpose","OwnerSubject","IdentityId","NormalizedEmail",
                 "BeforeSecurityStamp","AfterSecurityStamp","AfterConcurrencyStamp","PasswordPayloadHash","AppliedAt","FinalizedAcknowledgedAt")
            VALUES ('11111111-1111-1111-1111-111111111111',repeat('a',64),'employee-password-reset',
                'service:synthetic','synthetic','SYNTHETIC@EXAMPLE.INVALID','before','after','concurrency','synthetic-salted-hash','2031-01-01Z',NULL);
            """,
            "Invoice" => """
            INSERT INTO public."InvoiceCreationAdmission"
                ("OperationID","QuotationID","EmployeeSubject","ServiceSubject","IntentFingerprint","State","ResultJson","CreatedAt","UpdatedAt")
            VALUES ('11111111-1111-1111-1111-111111111111',1,'synthetic','service:synthetic',repeat('a',64),'synthetic','{"ID":1}','2031-01-01Z','2031-01-01Z');
            INSERT INTO public."InvoiceNotificationCorrelation"
                ("IntentID","InvoiceID","Purpose","QuotationID","WorkflowOperationID","OriginIssuer","OriginEmployeeSubject","OriginServiceSubject",
                 "SenderIssuer","SenderServiceSubject","PayloadFrameVersion","BindingVersion","BindingKeyID","PayloadBinding","Phase","Version","CreatedAt","UpdatedAt")
            VALUES ('11111111-1111-1111-1111-111111111111',1,'invoice-issued',1,'22222222-2222-2222-2222-222222222222',
                'synthetic-issuer','synthetic','service:synthetic','synthetic-issuer','service:legacy-accounting',
                'notification-payload-v1','accounting-invoice-notification-hmac-v1','synthetic-key',decode(repeat('ab',32),'hex'),'Prepared',1,'2031-01-01Z','2031-01-01Z');
            """,
            _ => throw new ArgumentOutOfRangeException(nameof(database)),
        };
    }
}
