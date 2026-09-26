using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class QuotationDispositionTargetBootstrapTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task Bootstrap_AddsOnlyReviewedTargets_AndPreservesRetainedRows()
    {
        (PostgreSqlShadowTarget target, ShadowDatabase shadow, DatabaseSchemaPlan plan, string connection) =
            await CreateSourceShapedAsync();
        try
        {
            string identity = await IdentityAsync(connection);
            Assert.Equal("created", await QuotationDispositionTargetBootstrap.ExecuteAsync(
                plan, connection, shadow.Name, identity, CancellationToken.None));
            Assert.Equal("already-current", await QuotationDispositionTargetBootstrap.ExecuteAsync(
                plan, connection, shadow.Name, identity, CancellationToken.None));
            Assert.Equal(1L, await ScalarAsync(connection,
                "SELECT COUNT(*) FROM public.\"QuotationOutcomeOutbox\" WHERE \"ID\"=7;"));
            Assert.Equal(0L, await ScalarAsync(connection,
                "SELECT COUNT(*) FROM public.\"QuotationAcceptedOutcome\";"));
            Assert.Equal(0L, await ScalarAsync(connection,
                "SELECT COUNT(*) FROM legacy_compatibility.\"GoogleAnalyticsOutbox\";"));
            await using var db = new NpgsqlConnection(connection);
            await db.OpenAsync();
            await using var transaction = await db.BeginTransactionAsync();
            var inspector = new PostgreSqlWholeDatabaseTransaction(db, transaction, ownsResources: false);
            string observedTransition = await inspector.InspectSchemaAsync(plan, CancellationToken.None);
            Assert.Equal(PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(plan, true),
                observedTransition);
            Assert.NotEqual(plan.TargetSchemaSha256,
                PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(plan, true));
            DeltaPlanException retained = Assert.Throws<DeltaPlanException>(() =>
                QuotationDeltaPhysicalSchemaGuard.RequireFinalSchema(plan, observedTransition));
            Assert.Equal("delta_quotation_transition_row_path_not_authorized", retained.Code);
            await transaction.RollbackAsync();
            _ = Assert.Throws<MigrationExecutionException>(() => ReconciliationDiagnostics.CompareSchema(
                plan.Database, plan.TargetSchemaSha256,
                PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(plan, true)));
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task AtomicDeltaBegin_RejectsRetainedTransitionBeforeDmlOrJournal()
    {
        await using var container = new PostgreSqlBuilder("postgres:18-alpine").Build();
        await container.StartAsync();
        string admin = container.GetConnectionString();
        await ExecuteAsync(admin, "CREATE DATABASE \"Quotation\";");
        string connection = new NpgsqlConnectionStringBuilder(admin) { Database = "Quotation" }.ConnectionString;
        DatabaseSchemaPlan schema = QuotationPlan();
        DatabaseSchemaPlan sourceShape = schema with
        {
            Database = "QuotationBootstrapFixture",
            SourceDispositionProfile = null,
            SourceTableDispositions = [],
        };
        await using (var db = new NpgsqlConnection(connection))
        {
            await db.OpenAsync();
            await using var tx = await db.BeginTransactionAsync();
            await using var writer = new PostgreSqlWholeDatabaseTransaction(db, tx, ownsResources: false);
            await writer.ApplySchemaAsync(sourceShape, CancellationToken.None);
            await writer.FinalizeSchemaAsync(sourceShape, CancellationToken.None);
            await tx.CommitAsync();
        }
        await ExecuteAsync(connection,
            "INSERT INTO public.\"QuotationOutcomeOutbox\" (\"ID\", \"EventKey\", \"QuotationID\", \"AcceptedUtc\", \"AcceptanceOrigin\") " +
            "VALUES (7, 'synthetic-7', 42, '2026-09-26 12:00:00', 'customer');");
        Assert.Equal("created", await QuotationDispositionTargetBootstrap.ExecuteAsync(schema, connection,
            "Quotation", await IdentityAsync(connection), CancellationToken.None));

        var target = new PostgreSqlDeltaCanonicalTarget(new(connection, "Quotation", "generation-1"));
        DeltaSynchronizationPlan plan = DeltaPlan();
        DeltaPlanException retained = await Assert.ThrowsAsync<DeltaPlanException>(() =>
            target.BeginAsync(plan, schema, "Quotation", CancellationToken.None));
        Assert.Equal("delta_quotation_transition_row_path_not_authorized", retained.Code);
        Assert.Equal(1L, await ScalarAsync(connection,
            "SELECT COUNT(*) FROM public.\"QuotationOutcomeOutbox\" WHERE \"ID\"=7;"));
        Assert.Equal(0L, await ScalarAsync(connection,
            "SELECT COUNT(*) FROM public.\"QuotationAcceptedOutcome\";"));
        Assert.Equal(0L, await ScalarAsync(connection,
            "SELECT COUNT(*) FROM legacy_compatibility.\"GoogleAnalyticsOutbox\";"));
        Assert.Null(await TextOrNullAsync(connection,
            "SELECT to_regclass('legacy_migration_internal.delta_journal')::text;"));

        MigrationExecutionException tampered = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            target.BeginAsync(plan, schema with { TargetSchemaSha256 = new string('0', 64) },
                "Quotation", CancellationToken.None));
        Assert.Equal("quotation_target_bootstrap_plan_invalid", tampered.Code);
        Assert.Null(await TextOrNullAsync(connection,
            "SELECT to_regclass('legacy_migration_internal.delta_journal')::text;"));
    }

    [Fact]
    public async Task Disposable_postcommit_transition_can_be_signed_but_not_reused_for_same_cluster()
    {
        (PostgreSqlShadowTarget target, ShadowDatabase shadow, DatabaseSchemaPlan plan, string connection) =
            await CreateSourceShapedAsync();
        try
        {
            string identity = await IdentityAsync(connection);
            string disposition = await QuotationDispositionTargetBootstrap.ExecuteAsync(plan, connection,
                shadow.Name, identity, CancellationToken.None);
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var signer = new P256MigrationEvidenceSigner("disposable-quotation-evidence",
                key.ExportECPrivateKeyPem());
            var trust = new ReceiptAttestationTrustStore(
                [new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
            var disposable = new DeltaTargetAuthority(DeltaTargetAuthorityKind.LocalAspire,
                "aspire://legacy-postgres-main-local/disposable-integration", identity);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            QuotationTargetBootstrapProof proof = QuotationTargetBootstrapProofProducer.Produce(plan,
                new string('a', 40), disposable, new string('b', 64), disposition, now, signer);
            Assert.True(QuotationTargetBootstrapProofVerifier.Verify(proof, plan, new string('a', 40),
                new DeltaTargetAuthority(DeltaTargetAuthorityKind.LocalAspire,
                    "aspire://legacy-postgres-main-local/persistent-synthetic", new string('c', 64)),
                trust, now));
            Assert.False(QuotationTargetBootstrapProofVerifier.Verify(proof, plan, new string('a', 40),
                new DeltaTargetAuthority(DeltaTargetAuthorityKind.LocalAspire,
                    "aspire://legacy-postgres-main-local/persistent-same-cluster", identity),
                trust, now));
            Assert.Equal("already-current", await QuotationDispositionTargetBootstrap.ExecuteAsync(
                plan, connection, shadow.Name, identity, CancellationToken.None));
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Theory]
    [InlineData("CREATE TABLE public.\"Unexpected\" (\"ID\" integer);", "quotation_target_bootstrap_schema_drift")]
    [InlineData("CREATE TABLE public.\"QuotationAcceptedOutcome\" (\"ID\" bigint);", "quotation_target_bootstrap_missing_set_invalid")]
    [InlineData("ALTER TABLE public.\"QuotationOutcomeOutbox\" ADD \"Drift\" integer;", "quotation_target_bootstrap_schema_drift")]
    public async Task Bootstrap_RejectsDriftWithoutCreatingTargets(string ddl, string code)
    {
        (PostgreSqlShadowTarget target, ShadowDatabase shadow, DatabaseSchemaPlan plan, string connection) =
            await CreateSourceShapedAsync();
        try
        {
            await ExecuteAsync(connection, ddl);
            string identity = await IdentityAsync(connection);
            MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                QuotationDispositionTargetBootstrap.ExecuteAsync(plan, connection, shadow.Name,
                    identity, CancellationToken.None));
            Assert.Equal(code, failure.Code);
            Assert.Equal(0L, await ScalarAsync(connection,
                "SELECT COUNT(*) FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n " +
                "ON n.oid=c.relnamespace WHERE n.nspname='legacy_compatibility' AND c.relname='GoogleAnalyticsOutbox';"));
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task Bootstrap_RejectsWrongTargetIdentityAndSignedPlan()
    {
        (PostgreSqlShadowTarget target, ShadowDatabase shadow, DatabaseSchemaPlan plan, string connection) =
            await CreateSourceShapedAsync();
        try
        {
            MigrationExecutionException identity = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                QuotationDispositionTargetBootstrap.ExecuteAsync(plan, connection, shadow.Name,
                    new string('0', 64), CancellationToken.None));
            Assert.Equal("quotation_target_bootstrap_identity_invalid", identity.Code);
            string validIdentity = await IdentityAsync(connection);
            MigrationExecutionException planError = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                QuotationDispositionTargetBootstrap.ExecuteAsync(plan with { TargetSchemaSha256 = new string('0', 64) },
                    connection, shadow.Name, validIdentity, CancellationToken.None));
            Assert.Equal("quotation_target_bootstrap_plan_invalid", planError.Code);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Fact]
    public async Task Bootstrap_RejectsMissingRetainedTableAndPostCommitSequenceDrift()
    {
        (PostgreSqlShadowTarget target, ShadowDatabase shadow, DatabaseSchemaPlan plan, string connection) =
            await CreateSourceShapedAsync();
        try
        {
            string identity = await IdentityAsync(connection);
            await ExecuteAsync(connection, "DROP TABLE public.\"GoogleAnalyticsOutbox\";");
            MigrationExecutionException missing = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                QuotationDispositionTargetBootstrap.ExecuteAsync(plan, connection, shadow.Name,
                    identity, CancellationToken.None));
            Assert.Equal("quotation_target_bootstrap_retained_set_invalid", missing.Code);
            // Restore the exact source shape only inside the disposable database.
            DatabaseSchemaPlan sourceTable = plan with
            {
                Database = "QuotationBootstrapFixture",
                Tables = [plan.Tables.Single(table => table.SourceTable == "GoogleAnalyticsOutbox")],
                SourceDispositionProfile = null,
                SourceTableDispositions = [],
            };
            await using (var db = new NpgsqlConnection(connection))
            {
                await db.OpenAsync();
                await using var tx = await db.BeginTransactionAsync();
                var writer = new PostgreSqlWholeDatabaseTransaction(db, tx, ownsResources: false);
                await writer.ApplySchemaAsync(sourceTable, CancellationToken.None);
                await writer.FinalizeSchemaAsync(sourceTable, CancellationToken.None);
                await tx.CommitAsync();
            }
            Assert.Equal("created", await QuotationDispositionTargetBootstrap.ExecuteAsync(plan,
                connection, shadow.Name, identity, CancellationToken.None));
            await ExecuteAsync(connection,
                "ALTER SEQUENCE public.\"QuotationAcceptedOutcome_ID_seq\" INCREMENT BY 2;");
            MigrationExecutionException sequence = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                QuotationDispositionTargetBootstrap.VerifyPostCommitAsync(plan, connection, shadow.Name,
                    identity, CancellationToken.None));
            Assert.Equal("quotation_target_bootstrap_sequence_drift", sequence.Code);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    private async Task<(PostgreSqlShadowTarget, ShadowDatabase, DatabaseSchemaPlan, string)> CreateSourceShapedAsync()
    {
        DatabaseSchemaPlan plan = QuotationPlan();
        TableCopyPlan[] tables = [.. plan.Tables];
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync("Quotation",
            $"legacy_shadow_quote_bootstrap_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), CancellationToken.None);
        DatabaseSchemaPlan sourceShape = plan with
        {
            Database = "QuotationBootstrapFixture",
            SourceDispositionProfile = null,
            SourceTableDispositions = [],
        };
        await using (IPostgreSqlWholeDatabaseTransaction transaction =
            await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None))
        {
            await transaction.ApplySchemaAsync(sourceShape, CancellationToken.None);
            await transaction.FinalizeSchemaAsync(sourceShape, CancellationToken.None);
            _ = await transaction.InspectSchemaAsync(sourceShape, CancellationToken.None);
            foreach (TableCopyPlan table in tables)
            {
                _ = await transaction.InspectTableAsync(table, CancellationToken.None);
            }
            await transaction.CommitAsync(CancellationToken.None);
        }
        string connection = new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString)
        {
            Database = shadow.Name,
        }.ConnectionString;
        await ExecuteAsync(connection,
            "INSERT INTO public.\"QuotationOutcomeOutbox\" (\"ID\", \"EventKey\", \"QuotationID\", \"AcceptedUtc\", \"AcceptanceOrigin\") " +
            "VALUES (7, 'synthetic-7', 42, '2026-09-26 12:00:00', 'customer');");
        return (target, shadow, plan, connection);
    }

    private static DatabaseSchemaPlan QuotationPlan()
    {
        TableCopyPlan[] tables =
        [
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
        ];
        var draft = new DatabaseSchemaPlan("Quotation", "1.0", new string('a', 64), new string('0', 64), tables)
        {
            SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
            SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables),
        };
        return draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
    }

    private static DeltaSynchronizationPlan DeltaPlan()
    {
        const string hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        return new("1.0", Guid.NewGuid(), new string('1', 40), DateTimeOffset.UtcNow, hash, hash, hash,
            "maliev-legacy", "legacy-postgres-main", "generation-1", hash, hash, hash,
            DateTimeOffset.UtcNow, [new DeltaDatabasePlan("Quotation", [])], "test", null);
    }

    private static async Task<string> IdentityAsync(string connection)
    {
        await using var db = new NpgsqlConnection(connection);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT system_identifier::text FROM pg_control_system();", db);
        string value = (string)(await command.ExecuteScalarAsync() ?? throw new InvalidOperationException());
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    private static async Task ExecuteAsync(string connection, string sql)
    {
        await using var db = new NpgsqlConnection(connection);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand(sql, db);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static async Task<long> ScalarAsync(string connection, string sql)
    {
        await using var db = new NpgsqlConnection(connection);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand(sql, db);
        return (long)(await command.ExecuteScalarAsync() ?? throw new InvalidOperationException());
    }

    private static async Task<string?> TextOrNullAsync(string connection, string sql)
    {
        await using var db = new NpgsqlConnection(connection);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand(sql, db);
        return await command.ExecuteScalarAsync() as string;
    }
}
