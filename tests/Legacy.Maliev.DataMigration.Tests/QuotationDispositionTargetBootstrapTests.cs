using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class QuotationDispositionTargetBootstrapTests(PostgreSqlAdapterFixture fixture)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task DisposableAuthorization_RejectsPhysicalDriftBeforeSigningOrDdl()
    {
        await using var container = new PostgreSqlBuilder("postgres:18-alpine").Build();
        await container.StartAsync();
        string admin = container.GetConnectionString();
        await ExecuteAsync(admin, "CREATE DATABASE \"Quotation\";");
        string connection = new NpgsqlConnectionStringBuilder(admin) { Database = "Quotation" }.ConnectionString;
        DatabaseSchemaPlan quotation = QuotationPlan();
        DatabaseSchemaPlan sourceShape = quotation with
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
        var authority = new DeltaTargetAuthority(DeltaTargetAuthorityKind.LocalAspire,
            "aspire://legacy-postgres-main-local/disposable-quotation-preflight", await IdentityAsync(connection));
        FreshSchemaPlan schema = new("2.0", DateTimeOffset.UtcNow, new string('a', 40),
            [.. DatabaseInventory.ActiveDatabases.Select(name => name == "Quotation" ? quotation :
                new DatabaseSchemaPlan(name, "1.0", new string('a', 64), new string('a', 64), []))]);
        string root = Path.Combine(Path.GetTempPath(), $"quotation-bootstrap-preflight-{Guid.NewGuid():N}");
        OwnerProtectedDirectory.CreateNew(root);
        try
        {
            string schemaPath = Path.Combine(root, "schema.json");
            string connectionPath = Path.Combine(root, "connection.txt");
            string signerPath = Path.Combine(root, "signer.pem");
            string trustPath = Path.Combine(root, "trust.b64");
            string configPath = Path.Combine(root, "config.json");
            string authorizationPath = Path.Combine(root, "authorization.json");
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            await File.WriteAllTextAsync(schemaPath, JsonSerializer.Serialize(schema, JsonOptions));
            await File.WriteAllTextAsync(connectionPath, admin);
            await File.WriteAllTextAsync(signerPath, key.ExportECPrivateKeyPem());
            await File.WriteAllTextAsync(trustPath, Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
            await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new
            {
                quotationTargetBootstrap = new
                {
                    schemaPlanPath = schemaPath,
                    targetConnectionFile = connectionPath,
                    targetAuthority = authority,
                    authorizationKey = new { keyId = "quotation-preflight-test", subjectPublicKeyInfoPath = trustPath },
                    outputPath = authorizationPath,
                    authorizationExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                    allowAuthorizationSigning = true,
                    allowExecution = false,
                },
            }, JsonOptions));
            foreach (string path in new[] { schemaPath, connectionPath, signerPath, trustPath, configPath })
            {
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
            }

            await ExecuteAsync(connection,
                "ALTER TABLE public.\"QuotationOutcomeOutbox\" ADD COLUMN \"UnexpectedDrift\" integer;");
            using var error = new StringWriter();
            int rejected = await MigrationConsole.RunQuotationTargetBootstrapForTestsAsync(
                ["authorize-quotation-target-bootstrap", "--config", configPath], TextWriter.Null, error,
                name => name switch
                {
                    "LEGACY_DEPLOY_ENABLED" => "false",
                    "LEGACY_MIGRATION_CALLER" => "owner",
                    "LEGACY_MIGRATION_QUOTATION_BOOTSTRAP_AUTHORIZATION_SIGNING_KEY_FILE" => signerPath,
                    _ => null,
                }, CancellationToken.None);
            Assert.Equal(65, rejected);
            Assert.Equal("quotation_target_bootstrap_schema_drift" + Environment.NewLine, error.ToString());
            Assert.False(File.Exists(authorizationPath));
            Assert.Null(await TextOrNullAsync(connection,
                "SELECT to_regclass('legacy_compatibility.\"GoogleAnalyticsOutbox\"')::text;"));
            Assert.Null(await TextOrNullAsync(connection,
                "SELECT to_regclass('public.\"QuotationAcceptedOutcome\"')::text;"));

            await ExecuteAsync(connection, "ALTER TABLE public.\"QuotationOutcomeOutbox\" DROP COLUMN \"UnexpectedDrift\";");
            using var successError = new StringWriter();
            int authorized = await MigrationConsole.RunQuotationTargetBootstrapForTestsAsync(
                ["authorize-quotation-target-bootstrap", "--config", configPath], TextWriter.Null, successError,
                name => name switch
                {
                    "LEGACY_DEPLOY_ENABLED" => "false",
                    "LEGACY_MIGRATION_CALLER" => "owner",
                    "LEGACY_MIGRATION_QUOTATION_BOOTSTRAP_AUTHORIZATION_SIGNING_KEY_FILE" => signerPath,
                    _ => null,
                }, CancellationToken.None);
            Assert.Equal(0, authorized);
            Assert.Equal(string.Empty, successError.ToString());
            Assert.True(File.Exists(authorizationPath));
            Assert.Null(await TextOrNullAsync(connection,
                "SELECT to_regclass('legacy_compatibility.\"GoogleAnalyticsOutbox\"')::text;"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Bootstrap_AddsOnlyReviewedTargets_AndPreservesRetainedRows()
    {
        (PostgreSqlShadowTarget target, ShadowDatabase shadow, DatabaseSchemaPlan plan, string connection) =
            await CreateSourceShapedAsync();
        try
        {
            string identity = await IdentityAsync(connection);
            Assert.Equal("source-shaped", await QuotationDispositionTargetBootstrap.PreflightAsync(
                plan, connection, shadow.Name, identity, CancellationToken.None));
            Assert.Null(await TextOrNullAsync(connection,
                "SELECT to_regclass('legacy_compatibility.\"GoogleAnalyticsOutbox\"')::text;"));
            Assert.Null(await TextOrNullAsync(connection,
                "SELECT to_regclass('public.\"QuotationAcceptedOutcome\"')::text;"));
            Assert.Equal("created", await QuotationDispositionTargetBootstrap.ExecuteAsync(
                plan, connection, shadow.Name, identity, CancellationToken.None));
            Assert.Equal("already-current", await QuotationDispositionTargetBootstrap.PreflightAsync(
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

        DeltaSynchronizationPlan transitionPlan = plan with
        {
            SchemaVersion = "1.4",
            TargetNamespace = "local-aspire",
            TargetCluster = "legacy-postgres-main-local",
            TargetAuthority = new(DeltaTargetAuthorityKind.LocalAspire,
                "aspire://legacy-postgres-main-local/disposable-quotation-atomic", await IdentityAsync(connection)),
            QuotationTransitionSchemaSha256 =
                PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(schema, true),
            SourceCaptureManifest = new DeltaSourceCaptureManifest(new string('a', 64), []),
        };
        await using (var db = new NpgsqlConnection(connection))
        {
            await db.OpenAsync();
            await using var tx = await db.BeginTransactionAsync();
            DeltaPlanException changedHash = await Assert.ThrowsAsync<DeltaPlanException>(() =>
                PostgreSqlDeltaMetadataProvisioner.ProvisionDatabaseAsync(db, tx,
                    transitionPlan with { QuotationTransitionSchemaSha256 = new string('0', 64) },
                    schema, CancellationToken.None));
            Assert.Equal("delta_quotation_transition_plan_invalid", changedHash.Code);
            await tx.RollbackAsync();
        }
        Assert.Null(await TextOrNullAsync(connection,
            "SELECT to_regclass('legacy_migration_internal.delta_journal')::text;"));
        await using (var db = new NpgsqlConnection(connection))
        {
            await db.OpenAsync();
            await using var tx = await db.BeginTransactionAsync();
            await PostgreSqlDeltaMetadataProvisioner.ProvisionDatabaseAsync(db, tx, transitionPlan,
                schema, CancellationToken.None);
            await tx.CommitAsync();
        }
        Assert.Equal(transitionPlan.QuotationTransitionSchemaSha256,
            await TextOrNullAsync(connection,
                "SELECT target_schema_sha256 FROM legacy_migration_internal.delta_fence WHERE database_name='Quotation';"));
        await using (IDeltaCanonicalTransaction accepted = await target.BeginAsync(
            transitionPlan, schema, "Quotation", CancellationToken.None))
        {
            Assert.NotNull(accepted);
        }
        Assert.Equal(1L, await ScalarAsync(connection,
            "SELECT COUNT(*) FROM public.\"QuotationOutcomeOutbox\" WHERE \"ID\"=7;"));
        Assert.Equal(0L, await ScalarAsync(connection,
            "SELECT COUNT(*) FROM legacy_migration_internal.delta_journal;"));
        await ExecuteAsync(connection,
            "ALTER TABLE public.\"QuotationOutcomeOutbox\" ADD COLUMN \"UnexpectedDrift\" integer;");
        MigrationExecutionException physicalDrift = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            target.BeginAsync(transitionPlan, schema, "Quotation", CancellationToken.None));
        Assert.Equal("shadow_reconciliation_failed", physicalDrift.Code);
        Assert.Equal(0L, await ScalarAsync(connection,
            "SELECT COUNT(*) FROM legacy_migration_internal.delta_journal;"));
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
            MigrationExecutionException preflight = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                QuotationDispositionTargetBootstrap.PreflightAsync(plan, connection, shadow.Name,
                    identity, CancellationToken.None));
            Assert.Equal(code, preflight.Code);
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
            MigrationExecutionException preflightIdentity = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                QuotationDispositionTargetBootstrap.PreflightAsync(plan, connection, shadow.Name,
                    new string('0', 64), CancellationToken.None));
            Assert.Equal("quotation_target_bootstrap_identity_invalid", preflightIdentity.Code);
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
