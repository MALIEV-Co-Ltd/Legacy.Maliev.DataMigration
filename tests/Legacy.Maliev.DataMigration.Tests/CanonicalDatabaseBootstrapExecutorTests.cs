using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class CanonicalDatabaseBootstrapExecutorTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task Execute_initializes_only_the_authorized_empty_database_and_returns_a_signed_receipt()
    {
        const string database = "ContactRequest";
        await RecreateDatabaseAsync(database, fixture.AdministratorUsername, revokePublicConnect: true);
        try
        {
            BootstrapFixture bootstrap = await CreateBootstrapAsync(database);

            CanonicalDatabaseBootstrapReceipt receipt = await bootstrap.Executor.ExecuteAsync(
                bootstrap.Request, Connection(database), fixture.AdministratorUsername, CancellationToken.None);

            Assert.Equal(database, receipt.Database);
            Assert.Equal(bootstrap.Authorization.AuthorizationId, receipt.AuthorizationId);
            Assert.Equal(bootstrap.Request.Schema.TargetSchemaSha256, receipt.TargetSchemaSha256);
            Assert.Equal(bootstrap.ExecutionSigner.KeyId, receipt.AttestationKeyId);
            Assert.NotNull(receipt.AttestationSignature);
            Assert.True(bootstrap.ExecutionTrust.Verify(
                receipt.AttestationKeyId,
                CanonicalDatabaseBootstrapReceiptCanonicalizer.CreatePayload(receipt),
                Convert.FromBase64String(receipt.AttestationSignature)));
            Assert.Equal(0L, await ScalarAsync<long>(database, "SELECT count(*) FROM public.\"Items\";"));
        }
        finally
        {
            await DropDatabaseAsync(database);
        }
    }

    [Fact]
    public async Task Execute_refuses_a_nonempty_database_and_preserves_every_existing_object()
    {
        const string database = "ContactRequest";
        await RecreateDatabaseAsync(database, fixture.AdministratorUsername, revokePublicConnect: true);
        await ExecuteAsync(database, "CREATE TABLE public.sentinel(value integer NOT NULL); INSERT INTO public.sentinel VALUES (73);");
        try
        {
            BootstrapFixture bootstrap = await CreateBootstrapAsync(database);

            CanonicalDatabaseBootstrapException error = await Assert.ThrowsAsync<CanonicalDatabaseBootstrapException>(() =>
                bootstrap.Executor.ExecuteAsync(
                    bootstrap.Request, Connection(database), fixture.AdministratorUsername, CancellationToken.None));

            Assert.Equal("canonical_database_bootstrap_target_not_empty", error.Code);
            Assert.Equal(73, await ScalarAsync<int>(database, "SELECT value FROM public.sentinel;"));
            Assert.False(await ScalarAsync<bool>(database, "SELECT to_regclass('public.\"Items\"') IS NOT NULL;"));
        }
        finally
        {
            await DropDatabaseAsync(database);
        }
    }

    [Theory]
    [InlineData("wrong-owner")]
    [InlineData("public-connect")]
    public async Task Execute_refuses_an_unreviewed_database_boundary_before_schema_changes(string scenario)
    {
        const string database = "ContactRequest";
        string owner = scenario == "wrong-owner" ? fixture.ShadowAdminRole : fixture.AdministratorUsername;
        await RecreateDatabaseAsync(database, owner, revokePublicConnect: scenario != "public-connect");
        try
        {
            BootstrapFixture bootstrap = await CreateBootstrapAsync(database);

            CanonicalDatabaseBootstrapException error = await Assert.ThrowsAsync<CanonicalDatabaseBootstrapException>(() =>
                bootstrap.Executor.ExecuteAsync(
                    bootstrap.Request, Connection(database), fixture.AdministratorUsername, CancellationToken.None));

            Assert.Equal("canonical_database_bootstrap_boundary_invalid", error.Code);
            Assert.False(await ScalarAsync<bool>(database, "SELECT to_regclass('public.\"Items\"') IS NOT NULL;"));
        }
        finally
        {
            await DropDatabaseAsync(database);
        }
    }

    [Fact]
    public async Task Execute_rejects_a_wrong_cluster_system_identifier_before_schema_changes()
    {
        const string database = "ContactRequest";
        await RecreateDatabaseAsync(database, fixture.AdministratorUsername, revokePublicConnect: true);
        try
        {
            BootstrapFixture bootstrap = await CreateBootstrapAsync(database, wrongSystemIdentifier: true);

            CanonicalDatabaseBootstrapException error = await Assert.ThrowsAsync<CanonicalDatabaseBootstrapException>(() =>
                bootstrap.Executor.ExecuteAsync(
                    bootstrap.Request, Connection(database), fixture.AdministratorUsername, CancellationToken.None));

            Assert.Equal("canonical_database_bootstrap_system_identifier_invalid", error.Code);
            Assert.False(await ScalarAsync<bool>(database, "SELECT to_regclass('public.\"Items\"') IS NOT NULL;"));
        }
        finally
        {
            await DropDatabaseAsync(database);
        }
    }

    [Fact]
    public async Task Execute_rolls_back_every_schema_object_when_schema_application_fails()
    {
        const string database = "ContactRequest";
        await RecreateDatabaseAsync(database, fixture.AdministratorUsername, revokePublicConnect: true);
        try
        {
            BootstrapFixture bootstrap = await CreateBootstrapAsync(database, invalidCollation: true);

            CanonicalDatabaseBootstrapException error = await Assert.ThrowsAsync<CanonicalDatabaseBootstrapException>(() =>
                bootstrap.Executor.ExecuteAsync(
                    bootstrap.Request, Connection(database), fixture.AdministratorUsername, CancellationToken.None));

            Assert.Equal("canonical_database_bootstrap_schema_apply_failed", error.Code);
            Assert.False(await ScalarAsync<bool>(database, "SELECT to_regclass('public.\"Items\"') IS NOT NULL;"));
        }
        finally
        {
            await DropDatabaseAsync(database);
        }
    }

    private async Task<BootstrapFixture> CreateBootstrapAsync(
        string database,
        bool wrongSystemIdentifier = false,
        bool invalidCollation = false)
    {
        DateTimeOffset now = new(2026, 9, 9, 4, 0, 0, TimeSpan.Zero);
        DatabaseSchemaPlan schema = Schema(database, invalidCollation);
        string systemIdentifier = await ScalarAsync<string>(database, "SELECT system_identifier::text FROM pg_control_system();");
        string systemIdentifierHash = Convert.ToHexString(SHA256.HashData(
            Encoding.ASCII.GetBytes(systemIdentifier))).ToLowerInvariant();
        var authority = new DeltaTargetAuthority(
            DeltaTargetAuthorityKind.ProductionCloudNativePg,
            "gke://maliev-website/us-central1-a/maliev-legacy/legacy-postgres-main/cluster-uid",
            wrongSystemIdentifier ? new string('9', 64) : systemIdentifierHash);
        using ECDsa authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa executionKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var authorizationSigner = new P256MigrationEvidenceSigner("bootstrap-authorization", authorizationKey.ExportECPrivateKeyPem());
        var executionSigner = new P256MigrationEvidenceSigner("bootstrap-execution", executionKey.ExportECPrivateKeyPem());
        var authorizationTrust = new ReceiptAttestationTrustStore(
            [new(authorizationSigner.KeyId, authorizationSigner.ExportSubjectPublicKeyInfo())]);
        var executionTrust = new ReceiptAttestationTrustStore(
            [new(executionSigner.KeyId, executionSigner.ExportSubjectPublicKeyInfo())]);
        CanonicalDatabaseBootstrapAuthorization authorization = CanonicalDatabaseBootstrapAuthorizationProducer.Produce(
            schema, "legacy-postgres-contact-request", "database-uid-1", "17", authority,
            now.AddMinutes(-1), now.AddMinutes(9), authorizationSigner);
        var request = new CanonicalDatabaseBootstrapRequest(
            schema, "legacy-postgres-contact-request", "database-uid-1", "17", authority);
        var executor = new CanonicalDatabaseBootstrapExecutor(
            authorization, authorizationTrust, new FixedTime(now), executionSigner);
        return new(request, authorization, executor, authorizationSigner, executionSigner, executionTrust);
    }

    private string Connection(string database)
    {
        return new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = database,
            Pooling = false,
        }.ConnectionString;
    }

    private async Task RecreateDatabaseAsync(string database, string owner, bool revokePublicConnect)
    {
        await DropDatabaseAsync(database);
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            $"CREATE DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(database)} OWNER {PostgreSqlShadowTarget.QuoteIdentifier(owner)} TEMPLATE template0;" +
            (revokePublicConnect
                ? $" REVOKE CONNECT ON DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(database)} FROM PUBLIC;"
                : string.Empty), connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private async Task DropDatabaseAsync(string database)
    {
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            $"DROP DATABASE IF EXISTS {PostgreSqlShadowTarget.QuoteIdentifier(database)} WITH (FORCE);", connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private async Task ExecuteAsync(string database, string sql)
    {
        await using var connection = new NpgsqlConnection(Connection(database));
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private async Task<T> ScalarAsync<T>(string database, string sql)
    {
        await using var connection = new NpgsqlConnection(Connection(database));
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        return (T)(await command.ExecuteScalarAsync())!;
    }

    private static DatabaseSchemaPlan Schema(string database, bool invalidCollation = false)
    {
        var table = new TableCopyPlan("dbo", "Items", "public", "Items", ["Id"], ["Id"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["Id"] = "integer" },
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["Id"] = "int" },
            PrimaryKey = new("PK_Items", ["Id"]),
            Collations = invalidCollation
                ? new Dictionary<string, string>(StringComparer.Ordinal) { ["Id"] = "missing_collation" }
                : new Dictionary<string, string>(StringComparer.Ordinal),
        };
        var draft = new DatabaseSchemaPlan(database, "1", new string('1', 64), string.Empty, [table]);
        return draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
    }

    private sealed record BootstrapFixture(
        CanonicalDatabaseBootstrapRequest Request,
        CanonicalDatabaseBootstrapAuthorization Authorization,
        CanonicalDatabaseBootstrapExecutor Executor,
        P256MigrationEvidenceSigner AuthorizationSigner,
        P256MigrationEvidenceSigner ExecutionSigner,
        IReceiptAttestationTrustStore ExecutionTrust) : IDisposable
    {
        public void Dispose()
        {
            AuthorizationSigner.Dispose();
            ExecutionSigner.Dispose();
        }
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
}
