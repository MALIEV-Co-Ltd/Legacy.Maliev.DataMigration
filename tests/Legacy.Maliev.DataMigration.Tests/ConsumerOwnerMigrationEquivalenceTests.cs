using System.Diagnostics;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

/// <summary>Actual pinned owner EF Up migrations, not an independently transcribed schema.</summary>
[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class ConsumerOwnerMigrationEquivalenceTests(PostgreSqlAdapterFixture fixture)
{
    [Theory]
    [InlineData("Invoice", "accounting-invoice-authority-v1")]
    [InlineData("CustomerIdentity", "auth-customer-create-authority-v1")]
    [InlineData("EmployeeIdentity", "auth-employee-recovery-authority-v1")]
    public async Task ActualOwnerMigrations_MatchIndependentReceiptComponentsAndCompleteInventory(string database, string profile)
    {
        await WithDatabaseAsync(async (connectionString, name, runId) =>
        {
            string[] applied = await MigrateAsync(database, connectionString, name, runId);
            Assert.Equal(ExpectedMigrations(database), applied);
            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync();
            var inventory = new List<string>();
            await using (var command = new NpgsqlCommand("SELECT n.nspname||'.'||c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' ORDER BY 1;", connection))
            await using (var reader = await command.ExecuteReaderAsync())
            { while (await reader.ReadAsync()) { inventory.Add(reader.GetString(0)); } }
            Assert.Equal(ExpectedTables(database).Order(StringComparer.Ordinal), inventory);
            var schema = Plan(database, profile);
            await using var transaction = await connection.BeginTransactionAsync();
            await using var inspection = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
            var (SchemaSha256, Components, Columns) = await inspection.InspectSchemaWithComponentsAsync(schema, default);
            foreach (var table in ApprovedTargetExtensionManifest.TablesFor(schema))
            {
                var actual = Assert.Single(Components, component => component.Schema == "public" && component.Table == table.TargetTable);
                Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpectedComponents(table), actual);
                await using var physical = new NpgsqlCommand("""
                    SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                    WHERE n.nspname='public' AND c.relname=@table AND
                        (c.relrowsecurity OR c.relforcerowsecurity OR
                         EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal) OR
                         EXISTS(SELECT 1 FROM pg_constraint k WHERE k.conrelid=c.oid AND k.condeferrable));
                    """, connection, transaction);
                _ = physical.Parameters.AddWithValue("table", table.TargetTable);
                Assert.Equal(0L, await physical.ExecuteScalarAsync());
            }
            await ConsumerTargetExtensionSequenceValidator.ValidateAsync(connection, transaction, schema, default);
        });
    }

    [Theory]
    [InlineData("Invoice", "accounting-invoice-authority-v1")]
    [InlineData("CustomerIdentity", "auth-customer-create-authority-v1")]
    [InlineData("EmployeeIdentity", "auth-employee-recovery-authority-v1")]
    public async Task ActualOwnerRestart_PreservesNonemptyReceiptDigestsAndAdvancedBigint(string database, string profile)
    {
        await WithDatabaseAsync(async (connectionString, name, runId) =>
        {
            _ = await MigrateAsync(database, connectionString, name, runId);
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using var seed = new NpgsqlCommand(SeedSql(database), connection);
                _ = await seed.ExecuteNonQueryAsync();
            }
            var schema = Plan(database, profile);
            var before = await StateAsync(connectionString, schema);
            Assert.All(before.Tables, table => Assert.Equal(1, table.RowCount));
            if (database == "CustomerIdentity")
            { Assert.Equal(3000000001L, before.SequenceNextValues["public.CustomerIdentityCreateOperations.Id"]); }
            Assert.Equal(ExpectedMigrations(database), await MigrateAsync(database, connectionString, name, runId));
            var after = await StateAsync(connectionString, schema);
            ApprovedTargetExtensionStateInspector.Compare(schema, before, after);
            Assert.Equal(ApprovedTargetExtensionStateInspector.ComputeSha256(schema, before),
                ApprovedTargetExtensionStateInspector.ComputeSha256(schema, after));
        });
    }

    [Theory]
    [InlineData("host")]
    [InlineData("database")]
    [InlineData("run")]
    [InlineData("marker")]
    [InlineData("context")]
    [InlineData("deployment")]
    public async Task Helper_UnownedRequestRejectsBeforeAnyMigration(string change)
    {
        await WithDatabaseAsync(async (connectionString, name, runId) =>
        {
            string context = "CustomerIdentity";
            if (change == "host") { connectionString = new NpgsqlConnectionStringBuilder(connectionString) { Host = "192.0.2.1" }.ConnectionString; }
            if (change == "database") { connectionString = new NpgsqlConnectionStringBuilder(connectionString) { Database = "postgres" }.ConnectionString; }
            if (change == "run") { runId = Guid.NewGuid().ToString("N"); }
            if (change == "context") { context = "RefreshSession"; }
            if (change == "marker")
            {
                await using var marked = new NpgsqlConnection(connectionString);
                await marked.OpenAsync();
                await using var command = new NpgsqlCommand($"COMMENT ON DATABASE \"{name}\" IS NULL;", marked);
                _ = await command.ExecuteNonQueryAsync();
            }
            var (ExitCode, Output, Error) = await InvokeAsync(context, connectionString, name, runId, change == "deployment" ? "true" : "false");
            Assert.Equal(1, ExitCode);
            Assert.Equal(string.Empty, Output);
            Assert.Equal("owner_migration_proof_failed", Error.Trim());
            string owned = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = name, Pooling = false }.ConnectionString;
            await using var connection = new NpgsqlConnection(owned);
            await connection.OpenAsync();
            await using var count = new NpgsqlCommand("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','S');", connection);
            Assert.Equal(0L, await count.ExecuteScalarAsync());
        });
    }

    private static async Task<ApprovedTargetExtensionState> StateAsync(string connectionString, DatabaseSchemaPlan schema)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        return await ApprovedTargetExtensionStateInspector.InspectAsync(connection, transaction, schema, default);
    }

    private async Task WithDatabaseAsync(Func<string, string, string, Task> action)
    {
        string runId = Guid.NewGuid().ToString("N");
        string name = "owner_ef_proof_" + runId;
        await using var admin = new NpgsqlConnection(fixture.ConnectionString);
        await admin.OpenAsync();
        await using (var create = new NpgsqlCommand($"CREATE DATABASE \"{name}\" TEMPLATE template0;", admin))
        { _ = await create.ExecuteNonQueryAsync(); }
        try
        {
            await using (var mark = new NpgsqlCommand($"COMMENT ON DATABASE \"{name}\" IS 'owner-ef-proof:{runId}';", admin))
            { _ = await mark.ExecuteNonQueryAsync(); }
            string connectionString = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = name, Pooling = false }.ConnectionString;
            await action(connectionString, name, runId);
        }
        finally
        {
            await using var drop = new NpgsqlCommand($"DROP DATABASE \"{name}\" WITH (FORCE);", admin);
            _ = await drop.ExecuteNonQueryAsync();
        }
    }

    private static async Task<string[]> MigrateAsync(string context, string connectionString, string database, string runId)
    {
        var (ExitCode, Output, Error) = await InvokeAsync(context, connectionString, database, runId, "false");
        Assert.Equal(0, ExitCode);
        Assert.Equal(string.Empty, Error);
        return JsonSerializer.Deserialize<string[]>(Output)!;
    }

    private static async Task<(int ExitCode, string Output, string Error)> InvokeAsync(string context, string connectionString, string database, string runId, string deployment)
    {
        string? dll = Environment.GetEnvironmentVariable("MALIEV_CONSUMER_OWNER_EF_PROOF_DLL");
        Assert.True(!string.IsNullOrWhiteSpace(dll) && File.Exists(dll), "The mandatory pinned owner migration proof binary is missing.");
        var start = new ProcessStartInfo("dotnet") { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        start.ArgumentList.Add(dll!);
        string? path = Environment.GetEnvironmentVariable("PATH");
        string? systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
        start.Environment.Clear();
        if (path is not null) { start.Environment["PATH"] = path; }
        if (systemRoot is not null) { start.Environment["SystemRoot"] = systemRoot; }
        start.Environment["LEGACY_DEPLOY_ENABLED"] = deployment;
        using var process = Process.Start(start)!;
        Task<string> stdout = process.StandardOutput.ReadToEndAsync();
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        try
        {
            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new { Context = context, ConnectionString = connectionString, Database = database, RunId = runId }));
            process.StandardInput.Close();
            await process.WaitForExitAsync(deadline.Token);
            return (process.ExitCode, await stdout, await stderr);
        }
        finally
        {
            if (!process.HasExited) { process.Kill(entireProcessTree: true); }
            using var drain = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await process.WaitForExitAsync(drain.Token);
            _ = await Task.WhenAll(stdout, stderr).WaitAsync(drain.Token);
        }
    }

    private static DatabaseSchemaPlan Plan(string database, string profile)
    {
        return new(database, "1.0", new string('a', 64), new string('0', 64), []) { TargetExtensionProfile = profile };
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

    private static string[] ExpectedTables(string database)
    {
        return database switch
        {
            "Invoice" => ["public.Invoice", "public.InvoiceFile", "public.OrderItem", "public.InvoiceCreationAdmission", "public.InvoiceNotificationCorrelation", "public.__EFMigrationsHistory"],
            "CustomerIdentity" => ["public.AspNetUsers", "public.CustomerIdentityCreateOperations", "public.__EFMigrationsHistory"],
            "EmployeeIdentity" => ["public.AspNetUsers", "public.EmployeeRecoveryEffects", "public.__EFMigrationsHistory"],
            _ => throw new ArgumentOutOfRangeException(nameof(database)),
        };
    }

    private static string[] ExpectedMigrations(string database)
    {
        return database switch
        {
            "Invoice" => ["20260715055541_InitialPostgres", "20260721024204_FixTimestampAndInvoiceColumnCasing", "20260905113336_AddInvoiceMarketingAttribution", "20260928094829_AddInvoiceCreationAdmission", "20261001105037_AddInvoiceNotificationCorrelation", "20261001133820_RetainInvoiceNotificationReceipt"],
            "CustomerIdentity" => ["202607150001_InitialCustomerIdentityPostgres", "202609070001_AddCustomerPasswordSetupLifecycle", "202609260001_AddCustomerIdentityCreateOperations"],
            "EmployeeIdentity" => ["202607150002_InitialEmployeeIdentityPostgres", "202609300001_AddEmployeeRecoveryEffects"],
            _ => throw new ArgumentOutOfRangeException(nameof(database)),
        };
    }
}
