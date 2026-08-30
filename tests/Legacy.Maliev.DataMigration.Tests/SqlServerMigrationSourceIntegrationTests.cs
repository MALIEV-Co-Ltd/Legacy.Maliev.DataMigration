using Microsoft.Data.SqlClient;
using Testcontainers.MsSql;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SqlServerIntegrationFactAttribute : FactAttribute
{
    public SqlServerIntegrationFactAttribute()
    {
        if (!string.Equals(
            Environment.GetEnvironmentVariable("MALIEV_RUN_SQLSERVER_INTEGRATION"),
            "1",
            StringComparison.Ordinal))
        {
            Skip = "SQL Server container execution is explicitly gated: set MALIEV_RUN_SQLSERVER_INTEGRATION=1 when Docker can pull the licensed SQL Server image.";
        }
    }
}

public sealed class SqlServerMigrationSourceIntegrationTests
{
    [SqlServerIntegrationFact]
    public async Task BackupRestoreTarget_RestoresFromPrivateReadOnlyContainerMountWithoutReplacement()
    {
        const string password = "MALIEV_test_Only!123456";
        const string image = "mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04";
        string root = Path.Combine(Path.GetTempPath(), $"verified-restore-e2e-{Guid.NewGuid():N}");
        string volume = $"legacy-restore-{Guid.NewGuid():N}";
        string targetContainerName = $"legacy-restore-sql-{Guid.NewGuid():N}";
        OwnerProtectedDirectory.CreateNew(root);
        const string backupFileName = "Full_Country_run-1.bak";
        string localBackup = Path.Combine(root, backupFileName);
        DockerRestoreResources? restoreResources = null;
        try
        {
            await using (MsSqlContainer producer = new MsSqlBuilder(image)
                .WithPassword(password)
                .Build())
            {
                await producer.StartAsync();
                await using var connection = new SqlConnection(producer.GetConnectionString());
                await connection.OpenAsync();
                foreach (string sql in new[] {
                    "CREATE DATABASE [Country];",
                    "CREATE TABLE [Country].dbo.Probe(Id int NOT NULL PRIMARY KEY, Value nvarchar(20) NOT NULL); INSERT [Country].dbo.Probe VALUES (1, N'custody-ok');",
                    $"BACKUP DATABASE [Country] TO DISK=N'/var/opt/mssql/backup/{backupFileName}' WITH COPY_ONLY, CHECKSUM, INIT;",
                })
                {
                    await using var command = new SqlCommand(sql, connection) { CommandTimeout = 0 };
                    _ = await command.ExecuteNonQueryAsync();
                }
                await DockerCopyAsync(producer.Id, $"/var/opt/mssql/backup/{backupFileName}", localBackup);
            }

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(localBackup, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            SecureLocalFile.EnsureOwnerOnlyDirectory(root);
            Assert.True(SecureLocalFile.IsOwnerOnlyFile(new FileInfo(localBackup)));

            string pinnedImage = await DockerInspectAsync(image, "{{index .RepoDigests 0}}");
            string targetImageId = await DockerInspectAsync(image, "{{.Id}}");
            const string stagingImage = "alpine:3.20";
            _ = await RunDockerAsync(["pull", stagingImage]);
            string pinnedStagingImage = await DockerInspectAsync(stagingImage, "{{index .RepoDigests 0}}");
            int port = GetFreeTcpPort();
            string targetConnection = new SqlConnectionStringBuilder
            {
                DataSource = $"127.0.0.1,{port}",
                UserID = "sa",
                Password = password,
                Encrypt = true,
                TrustServerCertificate = true,
                InitialCatalog = "master",
            }.ConnectionString;
            restoreResources = await DockerDisposableSqlServerProvisioner.ProvisionAsync(
                targetConnection, volume, targetContainerName, "/var/opt/mssql/backup",
                pinnedImage, targetImageId, pinnedStagingImage, "run-1", CancellationToken.None);
            var sourceArtifact = new VerifiedBackupRestoreArtifact(
                "Country",
                localBackup,
                new FileInfo(localBackup).Length,
                await HashAsync(localBackup),
                SecureLocalFile.OpenReadShared(localBackup));
            SqlServerStagedBackup staged;
            await using (sourceArtifact.RetainedHandle)
            {
                var stager = new DockerVolumeBackupStager(
                    restoreResources.VolumeName, "/var/opt/mssql/backup", pinnedStagingImage, targetContainerName, targetImageId);
                staged = await stager.StageAsync(sourceArtifact, CancellationToken.None);
            }

            await File.WriteAllTextAsync(localBackup, "host replacement that must not reach staged bytes");
            await using var unusedHandle = SecureLocalFile.OpenReadShared(localBackup);
            var target = new SqlServerBackupRestoreTarget(
                targetConnection, "/var/opt/mssql/data", new FixedStager(staged));
            await target.RestoreAsync(sourceArtifact with { RetainedHandle = unusedHandle }, CancellationToken.None);

            (int replacementExit, _, _) = await RunDockerAsync(
                ["exec", targetContainerName, "sh", "-c", $"printf replacement > /var/opt/mssql/backup/{backupFileName}"]);
            Assert.NotEqual(0, replacementExit);

            await using var verify = new SqlConnection(targetConnection);
            await verify.OpenAsync();
            await using var state = new SqlCommand(
                "SELECT d.is_read_only, d.snapshot_isolation_state, (SELECT Value FROM Country.dbo.Probe WHERE Id=1) " +
                "FROM sys.databases d WHERE d.name=N'Country';", verify);
            await using SqlDataReader reader = await state.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.True(reader.GetBoolean(0));
            Assert.Equal(1, reader.GetByte(1));
            Assert.Equal("custody-ok", reader.GetString(2));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
            _ = await RunDockerAsync(["rm", "-f", targetContainerName]);
            if (restoreResources is not null)
            {
                _ = await RunDockerAsync(["volume", "rm", "-f", restoreResources.VolumeName]);
            }
        }
    }

    private static async Task DockerCopyAsync(string containerId, string source, string destination)
    {
        var startInfo = new ProcessStartInfo("docker")
        {
            UseShellExecute = false,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add("cp");
        startInfo.ArgumentList.Add($"{containerId}:{source}");
        startInfo.ArgumentList.Add(destination);
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("docker cp could not start.");
        string error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        Assert.True(process.ExitCode == 0, error);
    }

    private static async Task<string> DockerInspectAsync(string image, string format)
    {
        (int exitCode, string output, string error) = await RunDockerAsync(["image", "inspect", "--format", format, image]);
        Assert.True(exitCode == 0, error);
        return output.Trim();
    }

    private static async Task<(int ExitCode, string Output, string Error)> RunDockerAsync(IReadOnlyList<string> arguments)
    {
        var startInfo = new ProcessStartInfo("docker") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("docker could not start.");
        Task<string> output = process.StandardOutput.ReadToEndAsync();
        Task<string> error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, await output, await error);
    }

    private static async Task<string> HashAsync(string path)
    {
        await using FileStream stream = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant();
    }

    private static int GetFreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private sealed class FixedStager(SqlServerStagedBackup staged) : ISqlServerBackupStager
    {
        public Task<SqlServerStagedBackup> StageAsync(VerifiedBackupRestoreArtifact artifact, CancellationToken cancellationToken)
        {
            return Task.FromResult(staged);
        }
    }

    [SqlServerIntegrationFact]
    public async Task DisposeAfterInterruptedSnapshot_RollsBackTransactionAndFreshAdapterCanRestart()
    {
        const string password = "MALIEV_test_Only!123456";
        await using MsSqlContainer container = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04")
            .WithPassword(password)
            .Build();
        await container.StartAsync();

        const string database = "CrashRestartTest";
        await using (var setup = new SqlConnection(container.GetConnectionString()))
        {
            await setup.OpenAsync();
            await using var command = setup.CreateCommand();
            command.CommandText = $"""
                CREATE DATABASE [{database}];
                ALTER DATABASE [{database}] SET ALLOW_SNAPSHOT_ISOLATION ON;
                """;
            _ = await command.ExecuteNonQueryAsync();
        }

        string applicationName = $"Legacy.Maliev.DataMigration.CrashRestart.{Guid.NewGuid():N}";
        var builder = new SqlConnectionStringBuilder(container.GetConnectionString())
        {
            InitialCatalog = database,
            ApplicationName = applicationName,
        };
        await using (var setup = new SqlConnection(builder.ConnectionString))
        {
            await setup.OpenAsync();
            await using var command = setup.CreateCommand();
            command.CommandText = """
                CREATE TABLE dbo.Items (
                    Id int NOT NULL CONSTRAINT PK_Items PRIMARY KEY,
                    Value nvarchar(100) NOT NULL);
                INSERT INTO dbo.Items (Id, Value) VALUES (1, N'before crash');
                """;
            _ = await command.ExecuteNonQueryAsync();
        }

        var interrupted = new SqlServerMigrationSource(new SqlServerMigrationSourceOptions(builder.ConnectionString));
        await interrupted.BeginDatabaseSnapshotAsync(database, CancellationToken.None);
        Assert.Equal(1, await CountSnapshotTransactionsAsync(container.GetConnectionString(), applicationName));

        // Simulate process teardown: no explicit Complete/Rollback call reaches the adapter.
        await interrupted.DisposeAsync();
        Assert.Equal(0, await CountSnapshotTransactionsAsync(container.GetConnectionString(), applicationName));

        await using (var writer = new SqlConnection(builder.ConnectionString))
        {
            await writer.OpenAsync();
            await using var command = writer.CreateCommand();
            command.CommandText = "INSERT INTO dbo.Items (Id, Value) VALUES (2, N'after restart');";
            _ = await command.ExecuteNonQueryAsync();
        }

        await using var restarted = new SqlServerMigrationSource(new SqlServerMigrationSourceOptions(builder.ConnectionString));
        await restarted.BeginDatabaseSnapshotAsync(database, CancellationToken.None);
        var plan = new TableCopyPlan("dbo", "Items", "public", "items", ["Id", "Value"], ["Id"])
        {
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "int",
                ["Value"] = "nvarchar(100)",
            },
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "integer",
                ["Value"] = "text",
            },
            PrimaryKey = new PrimaryKeyCopyPlan("PK_Items", ["Id"]),
        };
        var observed = new List<MigrationRow>();
        await foreach (MigrationRow row in restarted.ReadTableAsync(database, plan, CancellationToken.None))
        {
            observed.Add(row);
        }

        Assert.Equal([1, 2], observed.Select(row => Assert.IsType<int>(row.Values["Id"])).ToArray());
        Assert.Equal(["before crash", "after restart"], observed.Select(row => Assert.IsType<string>(row.Values["Value"])).ToArray());
        await restarted.RollbackDatabaseSnapshotAsync(database, CancellationToken.None);
    }

    [SqlServerIntegrationFact]
    public async Task SnapshotCatalogStreamingAndDispose_PreserveProductionSemantics()
    {
        const string password = "MALIEV_test_Only!123456";
        await using MsSqlContainer container = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04")
            .WithPassword(password)
            .Build();
        await container.StartAsync();

        const string database = "MigrationTest";
        await using (var setup = new SqlConnection(container.GetConnectionString()))
        {
            await setup.OpenAsync();
            await using var command = setup.CreateCommand();
            command.CommandText = $"""
                CREATE DATABASE [{database}];
                ALTER DATABASE [{database}] SET ALLOW_SNAPSHOT_ISOLATION ON;
                """;
            _ = await command.ExecuteNonQueryAsync();
        }

        var builder = new SqlConnectionStringBuilder(container.GetConnectionString()) { InitialCatalog = database };
        await using (var setup = new SqlConnection(builder.ConnectionString))
        {
            await setup.OpenAsync();
            await using var command = setup.CreateCommand();
            command.CommandText = "CREATE SCHEMA sales;";
            _ = await command.ExecuteNonQueryAsync();
            command.CommandText = """
                CREATE TABLE sales.Parent (
                    TenantId int NOT NULL,
                    Id int NOT NULL,
                    CONSTRAINT PK_Parent PRIMARY KEY (TenantId, Id));
                CREATE TABLE sales.Child (
                    Id bigint IDENTITY(100, 5) NOT NULL,
                    TenantId int NOT NULL,
                    ParentId int NOT NULL,
                    ThaiName nvarchar(200) NOT NULL,
                    Amount decimal(19, 4) NOT NULL,
                    LocalTime datetime2(7) NOT NULL,
                    OffsetTime datetimeoffset(7) NOT NULL,
                    LargeText nvarchar(max) NULL,
                    LargeBinary varbinary(max) NULL,
                    CONSTRAINT PK_Child PRIMARY KEY (Id),
                    CONSTRAINT FK_Child_Parent FOREIGN KEY (TenantId, ParentId)
                        REFERENCES sales.Parent (TenantId, Id) ON DELETE CASCADE);
                CREATE INDEX IX_Child_Amount ON sales.Child (Amount DESC)
                    INCLUDE (ThaiName) WHERE Amount > 0;
                INSERT INTO sales.Parent (TenantId, Id) VALUES (1, 10);
                INSERT INTO sales.Child (TenantId, ParentId, ThaiName, Amount, LocalTime, OffsetTime)
                VALUES (1, 10, N'ชิ้นงานทดสอบ', 1234.5678, '2026-08-29T17:45:12.1234567', '2026-08-29T17:45:12.1234567+07:00');
                """;
            _ = await command.ExecuteNonQueryAsync();

            command.CommandText = "UPDATE sales.Child SET LargeText = @text, LargeBinary = @binary;";
            string largeText = new('ก', 3 * 1024 * 1024);
            byte[] largeBinary = Enumerable.Repeat((byte)0xA5, 5 * 1024 * 1024).ToArray();
            _ = command.Parameters.AddWithValue("@text", largeText);
            _ = command.Parameters.AddWithValue("@binary", largeBinary);
            _ = await command.ExecuteNonQueryAsync();
            command.Parameters.Clear();

            command.CommandText = """
                SELECT identity_column.seed_value, identity_column.increment_value, identity_column.last_value,
                       index_column.is_descending_key, index_column.is_included_column, index_row.filter_definition,
                       foreign_key.delete_referential_action, foreign_key.is_disabled, foreign_key.is_not_trusted
                FROM sys.identity_columns AS identity_column
                INNER JOIN sys.tables AS table_row ON table_row.object_id = identity_column.object_id
                INNER JOIN sys.indexes AS index_row ON index_row.object_id = table_row.object_id
                INNER JOIN sys.index_columns AS index_column
                    ON index_column.object_id = index_row.object_id AND index_column.index_id = index_row.index_id
                INNER JOIN sys.foreign_keys AS foreign_key ON foreign_key.parent_object_id = table_row.object_id
                WHERE table_row.name = 'Child' AND index_row.name = 'IX_Child_Amount'
                  AND foreign_key.name = 'FK_Child_Parent'
                ORDER BY index_column.index_column_id;
                """;
            await using SqlDataReader catalog = await command.ExecuteReaderAsync();
            Assert.True(await catalog.ReadAsync());
            Assert.Equal(100L, Convert.ToInt64(catalog.GetValue(0), System.Globalization.CultureInfo.InvariantCulture));
            Assert.Equal(5L, Convert.ToInt64(catalog.GetValue(1), System.Globalization.CultureInfo.InvariantCulture));
            Assert.Equal(100L, Convert.ToInt64(catalog.GetValue(2), System.Globalization.CultureInfo.InvariantCulture));
            Assert.True(catalog.GetBoolean(3));
            Assert.False(catalog.GetBoolean(4));
            Assert.Equal("([Amount]>(0))", catalog.GetString(5));
            Assert.Equal(1, catalog.GetByte(6));
            Assert.False(catalog.GetBoolean(7));
            Assert.False(catalog.GetBoolean(8));
            Assert.True(await catalog.ReadAsync());
            Assert.True(catalog.GetBoolean(4));
        }

        await using var source = new SqlServerMigrationSource(new SqlServerMigrationSourceOptions(builder.ConnectionString));
        await source.BeginDatabaseSnapshotAsync(database, CancellationToken.None);
        SourceSchemaEvidence schema = await source.InspectSchemaAsync(database, CancellationToken.None);
        Assert.Matches("^[0-9a-f]{64}$", schema.SchemaSha256);
        Assert.Equal(
            ["TenantId", "Id"],
            Assert.Single(schema.Tables, table => table.SourceSchema == "sales" && table.SourceTable == "Parent").OrderedColumns);
        SourceTableInventory childInventory = Assert.Single(schema.Tables, table => table.SourceSchema == "sales" && table.SourceTable == "Child");
        Assert.Equal(
            ["Id", "TenantId", "ParentId", "ThaiName", "Amount", "LocalTime", "OffsetTime", "LargeText", "LargeBinary"],
            childInventory.OrderedColumns);
        Assert.Equal("datetime2(7)", Assert.Single(childInventory.Columns, column => column.Column == "LocalTime").DeclaredType);
        Assert.Equal(6L * 1024 * 1024, Assert.Single(childInventory.Columns, column => column.Column == "LargeText").MaxObservedDataLength);
        Assert.Equal(5L * 1024 * 1024, Assert.Single(childInventory.Columns, column => column.Column == "LargeBinary").MaxObservedDataLength);

        DatabaseSchemaPlan generatedPlan = await source.GenerateDatabasePlanAsync(database, CancellationToken.None);
        TableCopyPlan generatedChild = Assert.Single(generatedPlan.Tables, table => table.SourceTable == "Child");
        Assert.Equal(["Id"], generatedChild.PrimaryKey!.Columns);
        Assert.Equal(["TenantId", "Id"], Assert.Single(generatedPlan.Tables, table => table.SourceTable == "Parent").PrimaryKey!.Columns);
        Assert.Equal("text", generatedChild.ColumnTypes["LocalTime"]);
        Assert.Equal("text", generatedChild.ColumnTypes["OffsetTime"]);
        Assert.Equal(new IdentityCopyPlan("Id", 100, 5, 100, true), Assert.Single(generatedChild.Identities));
        IndexCopyPlan generatedIndex = Assert.Single(generatedChild.Indexes, index => index.Name == "IX_Child_Amount");
        Assert.Equal(["Amount"], generatedIndex.DescendingColumns);
        Assert.Equal(["ThaiName"], generatedIndex.IncludedColumns);
        ForeignKeyCopyPlan generatedForeignKey = Assert.Single(generatedChild.ForeignKeys);
        Assert.Equal(["TenantId", "ParentId"], generatedForeignKey.Columns);
        Assert.Equal(["TenantId", "Id"], generatedForeignKey.ReferencedColumns);
        Assert.Equal(ReferentialAction.Cascade, generatedForeignKey.OnDelete);
        Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpected(generatedPlan), generatedPlan.TargetSchemaSha256);

        var table = new TableCopyPlan(
            "sales", "Child", "sales", "child",
            ["Id", "TenantId", "ParentId", "ThaiName", "Amount", "LocalTime", "OffsetTime", "LargeText", "LargeBinary"],
            ["Id"])
        {
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "bigint",
                ["TenantId"] = "int",
                ["ParentId"] = "int",
                ["ThaiName"] = "nvarchar",
                ["Amount"] = "decimal",
                ["LocalTime"] = "datetime2(7)",
                ["OffsetTime"] = "datetimeoffset(7)",
                ["LargeText"] = "nvarchar(max)",
                ["LargeBinary"] = "varbinary(max)",
            },
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "bigint",
                ["TenantId"] = "integer",
                ["ParentId"] = "integer",
                ["ThaiName"] = "text",
                ["Amount"] = "numeric(19,4)",
                ["LocalTime"] = "text",
                ["OffsetTime"] = "text",
                ["LargeText"] = "text",
                ["LargeBinary"] = "bytea",
            },
            PrimaryKey = new PrimaryKeyCopyPlan("PK_Child", ["Id"]),
            ForeignKeys =
            [
                new ForeignKeyCopyPlan("FK_Child_Parent", ["TenantId", "ParentId"], "sales", "parent", ["tenant_id", "id"])
                {
                    SourceReferencedSchema = "sales",
                    SourceReferencedTable = "Parent",
                    SourceReferencedColumns = ["TenantId", "Id"],
                    OnDelete = ReferentialAction.Cascade,
                },
            ],
        };

        List<MigrationRow> rows = [];
        await foreach (MigrationRow row in source.ReadTableAsync(database, table, CancellationToken.None))
        {
            rows.Add(row);
        }

        _ = Assert.Single(rows);
        Assert.Equal("ชิ้นงานทดสอบ", rows[0].Values["ThaiName"]);
        Assert.Equal(1234.5678m, rows[0].Values["Amount"]);
        Assert.Equal("2026-08-29T17:45:12.1234567", rows[0].Values["LocalTime"]);
        Assert.Equal("2026-08-29T17:45:12.1234567+07:00", rows[0].Values["OffsetTime"]);
        StreamingLob largeTextValue = Assert.IsType<StreamingLob>(rows[0].Values["LargeText"]);
        StreamingLob largeBinaryValue = Assert.IsType<StreamingLob>(rows[0].Values["LargeBinary"]);
        await largeTextValue.ConsumeAsync(Stream.Null, CancellationToken.None);
        await largeBinaryValue.ConsumeAsync(Stream.Null, CancellationToken.None);
        Assert.Equal(9L * 1024 * 1024, largeTextValue.CanonicalByteLength);
        Assert.Equal(5L * 1024 * 1024, largeBinaryValue.CanonicalByteLength);
        IReadOnlyDictionary<string, long> orphans = await source.InspectForeignKeyOrphansAsync(database, table, CancellationToken.None);
        Assert.Equal(0, orphans["FK_Child_Parent"]);
        IReadOnlyDictionary<string, long> relationships = await source.InspectForeignKeyRelationshipsAsync(database, table, CancellationToken.None);
        Assert.Equal(1, relationships["FK_Child_Parent"]);
        IReadOnlyDictionary<string, long> sequences = await source.InspectSequenceNextValuesAsync(database, generatedPlan, CancellationToken.None);
        Assert.Equal(105, Assert.Single(sequences).Value);

        await source.RollbackDatabaseSnapshotAsync(database, CancellationToken.None);
        await source.RollbackDatabaseSnapshotAsync(database, CancellationToken.None);
    }

    private static async Task<int> CountSnapshotTransactionsAsync(string connectionString, string applicationName)
    {
        await using var connection = new SqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*)
            FROM sys.dm_tran_session_transactions AS transaction_session
            INNER JOIN sys.dm_exec_sessions AS session_row
                ON session_row.session_id = transaction_session.session_id
            WHERE session_row.program_name = @applicationName;
            """;
        _ = command.Parameters.AddWithValue("@applicationName", applicationName);
        return Convert.ToInt32(
            await command.ExecuteScalarAsync(CancellationToken.None),
            System.Globalization.CultureInfo.InvariantCulture);
    }
}
