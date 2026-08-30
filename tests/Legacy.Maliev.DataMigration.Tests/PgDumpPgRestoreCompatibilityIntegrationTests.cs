using System.Diagnostics;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class PostgreSql18SnapshotIntegrationFactAttribute : FactAttribute
{
    public PostgreSql18SnapshotIntegrationFactAttribute()
    {
        if (!string.Equals(
            Environment.GetEnvironmentVariable("MALIEV_RUN_PG18_SNAPSHOT_INTEGRATION"),
            "1",
            StringComparison.Ordinal))
        {
            Skip = "PostgreSQL 18 snapshot compatibility is explicitly gated: set MALIEV_RUN_PG18_SNAPSHOT_INTEGRATION=1 and configure the tool and database prerequisites.";
        }
    }
}

public sealed class PgDumpPgRestoreCompatibilityIntegrationTests
{
    [PostgreSql18SnapshotIntegrationFact]
    public async Task ProducerCustomArchive_RestoresSchemaAndRowsIntoFreshPostgreSql18Database()
    {
        string connection = RequiredEnvironment("LEGACY_SNAPSHOT_INTEGRATION_CONNECTION");
        string shadow = RequiredEnvironment("LEGACY_SNAPSHOT_INTEGRATION_SHADOW_DATABASE");
        string pgDump = RequiredEnvironment("PG_DUMP_PATH");
        string pgRestore = RequiredEnvironment("PG_RESTORE_PATH");

        AssertPostgreSql18Tool(pgDump, "pg_dump");
        AssertPostgreSql18Tool(pgRestore, "pg_restore");

        string archive = Path.Combine(Path.GetTempPath(), $"snapshot-custom-{Guid.NewGuid():N}.dump");
        string restoredDatabase = $"legacy_snapshot_restore_{Guid.NewGuid():N}";
        try
        {
            var source = new PgDumpSource(pgDump, connection);
            await using Stream dump = await source.OpenDumpAsync("integration", shadow, CancellationToken.None);
            await using (FileStream output = File.Create(archive))
            {
                await dump.CopyToAsync(output);
            }

            await ExecuteAdministrativeCommandAsync(connection, $"CREATE DATABASE \"{restoredDatabase}\"");
            var targetConnection = new NpgsqlConnectionStringBuilder(connection) { Database = restoredDatabase };
            var start = new ProcessStartInfo(pgRestore)
            {
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardError = true,
            };
            foreach (string argument in new[]
            {
                "--exit-on-error", "--no-owner", "--no-privileges", "--single-transaction", "--no-password",
                "--host", targetConnection.Host ?? throw new InvalidOperationException("Integration target host is required."),
                "--port", targetConnection.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--username", targetConnection.Username ?? throw new InvalidOperationException("Integration target username is required."),
                "--dbname", restoredDatabase,
            })
            {
                start.ArgumentList.Add(argument);
            }
            start.Environment["PGPASSWORD"] = targetConnection.Password;
            using Process process = Process.Start(start) ?? throw new InvalidOperationException("pg_restore did not start.");
            await using (FileStream input = File.OpenRead(archive))
            {
                await input.CopyToAsync(process.StandardInput.BaseStream);
            }
            await process.StandardInput.DisposeAsync();
            string error = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            Assert.True(process.ExitCode == 0, error);

            await using var restored = new NpgsqlConnection(targetConnection.ConnectionString);
            await restored.OpenAsync();
            await using var query = new NpgsqlCommand("SELECT value FROM snapshot_probe WHERE id = 1", restored);
            Assert.Equal("pg18", await query.ExecuteScalarAsync());
        }
        finally
        {
            await ExecuteAdministrativeCommandAsync(connection,
                $"DROP DATABASE IF EXISTS \"{restoredDatabase}\" WITH (FORCE)");
            if (File.Exists(archive))
            {
                File.Delete(archive);
            }
        }
    }

    private static async Task ExecuteAdministrativeCommandAsync(string connectionString, string sql)
    {
        var builder = new NpgsqlConnectionStringBuilder(connectionString) { Database = "postgres" };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static string RequiredEnvironment(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        return !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidOperationException($"{name} is required when PostgreSQL 18 snapshot integration is enabled.");
    }

    private static void AssertPostgreSql18Tool(string executable, string tool)
    {
        var start = new ProcessStartInfo(executable, "--version")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using Process process = Process.Start(start) ?? throw new InvalidOperationException($"{tool} did not start.");
        string output = process.StandardOutput.ReadToEnd();
        string error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, error);
        Assert.Contains("18.", output, StringComparison.Ordinal);
    }
}
