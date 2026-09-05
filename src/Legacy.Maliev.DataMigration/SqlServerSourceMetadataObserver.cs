using System.Collections.Immutable;
using Microsoft.Data.SqlClient;

namespace Legacy.Maliev.DataMigration;

internal static class SqlServerSourceMetadataObserver
{
    internal static async Task<SqlRestoredSourceState> ObserveAsync(string connectionString, CancellationToken token)
    {
        try
        {
            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync(token).ConfigureAwait(false);
            // Require complete server metadata visibility; a restricted login can silently hide offline databases/files.
            const string metadata = """
                SELECT CONVERT(varchar(64), CONNECTIONPROPERTY('local_net_address')),
                       CONVERT(int, CONNECTIONPROPERTY('local_tcp_port')),
                       CONVERT(nvarchar(128), SERVERPROPERTY('MachineName')),
                       CONVERT(nvarchar(128), SERVERPROPERTY('ServerName')),
                       CONVERT(varchar(10), SERVERPROPERTY('ProductMajorVersion')),
                       IS_SRVROLEMEMBER('sysadmin');
                SELECT d.database_id, d.name, r.database_guid, d.is_read_only,
                       CONVERT(int, d.snapshot_isolation_state), CONVERT(int, d.state)
                FROM sys.databases d LEFT JOIN sys.database_recovery_status r ON r.database_id=d.database_id
                WHERE d.database_id > 4 ORDER BY d.name;
                SELECT database_id, file_id, CONVERT(int, type), physical_name
                FROM sys.master_files WHERE database_id > 4 ORDER BY database_id, file_id;
                """;
            await using var command = new SqlCommand(metadata, connection) { CommandTimeout = 30 };
            await using SqlDataReader reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            LocalDockerResourceObserver.Require(await reader.ReadAsync(token).ConfigureAwait(false), "sql_metadata");
            string address = reader.GetString(0);
            int port = reader.GetInt32(1);
            string machine = reader.GetString(2), server = reader.GetString(3), version = reader.GetString(4);
            bool visible = !reader.IsDBNull(5) && reader.GetInt32(5) == 1;
            var databases = ImmutableArray.CreateBuilder<SqlObservedDatabase>();
            LocalDockerResourceObserver.Require(await reader.NextResultAsync(token).ConfigureAwait(false), "sql_metadata");
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                databases.Add(new(reader.GetInt32(0), reader.GetString(1), reader.IsDBNull(2) ? Guid.Empty : reader.GetGuid(2),
                    reader.GetBoolean(3), reader.GetInt32(4), reader.GetInt32(5)));
            }
            var files = ImmutableArray.CreateBuilder<SqlObservedFile>();
            LocalDockerResourceObserver.Require(await reader.NextResultAsync(token).ConfigureAwait(false), "sql_metadata");
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                files.Add(new(reader.GetInt32(0), reader.GetInt32(1), reader.GetInt32(2), reader.GetString(3)));
            }
            return new(address, port, machine, server, version, visible, databases.ToImmutable(), files.ToImmutable());
        }
        catch (Exception error) when (error is SqlException or InvalidOperationException or System.Data.SqlTypes.SqlNullValueException)
        {
            // SQL exception messages can contain endpoint/credential/row text. Never expose them as inner exceptions.
            throw LocalDockerResourceObserver.Reject("sql_metadata");
        }
    }
}
