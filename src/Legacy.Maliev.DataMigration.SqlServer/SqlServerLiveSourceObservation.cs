using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.SqlClient;

namespace Legacy.Maliev.DataMigration;

/// <summary>Read-only identity evidence for a live exact-23 comparison, not a backup or common database cutoff.</summary>
public static class SqlServerLiveSourceObservation
{
    public static async Task<string> ObserveSha256Async(string connectionString, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        try
        {
            var settings = new SqlConnectionStringBuilder(connectionString)
            {
                InitialCatalog = "master",
                ApplicationIntent = ApplicationIntent.ReadOnly,
                Pooling = false,
            };
            await using var connection = new SqlConnection(settings.ConnectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            const string query = """
                SELECT CONVERT(nvarchar(128), SERVERPROPERTY('ServerName')),
                       CONVERT(nvarchar(20), SERVERPROPERTY('ProductMajorVersion'));
                SELECT d.name, r.database_guid, d.state, d.snapshot_isolation_state
                FROM sys.databases AS d
                LEFT JOIN sys.database_recovery_status AS r ON r.database_id = d.database_id
                WHERE d.database_id > 4 ORDER BY d.name;
                """;
            await using var command = new SqlCommand(query, connection) { CommandTimeout = 30 };
            await using SqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
                reader.IsDBNull(0) || reader.IsDBNull(1))
            {
                throw Invalid();
            }
            string server = reader.GetString(0);
            string majorVersion = reader.GetString(1);
            if (!await reader.NextResultAsync(cancellationToken).ConfigureAwait(false))
            {
                throw Invalid();
            }
            var observed = new Dictionary<string, (Guid Guid, int State, int SnapshotState)>(StringComparer.Ordinal);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                string name = reader.GetString(0);
                if (!DatabaseInventory.ActiveDatabases.Contains(name, StringComparer.Ordinal))
                {
                    continue;
                }
                if (reader.IsDBNull(1) || !observed.TryAdd(name,
                    (reader.GetGuid(1), reader.GetInt32(2), reader.GetInt32(3))))
                {
                    throw Invalid();
                }
            }
            return ComputeSha256(server, majorVersion, observed);
        }
        catch (Exception failure) when (failure is SqlException or InvalidOperationException or FormatException)
        {
            // SQL client messages can contain endpoint and credential details.
            throw Invalid();
        }
    }

    internal static string ComputeSha256(string server, string majorVersion,
        IReadOnlyDictionary<string, (Guid Guid, int State, int SnapshotState)> observed)
    {
        if (string.IsNullOrWhiteSpace(server) || string.IsNullOrWhiteSpace(majorVersion) ||
            !observed.Keys.Order(StringComparer.Ordinal)
                .SequenceEqual(DatabaseInventory.ActiveDatabases.Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
            observed.Values.Any(value => value.Guid == Guid.Empty || value.State != 0 || value.SnapshotState != 1))
        {
            throw Invalid();
        }
        var canonical = new StringBuilder("legacy-maliev-live-sqlserver-source-v1\n");
        _ = canonical.Append(server).Append('\n').Append(majorVersion).Append('\n');
        foreach (string name in DatabaseInventory.ActiveDatabases)
        {
            _ = canonical.Append(name).Append(':').Append(observed[name].Guid.ToString("D")).Append('\n');
        }
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString()))).ToLowerInvariant();
    }

    private static MigrationExecutionException Invalid()
    {
        return new("delta_live_source_observation_invalid",
        "The read-only SQL Server identity or exact-23 snapshot inventory could not be verified.");
    }
}
