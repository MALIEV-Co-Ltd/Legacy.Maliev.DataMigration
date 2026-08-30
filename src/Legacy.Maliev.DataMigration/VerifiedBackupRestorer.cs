using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.SqlClient;

namespace Legacy.Maliev.DataMigration;

public sealed record VerifiedBackupRestoreArtifact(
    string Database,
    string LocalPath,
    long ByteLength,
    string Sha256,
    FileStream RetainedHandle);

public interface IVerifiedBackupRestoreTarget
{
    Task RestoreAsync(VerifiedBackupRestoreArtifact artifact, CancellationToken cancellationToken);
}

public static class VerifiedBackupRestorer
{
    public static async Task RestoreAsync(
        BackupReceipt receipt,
        IReceiptAttestationTrustStore trust,
        string recoveryDirectory,
        IVerifiedBackupRestoreTarget target,
        DateTimeOffset nowUtc,
        TimeSpan maximumReceiptAge,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(target);
        ValidateReceipt(receipt, trust, nowUtc, maximumReceiptAge);
        string root = Path.GetFullPath(recoveryDirectory);
        SecureLocalFile.EnsureOwnerOnlyDirectory(root);
        foreach (BackupArtifact artifact in receipt.Artifacts!.Select(item => item!))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!string.Equals(artifact.FileName, Path.GetFileName(artifact.FileName), StringComparison.Ordinal))
            {
                throw new Exact25FullBackupException("restore_artifact_path_invalid", "A signed backup filename is unsafe.");
            }

            string localPath = Path.Combine(root, artifact.FileName!);
            SecureLocalFile.EnsurePathWithin(root, localPath);
            await using FileStream retained = SecureLocalFile.OpenReadShared(localPath);
            if (retained.Length != artifact.ByteLength)
            {
                throw new Exact25FullBackupException("restore_artifact_invalid", "A retained backup does not match its signed receipt.");
            }

            string sha256 = await SecureLocalFile.ComputeSha256Async(retained, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(sha256), Encoding.ASCII.GetBytes(artifact.Sha256!.ToLowerInvariant())))
            {
                throw new Exact25FullBackupException("restore_artifact_invalid", "A retained backup does not match its signed receipt.");
            }

            retained.Position = 0;
            await target.RestoreAsync(
                new(artifact.Database!, localPath, retained.Length, sha256, retained), cancellationToken).ConfigureAwait(false);
        }
    }

    public static void ValidateReceipt(
        BackupReceipt receipt,
        IReceiptAttestationTrustStore trust,
        DateTimeOffset nowUtc,
        TimeSpan maximumReceiptAge)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(trust);
        var semanticErrors = new List<PreflightError>();
        PreflightService.ValidateReceipt(receipt, nowUtc, maximumReceiptAge, semanticErrors);
        if (semanticErrors.Count > 0 ||
            !ReceiptAttestation.TryCreatePayload(receipt, out byte[] payload) ||
            string.IsNullOrWhiteSpace(receipt.AttestationKeyId) ||
            string.IsNullOrWhiteSpace(receipt.AttestationSignature) ||
            !TryDecode(receipt.AttestationSignature, out byte[] signature) ||
            !trust.Verify(receipt.AttestationKeyId, payload, signature) ||
            receipt.Artifacts is null || receipt.SourceObservedAtUtc is null ||
            !receipt.Artifacts.Select(item => item?.Database).Order(StringComparer.Ordinal)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            throw new Exact25FullBackupException("restore_receipt_invalid", "The signed exact-25 backup receipt is invalid.");
        }
    }

    private static bool TryDecode(string value, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromBase64String(value);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }
}

public sealed class SqlServerBackupRestoreTarget(
    string adminConnectionString,
    string dataDirectory,
    ISqlServerBackupStager stager)
    : IVerifiedBackupRestoreTarget
{
    private readonly string _adminConnectionString = string.IsNullOrWhiteSpace(adminConnectionString)
        ? throw new ArgumentException("The disposable SQL Server admin connection is required.", nameof(adminConnectionString))
        : adminConnectionString;
    private readonly string _dataDirectory = string.IsNullOrWhiteSpace(dataDirectory)
        ? throw new ArgumentException("The disposable SQL Server data directory is required.", nameof(dataDirectory))
        : dataDirectory.TrimEnd('/', '\\');
    private readonly ISqlServerBackupStager _stager = stager ?? throw new ArgumentNullException(nameof(stager));

    public async Task RestoreAsync(VerifiedBackupRestoreArtifact artifact, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        if (!DatabaseInventory.ActiveDatabases.Contains(artifact.Database, StringComparer.Ordinal))
        {
            throw new Exact25FullBackupException("restore_database_invalid", "The restore database is outside the exact-25 inventory.");
        }

        SqlServerStagedBackup staged = await _stager.StageAsync(artifact, cancellationToken).ConfigureAwait(false);
        if (staged.ByteLength != artifact.ByteLength || !CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(staged.Sha256.ToLowerInvariant()),
            Encoding.ASCII.GetBytes(artifact.Sha256.ToLowerInvariant())))
        {
            throw new Exact25FullBackupException("restore_stage_invalid", "The staged backup does not match the signed artifact.");
        }
        string sqlVisiblePath = staged.SqlServerPath;
        await using var connection = new SqlConnection(_adminConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        string backup = QuoteSqlLiteral(sqlVisiblePath);
        string database = QuoteIdentifier(artifact.Database);
        await ExecuteAsync(connection, $"RESTORE VERIFYONLY FROM DISK = N'{backup}' WITH CHECKSUM;", cancellationToken).ConfigureAwait(false);

        var files = new List<(string LogicalName, string Type, int FileId)>();
        await using (var command = new SqlCommand($"RESTORE FILELISTONLY FROM DISK = N'{backup}';", connection) { CommandTimeout = 0 })
        await using (SqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            int logicalOrdinal = reader.GetOrdinal("LogicalName");
            int typeOrdinal = reader.GetOrdinal("Type");
            int fileIdOrdinal = reader.GetOrdinal("FileId");
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                files.Add((reader.GetString(logicalOrdinal), reader.GetString(typeOrdinal),
                    Convert.ToInt32(reader.GetValue(fileIdOrdinal), System.Globalization.CultureInfo.InvariantCulture)));
            }
        }
        if (files.Count < 2 || !files.Any(file => file.Type == "D") || !files.Any(file => file.Type == "L"))
        {
            throw new Exact25FullBackupException("restore_file_layout_invalid", "The backup file layout is incomplete.");
        }

        await using (var exists = new SqlCommand("SELECT DB_ID(@database);", connection) { CommandTimeout = 0 })
        {
            _ = exists.Parameters.AddWithValue("@database", artifact.Database);
            if (await exists.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is not DBNull and not null)
            {
                throw new Exact25FullBackupException("restore_target_exists", "The disposable restore target already contains the database.");
            }
        }

        string moves = string.Join(", ", files.Select(file =>
        {
            string extension = file.Type == "L" ? ".ldf" : ".mdf";
            string suffix = file.Type == "L" ? $"log-{file.FileId}" : $"data-{file.FileId}";
            string target = QuoteSqlLiteral($"{_dataDirectory}/{artifact.Database}-{suffix}{extension}");
            return $"MOVE N'{QuoteSqlLiteral(file.LogicalName)}' TO N'{target}'";
        }));
        try
        {
            await ExecuteAsync(connection,
                $"RESTORE DATABASE {database} FROM DISK = N'{backup}' WITH {moves}, RECOVERY; " +
                $"ALTER DATABASE {database} SET ALLOW_SNAPSHOT_ISOLATION ON;", cancellationToken).ConfigureAwait(false);

            await using (var state = new SqlCommand(
                "SELECT snapshot_isolation_state FROM sys.databases WHERE name = @database;", connection)
            { CommandTimeout = 0 })
            {
                _ = state.Parameters.AddWithValue("@database", artifact.Database);
                object? observed = await state.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
                if (observed is null || observed is DBNull || Convert.ToInt32(observed, System.Globalization.CultureInfo.InvariantCulture) != 1)
                {
                    throw new Exact25FullBackupException("snapshot_isolation_unavailable", "Snapshot isolation was not enabled on the restored source.");
                }
            }
            await ExecuteAsync(connection, $"ALTER DATABASE {database} SET READ_ONLY WITH ROLLBACK IMMEDIATE;", cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            await DropPartialDatabaseAsync(connection, database).ConfigureAwait(false);
            throw;
        }
    }

    private static async Task DropPartialDatabaseAsync(SqlConnection connection, string database)
    {
        try
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await ExecuteAsync(connection,
                $"IF DB_ID(N'{QuoteSqlLiteral(database.Trim('[', ']'))}') IS NOT NULL BEGIN " +
                $"ALTER DATABASE {database} SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE {database}; END;",
                cleanup.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Preserve the restore failure; the disposable container remains a failed release gate.
        }
    }

    private static async Task ExecuteAsync(SqlConnection connection, string sql, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(sql, connection) { CommandTimeout = 0 };
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string QuoteIdentifier(string value)
    {
        return $"[{value.Replace("]", "]]", StringComparison.Ordinal)}]";
    }

    private static string QuoteSqlLiteral(string value)
    {
        return value.Replace("'", "''", StringComparison.Ordinal);
    }
}
