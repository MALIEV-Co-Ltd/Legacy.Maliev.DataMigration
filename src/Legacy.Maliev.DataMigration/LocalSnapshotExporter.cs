using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public interface IPostgreSqlDumpSource
{
    Task<Stream> OpenDumpAsync(string database, string shadowDatabase, CancellationToken cancellationToken);
}

public sealed record LocalSnapshotDatabase(
    string Database,
    string ShadowDatabase,
    string FileName,
    long PlaintextByteLength,
    string PlaintextSha256,
    long EncryptedByteLength,
    string EncryptedSha256);

public sealed record LocalSnapshotManifest(
    int SchemaVersion,
    string Encryption,
    IReadOnlyList<LocalSnapshotDatabase> Databases);

public static partial class LocalSnapshotExporter
{
    public static async Task<LocalSnapshotManifest> ExportAsync(
        IReadOnlyList<MigratedShadowDatabase> databases,
        string outputDirectory,
        ReadOnlyMemory<byte> encryptionKey,
        IPostgreSqlDumpSource dumpSource,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(databases);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        ArgumentNullException.ThrowIfNull(dumpSource);
        string[] observed = [.. databases.Select(database => database.Database)];
        if (observed.Distinct(StringComparer.Ordinal).Count() != observed.Length ||
            !observed.OrderBy(database => database, StringComparer.Ordinal)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            databases.Any(database => !ShadowName().IsMatch(database.ShadowName)))
        {
            throw new MigrationExecutionException("snapshot_database_inventory_invalid", "Snapshot export requires the exact run-owned shadow inventory.");
        }

        string directory = Path.GetFullPath(outputDirectory);
        if (Directory.Exists(directory))
        {
            throw new MigrationExecutionException("snapshot_output_exists", "Snapshot output must be a new restricted directory.");
        }
        _ = Directory.CreateDirectory(directory);
        RestrictDirectory(directory);
        var exported = new List<LocalSnapshotDatabase>(databases.Count);
        try
        {
            foreach (MigratedShadowDatabase database in databases.OrderBy(item => item.Database, StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                string fileName = $"{database.Database}.dump.aes256";
                string filePath = Path.Combine(directory, fileName);
                await using Stream dump = await dumpSource.OpenDumpAsync(database.Database, database.ShadowName, cancellationToken)
                    .ConfigureAwait(false);
                SnapshotEncryptionResult encryption;
                await using (FileStream encrypted = new(filePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024,
                    FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    encryption = await SnapshotEncryption.EncryptAsync(
                        dump, encrypted, encryptionKey, cancellationToken).ConfigureAwait(false);
                    await encrypted.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                var file = new FileInfo(filePath);
                string encryptedSha256 = await HashFileAsync(filePath, cancellationToken).ConfigureAwait(false);
                exported.Add(new(database.Database, database.ShadowName, fileName, encryption.PlaintextByteLength,
                    encryption.PlaintextSha256, file.Length, encryptedSha256));
                RestrictFile(filePath);
            }

            var manifest = new LocalSnapshotManifest(1, "AES-256-GCM-chunked-v1", exported);
            string manifestPath = Path.Combine(directory, "manifest.json");
            await using (FileStream stream = new(manifestPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, manifest, cancellationToken: cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            RestrictFile(manifestPath);
            return manifest;
        }
        catch
        {
            Directory.Delete(directory, recursive: true);
            throw;
        }
    }

    private static async Task<string> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false)).ToLowerInvariant();
    }

    private static void RestrictDirectory(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            RestrictDirectoryWindows(path);
        }
        else
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static void RestrictFile(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void RestrictDirectoryWindows(string path)
    {
        SecurityIdentifier owner = WindowsIdentity.GetCurrent().User ??
            throw new UnauthorizedAccessException("The current Windows identity has no security identifier.");
        var security = new DirectorySecurity();
        security.SetOwner(owner);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            owner,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }

    [GeneratedRegex("^legacy_shadow_[a-z0-9_]+_[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex ShadowName();
}
