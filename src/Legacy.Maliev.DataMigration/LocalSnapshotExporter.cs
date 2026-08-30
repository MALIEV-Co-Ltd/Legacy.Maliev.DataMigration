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
    string Format,
    string Encryption,
    string SnapshotId,
    string ManifestDigestSha256,
    string ManifestMacSha256,
    IReadOnlyList<LocalSnapshotDatabase> Databases);

public static partial class LocalSnapshotExporter
{
    public static async Task<LocalSnapshotManifest> ExportAsync(
        IReadOnlyList<MigratedShadowDatabase> databases,
        string outputDirectory,
        string snapshotId,
        ReadOnlyMemory<byte> encryptionKey,
        IPostgreSqlDumpSource dumpSource,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(databases);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(snapshotId);
        ArgumentNullException.ThrowIfNull(dumpSource);
        string[] observed = [.. databases.Select(database => database.Database)];
        if (observed.Distinct(StringComparer.Ordinal).Count() != observed.Length ||
            !observed.OrderBy(database => database, StringComparer.Ordinal)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            databases.Any(database => !ShadowName().IsMatch(database.ShadowName)))
        {
            throw new MigrationExecutionException("snapshot_database_inventory_invalid", "Snapshot export requires the exact run-owned shadow inventory.");
        }
        if (!SnapshotId().IsMatch(snapshotId))
        {
            throw new MigrationExecutionException("snapshot_identity_invalid", "Snapshot identity is invalid.");
        }

        string directory = Path.GetFullPath(outputDirectory);
        if (Directory.Exists(directory))
        {
            throw new MigrationExecutionException("snapshot_output_exists", "Snapshot output must be a new restricted directory.");
        }
        var staged = new List<(MigratedShadowDatabase Database, string Path, SnapshotArchiveContext Context, LocalSnapshotDatabase Entry)>(databases.Count);
        try
        {
            _ = Directory.CreateDirectory(directory);
            RestrictDirectory(directory);
            foreach (MigratedShadowDatabase database in databases.OrderBy(item => item.Database, StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                string fileName = $"{database.Database}.dump.aes256";
                string stagingPath = Path.Combine(directory, $".{database.Database}.{Guid.NewGuid():N}.staged.aes256.tmp");
                string stagingDigest = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
                    $"provisional-staging\n{snapshotId}\n{database.Database}"))).ToLowerInvariant();
                SnapshotArchiveContext stagingContext = SnapshotArchiveContext.Create(snapshotId, database.Database, stagingDigest);
                await using Stream dump = await dumpSource.OpenDumpAsync(database.Database, database.ShadowName, cancellationToken)
                    .ConfigureAwait(false);
                SnapshotEncryptionResult result;
                await using (FileStream staging = new(stagingPath, CreateSecureOptions(FileAccess.ReadWrite,
                    FileOptions.Asynchronous | FileOptions.WriteThrough)))
                {
                    SecureSnapshotFileCreation.Validate(staging, stagingPath);
                    result = await SnapshotEncryption.EncryptStagingAsync(dump, staging, encryptionKey, stagingContext,
                        cancellationToken).ConfigureAwait(false);
                    await staging.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                RestrictFile(stagingPath);
                staged.Add((database, stagingPath, stagingContext, new(database.Database, database.ShadowName, fileName,
                    result.PlaintextByteLength, result.PlaintextSha256, 0, string.Empty)));
            }

            string digest = SnapshotManifestAuthentication.ComputeSemanticDigest(snapshotId, staged.Select(x => x.Entry).ToArray());
            var exported = new List<LocalSnapshotDatabase>(databases.Count);
            foreach ((MigratedShadowDatabase database, string stagingPath, SnapshotArchiveContext stagingContext,
                LocalSnapshotDatabase entry) in staged)
            {
                string filePath = Path.Combine(directory, entry.FileName);
                await using (var staging = new FileStream(stagingPath, FileMode.Open, FileAccess.Read, FileShare.None, 64 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan))
                await using (var encrypted = new FileStream(filePath, CreateSecureOptions(FileAccess.Write,
                    FileOptions.Asynchronous | FileOptions.WriteThrough)))
                {
                    SecureSnapshotFileCreation.Validate(encrypted, filePath);
                    SnapshotEncryptionResult result = await SnapshotEncryption.ReencryptStagingAsync(staging, encrypted,
                        encryptionKey, stagingContext, SnapshotArchiveContext.Create(snapshotId, database.Database, digest),
                        cancellationToken).ConfigureAwait(false);
                    if (result.PlaintextByteLength != entry.PlaintextByteLength ||
                        !string.Equals(result.PlaintextSha256, entry.PlaintextSha256, StringComparison.Ordinal))
                    {
                        throw new CryptographicException("Provisional snapshot staging content changed before final encryption.");
                    }
                    await encrypted.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                var encryptedInfo = new FileInfo(filePath);
                exported.Add(entry with
                {
                    EncryptedByteLength = encryptedInfo.Length,
                    EncryptedSha256 = await HashFileAsync(filePath, cancellationToken).ConfigureAwait(false)
                });
                RestrictFile(filePath);
                File.Delete(stagingPath);
            }

            var unsigned = new LocalSnapshotManifest(2, "MLVSNP02", "AES-256-GCM-chunked-v2", snapshotId, digest, string.Empty, exported);
            var manifest = unsigned with { ManifestMacSha256 = SnapshotManifestAuthentication.ComputeMac(unsigned, encryptionKey.Span) };
            string manifestPath = Path.Combine(directory, "manifest.json");
            await using (FileStream stream = new(manifestPath, CreateSecureOptions(FileAccess.Write,
                FileOptions.Asynchronous | FileOptions.WriteThrough)))
            {
                SecureSnapshotFileCreation.Validate(stream, manifestPath);
                await JsonSerializer.SerializeAsync(stream, manifest, cancellationToken: cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            RestrictFile(manifestPath);
            return manifest;
        }
        catch (Exception primaryFailure)
        {
            try
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
            catch (Exception cleanupFailure) when (cleanupFailure is not OutOfMemoryException and not AccessViolationException)
            {
                throw new AggregateException("Snapshot export failed and encrypted staging cleanup also failed.",
                    primaryFailure, cleanupFailure);
            }
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primaryFailure).Throw();
            throw;
        }
    }

    private static async Task<string> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false)).ToLowerInvariant();
    }

    private static FileStreamOptions CreateSecureOptions(FileAccess access, FileOptions options)
    {
        var result = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = access,
            Share = FileShare.None,
            BufferSize = 64 * 1024,
            Options = options
        };
        if (!OperatingSystem.IsWindows())
        {
            result.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        return result;
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

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex SnapshotId();
}
