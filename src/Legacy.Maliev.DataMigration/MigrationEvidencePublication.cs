using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace Legacy.Maliev.DataMigration;

public static class MigrationEvidencePublication
{
    public const string EvidenceFileName = "evidence.json";
    public const string ApprovedBaselineFileName = "approved-baseline.json";

    public static Task PublishAsync(
        AppHostMigrationEvidenceV2Document document,
        string publicationDirectory,
        CancellationToken cancellationToken)
    {
        return PublishAsync(document, publicationDirectory, WriteNewTextAsync, cancellationToken);
    }

    internal static async Task PublishAsync(
        AppHostMigrationEvidenceV2Document document,
        string publicationDirectory,
        Func<string, string, CancellationToken, Task> writeArtifact,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentException.ThrowIfNullOrWhiteSpace(publicationDirectory);
        ArgumentNullException.ThrowIfNull(writeArtifact);

        string target = Path.GetFullPath(publicationDirectory);
        string? parent = Path.GetDirectoryName(target);
        string name = Path.GetFileName(target);
        if (string.IsNullOrWhiteSpace(parent) || string.IsNullOrWhiteSpace(name) || Directory.Exists(target) || File.Exists(target))
        {
            throw new IOException("The evidence publication destination must be a new directory.");
        }

        _ = Directory.CreateDirectory(parent);
        string staging = Path.Combine(parent, $".{name}.{Guid.NewGuid():N}.tmp");
        try
        {
            CreateOwnerProtectedDirectory(staging);
            await writeArtifact(Path.Combine(staging, EvidenceFileName), document.EvidenceJson, cancellationToken).ConfigureAwait(false);
            await writeArtifact(Path.Combine(staging, ApprovedBaselineFileName), document.ApprovedBaselineJson, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            Directory.Move(staging, target);
        }
        catch
        {
            if (Directory.Exists(staging))
            {
                Directory.Delete(staging, recursive: true);
            }

            throw;
        }
    }

    private static async Task WriteNewTextAsync(string path, string value, CancellationToken cancellationToken)
    {
        await using FileStream stream = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        await using var writer = new StreamWriter(stream, new UTF8Encoding(false), 64 * 1024, leaveOpen: true);
        await writer.WriteAsync(value.AsMemory(), cancellationToken).ConfigureAwait(false);
        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static void CreateOwnerProtectedDirectory(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            CreateOwnerProtectedWindowsDirectory(path);
            return;
        }

        _ = Directory.CreateDirectory(
            path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    [SupportedOSPlatform("windows")]
    private static void CreateOwnerProtectedWindowsDirectory(string path)
    {
        SecurityIdentifier owner = WindowsIdentity.GetCurrent().User ??
            throw new UnauthorizedAccessException("The current Windows owner identity is unavailable.");
        var security = new DirectorySecurity();
        security.SetOwner(owner);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            owner,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        var directory = new DirectoryInfo(path);
        directory.Create(security);
    }
}
