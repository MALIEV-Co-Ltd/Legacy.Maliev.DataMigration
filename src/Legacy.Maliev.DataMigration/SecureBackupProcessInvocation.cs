using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

public sealed class SecureBackupProcessInvocation
{
    internal SecureBackupProcessInvocation(string fileName, IReadOnlyList<string> arguments, string standardInput)
    {
        FileName = fileName;
        Arguments = arguments;
        StandardInput = standardInput;
    }

    public string FileName { get; }

    public IReadOnlyList<string> Arguments { get; }

    internal string StandardInput { get; }

    public override string ToString()
    {
        return $"{FileName} {string.Join(' ', Arguments)} < [REDACTED STDIN]";
    }
}

public static class SecureKubectlSqlCmdInvocation
{
    private const string ShellScript =
        "IFS= read -r SQLCMDUSER; IFS= read -r SQLCMDPASSWORD; export SQLCMDUSER SQLCMDPASSWORD; " +
        "exec /opt/mssql-tools18/bin/sqlcmd -S localhost -C -b -r 1";

    public static SecureBackupProcessInvocation Create(
        string @namespace,
        string pod,
        string container,
        string sql,
        SecureSqlBackupCredential credential)
    {
        ValidateArgument(@namespace, nameof(@namespace));
        ValidateArgument(pod, nameof(pod));
        ValidateArgument(container, nameof(container));
        ArgumentException.ThrowIfNullOrWhiteSpace(sql);
        ArgumentNullException.ThrowIfNull(credential);

        string standardInput = credential.CreateChildProcessStandardInput() + sql.TrimEnd('\r', '\n') + "\n";
        string[] arguments = [
            "exec", pod, "-n", @namespace, "-c", container, "--",
            "sh", "-ceu", ShellScript,
        ];
        return new SecureBackupProcessInvocation("kubectl", arguments, standardInput);
    }

    private static void ValidateArgument(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value[0] == '-' || value.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
        {
            throw new ArgumentException("The kubectl identifier is unsafe.", parameterName);
        }
    }
}

public sealed class AtomicBackupReceiptPublisher : IBackupReceiptPublisher
{
    public const string ReceiptFileName = "backup-receipt.json";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private readonly string _publicationDirectory;
    private readonly Func<string, string, CancellationToken, Task> _writeArtifact;

    public AtomicBackupReceiptPublisher(string publicationDirectory)
        : this(publicationDirectory, WriteNewTextAsync)
    {
    }

    internal AtomicBackupReceiptPublisher(
        string publicationDirectory,
        Func<string, string, CancellationToken, Task> writeArtifact)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(publicationDirectory);
        ArgumentNullException.ThrowIfNull(writeArtifact);
        _publicationDirectory = Path.GetFullPath(publicationDirectory);
        _writeArtifact = writeArtifact;
    }

    public async Task PublishNewAsync(BackupReceipt receipt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        string? parent = Path.GetDirectoryName(_publicationDirectory);
        string name = Path.GetFileName(_publicationDirectory);
        if (string.IsNullOrWhiteSpace(parent) || string.IsNullOrWhiteSpace(name) ||
            Directory.Exists(_publicationDirectory) || File.Exists(_publicationDirectory))
        {
            throw new IOException("The backup receipt destination must be a new directory.");
        }

        _ = Directory.CreateDirectory(parent);
        string staging = Path.Combine(parent, $".{name}.{Guid.NewGuid():N}.tmp");
        try
        {
            CreateOwnerProtectedDirectory(staging);
            string json = JsonSerializer.Serialize(receipt, JsonOptions);
            await _writeArtifact(Path.Combine(staging, ReceiptFileName), json, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            Directory.Move(staging, _publicationDirectory);
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

        _ = Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
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
        new DirectoryInfo(path).Create(security);
    }
}
