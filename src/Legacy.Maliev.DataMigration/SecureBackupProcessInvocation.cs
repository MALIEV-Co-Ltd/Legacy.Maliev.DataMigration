using System.Diagnostics;
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
        "exec /opt/mssql-tools18/bin/sqlcmd -S localhost -C -b -r 1 -W -h -1 -s '|'";

    public static SecureBackupProcessInvocation Create(
        string @namespace,
        string pod,
        string container,
        string sql,
        SecureSqlBackupCredential credential)
    {
        return Create(@namespace, pod, container, sql, credential, null);
    }

    public static SecureBackupProcessInvocation Create(
        string @namespace,
        string pod,
        string container,
        string sql,
        SecureSqlBackupCredential credential,
        string? sessionMarker)
    {
        ValidateArgument(@namespace, nameof(@namespace));
        ValidateArgument(pod, nameof(pod));
        ValidateArgument(container, nameof(container));
        ArgumentException.ThrowIfNullOrWhiteSpace(sql);
        ArgumentNullException.ThrowIfNull(credential);

        string standardInput = credential.CreateChildProcessStandardInput() + sql.TrimEnd('\r', '\n') + "\n";
        string shellScript = sessionMarker is null
            ? ShellScript
            : "marker=$1; shift; test -f \"$marker\"; test ! -L \"$marker\"; test \"$(stat -c %u -- \"$marker\")\" = \"$(id -u)\"; test \"$(stat -c %a -- \"$marker\")\" = 600; " + ShellScript;
        string[] arguments = sessionMarker is null ? [
            "exec", pod, "-n", @namespace, "-c", container, "--",
            "sh", "-ceu", shellScript,
        ] : [
            "exec", pod, "-n", @namespace, "-c", container, "--",
            "sh", "-ceu", shellScript, "sh", sessionMarker,
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

        string staging = Path.Combine(parent, $".{name}.{Guid.NewGuid():N}.tmp");
        try
        {
            OwnerProtectedDirectory.CreateNew(staging);
            SecureLocalFile.EnsureOwnerOnlyDirectory(staging);
            string json = JsonSerializer.Serialize(receipt, JsonOptions);
            string receiptPath = Path.Combine(staging, ReceiptFileName);
            await _writeArtifact(receiptPath, json, cancellationToken).ConfigureAwait(false);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(receiptPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            if (!SecureLocalFile.IsOwnerOnlyFile(new FileInfo(receiptPath)))
            {
                throw new IOException("The staged backup receipt is not a regular non-link file.");
            }
            cancellationToken.ThrowIfCancellationRequested();
            SecureLocalFile.EnsureOwnerOnlyDirectory(staging);
            Directory.Move(staging, _publicationDirectory);
            SecureLocalFile.EnsureOwnerOnlyDirectory(_publicationDirectory);
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

}

public sealed record BackupProcessResult(int ExitCode, string StandardOutput, string StandardError);

public interface IBackupProcessRunner
{
    Task<BackupProcessResult> RunAsync(SecureBackupProcessInvocation invocation, CancellationToken cancellationToken);

    Task<BackupProcessResult> RunToNewFileAsync(
        SecureBackupProcessInvocation invocation,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        throw new NotSupportedException("This process runner does not support binary streaming output.");
    }
}

internal interface IBackupProcessIo
{
    Stream CreateDestination(string path);
    Task<string> ReadStandardOutputAsync(Process process, CancellationToken cancellationToken);
    Task<string> ReadStandardErrorAsync(Process process, CancellationToken cancellationToken);
    Task WriteStandardInputAsync(Process process, string input, CancellationToken cancellationToken);
    Task CopyStandardOutputAsync(Process process, Stream destination, CancellationToken cancellationToken);
    Task FlushDestinationAsync(Stream destination, CancellationToken cancellationToken);
    void Kill(Process process);
    Task WaitForExitAsync(Process process, CancellationToken cancellationToken);
}

internal sealed class SystemBackupProcessIo : IBackupProcessIo
{
    public Stream CreateDestination(string path)
    {
        return new FileStream(
        path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024,
        FileOptions.Asynchronous | FileOptions.WriteThrough);
    }

    public Task<string> ReadStandardOutputAsync(Process process, CancellationToken cancellationToken)
    {
        return process.StandardOutput.ReadToEndAsync(cancellationToken);
    }

    public Task<string> ReadStandardErrorAsync(Process process, CancellationToken cancellationToken)
    {
        return process.StandardError.ReadToEndAsync(cancellationToken);
    }

    public Task WriteStandardInputAsync(Process process, string input, CancellationToken cancellationToken)
    {
        return process.StandardInput.WriteAsync(input.AsMemory(), cancellationToken);
    }

    public Task CopyStandardOutputAsync(Process process, Stream destination, CancellationToken cancellationToken)
    {
        return process.StandardOutput.BaseStream.CopyToAsync(destination, cancellationToken);
    }

    public Task FlushDestinationAsync(Stream destination, CancellationToken cancellationToken)
    {
        return destination.FlushAsync(cancellationToken);
    }

    public void Kill(Process process)
    {
        process.Kill(entireProcessTree: true);
    }

    public Task WaitForExitAsync(Process process, CancellationToken cancellationToken)
    {
        return process.WaitForExitAsync(cancellationToken);
    }
}

public sealed class SystemBackupProcessRunner : IBackupProcessRunner
{
    private static readonly TimeSpan CleanupTimeout = TimeSpan.FromSeconds(5);
    private readonly IBackupProcessIo _io;

    public SystemBackupProcessRunner() : this(new SystemBackupProcessIo())
    {
    }

    internal SystemBackupProcessRunner(IBackupProcessIo io)
    {
        _io = io ?? throw new ArgumentNullException(nameof(io));
    }

    public async Task<BackupProcessResult> RunAsync(
        SecureBackupProcessInvocation invocation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        var startInfo = new ProcessStartInfo(invocation.FileName)
        {
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        foreach (string argument in invocation.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
            {
                throw new Exact25BackupTransportException("process_start_failed", $"Failed to start {invocation}.", retryable: false);
            }
        }
        catch (Exception exception) when (exception is not Exact25BackupTransportException and not OperationCanceledException)
        {
            throw new Exact25BackupTransportException("process_start_failed", $"Failed to start {invocation}: {exception.GetType().Name}.", retryable: false);
        }

        Task<string>? stdout = null;
        Task<string>? stderr = null;
        try
        {
            stdout = _io.ReadStandardOutputAsync(process, cancellationToken);
            stderr = _io.ReadStandardErrorAsync(process, cancellationToken);
            if (invocation.StandardInput.Length > 0)
            {
                await _io.WriteStandardInputAsync(process, invocation.StandardInput, cancellationToken).ConfigureAwait(false);
            }

            TryCloseStandardInput(process);
            Task exited = _io.WaitForExitAsync(process, cancellationToken);
            await ThrowIfAnyCompletesFaultedAsync(exited, stdout, stderr).ConfigureAwait(false);
            await Task.WhenAll(exited, stdout, stderr).ConfigureAwait(false);
            return new(process.ExitCode, stdout.Result, stderr.Result);
        }
        catch
        {
            await TerminateAndObserveAsync(process, stdout, stderr).ConfigureAwait(false);
            throw;
        }
        finally
        {
            TryCloseStandardInput(process);
        }

    }

    public async Task<BackupProcessResult> RunToNewFileAsync(
        SecureBackupProcessInvocation invocation,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        string fullDestination = Path.GetFullPath(destinationPath);
        var startInfo = new ProcessStartInfo(invocation.FileName)
        {
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        foreach (string argument in invocation.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
            {
                throw new Exact25BackupTransportException("process_start_failed", $"Failed to start {invocation}.", false);
            }
        }
        catch (Exception exception) when (exception is not Exact25BackupTransportException and not OperationCanceledException)
        {
            throw new Exact25BackupTransportException("process_start_failed", $"Failed to start {invocation}: {exception.GetType().Name}.", false);
        }

        Task<string>? stderr = null;
        Task? copy = null;
        try
        {
            stderr = _io.ReadStandardErrorAsync(process, cancellationToken);
            await using Stream destination = _io.CreateDestination(fullDestination);
            if (invocation.StandardInput.Length > 0)
            {
                await _io.WriteStandardInputAsync(process, invocation.StandardInput, cancellationToken).ConfigureAwait(false);
            }
            TryCloseStandardInput(process);
            copy = _io.CopyStandardOutputAsync(process, destination, cancellationToken);
            Task exited = _io.WaitForExitAsync(process, cancellationToken);
            await ThrowIfAnyCompletesFaultedAsync(exited, copy, stderr).ConfigureAwait(false);
            await Task.WhenAll(exited, copy, stderr).ConfigureAwait(false);
            await _io.FlushDestinationAsync(destination, cancellationToken).ConfigureAwait(false);
            return new(process.ExitCode, string.Empty, stderr.Result);
        }
        catch
        {
            await TerminateAndObserveAsync(process, stderr, copy).ConfigureAwait(false);
            throw;
        }
        finally
        {
            TryCloseStandardInput(process);
        }
    }

    private static async Task ThrowIfAnyCompletesFaultedAsync(params Task[] tasks)
    {
        Task completed = await Task.WhenAny(tasks).ConfigureAwait(false);
        await completed.ConfigureAwait(false);
    }

    private async Task TerminateAndObserveAsync(Process process, params Task?[] backgroundTasks)
    {
        TryCloseStandardInput(process);

        for (var attempt = 0; attempt < 2; attempt++)
        {
            try
            {
                if (!process.HasExited)
                {
                    _io.Kill(process);
                }
            }
            catch (Exception)
            {
                // A transient platform failure must not skip a second termination attempt.
            }
        }

        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception)
        {
            // The bounded wait below still observes a concurrent or platform-specific exit.
        }

        using var cleanupTimeout = new CancellationTokenSource(CleanupTimeout);
        try
        {
            await _io.WaitForExitAsync(process, cleanupTimeout.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Preserve the original operation failure after attempting every cleanup step.
        }

        foreach (Task task in backgroundTasks.OfType<Task>())
        {
            try
            {
                await task.WaitAsync(CleanupTimeout).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Preserve the original failure after every child I/O task has been observed.
                _ = task.ContinueWith(
                    completed => _ = completed.Exception,
                    CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
        }
    }

    private static void TryCloseStandardInput(Process process)
    {
        try
        {
            process.StandardInput.Close();
        }
        catch (InvalidOperationException)
        {
        }
    }
}

internal static class OwnerProtectedDirectory
{
    public static void CreateNew(string path)
    {
        string fullPath = Path.GetFullPath(path);
        string? parent = Path.GetDirectoryName(fullPath);
        string name = Path.GetFileName(fullPath);
        if (string.IsNullOrWhiteSpace(parent) || string.IsNullOrWhiteSpace(name))
        {
            throw new IOException("The owner-protected directory requires a parent and a new name.");
        }

        EnsureNoLinkAncestors(parent);
        _ = Directory.CreateDirectory(parent);
        EnsureNoLinkAncestors(parent);
        string staging = Path.Combine(parent, $".{name}.{Guid.NewGuid():N}.tmp");
        try
        {
            CreateOwnerProtected(staging);
            Directory.Move(staging, fullPath);
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

    private static void EnsureNoLinkAncestors(string path)
    {
        for (DirectoryInfo? current = new(Path.GetFullPath(path)); current is not null; current = current.Parent)
        {
            current.Refresh();
            if (!current.Exists)
            {
                continue;
            }

            if (current.LinkTarget is not null || (current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("The owner-protected directory path contains a symbolic link or reparse point.");
            }
        }
    }

    private static void CreateOwnerProtected(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            CreateOwnerProtectedWindowsDirectory(path);
            return;
        }

        _ = Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
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
