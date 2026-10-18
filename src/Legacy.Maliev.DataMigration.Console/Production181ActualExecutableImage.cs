using System.Diagnostics;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Console;

// Only the actual current process image is eligible. Public installed executables do not have
// artifact-owner ACLs; protected DLLs and all proof artifacts keep their existing custody readers.
internal sealed class Production181ActualExecutableImage : IDisposable
{
    private readonly Process _process;
    private readonly FileStream _image;
    private bool _disposed;
    internal string Path { get; }
    internal int ProcessId { get; }
    internal DateTimeOffset ProcessStartTimeUtc { get; }
    internal string Sha256 { get; }
    private Production181ActualExecutableImage(Process process, FileStream image, string path)
    {
        _process = process; _image = image; Path = path; ProcessId = process.Id;
        ProcessStartTimeUtc = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
        Require(); Sha256 = Convert.ToHexStringLower(SHA256.HashData(image)); Require();
    }
    internal static Production181ActualExecutableImage OpenCurrent()
    {
        if (!OperatingSystem.IsWindows()) { throw Invalid(); }
        var process = Process.GetCurrentProcess(); FileStream? image = null;
        try
        {
            string path = Environment.ProcessPath ?? throw Invalid();
            if (!System.IO.Path.IsPathFullyQualified(path) ||
                !StringComparer.OrdinalIgnoreCase.Equals(process.MainModule?.FileName, path)) { throw Invalid(); }
            RequireNonReparseAncestry(path);
            image = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return new(process, image, path);
        }
        catch { image?.Dispose(); process.Dispose(); throw; }
    }
    internal void Require()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_process.HasExited || _process.Id != Environment.ProcessId || _process.Id != ProcessId ||
            new DateTimeOffset(_process.StartTime.ToUniversalTime(), TimeSpan.Zero) != ProcessStartTimeUtc ||
            !StringComparer.OrdinalIgnoreCase.Equals(Environment.ProcessPath, Path) ||
            !StringComparer.OrdinalIgnoreCase.Equals(_process.MainModule?.FileName, Path) ||
            !SecureLocalFile.HandleResolvesToApprovedPath(_image, Path) || _image.Length is < 1 or > 128L * 1024 * 1024) { throw Invalid(); }
        RequireNonReparseAncestry(Path);
    }
    private static void RequireNonReparseAncestry(string path)
    {
        FileSystemInfo? entry = new FileInfo(path);
        while (entry is not null)
        {
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0) { throw Invalid(); }
            entry = entry is FileInfo file ? file.Directory : (entry as DirectoryInfo)?.Parent;
        }
    }
    public void Dispose()
    { if (_disposed) { return; } _disposed = true; _image.Dispose(); _process.Dispose(); }
    private static MigrationExecutionException Invalid()
    {
        return CurrentCustomerSequenceRepairPermit.Invalid();
    }
}
