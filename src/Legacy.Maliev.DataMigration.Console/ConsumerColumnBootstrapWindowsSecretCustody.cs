using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Legacy.Maliev.DataMigration.Console;

// Local cleanup only. These receipts never authorize a database operation or accept recovery proof.
internal static class ConsumerColumnBootstrapWindowsSecretCustody
{
    private const string Kind = "consumer-bootstrap-generated-windows-secret-custody-v1";
    private sealed record Creation(string Kind, string RunBindingSha256, string Root, string Leaf, string Identity, DateTimeOffset CreatedAtUtc);
    private static readonly string[] Fixed = ["review-private.pem", "authorization-private.pem", "receipt-private.pem", "operator.secret", "ordinary.secret"];
    private static readonly string[] Forward = ["review-private.pem", "authorization-private.pem", "receipt-private.pem"];
    private static readonly string[] Reviewed = ["review.pem", "authorization.pem", "receipt.pem"];

    internal static async Task<string> CreateAsync(LocalExecutionBinding binding, CurrentAppOwnedRepairCustody files, string path, byte[] bytes, CancellationToken ct)
    {
        FileStream? output = null; bool published = false; string? identity = null;
        try
        {
            ct.ThrowIfCancellationRequested();
            RequirePath(binding, path); files.Require();
            if (bytes.Length is < 1 or > 65536) { throw Invalid(); }
            SafeFileHandle created = CreateFile(NativePath(path), 0x80000000 | 0x40000000 | 0x10000 | 0x80, 0, IntPtr.Zero, 1, 0xC0200000, IntPtr.Zero);
            if (created.IsInvalid) { int error = Marshal.GetHRForLastWin32Error(); created.Dispose(); throw new IOException("bootstrap_generated_secret_create_failed", error); }
            try { output = new(created, FileAccess.ReadWrite, 4096, isAsync: true); }
            catch { created.Dispose(); throw; }
            identity = Observe(output, path);
            var capture = new Creation(Kind, binding.ComputeSha256(), binding.ArtifactRootCanonicalPath, Path.GetFileName(path), identity, DateTimeOffset.UtcNow);
            // Persist the actual created object BEFORE private bytes, including partial-write/cancellation recovery.
            await files.WriteNewAsync(Sidecar(path), JsonSerializer.SerializeToUtf8Bytes(capture), ct).ConfigureAwait(false); published = true;
            await output.WriteAsync(bytes, ct).ConfigureAwait(false); await output.FlushAsync(ct).ConfigureAwait(false); output.Flush(true); output.Position = 0;
            byte[] readback = new byte[bytes.Length];
            try
            {
                await output.ReadExactlyAsync(readback, ct).ConfigureAwait(false);
                if (output.Length != bytes.Length || !readback.AsSpan().SequenceEqual(bytes) || Observe(output, path) != identity) { throw Invalid(); }
            }
            finally { CryptographicOperations.ZeroMemory(readback); }
            files.Require(); return identity;
        }
        catch (Exception primary)
        {
            if (!published && output is not null && identity is not null)
            {
                try
                {
                    // This exact CreateNew handle is still open and no private bytes were written.
                    if (output.Length != 0 || Observe(output, path) != identity) { throw Invalid(); }
                    MarkDelete(output.SafeFileHandle);
                }
                catch (Exception cleanup) { throw new AggregateException(primary, cleanup); }
            }
            throw;
        }
        finally { output?.Dispose(); CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static void RemoveDetached(LocalExecutionBinding binding, IEnumerable<(string Path, string Identity)> secrets, DateTimeOffset createdAfter)
    {
        if (!OperatingSystem.IsWindows()) { throw Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        foreach (var secret in secrets)
        {
            RequirePath(binding, secret.Path); files.Require();
            if (!File.Exists(secret.Path) && !File.Exists(Sidecar(secret.Path))) { continue; }
            if (!File.Exists(Sidecar(secret.Path))) { throw Invalid(); } // Existing untracked file is not cleanup authority.
            var capture = MigrationConsole.DecodeAuthRepair<Creation>(files.Read(Sidecar(secret.Path), sharedReader: true, maximumBytes: 65536));
            if (capture.Kind != Kind || capture.RunBindingSha256 != binding.ComputeSha256() || capture.Root != binding.ArtifactRootCanonicalPath ||
                capture.Leaf != Path.GetFileName(secret.Path) || capture.CreatedAtUtc < createdAfter.AddSeconds(-1) ||
                capture.CreatedAtUtc.Offset != TimeSpan.Zero || capture.CreatedAtUtc > DateTimeOffset.UtcNow ||
                (!string.IsNullOrEmpty(secret.Identity) && capture.Identity != secret.Identity)) { throw Invalid(); }
            if (!File.Exists(secret.Path)) { continue; } // Previously deleted exact created object; sidecar remains immutable.
            using (SafeFileHandle handle = CreateFile(NativePath(secret.Path), 0x80000000 | 0x10000 | 0x80, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero))
            {
                if (handle.IsInvalid) { throw new IOException("bootstrap_generated_secret_cleanup_open_failed"); }
                using var stream = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
                if (Observe(stream, secret.Path) != capture.Identity || stream.Length > 65536 || File.GetCreationTimeUtc(secret.Path) < createdAfter.UtcDateTime.AddSeconds(-1)) { throw Invalid(); }
                authority.ValidateHeld(); MarkDelete(handle);
            }
            files.Require(); if (File.Exists(secret.Path)) { throw new IOException("bootstrap_generated_secret_cleanup_absence_failed"); }
        }
        files.Require();
    }
    private static string Observe(FileStream stream, string path)
    {
        return !OperatingSystem.IsWindows() || !SecureLocalFile.HandleResolvesToApprovedPath(stream, path) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path)) ||
            !GetInformation(stream.SafeFileHandle, out FileInformation information) || information.Links != 1 || (information.Attributes & 0x410) != 0
            ? throw Invalid()
            : JsonSerializer.Serialize(WindowsRunFileIdentity.Observe(stream.SafeFileHandle));
    }
    private static void RequirePath(LocalExecutionBinding binding, string path)
    {
        if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(path) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(path)), binding.ArtifactRootCanonicalPath)) { throw Invalid(); }
        string leaf = Path.GetFileName(path);
        if (!Fixed.Contains(leaf, StringComparer.Ordinal) && !Generated(leaf, "fault-forward-", Forward) && !Generated(leaf, "bootstrap-reviewed-", Reviewed)) { throw Invalid(); }
    }
    private static bool Generated(string leaf, string prefix, IReadOnlyList<string> suffixes)
    {
        if (!leaf.StartsWith(prefix, StringComparison.Ordinal) || leaf.Length <= prefix.Length + 33 || leaf[prefix.Length + 32] != '-') { return false; }
        string nonce = leaf.Substring(prefix.Length, 32);
        return nonce.All(x => x is (>= '0' and <= '9') or (>= 'a' and <= 'f')) && Guid.TryParseExact(nonce, "N", out Guid id) && id != Guid.Empty &&
            suffixes.Contains(leaf[(prefix.Length + 33)..], StringComparer.Ordinal);
    }
    private static string Sidecar(string path)
    {
        return path + ".bootstrap-secret-custody.json";
    }

    private static string NativePath(string path)
    {
        return @"\\?\" + Path.GetFullPath(path);
    }

    private static void MarkDelete(SafeFileHandle handle)
    { var disposition = new Disposition { DeleteFile = 1 }; if (!SetInformation(handle, 4, ref disposition, 1)) { throw new IOException("bootstrap_generated_secret_cleanup_delete_failed"); } }
    private static MigrationExecutionException Invalid()
    {
        return ConsumerColumnBootstrapOperationalContract.Invalid();
    }

    [StructLayout(LayoutKind.Sequential)] private struct Disposition { internal byte DeleteFile; }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    { internal uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
#pragma warning disable SYSLIB1054 // Fixed Windows file-handle ABI, matching existing custody without enabling unsafe source generation.
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint sharing, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetInformation(SafeFileHandle handle, out FileInformation information);
    [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformation(SafeFileHandle handle, int informationClass, ref Disposition value, uint size);
#pragma warning restore SYSLIB1054
}
