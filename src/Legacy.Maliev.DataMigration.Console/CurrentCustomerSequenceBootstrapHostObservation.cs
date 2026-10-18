using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

// Observes a testhost already owned by the serialized host runner. It never launches, assigns,
// terminates or admits a process. The runner retains its unchanged capacity/cleanup obligations.
internal sealed class CustomerGuardedBootstrapHostObservation : IDisposable
{
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    private delegate nint OpenJob(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, string name);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool Member(nint process, nint job, [MarshalAs(UnmanagedType.Bool)] out bool member);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool Query(nint job, int informationClass, nint buffer, uint length, out uint returned);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool Close(nint handle);
    private readonly Process _process;
    private readonly FileStream _image, _test;
    private readonly nint _library, _job;
    private readonly Member _member;
    private readonly Query _query;
    private readonly Close _close;
    private readonly int _pid;
    private readonly DateTimeOffset _start, _observed;
    private readonly string _executable, _imageHash, _testHash, _nonce;
    private bool _disposed;

    internal CustomerGuardedBootstrapHostObservation(int processId, string jobNonce, string testAssemblyPath)
    {
        if (!OperatingSystem.IsWindows() || processId <= 0 || !Guid.TryParseExact(jobNonce, "N", out _) || !Path.IsPathFullyQualified(testAssemblyPath)) { throw Invalid(); }
        _nonce = jobNonce; _pid = processId;
        _library = NativeLibrary.Load(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
        Process? process = null; FileStream? image = null, test = null; nint job = 0;
        try
        {
            T Function<T>(string name) where T : Delegate
            {
                return Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(_library, name));
            }

            _member = Function<Member>("IsProcessInJob"); _query = Function<Query>("QueryInformationJobObject"); _close = Function<Close>("CloseHandle");
            job = Function<OpenJob>("OpenJobObjectW")(4, false, "Local\\Maliev.CustomerSequence.TypedProof." + jobNonce);
            process = Process.GetProcessById(processId);
            if (job == 0 || process.HasExited || !_member(process.SafeHandle.DangerousGetHandle(), job, out bool member) || !member) { throw Invalid(); }
            _start = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero); _executable = process.MainModule?.FileName ?? throw Invalid();
            image = HoldImage(_executable); test = SecureLocalFile.OpenReadShared(testAssemblyPath);
            if (test.Length is < 1 or > 128 * 1024 * 1024) { throw Invalid(); }
            _imageHash = Convert.ToHexStringLower(SHA256.HashData(image)); _testHash = Convert.ToHexStringLower(SHA256.HashData(test));
            _observed = DateTimeOffset.UtcNow; _process = process; _image = image; _test = test; _job = job;
            RequireLive(); process = null; image = null; test = null; job = 0;
        }
        catch
        { process?.Dispose(); image?.Dispose(); test?.Dispose(); if (job != 0) { _ = Marshal.GetDelegateForFunctionPointer<Close>(NativeLibrary.GetExport(_library, "CloseHandle"))(job); } NativeLibrary.Free(_library); throw; }
    }

    internal static void RequireCurrentMembership(string nonce)
    {
        if (!OperatingSystem.IsWindows() || !Guid.TryParseExact(nonce, "N", out _)) { throw Invalid(); }
        nint library = NativeLibrary.Load(Path.Combine(Environment.SystemDirectory, "kernel32.dll")), job = 0;
        try
        {
            T Function<T>(string name) where T : Delegate
            {
                return Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
            }

            job = Function<OpenJob>("OpenJobObjectW")(4, false, "Local\\Maliev.CustomerSequence.TypedProof." + nonce);
            using var process = Process.GetCurrentProcess();
            if (job == 0 || !Function<Member>("IsProcessInJob")(process.SafeHandle.DangerousGetHandle(), job, out bool member) || !member) { throw Invalid(); }
        }
        finally { if (job != 0) { _ = Marshal.GetDelegateForFunctionPointer<Close>(NativeLibrary.GetExport(library, "CloseHandle"))(job); } NativeLibrary.Free(library); }
    }

    internal async Task<CustomerDefinitionArtifact> RetainActualSuccessfulExitAsync(CurrentAppOwnedRepairCustody files, string outputPath,
        IReadOnlyList<Guid> actualRunIds, CancellationToken ct)
    {
        if (_disposed || actualRunIds.Count is not (4 or 6) || actualRunIds.Any(x => x == Guid.Empty) || actualRunIds.Distinct().Count() != actualRunIds.Count) { throw Invalid(); }
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddMinutes(50);
        while (!_process.HasExited)
        { ct.ThrowIfCancellationRequested(); CurrentCustomerSequenceCapacity.Require(admission: false); RequireLive(); if (DateTimeOffset.UtcNow >= deadline) { throw Invalid(); } await Task.Delay(250, ct).ConfigureAwait(false); }
        await _process.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
        DateTimeOffset exited = new(_process.ExitTime.ToUniversalTime(), TimeSpan.Zero);
        if (_process.ExitCode != 0 || _process.Id != _pid || exited < _observed || Members().Length != 0 ||
            !SecureLocalFile.HandleResolvesToApprovedPath(_image, _executable)) { throw Invalid(); }
        var evidence = new CustomerGuardedBootstrapHostExit("current-customer-sequence-actual-testhost-exit-v1", _pid, _start, _executable,
            _imageHash, _testHash, exited, _process.ExitCode, actualRunIds, true, _nonce, _observed, true, true);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(evidence);
        await files.WriteNewAsync(outputPath, bytes, ct).ConfigureAwait(false);
        byte[] readback = files.Read(outputPath, sharedReader: true, maximumBytes: 65536);
        return !CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), SHA256.HashData(readback))
            ? throw Invalid()
            : new(outputPath, Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }
    private void RequireLive()
    {
        if (_disposed || _process.HasExited || _process.Id != _pid || new DateTimeOffset(_process.StartTime.ToUniversalTime(), TimeSpan.Zero) != _start ||
            !StringComparer.OrdinalIgnoreCase.Equals(_process.MainModule?.FileName, _executable) ||
            !_member(_process.SafeHandle.DangerousGetHandle(), _job, out bool member) || !member || !Members().Contains(_pid) ||
            !SecureLocalFile.HandleResolvesToApprovedPath(_image, _executable)) { throw Invalid(); }
    }
    private int[] Members()
    {
        const int capacity = 64; int bytes = 8 + (capacity * IntPtr.Size); nint buffer = Marshal.AllocHGlobal(bytes);
        try
        {
            return !_query(_job, 3, buffer, (uint)bytes, out _) || Marshal.ReadInt32(buffer) != Marshal.ReadInt32(buffer, 4) || Marshal.ReadInt32(buffer, 4) is < 0 or > capacity
                ? throw Invalid()
                : Enumerable.Range(0, Marshal.ReadInt32(buffer, 4)).Select(i => checked((int)Marshal.ReadIntPtr(buffer, 8 + (i * IntPtr.Size)))).ToArray();
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    private static FileStream HoldImage(string path)
    {
        FileSystemInfo? entry = new FileInfo(path);
        while (entry is not null) { if ((entry.Attributes & FileAttributes.ReparsePoint) != 0) { throw Invalid(); } entry = entry is FileInfo file ? file.Directory : (entry as DirectoryInfo)?.Parent; }
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            return !SecureLocalFile.HandleResolvesToApprovedPath(stream, path) || stream.Length is < 1 or > 128 * 1024 * 1024
            ? throw Invalid()
            : stream;
        }
        catch { stream.Dispose(); throw; }
    }
    public void Dispose()
    { if (_disposed) { return; } _disposed = true; _image.Dispose(); _test.Dispose(); _process.Dispose(); if (_job != 0) { _ = _close(_job); } NativeLibrary.Free(_library); }
    private static MigrationExecutionException Invalid()
    {
        return new("customer_guarded_bootstrap_host_invalid", "Actual held testhost membership and successful observed exit required.");
    }
}
