using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentCustomerSequenceBootstrapHostCapacity(DateTimeOffset ObservedAtUtc, ulong AvailablePhysicalBytes, ulong OwnedRssBytes);

internal sealed record CurrentCustomerSequenceBootstrapProcessFrame(int ProcessId, DateTimeOffset StartTimeUtc,
    string ExecutablePath, string ExecutableSha256, bool Exited, long WorkingSetBytes);

/// <summary>A fresh Windows job observes ownership; cleanup kills individually verified handles, never a tree or job.</summary>
internal sealed class CurrentCustomerSequenceBootstrapHostJob : IDisposable
{
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private delegate nint CreateJob(nint security, string? name);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    private delegate nint OpenJob(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, string name);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool Assign(nint job, nint process);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool Query(nint job, int informationClass, nint buffer, uint length, out uint returned);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool Member(nint process, nint job, [MarshalAs(UnmanagedType.Bool)] out bool member);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool Close(nint handle);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool Memory(ref MemoryStatus value);
    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        internal uint Length, Load;
        internal ulong TotalPhysical, AvailablePhysical, TotalPageFile, AvailablePageFile, TotalVirtual, AvailableVirtual, AvailableExtendedVirtual;
    }
    private sealed record Held(Process Process, DateTimeOffset Start, string Image, string Hash, FileStream ImageHandle);
    private readonly nint _library, _job;
    private readonly Query _query;
    private readonly Member _member;
    private readonly Close _close;
    private readonly Memory _memory;
    private readonly Dictionary<int, Held> _held = [];
    private readonly HashSet<string> _allowedImages;
    private bool _disposed;
    internal CurrentCustomerSequenceBootstrapHostJob(IReadOnlyList<string> allowedImages, string nonce)
    {
        if (!OperatingSystem.IsWindows() || !Guid.TryParseExact(nonce, "N", out _) || allowedImages.Count is < 1 or > 8 || allowedImages.Any(x => !Path.IsPathFullyQualified(x)))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        _allowedImages = new(allowedImages.Select(Path.GetFullPath), StringComparer.OrdinalIgnoreCase);
        _library = NativeLibrary.Load(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
        try
        {
            T Function<T>(string name) where T : Delegate
            {
                return Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(_library, name));
            }

            _query = Function<Query>("QueryInformationJobObject"); _member = Function<Member>("IsProcessInJob");
            _close = Function<Close>("CloseHandle"); _memory = Function<Memory>("GlobalMemoryStatusEx");
            _job = Function<CreateJob>("CreateJobObjectW")(0, "Local\\Maliev.CustomerSequence.TypedProof." + nonce);
            if (_job == 0) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            if (Marshal.GetLastPInvokeError() == 183) { _ = _close(_job); throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        catch { NativeLibrary.Free(_library); throw; }
    }
    internal static void RequireWaitingChildMembership(string nonce)
    {
        if (!OperatingSystem.IsWindows() || !Guid.TryParseExact(nonce, "N", out _)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        nint library = NativeLibrary.Load(Path.Combine(Environment.SystemDirectory, "kernel32.dll")); nint job = 0;
        try
        {
            T Function<T>(string name) where T : Delegate
            {
                return Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));
            }

            job = Function<OpenJob>("OpenJobObjectW")(4, false, "Local\\Maliev.CustomerSequence.TypedProof." + nonce);
            using Process self = Process.GetCurrentProcess();
            if (job == 0 || !Function<Member>("IsProcessInJob")(self.SafeHandle.DangerousGetHandle(), job, out bool member) || !member)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        finally
        {
            if (job != 0) { _ = Marshal.GetDelegateForFunctionPointer<Close>(NativeLibrary.GetExport(library, "CloseHandle"))(job); }
            NativeLibrary.Free(library);
        }
    }
    internal void AssignWaitingChild(Process process)
    {
        if (_disposed || _held.Count != 0 || process.HasExited) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var assign = Marshal.GetDelegateForFunctionPointer<Assign>(NativeLibrary.GetExport(_library, "AssignProcessToJobObject"));
        // The child has no permission to launch VSTest until a held gate is written after this assignment.
        if (!assign(_job, process.SafeHandle.DangerousGetHandle())) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        Hold(process.Id);
        if (Members().Length != 1) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    private int[] Members()
    {
        const int capacity = 64;
        int bytes = 8 + (capacity * IntPtr.Size); nint buffer = Marshal.AllocHGlobal(bytes);
        try
        {
            return !_query(_job, 3, buffer, (uint)bytes, out _) || Marshal.ReadInt32(buffer) != Marshal.ReadInt32(buffer, 4) ||
                Marshal.ReadInt32(buffer, 4) is < 0 or > capacity
                ? throw CurrentCustomerSequenceRepairPermit.Invalid()
                : Enumerable.Range(0, Marshal.ReadInt32(buffer, 4)).Select(i => checked((int)Marshal.ReadIntPtr(buffer, 8 + (i * IntPtr.Size)))).ToArray();
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    private void Hold(int pid)
    {
        if (_held.TryGetValue(pid, out Held? old))
        {
            if (old.Process.HasExited) { throw CurrentCustomerSequenceRepairPermit.Invalid(); } // PID reuse in this finite job is never collapsed.
            Verify(old); return;
        }
        Process process = Process.GetProcessById(pid); FileStream? imageHandle = null;
        try
        {
            _ = process.SafeHandle;
            if (!_member(process.SafeHandle.DangerousGetHandle(), _job, out bool member) || !member || process.HasExited)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            DateTimeOffset start = new(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
            string image = process.MainModule?.FileName ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
            FileSystemInfo? ancestor = new FileInfo(image);
            while (ancestor is not null)
            {
                if ((ancestor.Attributes & FileAttributes.ReparsePoint) != 0) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                ancestor = ancestor is FileInfo file ? file.Directory : (ancestor as DirectoryInfo)?.Parent;
            }
            imageHandle = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read);
            var held = new Held(process, start, image, Convert.ToHexStringLower(SHA256.HashData(imageHandle)), imageHandle);
            Verify(held); _held.Add(pid, held); imageHandle = null;
            if (!_allowedImages.Contains(Path.GetFullPath(image))) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        catch { imageHandle?.Dispose(); process.Dispose(); throw; }
    }
    private void Verify(Held held)
    {
        if (held.Process.HasExited) { return; }
        if (new DateTimeOffset(held.Process.StartTime.ToUniversalTime(), TimeSpan.Zero) != held.Start ||
            !StringComparer.OrdinalIgnoreCase.Equals(held.Process.MainModule?.FileName, held.Image) ||
            !_member(held.Process.SafeHandle.DangerousGetHandle(), _job, out bool member) || !member ||
            !SecureLocalFile.HandleResolvesToApprovedPath(held.ImageHandle, held.Image)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    internal (CurrentCustomerSequenceBootstrapHostCapacity Capacity, CurrentCustomerSequenceBootstrapProcessFrame[] Processes) Observe(bool admission)
    {
        if (_disposed) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        foreach (int pid in Members()) { Hold(pid); }
        ulong rss = 0;
        using (Process parent = Process.GetCurrentProcess()) { parent.Refresh(); rss = checked((ulong)parent.WorkingSet64); }
        var frames = new List<CurrentCustomerSequenceBootstrapProcessFrame>();
        foreach ((int pid, Held held) in _held)
        {
            Verify(held); bool exited = held.Process.HasExited; long size = 0;
            if (!exited) { held.Process.Refresh(); size = held.Process.WorkingSet64; rss = checked(rss + (ulong)size); }
            frames.Add(new(pid, held.Start, held.Image, held.Hash, exited, size));
        }
        var memory = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
        if (!_memory(ref memory)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        CurrentCustomerSequenceCapacity.RequireValues(memory.AvailablePhysical, rss, admission);
        return (new(DateTimeOffset.UtcNow, memory.AvailablePhysical, rss), frames.ToArray());
    }
    internal bool Empty => Members().Length == 0;
    internal async Task CompleteCleanupAsync()
    {
        // Refresh the authoritative job inventory before individually terminating any exact held process.
        foreach (int pid in Members()) { Hold(pid); }
        foreach (Held held in _held.Values)
        {
            Verify(held);
            if (!held.Process.HasExited) { held.Process.Kill(); }
        }
        foreach (Held held in _held.Values)
        { await held.Process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false); }
        if (!Empty || _held.Values.Any(x => !x.Process.HasExited)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    public void Dispose()
    {
        if (_disposed) { return; }
        _disposed = true;
        foreach (Held held in _held.Values) { held.ImageHandle.Dispose(); held.Process.Dispose(); }
        // No KILL_ON_JOB_CLOSE and no TerminateJobObject: disposal never substitutes for verified cleanup.
        if (_job != 0) { _ = _close(_job); }
        NativeLibrary.Free(_library);
    }
}
