using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Legacy.Maliev.DataMigration.Console;

internal static class CurrentAuthRepairCapacity
{
    private const ulong GiB = 1024UL * 1024 * 1024;
    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        internal uint Length, Load;
        internal ulong TotalPhysical, AvailablePhysical, TotalPageFile, AvailablePageFile, TotalVirtual, AvailableVirtual, AvailableExtendedVirtual;
    }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool ObserveMemory(ref MemoryStatus value);
    internal static void Require(bool admission)
    {
        if (!OperatingSystem.IsWindows()) { throw CurrentAuthRepairPermit.Invalid(); }
        nint library = NativeLibrary.Load(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
        try
        {
            var observer = Marshal.GetDelegateForFunctionPointer<ObserveMemory>(NativeLibrary.GetExport(library, "GlobalMemoryStatusEx"));
            var memory = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
            if (!observer(ref memory)) { throw new MigrationExecutionException("host_memory_observation_failed", "Host memory observation failed."); }
            using var process = Process.GetCurrentProcess(); process.Refresh();
            RequireValues(memory.AvailablePhysical, (ulong)process.WorkingSet64, admission);
        }
        finally { NativeLibrary.Free(library); }
    }
    internal static void RequireValues(ulong available, ulong ownedRss, bool admission)
    {
        if (available < (admission ? 3 * GiB : GiB))
        {
            throw new MigrationExecutionException(admission ?
            "host_free_memory_admission_below_3GiB" : "host_free_memory_floor_below_1GiB", "Host memory admission failed.");
        }
        if (ownedRss > 5 * GiB) { throw new MigrationExecutionException("owned_rss_above_5GiB", "Owned process memory admission failed."); }
    }
}
