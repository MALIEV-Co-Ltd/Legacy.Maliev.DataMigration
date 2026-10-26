using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchivePhysicalDevice(string VolumeGuid, uint DiskNumber, long ExtentStart,
    long ExtentLength, uint BusType, string SerialSha256);
internal sealed record CurrentAuthArchiveDeviceProof(string Domain, Guid OperationId, string SourceCommitSha,
    string OwnerPinsSha256, string LocalRunBindingSha256, string ProductionRunBindingSha256,
    string LocalTargetObservationSha256, string ProductionTargetObservationSha256,
    CurrentAuthArchivePaths Paths, CurrentAuthArchivePhysicalDevice First, CurrentAuthArchivePhysicalDevice Second,
    DateTimeOffset ObservedAtUtc);

/// <summary>Actual held Windows native disk extent/descriptor observation. No configured device claims.</summary>
internal static class CurrentAuthLocalSessionArchiveRecoveryDevices
{
    // Called only by the fixed child route: parent never executes synchronous driver calls.
    internal static CurrentAuthArchiveDeviceProof ObserveInChild(CurrentAuthArchiveScope scope, string firstRoot, string secondRoot, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows()) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        firstRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(firstRoot));
        secondRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(secondRoot));
        RequireDirectChild(scope.Paths.FirstCiphertext, firstRoot); RequireDirectChild(scope.Paths.RecoveryPrivateKey, firstRoot);
        RequireDirectChild(scope.Paths.SecondCiphertext, secondRoot); RequireDirectChild(scope.Paths.SecondRecoveryPrivateKey, secondRoot);
        if (StringComparer.OrdinalIgnoreCase.Equals(firstRoot, secondRoot)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        CurrentAuthArchivePhysicalDevice first = Read(firstRoot, ct), second = Read(secondRoot, ct);
        RequireIndependent(first, second);
        return new("Legacy.Maliev.CurrentAuth.ArchivePhysicalDevices.v1", scope.OperationId, scope.LocalObservationPolicy.SourceCommitSha,
            CurrentAuthRepairPermit.OwnerPinsSha256, scope.LocalObservationPolicy.RunBindingSha256, scope.ProductionObservationPolicy.RunBindingSha256,
            scope.LocalObservationPolicy.TargetObservationSha256, scope.ProductionObservationPolicy.TargetObservationSha256, scope.Paths, first, second, DateTimeOffset.UtcNow);
    }
    internal static void RequireSubject(CurrentAuthArchiveDeviceProof proof, CurrentAuthArchiveScope scope, string firstRoot, string secondRoot)
    {
        RequireDirectChild(scope.Paths.FirstCiphertext, Path.TrimEndingDirectorySeparator(Path.GetFullPath(firstRoot)));
        RequireDirectChild(scope.Paths.RecoveryPrivateKey, Path.TrimEndingDirectorySeparator(Path.GetFullPath(firstRoot)));
        RequireDirectChild(scope.Paths.SecondCiphertext, Path.TrimEndingDirectorySeparator(Path.GetFullPath(secondRoot)));
        RequireDirectChild(scope.Paths.SecondRecoveryPrivateKey, Path.TrimEndingDirectorySeparator(Path.GetFullPath(secondRoot)));
        if (proof.Domain != "Legacy.Maliev.CurrentAuth.ArchivePhysicalDevices.v1" || proof.OperationId != scope.OperationId ||
            proof.SourceCommitSha != scope.LocalObservationPolicy.SourceCommitSha || proof.OwnerPinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 ||
            proof.LocalRunBindingSha256 != scope.LocalObservationPolicy.RunBindingSha256 || proof.ProductionRunBindingSha256 != scope.ProductionObservationPolicy.RunBindingSha256 ||
            proof.LocalTargetObservationSha256 != scope.LocalObservationPolicy.TargetObservationSha256 || proof.ProductionTargetObservationSha256 != scope.ProductionObservationPolicy.TargetObservationSha256 ||
            proof.Paths != scope.Paths || proof.ObservedAtUtc.Offset != TimeSpan.Zero || proof.ObservedAtUtc > DateTimeOffset.UtcNow ||
            DateTimeOffset.UtcNow - proof.ObservedAtUtc > TimeSpan.FromMinutes(1)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        RequireIndependent(proof.First, proof.Second);
    }
    internal static void RequireProof(CurrentAuthArchiveDeviceProof pinned, CurrentAuthArchiveScope scope,
        CurrentAuthArchiveDeviceProof actual, DateTimeOffset now)
    {
        if (CurrentAuthLocalSessionArchivePolicy.Hash(pinned) != scope.RecoveryDeviceProofSha256 ||
            pinned.ObservedAtUtc.Offset != TimeSpan.Zero || pinned.ObservedAtUtc > now || now - pinned.ObservedAtUtc > TimeSpan.FromMinutes(5) ||
            actual.ObservedAtUtc.Offset != TimeSpan.Zero || actual.ObservedAtUtc > now || now - actual.ObservedAtUtc > TimeSpan.FromMinutes(1) ||
            pinned != actual with { ObservedAtUtc = pinned.ObservedAtUtc }) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        RequireIndependent(actual.First, actual.Second);
    }
    internal static void RequireIndependent(CurrentAuthArchivePhysicalDevice first, CurrentAuthArchivePhysicalDevice second)
    {
        static bool Valid(CurrentAuthArchivePhysicalDevice device)
        {
            return device.VolumeGuid.StartsWith(@"\\?\Volume{", StringComparison.Ordinal) &&
            device.VolumeGuid.EndsWith("}\\", StringComparison.Ordinal) && device.ExtentStart >= 0 && device.ExtentLength > 0 &&
            device.BusType is 3 or 7 or 10 or 11 or 17 && CurrentAuthRepairPermit.HashShape(device.SerialSha256);
        }
        // Require distinct actual physical-device failure domains. This does not
        // claim separate hosts/power/controllers. Virtual disks,
        // Storage Spaces, network shares and same-device partitions are unsupported.
        if (!Valid(first) || !Valid(second) || first.DiskNumber == second.DiskNumber || first.SerialSha256 == second.SerialSha256 ||
            first.VolumeGuid == second.VolumeGuid)
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
    }
    private static void RequireDirectChild(string path, string root)
    {
        if (!Path.IsPathFullyQualified(path) || !string.Equals(Path.GetDirectoryName(Path.GetFullPath(path)), root, StringComparison.OrdinalIgnoreCase))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
    }
    private static CurrentAuthArchivePhysicalDevice Read(string root, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        char[] mount = new char[1024], volume = new char[1024];
        if (!GetVolumePathName(root, mount, 1024))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        int mountEnd = Array.IndexOf(mount, '\0');
        if (mountEnd <= 0 || !GetVolumeNameForVolumeMountPoint(new string(mount, 0, mountEnd), volume, 1024))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        int volumeEnd = Array.IndexOf(volume, '\0');
        if (volumeEnd <= 0) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        string volumeName = new(volume, 0, volumeEnd);
        using SafeFileHandle volumeHandle = CreateFile(volumeName.TrimEnd('\\'), 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        byte[] extent = new byte[4096];
        if (volumeHandle.IsInvalid || !DeviceIoControl(volumeHandle, 0x00560000, null, 0, extent, extent.Length, out int returned, IntPtr.Zero) ||
            returned != 32 || BinaryPrimitives.ReadUInt32LittleEndian(extent.AsSpan(0, 4)) != 1) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        uint disk = BinaryPrimitives.ReadUInt32LittleEndian(extent.AsSpan(8, 4));
        long begin = BinaryPrimitives.ReadInt64LittleEndian(extent.AsSpan(16, 8)), length = BinaryPrimitives.ReadInt64LittleEndian(extent.AsSpan(24, 8));
        ct.ThrowIfCancellationRequested();
        using SafeFileHandle device = CreateFile(@"\\.\PhysicalDrive" + disk.ToString(System.Globalization.CultureInfo.InvariantCulture), 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        byte[] query = new byte[12], descriptor = new byte[65536];
        if (device.IsInvalid || !DeviceIoControl(device, 0x002D1400, query, query.Length, descriptor, descriptor.Length, out int bytes, IntPtr.Zero) || bytes < 36)
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        uint declared = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(4, 4));
        uint serialOffset = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(24, 4));
        uint bus = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(28, 4));
        if (declared < 36 || declared > bytes || serialOffset < 36 || serialOffset >= declared) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        int end = (int)serialOffset;
        while (end < declared && end - serialOffset < 256 && descriptor[end] != 0) { end++; }
        if (end == serialOffset || end == declared || end - serialOffset == 256) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        string serial = Convert.ToHexStringLower(SHA256.HashData(descriptor.AsSpan((int)serialOffset, end - (int)serialOffset)));
        ct.ThrowIfCancellationRequested(); return new(volumeName, disk, begin, length, bus, serial);
    }
#pragma warning disable SYSLIB1054 // Fixed Windows handle ABI matches the accepted custody implementation without enabling unsafe marshalling.
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "GetVolumePathNameW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumePathName(string path, [Out] char[] result, uint size);
    [DllImport("kernel32.dll", EntryPoint = "GetVolumeNameForVolumeMountPointW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPoint(string mount, [Out] char[] result, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle device, uint code, byte[]? input, int inputSize, byte[] output, int outputSize, out int bytesReturned, IntPtr overlapped);
#pragma warning restore SYSLIB1054
}
