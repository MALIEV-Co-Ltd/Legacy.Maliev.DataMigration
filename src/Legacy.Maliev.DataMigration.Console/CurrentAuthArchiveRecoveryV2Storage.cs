using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveRecoveryOriginalFile(string Path, string Identity, string Sha256, long Length);
internal sealed record CurrentAuthArchiveRecoveryUnavailableFile(string Path, string Identity, string Sha256, int NativeError, DateTimeOffset ObservedAtUtc);

// Reads the original engine output only. No write/reset/replacement or alternate path is implemented.
internal sealed class CurrentAuthArchiveRecoveryV2Storage : ICurrentAuthLocalSessionArchiveStorage, IDisposable
{
    private sealed record Held(FileStream Stream, CurrentAuthArchiveRecoveryOriginalFile Original, bool Selected);
    private readonly Dictionary<string, Held> _held = new(StringComparer.OrdinalIgnoreCase);
    private readonly CurrentAppOwnedRepairCustody _first, _second;
    private readonly string _firstRoot, _secondRoot;
    private readonly CurrentAuthArchiveScope _original;
    private readonly CurrentAuthArchiveDeviceProof _devices;
    private readonly bool _firstDomain;
    private bool _disposed;
    internal IReadOnlyList<CurrentAuthArchiveRecoveryUnavailableFile> Unavailable { get; }

    internal CurrentAuthArchiveRecoveryV2Storage(WindowsLocalRunAuthority first, WindowsLocalRunAuthority second,
        CurrentAuthArchiveScope original, CurrentAuthArchiveDeviceProof devices, CurrentAuthArchiveRecoveryV2Case selected,
        IReadOnlyList<CurrentAuthArchiveRecoveryOriginalFile> originals)
    {
        if (!OperatingSystem.IsWindows() || original.ProofAdmission != CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap ||
            original.ComponentSubject?.Seed.CaseId != CurrentAuthArchiveRecoveryV2.CaseId(selected) || first.Binding.ComputeSha256() != original.LocalObservationPolicy.RunBindingSha256 ||
            second.Binding.ComputeSha256() != original.ProductionObservationPolicy.RunBindingSha256 || CurrentAuthLocalSessionArchivePolicy.Hash(devices) != original.RecoveryDeviceProofSha256)
        { throw Invalid(); }
        _first = new(first); _second = new(second); _firstRoot = first.Binding.ArtifactRootCanonicalPath; _secondRoot = second.Binding.ArtifactRootCanonicalPath;
        _original = original; _devices = devices; _firstDomain = selected == CurrentAuthArchiveRecoveryV2Case.FirstOnly;
        string[] paths = [original.Paths.FirstCiphertext, original.Paths.RecoveryPrivateKey, original.Paths.SecondCiphertext, original.Paths.SecondRecoveryPrivateKey];
        if (originals.Count != 4 || !paths.Order(StringComparer.Ordinal).SequenceEqual(originals.Select(item => item.Path).Order(StringComparer.Ordinal))) { Dispose(); throw Invalid(); }
        var unavailable = new List<CurrentAuthArchiveRecoveryUnavailableFile>();
        try
        {
            foreach (var item in originals)
            {
                bool firstFile = item.Path == original.Paths.FirstCiphertext || item.Path == original.Paths.RecoveryPrivateKey;
                if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(item.Path), firstFile ? _firstRoot : _secondRoot)) { throw Invalid(); }
                bool use = firstFile == _firstDomain;
                var stream = new FileStream(item.Path, FileMode.Open, FileAccess.Read, use ? FileShare.Read : FileShare.None);
                _held.Add(item.Path, new(stream, item, use)); Verify(_held[item.Path]);
                if (!use) { unavailable.Add(ObserveBlocked(item)); }
            }
            Unavailable = unavailable.AsReadOnly();
        }
        catch { Dispose(); throw; }
    }
    public Task RequireFreshIndependentRecoveryPathsAsync(CurrentAuthArchivePaths paths, CancellationToken ct)
    {
        throw Invalid();
    }

    public Task WriteCreateNewDurableAsync(string path, byte[] bytes, CancellationToken ct)
    {
        throw Invalid();
    }

    public Task<byte[]> ReadHeldAsync(string path, int maximumBytes, CancellationToken ct)
    {
        throw Invalid();
    }

    public async Task<byte[]> ReadDomainHeldAsync(bool firstDomain, string path, int maximumBytes, CancellationToken ct)
    {
        await RequireCustodyAsync(ct);
        if (firstDomain != _firstDomain || !_held.TryGetValue(path, out var held) || !held.Selected || maximumBytes is < 1 or > 12 * 1024 * 1024 || held.Stream.Length > maximumBytes) { throw Invalid(); }
        held.Stream.Position = 0; byte[] bytes = new byte[checked((int)held.Stream.Length)];
        try { await held.Stream.ReadExactlyAsync(bytes, ct); Verify(held); return bytes; }
        catch { CryptographicOperations.ZeroMemory(bytes); throw; }
    }
    public async Task RequireCustodyAsync(CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this); ct.ThrowIfCancellationRequested();
        if (DateTimeOffset.UtcNow >= _original.ExpiresAtUtc) { throw Invalid(); }
        _first.Require(); _second.Require();
        foreach (var held in _held.Values) { Verify(held); if (!held.Selected) { _ = ObserveBlocked(held.Original); } }
        var actual = await CurrentAuthLocalSessionArchiveDeviceProcess.ObserveAsync(_original, _firstRoot, _secondRoot, _first, _second, ct);
        CurrentAuthLocalSessionArchiveRecoveryDevices.RequireProof(_devices, _original, actual, DateTimeOffset.UtcNow);
    }
    private static CurrentAuthArchiveRecoveryUnavailableFile ObserveBlocked(CurrentAuthArchiveRecoveryOriginalFile original)
    {
        try { using var impossible = new FileStream(original.Path, FileMode.Open, FileAccess.Read, FileShare.Read); }
        catch (IOException failure) when ((failure.HResult & 0xffff) == 32)
        { return new(original.Path, original.Identity, original.Sha256, 32, DateTimeOffset.UtcNow); }
        throw Invalid();
    }
    private static void Verify(Held held)
    {
        if (!OperatingSystem.IsWindows()) { throw Invalid(); }
        var expected = held.Original;
        if (!SecureLocalFile.HandleResolvesToApprovedPath(held.Stream, expected.Path) ||
            SecureLocalFile.GetHandleIdentity(held.Stream) != expected.Identity || held.Stream.Length != expected.Length) { throw Invalid(); }
        FileSecurity acl = held.Stream.GetAccessControl(); SecurityIdentifier owner = WindowsIdentity.GetCurrent().User ?? throw Invalid();
        if (!owner.Equals(acl.GetOwner(typeof(SecurityIdentifier)))) { throw Invalid(); }
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Deny && !owner.Equals(rule.IdentityReference)) { throw Invalid(); }
        }
        held.Stream.Position = 0;
        if (Convert.ToHexStringLower(SHA256.HashData(held.Stream)) != expected.Sha256) { throw Invalid(); }
    }
    internal IReadOnlyList<CurrentAuthArchiveRecoveryUnavailableFile> ObserveUnavailable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        foreach (var item in _held.Values) { Verify(item); }
        return _held.Values.Where(item => !item.Selected).Select(item => ObserveBlocked(item.Original)).ToArray();
    }
    public void Dispose()
    {
        if (_disposed) { return; }
        _disposed = true;
        foreach (var item in _held.Values) { item.Stream.Dispose(); }
        _held.Clear(); _first.Dispose(); _second.Dispose();
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveRecoveryV2.Invalid();
    }
}
