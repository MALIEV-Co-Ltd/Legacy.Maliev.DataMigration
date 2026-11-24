using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace Legacy.Maliev.DataMigration.Console;

// Recovery-file fault mechanics ONLY. No endpoints, SQL, arbitrary path, mutation
// offset or byte callback is accepted. The fixed owned-pair factory retains this.
internal sealed class CurrentAuthArchiveGenuineRecoveryHelpersStorage : ICurrentAuthLocalSessionArchiveStorage, IDisposable
{
    private sealed record Held(FileStream Stream, WindowsRunFileIdentity.Identity Identity, string Sha256);
    private readonly CurrentAppOwnedRepairCustody _first, _second;
    private readonly string _firstRoot, _secondRoot;
    private readonly CurrentAuthArchiveScope _scope;
    private readonly CurrentAuthArchiveDeviceProof _devices;
    private readonly CurrentAuthArchiveGenuineRecoveryHelperCase _case;
    private readonly Dictionary<string, Held> _held = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Held> _blocked = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _fresh, _faulted, _disposed;

    internal CurrentAuthArchiveGenuineRecoveryHelpersStorage(WindowsLocalRunAuthority first, WindowsLocalRunAuthority second,
        CurrentAuthArchiveScope scope, CurrentAuthArchiveDeviceProof devices, CurrentAuthArchiveGenuineRecoveryHelperCase helperCase)
    {
        if (helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback ||
            CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(helperCase) != scope.ComponentSubject?.Seed.CaseId ||
            first.Binding.ComputeSha256() != scope.LocalObservationPolicy.RunBindingSha256 ||
            second.Binding.ComputeSha256() != scope.ProductionObservationPolicy.RunBindingSha256 ||
            CurrentAuthLocalSessionArchivePolicy.Hash(devices) != scope.RecoveryDeviceProofSha256) { throw Invalid(); }
        _first = new(first); _second = new(second); _firstRoot = first.Binding.ArtifactRootCanonicalPath;
        _secondRoot = second.Binding.ArtifactRootCanonicalPath; _scope = scope; _devices = devices; _case = helperCase;
    }

    public async Task RequireFreshIndependentRecoveryPathsAsync(CurrentAuthArchivePaths paths, CancellationToken ct)
    {
        await RequireCustodyAsync(ct);
        if (_fresh || paths != _scope.Paths || Paths().Any(path => File.Exists(path) || Directory.Exists(path))) { throw Invalid(); }
        _fresh = true;
    }

    public async Task WriteCreateNewDurableAsync(string path, byte[] bytes, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await RequireCustodyAsync(ct); var custody = ForPath(path);
            if (!_fresh || _faulted || _held.ContainsKey(path) || bytes.Length is < 1 or > 12 * 1024 * 1024 ||
                ((path == _scope.Paths.RecoveryPrivateKey || path == _scope.Paths.SecondRecoveryPrivateKey) && bytes.Length > 65536)) { throw Invalid(); }
            await custody.WriteNewAsync(path, bytes, ct);
            var held = OpenHeld(path);
            if (held.Sha256 != CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes)) { held.Stream.Dispose(); throw Invalid(); }
            _held.Add(path, held);
        }
        finally { _ = _gate.Release(); }
    }

    public Task<byte[]> ReadHeldAsync(string path, int maximumBytes, CancellationToken ct)
    {
        return ReadDomainHeldAsync(path == _scope.Paths.FirstCiphertext || path == _scope.Paths.RecoveryPrivateKey, path, maximumBytes, ct);
    }

    public async Task<byte[]> ReadDomainHeldAsync(bool firstDomain, string path, int maximumBytes, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this); ct.ThrowIfCancellationRequested();
            if (DateTimeOffset.UtcNow >= _scope.ExpiresAtUtc) { throw Invalid(); }
            if ((firstDomain ? path != _scope.Paths.FirstCiphertext && path != _scope.Paths.RecoveryPrivateKey :
                path != _scope.Paths.SecondCiphertext && path != _scope.Paths.SecondRecoveryPrivateKey) || maximumBytes is < 1 or > 12 * 1024 * 1024) { throw Invalid(); }
            ForPath(path).Require();
            if (_blocked.ContainsKey(path))
            {
                // Perform the real failing Windows open, not a managed availability flag.
                using var impossible = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                throw Invalid();
            }
            if (!_held.TryGetValue(path, out var held) || held.Stream.Length > maximumBytes) { throw Invalid(); }
            Verify(path, held); held.Stream.Position = 0;
            byte[] bytes = new byte[checked((int)held.Stream.Length)];
            try
            {
                await held.Stream.ReadExactlyAsync(bytes, ct); Verify(path, held);
                return DateTimeOffset.UtcNow >= _scope.ExpiresAtUtc ? throw Invalid() : bytes;
            }
            catch { CryptographicOperations.ZeroMemory(bytes); throw; }
        }
        finally { _ = _gate.Release(); }
    }

    public async Task RequireCustodyAsync(CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this); ct.ThrowIfCancellationRequested();
        if (DateTimeOffset.UtcNow >= _scope.ExpiresAtUtc) { throw Invalid(); }
        _first.Require(); _second.Require();
        var actual = await CurrentAuthLocalSessionArchiveDeviceProcess.ObserveAsync(_scope, _firstRoot, _secondRoot, _first, _second, ct);
        CurrentAuthLocalSessionArchiveRecoveryDevices.RequireProof(_devices, _scope, actual, DateTimeOffset.UtcNow);
        foreach (var entry in _held) { Verify(entry.Key, entry.Value); }
        foreach (var entry in _blocked) { Verify(entry.Key, entry.Value); RequireBlocked(entry.Key); }
        if (DateTimeOffset.UtcNow >= _scope.ExpiresAtUtc) { throw Invalid(); }
        ct.ThrowIfCancellationRequested();
    }

    internal async Task<CurrentAuthArchiveGenuineRecoveryFaultWitness> InjectFixedFaultAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) { throw Invalid(); }
        await _gate.WaitAsync(ct);
        try
        {
            await RequireCustodyAsync(ct);
            if (_faulted || _held.Count != 4 || !_fresh) { throw Invalid(); }
            _faulted = true; DateTimeOffset began = DateTimeOffset.UtcNow;
            var evidence = new List<CurrentAuthArchiveGenuineRecoveryFileFault>();
            if (_case is CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery or CurrentAuthArchiveGenuineRecoveryHelperCase.SecondOnlyRecovery)
            {
                string[] paths = _case == CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery
                    ? [_scope.Paths.SecondCiphertext, _scope.Paths.SecondRecoveryPrivateKey]
                    : [_scope.Paths.FirstCiphertext, _scope.Paths.RecoveryPrivateKey];
                foreach (string path in paths)
                {
                    Held original = _held[path]; original.Stream.Dispose(); _ = _held.Remove(path);
                    var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None);
                    var blocker = new Held(stream, original.Identity, original.Sha256);
                    _blocked.Add(path, blocker); Verify(path, blocker); RequireBlocked(path);
                    evidence.Add(new(path, original.Identity.Volume + "/" + original.Identity.ObjectId, original.Sha256, original.Sha256, 32));
                }
            }
            else
            {
                string path = _case == CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption ? _scope.Paths.RecoveryPrivateKey : _scope.Paths.FirstCiphertext;
                Held original = _held[path]; original.Stream.Dispose(); _ = _held.Remove(path);
                using (var write = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    Verify(path, new(write, original.Identity, original.Sha256));
                    write.Position = 0; int first = write.ReadByte(); if (first < 0) { throw Invalid(); }
                    write.Position = 0; write.WriteByte((byte)(first ^ 1)); write.Flush(flushToDisk: true);
                }
                Held changed = OpenHeld(path);
                _held.Add(path, changed);
                if (changed.Identity != original.Identity || changed.Sha256 == original.Sha256) { throw Invalid(); }
                evidence.Add(new(path, changed.Identity.Volume + "/" + changed.Identity.ObjectId, original.Sha256, changed.Sha256, null));
            }
            return new(CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(_case), began, DateTimeOffset.UtcNow, evidence.AsReadOnly());
        }
        finally { _ = _gate.Release(); }
    }

    internal void RestoreReadAvailability()
    {
        if (!OperatingSystem.IsWindows()) { throw Invalid(); }
        foreach (var entry in _blocked.ToArray())
        {
            entry.Value.Stream.Dispose(); _ = _blocked.Remove(entry.Key);
            Held reopened = OpenHeld(entry.Key);
            if (reopened.Identity != entry.Value.Identity || reopened.Sha256 != entry.Value.Sha256) { reopened.Stream.Dispose(); throw Invalid(); }
            _held.Add(entry.Key, reopened);
        }
    }

    private static Held OpenHeld(string path)
    {
        if (!OperatingSystem.IsWindows()) { throw Invalid(); }
        FileStream stream = SecureLocalFile.OpenReadShared(path);
        try { return new(stream, WindowsRunFileIdentity.Observe(stream.SafeFileHandle), Convert.ToHexStringLower(SHA256.HashData(stream))); }
        catch { stream.Dispose(); throw; }
    }

    private static void Verify(string path, Held held)
    {
        if (!OperatingSystem.IsWindows() || !SecureLocalFile.HandleResolvesToApprovedPath(held.Stream, path) ||
            WindowsRunFileIdentity.Observe(held.Stream.SafeFileHandle) != held.Identity) { throw Invalid(); }
        // Query the already-open handle: a filename ACL query may itself require
        // a second open, which the genuine exclusive fault intentionally denies.
        FileSecurity acl = held.Stream.GetAccessControl();
        SecurityIdentifier owner = WindowsIdentity.GetCurrent().User ?? throw Invalid();
        if (!owner.Equals(acl.GetOwner(typeof(SecurityIdentifier)))) { throw Invalid(); }
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Deny && !owner.Equals(rule.IdentityReference)) { throw Invalid(); }
        }
        held.Stream.Position = 0;
        if (Convert.ToHexStringLower(SHA256.HashData(held.Stream)) != held.Sha256) { throw Invalid(); }
    }

    private static void RequireBlocked(string path)
    {
        try { using var opened = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); }
        catch (IOException failure) when ((failure.HResult & 0xffff) == 32) { return; }
        throw Invalid();
    }

    private string[] Paths()
    {
        return [_scope.Paths.FirstCiphertext, _scope.Paths.SecondCiphertext, _scope.Paths.RecoveryPrivateKey, _scope.Paths.SecondRecoveryPrivateKey];
    }

    private CurrentAppOwnedRepairCustody ForPath(string path)
    {
        return path == _scope.Paths.FirstCiphertext || path == _scope.Paths.RecoveryPrivateKey ? _first :
            path == _scope.Paths.SecondCiphertext || path == _scope.Paths.SecondRecoveryPrivateKey ? _second : throw Invalid();
    }

    public void Dispose()
    {
        if (_disposed) { return; }
        _disposed = true;
        Exception? failure = null;
        foreach (var entry in _held.Values.Concat(_blocked.Values))
        { try { entry.Stream.Dispose(); } catch (Exception cleanup) { failure ??= cleanup; } }
        try { _first.Dispose(); } catch (Exception cleanup) { failure ??= cleanup; }
        try { _second.Dispose(); } catch (Exception cleanup) { failure ??= cleanup; }
        try { _gate.Dispose(); } catch (Exception cleanup) { failure ??= cleanup; }
        if (failure is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw(); }
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveGenuineHost.Invalid("recovery_fault_storage");
    }
}
