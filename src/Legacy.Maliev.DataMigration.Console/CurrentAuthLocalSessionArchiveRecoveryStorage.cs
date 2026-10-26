using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Genuine resumed Windows custody with immutable held readback and native device proof.</summary>
internal sealed class CurrentAuthLocalSessionArchiveRecoveryStorage : ICurrentAuthLocalSessionArchiveStorage, IDisposable
{
    private readonly CurrentAppOwnedRepairCustody _first, _second;
    private readonly string _firstRoot, _secondRoot;
    private readonly CurrentAuthArchiveScope _scope;
    private readonly CurrentAuthArchiveDeviceProof _devices;
    private readonly Dictionary<string, (FileStream Stream, string Identity)> _held = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _fresh, _disposed;
    internal CurrentAuthLocalSessionArchiveRecoveryStorage(CurrentAppOwnedRepairCustody first, CurrentAppOwnedRepairCustody second,
        WindowsLocalRunAuthority firstAuthority, WindowsLocalRunAuthority secondAuthority, CurrentAuthArchiveScope scope,
        CurrentAuthArchiveDeviceProof devices)
    {
        _first = first; _second = second; _scope = scope; _devices = devices;
        _firstRoot = firstAuthority.Binding.ArtifactRootCanonicalPath; _secondRoot = secondAuthority.Binding.ArtifactRootCanonicalPath;
        if (firstAuthority.Binding.ComputeSha256() != scope.LocalObservationPolicy.RunBindingSha256 ||
            secondAuthority.Binding.ComputeSha256() != scope.ProductionObservationPolicy.RunBindingSha256) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
    }
    public async Task RequireFreshIndependentRecoveryPathsAsync(CurrentAuthArchivePaths paths, CancellationToken ct)
    {
        await RequireAsync(ct).ConfigureAwait(false);
        if (_fresh || paths != _scope.Paths || _held.Count != 0 || new[] { paths.FirstCiphertext, paths.SecondCiphertext, paths.RecoveryPrivateKey, paths.SecondRecoveryPrivateKey }.Any(path => File.Exists(path) || Directory.Exists(path)))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        _fresh = true;
    }
    public async Task WriteCreateNewDurableAsync(string path, byte[] bytes, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await RequireAsync(ct).ConfigureAwait(false); if (!_fresh || _held.ContainsKey(path) || bytes.Length > 12 * 1024 * 1024 ||
                ((path == _scope.Paths.RecoveryPrivateKey || path == _scope.Paths.SecondRecoveryPrivateKey) && bytes.Length > 65536)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            CurrentAppOwnedRepairCustody custody = ForPath(path);
            await custody.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
            // Opening under shared READ custody denies writes/deletion, while allowing
            // the separately retained read handle to perform each genuine readback.
            byte[] observed = custody.Read(path, sharedReader: true, maximumBytes: bytes.Length);
            try { if (!observed.AsSpan().SequenceEqual(bytes)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); } }
            finally { CryptographicOperations.ZeroMemory(observed); }
            FileStream stream = SecureLocalFile.OpenReadShared(path);
            try
            {
                if (!SecureLocalFile.HandleResolvesToApprovedPath(stream, path) || stream.Length != bytes.Length) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                _held.Add(path, (stream, SecureLocalFile.GetHandleIdentity(stream))); stream = null!;
            }
            finally { stream?.Dispose(); }
            await RequireAsync(ct).ConfigureAwait(false);
        }
        finally { _ = _gate.Release(); }
    }
    public async Task<byte[]> ReadHeldAsync(string path, int maximumBytes, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await RequireAsync(ct).ConfigureAwait(false); _ = ForPath(path);
            if (!_held.TryGetValue(path, out var held) || maximumBytes is < 1 or > 12 * 1024 * 1024 || held.Stream.Length > maximumBytes)
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            held.Stream.Position = 0; byte[] bytes = new byte[checked((int)held.Stream.Length)];
            try
            {
                await held.Stream.ReadExactlyAsync(bytes, ct).ConfigureAwait(false);
                if (held.Stream.Position != held.Stream.Length) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                await RequireAsync(ct).ConfigureAwait(false); return bytes;
            }
            catch { CryptographicOperations.ZeroMemory(bytes); throw; }
        }
        finally { _ = _gate.Release(); }
    }
    public async Task<byte[]> ReadDomainHeldAsync(bool firstDomain, string path, int maximumBytes, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            CurrentAuthArchiveCapacity.Require(admission: false); ObjectDisposedException.ThrowIf(_disposed, this); ct.ThrowIfCancellationRequested();
            CurrentAppOwnedRepairCustody selected = firstDomain ? _first : _second;
            if ((firstDomain ? path != _scope.Paths.FirstCiphertext && path != _scope.Paths.RecoveryPrivateKey :
                path != _scope.Paths.SecondCiphertext && path != _scope.Paths.SecondRecoveryPrivateKey) ||
                !_held.TryGetValue(path, out var held) || maximumBytes is < 1 or > 12 * 1024 * 1024 || held.Stream.Length > maximumBytes)
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            selected.Require();
            if (!SecureLocalFile.HandleResolvesToApprovedPath(held.Stream, path) || SecureLocalFile.GetHandleIdentity(held.Stream) != held.Identity)
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            held.Stream.Position = 0; byte[] bytes = new byte[checked((int)held.Stream.Length)];
            try
            {
                await held.Stream.ReadExactlyAsync(bytes, ct).ConfigureAwait(false); selected.Require();
                if (held.Stream.Position != held.Stream.Length || !SecureLocalFile.HandleResolvesToApprovedPath(held.Stream, path) ||
                    SecureLocalFile.GetHandleIdentity(held.Stream) != held.Identity) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                CurrentAuthArchiveCapacity.Require(admission: false); return bytes;
            }
            catch { CryptographicOperations.ZeroMemory(bytes); throw; }
        }
        finally { _ = _gate.Release(); }
    }
    public Task RequireCustodyAsync(CancellationToken ct)
    {
        return RequireAsync(ct);
    }

    private async Task RequireAsync(CancellationToken ct)
    {
        CurrentAuthArchiveCapacity.Require(admission: false);
        ObjectDisposedException.ThrowIf(_disposed, this); ct.ThrowIfCancellationRequested(); _first.Require(); _second.Require();
        CurrentAuthArchiveDeviceProof actual = await CurrentAuthLocalSessionArchiveDeviceProcess.ObserveAsync(_scope, _firstRoot, _secondRoot, _first, _second, ct).ConfigureAwait(false);
        CurrentAuthLocalSessionArchiveRecoveryDevices.RequireProof(_devices, _scope, actual, DateTimeOffset.UtcNow);
        foreach (var (path, held) in _held)
        {
            if (!SecureLocalFile.HandleResolvesToApprovedPath(held.Stream, path) || SecureLocalFile.GetHandleIdentity(held.Stream) != held.Identity)
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
    }
    private CurrentAppOwnedRepairCustody ForPath(string path)
    {
        return path == _scope.Paths.FirstCiphertext || path == _scope.Paths.RecoveryPrivateKey
            ? _first
            : path == _scope.Paths.SecondCiphertext || path == _scope.Paths.SecondRecoveryPrivateKey ? _second : throw CurrentAuthLocalSessionArchivePolicy.Invalid();
    }
    public void Dispose()
    {
        if (_disposed) { return; }
        _disposed = true;
        foreach (var held in _held.Values) { held.Stream.Dispose(); }
        _held.Clear(); _gate.Dispose();
        // Retain both encrypted archives and the owner-only recovery key; they are
        // recovery evidence, never disposable resource cleanup.
    }
}
