using System.Runtime.Versioning;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CurrentAuthArchiveGenuineExecutionIssuer
{
    private SlotDenial? _ownedDenial;

    private async Task InstallPublicationDenialAsync(CurrentAuthArchiveGenuineExecutionCase expected, CancellationToken ct)
    {
        lock (_gate) { if (_disposed || _failed || _closed || _minted || _ownedDenial is not null) { throw Invalid(); } }
        var binding = await ObserveAsync(true, ct);
        if (binding.Case != expected || !CurrentAuthArchiveGenuinePublicationFault.IsCase(expected)) { throw Invalid(); }
        var denial = SlotDenial.FromOwnedIssuer(this, binding);
        await _lease.BindPublicationDenialAsync(denial, ct);
        lock (_gate) { if (_disposed || _failed || _closed || _minted) { throw Invalid(); } _ownedDenial = denial; }
        _ = await ObserveAsync(true, ct);
    }

    internal async Task<CurrentAuthArchiveGenuineDualArtifacts> RetainPublicationFailureAsync(Guid id,
        CurrentAuthArchiveGenuinePublicationFailureFacts facts, CancellationToken ct)
    {
        Check(id, false); _bundle.Require();
        if (_ownedDenial is null || facts.Case != _ownedDenial.Case) { throw Invalid(); }
        // Normal observation/execution remains permanently failed. This separate fixed receiver can only retain read-only failure proof.
        try
        {
            var result = await _lease.RetainPublicationFailureAsync(facts, ct);
            lock (_gate) { if (_disposed || _failed || _closed || id != _id) { throw Invalid(); } _closed = true; }
            _bundle.Require(); return result;
        }
        catch { lock (_gate) { _failed = true; } throw; }
    }

    // No public/JSON constructor. Only the exact qualified issuer, after its real owned lease exists, can create this hook.
    internal sealed class SlotDenial
    {
        private readonly ICurrentAuthArchiveGenuineExecutionLease _owner;
        private readonly CurrentAuthArchiveGenuineExecutionAttestation _binding;
        private CurrentAuthLocalSessionArchiveEnvironment? _environment;
        private CurrentAppOwnedRepairCustody? _files;
        private WindowsLocalRunAuthority? _local, _comparison;
        private CurrentAuthArchiveGenuineSlotWitness? _witness;
        private int _used;
        internal CurrentAuthArchiveGenuineExecutionCase Case => _binding.Case;
        private SlotDenial(ICurrentAuthArchiveGenuineExecutionLease owner, CurrentAuthArchiveGenuineExecutionAttestation binding)
        { _owner = owner; _binding = binding; }
        internal static SlotDenial FromOwnedIssuer(CurrentAuthArchiveGenuineExecutionIssuer issuer, CurrentAuthArchiveGenuineExecutionAttestation binding)
        {
            lock (issuer._gate)
            {
                return issuer._disposed || issuer._failed || issuer._closed || issuer._minted || issuer._ownedDenial is not null ||
                    !CurrentAuthArchiveGenuinePublicationFault.IsCase(binding.Case)
                    ? throw Invalid()
                    : new(issuer._lease, binding);
            }
        }

        internal void BindFinalEnvironment(ICurrentAuthArchiveGenuineExecutionLease owner, CurrentAuthLocalSessionArchiveEnvironment environment,
            CurrentAuthArchiveScope scope, string authorization, CurrentAppOwnedRepairCustody files,
            WindowsLocalRunAuthority local, WindowsLocalRunAuthority comparison)
        {
            if (!ReferenceEquals(owner, _owner) || _environment is not null || _used != 0 ||
                CurrentAuthLocalSessionArchivePolicy.Hash(scope) != CurrentAuthLocalSessionArchivePolicy.Hash(_binding.Owned.Scope) ||
                authorization != _binding.AuthorizationSha256 || local.Binding.ComputeSha256() != scope.LocalObservationPolicy.RunBindingSha256 ||
                comparison.Binding.ComputeSha256() != scope.ProductionObservationPolicy.RunBindingSha256 ||
                Path.GetDirectoryName(scope.Paths.FirstCiphertext) != local.Binding.ArtifactRootCanonicalPath ||
                Path.GetDirectoryName(scope.Paths.SecondCiphertext) != comparison.Binding.ArtifactRootCanonicalPath) { throw Invalid(); }
            local.ValidateHeld(); comparison.ValidateHeld(); files.Require();
            _environment = environment; _files = files; _local = local; _comparison = comparison;
        }

        internal CurrentAuthArchiveGenuineSlotWitness RequirePostFailure(CurrentAuthLocalSessionArchiveEnvironment environment,
            CurrentAuthArchiveScope scope, string authorization, WindowsLocalRunAuthority local, WindowsLocalRunAuthority comparison)
        {
            RequireBound(environment, scope, authorization);
            if (!ReferenceEquals(local, _local) || !ReferenceEquals(comparison, _comparison) || _witness is null) { throw Invalid(); }
            CurrentAuthArchiveGenuinePublicationFault.RequireWitness(_witness, scope, authorization, Case, scope.CapturedAtUtc, DateTimeOffset.UtcNow);
            return _witness;
        }

        private void RequireBound(CurrentAuthLocalSessionArchiveEnvironment environment, CurrentAuthArchiveScope scope, string authorization)
        {
            if (!ReferenceEquals(environment, _environment) || _files is null || _local is null || _comparison is null ||
                CurrentAuthLocalSessionArchivePolicy.Hash(scope) != CurrentAuthLocalSessionArchivePolicy.Hash(_binding.Owned.Scope) ||
                authorization != _binding.AuthorizationSha256 || DateTimeOffset.UtcNow >= scope.ExpiresAtUtc) { throw Invalid(); }
            _local.ValidateHeld(); _comparison.ValidateHeld(); _files.Require();
        }

        internal Collision? BeginSlot(string name, Guid operation, CurrentAppOwnedRepairCustody files,
            WindowsLocalRunAuthority local, WindowsLocalRunAuthority comparison)
        {
            string expected = $"{_binding.Owned.Scope.OperationId:D}-Auth-session-archive-{CurrentAuthArchiveGenuinePublicationFault.Slot(Case)}.json";
            if (name != expected) { return null; }
            if (!OperatingSystem.IsWindows() || operation != _binding.Owned.Scope.OperationId || !ReferenceEquals(files, _files) ||
                !ReferenceEquals(local, _local) || !ReferenceEquals(comparison, _comparison) || Interlocked.CompareExchange(ref _used, 1, 0) != 0) { throw Invalid(); }
            RequireBound(_environment ?? throw Invalid(), _binding.Owned.Scope, _binding.AuthorizationSha256);
            string path = Path.Combine(local.Binding.ArtifactRootCanonicalPath, name);
            return Collision.CreateForSlot(this, path);
        }

        [SupportedOSPlatform("windows")]
        internal sealed class Collision : IDisposable
        {
            private readonly SlotDenial _owner;
            private readonly FileStream _stream;
            private readonly string _path;
            private readonly WindowsRunFileIdentity.Identity _identity;
            private bool _disposed;
            private int _nativeError;
            private DateTimeOffset _failed;
            internal DateTimeOffset Created { get; } = DateTimeOffset.UtcNow;
            internal string Volume => _identity.Volume;
            internal string FileId => _identity.ObjectId;
            private Collision(SlotDenial owner, string path)
            {
                _owner = owner; _path = path;
                _stream = new(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.DeleteOnClose | FileOptions.WriteThrough);
                try { _identity = WindowsRunFileIdentity.Observe(_stream.SafeFileHandle); RequireHeld(); }
                catch { _stream.Dispose(); throw; }
            }
            internal static Collision CreateForSlot(SlotDenial owner, string path)
            {
                string expected = Path.Combine(owner._local?.Binding.ArtifactRootCanonicalPath ?? throw Invalid(),
                    $"{owner._binding.Owned.Scope.OperationId:D}-Auth-session-archive-{CurrentAuthArchiveGenuinePublicationFault.Slot(owner.Case)}.json");
                return owner._used != 1 || owner._witness is not null || path != expected ? throw Invalid() : new(owner, path);
            }
            internal void RecordOriginalCreateFailure(Exception failure)
            {
                int native = failure.HResult & 0xffff;
                if (_failed != default || failure is not (IOException or UnauthorizedAccessException) || native is not (5 or 32 or 80 or 183)) { throw Invalid(); }
                RequireHeld(); _nativeError = native; _failed = DateTimeOffset.UtcNow;
            }
            internal void RequireHeld()
            {
                WindowsRunFileIdentity.ValidateLock(_stream.SafeFileHandle, _path);
                if (_stream.Length != 0 || WindowsRunFileIdentity.Observe(_stream.SafeFileHandle) != _identity) { throw Invalid(); }
            }
            public void Dispose()
            {
                if (_disposed) { return; }
                _disposed = true;
                try { RequireHeld(); } finally { _stream.Dispose(); }
                if (_failed == default || File.Exists(_path) || Directory.Exists(_path)) { throw Invalid(); }
                var scope = _owner._binding.Owned.Scope;
                _owner._witness = new(scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(scope), _owner._binding.AuthorizationSha256,
                    scope.LocalObservationPolicy.RunBindingSha256, scope.ProductionObservationPolicy.RunBindingSha256,
                    CurrentAuthArchiveGenuinePublicationFault.Slot(_owner.Case), _path, Volume, FileId, 0, true, true,
                    _nativeError, Created, _failed, DateTimeOffset.UtcNow, true);
            }
        }
    }
}
