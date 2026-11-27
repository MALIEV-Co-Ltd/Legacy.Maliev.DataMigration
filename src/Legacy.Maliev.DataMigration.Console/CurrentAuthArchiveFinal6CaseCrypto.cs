using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CurrentAuthArchiveFinal6CaseReadback
{
    private void VerifyCryptoCopies(CurrentAuthArchiveRecoveryManifest manifest, IReadOnlyList<CurrentAuthArchiveSession> rows, string caseId, CancellationToken ct)
    {
        var map = new Dictionary<string, CurrentAuthArchiveGenuineArtifact>(StringComparer.Ordinal)
        {
            [Scope.Paths.FirstCiphertext] = _artifacts["first-ciphertext"],
            [Scope.Paths.SecondCiphertext] = _artifacts["second-ciphertext"],
            [Scope.Paths.RecoveryPrivateKey] = _artifacts["first-recovery-key"],
            [Scope.Paths.SecondRecoveryPrivateKey] = _artifacts["second-recovery-key"],
        };
        VerifyCryptoMap(manifest, rows, caseId, map, ct);
    }
    private void VerifyCryptoMap(CurrentAuthArchiveRecoveryManifest manifest, IReadOnlyList<CurrentAuthArchiveSession> rows, string caseId,
        IReadOnlyDictionary<string, CurrentAuthArchiveGenuineArtifact> map, CancellationToken ct)
    {
        if (manifest.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(Scope) || manifest.FirstCiphertextSha256 == manifest.SecondCiphertextSha256) { throw Invalid(); }
        var storage = new HistoricalCryptoStorage(_roots.For(map.First().Value.Path), Scope.Paths, map);
        byte[] expected = CurrentAuthLocalSessionArchivePolicy.EncodeRows(rows);
        try
        {
            if (rows.Count != Scope.DeleteCount || CurrentAuthLocalSessionArchivePolicy.HashBytes(expected) != Scope.DeleteSetSha256) { throw Invalid(); }
            if (caseId is "key-corruption" or "cipher-corruption")
            {
                bool actualRejection = false;
                try
                {
                    byte[] unexpected = CurrentAuthLocalSessionArchiveCrypto.RecoverDomainAsync(storage, Scope, manifest, true, ct).GetAwaiter().GetResult();
                    CryptographicOperations.ZeroMemory(unexpected);
                }
                catch (Exception failure) when (failure is CryptographicException or MigrationExecutionException or JsonException or FormatException) { actualRejection = true; }
                if (!actualRejection) { throw Invalid(); }
                // The unaffected original second domain must still verify independently.
                RequireDomain(false);
            }
            else if (caseId.StartsWith("first-only", StringComparison.Ordinal)) { RequireDomain(true); }
            else if (caseId.StartsWith("second-only", StringComparison.Ordinal)) { RequireDomain(false); }
            else { RequireDomain(true); RequireDomain(false); }
            void RequireDomain(bool first)
            {
                byte[] plaintext = CurrentAuthLocalSessionArchiveCrypto.RecoverDomainAsync(storage, Scope, manifest, first, ct).GetAwaiter().GetResult();
                try { if (!plaintext.AsSpan().SequenceEqual(expected)) { throw Invalid(); } }
                finally { CryptographicOperations.ZeroMemory(plaintext); }
            }
        }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }
    // Read-only historical evidence. This does not assert current domain unavailability or revive an expired execution scope.
    private sealed class HistoricalCryptoStorage(CurrentAppOwnedRepairCustody files, CurrentAuthArchivePaths paths,
        IReadOnlyDictionary<string, CurrentAuthArchiveGenuineArtifact> artifacts) : ICurrentAuthLocalSessionArchiveStorage
    {
        public Task RequireFreshIndependentRecoveryPathsAsync(CurrentAuthArchivePaths value, CancellationToken ct)
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

        public Task RequireCustodyAsync(CancellationToken ct) { ct.ThrowIfCancellationRequested(); files.Require(); return Task.CompletedTask; }
        public Task<byte[]> ReadDomainHeldAsync(bool firstDomain, string path, int maximumBytes, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); files.Require();
            if (firstDomain ? path != paths.FirstCiphertext && path != paths.RecoveryPrivateKey : path != paths.SecondCiphertext && path != paths.SecondRecoveryPrivateKey)
            { throw Invalid(); }
            var artifact = artifacts[path]; byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: maximumBytes);
            if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != artifact.Sha256) { CryptographicOperations.ZeroMemory(bytes); throw Invalid(); }
            return Task.FromResult(bytes);
        }
    }
}
