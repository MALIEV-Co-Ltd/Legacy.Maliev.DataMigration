using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAuthArchiveCiphertext(int Version, string BindingSha256, string RecoveryPublicKeySha256,
    string WrappedKeyBase64, string NonceBase64, string CiphertextBase64, string TagBase64);
internal sealed record CurrentAuthArchiveRecoveryManifest(string ScopeSha256, string AuthorizationSha256,
    string RecoveryPublicKeySha256, string FirstCiphertextSha256, string SecondCiphertextSha256);

/// <summary>Bounded encryption/readback component; does not grant deletion or restore authority.</summary>
internal static class CurrentAuthLocalSessionArchiveCrypto
{
    private const int MaximumEnvelopeBytes = 12 * 1024 * 1024;
    internal static async Task<CurrentAuthArchiveRecoveryManifest> WriteAndVerifyAsync(ICurrentAuthLocalSessionArchiveStorage storage,
        CurrentAuthArchiveScope scope, string authorizationSha256, IReadOnlyList<CurrentAuthArchiveSession> rows, CancellationToken ct)
    {
        byte[] plaintext = CurrentAuthLocalSessionArchivePolicy.EncodeRows(rows);
        try
        {
            if (rows.Count != scope.DeleteCount || CurrentAuthLocalSessionArchivePolicy.HashBytes(plaintext) != scope.DeleteSetSha256 ||
                !CurrentAuthRepairPermit.HashShape(authorizationSha256)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            await storage.RequireFreshIndependentRecoveryPathsAsync(scope.Paths, ct).ConfigureAwait(false);
            using RSA recovery = RSA.Create(3072);
            string publicHash = CurrentAuthLocalSessionArchivePolicy.HashBytes(recovery.ExportSubjectPublicKeyInfo());
            byte[] pem = recovery.ExportPkcs8PrivateKey();
            try
            {
                // Owner-only durable recovery key is retained BEFORE either ciphertext
                // can authorize deletion. Actual held-readback import proves recovery.
                await storage.WriteCreateNewDurableAsync(scope.Paths.RecoveryPrivateKey, pem, ct).ConfigureAwait(false);
                await storage.WriteCreateNewDurableAsync(scope.Paths.SecondRecoveryPrivateKey, pem, ct).ConfigureAwait(false);
                byte[] retained = await storage.ReadHeldAsync(scope.Paths.RecoveryPrivateKey, 65536, ct).ConfigureAwait(false);
                try { if (!retained.AsSpan().SequenceEqual(pem)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); } }
                finally { CryptographicOperations.ZeroMemory(retained); }
            }
            finally { CryptographicOperations.ZeroMemory(pem); }
            byte[] aad = Binding(scope, authorizationSha256, publicHash);
            byte[] first = Encrypt(plaintext, aad, publicHash, recovery), second = Encrypt(plaintext, aad, publicHash, recovery);
            await storage.WriteCreateNewDurableAsync(scope.Paths.FirstCiphertext, first, ct).ConfigureAwait(false);
            await storage.WriteCreateNewDurableAsync(scope.Paths.SecondCiphertext, second, ct).ConfigureAwait(false);
            var manifest = new CurrentAuthArchiveRecoveryManifest(CurrentAuthLocalSessionArchivePolicy.Hash(scope), authorizationSha256,
                publicHash, CurrentAuthLocalSessionArchivePolicy.HashBytes(first), CurrentAuthLocalSessionArchivePolicy.HashBytes(second));
            await VerifyAsync(storage, scope, manifest, rows, ct).ConfigureAwait(false); return manifest;
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }
    internal static async Task VerifyAsync(ICurrentAuthLocalSessionArchiveStorage storage, CurrentAuthArchiveScope scope,
        CurrentAuthArchiveRecoveryManifest manifest, IReadOnlyList<CurrentAuthArchiveSession> rows, CancellationToken ct)
    {
        if (manifest.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(scope) || !CurrentAuthRepairPermit.HashShape(manifest.AuthorizationSha256))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        await storage.RequireCustodyAsync(ct).ConfigureAwait(false);
        byte[] expected = CurrentAuthLocalSessionArchivePolicy.EncodeRows(rows);
        try
        {
            if (rows.Count != scope.DeleteCount || CurrentAuthLocalSessionArchivePolicy.HashBytes(expected) != scope.DeleteSetSha256)
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            foreach (bool first in new[] { true, false })
            {
                byte[] recovered = await RecoverDomainAsync(storage, scope, manifest, first, ct).ConfigureAwait(false);
                try { if (!recovered.AsSpan().SequenceEqual(expected)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); } }
                finally { CryptographicOperations.ZeroMemory(recovered); }
            }
            await storage.RequireCustodyAsync(ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }
    // Reads only the selected recovery domain: it must work when the other domain is unavailable.
    internal static async Task<byte[]> RecoverDomainAsync(ICurrentAuthLocalSessionArchiveStorage storage, CurrentAuthArchiveScope scope,
        CurrentAuthArchiveRecoveryManifest manifest, bool firstDomain, CancellationToken ct)
    {
        if (manifest.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(scope) || !CurrentAuthRepairPermit.HashShape(manifest.AuthorizationSha256))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        string keyPath = firstDomain ? scope.Paths.RecoveryPrivateKey : scope.Paths.SecondRecoveryPrivateKey;
        string cipherPath = firstDomain ? scope.Paths.FirstCiphertext : scope.Paths.SecondCiphertext;
        byte[] key = await storage.ReadDomainHeldAsync(firstDomain, keyPath, 65536, ct).ConfigureAwait(false);
        using RSA recipient = RSA.Create();
        try { recipient.ImportPkcs8PrivateKey(key, out int consumed); if (consumed != key.Length) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); } }
        finally { CryptographicOperations.ZeroMemory(key); }
        if (recipient.KeySize != 3072 || CurrentAuthLocalSessionArchivePolicy.HashBytes(recipient.ExportSubjectPublicKeyInfo()) != manifest.RecoveryPublicKeySha256)
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        byte[] envelope = await storage.ReadDomainHeldAsync(firstDomain, cipherPath, MaximumEnvelopeBytes, ct).ConfigureAwait(false);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(envelope) != (firstDomain ? manifest.FirstCiphertextSha256 : manifest.SecondCiphertextSha256))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        byte[] recovered = Decrypt(envelope, Binding(scope, manifest.AuthorizationSha256, manifest.RecoveryPublicKeySha256), manifest.RecoveryPublicKeySha256, recipient);
        try
        {
            var rows = JsonSerializer.Deserialize<CurrentAuthArchiveSession[]>(recovered) ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid();
            byte[] canonical = CurrentAuthLocalSessionArchivePolicy.EncodeRows(rows);
            try
            {
                if (rows.Length != scope.DeleteCount || !canonical.AsSpan().SequenceEqual(recovered) || CurrentAuthLocalSessionArchivePolicy.HashBytes(recovered) != scope.DeleteSetSha256)
                { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            }
            finally { CryptographicOperations.ZeroMemory(canonical); }
            return recovered;
        }
        catch { CryptographicOperations.ZeroMemory(recovered); throw; }
    }
    private static byte[] Binding(CurrentAuthArchiveScope scope, string authorization, string publicKey)
    {
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            Domain = "Legacy.Maliev.CurrentAuth.SessionRecovery.v1",
            ScopeSha256 = CurrentAuthLocalSessionArchivePolicy.Hash(scope),
            AuthorizationSha256 = authorization,
            RecoveryPublicKeySha256 = publicKey,
            scope.DeleteCount,
            scope.DeleteSetSha256
        });
    }

    internal static byte[] Encrypt(byte[] plaintext, byte[] binding, string publicHash, RSA recovery)
    {
        if (plaintext.Length > CurrentAuthLocalSessionArchivePolicy.MaximumPlaintextBytes || recovery.KeySize != 3072) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        byte[] key = RandomNumberGenerator.GetBytes(32), nonce = RandomNumberGenerator.GetBytes(12), cipher = new byte[plaintext.Length], tag = new byte[16];
        try
        {
            using var aes = new AesGcm(key, 16); aes.Encrypt(nonce, plaintext, cipher, tag, binding);
            return JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthArchiveCiphertext(1, CurrentAuthLocalSessionArchivePolicy.HashBytes(binding), publicHash,
                Convert.ToBase64String(recovery.Encrypt(key, RSAEncryptionPadding.OaepSHA256)), Convert.ToBase64String(nonce), Convert.ToBase64String(cipher), Convert.ToBase64String(tag)));
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    internal static byte[] Decrypt(byte[] bytes, byte[] binding, string publicHash, RSA recovery)
    {
        if (bytes.Length > MaximumEnvelopeBytes) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        CurrentAuthArchiveCiphertext value = JsonSerializer.Deserialize<CurrentAuthArchiveCiphertext>(bytes) ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid();
        if (!JsonSerializer.SerializeToUtf8Bytes(value).AsSpan().SequenceEqual(bytes) || value.Version != 1 ||
            value.BindingSha256 != CurrentAuthLocalSessionArchivePolicy.HashBytes(binding) || value.RecoveryPublicKeySha256 != publicHash ||
            recovery.KeySize != 3072 || CurrentAuthLocalSessionArchivePolicy.HashBytes(recovery.ExportSubjectPublicKeyInfo()) != publicHash) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        byte[] nonce = Convert.FromBase64String(value.NonceBase64), tag = Convert.FromBase64String(value.TagBase64), cipher = Convert.FromBase64String(value.CiphertextBase64);
        if (nonce.Length != 12 || tag.Length != 16 || cipher.Length > CurrentAuthLocalSessionArchivePolicy.MaximumPlaintextBytes) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        byte[] key = recovery.Decrypt(Convert.FromBase64String(value.WrappedKeyBase64), RSAEncryptionPadding.OaepSHA256), plaintext = new byte[cipher.Length];
        try
        {
            if (key.Length != 32) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            using var aes = new AesGcm(key, 16); aes.Decrypt(nonce, cipher, tag, plaintext, binding); return plaintext;
        }
        catch { CryptographicOperations.ZeroMemory(plaintext); throw; }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
