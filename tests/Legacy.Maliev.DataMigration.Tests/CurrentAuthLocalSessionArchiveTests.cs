using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthLocalSessionArchiveTests
{
    private static readonly string[] ExpectedRecoveryWriteOrder = ["synthetic/key.pkcs8", "synthetic/second/key.pkcs8", "synthetic/first/archive.json", "synthetic/second/archive.json"];
    private static CurrentAuthArchiveSession Row()
    {
        return new(Guid.Parse("11111111-1111-1111-1111-111111111111"),
        Guid.Parse("22222222-2222-2222-2222-222222222222"), "synthetic-ไทย", 1, null, "synthetic-token-hash",
        new DateTime(2031, 1, 1, 0, 0, 0, DateTimeKind.Utc), new DateTime(2031, 1, 2, 0, 0, 0, DateTimeKind.Utc), null, null, null);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    public void Every_typed_field_participates_in_exact_CAS(int field)
    {
        CurrentAuthArchiveSession row = Row();
        CurrentAuthArchiveSession changed = field switch
        {
            0 => row with { Id = Guid.NewGuid() },
            1 => row with { FamilyId = Guid.NewGuid() },
            2 => row with { IdentityId = "synthetic-ไทย " },
            3 => row with { IdentityKind = 2 },
            4 => row with { SecurityStamp = "" },
            5 => row with { TokenHash = "different" },
            6 => row with { CreatedAt = row.CreatedAt.AddTicks(10) },
            7 => row with { ExpiresAt = row.ExpiresAt.AddTicks(10) },
            8 => row with { RotatedAt = row.CreatedAt },
            9 => row with { RevokedAt = row.CreatedAt },
            10 => row with { ReplacedById = Guid.NewGuid() },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireRows([row], [changed]));
    }
    [Fact]
    public void Fresh_sets_are_not_hardcoded_to_two_and_order_does_not_change_the_CAS_set()
    {
        CurrentAuthArchiveSession row = Row(); CurrentAuthArchiveSession[] rows = [row, row with { Id = Guid.NewGuid() }, row with { Id = Guid.NewGuid() }];
        CurrentAuthLocalSessionArchivePolicy.RequireRows(rows, rows.Reverse().ToArray());
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.EncodeRows([row, row]));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.EncodeRows([row with { CreatedAt = row.CreatedAt.AddTicks(1) }]));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.EncodeRows([row with { ExpiresAt = DateTime.SpecifyKind(row.ExpiresAt, DateTimeKind.Unspecified) }]));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireRows(rows, [row]));
    }
    [Theory]
    [InlineData("catalog")]
    [InlineData("history")]
    [InlineData("private-journal")]
    [InlineData("sequence")]
    [InlineData("row-hash")]
    [InlineData("count")]
    [InlineData("duplicate-relation")]
    public void Exact_DELETE_comparator_rejects_every_unapproved_delta(string fault)
    {
        var before = new CurrentAppOwnedDatabaseSnapshot("Auth", [new("pg_index", "synthetic", new string('a', 64), "pg_class", "1")],
            [new("public", "__EFMigrationsHistory", 5, new string('b', 64)), new("private", "journal", 1, new string('c', 64)),
             new("public", "refresh_sessions", 3, new string('d', 64))], [new("private", "sequence", "synthetic-owner", new string('e', 64))]);
        var relations = before.Relations.ToArray(); relations[2] = relations[2] with { Rows = 0, RowSha256 = Convert.ToHexStringLower(SHA256.HashData([])) };
        var after = before with { Relations = relations };
        CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(before, after);
        after = fault switch
        {
            "catalog" => after with { Catalog = [before.Catalog[0] with { Sha256 = new string('f', 64) }] },
            "history" => after with { Relations = [relations[0] with { RowSha256 = new string('f', 64) }, relations[1], relations[2]] },
            "private-journal" => after with { Relations = [relations[0], relations[1] with { Rows = 0 }, relations[2]] },
            "sequence" => after with { Sequences = [before.Sequences[0] with { TupleSha256 = new string('f', 64) }] },
            "row-hash" => after with { Relations = [relations[0], relations[1], relations[2] with { RowSha256 = new string('f', 64) }] },
            "count" => after with { Relations = [relations[0], relations[1], relations[2] with { Rows = 1 }] },
            "duplicate-relation" => after with { Relations = [.. relations, relations[2]] },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(before, after));
    }
    [Fact]
    public void Encrypted_copy_roundtrips_all_fields_and_rejects_wrong_binding_recipient_and_tampering()
    {
        using RSA recipient = RSA.Create(3072); using RSA foreign = RSA.Create(3072);
        byte[] plain = CurrentAuthLocalSessionArchivePolicy.EncodeRows([Row()]); byte[] binding = "synthetic-reviewed-binding"u8.ToArray();
        string fingerprint = CurrentAuthLocalSessionArchivePolicy.HashBytes(recipient.ExportSubjectPublicKeyInfo());
        byte[] archive = CurrentAuthLocalSessionArchiveCrypto.Encrypt(plain, binding, fingerprint, recipient);
        byte[] recovered = CurrentAuthLocalSessionArchiveCrypto.Decrypt(archive, binding, fingerprint, recipient);
        try { Assert.Equal(plain, recovered); }
        finally { CryptographicOperations.ZeroMemory(recovered); }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveCrypto.Decrypt(archive, "foreign"u8.ToArray(), fingerprint, recipient));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveCrypto.Decrypt(archive, binding, fingerprint, foreign));
        CurrentAuthArchiveCiphertext envelope = JsonSerializer.Deserialize<CurrentAuthArchiveCiphertext>(archive)!;
        byte[] ciphertext = Convert.FromBase64String(envelope.CiphertextBase64); ciphertext[0] ^= 1;
        byte[] corrupt = JsonSerializer.SerializeToUtf8Bytes(envelope with { CiphertextBase64 = Convert.ToBase64String(ciphertext) });
        _ = Assert.ThrowsAny<CryptographicException>(() => CurrentAuthLocalSessionArchiveCrypto.Decrypt(corrupt, binding, fingerprint, recipient));
        CryptographicOperations.ZeroMemory(plain);
    }
    [Fact]
    public void Genuine_signature_is_domain_separated_and_unknown_payload_cannot_be_adopted()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("synthetic-review", key.ExportPkcs8PrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore([new("synthetic-review", key.ExportSubjectPublicKeyInfo())]);
        var value = new CurrentAuthArchiveAuthorization(Guid.NewGuid(), new string('a', 64), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1));
        CurrentAuthArchiveClaim claim = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain, value, signer);
        Assert.Equal(value, CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveAuthorization>(claim,
            CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain, signer.KeyId, signer.PublicKeyFingerprintSha256, trust));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveAuthorization>(claim,
            CurrentAuthLocalSessionArchivePolicy.ReviewDomain, signer.KeyId, signer.PublicKeyFingerprintSha256, trust));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveAuthorization>(claim with { SignatureBase64 = Convert.ToBase64String(new byte[64]) },
            CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain, signer.KeyId, signer.PublicKeyFingerprintSha256, trust));
    }
    [Fact]
    public async Task Both_independent_ciphertexts_and_durable_recovery_key_are_actually_read_and_decrypted()
    {
        using var storage = new SyntheticStorage();
        CurrentAuthArchiveScope scope = CryptoOnlyScope();
        CurrentAuthArchiveRecoveryManifest manifest = await CurrentAuthLocalSessionArchiveCrypto.WriteAndVerifyAsync(storage, scope,
            new string('a', 64), [Row()], CancellationToken.None);
        Assert.Equal(ExpectedRecoveryWriteOrder, storage.WriteOrder);
        Assert.NotEqual(manifest.FirstCiphertextSha256, manifest.SecondCiphertextSha256);
        Assert.True(storage.ReadCounts[scope.Paths.RecoveryPrivateKey] >= 2);
        Assert.True(storage.ReadCounts[scope.Paths.FirstCiphertext] >= 1); Assert.True(storage.ReadCounts[scope.Paths.SecondCiphertext] >= 1);
        storage.Bytes[scope.Paths.SecondCiphertext][0] ^= 1;
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveCrypto.VerifyAsync(storage, scope, manifest, [Row()], CancellationToken.None));
    }
    [Theory]
    [InlineData("synthetic/key.pkcs8")]
    [InlineData("synthetic/second/key.pkcs8")]
    [InlineData("synthetic/first/archive.json")]
    [InlineData("synthetic/second/archive.json")]
    public async Task Any_durable_creation_failure_produces_no_recovery_manifest(string failingPath)
    {
        using var storage = new SyntheticStorage { FailPath = failingPath };
        _ = await Assert.ThrowsAsync<IOException>(() => CurrentAuthLocalSessionArchiveCrypto.WriteAndVerifyAsync(storage,
            CryptoOnlyScope(), new string('a', 64), [Row()], CancellationToken.None));
    }
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Either_domain_recovers_when_the_other_is_unavailable(bool first)
    {
        using var storage = new SyntheticStorage(); var scope = CryptoOnlyScope();
        var manifest = await CurrentAuthLocalSessionArchiveCrypto.WriteAndVerifyAsync(storage, scope, new string('a', 64), [Row()], CancellationToken.None);
        storage.AvailableDomain = first;
        byte[] recovered = await CurrentAuthLocalSessionArchiveCrypto.RecoverDomainAsync(storage, scope, manifest, first, CancellationToken.None);
        try { CurrentAuthLocalSessionArchivePolicy.RequireRows(JsonSerializer.Deserialize<CurrentAuthArchiveSession[]>(recovered)!, [Row()]); }
        finally { CryptographicOperations.ZeroMemory(recovered); }
        _ = await Assert.ThrowsAsync<IOException>(() => CurrentAuthLocalSessionArchiveCrypto.RecoverDomainAsync(storage, scope, manifest, !first, CancellationToken.None));
    }
    // Encryption component fixture only. Null policy fields deliberately cannot admit
    // a deletion permit and are not evidence of Windows custody or target observation.
    private static CurrentAuthArchiveScope CryptoOnlyScope()
    {
        byte[] rows = CurrentAuthLocalSessionArchivePolicy.EncodeRows([Row()]);
        try
        {
            return new(Guid.NewGuid(), null!, null!, CurrentAuthLocalSessionArchivePolicy.HashBytes(rows), 1, new string('b', 64),
            new("synthetic/first/archive.json", "synthetic/second/archive.json", "synthetic/key.pkcs8", "synthetic/second/key.pkcs8"), new string('c', 64),
            new string('d', 64), new string('e', 64), new string('f', 64), new string('a', 64), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1));
        }
        finally { CryptographicOperations.ZeroMemory(rows); }
    }
    private sealed class SyntheticStorage : ICurrentAuthLocalSessionArchiveStorage, IDisposable
    {
        internal string? FailPath { get; init; }
        internal bool? AvailableDomain { get; set; }
        internal Dictionary<string, byte[]> Bytes { get; } = new(StringComparer.Ordinal);
        internal Dictionary<string, int> ReadCounts { get; } = new(StringComparer.Ordinal);
        internal List<string> WriteOrder { get; } = [];
        public Task RequireFreshIndependentRecoveryPathsAsync(CurrentAuthArchivePaths paths, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); Assert.Empty(Bytes); return Task.CompletedTask; }
        public Task WriteCreateNewDurableAsync(string path, byte[] bytes, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); if (path == FailPath) { throw new IOException("synthetic durable write rejection"); }
            Bytes.Add(path, bytes.ToArray()); WriteOrder.Add(path); return Task.CompletedTask;
        }
        public Task<byte[]> ReadHeldAsync(string path, int maximumBytes, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); Assert.True(Bytes[path].Length <= maximumBytes); ReadCounts[path] = ReadCounts.GetValueOrDefault(path) + 1; return Task.FromResult(Bytes[path].ToArray()); }
        public Task<byte[]> ReadDomainHeldAsync(bool firstDomain, string path, int maximumBytes, CancellationToken ct)
        {
            if (AvailableDomain is { } available && available != firstDomain) { throw new IOException("Other synthetic domain is unavailable"); }
            bool actualFirst = path is "synthetic/key.pkcs8" or "synthetic/first/archive.json";
            Assert.Equal(actualFirst, firstDomain); return ReadHeldAsync(path, maximumBytes, ct);
        }
        public Task RequireCustodyAsync(CancellationToken ct) { ct.ThrowIfCancellationRequested(); return Task.CompletedTask; }
        public void Dispose() { foreach (byte[] bytes in Bytes.Values) { CryptographicOperations.ZeroMemory(bytes); } }
    }
}
