using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed partial class CurrentAuthLocalSessionArchiveNativeTests
{
    // Genuine disposable PostgreSQL decrypt/insert/readback component. This in-memory
    // storage seam cannot produce the closed Windows/device/provider proof manifest.
    [WindowsLocalRunTheory]
    [InlineData(true)]
    [InlineData(false)]
    public Task Decrypted_domain_restores_all_eleven_fields_with_other_domain_unavailable(bool firstDomain)
    {
        return RunOwnedAsync(async (admin, token) =>
        {
            string endpoint = await BootstrapAsync(admin, "10.0.12", token); string binding = new('a', 64);
            CurrentAuthLocalSessionArchiveObservation original;
            await using (var connection = new NpgsqlConnection(endpoint))
            {
                await connection.OpenAsync(token); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token);
                await CandidateAsync(connection, tx, token); await tx.CommitAsync(token);
            }
            using var storage = new RecoveryComponentStorage();
            CurrentAuthArchiveScope scope;
            CurrentAuthArchiveRecoveryManifest manifest;
            await using (var connection = new NpgsqlConnection(endpoint))
            {
                await connection.OpenAsync(token); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token);
                original = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, binding, token);
                byte[] rows = CurrentAuthLocalSessionArchivePolicy.EncodeRows(original.Sessions);
                try
                {
                    scope = new(Guid.NewGuid(), null!, null!, CurrentAuthLocalSessionArchivePolicy.HashBytes(rows), original.Sessions.Count, new string('b', 64),
                        new("first-cipher", "second-cipher", "first-key", "second-key"), new string('c', 64), new string('d', 64), new string('e', 64),
                        new string('f', 64), new string('a', 64), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap);
                }
                finally { CryptographicOperations.ZeroMemory(rows); }
                manifest = await CurrentAuthLocalSessionArchiveCrypto.WriteAndVerifyAsync(storage, scope, new string('a', 64), original.Sessions, token);
                await DeleteAsync(connection, tx, original, token); await tx.CommitAsync(token);
            }
            storage.AvailableDomain = firstDomain;
            byte[] decrypted = await CurrentAuthLocalSessionArchiveCrypto.RecoverDomainAsync(storage, scope, manifest, firstDomain, token);
            try
            {
                var recovered = JsonSerializer.Deserialize<CurrentAuthArchiveSession[]>(decrypted) ?? throw new InvalidOperationException("Missing typed recovery rows");
                CurrentAuthLocalSessionArchivePolicy.RequireRows(recovered, original.Sessions);
                await using (var connection = new NpgsqlConnection(endpoint))
                {
                    await connection.OpenAsync(token); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token);
                    var empty = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, binding, token);
                    CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(original, empty);
                    foreach (var row in recovered)
                    {
                        await using var insert = new NpgsqlCommand("INSERT INTO public.refresh_sessions (" + CurrentAuthLocalSessionArchiveObservation.Fields +
                            ") VALUES (@id,@family,@identity,@kind,@stamp,@token,@created,@expires,@rotated,@revoked,@replacement);", connection, tx);
                        _ = insert.Parameters.AddWithValue("id", NpgsqlDbType.Uuid, row.Id);
                        _ = insert.Parameters.AddWithValue("family", NpgsqlDbType.Uuid, row.FamilyId);
                        _ = insert.Parameters.AddWithValue("identity", NpgsqlDbType.Varchar, row.IdentityId);
                        _ = insert.Parameters.AddWithValue("kind", NpgsqlDbType.Integer, row.IdentityKind);
                        _ = insert.Parameters.AddWithValue("stamp", NpgsqlDbType.Varchar, (object?)row.SecurityStamp ?? DBNull.Value);
                        _ = insert.Parameters.AddWithValue("token", NpgsqlDbType.Varchar, row.TokenHash);
                        _ = insert.Parameters.AddWithValue("created", NpgsqlDbType.TimestampTz, row.CreatedAt);
                        _ = insert.Parameters.AddWithValue("expires", NpgsqlDbType.TimestampTz, row.ExpiresAt);
                        _ = insert.Parameters.AddWithValue("rotated", NpgsqlDbType.TimestampTz, (object?)row.RotatedAt ?? DBNull.Value);
                        _ = insert.Parameters.AddWithValue("revoked", NpgsqlDbType.TimestampTz, (object?)row.RevokedAt ?? DBNull.Value);
                        _ = insert.Parameters.AddWithValue("replacement", NpgsqlDbType.Uuid, (object?)row.ReplacedById ?? DBNull.Value);
                        Assert.Equal(1, await insert.ExecuteNonQueryAsync(token));
                    }
                    CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(
                        await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, binding, token), original);
                    await tx.CommitAsync(token);
                }
                // Prior restore writer is disposed before independent readback.
                await using (var connection = new NpgsqlConnection(endpoint))
                {
                    await connection.OpenAsync(token); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, token);
                    await ExecuteAsync(connection, "SET TRANSACTION READ ONLY;", token, tx);
                    CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(
                        await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, binding, token), original);
                    await tx.RollbackAsync(token);
                }
            }
            finally { CryptographicOperations.ZeroMemory(decrypted); }
            _ = await Assert.ThrowsAsync<IOException>(() => CurrentAuthLocalSessionArchiveCrypto.RecoverDomainAsync(storage, scope, manifest, !firstDomain, token));
        });
    }
    private sealed class RecoveryComponentStorage : ICurrentAuthLocalSessionArchiveStorage, IDisposable
    {
        private readonly Dictionary<string, byte[]> _bytes = new(StringComparer.Ordinal);
        internal bool? AvailableDomain { get; set; }
        public Task RequireFreshIndependentRecoveryPathsAsync(CurrentAuthArchivePaths paths, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); Assert.Empty(_bytes); return Task.CompletedTask; }
        public Task WriteCreateNewDurableAsync(string path, byte[] bytes, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); _bytes.Add(path, bytes.ToArray()); return Task.CompletedTask; }
        public Task<byte[]> ReadHeldAsync(string path, int maximumBytes, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); Assert.True(_bytes[path].Length <= maximumBytes); return Task.FromResult(_bytes[path].ToArray()); }
        public Task<byte[]> ReadDomainHeldAsync(bool first, string path, int maximumBytes, CancellationToken ct)
        {
            if (AvailableDomain is { } available && available != first) { throw new IOException("Other component domain unavailable"); }
            Assert.Equal(first, path.StartsWith("first", StringComparison.Ordinal)); return ReadHeldAsync(path, maximumBytes, ct);
        }
        public Task RequireCustodyAsync(CancellationToken ct) { ct.ThrowIfCancellationRequested(); return Task.CompletedTask; }
        public void Dispose() { foreach (byte[] bytes in _bytes.Values) { CryptographicOperations.ZeroMemory(bytes); } }
    }
}
