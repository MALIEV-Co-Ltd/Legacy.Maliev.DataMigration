using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

public static class SnapshotManifestAuthentication
{
    public static string ComputeSemanticDigest(string snapshotId, IReadOnlyList<LocalSnapshotDatabase> databases)
    {
        return Convert.ToHexString(SHA256.HashData(WriteSemantic(snapshotId, databases))).ToLowerInvariant();
    }

    public static string ComputeMac(LocalSnapshotManifest manifest, ReadOnlySpan<byte> rootKey)
    {
        byte[] macKey = SnapshotKeyDerivation.DeriveManifestMacKey(rootKey);
        try { return Convert.ToHexString(HMACSHA256.HashData(macKey, WriteAuthenticated(manifest))).ToLowerInvariant(); }
        finally { CryptographicOperations.ZeroMemory(macKey); }
    }

    private static byte[] WriteSemantic(string snapshotId, IReadOnlyList<LocalSnapshotDatabase> databases)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject(); writer.WriteNumber("schemaVersion", 2); writer.WriteString("format", "MLVSNP02");
            writer.WriteString("snapshotId", snapshotId); writer.WriteStartArray("databases");
            foreach (LocalSnapshotDatabase entry in databases.OrderBy(x => x.Database, StringComparer.Ordinal))
            {
                writer.WriteStartObject(); writer.WriteString("database", entry.Database); writer.WriteString("shadowDatabase", entry.ShadowDatabase);
                writer.WriteString("fileName", entry.FileName); writer.WriteNumber("plaintextByteLength", entry.PlaintextByteLength);
                writer.WriteString("plaintextSha256", entry.PlaintextSha256); writer.WriteEndObject();
            }
            writer.WriteEndArray(); writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    private static byte[] WriteAuthenticated(LocalSnapshotManifest manifest)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject(); writer.WriteNumber("schemaVersion", manifest.SchemaVersion); writer.WriteString("format", manifest.Format);
            writer.WriteString("encryption", manifest.Encryption); writer.WriteString("snapshotId", manifest.SnapshotId);
            writer.WriteString("manifestDigestSha256", manifest.ManifestDigestSha256); writer.WriteStartArray("databases");
            foreach (LocalSnapshotDatabase entry in manifest.Databases.OrderBy(x => x.Database, StringComparer.Ordinal))
            {
                writer.WriteStartObject(); writer.WriteString("database", entry.Database); writer.WriteString("shadowDatabase", entry.ShadowDatabase);
                writer.WriteString("fileName", entry.FileName); writer.WriteNumber("plaintextByteLength", entry.PlaintextByteLength);
                writer.WriteString("plaintextSha256", entry.PlaintextSha256); writer.WriteNumber("encryptedByteLength", entry.EncryptedByteLength);
                writer.WriteString("encryptedSha256", entry.EncryptedSha256); writer.WriteEndObject();
            }
            writer.WriteEndArray(); writer.WriteEndObject();
        }
        return stream.ToArray();
    }
}
