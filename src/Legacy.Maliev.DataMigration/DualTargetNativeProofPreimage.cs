using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record DualTargetNativeProofRows(long Count, string MultisetSha256);
internal sealed record DualTargetNativeProofSequence(string Type, long Start, long Increment, long Minimum,
    long Maximum, long Cache, bool Cycle, long LastValue, bool IsCalled);
internal sealed record DualTargetNativeProofDatabase(string Database, string DefinitionSha256,
    IReadOnlyDictionary<string, DualTargetNativeProofRows> Tables,
    IReadOnlyDictionary<string, DualTargetNativeProofSequence> Sequences);
internal sealed record DualTargetNativeProofDump(string Database, string FileName, long Bytes, string Sha256,
    DateTimeOffset SnapshotBeganAtUtc, DateTimeOffset SnapshotCompletedAtUtc, string SourceSystemSha256);

// A logical clone is not an OID/filenode clone. Its own native baseline is bound separately.
internal static class DualTargetNativeProofPreimage
{
    internal static string Hash(DualTargetNativeProofDatabase database)
    {
        return HashBytes(JsonSerializer.SerializeToUtf8Bytes(new
        {
            Domain = "dual-target-native-logical-preimage-v1",
            database.Database,
            database.DefinitionSha256,
            Tables = database.Tables.OrderBy(x => x.Key, StringComparer.Ordinal),
            Sequences = database.Sequences.OrderBy(x => x.Key, StringComparer.Ordinal)
        }));
    }

    internal static void RequireClone(DualTargetNativeProofDatabase source, DualTargetNativeProofDatabase clone)
    {
        if (source.Database != clone.Database || !IsHash(source.DefinitionSha256) ||
            source.Tables.Values.Any(x => x.Count < 0 || !IsHash(x.MultisetSha256)) ||
            source.Sequences.Values.Any(x => x.Increment == 0 || x.Minimum > x.Maximum || x.Start < x.Minimum ||
                x.Start > x.Maximum || x.LastValue < x.Minimum || x.LastValue > x.Maximum || x.Cache < 1) || Hash(source) != Hash(clone))
        { throw Invalid(); }
    }

    internal static void RequireInventory(DualTargetCapturedDeltaPurpose source, IEnumerable<string> databases)
    {
        string[] expected = source switch
        {
            DualTargetCapturedDeltaPurpose.Production => [.. ReviewedProductionRepairInventory.ExportProductionNames()],
            DualTargetCapturedDeltaPurpose.PersistentLocal => [.. DatabaseInventory.ActiveDatabases, "Auth", "postgres", "legacy_local"],
            DualTargetCapturedDeltaPurpose.ProductionProof => throw Invalid(),
            DualTargetCapturedDeltaPurpose.LocalProof => throw Invalid(),
            _ => throw Invalid()
        };
        if (!databases.Order(StringComparer.Ordinal).SequenceEqual(expected.Order(StringComparer.Ordinal), StringComparer.Ordinal)) { throw Invalid(); }
    }

    internal static void RequireRoleNames(IReadOnlyList<string> names, string generatedAdministrator)
    {
        if (names.Count is 0 or > 256 || names.Distinct(StringComparer.Ordinal).Count() != names.Count ||
            names.Contains(generatedAdministrator, StringComparer.Ordinal) || names.Any(x => string.IsNullOrEmpty(x) ||
                x.Length > 63 || x.Any(char.IsControl) || x.StartsWith("pg_", StringComparison.Ordinal))) { throw Invalid(); }
    }

    internal static string HashBytes(ReadOnlySpan<byte> bytes)
    {
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }

    internal static bool IsHash(string value)
    {
        return value.Length == 64 && value.All(x => char.IsAsciiHexDigit(x) && !char.IsUpper(x));
    }

    internal static MigrationExecutionException Invalid()
    {
        return new("dual_target_native_proof_preimage_invalid",
            "The fixed owned full-fleet logical proof preimage is not verified.");
    }
}
