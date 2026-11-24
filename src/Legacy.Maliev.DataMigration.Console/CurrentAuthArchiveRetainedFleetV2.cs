using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveRetainedFleetV2(CurrentAppOwnedDatabaseSnapshot[] Databases,
    CurrentAuthArchiveFleetCatalogs Catalogs, CurrentAuthArchiveSession[] Sessions, CurrentAuthArchiveNativeCommitmentV2 Native)
{
    internal void RequireWindow(CurrentAuthRepairScope policy, bool comparison, DateTimeOffset began, DateTimeOffset returned, bool original)
    {
        Native.Require();
        CurrentAuthLocalSessionArchivePolicy.RequireCatalogs(Catalogs, policy, comparison, Databases.Select(item => item.Database), began, returned);
        if (!ReviewedProductionRepairInventory.MatchesKeys(CurrentAuthLocalSessionArchivePolicy.InventoryProfile(comparison), Databases.Select(item => item.Database)) ||
            Databases.Select(item => item.Database).Distinct(StringComparer.Ordinal).Count() != Databases.Length ||
            Databases.Length != policy.BeforeDatabaseSha256.Count || Native.Snapshot.Sha256 != Databases.Single(item => item.Database == "Auth").Sha256 ||
            Native.Snapshot.Relations.Single(item => item.Schema == "public" && item.Name == "refresh_sessions").Rows != Sessions.Length ||
            (original && Databases.Any(item => !policy.BeforeDatabaseSha256.TryGetValue(item.Database, out string? expected) || item.Sha256 != expected))) { throw Invalid(); }
    }
    internal static void RequireExact(CurrentAuthArchiveRetainedFleetV2 left, CurrentAuthArchiveRetainedFleetV2 right)
    {
        if (!left.Databases.Select(item => item.Database).SequenceEqual(right.Databases.Select(item => item.Database), StringComparer.Ordinal) ||
            left.Databases.Any(item => item.Sha256 != right.Databases.Single(other => other.Database == item.Database).Sha256)) { throw Invalid(); }
        CurrentAuthArchiveNativeCommitmentV2.RequireSameAuxiliary(left.Native, right.Native);
        CurrentAuthLocalSessionArchivePolicy.RequireRows(left.Sessions, right.Sessions);
    }
    internal static void RequireDeletedOnly(CurrentAuthArchiveRetainedFleetV2 before, CurrentAuthArchiveRetainedFleetV2 after)
    {
        CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(before.Native.Snapshot, after.Native.Snapshot);
        CurrentAuthArchiveNativeCommitmentV2.RequireSameAuxiliary(before.Native, after.Native);
        if (after.Sessions.Length != 0 || !before.Databases.Select(item => item.Database).SequenceEqual(after.Databases.Select(item => item.Database), StringComparer.Ordinal) ||
            before.Databases.Where(item => item.Database != "Auth").Any(item => item.Sha256 != after.Databases.Single(other => other.Database == item.Database).Sha256)) { throw Invalid(); }
    }
    internal static void RequireRoleOnly(CurrentAuthArchiveRetainedFleetV2 before, CurrentAuthArchiveRetainedFleetV2 after,
        CurrentAuthArchiveGenuinePreflightRole? role)
    {
        CurrentAuthArchiveGenuinePreflight.RequireDataPreserved(before.Databases, after.Databases, role);
        CurrentAuthLocalSessionArchivePolicy.RequireRows(before.Sessions, after.Sessions);
        before.Native.Require(); after.Native.Require();
        var afterTuples = after.Native.TupleDigests.ToDictionary(pair => pair.Key, pair => pair.Value.ToArray(), StringComparer.Ordinal);
        if (role is not null)
        {
            var values = afterTuples["pg_authid"].ToList();
            if (values.Count(value => value == role.NativeTupleSha256) != 1) { throw Invalid(); }
            _ = values.Remove(role.NativeTupleSha256); afterTuples["pg_authid"] = values.ToArray();
        }
        var normalized = after.Native with { Snapshot = before.Native.Snapshot, TupleDigests = afterTuples };
        normalized = normalized with { NativeSha256 = normalized.ComputeNativeSha256() };
        CurrentAuthArchiveNativeCommitmentV2.RequireSameAuxiliary(before.Native, normalized);
    }
    // Explicit commitment parsing only. Digest strings are never reconstituted as raw CurrentAuthNativeObservation tuples.
    internal static CurrentAuthArchiveNativeCommitmentV2 ParseLegacyCommitment(JsonElement value, CurrentAppOwnedDatabaseSnapshot snapshot)
    {
        Dictionary<string, string[]> tuples;
        Dictionary<string, CurrentAuthProofStorage> storage;
        Dictionary<string, string> expressions;
        string? original = null;
        if (value.TryGetProperty("Kind", out var kind) && kind.GetString() == "current-auth-native-evidence-v2")
        {
            if (value.GetProperty("SnapshotSha256").GetString() != snapshot.Sha256) { throw Invalid(); }
            tuples = value.GetProperty("Tuples").EnumerateArray().ToDictionary(pair => pair.GetProperty("Key").GetString()!,
                pair => pair.GetProperty("Values").EnumerateArray().Select(item => item.GetString()!).ToArray(), StringComparer.Ordinal);
            storage = value.GetProperty("Storage").EnumerateArray().ToDictionary(pair => pair.GetProperty("Key").GetString()!,
                pair => new CurrentAuthProofStorage(pair.GetProperty("FileNode").GetUInt32(), pair.GetProperty("Blocks").GetInt64()), StringComparer.Ordinal);
            expressions = value.GetProperty("Expressions").EnumerateArray().ToDictionary(pair => pair.GetProperty("Key").GetString()!, pair => pair.GetProperty("Value").GetString()!, StringComparer.Ordinal);
            original = value.GetProperty("Sha256").GetString();
        }
        else
        {
            tuples = MigrationConsole.DecodeAuthRepair<Dictionary<string, string[]>>(JsonSerializer.SerializeToUtf8Bytes(value.GetProperty("Tuples")));
            storage = MigrationConsole.DecodeAuthRepair<Dictionary<string, CurrentAuthProofStorage>>(JsonSerializer.SerializeToUtf8Bytes(value.GetProperty("Storage")));
            expressions = MigrationConsole.DecodeAuthRepair<Dictionary<string, string>>(JsonSerializer.SerializeToUtf8Bytes(value.GetProperty("Expressions")));
        }
        var result = new CurrentAuthArchiveNativeCommitmentV2("current-auth-native-tuple-digest-commitment-v2", snapshot, tuples, storage, expressions, string.Empty);
        result = result with { NativeSha256 = original ?? result.ComputeNativeSha256() }; result.Require(); return result;
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveRecoveryV2.Invalid();
    }
}
