using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Actual bounded typed session/native observation; no credential acquisition or authority.</summary>
internal sealed class CurrentAuthLocalSessionArchiveObservation
{
    internal string TargetBindingSha256 { get; }
    internal CurrentAuthNativeObservation Native { get; }
    internal IReadOnlyList<CurrentAuthArchiveSession> Sessions { get; }
    private CurrentAuthLocalSessionArchiveObservation(string binding, CurrentAuthNativeObservation native, CurrentAuthArchiveSession[] rows)
    { TargetBindingSha256 = binding; Native = native; Sessions = Array.AsReadOnly(rows); }
    internal const string Fields = "\"Id\",\"FamilyId\",\"IdentityId\",\"IdentityKind\",\"SecurityStamp\",\"TokenHash\",\"CreatedAt\",\"ExpiresAt\",\"RotatedAt\",\"RevokedAt\",\"ReplacedById\"";
    internal static async Task<CurrentAuthLocalSessionArchiveObservation> CaptureAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string targetBindingSha256, CancellationToken ct)
    {
        if (connection.Database != "Auth" || transaction.Connection != connection ||
            transaction.IsolationLevel is not (IsolationLevel.RepeatableRead or IsolationLevel.Serializable) ||
            !CurrentAuthRepairPermit.HashShape(targetBindingSha256)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        // The owner closure applies to exactly four public tables. Private journals
        // are independently retained in the complete raw snapshot below, never
        // treated as extra owner tables or omitted from preservation comparison.
        // Reject dependencies with DELETE effects, including private-schema inbound FKs.
        const string unsupported = """
            SELECT (SELECT count(*) FROM pg_trigger WHERE tgrelid='public.refresh_sessions'::regclass AND tgenabled<>'D'),
              (SELECT count(*) FROM pg_constraint WHERE contype='f' AND (conrelid='public.refresh_sessions'::regclass OR confrelid='public.refresh_sessions'::regclass)),
              (SELECT count(*) FROM pg_rewrite WHERE ev_class='public.refresh_sessions'::regclass),
              (SELECT count(*) FROM pg_policy WHERE polrelid='public.refresh_sessions'::regclass);
            """;
        await using (var command = new NpgsqlCommand(unsupported, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        { if (!await reader.ReadAsync(ct).ConfigureAwait(false) || Enumerable.Range(0, 4).Any(i => reader.GetInt64(i) != 0)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); } }
        await using (var bound = new NpgsqlCommand("SELECT count(*),coalesce(sum(octet_length(row_to_json(s)::text)),0)::bigint FROM public.refresh_sessions s;", connection, transaction))
        await using (NpgsqlDataReader reader = await bound.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(ct).ConfigureAwait(false) || reader.GetInt64(0) > CurrentAuthLocalSessionArchivePolicy.MaximumRows ||
                reader.GetInt64(1) > CurrentAuthLocalSessionArchivePolicy.MaximumPlaintextBytes) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
        CurrentAuthNativeObservation native = await CurrentAuthNativePreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
        CurrentAuthNativePreservation.RequireCurrentExplicitCShape(native);
        RequireIndexCollations(native);
        await using var rowsCommand = new NpgsqlCommand("SELECT " + Fields + " FROM public.refresh_sessions ORDER BY \"Id\" LIMIT 8193;", connection, transaction);
        CurrentAuthArchiveSession[] rows = await ReadRowsAsync(rowsCommand, ct).ConfigureAwait(false);
        CurrentAppOwnedRelationFact relation = native.Snapshot.Relations.Single(x => x.Schema == "public" && x.Name == "refresh_sessions");
        return relation.Rows != rows.Length ? throw CurrentAuthLocalSessionArchivePolicy.Invalid() : new(targetBindingSha256, native, rows);
    }
    private static void RequireIndexCollations(CurrentAuthNativeObservation observation)
    {
        // After-only shape validation preserves the historical transition reader.
        // Also require each current public index's native collation vector to match
        // its exact bound columns; NULLS DISTINCT/opclass/options use the shared validator.
        var namespaces = observation.Read("pg_namespace"); var classes = observation.Read("pg_class");
        var attributes = observation.Read("pg_attribute");
        string ns = namespaces.Single(row => row["nspname"]!.ToString() == "public")["oid"]!.ToString();
        foreach (var index in observation.Read("pg_index"))
        {
            string relation = index["indrelid"]!.ToString();
            var table = classes.Single(row => row["oid"]!.ToString() == relation);
            if (table["relnamespace"]!.ToString() != ns) { continue; }
            string[] keys = NativeVector(index["indkey"]!);
            string[] collations = NativeVector(index["indcollation"]!);
            if (keys.Length != collations.Length || keys.Select((key, position) => (key, position)).Any(pair =>
                attributes.Single(row => row["attrelid"]!.ToString() == relation && row["attnum"]!.ToString() == pair.key)["attcollation"]!.ToString() != collations[pair.position]))
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
        static string[] NativeVector(System.Text.Json.Nodes.JsonNode value)
        {
            return value is System.Text.Json.Nodes.JsonArray array
            ? array.Select(item => item!.ToString()).ToArray()
            : value.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        }
    }
    internal static async Task<CurrentAuthArchiveSession[]> ReadRowsAsync(NpgsqlCommand command, CancellationToken ct)
    {
        var rows = new List<CurrentAuthArchiveSession>();
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            if (rows.Count == CurrentAuthLocalSessionArchivePolicy.MaximumRows) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            rows.Add(new(reader.GetGuid(0), reader.GetGuid(1), reader.GetString(2), reader.GetInt32(3),
                reader.IsDBNull(4) ? null : reader.GetString(4), reader.GetString(5), reader.GetDateTime(6), reader.GetDateTime(7),
                reader.IsDBNull(8) ? null : reader.GetDateTime(8), reader.IsDBNull(9) ? null : reader.GetDateTime(9), reader.IsDBNull(10) ? null : reader.GetGuid(10)));
        }
        byte[] encoded = CurrentAuthLocalSessionArchivePolicy.EncodeRows(rows);
        CryptographicOperations.ZeroMemory(encoded); return rows.ToArray();
    }
    internal static void RequireExactPreimage(CurrentAuthLocalSessionArchiveObservation actual, CurrentAuthLocalSessionArchiveObservation expected)
    {
        if (actual.TargetBindingSha256 != expected.TargetBindingSha256 || actual.Native.Snapshot.Sha256 != expected.Native.Snapshot.Sha256 ||
            !SameNativeAuxiliary(actual.Native, expected.Native)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        CurrentAuthLocalSessionArchivePolicy.RequireRows(actual.Sessions, expected.Sessions);
    }
    internal static void RequireDeletedOnly(CurrentAuthLocalSessionArchiveObservation before, CurrentAuthLocalSessionArchiveObservation after)
    {
        RequireDeletedOnly(before.Native.Snapshot, after.Native.Snapshot);
        if (before.TargetBindingSha256 != after.TargetBindingSha256 || after.Sessions.Count != 0 || !SameNativeAuxiliary(before.Native, after.Native))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
    }
    internal static void RequireDeletedOnly(CurrentAppOwnedDatabaseSnapshot before, CurrentAppOwnedDatabaseSnapshot after)
    {
        if (before.Database != "Auth" || after.Database != "Auth" || !before.Catalog.SequenceEqual(after.Catalog) ||
            !before.Sequences.SequenceEqual(after.Sequences) || before.Relations.Count != after.Relations.Count) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        string empty = Convert.ToHexStringLower(SHA256.HashData([]));
        int targets = 0;
        for (int i = 0; i < before.Relations.Count; i++)
        {
            CurrentAppOwnedRelationFact left = before.Relations[i], right = after.Relations[i];
            if (left.Schema == "public" && left.Name == "refresh_sessions")
            { targets++; if (left.Rows <= 0 || right != left with { Rows = 0, RowSha256 = empty }) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); } }
            else if (left != right) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
        if (targets != 1) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
    }
    private static bool SameNativeAuxiliary(CurrentAuthNativeObservation left, CurrentAuthNativeObservation right)
    {
        var a = left.CopyTuples(); var b = right.CopyTuples();
        var leftStorage = left.CopyStorage(); var rightStorage = right.CopyStorage();
        return a.Count == b.Count && a.All(pair => b.TryGetValue(pair.Key, out string[]? other) &&
                pair.Value.Order(StringComparer.Ordinal).SequenceEqual(other.Order(StringComparer.Ordinal), StringComparer.Ordinal)) &&
            leftStorage.Count == rightStorage.Count && leftStorage.All(pair => rightStorage.TryGetValue(pair.Key, out var other) && pair.Value == other) &&
            JsonSerializer.Serialize(left.CopyExpressions().OrderBy(x => x.Key, StringComparer.Ordinal)) == JsonSerializer.Serialize(right.CopyExpressions().OrderBy(x => x.Key, StringComparer.Ordinal));
    }
}
