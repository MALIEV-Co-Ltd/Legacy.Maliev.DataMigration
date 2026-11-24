using System.Text;

namespace Legacy.Maliev.DataMigration.Console;

// These are digest commitments, not raw native tuples and never a CurrentAuthNativeObservation or runtime admission.
internal sealed record CurrentAuthArchiveNativeCommitmentV2(string Kind, CurrentAppOwnedDatabaseSnapshot Snapshot,
    Dictionary<string, string[]> TupleDigests, Dictionary<string, CurrentAuthProofStorage> Storage,
    Dictionary<string, string> Expressions, string NativeSha256)
{
    private static readonly string[] CatalogInventory =
    [
        "pg_class", "pg_type", "pg_namespace", "pg_constraint", "pg_attrdef", "pg_trigger", "pg_proc", "pg_collation", "pg_policy", "pg_rewrite",
        "pg_extension", "pg_event_trigger", "pg_authid", "pg_database", "pg_tablespace", "pg_language", "pg_operator", "pg_cast", "pg_opclass", "pg_opfamily",
        "pg_am", "pg_conversion", "pg_attribute", "pg_index", "pg_depend", "pg_shdepend", "pg_description", "pg_shdescription", "pg_auth_members", "pg_default_acl",
        "pg_init_privs", "pg_inherits", "pg_partitioned_table", "pg_sequence", "pg_statistic", "pg_statistic_ext", "pg_statistic_ext_data", "pg_amop", "pg_amproc",
        "pg_range", "pg_transform", "pg_seclabel", "pg_shseclabel",
    ];
    internal static CurrentAuthArchiveNativeCommitmentV2 Capture(CurrentAuthNativeObservation value)
    {
        return new("current-auth-native-tuple-digest-commitment-v2", value.Snapshot,
            value.CopyTuples().ToDictionary(pair => pair.Key, pair => pair.Value.Select(text =>
                CurrentAuthLocalSessionArchivePolicy.HashBytes(Encoding.UTF8.GetBytes(text))).Order(StringComparer.Ordinal).ToArray(), StringComparer.Ordinal),
            value.CopyStorage().ToDictionary(pair => pair.Key, pair => new CurrentAuthProofStorage(pair.Value.FileNode, pair.Value.Blocks), StringComparer.Ordinal),
            value.CopyExpressions(), CurrentAuthArchiveRecoveryV2Preservation.NativeSha(value));
    }
    internal void Require()
    {
        if (Kind != "current-auth-native-tuple-digest-commitment-v2" || Snapshot.Database != "Auth" ||
            !TupleDigests.Keys.Order(StringComparer.Ordinal).SequenceEqual(CatalogInventory.Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
            !Storage.Keys.Order(StringComparer.Ordinal).SequenceEqual(Snapshot.Catalog.Where(fact => fact.Catalog == "pg_index").Select(fact => fact.ObjectId).Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
            TupleDigests.Any(pair => string.IsNullOrWhiteSpace(pair.Key) || pair.Value.Any(value => !CurrentAuthRepairPermit.HashShape(value))) ||
            Storage.Any(pair => string.IsNullOrWhiteSpace(pair.Key) || pair.Value.Blocks < 0) ||
            Expressions.Any(pair => string.IsNullOrWhiteSpace(pair.Key) || pair.Value is null) || NativeSha256 != ComputeNativeSha256())
        { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
    }
    internal string ComputeNativeSha256()
    {
        return CurrentAuthLocalSessionArchivePolicy.Hash(new
        {
            Kind = "current-auth-native-commitment-v2",
            Snapshot.Sha256,
            Tuples = TupleDigests.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, Values = pair.Value.Order(StringComparer.Ordinal) }),
            Storage = Storage.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, pair.Value.FileNode, pair.Value.Blocks }),
            Expressions = Expressions.OrderBy(pair => pair.Key, StringComparer.Ordinal),
        });
    }

    internal static void RequireSameAuxiliary(CurrentAuthArchiveNativeCommitmentV2 left, CurrentAuthArchiveNativeCommitmentV2 right)
    {
        left.Require(); right.Require();
        if (Auxiliary(left) != Auxiliary(right)) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
    }
    private static string Auxiliary(CurrentAuthArchiveNativeCommitmentV2 value)
    {
        return CurrentAuthLocalSessionArchivePolicy.Hash(new
        {
            Tuples = value.TupleDigests.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, Values = pair.Value.Order(StringComparer.Ordinal) }),
            Storage = value.Storage.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, pair.Value.FileNode, pair.Value.Blocks }),
            Expressions = value.Expressions.OrderBy(pair => pair.Key, StringComparer.Ordinal),
        });
    }
}
