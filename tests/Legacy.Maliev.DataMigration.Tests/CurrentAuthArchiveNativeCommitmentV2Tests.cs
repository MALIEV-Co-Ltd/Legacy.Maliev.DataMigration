using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveNativeCommitmentV2Tests
{
    private static readonly string[] Catalogs = ("pg_class pg_type pg_namespace pg_constraint pg_attrdef pg_trigger pg_proc pg_collation pg_policy pg_rewrite " +
        "pg_extension pg_event_trigger pg_authid pg_database pg_tablespace pg_language pg_operator pg_cast pg_opclass pg_opfamily pg_am pg_conversion " +
        "pg_attribute pg_index pg_depend pg_shdepend pg_description pg_shdescription pg_auth_members pg_default_acl pg_init_privs pg_inherits " +
        "pg_partitioned_table pg_sequence pg_statistic pg_statistic_ext pg_statistic_ext_data pg_amop pg_amproc pg_range pg_transform pg_seclabel pg_shseclabel").Split(' ');

    [Fact]
    public void Complete_native_commitment_retains_multiplicity_and_storage_without_raw_role_values()
    {
        var native = Native(); var retained = CurrentAuthArchiveNativeCommitmentV2.Capture(native); retained.Require();
        Assert.Equal(CurrentAuthArchiveRecoveryV2Preservation.NativeSha(native), retained.ComputeNativeSha256());
        Assert.Equal(43, retained.TupleDigests.Count); Assert.Equal(2, retained.TupleDigests["pg_authid"].Length);
        Assert.Equal(retained.TupleDigests["pg_authid"][0], retained.TupleDigests["pg_authid"][1]);
        string json = JsonSerializer.Serialize(retained);
        Assert.DoesNotContain("synthetic-password-verifier", json, StringComparison.Ordinal);
        Assert.Contains("\"FileNode\":77", json, StringComparison.Ordinal); Assert.Contains("\"Blocks\":3", json, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("block")]
    [InlineData("file")]
    [InlineData("tuple")]
    [InlineData("multiplicity")]
    [InlineData("catalog")]
    [InlineData("expression")]
    public void Independently_consistent_native_commitments_still_reject_any_auxiliary_change(string fault)
    {
        var original = CurrentAuthArchiveNativeCommitmentV2.Capture(Native()); original.Require();
        var changed = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveNativeCommitmentV2>(JsonSerializer.SerializeToUtf8Bytes(original));
        switch (fault)
        {
            case "block": changed.Storage["100"] = changed.Storage["100"] with { Blocks = 4 }; break;
            case "file": changed.Storage["100"] = changed.Storage["100"] with { FileNode = 78 }; break;
            case "tuple": changed.TupleDigests["pg_authid"][0] = new('b', 64); break;
            case "multiplicity": changed.TupleDigests["pg_authid"] = changed.TupleDigests["pg_authid"][..1]; break;
            case "catalog": _ = changed.TupleDigests.Remove("pg_authid"); break;
            case "expression": changed.Expressions["200"] = "synthetic changed constraint"; break;
            default:
                break;
        }
        changed = changed with { NativeSha256 = changed.ComputeNativeSha256() };
        if (fault != "catalog") { changed.Require(); }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveNativeCommitmentV2.RequireSameAuxiliary(original, changed));
    }

    private static CurrentAuthNativeObservation Native()
    {
        var tuples = Catalogs.ToDictionary(name => name, _ => Array.Empty<string>(), StringComparer.Ordinal);
        tuples["pg_authid"] = ["synthetic-password-verifier", "synthetic-password-verifier"];
        var snapshot = new CurrentAppOwnedDatabaseSnapshot("Auth",
            [new("pg_index", "synthetic-index", new('a', 64), "pg_class", "100"), new("pg_constraint", "synthetic-check", new('a', 64), "pg_constraint", "200")], [], []);
        return new(snapshot, tuples, new(StringComparer.Ordinal) { ["100"] = (77, 3) },
            new(StringComparer.Ordinal) { ["200"] = "synthetic constraint" });
    }
}
