using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ConsumerColumnBootstrapUploadFaultPreservationTests
{
    [Fact]
    public void Exactly_one_fixed_probe_change_preserves_all_other_native_facts()
    {
        ConsumerColumnBootstrapUploadFaultPreservation.Require(Witness(false), Witness(true), 1);
    }

    [Theory]
    [InlineData("affected-count")]
    [InlineData("wrong-relation")]
    [InlineData("row-count")]
    [InlineData("sequence")]
    [InlineData("catalog")]
    [InlineData("auxiliary")]
    [InlineData("new-relation")]
    [InlineData("other-row")]
    [InlineData("checksum")]
    [InlineData("heap")]
    [InlineData("index")]
    public void Unbounded_or_unrelated_Upload_changes_are_rejected(string fault)
    {
        var before = Witness(false); var after = Witness(true);
        after = fault switch
        {
            "wrong-relation" => after with { Snapshot = after.Snapshot with { Relations = after.Snapshot.Relations.Select(relation => relation.Name == ConsumerColumnBootstrapUploadFaultPreservation.Table ? relation with { Schema = "public" } : relation).ToArray() } },
            "row-count" => after with { Snapshot = after.Snapshot with { Relations = after.Snapshot.Relations.Select(relation => relation.Name == ConsumerColumnBootstrapUploadFaultPreservation.Table ? relation with { Rows = 3 } : relation).ToArray() } },
            "sequence" => after with { Snapshot = after.Snapshot with { Sequences = after.Snapshot.Sequences.Select(sequence => sequence with { TupleSha256 = new string('c', 64) }).ToArray() } },
            "catalog" => after with { Snapshot = after.Snapshot with { Catalog = after.Snapshot.Catalog.Select(fact => fact with { Sha256 = new string('c', 64) }).ToArray() } },
            "auxiliary" => after with { Snapshot = after.Snapshot with { Relations = after.Snapshot.Relations.Select(relation => relation.Name == "BootstrapJournal" ? relation with { RowSha256 = new string('c', 64) } : relation).ToArray() } },
            "new-relation" => after with { Snapshot = after.Snapshot with { Relations = [.. after.Snapshot.Relations, new("public", "Unexpected", 0, new string('c', 64))] } },
            "other-row" => after with { ProbeRows = [after.ProbeRows[0], new(2, "unexpected")] },
            "checksum" => after with { Snapshot = after.Snapshot with { Relations = after.Snapshot.Relations.Select(relation => relation.Name == ConsumerColumnBootstrapUploadFaultPreservation.Table ? relation with { RowSha256 = new string('c', 64) } : relation).ToArray() } },
            "heap" => after with { Heaps = [new("100", 100, 2)] },
            "index" => after with { Indexes = [new("101", 102, 1)] },
            _ => after,
        };
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapUploadFaultPreservation.Require(before, after, fault == "affected-count" ? 2 : 1));
    }

    private static ConsumerColumnBootstrapUploadFaultWitness Witness(bool after)
    {
        // Synthetic unit metadata only; not source, native evidence or execution authority.
        string h = new('a', 64);
        return new(new("Upload", [new("pg_class", "100", h, "1259", "100")],
            [ConsumerColumnBootstrapUploadFaultPreservation.ExpectedProbe(after), new("legacy_migration_internal", "BootstrapJournal", 2, h)],
            [new("legacy_migration_internal", "BootstrapJournal_ID_seq", "owner", h)]), ConsumerColumnBootstrapNativePreservation.CatalogNames,
            [new(1, after ? "owned final fleet fault" : "before-one"), new(2, "before-two")], [new("100", 100, 1)], [new("101", 101, 1)]);
    }
}
