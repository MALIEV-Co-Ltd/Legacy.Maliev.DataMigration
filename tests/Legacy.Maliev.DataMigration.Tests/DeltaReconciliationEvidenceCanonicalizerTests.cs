namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DeltaReconciliationEvidenceCanonicalizerTests
{
    [Fact]
    public void ComputeSha256_DictionaryAndTableInsertionOrder_DoesNotChangeEvidenceBinding()
    {
        DatabaseReconciliationEvidence first = Evidence(reverse: false);
        DatabaseReconciliationEvidence second = Evidence(reverse: true);

        Assert.Equal(
            DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(first),
            DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(second));
    }

    [Fact]
    public void ComputeSha256_ChangedEvidenceFieldOrValue_ChangesSecurityBinding()
    {
        DatabaseReconciliationEvidence baseline = Evidence(reverse: false);
        TableReconciliationEvidence first = baseline.Tables[0];
        DatabaseReconciliationEvidence changed = baseline with
        {
            Tables = [first with { RowCount = first.RowCount + 1 }, .. baseline.Tables.Skip(1)],
        };

        Assert.NotEqual(
            DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(baseline),
            DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(changed));
    }

    private static DatabaseReconciliationEvidence Evidence(bool reverse)
    {
        string[] names = reverse ? ["public.second", "public.first"] : ["public.first", "public.second"];
        TableReconciliationEvidence[] tables = [.. names.Select(name => new TableReconciliationEvidence(
            name,
            2,
            new('1', 64),
            new('2', 64),
            Counts(reverse),
            Counts(reverse))
        {
            ForeignKeyRelationshipCounts = Counts(reverse),
        })];
        return new("ContactRequest", new('3', 64), new('4', 64), tables)
        {
            SequenceNextValues = Counts(reverse),
        };
    }

    private static Dictionary<string, long> Counts(bool reverse)
    {
        IEnumerable<KeyValuePair<string, long>> values = reverse
            ? [new("second", 2), new("first", 1)]
            : [new("first", 1), new("second", 2)];
        return values.ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal);
    }
}
