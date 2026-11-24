using System.Reflection;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveComparisonPreservationTests
{
    [Theory]
    [InlineData("file-node")]
    [InlineData("blocks")]
    [InlineData("expression")]
    [InlineData("tuple")]
    public void Untouched_comparison_rejects_existing_key_auxiliary_changes(string fault)
    {
        var before = Observation();
        // First admit an independently constructed valid baseline, so these failures cannot
        // be explained by an invalid fixture or missing auxiliary key.
        CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(Observation(), before);
        var changed = Observation(fault);
        Assert.Equal(before.Native.Snapshot.Sha256, changed.Native.Snapshot.Sha256);
        var error = Assert.Throws<MigrationExecutionException>(() =>
            CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(changed, before));
        Assert.Equal("current_auth_local_archive_invalid", error.Code);
    }

    private static CurrentAuthLocalSessionArchiveObservation Observation(string? fault = null)
    {
        var snapshot = new CurrentAppOwnedDatabaseSnapshot("Auth", [], [], []);
        var tuples = new Dictionary<string, string[]>(StringComparer.Ordinal)
        { ["pg_class"] = [fault == "tuple" ? /*lang=json,strict*/ "{\"oid\":1,\"relpages\":2}" : /*lang=json,strict*/ "{\"oid\":1,\"relpages\":1}"] };
        var storage = new Dictionary<string, (uint FileNode, long Blocks)>(StringComparer.Ordinal)
        { ["1"] = (fault == "file-node" ? 101u : 100u, fault == "blocks" ? 4L : 3L) };
        var expressions = new Dictionary<string, string>(StringComparer.Ordinal)
        { ["1"] = fault == "expression" ? "changed-synthetic-expression" : "synthetic-expression" };
        var native = new CurrentAuthNativeObservation(snapshot, tuples, storage, expressions);
        // Fixed data-only wrapper construction; no environment, issuer, target or permit.
        var constructor = typeof(CurrentAuthLocalSessionArchiveObservation).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null, types: [typeof(string), typeof(CurrentAuthNativeObservation), typeof(CurrentAuthArchiveSession[])], modifiers: null)!;
        return (CurrentAuthLocalSessionArchiveObservation)constructor.Invoke([new string('a', 64), native, Array.Empty<CurrentAuthArchiveSession>()])!;
    }
}
