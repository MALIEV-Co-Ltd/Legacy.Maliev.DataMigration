using System.Text;
using System.Text.Json.Nodes;
using System.Reflection;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineDriftContractTests
{
    [Theory]
    [InlineData(false, "tuple")] [InlineData(true, "tuple")]
    [InlineData(false, "storage")] [InlineData(true, "storage")]
    [InlineData(false, "filenode")] [InlineData(true, "filenode")]
    [InlineData(false, "expression")] [InlineData(true, "expression")]
    public void Applied_and_postguard_checks_reject_auxiliary_only_changes_on_either_side(bool comparison, string kind)
    {
        DateTimeOffset now = new(2031, 1, 1, 0, 1, 0, TimeSpan.Zero);
        var scope = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(now);
        const CurrentAuthArchiveGenuineExecutionCase selected = CurrentAuthArchiveGenuineExecutionCase.SequenceDrift;
        scope = scope with { ComponentSubject = scope.ComponentSubject! with { Seed = scope.ComponentSubject.Seed with { CaseId = CurrentAuthArchiveGenuineExecutionCases.Identity(selected).CaseId } } };
        var before = Snapshot(); var fault = Changed(before, selected);
        var local = Fleet(scope.LocalObservationPolicy, false, before, now.AddSeconds(-40));
        var production = Fleet(scope.ProductionObservationPolicy, true, before, now.AddSeconds(-33));
        scope = scope with { LocalObservationPolicy = Pin(scope.LocalObservationPolicy, local), ProductionObservationPolicy = Pin(scope.ProductionObservationPolicy, production) };
        var localFault = Fleet(scope.LocalObservationPolicy, false, fault, now.AddSeconds(-15));
        var productionFault = Fleet(scope.ProductionObservationPolicy, true, before, now.AddSeconds(-8));
        var mutation = Mutation(selected) with { BeganAtUtc = now.AddSeconds(-25), CommittedAtUtc = now.AddSeconds(-24) };
        var applied = new CurrentAuthArchiveGenuineDriftApplied(selected, local, localFault, production, productionFault, mutation);
        CurrentAuthArchiveGenuineDrift.RequireApplied(scope, applied, now);
        var original = comparison ? productionFault : localFault;
        CurrentAuthArchiveGenuineDrift.RequireUnchanged(original, original);
        var native = original.Auth.Native;
        var tuples = native.CopyTuples(); var storage = native.CopyStorage(); var expressions = native.CopyExpressions();
        switch (kind)
        {
            case "tuple": tuples.Add("synthetic", ["{\"changed\":true}"]); break;
            case "storage": storage["123"] = (456, 8); break;
            case "filenode": storage["123"] = (457, 7); break;
            case "expression": expressions.Add("123", "changed"); break;
            default: throw new InvalidOperationException();
        }
        var changed = original with { Auth = Observation(original.Auth.TargetBindingSha256, new(native.Snapshot, tuples, storage, expressions)) };
        Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RequireUnchanged(original, changed));
        Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RequireApplied(scope,
            comparison ? applied with { ComparisonFault = changed } : applied with { LocalFault = changed }, now));
    }

    private static CurrentAuthRepairScope Pin(CurrentAuthRepairScope policy, CurrentAuthArchiveFleet fleet)
    {
        var hashes = fleet.Databases.ToDictionary(row => row.Database, row => row.Sha256, StringComparer.Ordinal);
        return policy with { BeforeDatabaseSha256 = hashes, GlobalPreservationSha256 = CurrentAuthRepairPermit.FleetSha256(hashes) };
    }
    private static CurrentAuthArchiveFleet Fleet(CurrentAuthRepairScope policy, bool comparison, CurrentAppOwnedDatabaseSnapshot auth, DateTimeOffset began)
    {
        var databases = policy.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal).Select(name => name == "Auth" ? auth : new CurrentAppOwnedDatabaseSnapshot(name, [], [], [])).ToArray();
        IReadOnlyList<ReviewedRepairDatabaseFlag> flags = comparison ? ReviewedProductionRepairInventory.ExportProductionCatalog() :
            databases.Select(row => new ReviewedRepairDatabaseFlag(row.Database, false, true)).Concat([new("template0", true, false), new("template1", true, true)]).ToArray();
        var first = new CurrentAuthArchiveCatalogObservation(policy.RunBindingSha256, policy.TargetObservationSha256, policy.Target.SystemIdentifierSha256, true, flags, began.AddSeconds(-2), began.AddSeconds(-1));
        var catalogs = new CurrentAuthArchiveFleetCatalogs(first, first with { BeganAtUtc = began.AddSeconds(2), EndedAtUtc = began.AddSeconds(3) }, began, began.AddSeconds(1));
        return new(Observation(policy.RunBindingSha256, new(auth, new(StringComparer.Ordinal), new(StringComparer.Ordinal) { ["123"] = (456, 7) }, new(StringComparer.Ordinal))), databases, began, began.AddSeconds(1), catalogs);
    }
    // Data-only wrapper construction; no environment, factory, permit or native evidence is admitted.
    private static CurrentAuthLocalSessionArchiveObservation Observation(string binding, CurrentAuthNativeObservation native)
    {
        ConstructorInfo constructor = typeof(CurrentAuthLocalSessionArchiveObservation).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null, types: [typeof(string), typeof(CurrentAuthNativeObservation), typeof(CurrentAuthArchiveSession[])], modifiers: null)!;
        return (CurrentAuthLocalSessionArchiveObservation)constructor.Invoke([binding, native, Array.Empty<CurrentAuthArchiveSession>()]);
    }
    [Theory]
    [InlineData(8)] [InlineData(9)] [InlineData(10)] [InlineData(11)]
    public void Fixed_mutation_witness_rejects_extra_effects(int number)
    {
        var mutation = Mutation((CurrentAuthArchiveGenuineExecutionCase)number);
        CurrentAuthArchiveGenuineDrift.RequireMutation(mutation);
        Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RequireMutation(mutation with { Affected = 2 }));
        Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RequireMutation(mutation with { StatementSha256 = new string('0', 64) }));
        Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RequireMutation(mutation with { CommittedAtUtc = mutation.BeganAtUtc.AddTicks(-1) }));
        if (mutation.Case == CurrentAuthArchiveGenuineExecutionCase.SequenceDrift)
        {
            Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RequireMutation(mutation with { SequenceAfter = mutation.SequenceBefore + 2 }));
            Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RequireMutation(mutation with { CalledAfter = !mutation.CalledBefore }));
        }
        else
        {
            var changed = JsonNode.Parse(mutation.AfterRow!)!.AsObject(); changed["extra"] = "not-owned";
            Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RequireMutation(mutation with { AfterRow = changed.ToJsonString() }));
            Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RequireMutation(mutation with { AfterRow = mutation.BeforeRow }));
        }
    }

    [Theory]
    [InlineData(8)] [InlineData(9)] [InlineData(10)] [InlineData(11)]
    public void Snapshot_change_is_exactly_one_fixed_operand_with_unchanged_definition_and_counts(int number)
    {
        var value = (CurrentAuthArchiveGenuineExecutionCase)number;
        var before = Snapshot(); var fault = Changed(before, value);
        CurrentAuthArchiveGenuineDrift.RequireControlledChange(value, before, fault);
        Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RequireControlledChange(value, before, before));
        Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RequireControlledChange(value, before,
            fault with { Catalog = [new("pg_class", "different", new string('f', 64), "pg_class", "1")] }));
        Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RequireControlledChange(value, before,
            fault with { Relations = fault.Relations.Select(row => row.Name == "unrelated" ? row with { RowSha256 = new string('f', 64) } : row).ToArray() }));
        Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RequireControlledChange(value, before,
            fault with { Sequences = fault.Sequences.Select(sequence => sequence with { Owner = "unreviewed" }).ToArray() }));
        if (value != CurrentAuthArchiveGenuineExecutionCase.SequenceDrift)
        {
            Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.RequireControlledChange(value, before,
                fault with { Relations = fault.Relations.Select(row => row.RowSha256 != before.Relations.Single(old => old.Schema == row.Schema && old.Name == row.Name).RowSha256
                    ? row with { Rows = row.Rows + 1 } : row).ToArray() }));
        }
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)]
    [InlineData(6)] [InlineData(7)] [InlineData(12)] [InlineData(13)] [InlineData(14)]
    public void Another_case_cannot_select_drift_sql(int number)
    {
        var value = (CurrentAuthArchiveGenuineExecutionCase)number;
        Assert.False(CurrentAuthArchiveGenuineDrift.IsCase(value));
        Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineDrift.MutationSql(value));
    }

    [Theory]
    [InlineData(8, false)] [InlineData(9, false)] [InlineData(10, false)] [InlineData(11, true)]
    public void Only_comparison_case_can_select_the_comparison_fixture(int number, bool comparison) =>
        Assert.Equal(comparison, CurrentAuthArchiveGenuineDrift.Comparison((CurrentAuthArchiveGenuineExecutionCase)number));

    private static CurrentAuthArchiveGenuineDriftMutation Mutation(CurrentAuthArchiveGenuineExecutionCase value)
    {
        DateTimeOffset began = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        string hash = CurrentAuthLocalSessionArchivePolicy.HashBytes(Encoding.UTF8.GetBytes(CurrentAuthArchiveGenuineDrift.MutationSql(value)));
        if (value == CurrentAuthArchiveGenuineExecutionCase.SequenceDrift) { return new(value, hash, 1, null, null, 113, 114, true, true, began, began.AddSeconds(1)); }
        string column = value switch { CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift => "SecurityStamp", CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift => "evidence", _ => "ServiceName" };
        var row = value == CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift
            ? new JsonObject { ["id"] = 1, [column] = "synthetic" }
            : new JsonObject { ["Id"] = value == CurrentAuthArchiveGenuineExecutionCase.ProductionDrift
                ? "00000000-0000-0000-0000-000000000030" : "00000000-0000-0000-0000-000000000001", [column] = "synthetic" };
        string before = row.ToJsonString(); row[column] = "synthetic" + CurrentAuthArchiveGenuineDrift.Marker(value);
        return new(value, hash, 1, before, row.ToJsonString(), null, null, null, null, began, began.AddSeconds(1));
    }
    private static CurrentAppOwnedDatabaseSnapshot Snapshot() => new("Auth", [new("pg_class", "1", new string('a', 64), "pg_class", "1")],
        [new("public", "refresh_sessions", 2, new('a', 64)), new("private", "journal", 2, new('b', 64)),
            new("public", "google_identity_nonces", 1, new('c', 64)), new("private", "unrelated", 1, new('d', 64))],
        [new("private", "allocation", "synthetic_owner", new('e', 64))]);
    private static CurrentAppOwnedDatabaseSnapshot Changed(CurrentAppOwnedDatabaseSnapshot before, CurrentAuthArchiveGenuineExecutionCase value)
    {
        if (value == CurrentAuthArchiveGenuineExecutionCase.SequenceDrift)
        { return before with { Sequences = before.Sequences.Select(row => row with { TupleSha256 = new string('f', 64) }).ToArray() }; }
        string table = value switch { CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift => "refresh_sessions", CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift => "journal", _ => "google_identity_nonces" };
        return before with { Relations = before.Relations.Select(row => row.Name == table ? row with { RowSha256 = new string('f', 64) } : row).ToArray() };
    }
}
