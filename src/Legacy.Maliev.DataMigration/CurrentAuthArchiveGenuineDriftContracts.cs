using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAuthArchiveGenuineDriftMutation(CurrentAuthArchiveGenuineExecutionCase Case,
    string StatementSha256, int Affected, string? BeforeRow, string? AfterRow,
    long? SequenceBefore, long? SequenceAfter, bool? CalledBefore, bool? CalledAfter,
    DateTimeOffset BeganAtUtc, DateTimeOffset CommittedAtUtc);
internal sealed record CurrentAuthArchiveGenuineDriftApplied(CurrentAuthArchiveGenuineExecutionCase Case,
    CurrentAuthArchiveFleet LocalBefore, CurrentAuthArchiveFleet LocalFault,
    CurrentAuthArchiveFleet ComparisonBefore, CurrentAuthArchiveFleet ComparisonFault,
    CurrentAuthArchiveGenuineDriftMutation Mutation);
internal sealed record CurrentAuthArchiveGenuineDriftFailure(CurrentAuthArchiveGenuineExecutionCase Case,
    CurrentAuthArchiveGenuineHelperClaims Claims, CurrentAuthArchiveGenuineDriftApplied Applied,
    string ActualExceptionType, string ActualCode, int ActualHResult, DateTimeOffset BeganAtUtc, DateTimeOffset FailedAtUtc);

internal static class CurrentAuthArchiveGenuineDrift
{
    internal static bool IsCase(CurrentAuthArchiveGenuineExecutionCase value)
    {
        return value is CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift or
        CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift or CurrentAuthArchiveGenuineExecutionCase.SequenceDrift or CurrentAuthArchiveGenuineExecutionCase.ProductionDrift;
    }

    internal static bool Comparison(CurrentAuthArchiveGenuineExecutionCase value)
    {
        return value == CurrentAuthArchiveGenuineExecutionCase.ProductionDrift;
    }

    internal static string Marker(CurrentAuthArchiveGenuineExecutionCase value)
    {
        return value switch
        {
            CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift => ":genuine-cas-drift-v1",
            CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift => ":genuine-journal-drift-v1",
            CurrentAuthArchiveGenuineExecutionCase.ProductionDrift => ":genuine-comparison-drift-v1",
            CurrentAuthArchiveGenuineExecutionCase.NativeComplete => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.PreparedPublication => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.TerminalPublication => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.HostUnprobedSdk => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.LocalTrust => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.ExactReviewedDelete => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.SequenceDrift => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.FirstOnlyDecryptInsertReadback => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.SecondOnlyDecryptInsertReadback => throw Invalid(),
            _ => throw Invalid(),
        };
    }

    internal static string RowSql(CurrentAuthArchiveGenuineExecutionCase value)
    {
        return value switch
        {
            CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift => "SELECT to_jsonb(x)::text FROM public.refresh_sessions x ORDER BY \"Id\" LIMIT 1;",
            CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift => "SELECT to_jsonb(x)::text FROM private.journal x WHERE id=1;",
            CurrentAuthArchiveGenuineExecutionCase.ProductionDrift => "SELECT to_jsonb(x)::text FROM public.google_identity_nonces x ORDER BY \"Id\" LIMIT 1;",
            CurrentAuthArchiveGenuineExecutionCase.NativeComplete => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.PreparedPublication => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.TerminalPublication => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.HostUnprobedSdk => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.LocalTrust => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.ExactReviewedDelete => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.SequenceDrift => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.FirstOnlyDecryptInsertReadback => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.SecondOnlyDecryptInsertReadback => throw Invalid(),
            _ => throw Invalid(),
        };
    }

    internal static string MutationSql(CurrentAuthArchiveGenuineExecutionCase value)
    {
        return value switch
        {
            CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift => "UPDATE public.refresh_sessions SET \"SecurityStamp\"=coalesce(\"SecurityStamp\",'')||':genuine-cas-drift-v1' WHERE \"Id\"=(SELECT \"Id\" FROM public.refresh_sessions ORDER BY \"Id\" LIMIT 1);",
            CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift => "UPDATE private.journal SET evidence=evidence||':genuine-journal-drift-v1' WHERE id=1;",
            CurrentAuthArchiveGenuineExecutionCase.SequenceDrift => "SELECT setval('private.allocation'::regclass,last_value+1,is_called) FROM private.allocation;",
            CurrentAuthArchiveGenuineExecutionCase.ProductionDrift => "UPDATE public.google_identity_nonces SET \"ServiceName\"=\"ServiceName\"||':genuine-comparison-drift-v1' WHERE \"Id\"=(SELECT \"Id\" FROM public.google_identity_nonces ORDER BY \"Id\" LIMIT 1);",
            CurrentAuthArchiveGenuineExecutionCase.NativeComplete => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.PreparedPublication => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.TerminalPublication => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.HostUnprobedSdk => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.LocalTrust => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.ExactReviewedDelete => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.FirstOnlyDecryptInsertReadback => throw Invalid(),
            CurrentAuthArchiveGenuineExecutionCase.SecondOnlyDecryptInsertReadback => throw Invalid(),
            _ => throw Invalid(),
        };
    }

    internal static void RequireMutation(CurrentAuthArchiveGenuineDriftMutation mutation)
    {
        if (!IsCase(mutation.Case) || mutation.Affected != 1 || mutation.StatementSha256 != CurrentAuthLocalSessionArchivePolicy.HashBytes(Encoding.UTF8.GetBytes(MutationSql(mutation.Case))) ||
            mutation.BeganAtUtc.Offset != TimeSpan.Zero || mutation.CommittedAtUtc.Offset != TimeSpan.Zero || mutation.CommittedAtUtc < mutation.BeganAtUtc) { throw Invalid(); }
        if (mutation.Case == CurrentAuthArchiveGenuineExecutionCase.SequenceDrift)
        {
            if (mutation.BeforeRow is not null || mutation.AfterRow is not null || mutation.SequenceBefore is null or long.MaxValue ||
                mutation.SequenceAfter != mutation.SequenceBefore + 1 || mutation.CalledBefore is null || mutation.CalledAfter != mutation.CalledBefore) { throw Invalid(); }
            return;
        }
        if (mutation.SequenceBefore is not null || mutation.SequenceAfter is not null || mutation.CalledBefore is not null || mutation.CalledAfter is not null ||
            mutation.BeforeRow is null || mutation.AfterRow is null) { throw Invalid(); }
        JsonObject before = JsonNode.Parse(mutation.BeforeRow)?.AsObject() ?? throw Invalid(), after = JsonNode.Parse(mutation.AfterRow)?.AsObject() ?? throw Invalid();
        string column = mutation.Case switch { CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift => "SecurityStamp", CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift => "evidence", CurrentAuthArchiveGenuineExecutionCase.NativeComplete => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.PreparedPublication => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.TerminalPublication => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.HostUnprobedSdk => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.LocalTrust => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.ExactReviewedDelete => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.SequenceDrift => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.ProductionDrift => "ServiceName", CurrentAuthArchiveGenuineExecutionCase.FirstOnlyDecryptInsertReadback => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.SecondOnlyDecryptInsertReadback => throw Invalid(), _ => throw Invalid() };
        if (!before.ContainsKey(column) || !after.ContainsKey(column) || after[column]?.GetValue<string>() != (before[column]?.GetValue<string>() ?? "") + Marker(mutation.Case)) { throw Invalid(); }
        _ = before.Remove(column); _ = after.Remove(column);
        if (!JsonNode.DeepEquals(before, after) || (mutation.Case == CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift && before["id"]?.GetValue<int>() != 1)) { throw Invalid(); }
    }

    internal static void RequireControlledChange(CurrentAuthArchiveGenuineExecutionCase value, CurrentAppOwnedDatabaseSnapshot before, CurrentAppOwnedDatabaseSnapshot fault)
    {
        if (!IsCase(value) || before.Database != "Auth" || fault.Database != "Auth" || before.Sha256 == fault.Sha256 || !before.Catalog.SequenceEqual(fault.Catalog) ||
            before.Relations.Count != fault.Relations.Count || before.Sequences.Count != fault.Sequences.Count) { throw Invalid(); }
        if (value == CurrentAuthArchiveGenuineExecutionCase.SequenceDrift)
        {
            if (!before.Relations.SequenceEqual(fault.Relations) || before.Sequences.Zip(fault.Sequences).Count(pair => pair.First != pair.Second) != 1 ||
                before.Sequences.Zip(fault.Sequences).Any(pair => pair.First != pair.Second && (pair.First.Schema != "private" || pair.First.Name != "allocation" ||
                    pair.First.Schema != pair.Second.Schema || pair.First.Name != pair.Second.Name || pair.First.Owner != pair.Second.Owner))) { throw Invalid(); }
            return;
        }
        string schema = value == CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift ? "private" : "public";
        string table = value switch { CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift => "refresh_sessions", CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift => "journal", CurrentAuthArchiveGenuineExecutionCase.NativeComplete => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.PreparedPublication => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.TerminalPublication => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.HostUnprobedSdk => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.LocalTrust => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.ExactReviewedDelete => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.SequenceDrift => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.ProductionDrift => "google_identity_nonces", CurrentAuthArchiveGenuineExecutionCase.FirstOnlyDecryptInsertReadback => throw Invalid(), CurrentAuthArchiveGenuineExecutionCase.SecondOnlyDecryptInsertReadback => throw Invalid(), _ => throw Invalid() };
        if (!before.Sequences.SequenceEqual(fault.Sequences) || before.Relations.Zip(fault.Relations).Count(pair => pair.First != pair.Second) != 1 ||
            before.Relations.Zip(fault.Relations).Any(pair => pair.First != pair.Second && (pair.First.Schema != schema || pair.First.Name != table ||
                pair.First.Schema != pair.Second.Schema || pair.First.Name != pair.Second.Name || pair.First.Rows != pair.Second.Rows))) { throw Invalid(); }
    }

    internal static void RequireApplied(CurrentAuthArchiveScope scope, CurrentAuthArchiveGenuineDriftApplied applied, DateTimeOffset now)
    {
        if (!IsCase(applied.Case) || applied.Mutation.Case != applied.Case || scope.ComponentSubject?.Seed.CaseId != CurrentAuthArchiveGenuineExecutionCases.Identity(applied.Case).CaseId) { throw Invalid(); }
        RequireMutation(applied.Mutation);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(applied.LocalBefore, scope.LocalObservationPolicy, now);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(applied.ComparisonBefore, scope.ProductionObservationPolicy, now, comparison: true);
        RequireWindows(applied.LocalFault, scope.LocalObservationPolicy, false, now); RequireWindows(applied.ComparisonFault, scope.ProductionObservationPolicy, true, now);
        RequireFleetChange(applied.LocalBefore, applied.LocalFault, !Comparison(applied.Case));
        RequireFleetChange(applied.ComparisonBefore, applied.ComparisonFault, Comparison(applied.Case));
        var before = Comparison(applied.Case) ? applied.ComparisonBefore : applied.LocalBefore;
        var fault = Comparison(applied.Case) ? applied.ComparisonFault : applied.LocalFault;
        var untouchedBefore = Comparison(applied.Case) ? applied.LocalBefore : applied.ComparisonBefore;
        var untouchedFault = Comparison(applied.Case) ? applied.LocalFault : applied.ComparisonFault;
        CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(untouchedFault.Auth, untouchedBefore.Auth);
        RequireControlledChange(applied.Case, before.Auth.Native.Snapshot, fault.Auth.Native.Snapshot);
        if (applied.Case == CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift)
        {
            var selected = before.Auth.Sessions.OrderBy(row => row.Id).FirstOrDefault() ?? throw Invalid();
            if (before.Auth.Sessions.Count != fault.Auth.Sessions.Count || before.Auth.Sessions.Zip(fault.Auth.Sessions).Any(pair =>
                pair.Second != (pair.First.Id == selected.Id ? pair.First with { SecurityStamp = (pair.First.SecurityStamp ?? string.Empty) + Marker(applied.Case) } : pair.First)) ||
                JsonNode.Parse(applied.Mutation.BeforeRow!)?["Id"]?.GetValue<Guid>() != selected.Id) { throw Invalid(); }
        }
        else { CurrentAuthLocalSessionArchivePolicy.RequireRows(before.Auth.Sessions, fault.Auth.Sessions); }
        if (applied.LocalBefore.EndedAtUtc > applied.Mutation.BeganAtUtc || applied.ComparisonBefore.EndedAtUtc > applied.Mutation.BeganAtUtc ||
            applied.Mutation.CommittedAtUtc > applied.LocalFault.BeganAtUtc || applied.Mutation.CommittedAtUtc > applied.ComparisonFault.BeganAtUtc || applied.ComparisonFault.EndedAtUtc > now || applied.LocalFault.EndedAtUtc > now) { throw Invalid(); }
        RequireNativeAuxiliary(before.Auth.Native, fault.Auth.Native);
    }

    internal static void RequireUnchanged(CurrentAuthArchiveFleet fault, CurrentAuthArchiveFleet after)
    {
        RequireFleetChange(fault, after, false);
        CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(after.Auth, fault.Auth);
    }
    internal static void RequireWindows(CurrentAuthArchiveFleet fleet, CurrentAuthRepairScope policy, bool comparison, DateTimeOffset now)
    {
        CurrentAuthLocalSessionArchivePolicy.RequireCatalogs(fleet.Catalogs, policy, comparison, fleet.Databases.Select(database => database.Database), now.AddMinutes(-5), now);
        if (fleet.BeganAtUtc.Offset != TimeSpan.Zero || fleet.EndedAtUtc.Offset != TimeSpan.Zero || fleet.BeganAtUtc > fleet.EndedAtUtc ||
            fleet.EndedAtUtc > now || now - fleet.BeganAtUtc > TimeSpan.FromMinutes(5) ||
            fleet.Catalogs!.CaptureBeganAtUtc != fleet.BeganAtUtc || fleet.Catalogs.CaptureEndedAtUtc != fleet.EndedAtUtc ||
            fleet.Auth.TargetBindingSha256 != policy.RunBindingSha256 || fleet.Auth.Native.Snapshot.Database != "Auth" ||
            fleet.Databases.Count != policy.BeforeDatabaseSha256.Count || fleet.Databases.Select(database => database.Database).Distinct(StringComparer.Ordinal).Count() != fleet.Databases.Count) { throw Invalid(); }
    }
    private static void RequireFleetChange(CurrentAuthArchiveFleet before, CurrentAuthArchiveFleet after, bool authChanged)
    {
        if (!before.Databases.Select(database => database.Database).SequenceEqual(after.Databases.Select(database => database.Database)) ||
            before.Databases.Select(database => database.Database).Distinct(StringComparer.Ordinal).Count() != before.Databases.Count ||
            before.Databases.Any(database => (!authChanged || database.Database != "Auth") && database.Sha256 != after.Databases.Single(item => item.Database == database.Database).Sha256) ||
            before.Auth.Native.Snapshot.Sha256 != before.Databases.Single(database => database.Database == "Auth").Sha256 ||
            after.Auth.Native.Snapshot.Sha256 != after.Databases.Single(database => database.Database == "Auth").Sha256) { throw Invalid(); }
    }
    private static void RequireNativeAuxiliary(CurrentAuthNativeObservation before, CurrentAuthNativeObservation after)
    {
        if (JsonSerializer.Serialize(before.CopyTuples().OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, Values = pair.Value.Order(StringComparer.Ordinal) })) !=
            JsonSerializer.Serialize(after.CopyTuples().OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, Values = pair.Value.Order(StringComparer.Ordinal) })) ||
            JsonSerializer.Serialize(before.CopyStorage().OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, pair.Value.FileNode, pair.Value.Blocks })) !=
            JsonSerializer.Serialize(after.CopyStorage().OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, pair.Value.FileNode, pair.Value.Blocks })) ||
            JsonSerializer.Serialize(before.CopyExpressions().OrderBy(pair => pair.Key, StringComparer.Ordinal)) != JsonSerializer.Serialize(after.CopyExpressions().OrderBy(pair => pair.Key, StringComparer.Ordinal))) { throw Invalid(); }
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveGenuineExecutionCases.Invalid();
    }
}
