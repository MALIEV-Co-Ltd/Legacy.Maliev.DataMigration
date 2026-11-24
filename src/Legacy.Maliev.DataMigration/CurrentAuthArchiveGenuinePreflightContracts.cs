using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration;

internal enum CurrentAuthArchiveGenuinePreflightCase { HostUnprobedSdk = 1, LocalTrust = 2 }
internal sealed record CurrentAuthArchiveGenuinePreflightRole(uint Oid, string Name, bool Login, bool Superuser,
    bool CreateRole, bool CreateDatabase, bool Replication, bool BypassRls, DateTimeOffset? ValidUntil,
    long Memberships, long DefaultAcls, bool HasPassword, bool Scram, string NativeTupleSha256);
internal sealed record CurrentAuthArchiveGenuinePreflightPolicy(CurrentAppOwnedMaintenancePin OriginalPin,
    string SystemIdentifierSha256, DateTimeOffset Postmaster, DateTimeOffset ConfigLoaded, string HbaPath,
    string HbaText, string RawRules, CurrentAuthArchiveGenuinePreflightRole Operator,
    CurrentAuthArchiveGenuinePreflightRole Ordinary, CurrentAuthArchiveGenuinePreflightRole? Unprobed,
    bool ReadOnly, bool Primary, long OtherClients, long PreparedTransactions, long EventTriggers, DateTimeOffset ObservedAtUtc);
internal sealed record CurrentAuthArchiveGenuinePreflightProbe(string Role, string Transport, bool Connected,
    string? CurrentUser, string? ActualSqlState, long? ActualExitCode, string? Executable,
    string StandardOutput, string StandardError, DateTimeOffset BeganAtUtc, DateTimeOffset EndedAtUtc);
internal sealed record CurrentAuthArchiveGenuinePreflightRejection(string ExceptionType, string ActualCode,
    DateTimeOffset BeganAtUtc, DateTimeOffset RejectedAtUtc, bool TransactionReadOnly);
internal sealed record CurrentAuthArchiveGenuinePreflightMethodResult(int ReturnCode, DateTimeOffset StartedAtUtc,
    DateTimeOffset ReturnedAtUtc, CurrentAuthArchiveGenuineDualArtifacts Artifacts);
internal sealed record CurrentAuthArchiveGenuinePreflightResult(CurrentAuthArchiveGenuinePreflightMethodResult Method,
    CurrentAuthArchiveGenuineArtifact FinalCandidate);

internal static class CurrentAuthArchiveGenuinePreflight
{
    internal const string SemanticCode = "current_app_owned_maintenance_hba_not_exclusive";
    internal static string CaseId(CurrentAuthArchiveGenuinePreflightCase value)
    {
        return value switch
        {
            CurrentAuthArchiveGenuinePreflightCase.HostUnprobedSdk => "host-unprobed-sdk",
            CurrentAuthArchiveGenuinePreflightCase.LocalTrust => "local-trust",
            _ => throw Invalid(),
        };
    }

    internal static void RequireSeed(CurrentAuthArchiveComponentBootstrapSeed seed, CurrentAuthArchivePins pins,
        IReceiptAttestationTrustStore trust, CurrentAuthArchiveGenuinePreflightCase value, DateTimeOffset now)
    {
        _ = CaseId(value);
        CurrentAuthArchiveGenuineExecutionSeed.RequireInitial(seed, pins, trust,
            value == CurrentAuthArchiveGenuinePreflightCase.HostUnprobedSdk ? CurrentAuthArchiveGenuineExecutionCase.HostUnprobedSdk : CurrentAuthArchiveGenuineExecutionCase.LocalTrust, now);
    }
    internal static string UnprobedRole(Guid operation)
    {
        return "archive_unprobed_" + operation.ToString("N");
    }

    internal static string UnsafeHba(CurrentAuthArchiveGenuinePreflightCase value, Guid operation, string original)
    {
        _ = CaseId(value);
        const string rejected = "local all all reject\n";
        return operation == Guid.Empty || original.Split(rejected, StringSplitOptions.None).Length != 2
            ? throw Invalid()
            : original.Replace(rejected, value == CurrentAuthArchiveGenuinePreflightCase.LocalTrust ? "local all all trust\n" :
            "host all " + UnprobedRole(operation) + " 0.0.0.0/0 trust\n" + rejected, StringComparison.Ordinal);
    }
    internal static CurrentAppOwnedMaintenanceHbaRule[] Rules(string raw)
    {
        using var document = JsonDocument.Parse(raw);
        return document.RootElement.EnumerateArray().Select(row => new CurrentAppOwnedMaintenanceHbaRule(row.GetProperty("rule_number").GetInt32(),
            row.GetProperty("type").GetString()!, Strings(row, "database"), Strings(row, "user_name"), Text(row, "address"), Text(row, "netmask"),
            row.GetProperty("auth_method").GetString()!, Strings(row, "options"), Text(row, "error"))).ToArray();
        static string? Text(JsonElement row, string name)
        {
            return row.GetProperty(name).ValueKind == JsonValueKind.Null ? null : row.GetProperty(name).GetString();
        }

        static string[] Strings(JsonElement row, string name)
        {
            return row.GetProperty(name).ValueKind == JsonValueKind.Null ? [] : row.GetProperty(name).EnumerateArray().Select(item => item.GetString()!).ToArray();
        }
    }
    internal static void RequireTransition(CurrentAuthArchiveGenuinePreflightCase value, CurrentAuthArchiveScope scope,
        CurrentAuthArchiveGenuinePreflightPolicy before, CurrentAuthArchiveGenuinePreflightPolicy after,
        CurrentAuthArchiveGenuinePreflightProbe blocked, CurrentAuthArchiveGenuinePreflightProbe allowed,
        CurrentAuthArchiveGenuinePreflightRejection rejection, CurrentAuthArchiveGenuinePreflightRole? created, DateTimeOffset now)
    {
        if (scope.ComponentSubject?.Seed.CaseId != CaseId(value) || scope.ProofAdmission != CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap ||
            before.OriginalPin != scope.LocalObservationPolicy.Maintenance || after.OriginalPin != before.OriginalPin ||
            before.SystemIdentifierSha256 != scope.LocalObservationPolicy.Target.SystemIdentifierSha256 || after.SystemIdentifierSha256 != before.SystemIdentifierSha256 ||
            before.Postmaster != before.OriginalPin.Postmaster || after.Postmaster != before.Postmaster || before.ConfigLoaded != before.OriginalPin.ConfigLoaded ||
            after.ConfigLoaded < before.ConfigLoaded || before.HbaPath != before.OriginalPin.HbaPath || after.HbaPath != before.HbaPath ||
            CurrentAuthLocalSessionArchivePolicy.HashBytes(Encoding.UTF8.GetBytes(before.HbaText)) != before.OriginalPin.HbaSha256 ||
            CurrentAuthLocalSessionArchivePolicy.HashBytes(Encoding.UTF8.GetBytes(before.RawRules)) != before.OriginalPin.HbaRulesSha256 ||
            after.HbaText != UnsafeHba(value, scope.OperationId, before.HbaText) || before.Operator != after.Operator || before.Ordinary != after.Ordinary ||
            !before.ReadOnly || !after.ReadOnly || !before.Primary || !after.Primary || before.OtherClients != 0 || after.OtherClients != 0 ||
            before.PreparedTransactions != 0 || after.PreparedTransactions != 0 || before.EventTriggers != 0 || after.EventTriggers != 0 ||
            !before.Operator.Login || !before.Operator.Superuser || before.Operator.Name != before.OriginalPin.Role ||
            before.Operator.CreateRole || before.Operator.CreateDatabase || before.Operator.Replication || before.Operator.BypassRls ||
            before.Operator.ValidUntil != before.OriginalPin.ExpiresAtUtc || !before.Operator.Scram || before.Operator.Memberships != 0 || before.Operator.DefaultAcls != 0 ||
            !before.Ordinary.Login || before.Ordinary.Superuser || before.Ordinary.CreateRole || before.Ordinary.CreateDatabase || before.Ordinary.Replication || before.Ordinary.BypassRls ||
            !before.Ordinary.HasPassword || !before.Ordinary.Scram || before.Ordinary.Memberships != 0 || before.Ordinary.DefaultAcls != 0 ||
            before.Ordinary.Name != "archive_denied_" + scope.OperationId.ToString("N")) { throw Invalid(); }
        RequireRulesTransition(value, scope.OperationId, before.RawRules, after.RawRules, before.HbaPath);
        CurrentAppOwnedMaintenanceHba.Require(Rules(before.RawRules), before.Operator.Name, DeltaTargetAuthorityKind.LocalAspire);
        bool rejected = false;
        try { CurrentAppOwnedMaintenanceHba.Require(Rules(after.RawRules), after.Operator.Name, DeltaTargetAuthorityKind.LocalAspire); }
        catch (MigrationExecutionException failure) when (failure.Code == SemanticCode) { rejected = true; }
        if (!rejected || rejection.ExceptionType != typeof(MigrationExecutionException).FullName || rejection.ActualCode != SemanticCode || !rejection.TransactionReadOnly ||
            rejection.BeganAtUtc.Offset != TimeSpan.Zero || rejection.RejectedAtUtc.Offset != TimeSpan.Zero || rejection.BeganAtUtc > rejection.RejectedAtUtc || rejection.RejectedAtUtc > now ||
            before.ObservedAtUtc > blocked.BeganAtUtc || blocked.EndedAtUtc > allowed.BeganAtUtc || allowed.EndedAtUtc > after.ObservedAtUtc ||
            after.ObservedAtUtc > rejection.BeganAtUtc || before.ObservedAtUtc.Offset != TimeSpan.Zero || after.ObservedAtUtc.Offset != TimeSpan.Zero ||
            before.ObservedAtUtc > after.ObservedAtUtc || blocked.Connected || blocked.CurrentUser is not null || !allowed.Connected || allowed.CurrentUser != allowed.Role ||
            blocked.Role != allowed.Role || blocked.Transport != allowed.Transport || blocked.BeganAtUtc.Offset != TimeSpan.Zero || blocked.EndedAtUtc.Offset != TimeSpan.Zero ||
            allowed.BeganAtUtc.Offset != TimeSpan.Zero || allowed.EndedAtUtc.Offset != TimeSpan.Zero || blocked.BeganAtUtc > blocked.EndedAtUtc || allowed.BeganAtUtc > allowed.EndedAtUtc) { throw Invalid(); }
        if (value == CurrentAuthArchiveGenuinePreflightCase.HostUnprobedSdk)
        {
            if (before.Unprobed is not null || created is null || after.Unprobed != created || created.Name != UnprobedRole(scope.OperationId) || created.Oid == 0 ||
                !created.Login || created.Superuser || created.CreateRole || created.CreateDatabase || created.Replication || created.BypassRls || created.HasPassword || created.Scram ||
                created.Oid == before.Operator.Oid || created.Oid == before.Ordinary.Oid || !CurrentAuthRepairPermit.HashShape(created.NativeTupleSha256) ||
                created.Memberships != 0 || created.DefaultAcls != 0 || created.ValidUntil is null || created.ValidUntil <= now || created.ValidUntil > scope.ExpiresAtUtc ||
                blocked.Role != created.Name || blocked.Transport != "loopback-tcp" || blocked.ActualSqlState != "28000" || allowed.ActualSqlState is not null ||
                blocked.ActualExitCode is not null || allowed.ActualExitCode is not null) { throw Invalid(); }
        }
        else if (created is not null || before.Unprobed is not null || after.Unprobed is not null || blocked.Role != before.Ordinary.Name || blocked.Transport != "unix-socket" ||
            blocked.ActualExitCode != 2 || allowed.ActualExitCode != 0 || blocked.Executable != "/usr/lib/postgresql/18/bin/psql" || allowed.Executable != blocked.Executable ||
            !blocked.StandardError.Contains("pg_hba.conf rejects connection", StringComparison.Ordinal) || allowed.StandardOutput.Trim() != before.Ordinary.Name)
        { throw Invalid(); }
    }
    private static void RequireRulesTransition(CurrentAuthArchiveGenuinePreflightCase value, Guid operation, string original, string changed, string path)
    {
        var expected = JsonNode.Parse(original)?.AsArray() ?? throw Invalid();
        if (expected.Count != 6 || expected.Select((item, index) => item is not JsonObject row || row["file_name"]?.GetValue<string>() != path ||
            row["line_number"]?.GetValue<int>() != index + 1 || row["rule_number"]?.GetValue<int>() != index + 1).Any(invalid => invalid)) { throw Invalid(); }
        if (value == CurrentAuthArchiveGenuinePreflightCase.LocalTrust)
        { expected[3]!["auth_method"] = "trust"; }
        else
        {
            var inserted = expected[4]!.DeepClone().AsObject(); inserted["rule_number"] = 4; inserted["line_number"] = 4;
            inserted["user_name"] = new JsonArray(UnprobedRole(operation)); inserted["auth_method"] = "trust";
            for (int index = 3; index < expected.Count; index++) { expected[index]!["rule_number"] = index + 2; expected[index]!["line_number"] = index + 2; }
            expected.Insert(3, inserted);
        }
        if (!JsonNode.DeepEquals(expected, JsonNode.Parse(changed))) { throw Invalid(); }
    }
    internal static void RequireDataPreserved(IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> before,
        IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> after, CurrentAuthArchiveGenuinePreflightRole? addedRole)
    {
        if (!before.Select(item => item.Database).SequenceEqual(after.Select(item => item.Database), StringComparer.Ordinal) || before.Count != after.Count ||
            before.Select(item => item.Database).Distinct(StringComparer.Ordinal).Count() != before.Count) { throw Invalid(); }
        foreach (var left in before)
        {
            var right = after.Single(item => item.Database == left.Database);
            if (!left.Relations.SequenceEqual(right.Relations) || !left.Sequences.SequenceEqual(right.Sequences)) { throw Invalid(); }
            var inserted = right.Catalog.Where(item => addedRole is not null && item.Catalog == "pg_authid" && item.ObjectId == addedRole.Oid.ToString(System.Globalization.CultureInfo.InvariantCulture)).ToArray();
            if ((addedRole is null ? inserted.Length != 0 : inserted.Length != 1 || inserted[0].Sha256 != addedRole.NativeTupleSha256 ||
                inserted[0].Key != inserted[0].ObjectId || inserted[0].ObjectClass != "1260") ||
                !left.Catalog.SequenceEqual(right.Catalog.Where(item => !inserted.Contains(item)))) { throw Invalid(); }
        }
    }
    internal static MigrationExecutionException Invalid()
    {
        return new("current_auth_archive_genuine_preflight_invalid", "The fixed owned policy-preflight evidence is incomplete, changed or unavailable.");
    }
}
