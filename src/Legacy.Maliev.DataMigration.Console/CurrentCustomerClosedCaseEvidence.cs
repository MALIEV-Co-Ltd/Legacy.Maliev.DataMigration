using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static class CurrentCustomerClosedCaseEvidence
{
    internal static void Require(CurrentAppOwnedRepairCustody files, CustomerClosedCase actual,
        CurrentCustomerSequenceRepairScope scope, Func<string, string> resolve, IReadOnlyList<CustomerDefinitionArtifact> artifacts)
    {
        string root = Path.GetDirectoryName(artifacts.Single(x => Path.GetFileName(x.SourcePath) == "closed-scope.json").SourcePath)!;
        byte[] Read(string original, int cap = 65536)
        {
            return files.Read(resolve(original), sharedReader: true, maximumBytes: cap);
        }

        var evidence = CustomerClosedCompletedReadback.Decode<CustomerClosedPolicy>(Read(Path.Combine(root, "closed-installed-policy.json")));
        var p = evidence.Native; var m = scope.Maintenance;
        if (p.SystemIdentifierSha256 != scope.Target.SystemIdentifierSha256 || p.Postmaster != m.Postmaster || p.ConfigLoaded != m.ConfigLoaded ||
            p.Role != m.Role || p.RoleExpiresAtUtc != m.ExpiresAtUtc || p.RoleComment != m.RoleComment || p.HbaPath != m.HbaPath ||
            p.HbaFile.Sha256 != m.HbaSha256 || p.RawHbaRules.Sha256 != m.HbaRulesSha256 || !p.Superuser || !p.Login || p.CreateRole || p.CreateDatabase ||
            p.Replication || p.BypassRls || p.Memberships != 0 || !p.Scram || p.DefaultAcls != 0 || p.OtherClients != 0 || p.PreparedTransactions != 0 ||
            p.EventTriggers != 0 || !p.Primary || p.ObservedAtUtc.Offset != TimeSpan.Zero || p.ObservedAtUtc >= m.ExpiresAtUtc ||
            evidence.CompletedAtUtc < p.ObservedAtUtc || evidence.CompletedAtUtc > actual.BeganAtUtc ||
            !evidence.RejectedOrdinaryDatabases.Order(StringComparer.Ordinal).SequenceEqual(scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal)))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        byte[] hba = Read(p.HbaFile.Path), rules = Read(p.RawHbaRules.Path, 2 * 1024 * 1024);
        if (CurrentCustomerSequenceRepairPermit.Hash(hba) != p.HbaFile.Sha256 || CurrentCustomerSequenceRepairPermit.Hash(rules) != p.RawHbaRules.Sha256)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        bool semantic = true;
        try { CurrentAppOwnedMaintenanceHba.Require(CurrentCustomerClosedPolicyEvidence.ParseRules(rules), m.Role, scope.Target.Kind); }
        catch (MigrationExecutionException e) when (e.Code == "current_app_owned_maintenance_hba_not_exclusive") { semantic = false; }
        bool early = actual.CaseId is "host-unprobed-sdk" or "local-ordinary-trust";
        if (semantic != evidence.SemanticPolicyAccepted || semantic == early || evidence.SdkHostAllowed != (actual.CaseId == "host-unprobed-sdk"))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        string[] operations = artifacts.Where(x => (Path.GetFileName(x.SourcePath) ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).StartsWith(scope.OperationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase)).Select(x => x.SourcePath!).ToArray();
        if (early && operations.Length != 0) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var controls = artifacts.Where(x => x.SourcePath!.EndsWith("-persistent-control-rejected.json", StringComparison.Ordinal)).ToArray();
        if (controls.Length != 1) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        using var control = JsonDocument.Parse(Read(controls[0].SourcePath!)); var c = control.RootElement;
        if (c.GetProperty("operation").GetGuid() != scope.OperationId || c.GetProperty("exit").GetInt32() != 1 ||
            !c.GetProperty("typedAdmissionRejected").GetBoolean() || c.GetProperty("observedAtUtc").GetDateTimeOffset() > actual.BeganAtUtc)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var rejectedScope = CustomerClosedCompletedReadback.Decode<CurrentCustomerSequenceRepairScope>(Read(c.GetProperty("scopePath").GetString()!));
        if (rejectedScope.ProofAdmission != CurrentCustomerSequenceProofAdmission.DisposableClosedConsoleBootstrap ||
            !rejectedScope.Target.AuthorityId.StartsWith("aspire://legacy-postgres-main-local/persistent-", StringComparison.Ordinal))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        bool rejected = false;
        try { CurrentCustomerSequenceRepairPermit.RequireProofAdmission(rejectedScope); }
        catch (MigrationExecutionException) { rejected = true; }
        if (!rejected) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var proxy = artifacts.Where(x => (Path.GetFileName(x.SourcePath) ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).StartsWith("customer-closed-" + scope.OperationId.ToString("N") + "-", StringComparison.Ordinal) &&
            (x.SourcePath!.EndsWith("-proxy-started.json", StringComparison.Ordinal) || x.SourcePath.EndsWith("-proxy-armed.json", StringComparison.Ordinal) ||
                x.SourcePath.EndsWith("-actual-commit-ack-dropped.json", StringComparison.Ordinal) || x.SourcePath.EndsWith("-proxy-disposed.json", StringComparison.Ordinal))).ToArray();
        if (actual.CaseId != "lost-commit-ack") { if (proxy.Length != 0) { throw CurrentCustomerSequenceRepairPermit.Invalid(); } return; }
        if (proxy.Length != 4) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        JsonElement Frame(string suffix)
        { using var doc = JsonDocument.Parse(Read(proxy.Single(x => x.SourcePath!.EndsWith(suffix, StringComparison.Ordinal)).SourcePath!)); return doc.RootElement.Clone(); }
        var started = Frame("-proxy-started.json"); var armed = Frame("-proxy-armed.json"); var dropped = Frame("-actual-commit-ack-dropped.json"); var disposed = Frame("-proxy-disposed.json");
        int port = started.GetProperty("Port").GetInt32(); DateTimeOffset armedAt = armed.GetProperty("ObservedAtUtc").GetDateTimeOffset(), droppedAt = dropped.GetProperty("ObservedAtUtc").GetDateTimeOffset();
        if (port is < 1 or > 65535 || armed.GetProperty("Port").GetInt32() != port || armed.GetProperty("OperationId").GetGuid() != scope.OperationId ||
            dropped.GetProperty("Count").GetInt32() != 1 || dropped.GetProperty("PayloadSha256").GetString() != CurrentCustomerSequenceRepairPermit.Hash("COMMIT\0"u8.ToArray()) ||
            armedAt < actual.Commands[3].BeganAtUtc || droppedAt < armedAt || droppedAt > actual.Commands[3].CompletedAtUtc ||
            disposed.GetProperty("Port").GetInt32() != port || !disposed.GetProperty("WorkerCompleted").GetBoolean() || !disposed.GetProperty("ListenerAbsent").GetBoolean() ||
            disposed.GetProperty("DroppedCommits").GetInt32() != 1 || disposed.GetProperty("CompletedAtUtc").GetDateTimeOffset() < droppedAt ||
            disposed.GetProperty("CompletedAtUtc").GetDateTimeOffset() > actual.CompletedAtUtc)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
}
