using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuinePreflightContractTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("case")]
    [InlineData("family")]
    [InlineData("boundary")]
    [InlineData("published")]
    [InlineData("complete")]
    [InlineData("os-exit")]
    [InlineData("return")]
    [InlineData("clock")]
    public void Candidate_method_record_cannot_claim_execution_full_proof_or_an_OS_exit(string fault)
    {
        DateTimeOffset began = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero), ended = began.AddSeconds(1);
        var method = new CurrentAuthArchiveGenuinePreflightMethodResult(1, began, ended.AddSeconds(1), new(new("stage", new('a', 64)), began, ended));
        var stage = JsonSerializer.SerializeToNode(new
        {
            Kind = "current-auth-genuine-preflight-incomplete-precleanup-v1",
            Phase = "native",
            CaseId = "local-trust",
            ActualBoundary = "before-issuer-mint",
            CleanupVerified = false,
            PhaseProofComplete = false,
            ProviderExitCode = (int?)null,
            BeganAtUtc = began,
            EndedAtUtc = ended,
        })!.AsObject();
        switch (fault)
        {
            case "none": break;
            case "case": stage["CaseId"] = "host-unprobed-sdk"; break;
            case "family": stage["Kind"] = "current-auth-genuine-execution-incomplete-precleanup-v1"; break;
            case "boundary": stage["ActualBoundary"] = "after-reservation"; break;
            case "published": stage["CleanupVerified"] = true; break;
            case "complete": stage["PhaseProofComplete"] = true; break;
            case "os-exit": stage["ProviderExitCode"] = 1; break;
            case "return": method = method with { ReturnCode = 0 }; break;
            case "clock": method = method with { ReturnedAtUtc = began }; break;
            default: throw new InvalidOperationException();
        }
        var json = JsonSerializer.SerializeToElement(stage);
        if (fault == "none") { CurrentAuthArchiveGenuinePreflightRunner.RequireMethod(json, CurrentAuthArchiveGenuinePreflightCase.LocalTrust, method, ended.AddSeconds(2)); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePreflightRunner.RequireMethod(json, CurrentAuthArchiveGenuinePreflightCase.LocalTrust, method, ended.AddSeconds(2))); }
    }

    [Theory]
    [InlineData(1, "none")]
    [InlineData(2, "none")]
    [InlineData(1, "ordinary-nologin")]
    [InlineData(2, "ordinary-nologin")]
    [InlineData(1, "pin-restamp")]
    [InlineData(2, "pin-restamp")]
    [InlineData(1, "other-hba-change")]
    [InlineData(2, "other-hba-change")]
    [InlineData(1, "raw-rule-change")]
    [InlineData(2, "raw-rule-change")]
    [InlineData(1, "synthetic-exception")]
    [InlineData(2, "synthetic-exception")]
    [InlineData(1, "writable-observer")]
    [InlineData(2, "writable-observer")]
    [InlineData(1, "probe-not-blocked")]
    [InlineData(2, "probe-not-blocked")]
    [InlineData(1, "wrong-case")]
    [InlineData(2, "wrong-case")]
    [InlineData(1, "extra-role-privilege")]
    [InlineData(2, "extra-role-privilege")]
    public void Fixed_transition_requires_original_pins_actual_baseline_probe_and_policy_rejection(int number, string fault)
    {
        var value = Fixture((CurrentAuthArchiveGenuinePreflightCase)number);
        var scope = value.Scope; var before = value.Before; var after = value.After; var blocked = value.Blocked;
        var created = value.Created; var rejection = value.Rejection;
        switch (fault)
        {
            case "none": break;
            case "ordinary-nologin": before = before with { Ordinary = before.Ordinary with { Login = false } }; after = after with { Ordinary = before.Ordinary }; break;
            case "pin-restamp": after = after with { OriginalPin = after.OriginalPin with { HbaSha256 = Hash(after.HbaText) } }; break;
            case "other-hba-change": after = after with { HbaText = after.HbaText + "# extra\n" }; break;
            case "raw-rule-change":
                var rules = System.Text.Json.Nodes.JsonNode.Parse(after.RawRules)!.AsArray(); rules[0]!["auth_method"] = "trust";
                after = after with { RawRules = rules.ToJsonString() }; break;
            case "synthetic-exception": rejection = rejection with { ActualCode = "unrelated" }; break;
            case "writable-observer": rejection = rejection with { TransactionReadOnly = false }; break;
            case "probe-not-blocked": blocked = blocked with { Connected = true }; break;
            case "wrong-case": scope = scope with { ComponentSubject = scope.ComponentSubject! with { Seed = scope.ComponentSubject.Seed with { CaseId = "complete" } } }; break;
            case "extra-role-privilege":
                if (created is not null) { created = created with { CreateRole = true }; after = after with { Unprobed = created }; }
                else { after = after with { Ordinary = after.Ordinary with { Superuser = true } }; }
                break;
            default: throw new InvalidOperationException();
        }
        if (fault == "none") { CurrentAuthArchiveGenuinePreflight.RequireTransition(value.Case, scope, before, after, blocked, value.Allowed, rejection, created, value.Now); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePreflight.RequireTransition(value.Case, scope, before, after, blocked, value.Allowed, rejection, created, value.Now)); }
    }

    [Fact]
    public void Fleet_preservation_allows_only_exact_new_role_tuple_and_never_data_or_definition_changes()
    {
        var role = Fixture(CurrentAuthArchiveGenuinePreflightCase.HostUnprobedSdk).Created!;
        var before = new CurrentAppOwnedDatabaseSnapshot("Auth", [new("pg_class", "1", new('a', 64), "1259", "1")],
            [new("private", "journal", 2, new('b', 64))], [new("private", "allocation", "owner", new('c', 64))]);
        string oid = role.Oid.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var roleFact = new CurrentAppOwnedCatalogFact("pg_authid", oid, role.NativeTupleSha256, "1260", oid);
        var after = before with { Catalog = before.Catalog.Concat([roleFact]).ToArray() };
        CurrentAuthArchiveGenuinePreflight.RequireDataPreserved([before], [after], role);
        CurrentAuthArchiveGenuinePreflight.RequireDataPreserved([before], [before], null);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePreflight.RequireDataPreserved([before], [after], null));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePreflight.RequireDataPreserved([before], [after with { Catalog = before.Catalog.Concat([roleFact with { Sha256 = new('f', 64) }]).ToArray() }], role));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePreflight.RequireDataPreserved([before], [after with { Catalog = after.Catalog.Concat([roleFact]).ToArray() }], role));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePreflight.RequireDataPreserved([before], [after with { Catalog = after.Catalog.Concat([before.Catalog[0]]).ToArray() }], role));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePreflight.RequireDataPreserved([before], [after with { Catalog = before.Catalog.Concat([roleFact with { ObjectClass = "1259" }]).ToArray() }], role));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePreflight.RequireDataPreserved([before], [after with { Relations = [before.Relations[0] with { Rows = 3 }] }], role));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePreflight.RequireDataPreserved([before], [after with { Sequences = [before.Sequences[0] with { TupleSha256 = new('f', 64) }] }], role));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(6)]
    public async Task Unknown_case_stops_before_input_access(int value)
    {
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePreflightRunner.ExecuteAsync("not-an-input", (CurrentAuthArchiveGenuinePreflightCase)value, CancellationToken.None));
    }

    private sealed record Transition(CurrentAuthArchiveGenuinePreflightCase Case, CurrentAuthArchiveScope Scope,
        CurrentAuthArchiveGenuinePreflightPolicy Before, CurrentAuthArchiveGenuinePreflightPolicy After,
        CurrentAuthArchiveGenuinePreflightProbe Blocked, CurrentAuthArchiveGenuinePreflightProbe Allowed,
        CurrentAuthArchiveGenuinePreflightRejection Rejection, CurrentAuthArchiveGenuinePreflightRole? Created, DateTimeOffset Now);

    private static Transition Fixture(CurrentAuthArchiveGenuinePreflightCase selected)
    {
        DateTimeOffset now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var scope = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(now);
        string op = "archive_policy_" + scope.OperationId.ToString("N"), ordinary = "archive_denied_" + scope.OperationId.ToString("N");
        string hba = "local all " + op + " scram-sha-256\nhost all " + op + " 0.0.0.0/0 scram-sha-256\nhost all " + op + " ::/0 scram-sha-256\nlocal all all reject\nhost all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n";
        string rules = Raw(hba); var pin = scope.LocalObservationPolicy.Maintenance with
        { Role = op, HbaPath = "/var/lib/postgresql/18/docker/pg_hba.conf", HbaSha256 = Hash(hba), HbaRulesSha256 = Hash(rules), Postmaster = now.AddMinutes(-1), ConfigLoaded = now.AddSeconds(-20), ExpiresAtUtc = now.AddMinutes(1) };
        scope = scope with { ExpiresAtUtc = now.AddMinutes(1), LocalObservationPolicy = scope.LocalObservationPolicy with { Maintenance = pin }, ComponentSubject = scope.ComponentSubject! with { Seed = scope.ComponentSubject.Seed with { CaseId = CurrentAuthArchiveGenuinePreflight.CaseId(selected) } } };
        var actor = new CurrentAuthArchiveGenuinePreflightRole(100, op, true, true, false, false, false, false, pin.ExpiresAtUtc, 0, 0, true, true, new('a', 64));
        var denied = actor with { Oid = 101, Name = ordinary, Superuser = false, ValidUntil = null };
        var before = new CurrentAuthArchiveGenuinePreflightPolicy(pin, scope.LocalObservationPolicy.Target.SystemIdentifierSha256, pin.Postmaster, pin.ConfigLoaded,
            pin.HbaPath, hba, rules, actor, denied, null, true, true, 0, 0, 0, now.AddSeconds(-10));
        CurrentAuthArchiveGenuinePreflightRole? created = selected == CurrentAuthArchiveGenuinePreflightCase.HostUnprobedSdk ?
            new(102, CurrentAuthArchiveGenuinePreflight.UnprobedRole(scope.OperationId), true, false, false, false, false, false, now.AddSeconds(30), 0, 0, false, false, new('c', 64)) : null;
        string changed = CurrentAuthArchiveGenuinePreflight.UnsafeHba(selected, scope.OperationId, hba);
        var after = before with { HbaText = changed, RawRules = Raw(changed), ConfigLoaded = now.AddSeconds(-7), Unprobed = created, ObservedAtUtc = now.AddSeconds(-3) };
        bool host = created is not null;
        var blocked = new CurrentAuthArchiveGenuinePreflightProbe(host ? created!.Name : ordinary, host ? "loopback-tcp" : "unix-socket", false, null,
            host ? "28000" : null, host ? null : 2, host ? null : "/usr/lib/postgresql/18/bin/psql", "", host ? "" : "pg_hba.conf rejects connection", now.AddSeconds(-9), now.AddSeconds(-8));
        var allowed = blocked with { Connected = true, CurrentUser = blocked.Role, ActualSqlState = null, ActualExitCode = host ? null : 0, StandardOutput = host ? "" : ordinary + "\n", StandardError = "", BeganAtUtc = now.AddSeconds(-6), EndedAtUtc = now.AddSeconds(-5) };
        var rejection = new CurrentAuthArchiveGenuinePreflightRejection(typeof(MigrationExecutionException).FullName!, CurrentAuthArchiveGenuinePreflight.SemanticCode, now.AddSeconds(-2), now.AddSeconds(-1), true);
        return new(selected, scope, before, after, blocked, allowed, rejection, created, now);
    }
    private static string Hash(string text)
    {
        return CurrentAuthLocalSessionArchivePolicy.HashBytes(Encoding.UTF8.GetBytes(text));
    }

    private static string Raw(string hba)
    {
        return JsonSerializer.Serialize(hba.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select((line, index) =>
        {
            var fields = line.Split(' '); bool local = fields[0] == "local", ipv6 = !local && fields[3] == "::/0";
            return new
            {
                rule_number = index + 1,
                line_number = index + 1,
                file_name = "/var/lib/postgresql/18/docker/pg_hba.conf",
                type = fields[0],
                database = new[] { fields[1] },
                user_name = new[] { fields[2] },
                address = local ? null : ipv6 ? "::" : "0.0.0.0",
                netmask = local ? null : ipv6 ? "::" : "0.0.0.0",
                auth_method = fields[^1],
                options = Array.Empty<string>(),
                error = (string?)null
            };
        }));
    }
}
