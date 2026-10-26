namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAppOwnedMaintenanceHbaTests
{
    [Fact]
    public void Exact_operator_with_all_ordinary_transports_rejected_is_accepted()
    {
        CurrentAppOwnedMaintenanceHba.Require(Rules(), "repair_operator", DeltaTargetAuthorityKind.LocalAspire);
    }

    [Theory]
    [InlineData("local", "trust", "all")]
    [InlineData("host", "scram-sha-256", "sdk_unprobed")]
    [InlineData("hostssl", "scram-sha-256", "sdk_unprobed")]
    [InlineData("hostnossl", "md5", "sdk_unprobed")]
    [InlineData("local", "peer", "postgres")]
    public void Unprobed_ordinary_access_is_rejected_even_when_another_role_is_blocked(string type, string method, string role)
    {
        CurrentAppOwnedMaintenanceHbaRule[] rules = Rules();
        CurrentAppOwnedMaintenanceHbaRule rule = new(1, type, ["all"], [role],
            type == "local" ? null : "0.0.0.0", type == "local" ? null : "0.0.0.0", method, [], null);
        rules = [rule, .. rules.Select(x => x with { Number = x.Number + 1 })];
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedMaintenanceHba.Require(rules, "repair_operator", DeltaTargetAuthorityKind.LocalAspire));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Every_ordinary_transport_requires_complete_terminal_rejection(int missing)
    {
        CurrentAppOwnedMaintenanceHbaRule[] rules = Rules().Where(x => x.Number != missing + 1).ToArray();
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedMaintenanceHba.Require(rules, "repair_operator", DeltaTargetAuthorityKind.LocalAspire));
    }

    [Fact]
    public void Allow_rules_after_terminal_rejections_are_rejected()
    {
        CurrentAppOwnedMaintenanceHbaRule[] initial = Rules();
        CurrentAppOwnedMaintenanceHbaRule[] rules =
        [.. initial.Skip(1).Select(x => x with { Number = x.Number - 1 }), initial[0] with { Number = 4 }];
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedMaintenanceHba.Require(rules, "repair_operator", DeltaTargetAuthorityKind.LocalAspire));
    }

    [Fact]
    public void Only_fixed_production_infrastructure_exceptions_are_allowed()
    {
        CurrentAppOwnedMaintenanceHbaRule[] exceptions =
        [
            new(1, "local", ["postgres"], ["postgres"], null, null, "peer", [], null),
            new(2, "hostssl", ["replication"], ["streaming_replica"], "all", null, "cert", ["clientcert=verify-full"], null),
            new(3, "hostssl", ["postgres"], ["streaming_replica"], "all", null, "cert", ["clientcert=verify-full"], null),
        ];
        CurrentAppOwnedMaintenanceHbaRule[] rules = [.. exceptions, .. Rules().Select(x => x with { Number = x.Number + 3 })];
        CurrentAppOwnedMaintenanceHba.Require(rules, "repair_operator", DeltaTargetAuthorityKind.ProductionCloudNativePg);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedMaintenanceHba.Require(rules, "repair_operator", DeltaTargetAuthorityKind.LocalAspire));
        foreach (CurrentAppOwnedMaintenanceHbaRule bad in new[]
        {
            exceptions[0] with { Databases = ["all"] }, exceptions[0] with { Users = ["all"] },
            exceptions[0] with { Options = ["map=caller"] }, exceptions[1] with { Databases = ["Customer"] },
            exceptions[1] with { Databases = ["postgres", "Customer"] }, exceptions[1] with { Users = ["sdk"] },
            exceptions[1] with { Type = "host" }, exceptions[1] with { Method = "trust" },
            exceptions[1] with { Options = ["map=caller"] },
            exceptions[1] with { Options = ["clientcert=verify-ca"] },
            exceptions[1] with { Options = [] },
            exceptions[1] with { Options = ["clientcert=verify-full", "map=caller"] },
            exceptions[1] with { Options = ["clientcert=verify-full", "clientcert=verify-full"] },
        })
        {
            rules = [bad with { Number = 1 }, .. Rules().Select(x => x with { Number = x.Number + 1 })];
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedMaintenanceHba.Require(rules, "repair_operator", DeltaTargetAuthorityKind.ProductionCloudNativePg));
        }
    }

    [Fact]
    public void Rules_cannot_use_metadata_errors_selectors_or_identity_maps_as_authority()
    {
        foreach (CurrentAppOwnedMaintenanceHbaRule bad in new[]
        {
            Rules()[0] with { Users = ["repair_operator", "sdk"] }, Rules()[0] with { Users = ["+repair_operator"] },
            Rules()[0] with { Databases = ["sameuser"] }, Rules()[0] with { Method = "md5" },
            Rules()[0] with { Error = "invalid" }, Rules()[0] with { Number = 0 },
            Rules()[0] with { Options = ["map=caller"] },
        })
        {
            CurrentAppOwnedMaintenanceHbaRule[] rules = [bad, .. Rules().Skip(1)];
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedMaintenanceHba.Require(rules, "repair_operator", DeltaTargetAuthorityKind.LocalAspire));
        }
    }

    private static CurrentAppOwnedMaintenanceHbaRule[] Rules()
    {
        return
        [
            new(1, "host", ["all"], ["repair_operator"], "0.0.0.0", "0.0.0.0", "scram-sha-256", [], null),
            new(2, "local", ["all"], ["all"], null, null, "reject", [], null),
            new(3, "host", ["all"], ["all"], "0.0.0.0", "0.0.0.0", "reject", [], null),
            new(4, "host", ["all"], ["all"], "::", "::", "reject", [], null),
        ];
    }
}
