using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthLocalSessionArchiveConsoleTests
{
    private static readonly string[] LocalAdditionalDatabases = ["Auth", "postgres", "legacy_local"];
    [Theory]
    [InlineData("review-current-auth-local-session-archive")]
    [InlineData("authorize-current-auth-local-session-archive")]
    [InlineData("verify-current-auth-local-session-archive")]
    [InlineData("apply-current-auth-local-session-archive")]
    public void Only_the_four_fixed_commands_are_supported(string command)
    {
        MigrationConsole.RequireArchiveCommand(command);
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequireArchiveCommand(command + "-callback"));
        _ = Assert.Throws<JsonException>(() => MigrationConsole.DecodeAuthRepair<CurrentAuthLocalSessionArchiveConfiguration>(/*lang=json,strict*/ "{\"environmentCallback\":\"bypass\"}"u8.ToArray()));
    }
    [Theory]
    [InlineData("same-disk")]
    [InlineData("same-volume")]
    [InlineData("same-serial")]
    [InlineData("virtual")]
    [InlineData("file-backed")]
    [InlineData("zero-extent")]
    [InlineData("network")]
    public void Paths_and_volume_letters_cannot_substitute_for_two_physical_device_failure_domains(string fault)
    {
        CurrentAuthArchivePhysicalDevice first = Device(0), second = Device(1);
        CurrentAuthLocalSessionArchiveRecoveryDevices.RequireIndependent(first, second);
        second = fault switch
        {
            "same-disk" => second with { DiskNumber = first.DiskNumber },
            "same-volume" => second with { VolumeGuid = first.VolumeGuid },
            "same-serial" => second with { SerialSha256 = first.SerialSha256 },
            "virtual" => second with { BusType = 14 },
            "file-backed" => second with { BusType = 15 },
            "zero-extent" => second with { ExtentLength = 0 },
            "network" => second with { VolumeGuid = @"\\server\share" },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveRecoveryDevices.RequireIndependent(first, second));
    }
    [Theory]
    [InlineData("operation")]
    [InlineData("key-path")]
    [InlineData("source")]
    [InlineData("target")]
    [InlineData("devices")]
    [InlineData("expiry")]
    public void Signed_device_proof_cannot_be_rebound_to_another_operation_key_source_target_or_device(string fault)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow; CurrentAuthArchiveScope scope = Scope(now);
        var pinned = new CurrentAuthArchiveDeviceProof("Legacy.Maliev.CurrentAuth.ArchivePhysicalDevices.v1", scope.OperationId,
            scope.LocalObservationPolicy.SourceCommitSha, CurrentAuthRepairPermit.OwnerPinsSha256, scope.LocalObservationPolicy.RunBindingSha256,
            scope.ProductionObservationPolicy.RunBindingSha256, scope.LocalObservationPolicy.TargetObservationSha256,
            scope.ProductionObservationPolicy.TargetObservationSha256, scope.Paths, Device(0), Device(1), now);
        scope = scope with { RecoveryDeviceProofSha256 = CurrentAuthLocalSessionArchivePolicy.Hash(pinned) };
        CurrentAuthLocalSessionArchiveRecoveryDevices.RequireProof(pinned, scope, pinned, now);
        CurrentAuthArchiveDeviceProof actual = fault switch
        {
            "operation" => pinned with { OperationId = Guid.NewGuid() },
            "key-path" => pinned with { Paths = pinned.Paths with { RecoveryPrivateKey = @"D:\foreign\key" } },
            "source" => pinned with { SourceCommitSha = new string('b', 40) },
            "target" => pinned with { LocalTargetObservationSha256 = new string('f', 64) },
            "devices" => pinned with { First = pinned.First with { SerialSha256 = new string('f', 64) } },
            "expiry" => pinned with { ObservedAtUtc = now.AddMinutes(-6) },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveRecoveryDevices.RequireProof(pinned, scope, actual, now));
    }
    [Theory]
    [InlineData("old-role-purpose")]
    [InlineData("unbounded-role")]
    [InlineData("default-collation-preimage")]
    [InlineData("wrong-namespace")]
    public void Observation_policy_requires_current_completed_Auth_and_fresh_archive_maintenance(string fault)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow; CurrentAuthArchiveScope scope = Scope(now);
        CurrentAuthLocalSessionArchiveEnvironment.RequireObservationPolicies(scope, now);
        CurrentAuthRepairScope local = scope.LocalObservationPolicy;
        local = fault switch
        {
            "old-role-purpose" => local with { Maintenance = local.Maintenance with { RoleComment = "legacy-maliev-current-auth-v1:" + local.RunBindingSha256 } },
            "unbounded-role" => local with { Maintenance = local.Maintenance with { ExpiresAtUtc = now.AddDays(1) } },
            "default-collation-preimage" => local with { AuthBeforeSchemaSha256 = ApprovedCurrentAuthSchema.PhysicalSha256(false) },
            "wrong-namespace" => local with { TargetNamespace = "foreign" },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveEnvironment.RequireObservationPolicies(scope with { LocalObservationPolicy = local }, now));
    }
    [Fact]
    public void Archive_scope_accepts_exact_reviewed_comparison_inventory()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        CurrentAuthArchiveScope scope = Scope(now);
        Assert.Equal(49, scope.ProductionObservationPolicy.BeforeDatabaseSha256.Count);
        CurrentAuthLocalSessionArchivePolicy.RequireScope(scope, now);
    }

    [Fact]
    public void Bootstrap_comparison_uses_reviewed_comparison_inventory_despite_local_transport()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        CurrentAuthArchiveScope scope = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(now);
        Assert.Equal(DeltaTargetAuthorityKind.LocalAspire, scope.ProductionObservationPolicy.Target.Kind);
        Assert.Equal(49, scope.ProductionObservationPolicy.BeforeDatabaseSha256.Count);
        CurrentAuthLocalSessionArchivePolicy.RequireScope(scope, now);
    }
    [Theory]
    [InlineData("old-53")]
    [InlineData("renamed")]
    [InlineData("template")]
    [InlineData("swapped")]
    public void Archive_scope_rejects_unreviewed_inventory_keys(string fault)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        CurrentAuthArchiveScope scope = Scope(now);
        var map = scope.ProductionObservationPolicy.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        if (fault == "old-53")
        {
            for (int i = 0; i < 4; i++) { map.Add("obsolete-" + i.ToString(System.Globalization.CultureInfo.InvariantCulture), new string('a', 64)); }
        }
        else if (fault == "swapped") { map = scope.LocalObservationPolicy.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal); }
        else
        {
            string name = map.Keys.First(x => x.StartsWith("legacy_shadow_", StringComparison.Ordinal));
            _ = map.Remove(name); map.Add(fault == "template" ? "template1" : "renamed-shadow", new string('a', 64));
        }
        CurrentAuthRepairScope policy = scope.ProductionObservationPolicy with
        { BeforeDatabaseSha256 = map, GlobalPreservationSha256 = CurrentAuthRepairPermit.FleetSha256(map) };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireScope(scope with { ProductionObservationPolicy = policy }, now));
    }
    private static CurrentAuthArchivePhysicalDevice Device(uint number)
    {
        return new(@"\\?\Volume{" + number.ToString(System.Globalization.CultureInfo.InvariantCulture) + @"}\",
        number, 1048576, 100000000, 17, new string(number == 0 ? 'a' : 'b', 64));
    }

    internal static CurrentAuthArchiveScope Scope(DateTimeOffset now)
    {
        Guid operation = Guid.NewGuid();
        CurrentAuthRepairScope Policy(bool local)
        {
            var names = local ? DatabaseInventory.ActiveDatabases.Concat(LocalAdditionalDatabases).ToArray() :
                ReviewedProductionRepairInventory.ExportProductionNames().ToArray();
            var map = names.ToDictionary(name => name, _ => new string('a', 64), StringComparer.Ordinal);
            string binding = new(local ? 'c' : 'd', 64);
            return new(operation, CurrentAuthRepairOperation.SixteenSameTypeTextCollations, new string('a', 40), new string('b', 64), ApprovedCurrentAuthSchema.AuthServiceCommit,
                CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256, ApprovedCurrentAuthSchema.PhysicalSha256(true), ApprovedCurrentAuthSchema.PhysicalSha256(true),
                new string('a', 64), new string('b', 64), CurrentAuthRepairEnvironment.IntegratedMaintenanceValidatorSha256,
                new(local ? DeltaTargetAuthorityKind.LocalAspire : DeltaTargetAuthorityKind.ProductionCloudNativePg,
                    local ? "aspire://legacy-postgres-main-local/persistent-aaaaaaaaaaaa" : "gke://maliev-website/synthetic", new string(local ? 'e' : 'f', 64)),
                local ? "local-aspire" : "maliev-legacy", local ? "legacy-postgres-main-local" : "legacy-postgres-main",
                local ? "docker:synthetic" : "cnpg:synthetic", new string('e', 64), binding, map, CurrentAuthRepairPermit.FleetSha256(map),
                new string('a', 64), new string('b', 64), new string('c', 64), new("synthetic_archive_operator", "legacy-maliev-current-auth-session-archive-v1:" + binding,
                    now.AddMinutes(-1), now.AddHours(1), now.AddMinutes(-2), now.AddMinutes(-2), new string('b', 64), new string('c', 64), "/synthetic/hba"));
        }
        string firstRoot = Path.Combine(Path.GetTempPath(), "synthetic-archive-first-" + operation.ToString("N"));
        string secondRoot = Path.Combine(Path.GetTempPath(), "synthetic-archive-second-" + operation.ToString("N"));
        return new(operation, Policy(true), Policy(false), new string('a', 64), 3, new string('b', 64),
            new(Path.Combine(firstRoot, "archive.json"), Path.Combine(secondRoot, "archive.json"),
                Path.Combine(firstRoot, "recovery.pkcs8"), Path.Combine(secondRoot, "recovery.pkcs8")),
            new string('c', 64), new string('d', 64), new string('e', 64), new string('f', 64), new string('a', 64), now, now.AddMinutes(4));
    }
}
