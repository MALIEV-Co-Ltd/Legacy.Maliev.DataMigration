using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveIntendedLifetimeV2Tests
{
    [Fact]
    public void Old_execution_scope_is_not_an_expectations_descriptor_and_new_markers_do_not_open_old_device_or_proof_domains()
    {
        var now = DateTimeOffset.UtcNow; var fixture = Fixture(now);
        _ = Assert.Throws<JsonException>(() => MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveIntendedDescriptorV2>(
            JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchiveConsoleTests.Scope(now))));
        var context = CurrentAuthArchiveIntendedObservationRuntimeV2.CreateUnadmittedObservation(fixture.Descriptor, fixture.Source,
            fixture.Local, fixture.Comparison, fixture.Audience, now);
        CurrentAuthLocalSessionArchiveDeviceProcess.RequireVersionedDeviceContext(context, now);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireScope(context, now));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofReader.Domain("helper", context.ProofAdmission));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveDeviceProcess.RequireVersionedDeviceContext(
            context with { ExpiresAtUtc = now.AddMinutes(3) }, now));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveDeviceProcess.RequireVersionedDeviceContext(
            context with { ProofAdmission = CurrentAuthArchiveProofAdmission.PersistentWithClosedConsoleProof }, now));
    }
    [Fact]
    public void Repeated_readonly_contexts_have_new_operations_without_extending_native_role_leases_or_mutating_inputs()
    {
        var now = new DateTimeOffset(2026, 11, 24, 0, 0, 0, TimeSpan.Zero);
        var fixture = Fixture(now); byte[] original = JsonSerializer.SerializeToUtf8Bytes(fixture.Descriptor);
        byte[] source = JsonSerializer.SerializeToUtf8Bytes(fixture.Source);
        var first = CurrentAuthArchiveIntendedObservationRuntimeV2.CreateUnadmittedObservation(fixture.Descriptor, fixture.Source,
            fixture.Local, fixture.Comparison, fixture.Audience, now);
        var nextSource = fixture.Source with
        {
            Plan = fixture.Source.Plan with { CapturedAtUtc = now.AddMinutes(10) },
            FullPlanSha256 = new string('b', 64),
            BeganAtUtc = now.AddMinutes(10),
            CompletedAtUtc = now.AddMinutes(10)
        };
        var later = CurrentAuthArchiveIntendedObservationRuntimeV2.CreateUnadmittedObservation(fixture.Descriptor, nextSource,
            fixture.Local, fixture.Comparison, fixture.Audience, now.AddMinutes(10));
        Assert.NotEqual(first.OperationId, later.OperationId); Assert.NotEqual(first.Paths, later.Paths);
        Assert.Equal(fixture.Descriptor.LocalPolicy.Maintenance, later.LocalObservationPolicy.Maintenance);
        Assert.Equal(fixture.Descriptor.ComparisonPolicy.Maintenance, later.ProductionObservationPolicy.Maintenance);
        Assert.Equal(now.AddMinutes(10), later.CapturedAtUtc); Assert.Equal(now.AddMinutes(12), later.ExpiresAtUtc);
        Assert.Equal(original, JsonSerializer.SerializeToUtf8Bytes(fixture.Descriptor));
        Assert.Equal(source, JsonSerializer.SerializeToUtf8Bytes(fixture.Source));
        // Data-only contexts cannot pass the old execution scope gate: genuine observation still requires live source, IOCTL and native targets.
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireScope(later, now.AddMinutes(10)));
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Actual_maintenance_expiry_cannot_be_renewed_by_a_new_observation_clock(bool comparison)
    {
        var now = new DateTimeOffset(2026, 11, 24, 0, 0, 0, TimeSpan.Zero); var fixture = Fixture(now);
        var old = comparison ? fixture.Descriptor.ComparisonPolicy : fixture.Descriptor.LocalPolicy;
        var expired = old with { Maintenance = old.Maintenance with { ExpiresAtUtc = now.AddMinutes(2) } };
        var descriptor = comparison ? fixture.Descriptor with { ComparisonPolicy = expired } : fixture.Descriptor with { LocalPolicy = expired };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveIntendedObservationRuntimeV2.CreateUnadmittedObservation(descriptor,
            fixture.Source, fixture.Local, fixture.Comparison, fixture.Audience, now));
    }
    [Fact]
    public void A_historical_execution_scope_is_not_an_intended_descriptor()
    {
        byte[] old = JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchiveConsoleTests.Scope(DateTimeOffset.UtcNow));
        _ = Assert.Throws<JsonException>(() => MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveIntendedDescriptorV2>(old));
    }
    private static (CurrentAuthArchiveIntendedDescriptorV2 Descriptor, CurrentAuthArchiveRecoverySourceEvidence Source,
        LocalExecutionBinding Local, LocalExecutionBinding Comparison, CurrentAuthArchiveProofAudienceV2 Audience) Fixture(DateTimeOffset now)
    {
        var original = CurrentAuthLocalSessionArchiveConsoleTests.Scope(now);
        LocalExecutionBinding Binding(string name)
        {
            return new(1, "synthetic", "synthetic", Path.GetFullPath(Path.Combine(Path.GetTempPath(), name)), "synthetic", "lock", "synthetic", 1);
        }

        var local = Binding("intended-first"); var comparison = Binding("intended-second");
        CurrentAuthRepairScope Policy(CurrentAuthRepairScope value, LocalExecutionBinding binding)
        {
            return value with
            { RunBindingSha256 = binding.ComputeSha256(), Maintenance = value.Maintenance with { RoleComment = "legacy-maliev-current-auth-session-archive-v1:" + binding.ComputeSha256() } };
        }

        var descriptor = new CurrentAuthArchiveIntendedDescriptorV2("current-auth-archive-intended-after-c-descriptor-v2",
            Policy(original.LocalObservationPolicy, local), Policy(original.ProductionObservationPolicy, comparison));
        string hash = new('a', 64); var plan = new FreshSchemaPlan("1.0", now, new string('a', 40), []);
        var source = new CurrentAuthArchiveRecoverySourceEvidence(plan, hash, hash, hash, now, now, []);
        var audience = new CurrentAuthArchiveProofAudienceV2("synthetic-only", Guid.NewGuid(), plan.SourceCommitSha,
            hash, hash, hash, hash, hash, hash, hash, hash, hash, hash, hash, hash, 3, now, now.AddHours(1));
        return (descriptor, source, local, comparison, audience);
    }
}
