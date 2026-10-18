using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentOwnerIsoIntendedRuntimeTests
{
    [Fact]
    public void Intended_subject_has_no_future_closed_proof_or_operational_claim_fields()
    {
        var names = typeof(IsoIntendedRuntimeFacts).GetProperties().Select(x => x.Name).ToArray();
        Assert.DoesNotContain("NativeProofSha256", names); Assert.DoesNotContain("MaintenanceProofSha256", names);
        Assert.DoesNotContain("AuthorizationSha256", names); Assert.DoesNotContain("ScopeSha256", names);
        Assert.DoesNotContain("BootstrapSubject", names);
        Assert.Contains("TargetObservationSha256", names); Assert.Contains("GlobalPreservationSha256", names);
    }
    [Fact]
    public void Distinct_intended_observation_and_phase_signature_domains_cannot_be_interchanged()
    {
        var observation = Observation();
        var phase = new IsoIntendedClosedPhase("current-owner-iso-intended-closed-phase-v1", IsoComponentProofPhase.Native, new('a', 64), new('b', 64), new("held.json", new('c', 64)), DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddHours(1), "proof", null);
        Assert.False(IsoIntendedRuntimeReader.Payload(observation).AsSpan().SequenceEqual(IsoExternalClosedReader.Payload(phase)));
        Assert.Equal(IsoIntendedRuntimeReader.Payload(observation), IsoIntendedRuntimeReader.Payload(observation with { Signature = "not-part-of-payload" }));
    }
    [Fact]
    public void Production18_1_and_disposable_cases_are_not_persistent_runtime_subjects()
    {
        var value = Observation(); var scope = Runtime(value.Facts);
        IsoIntendedRuntimeReader.RequireRuntime(value, scope);
        _ = Assert.Throws<MigrationExecutionException>(() => IsoIntendedRuntimeReader.RequireRuntime(value with { ServerVersionNumber = 180001 }, scope));
        _ = Assert.Throws<MigrationExecutionException>(() => IsoIntendedRuntimeReader.RequireRuntime(value, scope with { Target = scope.Target with { Kind = DeltaTargetAuthorityKind.ProductionCloudNativePg } }));
        _ = Assert.Throws<MigrationExecutionException>(() => IsoIntendedRuntimeReader.RequireRuntime(value, scope with { ProofAdmission = CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap }));
        _ = Assert.Throws<MigrationExecutionException>(() => IsoIntendedRuntimeReader.RequireRuntime(value, scope with { TargetGeneration = "changed-generation" }));
        _ = Assert.Throws<MigrationExecutionException>(() => IsoIntendedRuntimeReader.RequireRuntime(value, scope with { BeforeDatabaseSha256 = new Dictionary<string, string> { { "Country", new('f', 64) } } }));
    }
    private static IsoIntendedRuntimeObservation Observation()
    {
        string hash = new('a', 64); var target = new DeltaTargetAuthority(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/persistent-0123456789ab", hash);
        var maintenance = new CurrentAppOwnedMaintenancePin("legacy_iso_native", "comment", DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddHours(1), DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, hash, hash, "/var/lib/postgresql/18/docker/pg_hba.conf");
        var names = DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]).ToDictionary(x => x, _ => hash, StringComparer.Ordinal);
        var facts = new IsoIntendedRuntimeFacts(Guid.Parse("a22536b3-1fdb-487a-87d2-b2d9340f99da"), new('a', 40), hash, hash, hash, hash, hash, target, "local", "legacy-postgres-main-local", "generation", hash, hash, names, hash, maintenance, CurrentOwnerIsoRepairPermit.MaintenanceValidator);
        var subject = new IsoDefinitionSubject(facts.SourceCommitSha, hash, hash, hash, hash, hash, hash, hash, hash, hash, hash); var artifact = new IsoDefinitionArtifact("held.json", hash);
        return new("current-owner-iso-intended-runtime-v1", facts, subject, hash, artifact, artifact, artifact, artifact, artifact, artifact, artifact, 180004, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddHours(1), "runtime", null);
    }
    private static CurrentOwnerIsoRepairScope Runtime(IsoIntendedRuntimeFacts f)
    {
        return new(f.OperationId, CurrentOwnerIsoSelection.LiteralWidthV1, f.SourceCommitSha, f.SourceSchemaPlanSha256, f.OwnerSourcesSha256, f.ContractSha256, f.OperationSha256, f.Target, f.TargetNamespace, f.TargetCluster, f.TargetGeneration, f.TargetObservationSha256, f.RunBindingSha256, f.BeforeDatabaseSha256, f.GlobalPreservationSha256, new('b', 64), new('c', 64), new('d', 64), f.Maintenance, "unchanged-recovery-policy", f.SourceCatalogSha256, f.MaintenanceValidatorSha256, new('e', 64));
    }
}
