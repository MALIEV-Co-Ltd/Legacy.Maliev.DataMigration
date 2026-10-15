using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentCustomerClosedIntegrationTests
{
    [Fact]
    public void Exact_named_child_route_requires_two_arguments_and_an_absolute_configuration()
    {
        string path = Path.Combine(Path.GetTempPath(), "customer-closed-child.json");
        var invocation = ConsoleInvocation.Parse([CustomerNamedClosedHostLauncher.ChildCommand, path]);
        Assert.Equal(CustomerNamedClosedHostLauncher.ChildCommand, invocation.Command);
        Assert.Equal(path, invocation.ConfigPath);
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([CustomerNamedClosedHostLauncher.ChildCommand, "relative.json"]));
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([CustomerNamedClosedHostLauncher.ChildCommand, path, "extra"]));
    }
    [Theory]
    [InlineData("absent")]
    [InlineData("component")]
    [InlineData("named")]
    [InlineData("native-path")]
    [InlineData("maintenance-path")]
    [InlineData("recovery-path")]
    [InlineData("role-path")]
    [InlineData("definition")]
    public void Supplied_closed_evidence_cannot_fall_back_to_another_mode_or_artifact(string fault)
    {
        var (configuration, scope) = Inputs();
        configuration = fault switch
        {
            "absent" => configuration with { ClosedEight = null },
            "component" => configuration with { ProofAdmission = CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap },
            "named" => configuration with { ProofAdmission = CurrentCustomerSequenceProofAdmission.DisposableClosedConsoleBootstrap },
            "native-path" => configuration with { NativeProof = new("other", configuration.NativeProof.Sha256) },
            "maintenance-path" => configuration with { MaintenanceProof = new("other", configuration.MaintenanceProof!.Sha256) },
            "recovery-path" => configuration with { RecoveryReview = new("other", configuration.RecoveryReview.Sha256) },
            "role-path" => configuration with { ExactRoleTransitionReview = new("other", configuration.ExactRoleTransitionReview.Sha256) },
            "definition" => configuration with { DefinitionProof = new("definition", new('f', 64)) },
            _ => throw new InvalidOperationException()
        };
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequireCustomerClosedEightConfiguration(configuration, scope));
    }
    [Fact]
    public void Structural_binding_does_not_read_or_accept_a_proof()
    {
        var (configuration, scope) = Inputs();
        MigrationConsole.RequireCustomerClosedEightConfiguration(configuration, scope);
        Assert.Equal(CurrentCustomerSequenceProofAdmission.PersistentWithClosedConsoleProof, configuration.ProofAdmission);
        Assert.Null(configuration.ClosedSeedEvidence);
        // No custody, signature, claim, permit or runtime proof is produced by this unit input.
    }
    private static (CurrentCustomerSequenceRepairConfiguration Configuration, CurrentCustomerSequenceRepairScope Scope) Inputs()
    {
        DateTimeOffset now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        string hash = new('a', 64);
        var native = new CustomerDefinitionArtifact("native.json", hash);
        var maintenance = new CustomerDefinitionArtifact("maintenance.json", hash);
        var recovery = new CustomerDefinitionArtifact("recovery.json", hash);
        var role = new CustomerDefinitionArtifact("role.json", hash);
        var evidence = new CustomerClosedEightEvidence("proof-binding.json", hash, new(native, maintenance, recovery, role), "proof-key", hash);
        var scope = new CurrentCustomerSequenceRepairScope(Guid.NewGuid(), CurrentCustomerSequenceRepairOperation.FixedStartDefinitionOnly,
            hash, hash, hash, new(hash, hash, now, 1000, 1, 1001), new(hash, true, now, hash, hash),
            hash, hash, hash, hash, hash, new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/persistent-aaaaaaaaaaaa", hash),
            "local-aspire", "legacy-postgres-main-local", "generation", hash, hash, new Dictionary<string, string>(), hash, hash, hash, hash,
            new("operator", "comment", now, now.AddHours(1), now, now, hash, hash, "/fixture/pg_hba.conf"), hash);
        var configuration = new CurrentCustomerSequenceRepairConfiguration("source.json", new("catalog.json", "source.txt", new(new Uri("https://kubernetes.default.svc"), "token", "ca")),
            "scope.json", "review.json", "authorization.json", "pins.json", "binding.json", "operator.txt", "ordinary.txt", "baseline.json", "target.json", [],
            "receipt.pem", new(native.Path, native.Sha256), new(recovery.Path, recovery.Sha256), new(role.Path, role.Sha256),
            DefinitionProof: new("definition.json", hash), MaintenanceProof: new(maintenance.Path, maintenance.Sha256), ClosedEight: evidence);
        return (configuration, scope);
    }
}
