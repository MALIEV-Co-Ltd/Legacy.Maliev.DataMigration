using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentOwnerIsoComponentProofReaderTests
{
    [Fact]
    public void Publication_loss_preserves_the_actual_unacknowledged_slot_instead_of_adopting_it()
    {
        var slots = new[] { ("Country", CurrentAppOwnedCommitClassification.Prepared, true), ("Country", CurrentAppOwnedCommitClassification.CommittedAndReadback, false), ("Country", CurrentAppOwnedCommitClassification.Uncertain, true) };
        IsoComponentProofReader.RequireScenarioSlots("terminal-publication", slots);
        var adopted = slots.ToArray(); adopted[1] = ("Country", CurrentAppOwnedCommitClassification.CommittedAndReadback, true);
        _ = Assert.Throws<MigrationExecutionException>(() => IsoComponentProofReader.RequireScenarioSlots("terminal-publication", adopted));
    }
    [Fact]
    public void Lost_commit_ack_requires_uncertain_and_forbids_a_Material_effect()
    {
        var slots = new[] { ("Country", CurrentAppOwnedCommitClassification.Prepared, true), ("Country", CurrentAppOwnedCommitClassification.Uncertain, true) };
        IsoComponentProofReader.RequireScenarioSlots("lost-commit-ack", slots);
        _ = Assert.Throws<MigrationExecutionException>(() => IsoComponentProofReader.RequireScenarioSlots("lost-commit-ack", slots.Append(("Material", CurrentAppOwnedCommitClassification.Prepared, true)).ToArray()));
        _ = Assert.Throws<MigrationExecutionException>(() => IsoComponentProofReader.RequireScenarioSlots("lost-commit-ack", [("Country", CurrentAppOwnedCommitClassification.Prepared, true), ("Country", CurrentAppOwnedCommitClassification.CommittedAndReadback, true)]));
    }
    [Fact]
    public void Full_success_requires_both_ordered_prepared_and_acknowledged_terminals()
    {
        var slots = new[] { ("Country", CurrentAppOwnedCommitClassification.Prepared, true), ("Country", CurrentAppOwnedCommitClassification.CommittedAndReadback, true), ("Material", CurrentAppOwnedCommitClassification.Prepared, true), ("Material", CurrentAppOwnedCommitClassification.CommittedAndReadback, true) };
        IsoComponentProofReader.RequireScenarioSlots("complete", slots);
        _ = Assert.Throws<MigrationExecutionException>(() => IsoComponentProofReader.RequireScenarioSlots("complete", slots.Reverse().ToArray()));
        _ = Assert.Throws<MigrationExecutionException>(() => IsoComponentProofReader.RequireScenarioSlots("complete", slots.Take(2).ToArray()));
    }
    [Fact]
    public void Rolled_back_prepared_publication_requires_unacknowledged_prepared_then_real_rollback()
    {
        var slots = new[] { ("Country", CurrentAppOwnedCommitClassification.Prepared, false), ("Country", CurrentAppOwnedCommitClassification.RolledBackBeforeCommit, true) };
        IsoComponentProofReader.RequireScenarioSlots("prepared-publication", slots);
        _ = Assert.Throws<MigrationExecutionException>(() => IsoComponentProofReader.RequireScenarioSlots("prepared-publication", []));
    }
    [Fact]
    public void Host_filters_select_exact_case_domains_and_never_a_whole_test_project()
    {
        string native = OwnerIsoGuardedBootstrapHostLauncher.Filter("native-component"), maintenance = OwnerIsoGuardedBootstrapHostLauncher.Filter("maintenance-component");
        Assert.Equal(6, native.Split('|').Length); Assert.Equal(4, maintenance.Split('|').Length);
        Assert.DoesNotContain("Unsafe_unprobed_host_rule_rejected", native, StringComparison.Ordinal);
        Assert.DoesNotContain("Complete_26_database_fleet", maintenance, StringComparison.Ordinal);
        _ = Assert.Throws<MigrationExecutionException>(() => OwnerIsoGuardedBootstrapHostLauncher.Filter("closed"));
    }
}
