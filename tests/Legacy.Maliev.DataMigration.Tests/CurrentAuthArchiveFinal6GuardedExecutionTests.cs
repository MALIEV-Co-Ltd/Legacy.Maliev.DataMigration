using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveFinal6FactAttribute : FactAttribute
{
    public CurrentAuthArchiveFinal6FactAttribute(int selected)
    {
        string input = CurrentAuthArchiveFinal6Host.InputVariable((CurrentAuthArchiveProofCaseV2)selected);
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(input)))
        { Skip = "Requires fresh Final6 protected input and the accepted Console provider host; a skip is no proof."; }
    }
}

public sealed class CurrentAuthArchiveFinal6GuardedExecutionTests
{
    [CurrentAuthArchiveFinal6Fact(1)]
    public Task Archive_helper_dual_durable_readback()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.Dual);
    }

    [CurrentAuthArchiveFinal6Fact(2)]
    public Task Archive_helper_first_only_recovery()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.FirstHelper);
    }

    [CurrentAuthArchiveFinal6Fact(3)]
    public Task Archive_helper_second_only_recovery()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.SecondHelper);
    }

    [CurrentAuthArchiveFinal6Fact(4)]
    public Task Archive_helper_key_corruption()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.KeyCorruption);
    }

    [CurrentAuthArchiveFinal6Fact(5)]
    public Task Archive_helper_cipher_corruption()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.CipherCorruption);
    }

    [CurrentAuthArchiveFinal6Fact(6)]
    public Task Archive_native_complete()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.Complete);
    }

    [CurrentAuthArchiveFinal6Fact(7)]
    public Task Archive_native_prepared_publication()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.PreparedPublication);
    }

    [CurrentAuthArchiveFinal6Fact(8)]
    public Task Archive_native_commit_ack_lost()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.CommitAckLost);
    }

    [CurrentAuthArchiveFinal6Fact(9)]
    public Task Archive_native_terminal_publication()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.TerminalPublication);
    }

    [CurrentAuthArchiveFinal6Fact(10)]
    public Task Archive_native_host_unprobed_sdk()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.HostUnprobed);
    }

    [CurrentAuthArchiveFinal6Fact(11)]
    public Task Archive_native_local_trust()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.LocalTrust);
    }

    [CurrentAuthArchiveFinal6Fact(12)]
    public Task Archive_delete_exact_reviewed_delete()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.ExactDelete);
    }

    [CurrentAuthArchiveFinal6Fact(13)]
    public Task Archive_delete_CAS_field_drift()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.CasDrift);
    }

    [CurrentAuthArchiveFinal6Fact(14)]
    public Task Archive_delete_private_journal_drift()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.JournalDrift);
    }

    [CurrentAuthArchiveFinal6Fact(15)]
    public Task Archive_delete_sequence_drift()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.SequenceDrift);
    }

    [CurrentAuthArchiveFinal6Fact(16)]
    public Task Archive_delete_production_drift()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.ComparisonDrift);
    }

    [CurrentAuthArchiveFinal6Fact(17)]
    public Task Archive_recovery_first_only_decrypt_insert_readback()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.FirstRestore);
    }

    [CurrentAuthArchiveFinal6Fact(18)]
    public Task Archive_recovery_second_only_decrypt_insert_readback()
    {
        return RunAsync(CurrentAuthArchiveProofCaseV2.SecondRestore);
    }

    private static async Task RunAsync(CurrentAuthArchiveProofCaseV2 selected)
    {
        string input = Environment.GetEnvironmentVariable(CurrentAuthArchiveFinal6Host.InputVariable(selected)) ?? throw CurrentAuthArchiveFinal6Source.Invalid();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        var result = await CurrentAuthArchiveFinal6SdkHarness.RunAsync(input, selected, timeout.Token);
        Assert.Equal(CurrentAuthArchiveFinal6Host.ExpectedMethodCode(selected), result.Method.ReturnCode);
    }
}