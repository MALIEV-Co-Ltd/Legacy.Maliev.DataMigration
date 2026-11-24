using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGeneratedCasesV2Tests
{
    [Fact]
    public void Known_cases_are_rejected_by_every_other_host_family()
    {
        foreach (var selected in Enum.GetValues<CurrentAuthArchiveProofCaseV2>())
        {
            var identity = CurrentAuthArchiveGeneratedCasesV2.Identity(selected);
            bool preflight = identity.CaseId is "host-unprobed-sdk" or "local-trust";
            if (identity.Phase != "helper") { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGeneratedCasesV2.Helper(selected)); }
            if (identity.Phase != "recovery") { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGeneratedCasesV2.Recovery(selected)); }
            if (!preflight) { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGeneratedCasesV2.Preflight(selected)); }
            if (identity.Phase is "helper" or "recovery" || preflight)
            { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGeneratedCasesV2.Execution(selected)); }
        }
    }

    [Fact]
    public void Generator_dispatch_covers_exactly_the_eighteen_existing_case_identities()
    {
        var actual = Enum.GetValues<CurrentAuthArchiveProofCaseV2>().Select(CurrentAuthArchiveGeneratedCasesV2.Identity).ToArray();
        Assert.Equal(18, actual.Length);
        Assert.Equal(CurrentAuthArchiveGenuineCases.Inventory().OrderBy(x => x.Phase, StringComparer.Ordinal).ThenBy(x => x.CaseId, StringComparer.Ordinal),
            actual.OrderBy(x => x.Phase, StringComparer.Ordinal).ThenBy(x => x.CaseId, StringComparer.Ordinal));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(19)]
    [InlineData(-1)]
    public void Unknown_case_cannot_select_any_fixed_host_family(int value)
    {
        var selected = (CurrentAuthArchiveProofCaseV2)value;
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGeneratedCasesV2.Identity(selected));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGeneratedCasesV2.Helper(selected));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGeneratedCasesV2.Execution(selected));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGeneratedCasesV2.Preflight(selected));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGeneratedCasesV2.Recovery(selected));
    }

    [Theory]
    [InlineData(10)]
    [InlineData(11)]
    [InlineData(17)]
    [InlineData(18)]
    public void Preflight_and_restore_cases_cannot_enter_the_legacy_execution_enum_dispatch(int value)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGeneratedCasesV2.Execution((CurrentAuthArchiveProofCaseV2)value));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineExecutionCases.RequireImplemented(
            value switch
            {
                10 => CurrentAuthArchiveGenuineExecutionCase.HostUnprobedSdk,
                11 => CurrentAuthArchiveGenuineExecutionCase.LocalTrust,
                17 => CurrentAuthArchiveGenuineExecutionCase.FirstOnlyDecryptInsertReadback,
                _ => CurrentAuthArchiveGenuineExecutionCase.SecondOnlyDecryptInsertReadback
            }));
    }
}
