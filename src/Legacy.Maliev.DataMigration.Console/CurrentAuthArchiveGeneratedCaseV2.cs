namespace Legacy.Maliev.DataMigration.Console;

internal enum CurrentAuthArchiveProofCaseV2
{
    Dual = 1, FirstHelper = 2, SecondHelper = 3, KeyCorruption = 4, CipherCorruption = 5,
    Complete = 6, PreparedPublication = 7, CommitAckLost = 8, TerminalPublication = 9,
    HostUnprobed = 10, LocalTrust = 11, ExactDelete = 12, CasDrift = 13, JournalDrift = 14,
    SequenceDrift = 15, ComparisonDrift = 16, FirstRestore = 17, SecondRestore = 18,
}
internal static class CurrentAuthArchiveGeneratedCasesV2
{
    internal const string BindingDomain = "Legacy.Maliev.CurrentAuth.ArchiveGeneratedCaseBinding.v2";
    internal static CurrentAuthArchiveGenuineCase Identity(CurrentAuthArchiveProofCaseV2 value)
    {
        var (phase, name) = value switch
        {
            CurrentAuthArchiveProofCaseV2.Dual => ("helper", "dual-durable-readback"),
            CurrentAuthArchiveProofCaseV2.FirstHelper => ("helper", "first-only-recovery"),
            CurrentAuthArchiveProofCaseV2.SecondHelper => ("helper", "second-only-recovery"),
            CurrentAuthArchiveProofCaseV2.KeyCorruption => ("helper", "key-corruption"),
            CurrentAuthArchiveProofCaseV2.CipherCorruption => ("helper", "cipher-corruption"),
            CurrentAuthArchiveProofCaseV2.Complete => ("native", "complete"),
            CurrentAuthArchiveProofCaseV2.PreparedPublication => ("native", "prepared-publication"),
            CurrentAuthArchiveProofCaseV2.CommitAckLost => ("native", "commit-ack-lost"),
            CurrentAuthArchiveProofCaseV2.TerminalPublication => ("native", "terminal-publication"),
            CurrentAuthArchiveProofCaseV2.HostUnprobed => ("native", "host-unprobed-sdk"),
            CurrentAuthArchiveProofCaseV2.LocalTrust => ("native", "local-trust"),
            CurrentAuthArchiveProofCaseV2.ExactDelete => ("delete", "exact-reviewed-delete"),
            CurrentAuthArchiveProofCaseV2.CasDrift => ("delete", "CAS-field-drift"),
            CurrentAuthArchiveProofCaseV2.JournalDrift => ("delete", "private-journal-drift"),
            CurrentAuthArchiveProofCaseV2.SequenceDrift => ("delete", "sequence-drift"),
            CurrentAuthArchiveProofCaseV2.ComparisonDrift => ("delete", "production-drift"),
            CurrentAuthArchiveProofCaseV2.FirstRestore => ("recovery", "first-only-decrypt-insert-readback"),
            CurrentAuthArchiveProofCaseV2.SecondRestore => ("recovery", "second-only-decrypt-insert-readback"),
            _ => throw CurrentAuthArchiveRecoveryV2.Invalid(),
        };
        return CurrentAuthArchiveGenuineCases.Require(phase, name);
    }
    internal static CurrentAuthArchiveGenuineExecutionCase Execution(CurrentAuthArchiveProofCaseV2 value)
    {
        return value switch
        {
            CurrentAuthArchiveProofCaseV2.Complete => CurrentAuthArchiveGenuineExecutionCase.NativeComplete,
            CurrentAuthArchiveProofCaseV2.PreparedPublication => CurrentAuthArchiveGenuineExecutionCase.PreparedPublication,
            CurrentAuthArchiveProofCaseV2.CommitAckLost => CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost,
            CurrentAuthArchiveProofCaseV2.TerminalPublication => CurrentAuthArchiveGenuineExecutionCase.TerminalPublication,
            CurrentAuthArchiveProofCaseV2.ExactDelete => CurrentAuthArchiveGenuineExecutionCase.ExactReviewedDelete,
            CurrentAuthArchiveProofCaseV2.CasDrift => CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift,
            CurrentAuthArchiveProofCaseV2.JournalDrift => CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift,
            CurrentAuthArchiveProofCaseV2.SequenceDrift => CurrentAuthArchiveGenuineExecutionCase.SequenceDrift,
            CurrentAuthArchiveProofCaseV2.ComparisonDrift => CurrentAuthArchiveGenuineExecutionCase.ProductionDrift,
            CurrentAuthArchiveProofCaseV2.Dual => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.FirstHelper => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.SecondHelper => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.KeyCorruption => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.CipherCorruption => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.HostUnprobed => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.LocalTrust => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.FirstRestore => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.SecondRestore => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            _ => throw CurrentAuthArchiveRecoveryV2.Invalid(),
        };
    }

    internal static CurrentAuthArchiveRecoveryV2Case Recovery(CurrentAuthArchiveProofCaseV2 value)
    {
        return value switch
        {
            CurrentAuthArchiveProofCaseV2.FirstRestore => CurrentAuthArchiveRecoveryV2Case.FirstOnly,
            CurrentAuthArchiveProofCaseV2.SecondRestore => CurrentAuthArchiveRecoveryV2Case.SecondOnly,
            CurrentAuthArchiveProofCaseV2.Dual => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.FirstHelper => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.SecondHelper => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.KeyCorruption => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.CipherCorruption => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.Complete => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.PreparedPublication => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.CommitAckLost => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.TerminalPublication => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.HostUnprobed => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.LocalTrust => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.ExactDelete => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.CasDrift => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.JournalDrift => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.SequenceDrift => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.ComparisonDrift => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            _ => throw CurrentAuthArchiveRecoveryV2.Invalid()
        };
    }

    internal static CurrentAuthArchiveGenuinePreflightCase Preflight(CurrentAuthArchiveProofCaseV2 value)
    {
        return value switch
        {
            CurrentAuthArchiveProofCaseV2.HostUnprobed => CurrentAuthArchiveGenuinePreflightCase.HostUnprobedSdk,
            CurrentAuthArchiveProofCaseV2.LocalTrust => CurrentAuthArchiveGenuinePreflightCase.LocalTrust,
            CurrentAuthArchiveProofCaseV2.Dual => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.FirstHelper => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.SecondHelper => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.KeyCorruption => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.CipherCorruption => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.Complete => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.PreparedPublication => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.CommitAckLost => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.TerminalPublication => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.ExactDelete => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.CasDrift => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.JournalDrift => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.SequenceDrift => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.ComparisonDrift => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.FirstRestore => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.SecondRestore => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            _ => throw CurrentAuthArchiveRecoveryV2.Invalid()
        };
    }

    internal static CurrentAuthArchiveGenuineRecoveryHelperCase Helper(CurrentAuthArchiveProofCaseV2 value)
    {
        return value switch
        {
            CurrentAuthArchiveProofCaseV2.Dual => CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback,
            CurrentAuthArchiveProofCaseV2.FirstHelper => CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery,
            CurrentAuthArchiveProofCaseV2.SecondHelper => CurrentAuthArchiveGenuineRecoveryHelperCase.SecondOnlyRecovery,
            CurrentAuthArchiveProofCaseV2.KeyCorruption => CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption,
            CurrentAuthArchiveProofCaseV2.CipherCorruption => CurrentAuthArchiveGenuineRecoveryHelperCase.CipherCorruption,
            CurrentAuthArchiveProofCaseV2.Complete => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.PreparedPublication => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.CommitAckLost => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.TerminalPublication => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.HostUnprobed => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.LocalTrust => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.ExactDelete => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.CasDrift => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.JournalDrift => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.SequenceDrift => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.ComparisonDrift => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.FirstRestore => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            CurrentAuthArchiveProofCaseV2.SecondRestore => throw CurrentAuthArchiveRecoveryV2.Invalid(),
            _ => throw CurrentAuthArchiveRecoveryV2.Invalid()
        };
    }
}

internal sealed record CurrentAuthArchiveGeneratedBindingV2(string Kind, string AudienceSha256, string Phase, string CaseId,
    Guid OperationId, string SeedSha256, string SourceFullSha256, string SourceIdentitySha256, string SourceDefinitionSha256,
    string DefinitionPrecursorSha256, string IntendedObservationSha256, string PreDefinitionIntendedObservationSha256,
    string InputSha256, string HostConfigurationSha256,
    DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record CurrentAuthArchiveGeneratedCaseInputV2(CurrentAuthArchiveProofArtifact Audience,
    CurrentAuthArchiveProofArtifact SourceCredential, CurrentAuthArchiveIntendedObservationInputV2 Intended,
    CurrentAuthArchiveProofArtifact QualifiedInputBinding, CurrentAuthArchiveProofArtifact TestImage,
    CurrentAuthArchiveDefinitionSigningInputs Signing, CurrentAuthArchiveProofArtifact AuthorizationPrivateKey,
    string FirstFixtureParent, string SecondFixtureParent);
internal sealed record CurrentAuthArchiveGeneratedCaseV2(CurrentAuthArchiveProofCaseV2 Case, Guid OperationId, CurrentAuthArchiveProofArtifact QualifiedInputBinding,
    CurrentAuthArchiveProofArtifact BindingClaim, CurrentAuthArchiveProofArtifact SourceCapture, CurrentAuthArchiveProofArtifact IntendedObservation,
    CurrentAuthArchiveProofArtifact PreDefinitionIntendedObservation,
    CurrentAuthArchiveProofArtifact Seed, CurrentAuthArchiveProofArtifact Input, CurrentAuthArchiveProofArtifact HostConfiguration,
    CurrentAuthArchiveFreshDefinition Definition, CurrentAuthArchiveProofArtifact Audience);
