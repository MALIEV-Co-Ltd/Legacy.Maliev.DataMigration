namespace Legacy.Maliev.DataMigration;

internal enum CurrentAuthArchiveGenuineRecoveryHelperCase
{
    DualDurableReadback = 1, FirstOnlyRecovery = 2, SecondOnlyRecovery = 3, KeyCorruption = 4, CipherCorruption = 5,
}

internal sealed record CurrentAuthArchiveGenuineRecoveryFileFault(string Path, string Identity, string BeforeSha256,
    string AfterSha256, int? SharingViolation);
internal sealed record CurrentAuthArchiveGenuineRecoveryFaultWitness(string CaseId, DateTimeOffset BeganAtUtc,
    DateTimeOffset EndedAtUtc, IReadOnlyList<CurrentAuthArchiveGenuineRecoveryFileFault> Files);
internal sealed record CurrentAuthArchiveGenuineRecoveryHelpersRequest(CurrentAuthArchiveScope Scope,
    CurrentAuthArchiveGenuineHelperClaims Claims, IReadOnlyList<CurrentAuthArchiveSession> Rows, DateTimeOffset BeganAtUtc);
internal sealed record CurrentAuthArchiveGenuineRecoveryHelpersOutcome(CurrentAuthArchiveRecoveryManifest Manifest,
    CurrentAuthArchiveGenuineRecoveryFaultWitness Fault, string? RejectionCode, string RecoveryStage,
    int ExpectedProviderExitCode, int? ProviderExitCode, bool HostEvidenceIncomplete);
internal sealed record CurrentAuthArchiveGenuineRecoveryHelpersFacts(CurrentAuthArchiveGenuineDualFacts Preservation,
    CurrentAuthArchiveGenuineRecoveryHelpersOutcome Outcome);
internal sealed record CurrentAuthArchiveGenuineProviderMethodResult(int ReturnCode, DateTimeOffset StartedAtUtc,
    DateTimeOffset ReturnedAtUtc, CurrentAuthArchiveGenuineDualArtifacts Artifacts);
internal sealed record CurrentAuthArchiveGenuineProviderCaseResult(CurrentAuthArchiveGenuineProviderMethodResult Method,
    CurrentAuthArchiveGenuineArtifact FinalCandidate);

internal static class CurrentAuthArchiveGenuineRecoveryHelpers
{
    internal static string CaseId(CurrentAuthArchiveGenuineRecoveryHelperCase value)
    {
        return value switch
        {
            CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback => "dual-durable-readback",
            CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery => "first-only-recovery",
            CurrentAuthArchiveGenuineRecoveryHelperCase.SecondOnlyRecovery => "second-only-recovery",
            CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption => "key-corruption",
            CurrentAuthArchiveGenuineRecoveryHelperCase.CipherCorruption => "cipher-corruption",
            _ => throw Invalid(),
        };
    }

    internal static CurrentAuthArchiveGenuineRecoveryHelperCase Parse(string value)
    {
        return value switch
        {
            "dual-durable-readback" => CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback,
            "first-only-recovery" => CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery,
            "second-only-recovery" => CurrentAuthArchiveGenuineRecoveryHelperCase.SecondOnlyRecovery,
            "key-corruption" => CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption,
            "cipher-corruption" => CurrentAuthArchiveGenuineRecoveryHelperCase.CipherCorruption,
            _ => throw Invalid(),
        };
    }

    internal static void RequireInitialSeed(CurrentAuthArchiveComponentBootstrapSeed seed, CurrentAuthArchivePins pins,
        IReceiptAttestationTrustStore trust, CurrentAuthArchiveGenuineRecoveryHelperCase expectedCase, DateTimeOffset now)
    {
        if (seed is null || pins is null || trust is null) { throw Invalid(); }
        CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        if (seed.Kind != "current-auth-genuine-archive-component-seed-v1" || seed.OperationId == Guid.Empty ||
            seed.CaseId != CaseId(expectedCase) || seed.AcceptedSourceCommitSha is not { Length: 40 } ||
            !seed.AcceptedSourceCommitSha.All(char.IsAsciiHexDigitLower) || seed.AuthOwnerCommitSha != ApprovedCurrentAuthSchema.AuthServiceCommit ||
            seed.OwnerPinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 || seed.ClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 ||
            new[] { seed.SourceSchemaPlanSha256, seed.DefinitionPrecursorSha256, seed.PrecursorSubjectSha256,
                seed.ParentRunBindingSha256, seed.TestAssemblySha256, seed.ConsoleAssemblySha256, seed.CoreAssemblySha256 }.Any(x => x is null || !CurrentAuthRepairPermit.HashShape(x)) ||
            seed.SigningPinsSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(pins) || seed.KeyId != pins.ReviewKeyId ||
            now.Offset != TimeSpan.Zero || seed.IssuedAtUtc.Offset != TimeSpan.Zero || seed.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            seed.IssuedAtUtc > now || seed.ExpiresAtUtc <= now || seed.ExpiresAtUtc <= seed.IssuedAtUtc ||
            seed.ExpiresAtUtc - seed.IssuedAtUtc > TimeSpan.FromMinutes(8) || string.IsNullOrWhiteSpace(seed.Signature)) { throw Invalid(); }
        try
        {
            if (!trust.Verify(seed.KeyId, CurrentAuthArchiveComponentBootstrap.SeedPayload(seed), Convert.FromBase64String(seed.Signature))) { throw Invalid(); }
        }
        catch (FormatException) { throw Invalid(); }
    }

    internal static int RequireObservedOutcome(CurrentAuthArchiveGenuineRecoveryHelpersOutcome outcome,
        CurrentAuthArchiveScope scope, CurrentAuthArchiveGenuineRecoveryHelperCase helperCase, string authorizationSha256, DateTimeOffset began)
    {
        if (outcome.ProviderExitCode is not null || !outcome.HostEvidenceIncomplete || outcome.Fault.CaseId != CaseId(helperCase) ||
            outcome.Manifest.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(scope) || outcome.Manifest.AuthorizationSha256 != authorizationSha256 ||
            outcome.Fault.BeganAtUtc < began || outcome.Fault.EndedAtUtc < outcome.Fault.BeganAtUtc || outcome.Fault.EndedAtUtc > DateTimeOffset.UtcNow ||
            outcome.Fault.Files.Any(x => !CurrentAuthRepairPermit.HashShape(x.BeforeSha256) || !CurrentAuthRepairPermit.HashShape(x.AfterSha256) ||
                !x.Identity.StartsWith("windows-ntfs:", StringComparison.Ordinal) || !x.Identity.Contains("/file-id-128:", StringComparison.Ordinal))) { throw Invalid(); }
        bool first = helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery;
        if (first || helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.SecondOnlyRecovery)
        {
            string[] expected = first ? [scope.Paths.SecondCiphertext, scope.Paths.SecondRecoveryPrivateKey] :
                [scope.Paths.FirstCiphertext, scope.Paths.RecoveryPrivateKey];
            return outcome.RejectionCode is not null || outcome.ExpectedProviderExitCode != 0 ||
                outcome.RecoveryStage != "selected-domain-recovered-with-other-domain-sharing-denied" ||
                !outcome.Fault.Files.Select(x => x.Path).Order(StringComparer.Ordinal).SequenceEqual(expected.Order(StringComparer.Ordinal)) ||
                outcome.Fault.Files.Any(x => x.SharingViolation != 32 || x.BeforeSha256 != x.AfterSha256)
                ? throw Invalid()
                : 0;
        }
        bool key = helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption;
        if (!key && helperCase != CurrentAuthArchiveGenuineRecoveryHelperCase.CipherCorruption) { throw Invalid(); }
        var fault = outcome.Fault.Files;
        return fault.Count != 1 || fault[0].Path != (key ? scope.Paths.RecoveryPrivateKey : scope.Paths.FirstCiphertext) ||
            fault[0].SharingViolation is not null || fault[0].BeforeSha256 == fault[0].AfterSha256 ||
            (!key && fault[0].BeforeSha256 != outcome.Manifest.FirstCiphertextSha256) || outcome.ExpectedProviderExitCode != 1 ||
            outcome.RecoveryStage != (key ? "key-import" : "ciphertext-digest") || outcome.RejectionCode !=
                (key ? "genuine_recovery_key_import_rejected" : "genuine_recovery_ciphertext_digest_rejected")
            ? throw Invalid()
            : 1;
    }

    private static MigrationExecutionException Invalid()
    {
        return new("current_auth_genuine_recovery_helper_invalid",
        "The fixed genuine recovery helper case or signed seed is invalid.");
    }
}
