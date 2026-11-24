namespace Legacy.Maliev.DataMigration;

internal static class CurrentAuthArchiveGenuineExecutionSeed
{
    // Existing signed wire/domain is deliberately unchanged: the existing engine authenticates these same bytes.
    // This distinct initial-reader entry accepts only the execution13 family, never helper5.
    internal static void RequireInitial(CurrentAuthArchiveComponentBootstrapSeed seed, CurrentAuthArchivePins pins,
        IReceiptAttestationTrustStore trust, CurrentAuthArchiveGenuineExecutionCase expectedCase, DateTimeOffset now)
    {
        var (Phase, CaseId) = CurrentAuthArchiveGenuineExecutionCases.Identity(expectedCase);
        if (seed is null || pins is null || trust is null) { throw CurrentAuthArchiveGenuineExecutionCases.Invalid(); }
        CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        if (seed.Kind != "current-auth-genuine-archive-component-seed-v1" || seed.OperationId == Guid.Empty ||
            seed.CaseId != CaseId || seed.AcceptedSourceCommitSha is not { Length: 40 } ||
            !seed.AcceptedSourceCommitSha.All(char.IsAsciiHexDigitLower) || seed.AuthOwnerCommitSha != ApprovedCurrentAuthSchema.AuthServiceCommit ||
            seed.OwnerPinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 || seed.ClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 ||
            new[] { seed.SourceSchemaPlanSha256, seed.DefinitionPrecursorSha256, seed.PrecursorSubjectSha256,
                seed.ParentRunBindingSha256, seed.TestAssemblySha256, seed.ConsoleAssemblySha256, seed.CoreAssemblySha256 }
                .Any(value => value is null || !CurrentAuthRepairPermit.HashShape(value)) ||
            seed.SigningPinsSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(pins) || seed.KeyId != pins.ReviewKeyId ||
            now.Offset != TimeSpan.Zero || seed.IssuedAtUtc.Offset != TimeSpan.Zero || seed.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            seed.IssuedAtUtc > now || seed.ExpiresAtUtc <= now || seed.ExpiresAtUtc <= seed.IssuedAtUtc ||
            seed.ExpiresAtUtc - seed.IssuedAtUtc > TimeSpan.FromMinutes(8) || string.IsNullOrWhiteSpace(seed.Signature))
        { throw CurrentAuthArchiveGenuineExecutionCases.Invalid(); }
        try
        {
            if (!trust.Verify(seed.KeyId, CurrentAuthArchiveComponentBootstrap.SeedPayload(seed), Convert.FromBase64String(seed.Signature)))
            { throw CurrentAuthArchiveGenuineExecutionCases.Invalid(); }
        }
        catch (FormatException) { throw CurrentAuthArchiveGenuineExecutionCases.Invalid(); }
    }
}
