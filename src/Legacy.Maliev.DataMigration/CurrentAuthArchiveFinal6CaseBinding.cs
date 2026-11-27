namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAuthArchiveFinal6CaseBinding(string Kind, string AudienceSha256, string Phase, string CaseId,
    Guid OperationId, string SeedSha256, string OriginalSourceFullSha256, string DefinitionSha256,
    DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);

internal static class CurrentAuthArchiveFinal6CasePolicy
{
    internal const string Domain = "Legacy.Maliev.CurrentAuth.Final6.CaseBinding.v1";
    internal const string Kind = "current-auth-archive-final6-case-binding-v1";

    internal static CurrentAuthArchiveFinal6CaseBinding Require(CurrentAuthArchiveClaim claim, CurrentAuthArchiveClaim audienceClaim,
        CurrentAuthArchiveComponentBootstrapSeed seed, CurrentAuthArchiveFinal6SourceEvidence source, string definitionSha256,
        string phase, string caseId, CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        _ = CurrentAuthArchiveGenuineCases.Require(phase, caseId); // Fixed identities only; this makes no method-availability claim.
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Audience>(audienceClaim,
            CurrentAuthArchiveFinal6AudiencePolicy.Domain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        CurrentAuthArchiveFinal6AudiencePolicy.Require(audience, pins, now);
        CurrentAuthArchiveFinal6Source.Require(source, audience.AcceptedCommitSha, audience.SourceIdentitySha256, audience.SourceDefinitionSha256, now);
        var binding = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6CaseBinding>(claim, Domain,
            pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        RequireHeader(binding, seed, CurrentAuthLocalSessionArchivePolicy.Hash(audienceClaim), source.Capture.FullPlanSha256, definitionSha256, phase, caseId, now);
        if (seed.Kind != "current-auth-genuine-archive-component-seed-v1" || seed.AcceptedSourceCommitSha != audience.AcceptedCommitSha ||
            seed.SourceSchemaPlanSha256 != source.Capture.FullPlanSha256 || seed.AuthOwnerCommitSha != ApprovedCurrentAuthSchema.AuthServiceCommit ||
            seed.OwnerPinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 || seed.ClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 ||
            seed.TestAssemblySha256 != audience.TestsImageSha256 || seed.ConsoleAssemblySha256 != audience.ConsoleImageSha256 || seed.CoreAssemblySha256 != audience.CoreImageSha256 ||
            seed.SigningPinsSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(pins) || seed.KeyId != pins.ReviewKeyId ||
            seed.IssuedAtUtc.Offset != TimeSpan.Zero || seed.ExpiresAtUtc.Offset != TimeSpan.Zero || seed.IssuedAtUtc > now || seed.ExpiresAtUtc <= now ||
            seed.ExpiresAtUtc <= seed.IssuedAtUtc || seed.ExpiresAtUtc - seed.IssuedAtUtc > TimeSpan.FromMinutes(8) ||
            seed.ExpiresAtUtc > audience.ExpiresAtUtc || string.IsNullOrWhiteSpace(seed.Signature) ||
            new[] { seed.SourceSchemaPlanSha256, seed.DefinitionPrecursorSha256, seed.PrecursorSubjectSha256, seed.ParentRunBindingSha256 }
                .Any(value => !CurrentAuthRepairPermit.HashShape(value))) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        try
        {
            if (!trust.Verify(seed.KeyId, CurrentAuthArchiveComponentBootstrap.SeedPayload(seed), Convert.FromBase64String(seed.Signature)))
            { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        }
        catch (FormatException) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        return binding;
    }

    internal static void RequireHeader(CurrentAuthArchiveFinal6CaseBinding value, CurrentAuthArchiveComponentBootstrapSeed seed,
        string audienceSha256, string originalSourceSha256, string definitionSha256, string phase, string caseId, DateTimeOffset now)
    {
        _ = CurrentAuthArchiveGenuineCases.Require(phase, caseId);
        if (value.Kind != Kind || value.AudienceSha256 != audienceSha256 || value.Phase != phase || value.CaseId != caseId || seed.CaseId != caseId ||
            seed.OperationId == Guid.Empty || value.OperationId != seed.OperationId || value.SeedSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(seed) ||
            value.OriginalSourceFullSha256 != originalSourceSha256 || value.DefinitionSha256 != definitionSha256 ||
            new[] { audienceSha256, originalSourceSha256, definitionSha256 }.Any(hash => !CurrentAuthRepairPermit.HashShape(hash)) ||
            value.IssuedAtUtc.Offset != TimeSpan.Zero || value.ExpiresAtUtc.Offset != TimeSpan.Zero || now.Offset != TimeSpan.Zero ||
            value.IssuedAtUtc < seed.IssuedAtUtc || value.IssuedAtUtc > now || value.ExpiresAtUtc <= now ||
            value.ExpiresAtUtc <= value.IssuedAtUtc || value.ExpiresAtUtc > seed.ExpiresAtUtc) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
    }
}
