namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAuthArchiveFinal6Audience(string Kind, Guid AudienceId, string AcceptedCommitSha,
    string SourceIdentitySha256, string SourceDefinitionSha256, string OwnerPinsSha256, string ClosureSha256,
    string CoreImageSha256, string ConsoleImageSha256, string TestsImageSha256, string SigningPinsSha256,
    string CaseInventorySha256, string IntendedLocalIdentitySha256, string IntendedComparisonIdentitySha256,
    string IntendedAuthRowsSha256, int IntendedAuthRows, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);

internal static class CurrentAuthArchiveFinal6AudiencePolicy
{
    internal const string Kind = "current-auth-archive-final6-audience-v1";
    internal const string Domain = "Legacy.Maliev.CurrentAuth.Final6.ArchiveProofAudience.v1";

    internal static void Require(CurrentAuthArchiveFinal6Audience value, CurrentAuthArchivePins pins, DateTimeOffset now)
    {
        if (value.Kind != Kind || value.AudienceId == Guid.Empty || value.AcceptedCommitSha.Length != 40 ||
            !value.AcceptedCommitSha.All(char.IsAsciiHexDigitLower) || value.OwnerPinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 ||
            value.ClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 || value.SigningPinsSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(pins) ||
            value.CaseInventorySha256 != CurrentAuthLocalSessionArchivePolicy.Hash(CurrentAuthArchiveGenuineCases.Inventory()) ||
            value.IntendedAuthRows is < 0 or > CurrentAuthLocalSessionArchivePolicy.MaximumRows ||
            new[] { value.SourceIdentitySha256, value.SourceDefinitionSha256, value.CoreImageSha256, value.ConsoleImageSha256,
                value.TestsImageSha256, value.IntendedLocalIdentitySha256, value.IntendedComparisonIdentitySha256, value.IntendedAuthRowsSha256 }
                .Any(hash => !CurrentAuthRepairPermit.HashShape(hash)) || value.IntendedLocalIdentitySha256 == value.IntendedComparisonIdentitySha256 ||
            now.Offset != TimeSpan.Zero || value.IssuedAtUtc.Offset != TimeSpan.Zero || value.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            value.IssuedAtUtc > now || value.ExpiresAtUtc <= now || value.ExpiresAtUtc <= value.IssuedAtUtc ||
            value.ExpiresAtUtc - value.IssuedAtUtc > TimeSpan.FromHours(12)) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
    }
}
