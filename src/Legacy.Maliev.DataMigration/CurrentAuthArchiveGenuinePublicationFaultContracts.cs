namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAuthArchiveGenuineSlotWitness(Guid OperationId, string ScopeSha256, string AuthorizationSha256,
    string LocalBindingSha256, string ComparisonBindingSha256, string Slot, string OriginalPath, string VolumeIdentity,
    string FileIdentity, long Bytes, bool NativeOwnerAndSingleLinkVerified, bool DeleteOnClose, int NativeCreateError,
    DateTimeOffset CreatedAtUtc, DateTimeOffset FailedAtUtc, DateTimeOffset RemovedAtUtc, bool VerifiedAbsent);
internal sealed record CurrentAuthArchiveGenuinePublicationFailureFacts(CurrentAuthArchiveGenuineExecutionCase Case,
    CurrentAuthArchiveGenuineHelperClaims Claims, string ActualExceptionType, int ActualHResult,
    CurrentAuthArchiveFleet LocalBefore, CurrentAuthArchiveFleet ComparisonBefore, DateTimeOffset BeganAtUtc, DateTimeOffset FailedAtUtc);

internal static class CurrentAuthArchiveGenuinePublicationFault
{
    internal static bool IsCase(CurrentAuthArchiveGenuineExecutionCase value)
    {
        return value is
        CurrentAuthArchiveGenuineExecutionCase.PreparedPublication or CurrentAuthArchiveGenuineExecutionCase.TerminalPublication;
    }

    internal static string Slot(CurrentAuthArchiveGenuineExecutionCase value)
    {
        return value switch
        {
            CurrentAuthArchiveGenuineExecutionCase.PreparedPublication => "prepared",
            CurrentAuthArchiveGenuineExecutionCase.TerminalPublication => "committed-readback",
            CurrentAuthArchiveGenuineExecutionCase.NativeComplete => throw new NotImplementedException(),
            CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost => throw new NotImplementedException(),
            CurrentAuthArchiveGenuineExecutionCase.HostUnprobedSdk => throw new NotImplementedException(),
            CurrentAuthArchiveGenuineExecutionCase.LocalTrust => throw new NotImplementedException(),
            CurrentAuthArchiveGenuineExecutionCase.ExactReviewedDelete => throw new NotImplementedException(),
            CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift => throw new NotImplementedException(),
            CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift => throw new NotImplementedException(),
            CurrentAuthArchiveGenuineExecutionCase.SequenceDrift => throw new NotImplementedException(),
            CurrentAuthArchiveGenuineExecutionCase.ProductionDrift => throw new NotImplementedException(),
            CurrentAuthArchiveGenuineExecutionCase.FirstOnlyDecryptInsertReadback => throw new NotImplementedException(),
            CurrentAuthArchiveGenuineExecutionCase.SecondOnlyDecryptInsertReadback => throw new NotImplementedException(),
            _ => throw CurrentAuthArchiveGenuineExecutionCases.Invalid(),
        };
    }

    internal static void RequireWitness(CurrentAuthArchiveGenuineSlotWitness witness, CurrentAuthArchiveScope scope,
        string authorization, CurrentAuthArchiveGenuineExecutionCase value, DateTimeOffset began, DateTimeOffset now)
    {
        if (scope.ComponentSubject?.Seed.CaseId != CurrentAuthArchiveGenuineExecutionCases.Identity(value).CaseId ||
            witness.OperationId != scope.OperationId || witness.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(scope) ||
            witness.AuthorizationSha256 != authorization || witness.LocalBindingSha256 != scope.LocalObservationPolicy.RunBindingSha256 ||
            witness.ComparisonBindingSha256 != scope.ProductionObservationPolicy.RunBindingSha256 || witness.Slot != Slot(value) ||
            !Path.IsPathFullyQualified(witness.OriginalPath) || Path.GetFileName(witness.OriginalPath) != $"{scope.OperationId:D}-Auth-session-archive-{Slot(value)}.json" ||
            Path.GetDirectoryName(witness.OriginalPath) != Path.GetDirectoryName(scope.Paths.FirstCiphertext) ||
            !VolumeIdentity(witness.VolumeIdentity) || !FileIdentity(witness.FileIdentity) ||
            witness.Bytes != 0 || !witness.NativeOwnerAndSingleLinkVerified || !witness.DeleteOnClose || !witness.VerifiedAbsent ||
            witness.NativeCreateError is not (5 or 32 or 80 or 183) || witness.CreatedAtUtc < began || witness.FailedAtUtc < witness.CreatedAtUtc ||
            witness.RemovedAtUtc < witness.FailedAtUtc || witness.RemovedAtUtc > now ||
            began.Offset != TimeSpan.Zero || now.Offset != TimeSpan.Zero || began > now ||
            witness.CreatedAtUtc.Offset != TimeSpan.Zero || witness.FailedAtUtc.Offset != TimeSpan.Zero || witness.RemovedAtUtc.Offset != TimeSpan.Zero)
        { throw CurrentAuthArchiveGenuineExecutionCases.Invalid(); }
    }
    private static bool VolumeIdentity(string value)
    {
        const string prefix = "windows-ntfs:";
        return value.Length == prefix.Length + 53 && value.StartsWith(prefix, StringComparison.Ordinal) &&
            Guid.TryParseExact(value.AsSpan(prefix.Length, 36), "D", out Guid volume) && volume != Guid.Empty &&
            value[prefix.Length + 36] == ':' && HexNonZero(value.AsSpan(prefix.Length + 37));
    }
    private static bool FileIdentity(string value)
    {
        const string prefix = "file-id-128:";
        return value.Length == prefix.Length + 32 && value.StartsWith(prefix, StringComparison.Ordinal) &&
            HexNonZero(value.AsSpan(prefix.Length));
    }
    private static bool HexNonZero(ReadOnlySpan<char> value)
    {
        bool nonzero = false;
        foreach (char character in value)
        {
            if (!char.IsAsciiHexDigitLower(character)) { return false; }
            nonzero |= character != '0';
        }
        return nonzero;
    }
}
