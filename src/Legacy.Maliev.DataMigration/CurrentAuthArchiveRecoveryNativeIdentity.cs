namespace Legacy.Maliev.DataMigration;

// Versioned opened-handle identity; the wire field remains a string, never a path identity.
internal static class CurrentAuthArchiveRecoveryNativeIdentity
{
    private const string Version = "current-auth-recovery-ntfs-file-v1";
    internal static string Observe(FileStream stream)
    {
        if (!OperatingSystem.IsWindows()) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
        var identity = WindowsRunFileIdentity.Observe(stream.SafeFileHandle);
        string value = Version + "|" + identity.Volume + "|" + identity.ObjectId;
        return IsValid(value) ? value : throw CurrentAuthArchiveRecoveryV2.Invalid();
    }

    internal static bool IsValid(string? value)
    {
        if (value is null || value.Length > 160) { return false; }
        string[] fields = value.Split('|');
        if (fields.Length != 3 || fields[0] != Version) { return false; }
        string[] volume = fields[1].Split(':');
        const string objectPrefix = "file-id-128:";
        return volume.Length == 3 && volume[0] == "windows-ntfs" && Guid.TryParseExact(volume[1], "D", out Guid id) && id != Guid.Empty &&
            Hex(volume[2], 16) && fields[2].StartsWith(objectPrefix, StringComparison.Ordinal) && Hex(fields[2][objectPrefix.Length..], 32);
    }

    private static bool Hex(string value, int length)
    {
        return value.Length == length && value.Any(character => character != '0') &&
        value.All(character => char.IsAsciiDigit(character) || character is >= 'a' and <= 'f');
    }
}
