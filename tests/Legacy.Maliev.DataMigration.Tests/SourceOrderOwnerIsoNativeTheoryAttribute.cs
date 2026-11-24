namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SourceOrderOwnerIsoNativeTheoryAttribute : TheoryAttribute
{
    internal const string LedgerVariable = "MALIEV_SOURCE_ORDER_ISO_NATIVE_LEDGER";
    public SourceOrderOwnerIsoNativeTheoryAttribute()
    {
        Skip = SkipReason(OperatingSystem.IsWindows(), Environment.GetEnvironmentVariable(LedgerVariable));
    }

    internal static string? SkipReason(bool windows, string? ledger)
    {
        return !windows || ledger is null
                ? "NotExecuted: requires Windows and an explicitly admitted protected ISO native ledger; no native proof was executed."
                : null;
    }

    internal static string RequireLedger(string? ledger)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException(); }
        if (string.IsNullOrWhiteSpace(ledger) || !Path.IsPathFullyQualified(ledger) || !Directory.Exists(ledger))
        { throw new InvalidOperationException("source_order_iso_native_ledger_invalid"); }
        SecureLocalFile.EnsureOwnerOnlyDirectory(ledger);
        return ledger;
    }
}
