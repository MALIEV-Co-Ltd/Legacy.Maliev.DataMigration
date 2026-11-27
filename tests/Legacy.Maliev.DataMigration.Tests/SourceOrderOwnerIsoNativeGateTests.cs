namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SourceOrderOwnerIsoNativeGateTests
{
    [Theory]
    [InlineData(false, null)]
    [InlineData(false, "supplied-input")]
    [InlineData(true, null)]
    public void Absent_or_unsupported_input_is_explicitly_not_executed(bool windows, string? input)
    {
        string reason = SourceOrderOwnerIsoNativeTheoryAttribute.SkipReason(windows, input) ?? throw new InvalidOperationException("Expected explicit native skip.");
        Assert.StartsWith("NotExecuted:", reason);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("relative-ledger")]
    [InlineData("supplied-absolute-or-malformed-path")]
    public void Supplied_input_is_not_silently_skipped(string input)
    {
        Assert.Null(SourceOrderOwnerIsoNativeTheoryAttribute.SkipReason(true, input));
    }

    [WindowsLocalRunTheory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("relative-ledger")]
    public void Malformed_supplied_input_refuses_before_native_resource_creation(string input)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException(); }
        _ = Assert.Throws<InvalidOperationException>(() => SourceOrderOwnerIsoNativeTheoryAttribute.RequireLedger(input));
    }

    [WindowsLocalRunFact]
    public void Missing_supplied_directory_refuses_before_native_resource_creation()
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException(); }
        string absent = Path.Combine(Path.GetTempPath(), "iso-native-gate-absent-" + Guid.NewGuid().ToString("N"));
        Assert.False(Directory.Exists(absent));
        _ = Assert.Throws<InvalidOperationException>(() => SourceOrderOwnerIsoNativeTheoryAttribute.RequireLedger(absent));
    }
}
