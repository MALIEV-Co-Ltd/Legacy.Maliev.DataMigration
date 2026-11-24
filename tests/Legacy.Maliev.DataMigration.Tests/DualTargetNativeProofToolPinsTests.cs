using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DualTargetNativeProofToolPinsTests
{
    [Fact]
    public void Complete_reviewed_fixed_inventory_is_required()
    { DualTargetNativeProofTools.RequirePins(Pins(), Commit, Names, Now); }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    public void Observed_unaccepted_or_incomplete_tool_pins_refuse(int mutation)
    {
        DualTargetNativeProofToolPins pins = Pins();
        string[] actual = Names;
        switch (mutation)
        {
            case 0: pins = pins with { Kind = "dual-target-native-proof-tools-observation-NOT-ACCEPTED" }; break;
            case 1: pins = pins with { AcceptedMain = new('b', 40) }; break;
            case 2: pins = pins with { Version = "17.9" }; break;
            case 3: pins = pins with { ExpiresAtUtc = Now }; break;
            case 4: pins = pins with { ExpiresAtUtc = Now.AddHours(13) }; break;
            case 5: pins = pins with { Files = pins.Files.Where(x => x.Key != "pg_restore.exe").ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal) }; actual = ["pg_dump.exe", "libpq.dll"]; break;
            case 6: actual = [.. Names, "injected.dll"]; break;
            case 7: pins = pins with { Files = pins.Files.ToDictionary(x => x.Key, _ => "not-a-hash", StringComparer.Ordinal) }; break;
            default: throw new InvalidOperationException();
        }
        _ = Assert.Throws<MigrationExecutionException>(() => DualTargetNativeProofTools.RequirePins(pins, Commit, actual, Now));
    }

    private const string Commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 0, 0, 0, TimeSpan.Zero);
    private static readonly string[] Names = ["pg_dump.exe", "pg_restore.exe", "libpq.dll"];
    private static DualTargetNativeProofToolPins Pins()
    {
        return new("dual-target-native-proof-pg18-tools-v1", Commit, "18.6",
        Names.ToDictionary(x => x, _ => new string('a', 64), StringComparer.Ordinal), Now.AddHours(1));
    }
}
