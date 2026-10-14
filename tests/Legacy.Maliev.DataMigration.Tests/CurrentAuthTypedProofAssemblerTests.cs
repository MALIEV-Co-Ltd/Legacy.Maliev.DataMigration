using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

/// <summary>Pure negative fixtures. None is an executed native proof or signed host observation.</summary>
public sealed class CurrentAuthTypedProofAssemblerTests
{
    private const ulong GiB = 1024UL * 1024 * 1024;
    private static readonly DateTimeOffset Start = new(2026, 10, 13, 0, 0, 0, TimeSpan.Zero);
    private static CurrentAuthTypedHostExit Host()
    {
        return new("synthetic-unit-fixture-not-native-evidence", new('a', 40), new('b', 64),
        "definition", @"D:\synthetic\Tests.dll", new('c', 64), new('d', 64), new('e', 64),
        @"C:\Program Files\dotnet\dotnet.exe", new('f', 64), 1, Start, Start, Start.AddSeconds(2), Start.AddMinutes(2),
        0, true, true, false, new(@"D:\synthetic\actual.trx", new('1', 64)), new(@"D:\synthetic\capacity.json", new('2', 64)), "synthetic", null);
    }

    [Fact]
    public void Capacity_requires_real_initial_admission_and_complete_finite_coverage()
    {
        var host = Host();
        CurrentAuthTypedProofAssembler.RequireCapacity([new(Start, 3 * GiB, GiB), new(Start.AddSeconds(1), GiB, GiB), new(Start.AddSeconds(2), GiB, GiB)], host);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthTypedProofAssembler.RequireCapacity(
            [new(Start, (3 * GiB) - 1, GiB), new(Start.AddSeconds(2), GiB, GiB)], host));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthTypedProofAssembler.RequireCapacity(
            [new(Start.AddMilliseconds(1), 3 * GiB, GiB), new(Start.AddSeconds(2), GiB, GiB)], host));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthTypedProofAssembler.RequireCapacity(
            [new(Start, 3 * GiB, GiB), new(Start.AddSeconds(1), GiB, GiB)], host));
    }

    [Fact]
    public void Capacity_rejects_gaps_nonmonotonic_times_changed_RSS_and_nonUTC()
    {
        var host = Host() with { ExitedAtUtc = Start.AddSeconds(4) };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthTypedProofAssembler.RequireCapacity(
            [new(Start, 3 * GiB, GiB), new(Start.AddSeconds(4), GiB, GiB)], host));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthTypedProofAssembler.RequireCapacity(
            [new(Start, 3 * GiB, GiB), new(Start.AddSeconds(2), GiB, GiB), new(Start.AddSeconds(1), GiB, GiB), new(Start.AddSeconds(4), GiB, GiB)], host));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthTypedProofAssembler.RequireCapacity(
            [new(Start, 3 * GiB, GiB), new(Start.AddSeconds(2), GiB, (5 * GiB) + 1), new(Start.AddSeconds(4), GiB, GiB)], host));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthTypedProofAssembler.RequireCapacity(
            [new(Start, 3 * GiB, GiB), new(Start.AddSeconds(2).ToOffset(TimeSpan.FromHours(7)), GiB, GiB), new(Start.AddSeconds(4), GiB, GiB)], host));
    }

    [Fact]
    public void Host_signature_payload_binds_actual_images_exit_TRX_and_capacity()
    {
        var value = Host(); byte[] payload = CurrentAuthTypedProofAssembler.HostPayload(value);
        Assert.Equal(payload, CurrentAuthTypedProofAssembler.HostPayload(value with { Signature = "ignored-only-in-signing-payload" }));
        Assert.NotEqual(payload, CurrentAuthTypedProofAssembler.HostPayload(value with { ExitCode = 1 }));
        Assert.NotEqual(payload, CurrentAuthTypedProofAssembler.HostPayload(value with { ReadersSettled = false }));
        Assert.NotEqual(payload, CurrentAuthTypedProofAssembler.HostPayload(value with { TestAssemblySha256 = new('3', 64) }));
        Assert.NotEqual(payload, CurrentAuthTypedProofAssembler.HostPayload(value with { Trx = value.Trx with { Sha256 = new('4', 64) } }));
        Assert.NotEqual(payload, CurrentAuthTypedProofAssembler.HostPayload(value with { Capacity = value.Capacity with { Sha256 = new('5', 64) } }));
        Assert.NotEqual(payload, CurrentAuthTypedProofAssembler.HostPayload(value with { ProcessStartTimeUtc = Start.AddTicks(1) }));
    }
}
