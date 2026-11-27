using System.Security.Cryptography;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DualTargetCapturedRelayHashTests
{
    [Fact]
    public void Canonical_lower_ascii_hash_accepts_only_the_actual_fixed_digest()
    {
        byte[] digest = SHA256.HashData("synthetic fixed tunnel configuration"u8);
        string expected = Convert.ToHexStringLower(digest);
        Assert.True(DualTargetCapturedDeltaRelay.MatchesTunnelHash(expected, digest));
        byte[] changed = digest.ToArray(); changed[0] ^= 1;
        Assert.False(DualTargetCapturedDeltaRelay.MatchesTunnelHash(expected, changed));
        Assert.False(DualTargetCapturedDeltaRelay.MatchesTunnelHash(expected, digest.AsSpan(1)));
        Assert.False(DualTargetCapturedDeltaRelay.MatchesTunnelHash(expected.ToUpperInvariant(), digest));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("not-a-digest")]
    [InlineData("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffｆ")]
    public void Malformed_supplied_hash_never_becomes_equal_through_case_normalization(string? expected)
    {
        Assert.False(DualTargetCapturedDeltaRelay.MatchesTunnelHash(expected, new byte[32]));
    }
}
