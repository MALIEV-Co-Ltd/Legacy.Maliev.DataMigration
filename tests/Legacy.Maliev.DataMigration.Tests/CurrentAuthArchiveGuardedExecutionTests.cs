using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

// Input-contract regressions only. These methods produce no archive execution proof.
public sealed class CurrentAuthArchiveGuardedExecutionTests
{
    private static readonly DateTimeOffset Now = new(2031, 1, 1, 1, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Host_source_input_preserves_exact_bytes_and_canonical_plan_identity()
    {
        FreshSchemaPlan plan = UnitPlan();
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(plan);
        FreshSchemaPlan actual = CurrentAuthArchiveFixtureSource.DecodeHeld(bytes, Hash(bytes), plan.SourceCommitSha, Now);
        Assert.Equal(SchemaPlanCanonicalizer.ComputeSha256(plan), SchemaPlanCanonicalizer.ComputeSha256(actual));
        Assert.Equal(23, actual.Databases.Count);
        Assert.Equal(100, actual.Databases.Sum(database => database.Tables.Count));
    }

    [Theory]
    [InlineData("bytes")]
    [InlineData("commit")]
    [InlineData("stale")]
    [InlineData("missing-database")]
    [InlineData("physical-hash")]
    [InlineData("mixed-profile")]
    public void Host_source_input_rejects_wrong_or_incomplete_operands(string fault)
    {
        FreshSchemaPlan plan = UnitPlan();
        plan = fault switch
        {
            "stale" => plan with { CapturedAtUtc = Now.AddHours(-3) },
            "missing-database" => plan with { Databases = plan.Databases.Skip(1).ToArray() },
            "physical-hash" => plan with { Databases = plan.Databases.Select((database, index) => index == 0 ? database with { TargetSchemaSha256 = new string('0', 64) } : database).ToArray() },
            "mixed-profile" => plan with { Databases = plan.Databases.Select(database => database.Database == "CustomerIdentity" ? database with { TargetExtensionProfile = null } : database).ToArray() },
            _ => plan,
        };
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(plan);
        string hash = fault == "bytes" ? new string('0', 64) : Hash(bytes);
        string commit = fault == "commit" ? new string('b', 40) : plan.SourceCommitSha;
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFixtureSource.DecodeHeld(bytes, hash, commit, Now));
    }

    [Theory]
    [InlineData(false, 26)]
    [InlineData(true, 49)]
    public void Disposable_target_settings_fix_archive_identity_inventory_and_resource_caps(bool comparison, int databases)
    {
        Guid operation = Guid.Parse("c7c3fe6e-1b37-41d7-907c-611f6c3653c8");
        var settings = CurrentAuthArchiveFixtureTarget.Settings(operation, comparison, new string('a', 64), Now);
        Assert.Equal("legacy-delta-proof-" + operation.ToString("N") + (comparison ? "-comparison" : ""), settings.Name);
        Assert.Equal("current-auth-local-session-archive-proof", settings.Labels["codex.repair.purpose"]);
        Assert.Equal(operation.ToString("D"), settings.Labels["codex.repair.operation"]);
        Assert.Equal(new string('a', 64), settings.Labels["codex.repair.run-binding"]);
        Assert.Equal(3, settings.Labels.Count);
        Assert.Equal(512L * 1024 * 1024, settings.MemoryBytes);
        Assert.Equal(750_000_000, settings.NanoCpus);
        Assert.Equal(Now.AddMinutes(8), settings.ExpiresAtUtc);
        Assert.Equal(databases, settings.Databases.Count);
        Assert.True(ReviewedProductionRepairInventory.MatchesKeys(CurrentAuthLocalSessionArchivePolicy.InventoryProfile(comparison), settings.Databases));
        Assert.Equal("postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382", settings.Image);
    }

    [Theory]
    [InlineData("operation")]
    [InlineData("binding")]
    [InlineData("non-utc")]
    public void Disposable_target_settings_reject_unbound_identity_or_clock(string fault)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFixtureTarget.Settings(
            fault == "operation" ? Guid.Empty : Guid.NewGuid(), false,
            fault == "binding" ? "unbound" : new string('a', 64),
            fault == "non-utc" ? Now.ToOffset(TimeSpan.FromHours(7)) : Now));
    }
    [Theory]
    [InlineData("running", "127.0.0.1", "54321", 0, 54321)]
    [InlineData("exited", "127.0.0.1", "54321", 0, 54321)]
    [InlineData("exited", "127.0.0.1", "", 54321, 54321)]
    [InlineData("created", "127.0.0.1", "", 0, 0)]
    public void Actual_transport_mapping_is_retained_even_without_successful_start_return(string status, string host, string mapped, int retained, int expected)
    {
        using var metadata = Transport(status, host, mapped);
        Assert.Equal(expected, CurrentAuthArchiveFixtureTarget.RecoverTransport(metadata.RootElement, retained));
    }

    [Theory]
    [InlineData("running", "127.0.0.1", "", 0)]
    [InlineData("exited", "127.0.0.1", "", 0)]
    [InlineData("running", "0.0.0.0", "54321", 0)]
    [InlineData("running", "127.0.0.1", "54322", 54321)]
    public void Unknown_or_changed_transport_cannot_be_treated_as_absent(string status, string host, string mapped, int retained)
    {
        using var metadata = Transport(status, host, mapped);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFixtureTarget.RecoverTransport(metadata.RootElement, retained));
    }

    private static JsonDocument Transport(string status, string host, string mapped)
    {
        object[] ports = mapped.Length == 0 ? [] : [new { HostIp = host, HostPort = mapped }];
        return JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            State = new { Status = status, Running = status == "running", StartedAt = status == "created" ? "0001-01-01T00:00:00Z" : "2031-01-01T00:00:00Z" },
            HostConfig = new { PortBindings = new Dictionary<string, object> { ["5432/tcp"] = new[] { new { HostIp = "127.0.0.1", HostPort = "" } } } },
            NetworkSettings = new { Ports = new Dictionary<string, object> { ["5432/tcp"] = ports } },
        }));
    }
    // Synthetic structural operands test only the importer; never exported as a source capture.
    private static FreshSchemaPlan UnitPlan()
    {
        return CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3) with { CapturedAtUtc = Now.AddMinutes(-1) };
    }

    private static string Hash(byte[] bytes)
    {
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }
}


