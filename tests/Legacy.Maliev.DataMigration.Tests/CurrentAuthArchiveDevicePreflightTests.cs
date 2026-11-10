using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Synthetic contract tests only; no native physical-device observation is claimed.
public sealed class CurrentAuthArchiveDevicePreflightTests
{
    private static readonly string[] ExpectedEnvironmentKeys = ["SystemRoot", "WINDIR"];
    [Fact]
    public void Initial_request_contains_no_completed_scope_future_proof_or_device_claim()
    {
        var request = Request(DateTimeOffset.UtcNow);
        CurrentAuthLocalSessionArchiveDeviceProcess.RequirePreflight(request, request.CapturedAtUtc);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(request);
        using var json = JsonDocument.Parse(bytes);
        foreach (string name in new[] { "Scope", "RecoveryDeviceProofSha256", "ComponentSubject", "First", "Second", "Executable" })
        { Assert.False(json.RootElement.TryGetProperty(name, out _)); }
        string substituted = System.Text.Encoding.UTF8.GetString(bytes).TrimEnd('}') + ",\"Scope\":null}";
        _ = Assert.Throws<JsonException>(() => MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveDevicePreflightRequest>(System.Text.Encoding.UTF8.GetBytes(substituted)));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("source")]
    [InlineData("paths")]
    public void Explicit_json_null_cannot_escape_as_a_null_reference(string fault)
    {
        var request = Request(DateTimeOffset.UtcNow);
        string json = JsonSerializer.Serialize(request);
        json = fault switch
        {
            "null" => "null",
            "source" => json.Replace("\"SourceCommitSha\":\"" + request.SourceCommitSha + "\"", "\"SourceCommitSha\":null", StringComparison.Ordinal),
            _ => json.Replace(JsonSerializer.Serialize(request.Paths), "null", StringComparison.Ordinal),
        };
        // Decoder or policy rejection are both fail-closed contract outcomes.
        Exception? rejection = Record.Exception(() =>
        {
            var decoded = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveDevicePreflightRequest>(System.Text.Encoding.UTF8.GetBytes(json));
            CurrentAuthLocalSessionArchiveDeviceProcess.RequirePreflight(decoded, request.CapturedAtUtc);
        });
        Assert.True(rejection is JsonException or MigrationExecutionException);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveDeviceProcess.RequirePreflight(
            fault == "null" ? null! : fault == "source" ? request with { SourceCommitSha = null! } : request with { Paths = null! }, request.CapturedAtUtc));
    }

    [Theory]
    [InlineData("domain")]
    [InlineData("operation")]
    [InlineData("source")]
    [InlineData("null-source")]
    [InlineData("binding")]
    [InlineData("target")]
    [InlineData("same-binding")]
    [InlineData("same-target")]
    [InlineData("future")]
    [InlineData("expired")]
    [InlineData("long-lease")]
    [InlineData("offset")]
    [InlineData("same-root")]
    [InlineData("relative-root")]
    [InlineData("outside-path")]
    [InlineData("duplicate-path")]
    public void Invalid_initial_operands_reject_without_native_calls(string fault)
    {
        var request = Request(DateTimeOffset.UtcNow);
        var changed = fault switch
        {
            "domain" => request with { Domain = "completed-scope" },
            "operation" => request with { OperationId = Guid.Empty },
            "source" => request with { SourceCommitSha = "unaccepted" },
            "null-source" => request with { SourceCommitSha = null! },
            "binding" => request with { LocalRunBindingSha256 = "substituted" },
            "target" => request with { ProductionTargetObservationSha256 = "substituted" },
            "same-binding" => request with { ProductionRunBindingSha256 = request.LocalRunBindingSha256 },
            "same-target" => request with { ProductionTargetObservationSha256 = request.LocalTargetObservationSha256 },
            "future" => request with { CapturedAtUtc = request.CapturedAtUtc.AddTicks(1) },
            "expired" => request with { ExpiresAtUtc = request.CapturedAtUtc },
            "long-lease" => request with { ExpiresAtUtc = request.CapturedAtUtc.AddMinutes(1).AddTicks(1) },
            "offset" => request with { CapturedAtUtc = request.CapturedAtUtc.ToOffset(TimeSpan.FromHours(7)) },
            "same-root" => request with { SecondRoot = request.FirstRoot },
            "relative-root" => request with { FirstRoot = "relative" },
            "outside-path" => request with { Paths = request.Paths with { FirstCiphertext = Path.Combine(request.SecondRoot, "outside.json") } },
            _ => request with { Paths = request.Paths with { RecoveryPrivateKey = request.Paths.FirstCiphertext } },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveDeviceProcess.RequirePreflight(changed, request.CapturedAtUtc));
    }

    [Theory]
    [InlineData("operation")]
    [InlineData("source")]
    [InlineData("owner")]
    [InlineData("binding")]
    [InlineData("target")]
    [InlineData("paths")]
    [InlineData("old")]
    [InlineData("future")]
    [InlineData("same-device")]
    public void Returned_proof_must_bind_exact_operands_and_distinct_physical_devices(string fault)
    {
        var request = Request(DateTimeOffset.UtcNow);
        var first = Device(1, 'a'); var second = Device(2, 'b');
        var proof = new CurrentAuthArchiveDeviceProof("Legacy.Maliev.CurrentAuth.ArchivePhysicalDevices.v1", request.OperationId,
            request.SourceCommitSha, CurrentAuthRepairPermit.OwnerPinsSha256, request.LocalRunBindingSha256, request.ProductionRunBindingSha256,
            request.LocalTargetObservationSha256, request.ProductionTargetObservationSha256, request.Paths, first, second, request.CapturedAtUtc);
        CurrentAuthLocalSessionArchiveDeviceProcess.RequirePreflightProof(proof, request, request.CapturedAtUtc);
        var changed = fault switch
        {
            "operation" => proof with { OperationId = Guid.NewGuid() },
            "source" => proof with { SourceCommitSha = new('f', 40) },
            "owner" => proof with { OwnerPinsSha256 = new('f', 64) },
            "binding" => proof with { ProductionRunBindingSha256 = new('f', 64) },
            "target" => proof with { LocalTargetObservationSha256 = new('f', 64) },
            "paths" => proof with { Paths = proof.Paths with { FirstCiphertext = proof.Paths.FirstCiphertext + ".substituted" } },
            "old" => proof with { ObservedAtUtc = request.CapturedAtUtc.AddTicks(-1) },
            "future" => proof with { ObservedAtUtc = request.CapturedAtUtc.AddTicks(1) },
            _ => proof with { Second = first },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveDeviceProcess.RequirePreflightProof(changed, request, request.CapturedAtUtc));
    }

    [Fact]
    public void Child_start_allows_only_two_fixed_routes_and_structured_operands()
    {
        string path = Path.Combine(Path.GetTempPath(), "preflight.json"), hash = new('a', 64);
        var start = CurrentAuthLocalSessionArchiveDeviceProcess.StartInfo(path, hash, CurrentAuthLocalSessionArchiveDeviceProcess.PreflightCommand);
        Assert.Equal(new[] { CurrentAuthLocalSessionArchiveDeviceProcess.PreflightCommand, path, hash }, start.ArgumentList);
        Assert.Equal((path, hash), MigrationConsole.RequireArchiveDevicePreflightInvocation(start.ArgumentList.ToArray()));
        Assert.Equal(ExpectedEnvironmentKeys, start.Environment.Keys.Order(StringComparer.Ordinal));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveDeviceProcess.StartInfo(path, hash, "arbitrary"));
        _ = Assert.Throws<CommandLineException>(() => MigrationConsole.RequireArchiveDevicePreflightInvocation([CurrentAuthLocalSessionArchiveDeviceProcess.Command, path, hash]));
        _ = Assert.Throws<CommandLineException>(() => MigrationConsole.RequireArchiveDevicePreflightInvocation([CurrentAuthLocalSessionArchiveDeviceProcess.PreflightCommand, path, hash, "extra"]));
    }

    [Fact]
    public async Task Precancelled_preflight_starts_no_child_or_file_operation()
    {
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CurrentAuthLocalSessionArchiveDeviceProcess.ObservePreflightAsync(null!, null!, null!, cancellation.Token));
    }

    private static CurrentAuthArchivePhysicalDevice Device(uint number, char serial)
    {
        return new(@"\\?\Volume{" + number.ToString(System.Globalization.CultureInfo.InvariantCulture) + @"}\",
            number, 1048576, 100000000, 17, new string(serial, 64));
    }

    private static CurrentAuthArchiveDevicePreflightRequest Request(DateTimeOffset now)
    {
        string first = Path.Combine(Path.GetTempPath(), "synthetic-device-first");
        string second = Path.Combine(Path.GetTempPath(), "synthetic-device-second");
        return new("Legacy.Maliev.CurrentAuth.ArchiveDevicePreflight.v1", Guid.NewGuid(), new('a', 40), new('a', 64), new('b', 64),
            new('c', 64), new('d', 64), new(Path.Combine(first, "cipher.json"), Path.Combine(second, "cipher.json"),
                Path.Combine(first, "recovery.pkcs8"), Path.Combine(second, "recovery.pkcs8")), first, second, now, now.AddSeconds(50));
    }
}
