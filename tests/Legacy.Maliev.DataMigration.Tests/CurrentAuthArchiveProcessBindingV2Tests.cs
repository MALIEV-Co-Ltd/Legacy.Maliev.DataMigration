using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveProcessBindingV2Tests
{
    [Theory]
    [InlineData("host", "ExitCode")]
    [InlineData("host", "OperationId")]
    [InlineData("cleanup", "OperationId")]
    [InlineData("cleanup", "SourceCommitSha")]
    [InlineData("cleanup", "RunSha256")]
    [InlineData("provider", "RequiredJobNonce")]
    [InlineData("vstest", "Nonce")]
    [InlineData("vstest", "SdkProcessId")]
    [InlineData("gate", "ProcessStartTimeUtc")]
    [InlineData("provider", "ProcessStartTimeUtc")]
    public void Cross_run_records_process_reuse_and_host_failure_cannot_satisfy_the_process_binding(string frame, string field)
    {
        Guid operation = Guid.NewGuid(); string source = new('a', 40), input = new('b', 64), runHash = new('c', 64), binding = new('d', 64);
        string nonce = Guid.NewGuid().ToString("N"); var began = new DateTimeOffset(2026, 11, 24, 0, 0, 0, TimeSpan.Zero);
        Dictionary<string, object?> Common(int pid, int start, int exit)
        {
            return new()
            {
                ["OperationId"] = operation,
                ["SourceCommitSha"] = source,
                ["RunSha256"] = runHash,
                ["Nonce"] = nonce,
                ["RequiredJobNonce"] = nonce,
                ["CaseInputSha256"] = input,
                ["ProcessId"] = pid,
                ["ProcessStartTimeUtc"] = began.AddSeconds(start),
                ["ExitedAtUtc"] = began.AddSeconds(exit),
                ["CleanupFailed"] = false,
                ["ExitCode"] = 0,
            };
        }

        var frames = new Dictionary<string, Dictionary<string, object?>>
        {
            ["run"] = new()
            {
                ["OperationId"] = operation,
                ["SourceCommitSha"] = source,
                ["Nonce"] = nonce,
                ["BeganAtUtc"] = began,
                ["ExpiresAtUtc"] = began.AddMinutes(8)
            },
            ["host"] = Common(10, 1, 9),
            ["provider"] = Common(13, 4, 6),
            ["vstest"] = Common(11, 2, 8),
            ["cleanup"] = Common(0, 0, 0),
            ["result"] = new() { ["SourceCommitSha"] = source, ["InputSha256"] = input },
            ["gate"] = new() { ["Nonce"] = nonce, ["ProcessId"] = 10, ["ProcessStartTimeUtc"] = began.AddSeconds(1), ["ControlBindingSha256"] = binding },
        };
        frames["provider"]["HarnessProcessId"] = 12; frames["provider"]["HarnessProcessStartTimeUtc"] = began.AddSeconds(3);
        frames["provider"]["StartedAtUtc"] = began.AddSeconds(4);
        frames["vstest"]["SdkProcessId"] = 10; frames["vstest"]["SdkProcessStartTimeUtc"] = began.AddSeconds(1);
        frames["cleanup"]["ObservedAtUtc"] = began.AddSeconds(10); frames["cleanup"]["ExpiresAtUtc"] = began.AddMinutes(8);
        frames["cleanup"]["PreservedUncertainResources"] = false; frames["cleanup"]["PhaseProofComplete"] = false;
        Require();
        frames[frame][field] = field switch
        {
            "ExitCode" => 1,
            "OperationId" => Guid.NewGuid(),
            "SdkProcessId" => 99,
            "ProcessStartTimeUtc" => began.AddSeconds(20),
            _ => new string('e', 64),
        };
        _ = Assert.Throws<MigrationExecutionException>(Require);
        void Require()
        {
            CurrentAuthArchiveProcessBindingV2.Require(Element("run"), Element("provider"), Element("vstest"), Element("host"),
            Element("cleanup"), Element("result"), Element("gate"), operation, source, input, runHash, binding, began, began.AddSeconds(11));
        }

        JsonElement Element(string name)
        {
            return JsonSerializer.SerializeToElement(frames[name]);
        }
    }
}
