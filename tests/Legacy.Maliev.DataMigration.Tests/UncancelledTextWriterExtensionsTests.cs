using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class UncancelledTextWriterExtensionsTests
{
    [Fact]
    public async Task OutputRetainsCustomStringOverloadDispatch()
    {
        using var writer = new TrackingWriter();

        await writer.WriteUncancelledAsync("message");
        await writer.WriteLineUncancelledAsync("status");

        Assert.Equal(["write:message", "line:status"], writer.Calls);
    }

    [Fact]
    public async Task OutputPropagatesCustomWriterFailure()
    {
        using var writer = new TrackingWriter { Fail = true };

        await Assert.ThrowsAsync<IOException>(() => writer.WriteLineUncancelledAsync("status"));
    }

    private sealed class TrackingWriter : StringWriter
    {
        public List<string> Calls { get; } = [];
        public bool Fail { get; init; }

        public override Task WriteAsync(string? value)
        {
            Calls.Add($"write:{value}");
            return Task.CompletedTask;
        }

        public override Task WriteLineAsync(string? value)
        {
            if (Fail) return Task.FromException(new IOException("sink failed"));
            Calls.Add($"line:{value}");
            return Task.CompletedTask;
        }
    }
}
