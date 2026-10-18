using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static class Production181PipelineCommand
{
    internal const string Command = "production181-customer-components";
    internal static bool IsCommand(string command)
    {
        return command is Command or "production181-customer-host-child" or Production181InputRootInitializer.Command;
    }

    // Fixed two-argument routes only. There is no configurable command/SQL/process entry point.
    internal static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: true);
        if (args.Length != 2 || !Path.IsPathFullyQualified(args[1])) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        if (args[0] == Production181InputRootInitializer.Command)
        {
            using var bounded = CancellationTokenSource.CreateLinkedTokenSource(ct); bounded.CancelAfter(TimeSpan.FromSeconds(30));
            var binding = await Production181InputRootInitializer.InitializeAsync(args[1], bounded.Token).ConfigureAwait(false);
            System.Console.WriteLine(JsonSerializer.Serialize(binding)); return 0;
        }
        if (args[0] == Production181HostLauncher.ChildCommand) { return await Production181FixedChildRoute.RunAsync(args, ct).ConfigureAwait(false); }
        if (args[0] != Command) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        // Two fresh unchanged capacity observations before inputs/baselines/native workers.
        CurrentCustomerSequenceCapacity.Require(admission: true); await Task.Delay(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
        CurrentCustomerSequenceCapacity.Require(admission: true);
        using var stream = SecureLocalFile.OpenReadShared(args[1]);
        if (stream.Length is < 1 or > 8_000_000 || !SecureLocalFile.HandleResolvesToApprovedPath(stream, args[1])) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        byte[] bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes);
        var configuration = MigrationConsole.DecodeCustomerSequence<Production181PipelineConfiguration>(bytes);
        var result = await Production181Pipeline.RunAsync(configuration, args[1], ct).ConfigureAwait(false);
        // Public result contains genuine roots/report/key pins only. No private key, acceptance or persistence claim.
        System.Console.WriteLine(JsonSerializer.Serialize(result)); return 0;
    }
}
