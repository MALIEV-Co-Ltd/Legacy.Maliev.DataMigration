namespace Legacy.Maliev.DataMigration.Console;

internal static class Production181FixedChildRoute
{
    // Proposed exact dispatcher adapter. No persistent review/authorize/apply route calls it.
    internal static Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        return args.Length != 2 || args[0] != Production181HostLauncher.ChildCommand || !Path.IsPathFullyQualified(args[1])
            ? throw CurrentCustomerSequenceRepairPermit.Invalid()
            : Production181HostLauncher.RunWaitingChildAsync(args[1], ct);
    }
}
