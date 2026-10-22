namespace Legacy.Maliev.DataMigration.Console;

internal sealed record IsoNamedClosedLaneInputs(string ParentRunBindingPath, string ParentRunBindingSha256,
    string SourcePath, string OwnersPath, CurrentOwnerIsoRepairSourceInputs SourceInputs,
    IsoClosedBootstrapInputs Precursors, CurrentOwnerIsoClosedPrecursorPins PrecursorPins,
    string NativeComponentSha256, string MaintenanceComponentSha256, string MaintenanceValidatorSourcePath,
    string TestAssemblyPath, string TestAssemblySha256, string ConsoleAssemblySha256, string CoreAssemblySha256);

internal sealed record IsoNamedClosedInvocation(string Command, Guid OperationId, DateTimeOffset StartedAtUtc,
    DateTimeOffset ExitedAtUtc, int ExitCode, string StdoutSha256, string StderrSha256);

internal sealed record IsoNamedClosedHostEntry(IsoActualHostEntry Host, string FixtureRoot, string FixtureBindingPath,
    DateTimeOffset BeganAtUtc, DateTimeOffset ExpiresAtUtc);
