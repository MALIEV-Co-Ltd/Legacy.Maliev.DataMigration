namespace Legacy.Maliev.DataMigration.Console;

internal sealed record OwnerIsoGuardedBootstrapHostExit(string Kind, int ProcessId, DateTimeOffset ProcessStartTimeUtc, string Executable,
    string ExecutableSha256, string TestAssemblySha256, DateTimeOffset ExitedAtUtc, int ExitCode, IReadOnlyList<Guid> RunIds, bool ProcessExitObserved,
    string JobNonce, DateTimeOffset MembershipObservedAtUtc, bool NativeMembershipObserved, bool EmptyJobObservedAfterExit);
