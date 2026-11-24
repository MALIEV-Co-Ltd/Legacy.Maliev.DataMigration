using System.Text.Json.Serialization;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAuthArchiveGenuineCommitProxyInfo(Guid OperationId, string ScopeSha256, string AuthorizationSha256,
    string Role, int UpstreamPort, int Port, int OwnerPid, DateTimeOffset OwnerStartedAtUtc, string OwnerImageSha256,
    DateTimeOffset CreatedAtUtc, DateTimeOffset ExpiresAtUtc, int AcceptedSessions, int BackendPid, bool Armed,
    int DroppedCommits, DateTimeOffset? ArmedAtUtc, DateTimeOffset? DroppedAtUtc, bool Closed, bool WorkerSettled, bool ListenerAbsent, bool ClientsAbsent,
    DateTimeOffset? ClosedAtUtc, [property: JsonIgnore] ICurrentAuthLocalSessionArchiveEnvironment Environment);
internal sealed record CurrentAuthArchiveGenuineCommitFailureFacts(CurrentAuthArchiveGenuineExecutionCase Case,
    CurrentAuthArchiveGenuineHelperClaims Claims, string ActualExceptionType, CurrentAuthArchiveFleet LocalBefore,
    CurrentAuthArchiveFleet ComparisonBefore, DateTimeOffset BeganAtUtc, DateTimeOffset FailedAtUtc,
    CurrentAuthArchiveGenuineCommitProxyInfo Proxy);

internal static class CurrentAuthArchiveGenuineCommitFacts
{
    internal static bool IsCommitCompletion(byte type, ReadOnlySpan<byte> payload)
    {
        return type == (byte)'C' && payload.SequenceEqual("COMMIT\0"u8);
    }

    internal static void RequireSettled(CurrentAuthArchiveGenuineCommitProxyInfo value, CurrentAuthArchiveScope scope, string authorization)
    {
        if (scope.ComponentSubject?.Seed.CaseId != "commit-ack-lost" || value.OperationId != scope.OperationId ||
            value.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(scope) || value.AuthorizationSha256 != authorization ||
            value.Role != scope.LocalObservationPolicy.Maintenance.Role || value.UpstreamPort is < 1 or > 65535 || value.Port is < 1 or > 65535 ||
            value.UpstreamPort == value.Port || value.OwnerPid <= 0 || !CurrentAuthRepairPermit.HashShape(value.OwnerImageSha256) ||
            value.AcceptedSessions != 1 || value.BackendPid <= 0 || value.Armed || value.DroppedCommits != 1 || value.ArmedAtUtc is null || value.DroppedAtUtc is null ||
            !value.Closed || !value.WorkerSettled || !value.ListenerAbsent || !value.ClientsAbsent || value.ClosedAtUtc is null ||
            value.CreatedAtUtc < scope.CapturedAtUtc || value.ExpiresAtUtc != scope.ExpiresAtUtc || value.CreatedAtUtc >= value.ExpiresAtUtc ||
            value.OwnerStartedAtUtc > value.CreatedAtUtc || value.OwnerStartedAtUtc.Offset != TimeSpan.Zero || value.CreatedAtUtc.Offset != TimeSpan.Zero ||
            value.ExpiresAtUtc.Offset != TimeSpan.Zero || value.ArmedAtUtc.Value.Offset != TimeSpan.Zero || value.DroppedAtUtc.Value.Offset != TimeSpan.Zero || value.ClosedAtUtc.Value.Offset != TimeSpan.Zero ||
            value.ArmedAtUtc < value.CreatedAtUtc || value.DroppedAtUtc < value.ArmedAtUtc || value.DroppedAtUtc > value.ExpiresAtUtc ||
            value.ClosedAtUtc < value.DroppedAtUtc || value.ClosedAtUtc > DateTimeOffset.UtcNow)
        { throw CurrentAuthArchiveGenuineExecutionCases.Invalid(); }
    }
}
