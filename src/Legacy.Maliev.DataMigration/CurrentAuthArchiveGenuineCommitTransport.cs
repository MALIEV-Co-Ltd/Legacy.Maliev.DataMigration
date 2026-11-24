using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed partial class CurrentAuthLocalSessionArchivePermit
{
    internal sealed partial class GenuineExecutionCapability
    {
        // A private-constructor transport handle, not a target identity or serialized permission.
        internal sealed class CommitWriterLease : IAsyncDisposable
        {
            private readonly GenuineExecutionCapability _owner;
            private readonly CurrentAuthLocalSessionArchivePermit _permit;
            private readonly string _direct;
            private readonly int _port;
            private bool _closed;
            private CommitWriterLease(GenuineExecutionCapability owner, CurrentAuthLocalSessionArchivePermit permit, string direct, int port)
            { _owner = owner; _permit = permit; _direct = direct; _port = port; }
            internal static async Task<CommitWriterLease> CreateOwnedAsync(GenuineExecutionCapability owner,
                CurrentAuthLocalSessionArchivePermit permit, CancellationToken ct)
            {
                await owner.RequireAsync(ct);
                if (owner._binding.Case != CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost ||
                    permit.Scope.ProofAdmission != CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap ||
                    !ReferenceEquals(owner._binding.Owned.Environment, permit.Environment) ||
                    permit.AuthorizationSha256 != owner._binding.AuthorizationSha256) { throw Invalid(); }
                string direct = await Invoke<string>(owner._issuer, Fixed(owner._issuer.GetType(), "ReadExecutionConnectionAsync", typeof(Task<string>),
                    [typeof(Guid), typeof(CancellationToken)]), [owner._id, ct]);
                var endpoint = Normalize(direct);
                var info = await Invoke<CurrentAuthArchiveGenuineCommitProxyInfo>(owner._issuer, Fixed(owner._issuer.GetType(), "OpenCommitWriterAsync",
                    typeof(Task<CurrentAuthArchiveGenuineCommitProxyInfo>), [typeof(Guid), typeof(CancellationToken)]), [owner._id, ct]);
                RequireInfo(owner, permit, endpoint, info, closed: false);
                return new(owner, permit, endpoint.ConnectionString, info.Port);
            }
            internal async Task<string> RequireWriterConnectionAsync(string direct, CurrentAuthLocalSessionArchivePermit permit, CancellationToken ct)
            {
                if (_closed || !ReferenceEquals(permit, _permit) || !Normalize(direct).EquivalentTo(Normalize(_direct))) { throw Invalid(); }
                await _owner.RequireAsync(ct); var info = await ObserveAsync(ct);
                RequireInfo(_owner, permit, Normalize(_direct), info, closed: false);
                return info.Port != _port ? throw Invalid() : new NpgsqlConnectionStringBuilder(_direct) { Port = _port }.ConnectionString;
            }
            internal async Task RequireBackendAsync(NpgsqlConnection writer, CurrentAuthLocalSessionArchivePermit permit, CancellationToken ct)
            {
                _ = await RequireWriterConnectionAsync(_direct, permit, ct); var info = await ObserveAsync(ct);
                if (writer.Host != "127.0.0.1" || writer.Port != _port || writer.Database != "Auth" || writer.ProcessID <= 0 ||
                    info.AcceptedSessions != 1 || info.BackendPid != writer.ProcessID) { throw Invalid(); }
            }
            internal async Task ArmAsync(NpgsqlConnection writer, CurrentAuthLocalSessionArchivePermit permit, string preparedSha, CancellationToken ct)
            {
                await RequireBackendAsync(writer, permit, ct);
                if (permit._prepared is null || permit._terminal || permit._state != 2 || permit._previousSha256 != preparedSha ||
                    permit._prepared.Classification != CurrentAppOwnedCommitClassification.Prepared) { throw Invalid(); }
                await (Fixed(_owner._issuer.GetType(), "ArmCommitWriterAsync", typeof(Task),
                    [typeof(Guid), typeof(int), typeof(CancellationToken)]).Invoke(_owner._issuer, [_owner._id, writer.ProcessID, ct]) as Task ?? throw Invalid());
            }
            private Task<CurrentAuthArchiveGenuineCommitProxyInfo> ObserveAsync(CancellationToken ct)
            {
                return Invoke<CurrentAuthArchiveGenuineCommitProxyInfo>(
                _owner._issuer, Fixed(_owner._issuer.GetType(), "RequireCommitWriterAsync", typeof(Task<CurrentAuthArchiveGenuineCommitProxyInfo>),
                [typeof(Guid), typeof(CancellationToken)]), [_owner._id, ct]);
            }

            internal async Task<CurrentAuthArchiveGenuineCommitProxyInfo> CloseAsync(CancellationToken ct)
            {
                var info = await Invoke<CurrentAuthArchiveGenuineCommitProxyInfo>(_owner._issuer,
                    Fixed(_owner._issuer.GetType(), "CloseCommitWriterAsync", typeof(Task<CurrentAuthArchiveGenuineCommitProxyInfo>),
                    [typeof(Guid), typeof(CancellationToken)]), [_owner._id, ct]);
                _closed = true; return info;
            }
            public async ValueTask DisposeAsync()
            {
                if (_closed) { return; }
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15)); _ = await CloseAsync(cleanup.Token);
            }
            private static NpgsqlConnectionStringBuilder Normalize(string direct)
            {
                var endpoint = new NpgsqlConnectionStringBuilder(direct);
                if (endpoint.Host != "127.0.0.1" || endpoint.Database != "Auth" || endpoint.Port is < 1 or > 65535 || endpoint.Pooling ||
                    endpoint.SslMode != SslMode.Disable || string.IsNullOrWhiteSpace(endpoint.Password) || !string.IsNullOrEmpty(endpoint.Options)) { throw Invalid(); }
                endpoint.IncludeErrorDetail = false; endpoint.Timeout = 5; endpoint.CommandTimeout = 30; return endpoint;
            }
            private static void RequireInfo(GenuineExecutionCapability owner, CurrentAuthLocalSessionArchivePermit permit,
                NpgsqlConnectionStringBuilder direct, CurrentAuthArchiveGenuineCommitProxyInfo info, bool closed)
            {
                if (!ReferenceEquals(info.Environment, permit.Environment) || info.OperationId != permit.Scope.OperationId ||
                    info.OwnerPid != System.Environment.ProcessId || !CurrentAuthRepairPermit.HashShape(info.OwnerImageSha256) || info.OwnerStartedAtUtc > info.CreatedAtUtc ||
                    info.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(permit.Scope) || info.AuthorizationSha256 != permit.AuthorizationSha256 ||
                    info.Role != direct.Username || direct.Username != permit.Scope.LocalObservationPolicy.Maintenance.Role || info.UpstreamPort != direct.Port ||
                    info.Port is < 1 or > 65535 || info.Port == direct.Port || info.Closed != closed || info.AcceptedSessions is < 0 or > 1 ||
                    info.ExpiresAtUtc != permit.Scope.ExpiresAtUtc || info.CreatedAtUtc > DateTimeOffset.UtcNow || info.ExpiresAtUtc <= DateTimeOffset.UtcNow ||
                    owner._binding.Case != CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost) { throw Invalid(); }
            }
        }
    }
}
