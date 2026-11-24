namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CurrentAuthArchiveGenuineExecutionIssuer
{
    private CommitProxyFactory? _commitFactory;
    internal async Task<CurrentAuthArchiveGenuineCommitProxyInfo> OpenCommitWriterAsync(Guid id, CancellationToken ct)
    {
        var binding = await RequireExecutionAsync(id, false, ct);
        lock (_gate)
        {
            if (_commitFactory is not null || _ownedDenial is not null || binding.Case != CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost) { throw Invalid(); }
            _commitFactory = CommitProxyFactory.CreateOwned(this, binding);
        }
        return await _lease.OpenCommitProxyAsync(_commitFactory, ct);
    }
    internal async Task<CurrentAuthArchiveGenuineCommitProxyInfo> RequireCommitWriterAsync(Guid id, CancellationToken ct)
    {
        _ = await RequireExecutionAsync(id, false, ct); return await _lease.ReadCommitProxyAsync(ct);
    }
    internal async Task ArmCommitWriterAsync(Guid id, int backendPid, CancellationToken ct)
    {
        _ = await RequireExecutionAsync(id, false, ct); await _lease.ArmCommitProxyAsync(backendPid, ct);
    }
    internal async Task<CurrentAuthArchiveGenuineCommitProxyInfo> CloseCommitWriterAsync(Guid id, CancellationToken ct)
    {
        Check(id, false); _bundle.Require();
        return _commitFactory is null ? throw Invalid() : await _lease.CloseCommitProxyAsync(ct);
    }
    internal async Task<CurrentAuthArchiveGenuineDualArtifacts> RetainCommitFailureAsync(Guid id, CurrentAuthArchiveGenuineCommitFailureFacts facts, CancellationToken ct)
    {
        Check(id, false); _bundle.Require(); if (_commitFactory is null || facts.Case != CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost) { throw Invalid(); }
        try
        {
            var result = await _lease.RetainCommitFailureAsync(facts, ct);
            lock (_gate) { if (_disposed || _closed || _failed || id != _id) { throw Invalid(); } _closed = true; }
            _bundle.Require(); return result;
        }
        catch { lock (_gate) { _failed = true; } throw; }
    }

    internal sealed class CommitProxyFactory
    {
        private readonly CurrentAuthArchiveGenuineExecutionIssuer _issuer;
        private readonly CurrentAuthArchiveGenuineExecutionAttestation _binding;
        private int _opened;
        private CommitProxyFactory(CurrentAuthArchiveGenuineExecutionIssuer issuer, CurrentAuthArchiveGenuineExecutionAttestation binding)
        { _issuer = issuer; _binding = binding; }
        internal static CommitProxyFactory CreateOwned(CurrentAuthArchiveGenuineExecutionIssuer issuer, CurrentAuthArchiveGenuineExecutionAttestation binding)
        {
            lock (issuer._gate)
            {
                return issuer._disposed || issuer._failed || issuer._closed || !issuer._minted || !issuer._reserved || issuer._commitFactory is not null ||
                    binding.Case != CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost
                    ? throw Invalid()
                    : new(issuer, binding);
            }
        }
        internal void ReserveProxy(CurrentAuthLocalSessionArchiveEnvironment environment, CurrentAuthArchiveScope scope, string authorization)
        {
            RequireOwner(environment, scope, authorization);
            if (Interlocked.CompareExchange(ref _opened, 1, 0) != 0) { throw Invalid(); }
        }
        internal void RequireOwner(CurrentAuthLocalSessionArchiveEnvironment environment, CurrentAuthArchiveScope scope, string authorization)
        {
            lock (_issuer._gate)
            {
                if (_issuer._disposed || _issuer._closed || _issuer._failed || !_issuer._reserved ||
                    !ReferenceEquals(environment, _binding.Owned.Environment) || CurrentAuthLocalSessionArchivePolicy.Hash(scope) != CurrentAuthLocalSessionArchivePolicy.Hash(_binding.Owned.Scope) ||
                    authorization != _binding.AuthorizationSha256 || scope.ComponentSubject?.Seed.CaseId != "commit-ack-lost" || DateTimeOffset.UtcNow >= scope.ExpiresAtUtc) { throw Invalid(); }
            }
            _issuer._bundle.Require();
        }
    }
}
