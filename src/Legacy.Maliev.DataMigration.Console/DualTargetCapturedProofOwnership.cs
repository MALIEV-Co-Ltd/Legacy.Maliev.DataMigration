using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

// A digest is only a swap check, never authority. Only a live fixed-factory clone mints the lease below.
internal sealed record DualTargetCapturedProofBinding(DualTargetCapturedDeltaPurpose Purpose, string ContainerId,
    string Volume, string ConnectionSha256, string EndpointSha256, string AcceptedMain, DateTimeOffset ExpiresAtUtc)
{
    internal static string ConnectionHash(string connection)
    {
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(connection)));
    }

    internal static string EndpointHash(DualTargetCapturedDeltaEndpoint endpoint)
    {
        return Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(endpoint)));
    }

    internal void Require(DualTargetCapturedDeltaEndpoint endpoint, string connection, string acceptedMain, DateTimeOffset now)
    {
        if (Purpose is not (DualTargetCapturedDeltaPurpose.ProductionProof or DualTargetCapturedDeltaPurpose.LocalProof) ||
            endpoint.Purpose != Purpose || endpoint.DockerContainerId != ContainerId || endpoint.DockerVolumeName != Volume ||
            EndpointHash(endpoint) != EndpointSha256 || ConnectionHash(connection) != ConnectionSha256 || AcceptedMain != acceptedMain ||
            ExpiresAtUtc.Offset != TimeSpan.Zero || now.Offset != TimeSpan.Zero || now >= ExpiresAtUtc)
        { throw DualTargetNativeProofPreimage.Invalid(); }
    }
}

internal sealed partial class DualTargetNativeProofClone
{
    private ProofLease? _proofLease;

    internal Task<ProofLease> BindProofEndpointAsync(DualTargetCapturedDeltaEndpoint endpoint, string connection,
        string acceptedMain, DateTimeOffset expiry, CancellationToken ct)
    {
        return ProofLease.MintAsync(this, endpoint, connection, acceptedMain, expiry, ct);
    }

    // No public/JSON constructor; no configured endpoint can stand in for the concrete owner instance.
    internal sealed class ProofLease
    {
        private readonly DualTargetNativeProofClone _owner;
        private readonly DualTargetCapturedProofBinding _binding;
        private ProofLease(DualTargetNativeProofClone owner, DualTargetCapturedProofBinding binding)
        { _owner = owner; _binding = binding; }
        internal DualTargetCapturedDeltaPurpose Purpose => _binding.Purpose;

        internal static async Task<ProofLease> MintAsync(DualTargetNativeProofClone owner, DualTargetCapturedDeltaEndpoint endpoint,
            string connection, string acceptedMain, DateTimeOffset expiry, CancellationToken ct)
        {
            if (endpoint.Purpose is not (DualTargetCapturedDeltaPurpose.ProductionProof or DualTargetCapturedDeltaPurpose.LocalProof) ||
                endpoint.DockerContainerId != owner.ContainerId || endpoint.DockerVolumeName != owner.Name || connection != owner.Connection ||
                expiry.Offset != TimeSpan.Zero || expiry <= DateTimeOffset.UtcNow || expiry > owner.ExpiresAtUtc ||
                await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != acceptedMain)
            { throw DualTargetNativeProofPreimage.Invalid(); }
            await owner.RequireOwnedAsync(ct).ConfigureAwait(false);
            var result = new ProofLease(owner, new(endpoint.Purpose, owner.ContainerId, owner.Name,
                DualTargetCapturedProofBinding.ConnectionHash(connection), DualTargetCapturedProofBinding.EndpointHash(endpoint), acceptedMain, expiry));
            if (Interlocked.CompareExchange(ref owner._proofLease, result, null) is not null) { throw DualTargetNativeProofPreimage.Invalid(); }
            result.RequireLive(); return result;
        }
        internal void RequireLive()
        {
            if (_owner._disposed || !ReferenceEquals(_owner._proofLease, this) || DateTimeOffset.UtcNow >= _binding.ExpiresAtUtc ||
                DateTimeOffset.UtcNow >= _owner.ExpiresAtUtc) { throw DualTargetNativeProofPreimage.Invalid(); }
            _owner.Token.ThrowIfCancellationRequested();
        }
        internal void RequireBinding(DualTargetCapturedDeltaEndpoint endpoint, string connection, string acceptedMain)
        { RequireLive(); _binding.Require(endpoint, connection, acceptedMain, DateTimeOffset.UtcNow); }
        internal async Task RequireAsync(DualTargetCapturedDeltaEndpoint endpoint, string connection, string acceptedMain, CancellationToken ct)
        {
            RequireBinding(endpoint, connection, acceptedMain);
            await _owner.RequireOwnedAsync(ct).ConfigureAwait(false);
            RequireBinding(endpoint, connection, acceptedMain);
        }
        internal static async Task RequireEndpointAsync(DualTargetCapturedDeltaEndpoint endpoint, string connection, string acceptedMain,
            ProofLease? lease, CancellationToken ct)
        {
            if (endpoint.Purpose is DualTargetCapturedDeltaPurpose.ProductionProof or DualTargetCapturedDeltaPurpose.LocalProof)
            {
                if (lease is null) { throw DualTargetNativeProofPreimage.Invalid(); }
                await lease.RequireAsync(endpoint, connection, acceptedMain, ct).ConfigureAwait(false);
            }
            else if (lease is not null || endpoint.Purpose is not (DualTargetCapturedDeltaPurpose.Production or DualTargetCapturedDeltaPurpose.PersistentLocal))
            { throw DualTargetNativeProofPreimage.Invalid(); }
        }
    }
}

internal sealed class DualTargetCapturedOwnedProofPair
{
    private readonly DualTargetNativeProofClone.ProofLease _production, _local;
    private DualTargetCapturedOwnedProofPair(DualTargetNativeProofClone.ProofLease production, DualTargetNativeProofClone.ProofLease local)
    { _production = production; _local = local; }
    internal static DualTargetCapturedOwnedProofPair Create(DualTargetNativeProofClone.ProofLease production, DualTargetNativeProofClone.ProofLease local)
    {
        if (ReferenceEquals(production, local) || production.Purpose != DualTargetCapturedDeltaPurpose.ProductionProof || local.Purpose != DualTargetCapturedDeltaPurpose.LocalProof)
        { throw DualTargetNativeProofPreimage.Invalid(); }
        production.RequireLive(); local.RequireLive(); return new(production, local);
    }
    internal DualTargetNativeProofClone.ProofLease Get(DualTargetCapturedDeltaPurpose purpose)
    {
        _production.RequireLive(); _local.RequireLive();
        return purpose switch
        {
            DualTargetCapturedDeltaPurpose.ProductionProof => _production,
            DualTargetCapturedDeltaPurpose.LocalProof => _local,
            DualTargetCapturedDeltaPurpose.Production => throw DualTargetNativeProofPreimage.Invalid(),
            DualTargetCapturedDeltaPurpose.PersistentLocal => throw DualTargetNativeProofPreimage.Invalid(),
            _ => throw DualTargetNativeProofPreimage.Invalid()
        };
    }
    internal static void RequireCommand(string command, DualTargetCapturedDeltaPurpose? purpose, DualTargetCapturedOwnedProofPair? owned)
    {
        if (command == "plan-dual-target-captured-delta")
        {
            if (owned is null) { throw DualTargetNativeProofPreimage.Invalid(); }
            _ = owned.Get(DualTargetCapturedDeltaPurpose.ProductionProof); _ = owned.Get(DualTargetCapturedDeltaPurpose.LocalProof);
        }
        else if (command == "prove-dual-target-captured-delta")
        {
            if (owned is null || purpose is null) { throw DualTargetNativeProofPreimage.Invalid(); }
            _ = owned.Get(purpose.Value);
        }
        else if (command is "review-dual-target-captured-delta" or "apply-dual-target-captured-delta")
        {
            if (purpose is not (DualTargetCapturedDeltaPurpose.Production or DualTargetCapturedDeltaPurpose.PersistentLocal))
            { throw DualTargetNativeProofPreimage.Invalid(); }
        }
        else { throw DualTargetNativeProofPreimage.Invalid(); }
    }
}
