using System.Text;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair
{
    async Task<CurrentAuthArchiveGenuineHelperClaims> ICurrentAuthArchiveGenuineOwnedLease.PrepareDualHelperClaimsAsync(CancellationToken ct)
    {
        await RequireAsync(ct);
        using var reviewer = DualSigner(_inputs.Pins.ReviewKeyId, CurrentAuthArchiveGenuineDualInputContract.ReviewKeyName, _inputs.Pins.ReviewFingerprint);
        using var authorizer = DualSigner(_inputs.Pins.AuthorizationKeyId, CurrentAuthArchiveGenuineDualInputContract.AuthorizationKeyName, _inputs.Pins.AuthorizationFingerprint);
        using var evidence = DualSigner(_inputs.Pins.EvidenceKeyId, CurrentAuthArchiveGenuineDualInputContract.EvidenceKeyName, _inputs.Pins.EvidenceFingerprint);
        var review = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReviewDomain, Scope, reviewer);
        DateTimeOffset issued = DateTimeOffset.UtcNow;
        var permission = new CurrentAuthArchiveAuthorization(Scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(review), issued, Scope.ExpiresAtUtc);
        var authorization = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain, permission, authorizer);
        var claims = new CurrentAuthArchiveGenuineHelperClaims(review, authorization);
        _ = CurrentAuthLocalSessionArchivePermit.RequireGenuineDualHelperClaims(claims, _inputs.TrustStore, _inputs.Pins, DateTimeOffset.UtcNow);
        await _inputs.RequireAsync(ct);
        return claims;
    }

    private P256MigrationEvidenceSigner DualSigner(string id, string name, string fingerprint)
    {
        string root = _inputs.ParentAuthority.Binding.ArtifactRootCanonicalPath;
        byte[] bytes = _inputs.ParentFiles.Read(Path.Combine(root, name), sharedReader: true, maximumBytes: 65536);
        try
        {
            var signer = new P256MigrationEvidenceSigner(id, Encoding.UTF8.GetString(bytes));
            if (signer.PublicKeyFingerprintSha256 == fingerprint) { return signer; }
            signer.Dispose(); throw Invalid();
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }
}
