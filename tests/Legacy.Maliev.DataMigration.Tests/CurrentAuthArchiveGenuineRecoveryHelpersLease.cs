using System.Security.Cryptography;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair
{
    private CurrentAuthArchiveGenuineRecoveryHelpersStorage? _recoveryHelpersStorage;

    internal static async Task<ICurrentAuthArchiveGenuineOwnedLease> OpenRecoveryHelperLeaseAsync(CurrentAuthArchiveGenuineHostConfiguration request,
        CurrentAuthArchiveGenuineRecoveryHelperCase helperCase, CancellationToken ct)
    {
        return await CreateRecoveryHelperAsync(request, helperCase, ct);
    }

    async Task<CurrentAuthArchiveGenuineHelperClaims> ICurrentAuthArchiveGenuineOwnedLease.PrepareRecoveryHelperClaimsAsync(
        CurrentAuthArchiveGenuineRecoveryHelperCase helperCase, CancellationToken ct)
    {
        if (helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback || _seed.CaseId != CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(helperCase)) { throw Invalid(); }
        await RequireAsync(ct);
        using var reviewer = DualSigner(_inputs.Pins.ReviewKeyId, CurrentAuthArchiveGenuineDualInputContract.ReviewKeyName, _inputs.Pins.ReviewFingerprint);
        using var authorizer = DualSigner(_inputs.Pins.AuthorizationKeyId, CurrentAuthArchiveGenuineDualInputContract.AuthorizationKeyName, _inputs.Pins.AuthorizationFingerprint);
        using var evidence = DualSigner(_inputs.Pins.EvidenceKeyId, CurrentAuthArchiveGenuineDualInputContract.EvidenceKeyName, _inputs.Pins.EvidenceFingerprint);
        var review = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReviewDomain, Scope, reviewer);
        var permission = new CurrentAuthArchiveAuthorization(Scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(review), DateTimeOffset.UtcNow, Scope.ExpiresAtUtc);
        var claims = new CurrentAuthArchiveGenuineHelperClaims(review,
            CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain, permission, authorizer));
        _ = CurrentAuthLocalSessionArchivePermit.RequireGenuineRecoveryHelperClaims(claims, _inputs.TrustStore, _inputs.Pins, helperCase, DateTimeOffset.UtcNow);
        return claims;
    }

    async Task<CurrentAuthArchiveGenuineRecoveryHelpersOutcome> ICurrentAuthArchiveGenuineOwnedLease.ExecuteRecoveryHelperFaultAsync(
        CurrentAuthArchiveGenuineRecoveryHelpersRequest request, CancellationToken ct)
    {
        var helperCase = CurrentAuthArchiveGenuineRecoveryHelpers.Parse(_seed.CaseId);
        if (_recoveryHelpersStorage is not null || _firstAuthority is null || _secondAuthority is null || _dualDeviceProof is null ||
            CurrentAuthLocalSessionArchivePolicy.Hash(request.Scope) != CurrentAuthLocalSessionArchivePolicy.Hash(Scope)) { throw Invalid(); }
        _ = CurrentAuthLocalSessionArchivePermit.RequireGenuineRecoveryHelperClaims(request.Claims, _inputs.TrustStore, _inputs.Pins, helperCase, DateTimeOffset.UtcNow);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, _lease.Token);
        deadline.CancelAfter(Scope.ExpiresAtUtc - DateTimeOffset.UtcNow); ct = deadline.Token;
        _recoveryHelpersStorage = new(_firstAuthority, _secondAuthority, Scope, _dualDeviceProof, helperCase);
        var storage = _recoveryHelpersStorage;
        var manifest = await CurrentAuthLocalSessionArchiveCrypto.WriteAndVerifyAsync(storage, Scope,
            CurrentAuthLocalSessionArchivePolicy.Hash(request.Claims.Authorization), request.Rows, ct);
        var fault = await storage.InjectFixedFaultAsync(ct);
        string? rejection = null; string stage;
        if (helperCase is CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery or CurrentAuthArchiveGenuineRecoveryHelperCase.SecondOnlyRecovery)
        {
            bool first = helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery;
            byte[] recovered = await CurrentAuthLocalSessionArchiveCrypto.RecoverDomainAsync(storage, Scope, manifest, first, ct);
            try { if (CurrentAuthLocalSessionArchivePolicy.HashBytes(recovered) != Scope.DeleteSetSha256) { throw Invalid(); } }
            finally { CryptographicOperations.ZeroMemory(recovered); }
            await storage.RequireCustodyAsync(ct); // Re-prove actual exclusive denial while recovery has just succeeded.
            storage.RestoreReadAvailability(); stage = "selected-domain-recovered-with-other-domain-sharing-denied";
        }
        else
        {
            stage = helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption ? "key-import" : "ciphertext-digest";
            try
            {
                byte[] unexpected = await CurrentAuthLocalSessionArchiveCrypto.RecoverDomainAsync(storage, Scope, manifest, true, ct);
                CryptographicOperations.ZeroMemory(unexpected); throw Invalid();
            }
            catch (CryptographicException) when (helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption)
            { rejection = "genuine_recovery_key_import_rejected"; }
            catch (MigrationExecutionException failure) when (helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.CipherCorruption && failure.Code == "current_auth_local_archive_invalid")
            { rejection = "genuine_recovery_ciphertext_digest_rejected"; }
            await storage.RequireCustodyAsync(ct);
        }
        return new(manifest, fault, rejection, stage, rejection is null ? 0 : 1, null, true);
    }

    Task<CurrentAuthArchiveGenuineDualArtifacts> ICurrentAuthArchiveGenuineOwnedLease.RetainRecoveryHelperFactsAsync(
        CurrentAuthArchiveGenuineRecoveryHelpersFacts facts, CancellationToken ct)
    {
        return RetainHelperEvidenceAsync(facts.Preservation, _recoveryHelpersStorage ?? throw Invalid(), facts.Outcome, ct);
    }
}
