using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal interface IConsumerColumnBootstrapOperationalEnvironment
{
    string ConnectionString { get; }
    Task RequireScopeAsync(ConsumerColumnBootstrapOperationalScope scope, CancellationToken ct);
    Task ReserveExecutionAsync(ConsumerColumnBootstrapOperationalScope scope, string authorizationSha256, CancellationToken ct);
    Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> ObserveFleetAsync(ConsumerColumnBootstrapOperationalScope scope, CancellationToken ct);
    Task RequirePolicyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, ConsumerColumnBootstrapOperationalScope scope, CancellationToken ct);
    Task<ConsumerColumnBootstrapProviderObservation> ObserveProviderAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct);
    Task RetainReceiptAsync(ConsumerColumnBootstrapOperationalReceipt receipt, CancellationToken ct);
    Task RetainRunReceiptAsync(ConsumerColumnBootstrapOperationalRunReceipt receipt, CancellationToken ct);
    Task RetainNativeWitnessAsync(ConsumerColumnBootstrapNativePhase phase, ConsumerColumnBootstrapPreservationObservation observation, CancellationToken ct);
}

/// <summary>Closed new-family admission; persistent scopes require genuine in-process rehearsal acceptance.</summary>
internal sealed class ConsumerColumnBootstrapOperationalPermit
{
    private readonly ConsumerColumnBootstrapOperationalClaim _review, _authorization;
    private readonly FreshSchemaPlan _source;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly CurrentAppOwnedRepairSigningPins _pins;
    private readonly TimeProvider _clock;
    private readonly ConsumerColumnBootstrapAcceptedCodeCustody _codeCustody;
    private readonly ConsumerColumnBootstrapRehearsalAcceptance? _rehearsal;
    private int _execution;
    internal IConsumerColumnBootstrapOperationalEnvironment Environment { get; }
    internal ConsumerColumnBootstrapOperationalScope Scope => ConsumerColumnBootstrapOperationalContract.Copy(_authorization.Scope);
    internal string AuthorizationSha256 => ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(_authorization));

    private ConsumerColumnBootstrapOperationalPermit(ConsumerColumnBootstrapOperationalClaim review, ConsumerColumnBootstrapOperationalClaim authorization,
        FreshSchemaPlan source, IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins,
        IConsumerColumnBootstrapOperationalEnvironment environment, TimeProvider clock, ConsumerColumnBootstrapAcceptedCodeCustody codeCustody,
        ConsumerColumnBootstrapRehearsalAcceptance? rehearsal)
    {
        _review = ConsumerColumnBootstrapOperationalContract.Copy(review); _authorization = ConsumerColumnBootstrapOperationalContract.Copy(authorization);
        _source = ConsumerColumnBootstrapOperationalContract.Copy(source); _trust = trust; _pins = pins; Environment = environment; _clock = clock; _codeCustody = codeCustody; _rehearsal = rehearsal;
    }

    internal static async Task<ConsumerColumnBootstrapOperationalPermit> AdmitAsync(ConsumerColumnBootstrapOperationalClaim review,
        ConsumerColumnBootstrapOperationalClaim authorization, FreshSchemaPlan source, IReceiptAttestationTrustStore trust,
        CurrentAppOwnedRepairSigningPins pins, IConsumerColumnBootstrapOperationalEnvironment environment, TimeProvider clock, CancellationToken ct,
        ConsumerColumnBootstrapRehearsalAcceptance? rehearsal = null)
    {
        var custody = ConsumerColumnBootstrapAcceptedCodeCustody.Acquire(environment.GetType(), clock);
        try
        {
            Validate(review, authorization, source, trust, pins, TimeProvider.System.GetUtcNow());
            if (authorization.Scope.Mode == ConsumerColumnBootstrapOperationalMode.PersistentReviewed)
            {
                (rehearsal ?? throw ConsumerColumnBootstrapOperationalContract.Invalid()).RequireRunner(custody.RunnerDigestSha256);
                rehearsal.Require(authorization.Scope, source, pins, TimeProvider.System.GetUtcNow());
            }
            else if (rehearsal is not null) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            var permit = new ConsumerColumnBootstrapOperationalPermit(review, authorization, source, trust, pins, environment, clock, custody, rehearsal);
            await permit.RequireAsync(ct).ConfigureAwait(false);
            await permit.RequireFleetAsync(permit.Scope.BeforeDatabaseSha256, ct).ConfigureAwait(false);
            return permit;
        }
        catch { custody.Dispose(); throw; }
    }

    internal static ConsumerColumnBootstrapOperationalClaim IssueReview(ConsumerColumnBootstrapOperationalScope scope, FreshSchemaPlan source,
        P256MigrationEvidenceSigner signer, CurrentAppOwnedRepairSigningPins pins, DateTimeOffset now, DateTimeOffset expires)
    {
        ConsumerColumnBootstrapOperationalContract.RequireScope(scope, source, now); RequirePins(pins);
        return signer.KeyId != pins.ReviewKeyId || signer.PublicKeyFingerprintSha256 != pins.ReviewFingerprint || expires > now.AddMinutes(30) ||
            expires > scope.Maintenance.ExpiresAtUtc || expires <= now
            ? throw ConsumerColumnBootstrapOperationalContract.Invalid()
            : Sign(new("consumer-column-bootstrap-review-v1", ConsumerColumnBootstrapOperationalContract.Copy(scope), Guid.NewGuid(), null, now, expires, signer.KeyId, null), signer);
    }

    internal static ConsumerColumnBootstrapOperationalClaim IssueAuthorization(ConsumerColumnBootstrapOperationalClaim review, FreshSchemaPlan source,
        IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins, P256MigrationEvidenceSigner signer, DateTimeOffset now)
    {
        RequireReview(review, source, trust, pins, now);
        if (signer.KeyId != pins.AuthorizationKeyId || signer.PublicKeyFingerprintSha256 != pins.AuthorizationFingerprint) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        DateTimeOffset expires = now.AddMinutes(15); if (review.ExpiresAtUtc < expires) { expires = review.ExpiresAtUtc; }
        return Sign(new("consumer-column-bootstrap-authorization-v1", ConsumerColumnBootstrapOperationalContract.Copy(review.Scope), Guid.NewGuid(),
            ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(review)), now, expires, signer.KeyId, null), signer);
    }

    internal static void Validate(ConsumerColumnBootstrapOperationalClaim review, ConsumerColumnBootstrapOperationalClaim authorization,
        FreshSchemaPlan source, IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins, DateTimeOffset now)
    {
        RequireReview(review, source, trust, pins, now);
        if (authorization.Kind != "consumer-column-bootstrap-authorization-v1" || authorization.KeyId != pins.AuthorizationKeyId ||
            authorization.Nonce == review.Nonce || authorization.ReviewSha256 != ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(review)) ||
            JsonSerializer.Serialize(authorization.Scope) != JsonSerializer.Serialize(review.Scope) || authorization.ExpiresAtUtc > review.ExpiresAtUtc ||
            !Verify(authorization, trust, pins.AuthorizationFingerprint, now, TimeSpan.FromMinutes(15))) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }

    internal async Task RequireAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); if (Volatile.Read(ref _execution) == 2) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        Validate(_review, _authorization, _source, _trust, _pins, _clock.GetUtcNow());
        if (_authorization.Scope.Mode == ConsumerColumnBootstrapOperationalMode.PersistentReviewed)
        { (_rehearsal ?? throw ConsumerColumnBootstrapOperationalContract.Invalid()).Require(_authorization.Scope, _source, _pins, _clock.GetUtcNow()); }
        await Environment.RequireScopeAsync(Scope, ct).ConfigureAwait(false);
    }
    internal async Task StartAsync(CancellationToken ct)
    {
        if (Interlocked.CompareExchange(ref _execution, 1, 0) != 0) { Stop(); throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        try
        {
            await RequireAsync(ct).ConfigureAwait(false); await RequireFleetAsync(Scope.BeforeDatabaseSha256, ct).ConfigureAwait(false);
            await RequireAsync(ct).ConfigureAwait(false);
            await Environment.ReserveExecutionAsync(Scope, AuthorizationSha256, ct).ConfigureAwait(false);
        }
        catch { Stop(); throw; }
    }
    internal void Stop() { if (Interlocked.Exchange(ref _execution, 2) != 2) { _codeCustody.Dispose(); } }
    internal async Task RequireFleetAsync(IReadOnlyDictionary<string, string> expected, CancellationToken ct)
    {
        await RequireAsync(ct).ConfigureAwait(false);
        var actual = await Environment.ObserveFleetAsync(Scope, ct).ConfigureAwait(false);
        if (!actual.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(expected.Keys.Order(StringComparer.Ordinal)) ||
            actual.Any(x => !expected.TryGetValue(x.Database, out string? hash) || x.Sha256 != hash)) { Stop(); throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }

    private static void RequireReview(ConsumerColumnBootstrapOperationalClaim review, FreshSchemaPlan source,
        IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins, DateTimeOffset now)
    {
        ConsumerColumnBootstrapOperationalContract.RequireScope(review.Scope, source, now); RequirePins(pins);
        if (review.Kind != "consumer-column-bootstrap-review-v1" || review.KeyId != pins.ReviewKeyId || review.ReviewSha256 is not null ||
            review.ExpiresAtUtc > review.Scope.Maintenance.ExpiresAtUtc || !Verify(review, trust, pins.ReviewFingerprint, now, TimeSpan.FromMinutes(30)))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }
    private static void RequirePins(CurrentAppOwnedRepairSigningPins pins)
    {
        string[] ids = [pins.ReviewKeyId, pins.AuthorizationKeyId, pins.ReceiptKeyId], fingerprints = [pins.ReviewFingerprint, pins.AuthorizationFingerprint, pins.ReceiptFingerprint];
        if (ids.Any(string.IsNullOrWhiteSpace) || ids.Distinct(StringComparer.Ordinal).Count() != 3 || fingerprints.Any(x => !ConsumerColumnBootstrapOperationalContract.IsHash(x)) ||
            fingerprints.Distinct(StringComparer.Ordinal).Count() != 3) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }
    private static ConsumerColumnBootstrapOperationalClaim Sign(ConsumerColumnBootstrapOperationalClaim claim, P256MigrationEvidenceSigner signer)
    {
        return claim with { Signature = Convert.ToBase64String(signer.Sign(Payload(claim))) };
    }

    private static byte[] Payload(ConsumerColumnBootstrapOperationalClaim claim)
    {
        return [.. "Legacy.Maliev.ConsumerColumnBootstrap.OperationalClaim.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(claim with { Signature = null })];
    }

    private static bool Verify(ConsumerColumnBootstrapOperationalClaim claim, IReceiptAttestationTrustStore trust, string fingerprint, DateTimeOffset now, TimeSpan maximum)
    {
        if (claim.Nonce == Guid.Empty || claim.IssuedAtUtc.Offset != TimeSpan.Zero || claim.ExpiresAtUtc.Offset != TimeSpan.Zero || claim.IssuedAtUtc > now ||
            claim.ExpiresAtUtc <= now || claim.ExpiresAtUtc <= claim.IssuedAtUtc || claim.ExpiresAtUtc - claim.IssuedAtUtc > maximum || string.IsNullOrWhiteSpace(claim.Signature) ||
            !trust.TryGetPublicKeyFingerprintSha256(claim.KeyId, out string actual) || actual != fingerprint) { return false; }
        try { return trust.Verify(claim.KeyId, Payload(claim), Convert.FromBase64String(claim.Signature)); } catch (FormatException) { return false; }
    }
}
