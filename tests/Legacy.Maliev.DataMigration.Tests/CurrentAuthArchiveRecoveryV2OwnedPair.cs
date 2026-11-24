using System.Text;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair : ICurrentAuthArchiveRecoveryV2Lease
{
    private CurrentAuthArchiveRecoveryV2Case? _recoveryV2Case;
    private CurrentAuthArchiveRecoveryV2Input? _recoveryV2Input;
    private CurrentAuthArchiveProofAudienceV2? _recoveryAudience;
    private CurrentAuthArchiveClaim? _recoveryAudienceClaim, _recoveryCaseClaim;
    private CurrentReviewedCapture? _recoveryCapture;
    private string? _recoverySourceConnection;
    private int _restoreStarted;

    internal static async Task<ICurrentAuthArchiveRecoveryV2Lease> OpenRecoveryV2LeaseAsync(CurrentAuthArchiveRecoveryV2Input input,
        CurrentAuthArchiveRecoveryV2Case expected, CancellationToken ct)
    {
        CurrentAuthArchiveRecoveryV2InputContract.Require(input, expected); var request = input.Request;
        var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(Path.GetDirectoryName(request.Inputs.TestImage.Path)!, ct);
        CurrentAuthArchiveComponentReadback? inputs = null; CurrentAuthArchiveGenuineOwnedPair? pair = null;
        try
        {
            bundle.Require(); inputs = await CurrentAuthArchiveComponentReadback.OpenRecoveryV2InitialAsync(request.Inputs, expected, ct);
            var seed = await inputs.ReadSeedAsync(ct);
            CurrentAuthArchiveGenuineExecutionSeed.RequireInitial(seed, inputs.Pins, inputs.TrustStore, CurrentAuthArchiveRecoveryV2.SetupCase(expected), DateTimeOffset.UtcNow);
            byte[] Read(CurrentAuthArchiveProofArtifact artifact)
            {
                byte[] bytes = inputs.ParentFiles.Read(artifact.Path, sharedReader: true, maximumBytes: 65536);
                return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) == artifact.Sha256 ? bytes : throw Invalid();
            }
            var audienceClaim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(Read(input.Audience));
            var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveProofAudienceV2>(audienceClaim, CurrentAuthArchiveRecoveryV2.AudienceDomain,
                inputs.Pins.ReviewKeyId, inputs.Pins.ReviewFingerprint, inputs.TrustStore);
            CurrentAuthArchiveRecoveryV2.RequireAudience(audience, seed, inputs.Pins, DateTimeOffset.UtcNow);
            var caseClaim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(Read(input.CaseBinding));
            var caseBinding = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveRecoveryCaseBindingV2>(caseClaim, CurrentAuthArchiveRecoveryV2.CaseDomain,
                inputs.Pins.ReviewKeyId, inputs.Pins.ReviewFingerprint, inputs.TrustStore);
            CurrentAuthArchiveRecoveryV2.RequireCaseBinding(caseBinding, audienceClaim, seed, expected, DateTimeOffset.UtcNow);
            if (SourceCatalogDefinitionFingerprintV1.Compute(inputs.Source, seed.AcceptedSourceCommitSha, audience.SourceIdentitySha256, DateTimeOffset.UtcNow) != audience.SourceDefinitionSha256) { throw Invalid(); }
            string sourceConnection = new UTF8Encoding(false, true).GetString(Read(input.SourceCredential));
            pair = new(inputs, bundle, seed, ct)
            {
                _recoveryV2Case = expected,
                _recoveryV2Input = input,
                _recoveryAudience = audience,
                _recoveryAudienceClaim = audienceClaim,
                _recoveryCaseClaim = caseClaim,
                _recoverySourceConnection = sourceConnection
            };
            // Original signed source/precursor/owner/images/audience all precede target creation.
            await pair.CreateOwnedAsync(request, pair._lease.Token);
            await pair.PrepareRecoverySetupAsync(pair._lease.Token); return pair;
        }
        catch (Exception primary)
        {
            if (pair is not null) { try { await pair.DisposeAsync(); } catch (Exception cleanup) { primary.Data["recovery_pair_cleanup_failure"] = cleanup.GetType().Name; } }
            else
            {
                try { inputs?.Dispose(); } catch (Exception cleanup) { primary.Data["recovery_input_cleanup_failure"] = cleanup.GetType().Name; }
                try { bundle.Dispose(); } catch (Exception cleanup) { primary.Data["recovery_bundle_cleanup_failure"] = cleanup.GetType().Name; }
            }
            throw;
        }
    }
    private async Task PrepareRecoverySetupAsync(CancellationToken ct)
    {
        await RequireAsync(ct);
        if (_environment is null || _firstFiles is null || _secondFiles is null || _firstAuthority is null || _secondAuthority is null ||
            _firstPolicy is null || _secondPolicy is null || _dualDeviceProof is null || _executionClaims is not null) { throw Invalid(); }
        var native = await _environment.CaptureDualHelperNativeEvidenceAsync(Scope, _firstPolicy.HbaFile, _firstPolicy.RawRules, _secondPolicy.HbaFile, _secondPolicy.RawRules, ct);
        using var reviewer = DualSigner(_inputs.Pins.ReviewKeyId, CurrentAuthArchiveGenuineDualInputContract.ReviewKeyName, _inputs.Pins.ReviewFingerprint);
        using var authorizer = DualSigner(_inputs.Pins.AuthorizationKeyId, CurrentAuthArchiveGenuineDualInputContract.AuthorizationKeyName, _inputs.Pins.AuthorizationFingerprint);
        var review = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReviewDomain, Scope, reviewer);
        var auth = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain,
            new CurrentAuthArchiveAuthorization(Scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(review), DateTimeOffset.UtcNow, Scope.ExpiresAtUtc), authorizer);
        var old = _environment; _environment = null; old.Dispose();
        _environment = new(_firstFiles, _secondFiles, _firstAuthority, _secondAuthority, Scope, _inputs.Source, native.LocalTarget, native.ComparisonTarget,
            Connection(_firstFiles, _firstPolicy.OperatorConnectionPath), Connection(_secondFiles, _secondPolicy.OperatorConnectionPath),
            Connection(_firstFiles, _firstPolicy.OrdinaryConnectionPath), Connection(_secondFiles, _secondPolicy.OrdinaryConnectionPath),
            _dualDeviceProof, _inputs.TrustStore, _inputs.Pins, CurrentAuthLocalSessionArchivePolicy.Hash(auth));
        _executionClaims = new(review, auth); await RequireAsync(ct);
        static string Connection(CurrentAppOwnedRepairCustody files, string path)
        {
            return Encoding.UTF8.GetString(files.Read(path, maximumBytes: 65536));
        }
    }
    private async Task RequireRecoveryLiveAsync(bool baseline, CancellationToken ct)
    {
        if (_recoveryV2Case is not { } selected || _recoveryAudience is null || _executionClaims is null || _disposed || DateTimeOffset.UtcNow >= Scope.ExpiresAtUtc) { throw Invalid(); }
        CurrentAuthArchiveRecoveryV2.RequireAudience(_recoveryAudience, _seed, _inputs.Pins, DateTimeOffset.UtcNow);
        if (baseline) { await RequireAsync(ct); return; }
        await RequireRecoveryCustodyAsync(ct);
        if (_environment is not null) { await _environment.RequireAcceptedSourceOwnerCustodyAndTargetsAsync(Scope, ct); }
        if (_seed.CaseId != CurrentAuthArchiveRecoveryV2.CaseId(selected)) { throw Invalid(); }
    }
    async Task<CurrentAuthArchiveGenuineExecutionAttestation> ICurrentAuthArchiveRecoveryV2Lease.AttestExecutionAsync(bool baseline, CancellationToken ct)
    {
        await RequireRecoveryLiveAsync(baseline, ct);
        return _environment is null || _executionEnvironmentClosed
            ? throw Invalid()
            : new(CurrentAuthArchiveRecoveryV2.SetupCase(_recoveryV2Case!.Value), new("recovery", _seed.CaseId, Scope, Subject, _inputs.Source,
            typeof(CurrentAuthArchiveGenuineOwnedPair).Assembly.Location, typeof(MigrationConsole).Assembly.Location, typeof(CurrentAuthLocalSessionArchivePermit).Assembly.Location,
            _inputs.Pins, _inputs.TrustStore, _environment), _executionClaims!, CurrentAuthLocalSessionArchivePolicy.Hash(_executionClaims!.Authorization));
    }
    async Task<string> ICurrentAuthArchiveRecoveryV2Lease.ReadExecutionConnectionAsync(CancellationToken ct)
    { await RequireRecoveryLiveAsync(false, ct); await using var connection = RecoveryConnection(false, "Auth"); return connection.ConnectionString; }
    async Task<P256MigrationEvidenceSigner> ICurrentAuthArchiveRecoveryV2Lease.CreateExecutionSignerAsync(CancellationToken ct)
    {
        await RequireRecoveryLiveAsync(false, ct);
        return DualSigner(_inputs.Pins.EvidenceKeyId, CurrentAuthArchiveGenuineDualInputContract.EvidenceKeyName, _inputs.Pins.EvidenceFingerprint);
    }
    private NpgsqlConnection RecoveryConnection(bool comparison, string database)
    {
        var files = comparison ? _secondFiles : _firstFiles; var policy = comparison ? _secondPolicy : _firstPolicy;
        if (files is null || policy is null) { throw Invalid(); }
        var endpoint = new NpgsqlConnectionStringBuilder(Encoding.UTF8.GetString(files.Read(policy.OperatorConnectionPath, maximumBytes: 65536)))
        { Database = database, Pooling = false, Options = "", IncludeErrorDetail = false, Timeout = 5, CommandTimeout = 30 };
        return endpoint.Host != "127.0.0.1" || endpoint.Username != policy.Maintenance.Role || endpoint.Port is < 1 or > 65535 || string.IsNullOrWhiteSpace(endpoint.Password)
            ? throw Invalid()
            : new(endpoint.ConnectionString);
    }
}
