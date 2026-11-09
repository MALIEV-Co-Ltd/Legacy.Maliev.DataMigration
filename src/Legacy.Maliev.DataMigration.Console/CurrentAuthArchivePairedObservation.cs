using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CurrentAuthLocalSessionArchiveEnvironment
{
    private sealed record ObservedDocker(string Container, string Volume, DockerLocalTargetObservation Target);

    // Fixed read-only observer only. Permit admission and the public bootstrap route remain closed.
    internal async Task<CurrentAuthArchiveComponentBootstrapSubject> ObserveComponentSubjectAsync(
        CurrentAuthArchiveComponentReadback inputs, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try { return await ObserveFreshComponentSubjectAsync(inputs, ct).ConfigureAwait(false); }
        finally { _ = _gate.Release(); }
    }

    private async Task<CurrentAuthArchiveComponentBootstrapSubject> ObserveFreshComponentSubjectAsync(
        CurrentAuthArchiveComponentReadback inputs, CancellationToken ct)
    {
        if (_scope.ProofAdmission != CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap || _reserved || _terminal || _prepared is not null)
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        CurrentAuthArchiveComponentBootstrapSeed seed = await inputs.RequireEnvironmentAsync(_scope, _source, ct).ConfigureAwait(false);
        CurrentAuthLocalSessionArchivePolicy.RequirePins(_pins, _trust);
        if (CurrentAuthLocalSessionArchivePolicy.Hash(_pins) != seed.SigningPinsSha256) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        await RequireAcceptedSourceOwnerCustodyAndTargetsAsync(_scope, ct).ConfigureAwait(false);
        CurrentAuthArchiveFleet local = await CaptureAsync(_scope, true, ct).ConfigureAwait(false);
        CurrentAuthArchiveFleet comparison = await CaptureAsync(_scope, false, ct).ConfigureAwait(false);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(local, _scope.LocalObservationPolicy, now);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(comparison, _scope.ProductionObservationPolicy, now, comparison: true);
        await FrameAsync("component-catalogs", new { Local = local.Catalogs, Comparison = comparison.Catalogs }).ConfigureAwait(false);
        var targets = await RequireTargetsAsync(ct).ConfigureAwait(false);
        await _storage.RequireCustodyAsync(ct).ConfigureAwait(false);
        byte[] rows = CurrentAuthLocalSessionArchivePolicy.EncodeRows(local.Auth.Sessions);
        CurrentAuthArchiveComponentBootstrapSubject observed;
        try
        {
            observed = new("current-auth-actual-paired-archive-component-subject-v1", seed,
                ObservedTarget(targets.Local, _localTarget, _localAuthority, _scope.LocalObservationPolicy, local),
                ObservedTarget(targets.Comparison ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid(),
                    _productionTarget, _productionAuthority, _scope.ProductionObservationPolicy, comparison),
                _scope.RecoveryDeviceProofSha256, CurrentAuthLocalSessionArchivePolicy.HashBytes(rows), local.Auth.Sessions.Count,
                CurrentAuthLocalSessionArchivePolicy.RequireComparison(local.Auth, comparison.Auth),
                CurrentAuthLocalSessionArchivePolicy.Hash(_scope.Paths));
        }
        finally { CryptographicOperations.ZeroMemory(rows); }
        // Candidate facts are not a completion receipt; authenticate again after retaining them.
        await FrameAsync("component-subject-candidate", observed).ConfigureAwait(false);
        // Re-read held inputs after all native work; no caller-supplied observed callback is used.
        await inputs.RequireObservedEnvironmentAsync(_scope, _source, observed, ct).ConfigureAwait(false);
        RequireHealthy();
        return observed;
    }

    private static CurrentAuthArchiveComponentTargetSubject ObservedTarget(ObservedDocker docker,
        CurrentAppOwnedRepairTargetPins pins, WindowsLocalRunAuthority authority, CurrentAuthRepairScope policy,
        CurrentAuthArchiveFleet fleet)
    {
        using JsonDocument container = JsonDocument.Parse(docker.Container);
        return new(authority.Binding.ComputeSha256(), docker.Target.ContainerId, docker.Target.ContainerName.TrimStart('/'),
            docker.Target.VolumeName, container.RootElement[0].GetProperty("Image").GetString() ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid(),
            docker.Target.PgData, LocalDockerGenerationGuard.ComposeGeneration(docker.Target), CurrentAuthLocalSessionArchivePolicy.Hash(pins),
            CurrentAuthLocalSessionArchivePolicy.HashBytes(Encoding.UTF8.GetBytes(docker.Container)),
            CurrentAuthLocalSessionArchivePolicy.HashBytes(Encoding.UTF8.GetBytes(docker.Volume)),
            fleet.Catalogs!.Before.SystemIdentifierSha256,
            CurrentAuthRepairPermit.FleetSha256(fleet.Databases.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal)),
            fleet.Auth.Native.Snapshot.Sha256, ComponentCatalogSha256(fleet.Catalogs),
            CurrentAuthLocalSessionArchivePolicy.Hash(policy.Maintenance));
    }

    // RequireFleet validates every capture clock separately; this digest binds repeatable native facts.
    internal static string ComponentCatalogSha256(CurrentAuthArchiveFleetCatalogs catalogs)
    {
        static object Facts(CurrentAuthArchiveCatalogObservation value)
        {
            return new
            {
                value.RunBindingSha256,
                value.TargetObservationSha256,
                value.SystemIdentifierSha256,
                value.ReadOnly,
                Databases = value.Databases.OrderBy(x => x.Name, StringComparer.Ordinal).ToArray(),
            };
        }
        return CurrentAuthLocalSessionArchivePolicy.Hash(new { Before = Facts(catalogs.Before), After = Facts(catalogs.After) });
    }
}
