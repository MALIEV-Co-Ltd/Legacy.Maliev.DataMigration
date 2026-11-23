using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

// Fixed accepted-bundle entry, invoked only by the Console's whitelisted loader. Not an execution-proof test.
internal static class CurrentAuthArchiveInitialNativeProducer
{
    internal static async Task<CurrentAuthArchiveComponentBootstrapSubject> ObserveAsync(
        CurrentAuthArchiveInitialProducerConfiguration config, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        CurrentAuthArchiveInitialProducer.RequireInput(config);
        // OpenInitial holds and authenticates parent/precursor/source/owner/images before CreateAsync is reachable.
        using var inputs = await CurrentAuthArchiveComponentReadback.OpenInitialAsync(config.Inputs, ct).ConfigureAwait(false);
        CurrentAuthArchiveComponentBootstrapSeed seed = await inputs.ReadSeedAsync(ct).ConfigureAwait(false);
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lease.CancelAfter(seed.ExpiresAtUtc - DateTimeOffset.UtcNow); ct = lease.Token;
        _ = await RetainAsync(inputs, "initial-authenticated", new
        { seed.OperationId, seed.AcceptedSourceCommitSha, seed.SourceSchemaPlanSha256, seed.DefinitionPrecursorSha256 }, ct);
        try
        {
            CurrentAuthArchiveComponentBootstrapSubject observed = await ObservePairAsync(config, inputs, seed, ct).ConfigureAwait(false);
            // Both exact targets and credentials have been disposed and absence-checked before success is retained.
            await inputs.RequireAsync(ct);
            _ = await RetainAsync(inputs, "observed-after-cleanup", observed, ct);
            return observed;
        }
        catch
        {
            using var retention = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            _ = await RetainAsync(inputs, "failed-no-proof", new { seed.OperationId, NoExecutionAuthority = true }, retention.Token);
            throw;
        }
    }

    private static async Task<CurrentAuthArchiveComponentBootstrapSubject> ObservePairAsync(
        CurrentAuthArchiveInitialProducerConfiguration config, CurrentAuthArchiveComponentReadback inputs,
        CurrentAuthArchiveComponentBootstrapSeed seed, CancellationToken ct)
    {
        await inputs.RequireAsync(ct);
        await using var local = await CurrentAuthArchiveFixtureTarget.CreateAsync(config.FirstFixtureParent, inputs.ParentFiles,
            inputs.SourceArtifact, seed.AcceptedSourceCommitSha, seed.OperationId, comparison: false, ct);
        await inputs.RequireAsync(ct);
        await using var comparison = await CurrentAuthArchiveFixtureTarget.CreateAsync(config.SecondFixtureParent, inputs.ParentFiles,
            inputs.SourceArtifact, seed.AcceptedSourceCommitSha, seed.OperationId, comparison: true, ct);
        var firstSeed = await CurrentAuthArchiveFixtureSeed.SeedAndCaptureAsync(local, inputs.ParentFiles, inputs.SourceArtifact, seed.AcceptedSourceCommitSha, ct);
        var secondSeed = await CurrentAuthArchiveFixtureSeed.SeedAndCaptureAsync(comparison, inputs.ParentFiles, inputs.SourceArtifact, seed.AcceptedSourceCommitSha, ct);
        using var firstPolicy = await CurrentAuthArchiveFixturePolicy.InstallAndObserveAsync(local, firstSeed, inputs.ParentFiles, inputs.SourceArtifact, seed.AcceptedSourceCommitSha, ct);
        using var secondPolicy = await CurrentAuthArchiveFixturePolicy.InstallAndObserveAsync(comparison, secondSeed, inputs.ParentFiles, inputs.SourceArtifact, seed.AcceptedSourceCommitSha, ct);
        using var firstAuthority = WindowsLocalRunAuthority.AcquireResume(local.Root, local.Binding);
        using var secondAuthority = WindowsLocalRunAuthority.AcquireResume(comparison.Root, comparison.Binding);
        using var firstFiles = new CurrentAppOwnedRepairCustody(firstAuthority);
        using var secondFiles = new CurrentAppOwnedRepairCustody(secondAuthority);
        await inputs.RequireAsync(ct);
        var first = await CaptureTargetAsync(local, firstPolicy, ct);
        var second = await CaptureTargetAsync(comparison, secondPolicy, ct);
        CurrentAuthRepairScope localPolicy = ObservationPolicy(seed, local, firstPolicy, first.Pins, first.Docker.Target);
        CurrentAuthRepairScope comparisonPolicy = ObservationPolicy(seed, comparison, secondPolicy, second.Pins, second.Docker.Target);
        var paths = new CurrentAuthArchivePaths(Path.Combine(local.Root, "archive-first.ciphertext"),
            Path.Combine(comparison.Root, "archive-second.ciphertext"), Path.Combine(local.Root, "archive-first-recovery.pem"),
            Path.Combine(comparison.Root, "archive-second-recovery.pem"));
        DateTimeOffset deviceBegan = DateTimeOffset.UtcNow;
        var request = new CurrentAuthArchiveDevicePreflightRequest("Legacy.Maliev.CurrentAuth.ArchiveDevicePreflight.v1",
            seed.OperationId, seed.AcceptedSourceCommitSha, localPolicy.RunBindingSha256, comparisonPolicy.RunBindingSha256,
            localPolicy.TargetObservationSha256, comparisonPolicy.TargetObservationSha256, paths, local.Root, comparison.Root,
            deviceBegan, deviceBegan.AddMinutes(1));
        CurrentAuthArchiveDeviceProof devices = await CurrentAuthLocalSessionArchiveDeviceProcess.ObservePreflightAsync(request, firstFiles, secondFiles, ct);
        CurrentAuthArchiveFleet localFleet = Fleet(firstPolicy.Baseline, localPolicy);
        CurrentAuthArchiveFleet comparisonFleet = Fleet(secondPolicy.Baseline, comparisonPolicy);
        byte[] rows = CurrentAuthLocalSessionArchivePolicy.EncodeRows(localFleet.Auth.Sessions);
        CurrentAuthArchiveComponentBootstrapSubject subject;
        try
        {
            subject = new("current-auth-actual-paired-archive-component-subject-v1", seed,
                CurrentAuthLocalSessionArchiveEnvironment.ObservedTarget(first.Docker, first.Pins, firstAuthority, localPolicy, localFleet),
                CurrentAuthLocalSessionArchiveEnvironment.ObservedTarget(second.Docker, second.Pins, secondAuthority, comparisonPolicy, comparisonFleet),
                CurrentAuthLocalSessionArchivePolicy.Hash(devices), CurrentAuthLocalSessionArchivePolicy.HashBytes(rows), localFleet.Auth.Sessions.Count,
                CurrentAuthLocalSessionArchivePolicy.RequireComparison(localFleet.Auth, comparisonFleet.Auth), CurrentAuthLocalSessionArchivePolicy.Hash(paths));
        }
        finally { CryptographicOperations.ZeroMemory(rows); }
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset expires = new[] { seed.ExpiresAtUtc, firstPolicy.Maintenance.ExpiresAtUtc.AddSeconds(-1),
            secondPolicy.Maintenance.ExpiresAtUtc.AddSeconds(-1), now.AddMinutes(4) }.Min();
        var scope = new CurrentAuthArchiveScope(seed.OperationId, localPolicy, comparisonPolicy, subject.DeleteSetSha256,
            subject.DeleteCount, subject.ApplicationComparisonSha256, paths, subject.RecoveryDeviceProofSha256,
            string.Empty, string.Empty, string.Empty, string.Empty, now, expires,
            CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap, subject);
        CurrentAuthArchiveComponentBootstrap.RequireClaims(scope, inputs.TrustStore, inputs.Pins, now);
        CurrentAuthArchiveProofArtifact scopeArtifact = await RetainAsync(inputs, "candidate-scope", scope, ct);
        _ = await RetainAsync(inputs, "candidate-devices", devices, ct);
        await inputs.AttachObservedScopeAsync(scopeArtifact, ct);
        using var environment = new CurrentAuthLocalSessionArchiveEnvironment(firstFiles, secondFiles, firstAuthority, secondAuthority,
            scope, inputs.Source, first.Pins, second.Pins,
            Encoding.UTF8.GetString(firstFiles.Read(firstPolicy.OperatorConnectionPath, maximumBytes: 65536)),
            Encoding.UTF8.GetString(secondFiles.Read(secondPolicy.OperatorConnectionPath, maximumBytes: 65536)),
            Encoding.UTF8.GetString(firstFiles.Read(firstPolicy.OrdinaryConnectionPath, maximumBytes: 65536)),
            Encoding.UTF8.GetString(secondFiles.Read(secondPolicy.OrdinaryConnectionPath, maximumBytes: 65536)),
            devices, inputs.TrustStore, inputs.Pins, CurrentAuthLocalSessionArchivePolicy.Hash(seed));
        return await environment.ObserveComponentSubjectAsync(inputs, ct);
    }

    private static CurrentAuthRepairScope ObservationPolicy(CurrentAuthArchiveComponentBootstrapSeed seed,
        CurrentAuthArchiveFixtureTarget fixture, CurrentAuthArchiveFixtureInstalledPolicy policy,
        CurrentAppOwnedRepairTargetPins pins, DockerLocalTargetObservation target)
    {
        var map = policy.Baseline.Databases.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal);
        return new(seed.OperationId, CurrentAuthRepairOperation.SixteenSameTypeTextCollations,
            seed.AcceptedSourceCommitSha, seed.SourceSchemaPlanSha256, seed.AuthOwnerCommitSha, seed.OwnerPinsSha256, seed.ClosureSha256,
            ApprovedCurrentAuthSchema.PhysicalSha256(true), ApprovedCurrentAuthSchema.PhysicalSha256(true),
            CurrentAuthLocalSessionArchivePolicy.Hash(seed), seed.DefinitionPrecursorSha256, CurrentAuthRepairEnvironment.IntegratedMaintenanceValidatorSha256,
            new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/disposable-" + fixture.ContainerId[..12], policy.Baseline.Before.SystemIdentifierSha256),
            "local-aspire", "legacy-postgres-main-local", LocalDockerGenerationGuard.ComposeGeneration(target),
            CurrentAuthLocalSessionArchivePolicy.Hash(pins), fixture.Binding.ComputeSha256(), map, CurrentAuthRepairPermit.FleetSha256(map),
            string.Empty, string.Empty, string.Empty, policy.Maintenance, CurrentAuthProofAdmission.DisposableNativeBootstrap);
    }

    private static CurrentAuthArchiveFleet Fleet(CurrentAuthArchiveFixtureSeedCapture capture, CurrentAuthRepairScope policy)
    {
        CurrentAuthArchiveCatalogObservation Catalog(CurrentAuthArchiveFixtureSeedCatalog x)
        {
            return new(policy.RunBindingSha256,
            policy.TargetObservationSha256, x.SystemIdentifierSha256, x.ReadOnly, x.Databases, x.BeganAtUtc, x.EndedAtUtc);
        }
        // Native capture brackets all database snapshots between its catalog reads.
        var catalogs = new CurrentAuthArchiveFleetCatalogs(Catalog(capture.Before), Catalog(capture.After), capture.Before.EndedAtUtc, capture.After.BeganAtUtc);
        return new(capture.Auth, capture.Databases, catalogs.CaptureBeganAtUtc, catalogs.CaptureEndedAtUtc, catalogs);
    }

    private static async Task<(CurrentAppOwnedRepairTargetPins Pins, CurrentAuthLocalSessionArchiveEnvironment.ObservedDocker Docker)> CaptureTargetAsync(
        CurrentAuthArchiveFixtureTarget fixture, CurrentAuthArchiveFixtureInstalledPolicy policy, CancellationToken ct)
    {
        await fixture.RequireHealthyAsync(ct);
        Task<string> Docker(IReadOnlyList<string> args)
        {
            return CurrentAppOwnedRepairDockerProcess.RunDockerAsync(args, ct,
            value => fixture.RecordAsync("initial-observer-docker", value, CancellationToken.None));
        }

        string container = await Docker(["inspect", "--type", "container", fixture.ContainerId]);
        string volume = await Docker(["inspect", "--type", "volume", fixture.Name]);
        var target = DockerLocalTargetObservation.Parse(container, volume, fixture.ContainerId, fixture.Name,
            new NpgsqlConnectionStringBuilder(fixture.AdminConnection).Port, persistent: false);
        string stat = await Docker(["exec", fixture.ContainerId, "env", "TZ=UTC", "LC_ALL=C", "stat", "--printf=%d|%i|%f|%u|%g|%h|%s|%y|%z", "--", policy.Maintenance.HbaPath]);
        using JsonDocument parsed = JsonDocument.Parse(container);
        var pins = new CurrentAppOwnedRepairTargetPins(fixture.ContainerId, fixture.Name, parsed.RootElement[0].GetProperty("Image").GetString(),
            CurrentAuthArchiveFixtureTarget.Image, policy.Maintenance.HbaPath, CurrentAuthLocalSessionArchivePolicy.HashBytes(Encoding.UTF8.GetBytes(stat)), null, null);
        return (pins, new(container, volume, target));
    }

    private static async Task<CurrentAuthArchiveProofArtifact> RetainAsync<T>(CurrentAuthArchiveComponentReadback inputs,
        string phase, T value, CancellationToken ct)
    {
        string path = Path.Combine(inputs.ParentAuthority.Binding.ArtifactRootCanonicalPath, "archive-pair-" + phase + ".json");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        await inputs.ParentFiles.WriteNewAsync(path, bytes, ct);
        return !inputs.ParentFiles.Read(path, sharedReader: true, maximumBytes: 1024 * 1024).AsSpan().SequenceEqual(bytes)
            ? throw CurrentAuthLocalSessionArchivePolicy.Invalid()
            : new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
    }
}
