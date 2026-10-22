using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed record IsoNamedClosedPreparation(string ConfigurationPath, CurrentOwnerIsoRepairScope Scope,
    CurrentOwnerIsoRepairSigningPins Pins, CurrentAppOwnedRepairTargetPins Target,
    IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> Baseline, IReadOnlyDictionary<string, IsoCapturedNative> BeforeNative,
    string Endpoint, string CaseId);

// Only a newly allocated fixture can enter this preparation. Reviews/authorizations are
// absent on return: the actual public Console routes must issue them after root custody closes.
internal static class CurrentOwnerIsoNamedClosedConfiguration
{
    internal static async Task<IsoNamedClosedPreparation> PrepareAsync(CurrentOwnerIsoNamedClosedFixture fixture,
        FreshSchemaPlan source, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners,
        CurrentOwnerIsoRepairSourceInputs sourceInputs, IsoClosedBootstrapInputs precursors,
        CurrentOwnerIsoClosedPrecursorPins precursorPins, string nativeSha256, string maintenanceSha256,
        string helperPath, string testAssembly, string caseId, CancellationToken ct)
    {
        if (caseId is not ("complete" or "prepared-publication" or "lost-commit-ack" or "terminal-publication" or "wrong-owner" or "fleet-drift" or
            "unsafe-host" or "local-trust" or "ordinary-all26" or "exclusive-policy") ||
            await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != source.SourceCommitSha) { throw Invalid(); }
        var contract = ApprovedCurrentOwnerIsoOverlay.Create(source, source.SourceCommitSha, CurrentOwnerIsoSelection.LiteralWidthV1, owners, DateTimeOffset.UtcNow);
        // This is synthetic owned fixture data, not production SQL Server row parity.
        await IsoGuardedFleetFixture.BootstrapAsync(fixture.AdminConnection, source, contract, caseId, ct).ConfigureAwait(false);
        // The deliberate drift sentinel is created before the baseline, in this fixture only.
        await using (var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.AdminConnection) { Database = "Upload" }.ConnectionString))
        {
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await IsoGuardedFleetFixture.Sql(connection, null, "CREATE SCHEMA private; CREATE TABLE private.owner_iso_closed_sentinel(id integer PRIMARY KEY,evidence text NOT NULL); INSERT INTO private.owner_iso_closed_sentinel VALUES(1,'unchanged');", ct).ConfigureAwait(false);
        }
        var policy = await IsoNamedClosedMaintenance.InstallAsync(fixture.AdminConnection, fixture.Binding.ComputeSha256(), caseId, fixture.LeaseExpiresAtUtc, ct).ConfigureAwait(false);
        using var authority = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding);
        using var files = new CurrentAppOwnedRepairCustody(authority); files.Require();
        MigrationConsole.RequireCanonicalHelper(files.Read(helperPath, sharedReader: true), CurrentOwnerIsoRepairPermit.MaintenanceValidator);
        byte[] catalogBytes = files.Read(sourceInputs.AcceptedCatalogReportPath, sharedReader: true, maximumBytes: 8_000_000);
        string catalogHash = CurrentAppOwnedRepairPermit.Hash(catalogBytes);
        _ = CurrentOwnerIsoRepairSourceObservation.ReadCatalog(catalogBytes, source, catalogHash, source.SourceCommitSha, DateTimeOffset.UtcNow);
        var container = fixture.ContainerMetadata; var volume = fixture.VolumeMetadata;
        string pgData = container.GetProperty("Config").GetProperty("PgData").GetString() ?? throw Invalid();
        string id = fixture.ContainerId;
        var projected = System.Text.Json.Nodes.JsonNode.Parse(container.GetRawText())!.AsObject();
        var config = projected["Config"]!.AsObject(); _ = config.Remove("PgData"); config["Env"] = new System.Text.Json.Nodes.JsonArray("PGDATA=" + pgData);
        var observed = DockerLocalTargetObservation.Parse("[" + projected.ToJsonString() + "]", "[" + volume.GetRawText() + "]", id, fixture.VolumeName, fixture.LoopbackPort, false);
        string stat = await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(["--host", "npipe:////./pipe/docker_engine", "exec", id, "env", "TZ=UTC", "LC_ALL=C", "stat", "--printf=%d|%i|%f|%u|%g|%h|%s|%y|%z", "--", policy.Pin.HbaPath], ct,
            value => files.WriteNewAsync(Path.Combine(fixture.Root, $"iso-closed-stat-{value.RunId:N}.json"), JsonSerializer.SerializeToUtf8Bytes(value), CancellationToken.None)).ConfigureAwait(false);
        var target = new CurrentAppOwnedRepairTargetPins(id, fixture.VolumeName, container.GetProperty("Image").GetString(), CurrentOwnerIsoNamedClosedFixture.Image,
            policy.Pin.HbaPath, CurrentAppOwnedRepairPermit.Hash(Encoding.UTF8.GetBytes(stat)), null, null);
        var baseline = new List<CurrentAppOwnedDatabaseSnapshot>(); var beforeNative = new Dictionary<string, IsoCapturedNative>(StringComparer.Ordinal);
        foreach (string database in IsoGuardedFleetFixture.Names.Order(StringComparer.Ordinal))
        {
            CurrentOwnerIsoCapacity.Require(admission: false);
            baseline.Add(await IsoGuardedFleetFixture.CaptureAsync(policy.Endpoint, database, ct).ConfigureAwait(false));
            if (database is "Country" or "Material")
            {
                var native = await IsoGuardedFleetFixture.NativeAsync(policy.Endpoint, database, contract, false, ct).ConfigureAwait(false);
                CurrentOwnerIsoNativePreservation.RequireBefore(native, contract); beforeNative.Add(database, IsoCapturedNative.Capture(native));
                await Write("before-native-" + database + ".json", beforeNative[database]).ConfigureAwait(false);
            }
        }
        using var reviewKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var receiptKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var bootstrapKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECDsa[] keys = [reviewKey, authorizationKey, receiptKey, bootstrapKey]; string suffix = fixture.Operation.ToString("N");
        string[] ids = ["iso-closed-review-" + suffix, "iso-closed-authorization-" + suffix, "iso-closed-receipt-" + suffix, "iso-closed-bootstrap-" + suffix];
        string[] fingerprints = [.. keys.Select(x => CurrentAppOwnedRepairPermit.Hash(x.ExportSubjectPublicKeyInfo()))];
        if (fingerprints.Distinct(StringComparer.Ordinal).Count() != 4) { throw Invalid(); }
        var trusted = new List<DeltaTrustedKeyReference>();
        for (int i = 0; i < 4; i++)
        {
            string publicPath = Path.Combine(fixture.Root, ids[i] + ".public.txt");
            await files.WriteNewAsync(publicPath, Encoding.UTF8.GetBytes(Convert.ToBase64String(keys[i].ExportSubjectPublicKeyInfo())), ct).ConfigureAwait(false);
            await files.WriteNewAsync(Path.Combine(fixture.Root, ids[i] + ".private.pem"), Encoding.UTF8.GetBytes(keys[i].ExportPkcs8PrivateKeyPem()), ct).ConfigureAwait(false);
            trusted.Add(new(ids[i], publicPath));
        }
        var pins = new CurrentOwnerIsoRepairSigningPins(ids[0], fingerprints[0], ids[1], fingerprints[1], ids[2], fingerprints[2]);
        var subject = new CurrentOwnerIsoComponentSubject(fixture.Operation, precursorPins.DefinitionProofSha256, source.SourceCommitSha, catalogHash,
            SchemaPlanCanonicalizer.ComputeSha256(source), CurrentAppOwnedSnapshotSerialization.Sha256(owners), contract.ComputeSha256(), PostgreSqlCurrentOwnerIsoRepair.OperationSha256,
            new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/disposable-" + id[..12], policy.Identity),
            CurrentAppOwnedSnapshotSerialization.Sha256(target), fixture.Binding.ComputeSha256(), ImageHash(typeof(MigrationConsole).Assembly.Location),
            ImageHash(typeof(CurrentOwnerIsoRepairPermit).Assembly.Location), ImageHash(testAssembly), DateTimeOffset.UtcNow, policy.Pin.ExpiresAtUtc);
        var unsigned = new CurrentOwnerIsoComponentSubjectClaim("current-owner-iso-component-subject-v1", subject, ids[3], null);
        var bootstrap = new CurrentOwnerIsoExecutionBootstrap("current-owner-iso-closed-bootstrap-v1", caseId, unsigned, ids[3], fingerprints[3],
            LocalDockerGenerationGuard.ComposeGeneration(observed), beforeNative["Country"].Snapshot.Sha256, beforeNative["Material"].Snapshot.Sha256,
            CurrentAppOwnedSnapshotSerialization.Sha256(baseline), subject.SourceSchemaPlanSha256, nativeSha256, maintenanceSha256, precursorPins.DefinitionSubjectSha256,
            fixture.VolumeName, id, fixture.Name, fixture.LoopbackPort, precursorPins, container.GetProperty("Created").GetDateTimeOffset(), volume.GetProperty("CreatedAt").GetDateTimeOffset(), fixture.LeaseExpiresAtUtc);
        var scope = new CurrentOwnerIsoRepairScope(fixture.Operation, CurrentOwnerIsoSelection.LiteralWidthV1, subject.SourceCommitSha, subject.SourceSchemaPlanSha256,
            subject.OwnerSourcesSha256, subject.ContractSha256, subject.FixedOperationSha256, subject.IntendedTarget, "local-aspire", "legacy-postgres-main-local",
            bootstrap.TargetGeneration, subject.TargetObservationSha256, subject.RunBindingSha256, baseline.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal),
            bootstrap.FleetBeforeSha256, nativeSha256, string.Empty, string.Empty, policy.Pin, CurrentOwnerIsoRepairPermit.FreshOnlyPolicy, catalogHash,
            CurrentOwnerIsoRepairPermit.MaintenanceValidator, maintenanceSha256, CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap, bootstrap);
        // Genuine completed definition/native/maintenance readers run BEFORE this subject is signed.
        await IsoClosedBootstrapReadback.RequireAsync(files, fixture.Binding, scope, precursors, ct).ConfigureAwait(false);
        bootstrap = bootstrap with { Claim = unsigned with { Signature = Convert.ToBase64String(bootstrapKey.SignData(CurrentOwnerIsoBootstrapSubjectValidator.Payload(unsigned), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) } };
        scope = scope with { BootstrapSubject = bootstrap };
        var trust = new ReceiptAttestationTrustStore(ids.Select((key, index) => new TrustedAttestationKey(key, keys[index].ExportSubjectPublicKeyInfo())));
        CurrentOwnerIsoRepairPermit.ValidateClosedBootstrapScope(scope, source, owners, trust, pins, DateTimeOffset.UtcNow);
        CurrentOwnerIsoNamedClosedTarget.Require(scope, target, container, volume, fixture.LoopbackPort, DateTimeOffset.UtcNow);
        string baselinePath = Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-fleet-before.json"); await files.WriteBaselineNewAsync(baselinePath, baseline.ToArray(), ct).ConfigureAwait(false);
        await files.WriteNewAsync(Path.Combine(fixture.Root, "operator.txt"), Encoding.UTF8.GetBytes(policy.Endpoint), ct).ConfigureAwait(false);
        await files.WriteNewAsync(Path.Combine(fixture.Root, "ordinary.txt"), Encoding.UTF8.GetBytes(fixture.AdminConnection), ct).ConfigureAwait(false);
        await Write("closed-source.json", source).ConfigureAwait(false); await Write("closed-owners.json", owners).ConfigureAwait(false);
        await Write("closed-scope.json", scope).ConfigureAwait(false); await Write("closed-pins.json", pins).ConfigureAwait(false);
        await Write("closed-target.json", target).ConfigureAwait(false); await Write("closed-binding.json", fixture.Binding).ConfigureAwait(false);
        await Write("installed-policy.json", new { policy.Pin, policy.Identity, rawHba = policy.RawHba, rawRules = policy.RawRules, observedAtUtc = DateTimeOffset.UtcNow }).ConfigureAwait(false);
        await Write("native-policy.json", await IsoMaintenanceNativeObserver.CaptureAsync(policy.Endpoint, ct).ConfigureAwait(false)).ConfigureAwait(false);
        await Write("public-keys.json", ids.Select((id, index) => new IsoCasePublicKey(id, Convert.ToBase64String(keys[index].ExportSubjectPublicKeyInfo()))).ToArray()).ConfigureAwait(false);
        var configuration = new CurrentOwnerIsoRepairConfiguration(Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-source.json"), sourceInputs, Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-owners.json"),
            Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-scope.json"), Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-review.json"), Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-authorization.json"), Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-pins.json"),
            Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-binding.json"), Path.Combine(fixture.Root, "operator.txt"), Path.Combine(fixture.Root, "ordinary.txt"), baselinePath, Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-target.json"),
            trusted, Path.Combine(fixture.Root, ids[2] + ".private.pem"), new(precursors.NativeComponentPath, nativeSha256), null, null, new(precursors.MaintenanceComponentPath, maintenanceSha256), helperPath,
            Path.Combine(fixture.Root, ids[0] + ".private.pem"), Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-review.json"), policy.Pin.ExpiresAtUtc, Path.Combine(fixture.Root, ids[1] + ".private.pem"),
            Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-authorization.json"), CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap, precursors);
        string path = Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-configuration.json"); await Write("closed-configuration.json", configuration).ConfigureAwait(false); files.Require();
        return new(path, scope, pins, target, baseline, beforeNative, policy.Endpoint, caseId);
        async Task Write<T>(string name, T value) { await files.WriteNewAsync(Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-" + name), JsonSerializer.SerializeToUtf8Bytes(value), ct).ConfigureAwait(false); }
    }
    private static string ImageHash(string path) { using var held = SecureLocalFile.OpenReadShared(path); return Convert.ToHexStringLower(SHA256.HashData(held)); }
    private static MigrationExecutionException Invalid()
    {
        return CurrentOwnerIsoRepairPermit.Invalid();
    }
}
