using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CompanyStorageObservationExpectation(string Kind, string SourceIdentitySha256, DeltaTargetAuthority Target,
    string TargetNamespace, string TargetCluster, string TargetGeneration, bool OwnerIsoAlreadyApplied, CurrentAppOwnedMaintenancePin Maintenance);

internal sealed partial class CompanyStorageRepairInputs
{
    // The observation config's IntentClaim slot contains only an expectation, not an accepted preimage.
    // Native/fleet/provider/owner facts below are always observed before signing an apply intent.
    internal static async Task<CompanyStorageArtifact> ObserveAndSignAsync(string path, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly) { throw Invalid(); }
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
        byte[] raw = ReadLoose(path, 65536);
        var config = MigrationConsole.DecodeAuthRepair<CompanyStorageRepairConfiguration>(raw);
        if (config.Kind != "current-company-storage-observe-configuration-v1") { throw Invalid(); }
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(ReadLoose(config.RunBindingPath, 65536));
        using var authority = WindowsLocalRunAuthority.AcquireResume(Path.GetDirectoryName(path)!, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        if (!files.Read(path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(raw) ||
            Path.GetDirectoryName(config.RunBindingPath) != binding.ArtifactRootCanonicalPath) { throw Invalid(); }
        var expectation = MigrationConsole.DecodeAuthRepair<CompanyStorageObservationExpectation>(Read(files, config.IntentClaim));
        if (expectation.Kind != "current-company-storage-observation-expectation-v1" ||
            !Path.IsPathFullyQualified(config.ProofParent) || !Directory.Exists(config.ProofParent)) { throw Invalid(); }
        var trust = new ReceiptAttestationTrustStore(config.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
            files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
        CurrentAuthLocalSessionArchivePolicy.RequirePins(ArchivePins(config.SigningPins), trust);
        byte[] secret = Read(files, config.SourceCredential);
        ConsumerColumnBootstrapSourceCapture source;
        try { source = await ConsumerColumnBootstrapProofSourceCapture.CaptureAsync(new System.Text.UTF8Encoding(false, true).GetString(secret), expectation.SourceIdentitySha256, accepted, ct); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(secret); }
        var pins = MigrationConsole.DecodeAuthRepair<CurrentAppOwnedRepairTargetPins>(Read(files, config.TargetPins));
        var names = expectation.Target.Kind == DeltaTargetAuthorityKind.ProductionCloudNativePg ? ReviewedProductionRepairInventory.ExportProductionNames() :
            DatabaseInventory.ActiveDatabases.Concat(LocalObservationExtras).ToArray();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var draft = new CompanyStorageRepairIntent(CompanyStorageRepairProtocol.IntentKind, Guid.NewGuid(), accepted, source.FullPlanSha256,
            source.SourceIdentitySha256, SourceCatalogDefinitionFingerprintV1.Compute(source.Plan, accepted, source.SourceIdentitySha256, now),
            new('0', 64), new('0', 64), CompanyStorageRepairProtocol.CandidateSha256, expectation.OwnerIsoAlreadyApplied, false,
            expectation.Target, expectation.TargetNamespace, expectation.TargetCluster, expectation.TargetGeneration, CompanyStorageRepairProtocol.Hash(pins),
            binding.ComputeSha256(), names.ToDictionary(x => x, _ => new string('0', 64), StringComparer.Ordinal), new('0', 64), "postgres", expectation.Maintenance,
            now, now.AddMinutes(5) < expectation.Maintenance.ExpiresAtUtc ? now.AddMinutes(5) : expectation.Maintenance.ExpiresAtUtc);
        // This in-memory draft is never retained or accepted as a preimage or apply claim.
        var input = new CompanyStorageRepairInputs(authority, files, config, draft, null!, trust);
        using var reviewer = input.Signer(config.ReviewPrivateKey, config.SigningPins.ReviewKeyId, config.SigningPins.ReviewFingerprint);
        using var authorizer = input.Signer(config.AuthorizationPrivateKey, config.SigningPins.AuthorizationKeyId, config.SigningPins.AuthorizationFingerprint);
        using var evidence = input.Signer(config.EvidencePrivateKey, config.SigningPins.ReceiptKeyId, config.SigningPins.ReceiptFingerprint);
        _ = authorizer.PublicKeyFingerprintSha256; _ = evidence.PublicKeyFingerprintSha256;
        var owner = await CompanyStorageRuntime.OwnerAsync(input, ct);
        var contract = ApprovedCustomerCompanyStorageRepair.Create(source.Plan.Databases.Single(x => x.Database == "Customer"), accepted, accepted, owner, DateTimeOffset.UtcNow);
        draft = draft with { CustomerBeforeSchemaSha256 = contract.Before().TargetSchemaSha256, CustomerAfterSchemaSha256 = contract.After().TargetSchemaSha256 };
        var actualInput = new CompanyStorageRepairInputs(authority, files, config, draft, null!, trust);
        var (After, Native, Fleet) = await CompanyStorageRuntime.ObserveReadOnlyAsync(actualInput, source, contract, ct);
        now = DateTimeOffset.UtcNow;
        var intent = draft with
        {
            SchemaAlreadyCorrect = After,
            NativePreimageSha256 = Native.Sha256,
            CompanyOwnerName = Native.OwnerName,
            BeforeDatabaseSha256 = Fleet.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal),
            IssuedAtUtc = now,
            ExpiresAtUtc = now.AddMinutes(5) < expectation.Maintenance.ExpiresAtUtc ? now.AddMinutes(5) : expectation.Maintenance.ExpiresAtUtc,
        };
        _ = CompanyStorageRepairProtocol.RequireIntent(intent, source.Plan, owner, now);
        source.Require(accepted, expectation.SourceIdentitySha256, now);
        if (now - source.BeganAtUtc > TimeSpan.FromMinutes(5)) { throw Invalid(); }
        var signed = CurrentAuthLocalSessionArchivePolicy.Sign(CompanyStorageRepairProtocol.IntentDomain, intent, reviewer);
        var claim = await input.PublishAsync("observed-intent", signed, intent.IntentId, ct);
        _ = await input.PublishAsync("observed-source", source, intent.IntentId, ct);
        _ = await input.PublishAsync("observed-native-and-fleet", new
        {
            Kind = "company-storage-readonly-observation-v1",
            NativeSha256 = Native.Sha256,
            Native.Observation.ProviderVersion,
            Native.Observation.CompositeDefense,
            Native.OwnerName,
            BeforeFleet = Fleet,
            SourceFullSha256 = source.FullPlanSha256,
            intent.SourceDefinitionSha256,
            ObservedAtUtc = now,
        }, intent.IntentId, ct);
        return await input.PublishAsync("apply-configuration", config with { Kind = "current-company-storage-fixed-configuration-v1", IntentClaim = claim }, intent.IntentId, ct);
    }
    private static readonly string[] LocalObservationExtras = ["Auth", "postgres", "legacy_local"];
}

internal sealed partial class CompanyStorageRuntime
{
    internal static async Task<(bool After, CompanyStorageNativeWitness Native, IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> Fleet)> ObserveReadOnlyAsync(
        CompanyStorageRepairInputs input, ConsumerColumnBootstrapSourceCapture source, ApprovedCustomerCompanyStorageRepair contract, CancellationToken ct)
    {
        using var runtime = new CompanyStorageRuntime(input, source, contract);
        await runtime.RequireAsync(ct);
        bool after;
        await using (var connection = runtime.Connect("Customer"))
        {
            await connection.OpenAsync(ct); await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await ReadOnlyAsync(connection, transaction, ct); await RequirePolicyAsync(connection, transaction, input.Intent.Maintenance, input.Intent.Target, ct);
            await using var command = new NpgsqlCommand("""
                SELECT array_agg(a.atttypid::regtype::text ORDER BY a.attname COLLATE "C")
                FROM pg_attribute a WHERE a.attrelid='public."Company"'::regclass AND a.attname IN ('Name','Registrar','TaxNumber') AND NOT a.attisdropped;
                """, connection, transaction);
            string[] types = (string[])(await command.ExecuteScalarAsync(ct))!;
            after = types.Length == 3 && types.All(x => x == "text");
            if (!after && (types.Length != 3 || types.Any(x => x != "character varying"))) { throw Invalid(); }
            await transaction.RollbackAsync(ct);
        }
        var native = await runtime.ReadNativeAsync(after, ct); var fleet = await runtime.FleetAsync(after, ct);
        if (native.Observation.Native.Snapshot.Sha256 != fleet.Single(x => x.Database == "Customer").Sha256) { throw Invalid(); }
        await runtime.RequireAsync(ct); return (after, native, fleet);
    }
}
