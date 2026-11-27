using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record SourceOrderOwnerIsoExpectation(string Kind, string SourceIdentitySha256, DeltaTargetAuthority Target, string TargetNamespace,
    string TargetCluster, string TargetGeneration, bool CompanyAlreadyApplied, CurrentAppOwnedMaintenancePin Maintenance);

internal sealed partial class SourceOrderOwnerIsoInputs
{
    internal static async Task<CompanyStorageArtifact> ObserveAndSignAsync(string path, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly) { throw Invalid(); }
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
        byte[] bytes = ReadLoose(path, 65536); var config = MigrationConsole.DecodeAuthRepair<SourceOrderOwnerIsoConfiguration>(bytes);
        if (config.Kind != "source-order-owner-iso-observe-configuration-v1") { throw Invalid(); }
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(ReadLoose(config.RunBindingPath, 65536));
        using var authority = WindowsLocalRunAuthority.AcquireResume(Path.GetDirectoryName(path)!, binding); using var files = new CurrentAppOwnedRepairCustody(authority);
        if (!files.Read(path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes) || Path.GetDirectoryName(config.RunBindingPath) != binding.ArtifactRootCanonicalPath) { throw Invalid(); }
        var expected = MigrationConsole.DecodeAuthRepair<SourceOrderOwnerIsoExpectation>(Read(files, config.IntentClaim));
        if (expected.Kind != "source-order-owner-iso-observation-expectation-v1" || !Path.IsPathFullyQualified(config.ProofParent) || !Directory.Exists(config.ProofParent)) { throw Invalid(); }
        var trust = new ReceiptAttestationTrustStore(config.TrustedKeys.Select(x => new TrustedAttestationKey(x.KeyId, files.Read(x.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
        CurrentAuthLocalSessionArchivePolicy.RequirePins(ArchivePins(config.SigningPins), trust);
        byte[] credential = Read(files, config.SourceCredential); ConsumerColumnBootstrapSourceCapture source;
        try { source = await ConsumerColumnBootstrapProofSourceCapture.CaptureAsync(new System.Text.UTF8Encoding(false, true).GetString(credential), expected.SourceIdentitySha256, accepted, ct); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(credential); }
        var pins = MigrationConsole.DecodeAuthRepair<CurrentAppOwnedRepairTargetPins>(Read(files, config.TargetPins));
        var names = expected.Target.Kind == DeltaTargetAuthorityKind.ProductionCloudNativePg ? ReviewedProductionRepairInventory.ExportProductionNames() : DatabaseInventory.ActiveDatabases.Concat(LocalExtras).ToArray();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var draft = new SourceOrderOwnerIsoIntent(SourceOrderOwnerIsoProtocol.IntentKind, Guid.NewGuid(), accepted, source.FullPlanSha256, source.SourceIdentitySha256,
            SourceCatalogDefinitionFingerprintV1.Compute(source.Plan, accepted, source.SourceIdentitySha256, now), new('0', 64), expected.CompanyAlreadyApplied,
            expected.Target, expected.TargetNamespace, expected.TargetCluster, expected.TargetGeneration, SourceOrderOwnerIsoProtocol.Hash(pins), binding.ComputeSha256(),
            names.ToDictionary(x => x, _ => new string('0', 64), StringComparer.Ordinal), SourceOrderOwnerIsoProtocol.Databases.ToDictionary(x => x, _ => false, StringComparer.Ordinal),
            SourceOrderOwnerIsoProtocol.Databases.ToDictionary(x => x, _ => new string('0', 64), StringComparer.Ordinal), expected.Maintenance, now,
            now.AddMinutes(5) < expected.Maintenance.ExpiresAtUtc ? now.AddMinutes(5) : expected.Maintenance.ExpiresAtUtc);
        var temporary = new SourceOrderOwnerIsoInputs(authority, files, config, draft, null!, trust);
        using var reviewer = temporary.Signer(config.ReviewPrivateKey, config.SigningPins.ReviewKeyId, config.SigningPins.ReviewFingerprint);
        using var authorizer = temporary.Signer(config.AuthorizationPrivateKey, config.SigningPins.AuthorizationKeyId, config.SigningPins.AuthorizationFingerprint);
        using var evidence = temporary.Signer(config.EvidencePrivateKey, config.SigningPins.ReceiptKeyId, config.SigningPins.ReceiptFingerprint);
        _ = authorizer.PublicKeyFingerprintSha256; _ = evidence.PublicKeyFingerprintSha256;
        var owners = await SourceOrderOwnerIsoRuntime.OwnersAsync(temporary, ct); draft = draft with { OwnerDefinitionsSha256 = SourceOrderOwnerIsoProtocol.OwnerDefinitions(owners) };
        var contract = SourceOrderOwnerIsoContract.Create(source.Plan, accepted, expected.CompanyAlreadyApplied, owners, DateTimeOffset.UtcNow);
        var input = new SourceOrderOwnerIsoInputs(authority, files, config, draft, null!, trust);
        var (Selected, Native, Fleet) = await SourceOrderOwnerIsoRuntime.ObserveReadOnlyAsync(input, source, contract, ct);
        now = DateTimeOffset.UtcNow;
        var intent = draft with
        {
            Selected = Selected,
            NativePreimageSha256 = Native.ToDictionary(x => x.Key, x => x.Value.Sha256, StringComparer.Ordinal),
            BeforeDatabaseSha256 = Fleet.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal),
            IssuedAtUtc = now,
            ExpiresAtUtc = now.AddMinutes(5) < expected.Maintenance.ExpiresAtUtc ? now.AddMinutes(5) : expected.Maintenance.ExpiresAtUtc,
        };
        _ = SourceOrderOwnerIsoProtocol.Require(intent, ConsumerOverlaySelection.CurrentConsumerSchemaV3, source.Plan, owners, now, false);
        if (now - source.BeganAtUtc > TimeSpan.FromMinutes(5)) { throw Invalid(); }
        var claim = await input.PublishAsync("observed-intent", CurrentAuthLocalSessionArchivePolicy.Sign(SourceOrderOwnerIsoProtocol.IntentDomain, intent, reviewer), intent.IntentId, ct);
        var baseline = await input.PublishAsync("operand-before", Native.Values.Select(x => x.Native.Snapshot).ToArray(), intent.IntentId, ct);
        _ = await input.PublishAsync("observed-source", source, intent.IntentId, ct); _ = await input.PublishAsync("observed-fleet", Fleet, intent.IntentId, ct);
        return await input.PublishAsync("apply-configuration", config with { Kind = "source-order-owner-iso-configuration-v1", IntentClaim = claim, OperandBefore = baseline }, intent.IntentId, ct);
    }
    private static readonly string[] LocalExtras = ["Auth", "postgres", "legacy_local"];
}

internal sealed partial class SourceOrderOwnerIsoRuntime
{
    internal static async Task<(IReadOnlyDictionary<string, bool> Selected, IReadOnlyDictionary<string, SourceOrderOwnerIsoNativeWitness> Native,
        IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> Fleet)> ObserveReadOnlyAsync(SourceOrderOwnerIsoInputs input, ConsumerColumnBootstrapSourceCapture source,
        SourceOrderOwnerIsoContract contract, CancellationToken ct)
    {
        using var runtime = new SourceOrderOwnerIsoRuntime(input, source, contract, null, null);
        await runtime.RequireAsync(ct); var selected = new Dictionary<string, bool>(StringComparer.Ordinal); var native = new Dictionary<string, SourceOrderOwnerIsoNativeWitness>(StringComparer.Ordinal);
        foreach (string database in SourceOrderOwnerIsoProtocol.Databases)
        {
            await using var connection = runtime.Connect(database); await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await ReadOnlyAsync(connection, tx, ct); await runtime.PolicyAsync(connection, tx, ct);
            await using var query = new NpgsqlCommand("SELECT atttypid::integer FROM pg_attribute WHERE attrelid='public.\"Country\"'::regclass AND attname IN ('ISO2','ISO3') AND NOT attisdropped ORDER BY attname;", connection, tx);
            var types = new List<int>(); await using (var reader = await query.ExecuteReaderAsync(ct)) { while (await reader.ReadAsync(ct)) { types.Add(reader.GetInt32(0)); } }
            if (types.Count != 2 || (types.Any(x => x != 1042) && types.Any(x => x != 1043))) { throw Invalid(); }
            bool after = types.All(x => x == 1043); selected.Add(database, after);
            var value = await SourceOrderOwnerIsoNativeWitness.CaptureAsync(connection, tx, contract, after, ct); _ = await runtime.OwnerAsync(connection, tx, value, ct); native.Add(database, value);
            await tx.RollbackAsync(ct);
        }
        var fleet = await runtime.FleetAsync(selected, ct);
        if (native.Any(x => x.Value.Native.Snapshot.Sha256 != fleet.Single(y => y.Database == x.Key).Sha256)) { throw Invalid(); }
        await runtime.RequireAsync(ct); return (selected, native, fleet);
    }
}
