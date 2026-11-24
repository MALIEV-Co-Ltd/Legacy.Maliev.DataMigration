using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal interface ISourceOrderOwnerIsoOwnedProofLease : IAsyncDisposable
{
    Guid OperationId { get; }
    string SourceFullSha256 { get; }
    bool CompanyAlreadyApplied { get; }
    string ConnectionString { get; }
    string OrdinaryConnectionString { get; }
    string TargetGeneration { get; }
    CurrentAppOwnedRepairTargetPins TargetPins { get; }
    CurrentAppOwnedMaintenancePin Maintenance { get; }
    DeltaTargetAuthority Target { get; }
    string ContainerId { get; }
    string Volume { get; }
    Task RequireAsync(CancellationToken ct); Task RequireAbsentAsync(CancellationToken ct);
    Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> CaptureFleetAsync(CancellationToken ct);
}
internal sealed record SourceOrderOwnerIsoOwnedConfiguration(string Path, LocalExecutionBinding Binding, DateTimeOffset CreatedAtUtc,
    IReadOnlyDictionary<string, WindowsRunFileIdentity.Identity> Secrets, Guid IntentId, IReadOnlyDictionary<string, bool> Selected,
    IReadOnlyDictionary<string, SourceOrderOwnerIsoNativeWitness> Native, IReadOnlyDictionary<string, string> BeforeDatabaseSha256);

internal static class SourceOrderOwnerIsoOwnedIssuer
{
    internal static async Task<SourceOrderOwnerIsoOwnedConfiguration> CreateAsync(SourceOrderOwnerIsoOwnedSession session, SourceOrderOwnerIsoInputs template,
        ConsumerColumnBootstrapSourceCapture source, SourceOrderOwnerIsoContract contract, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners, string root, CancellationToken ct)
    {
        await session.RequireAsync(ct);
        if (!OperatingSystem.IsWindows() || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly || !Path.IsPathFullyQualified(root) || Directory.Exists(root) ||
            contract.CompanyAlreadyApplied != session.Lease.CompanyAlreadyApplied) { throw SourceOrderOwnerIsoProtocol.Invalid(); }
        SecureSnapshotFileCreation.CreateRestrictedDirectory(root); DateTimeOffset began = DateTimeOffset.UtcNow;
        using var authority = WindowsLocalRunAuthority.AcquireFresh(root); using var files = new CurrentAppOwnedRepairCustody(authority); var binding = authority.Binding;
        var secrets = new Dictionary<string, WindowsRunFileIdentity.Identity>(StringComparer.Ordinal);
        try
        {
            using var review = new Material("iso-source-review-"); using var authorization = new Material("iso-source-authorization-"); using var evidence = new Material("iso-source-evidence-");
            var pins = new CurrentAppOwnedRepairSigningPins(review.Signer.KeyId, review.Signer.PublicKeyFingerprintSha256, authorization.Signer.KeyId, authorization.Signer.PublicKeyFingerprintSha256,
                evidence.Signer.KeyId, evidence.Signer.PublicKeyFingerprintSha256); var keys = new List<DeltaTrustedKeyReference>();
            foreach (var key in new[] { review, authorization, evidence }) { var file = await Store(key.Signer.KeyId + ".spki", key.Signer.ExportSubjectPublicKeyInfo()); keys.Add(new(key.Signer.KeyId, file.Path)); }
            var sourceSecret = await Store("source.secret", template.Read(template.Configuration.SourceCredential), true);
            var op = await Store("operator.secret", Encoding.UTF8.GetBytes(session.Lease.ConnectionString), true);
            var ordinary = await Store("ordinary.secret", Encoding.UTF8.GetBytes(session.Lease.OrdinaryConnectionString), true);
            var reviewFile = await Store("review-private.pem", Encoding.UTF8.GetBytes(review.Pem), true); var authFile = await Store("authorization-private.pem", Encoding.UTF8.GetBytes(authorization.Pem), true);
            var evidenceFile = await Store("evidence-private.pem", Encoding.UTF8.GetBytes(evidence.Pem), true);
            var target = await Store("target-pins.json", JsonSerializer.SerializeToUtf8Bytes(session.Lease.TargetPins)); var bindingFile = await Store("binding.json", JsonSerializer.SerializeToUtf8Bytes(binding));
            var native = new Dictionary<string, SourceOrderOwnerIsoNativeWitness>(StringComparer.Ordinal); var selected = new Dictionary<string, bool>(StringComparer.Ordinal);
            foreach (string database in SourceOrderOwnerIsoProtocol.Databases)
            {
                await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(session.Lease.ConnectionString) { Database = database }.ConnectionString); await connection.OpenAsync(ct);
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
                await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx)) { _ = await readOnly.ExecuteNonQueryAsync(ct); }
                await CompanyStorageRuntime.RequirePolicyAsync(connection, tx, session.Lease.Maintenance, session.Lease.Target, ct);
                await using var query = new NpgsqlCommand("SELECT count(*)=2 AND bool_and(atttypid='varchar'::regtype) FROM pg_attribute WHERE attrelid='public.\"Country\"'::regclass AND attname IN ('ISO2','ISO3') AND NOT attisdropped;", connection, tx);
                bool after = await query.ExecuteScalarAsync(ct) is true; selected.Add(database, after);
                var value = await SourceOrderOwnerIsoNativeWitness.CaptureAsync(connection, tx, contract, after, ct);
                _ = await CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx, database == "Country" ? CurrentRepairOperandOwnerPurpose.CountryIsoLiteral : CurrentRepairOperandOwnerPurpose.MaterialCountryIsoLiteral,
                    session.Lease.Target, value.Native.Snapshot, ct); native.Add(database, value); await tx.RollbackAsync(ct);
            }
            var fleet = await session.Lease.CaptureFleetAsync(ct);
            if (native.Any(x => x.Value.Native.Snapshot.Sha256 != fleet.Single(y => y.Database == x.Key).Sha256)) { throw SourceOrderOwnerIsoProtocol.Invalid(); }
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var intent = new SourceOrderOwnerIsoIntent(SourceOrderOwnerIsoProtocol.OwnedIntentKind, Guid.NewGuid(), source.Plan.SourceCommitSha, source.FullPlanSha256, source.SourceIdentitySha256,
                SourceCatalogDefinitionFingerprintV1.Compute(source.Plan, source.Plan.SourceCommitSha, source.SourceIdentitySha256, now), SourceOrderOwnerIsoProtocol.OwnerDefinitions(owners),
                contract.CompanyAlreadyApplied, session.Lease.Target, "local-aspire", "legacy-postgres-main-local", session.Lease.TargetGeneration, SourceOrderOwnerIsoProtocol.Hash(session.Lease.TargetPins), binding.ComputeSha256(),
                fleet.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal), selected, native.ToDictionary(x => x.Key, x => x.Value.Sha256, StringComparer.Ordinal), session.Lease.Maintenance,
                now, now.AddMinutes(5) < session.Lease.Maintenance.ExpiresAtUtc ? now.AddMinutes(5) : session.Lease.Maintenance.ExpiresAtUtc);
            var claim = await Store("intent.json", JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchivePolicy.Sign(SourceOrderOwnerIsoProtocol.IntentDomain, intent, review.Signer)));
            var before = await Store("operand-before.json", JsonSerializer.SerializeToUtf8Bytes(native.Values.Select(x => x.Native.Snapshot).ToArray()));
            var config = new SourceOrderOwnerIsoConfiguration("source-order-owner-iso-owned-configuration-v1", bindingFile.Path, claim, sourceSecret, target, op, ordinary, before,
                pins, keys, reviewFile, authFile, evidenceFile, Path.GetDirectoryName(root)!, template.Configuration.TestsImage);
            var fileConfig = await Store("configuration.json", JsonSerializer.SerializeToUtf8Bytes(config)); _ = await Store("creation-source.json", JsonSerializer.SerializeToUtf8Bytes(source));
            return new(fileConfig.Path, binding, began, secrets, intent.IntentId, selected, native, intent.BeforeDatabaseSha256);

            async Task<CompanyStorageArtifact> Store(string name, byte[] bytes, bool secret = false)
            {
                string path = Path.Combine(root, name);
                try
                {
                    if (secret)
                    {
                        await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough);
                        secrets.Add(path, CompanyStorageSecretCustody.Observe(output, path)); await output.WriteAsync(bytes, ct); await output.FlushAsync(ct); output.Flush(true);
                        output.Position = 0; byte[] check = new byte[bytes.Length];
                        try { await output.ReadExactlyAsync(check, ct); if (!check.AsSpan().SequenceEqual(bytes)) { throw SourceOrderOwnerIsoProtocol.Invalid(); } }
                        finally { CryptographicOperations.ZeroMemory(check); }
                    }
                    else { await files.WriteNewAsync(path, bytes, ct); }
                    files.Require(); return new(path, SourceOrderOwnerIsoProtocol.Hash(bytes));
                }
                finally { if (secret) { CryptographicOperations.ZeroMemory(bytes); } }
            }
        }
        catch (Exception primary)
        {
            files.Dispose(); authority.Dispose();
            try { CompanyStorageSecretCustody.Remove(root, binding, began, secrets); } catch (Exception cleanup) { throw new AggregateException(primary, cleanup); }
            throw;
        }
    }
    internal static void ClearSecrets(SourceOrderOwnerIsoOwnedConfiguration owned)
    {
        CompanyStorageSecretCustody.Remove(owned.Binding.ArtifactRootCanonicalPath, owned.Binding, owned.CreatedAtUtc, owned.Secrets);
    }

    private sealed class Material : IDisposable
    {
        internal P256MigrationEvidenceSigner Signer { get; }
        internal string Pem { get; }
        internal Material(string prefix) { using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); Pem = key.ExportPkcs8PrivateKeyPem(); Signer = new(prefix + Guid.NewGuid().ToString("N"), Pem); }
        public void Dispose()
        {
            Signer.Dispose();
        }
    }
}
