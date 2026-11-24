using System.Data;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

// Only this private construction path obtains an owned lease. JSON cannot adopt an endpoint.
internal sealed class CompanyStorageOwnedSession : IAsyncDisposable
{
    private readonly CurrentAuthTypedHostProducer.HeldTestBundle _bundle;
    private readonly CurrentAuthArchiveInitialProducer.FixedNativeBundle _loader;
    internal ICompanyStorageOwnedProofLease Lease { get; }
    private bool _disposed;
    private CompanyStorageOwnedSession(CurrentAuthTypedHostProducer.HeldTestBundle bundle,
        CurrentAuthArchiveInitialProducer.FixedNativeBundle loader, ICompanyStorageOwnedProofLease lease)
    { _bundle = bundle; _loader = loader; Lease = lease; }
    internal static async Task<CompanyStorageOwnedSession> CreateAsync(CompanyStorageRepairInputs template, ConsumerColumnBootstrapSourceCapture source, string parent, CancellationToken ct)
    {
        if (Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != source.Plan.SourceCommitSha)
        { throw Invalid(); }
        var image = template.Configuration.TestsImage;
        if (Path.GetFileName(image.Path) != "Legacy.Maliev.DataMigration.Tests.dll") { throw Invalid(); }
        var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(Path.GetDirectoryName(image.Path)!, ct);
        CurrentAuthArchiveInitialProducer.FixedNativeBundle? loader = null; ICompanyStorageOwnedProofLease? lease = null;
        try
        {
            if (CurrentAuthTypedHostProducer.ImageHash(image.Path) != image.Sha256) { throw Invalid(); }
            loader = new(image.Path); var tests = loader.LoadFromAssemblyPath(image.Path);
            Type exact = tests.GetType("Legacy.Maliev.DataMigration.Tests.CompanyStorageOwnedProofLease", true)!;
            var factory = exact.GetMethod("CreateAsync", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.DeclaredOnly,
                null, [typeof(string), typeof(FreshSchemaPlan), typeof(CancellationToken)], null) ?? throw Invalid();
            if (!exact.IsSealed || exact.GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length != 0 || factory.ReturnType != typeof(Task<ICompanyStorageOwnedProofLease>))
            { throw Invalid(); }
            lease = await (factory.Invoke(null, [parent, source.Plan, ct]) as Task<ICompanyStorageOwnedProofLease> ?? throw Invalid());
            if (lease.GetType() != exact || lease.SourceFullSha256 != source.FullPlanSha256 || !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(lease.Target)) { throw Invalid(); }
            await lease.RequireAsync(ct); bundle.Require(); return new(bundle, loader, lease);
        }
        catch (Exception primary)
        {
            Exception? cleanup = null;
            try { if (lease is not null) { await lease.DisposeAsync(); await lease.RequireAbsentAsync(CancellationToken.None); } }
            catch (Exception failure) { cleanup = failure; }
            finally { loader?.Dispose(); bundle.Dispose(); }
            if (cleanup is not null) { throw new AggregateException(primary, cleanup); }
            throw;
        }
    }
    internal async Task RequireAsync(CancellationToken ct)
    { ObjectDisposedException.ThrowIf(_disposed, this); _bundle.Require(); await Lease.RequireAsync(ct); }
    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true;
        try
        {
            await Lease.DisposeAsync(); using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await Lease.RequireAbsentAsync(cleanup.Token);
        }
        finally { _loader.Dispose(); _bundle.Dispose(); }
    }
    private static MigrationExecutionException Invalid()
    {
        return CompanyStorageRepairProtocol.Invalid();
    }
}

internal sealed record CompanyStorageOwnedConfiguration(string Path, LocalExecutionBinding Binding, DateTimeOffset CreatedAtUtc,
    IReadOnlyDictionary<string, WindowsRunFileIdentity.Identity> OwnedSecretIdentities, string IntentSha256, Guid IntentId,
    IReadOnlyDictionary<string, string> BeforeDatabaseSha256, CompanyStorageNativeWitness Before);

internal static class CompanyStorageOwnedInputs
{
    internal static async Task<CompanyStorageOwnedConfiguration> CreateAsync(CompanyStorageOwnedSession session, CompanyStorageRepairInputs template,
        ConsumerColumnBootstrapSourceCapture source, ApprovedCustomerCompanyStorageRepair contract, string root, CancellationToken ct)
    {
        await session.RequireAsync(ct);
        if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(root) || Directory.Exists(root) ||
            Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly) { throw CompanyStorageRepairProtocol.Invalid(); }
        SecureSnapshotFileCreation.CreateRestrictedDirectory(root); DateTimeOffset created = DateTimeOffset.UtcNow;
        using var authority = WindowsLocalRunAuthority.AcquireFresh(root); using var files = new CurrentAppOwnedRepairCustody(authority);
        LocalExecutionBinding retainedBinding = authority.Binding;
        var secrets = new Dictionary<string, WindowsRunFileIdentity.Identity>(StringComparer.Ordinal);
        try
        {
            using var review = new Material("company-owned-review-"); using var auth = new Material("company-owned-authorization-"); using var evidence = new Material("company-owned-evidence-");
            var pins = new CurrentAppOwnedRepairSigningPins(review.Signer.KeyId, review.Signer.PublicKeyFingerprintSha256, auth.Signer.KeyId, auth.Signer.PublicKeyFingerprintSha256,
                evidence.Signer.KeyId, evidence.Signer.PublicKeyFingerprintSha256);
            var keys = new List<DeltaTrustedKeyReference>();
            foreach (var material in new[] { review, auth, evidence })
            { var file = await Store(material.Signer.KeyId + ".spki", material.Signer.ExportSubjectPublicKeyInfo()); keys.Add(new(material.Signer.KeyId, file.Path)); }
            var sourceCredential = await Store("source.secret", template.Read(template.Configuration.SourceCredential), secret: true);
            var op = await Store("operator.secret", Encoding.UTF8.GetBytes(session.Lease.ConnectionString), secret: true);
            var ordinary = await Store("ordinary.secret", Encoding.UTF8.GetBytes(session.Lease.OrdinaryConnectionString), secret: true);
            var reviewKey = await Store("review-private.pem", Encoding.UTF8.GetBytes(review.Pem), secret: true);
            var authKey = await Store("authorization-private.pem", Encoding.UTF8.GetBytes(auth.Pem), secret: true);
            var evidenceKey = await Store("evidence-private.pem", Encoding.UTF8.GetBytes(evidence.Pem), secret: true);
            var targetPins = await Store("target-pins.json", JsonSerializer.SerializeToUtf8Bytes(session.Lease.TargetPins));
            var binding = await Store("run-binding.json", JsonSerializer.SerializeToUtf8Bytes(authority.Binding));
            bool after; CompanyStorageNativeWitness native;
            await using (var connection = new NpgsqlConnection(session.Lease.ConnectionString))
            {
                await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
                await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx)) { _ = await readOnly.ExecuteNonQueryAsync(ct); }
                await CompanyStorageRuntime.RequirePolicyAsync(connection, tx, session.Lease.Maintenance, session.Lease.Target, ct);
                await using var command = new NpgsqlCommand("SELECT count(*)=3 AND bool_and(atttypid='text'::regtype) FROM pg_attribute WHERE attrelid='public.\"Company\"'::regclass AND attname IN ('Name','Registrar','TaxNumber') AND NOT attisdropped;", connection, tx);
                after = await command.ExecuteScalarAsync(ct) is true;
                native = await CompanyStorageNativeWitness.CaptureAsync(connection, tx, contract, after, ct); await tx.RollbackAsync(ct);
            }
            var fleet = await session.Lease.CaptureFleetAsync(ct);
            if (fleet.Single(x => x.Database == "Customer").Sha256 != native.Observation.Native.Snapshot.Sha256) { throw CompanyStorageRepairProtocol.Invalid(); }
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var intent = new CompanyStorageRepairIntent(CompanyStorageRepairProtocol.OwnedIntentKind, Guid.NewGuid(), source.Plan.SourceCommitSha, source.FullPlanSha256,
                source.SourceIdentitySha256, SourceCatalogDefinitionFingerprintV1.Compute(source.Plan, source.Plan.SourceCommitSha, source.SourceIdentitySha256, now),
                contract.Before().TargetSchemaSha256, contract.After().TargetSchemaSha256, CompanyStorageRepairProtocol.CandidateSha256,
                false, after, session.Lease.Target, "local-aspire", "legacy-postgres-main-local", session.Lease.TargetGeneration, CompanyStorageRepairProtocol.Hash(session.Lease.TargetPins), authority.Binding.ComputeSha256(),
                fleet.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal), native.Sha256, native.OwnerName, session.Lease.Maintenance,
                now, now.AddMinutes(5) < session.Lease.Maintenance.ExpiresAtUtc ? now.AddMinutes(5) : session.Lease.Maintenance.ExpiresAtUtc);
            var claim = await Store("reviewed-intent.json", JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchivePolicy.Sign(CompanyStorageRepairProtocol.IntentDomain, intent, review.Signer)));
            var config = new CompanyStorageRepairConfiguration("current-company-storage-owned-fault-configuration-v1", binding.Path, claim, sourceCredential, targetPins, op, ordinary,
                pins, keys, reviewKey, authKey, evidenceKey, Path.GetDirectoryName(root)!, template.Configuration.TestsImage);
            var configuration = await Store("configuration.json", JsonSerializer.SerializeToUtf8Bytes(config));
            _ = await Store("creation-source.json", JsonSerializer.SerializeToUtf8Bytes(source));
            return new(configuration.Path, authority.Binding, created, secrets, CompanyStorageRepairProtocol.Hash(intent), intent.IntentId, intent.BeforeDatabaseSha256, native);

            async Task<CompanyStorageArtifact> Store(string name, byte[] bytes, bool secret = false)
            {
                string file = Path.Combine(root, name);
                try
                {
                    if (secret)
                    {
                        if (!OperatingSystem.IsWindows()) { throw CompanyStorageRepairProtocol.Invalid(); }
                        files.Require();
                        await using var output = new FileStream(file, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough);
                        secrets.Add(file, CompanyStorageSecretCustody.Observe(output, file));
                        if (!SecureLocalFile.HandleResolvesToApprovedPath(output, file) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(file))) { throw CompanyStorageRepairProtocol.Invalid(); }
                        await output.WriteAsync(bytes, ct); await output.FlushAsync(ct); output.Flush(true); output.Position = 0;
                        byte[] readback = new byte[bytes.Length];
                        try { await output.ReadExactlyAsync(readback, ct); if (!readback.AsSpan().SequenceEqual(bytes)) { throw CompanyStorageRepairProtocol.Invalid(); } }
                        finally { CryptographicOperations.ZeroMemory(readback); }
                        files.Require();
                    }
                    else { await files.WriteNewAsync(file, bytes, ct); }
                    using var held = SecureLocalFile.OpenReadShared(file);
                    return !SecureLocalFile.HandleResolvesToApprovedPath(held, file) || (secret && secrets[file] != CompanyStorageSecretCustody.Observe(held, file))
                        ? throw CompanyStorageRepairProtocol.Invalid()
                        : new(file, CompanyStorageRepairProtocol.Hash(bytes));
                }
                finally { if (secret) { CryptographicOperations.ZeroMemory(bytes); } }
            }
        }
        catch (Exception primary)
        {
            files.Dispose(); authority.Dispose();
            try { ClearTracked(root, retainedBinding, created, secrets); }
            catch (Exception cleanup) { throw new AggregateException(primary, cleanup); }
            throw;
        }
    }
    internal static void ClearSecrets(CompanyStorageOwnedConfiguration owned)
    {
        ClearTracked(owned.Binding.ArtifactRootCanonicalPath, owned.Binding, owned.CreatedAtUtc, owned.OwnedSecretIdentities);
    }

    private static void ClearTracked(string root, LocalExecutionBinding binding, DateTimeOffset createdAtUtc, IReadOnlyDictionary<string, WindowsRunFileIdentity.Identity> secrets)
    {
        CompanyStorageSecretCustody.Remove(root, binding, createdAtUtc, secrets);
    }

    private sealed class Material : IDisposable
    {
        internal string Pem { get; }
        internal P256MigrationEvidenceSigner Signer { get; }
        internal Material(string prefix)
        { using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); Pem = key.ExportPkcs8PrivateKeyPem(); Signer = new(prefix + Guid.NewGuid().ToString("N"), Pem); }
        public void Dispose()
        {
            Signer.Dispose();
        }
    }
}

internal sealed partial class CompanyStorageRuntime
{
    private readonly CompanyStorageOwnedSession? _owned;
    private readonly CompanyStorageFaultControl? _fault;
    private CompanyStorageRuntime(CompanyStorageRepairInputs input, ConsumerColumnBootstrapSourceCapture source, ApprovedCustomerCompanyStorageRepair contract,
        CompanyStorageOwnedSession owned, CompanyStorageFaultControl? fault)
    { _inputs = input; Source = source; Contract = contract; _owned = owned; _fault = fault; _connection = owned.Lease.ConnectionString; _ordinary = owned.Lease.OrdinaryConnectionString; _code = CompanyStorageAcceptedCodeCustody.Acquire(); }
    private static async Task<CompanyStorageRuntime> OpenOwnedAsync(CompanyStorageRepairInputs input, ConsumerColumnBootstrapSourceCapture source,
        CompanyStorageOwnedSession owned, CompanyStorageFaultControl? fault, CancellationToken ct)
    {
        await owned.RequireAsync(ct);
        var contract = CompanyStorageRepairProtocol.RequireOwnedIntent(input.Intent, source.Plan, await OwnerAsync(input, ct), DateTimeOffset.UtcNow);
        if (input.Intent.Target != owned.Lease.Target || input.Intent.TargetGeneration != owned.Lease.TargetGeneration || input.Intent.TargetObservationSha256 != CompanyStorageRepairProtocol.Hash(owned.Lease.TargetPins))
        { throw Invalid(); }
        var result = new CompanyStorageRuntime(input, source, contract, owned, fault);
        try { await result.RequireAsync(ct); return result; } catch { result.Dispose(); throw; }
    }
}
