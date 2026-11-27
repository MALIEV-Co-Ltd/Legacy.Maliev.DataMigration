using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Actual same-process source capture and freshly signed target preparation, never deserialized as authority.</summary>
internal sealed class ConsumerColumnBootstrapReviewedInvocation : IDisposable
{
    private readonly LocalExecutionBinding _binding;
    private readonly List<(string Path, string Identity)> _secrets;
    private readonly DateTimeOffset _createdAfterUtc;
    private string? _sourceConnection;
    internal ConsumerColumnBootstrapSourceCapture Source { get; }
    internal ConsumerColumnBootstrapRehearsalAcceptance Acceptance { get; }
    internal string ConfigurationPath { get; }
    internal string SourceConnection => _sourceConnection ?? throw Invalid();

    private ConsumerColumnBootstrapReviewedInvocation(ConsumerColumnBootstrapSourceCapture source,
        ConsumerColumnBootstrapRehearsalAcceptance acceptance, string connection, string configurationPath,
        LocalExecutionBinding binding, List<(string Path, string Identity)> secrets)
    { Source = source; Acceptance = acceptance; _sourceConnection = connection; ConfigurationPath = configurationPath; _binding = binding; _secrets = secrets; _createdAfterUtc = DateTimeOffset.UtcNow; }

    internal static async Task<ConsumerColumnBootstrapReviewedInvocation> CreateAsync(string inputPath,
        IConsumerColumnBootstrapRehearsalCompletion completion, CancellationToken ct)
    {
        if (System.Reflection.Assembly.GetEntryAssembly() != typeof(ConsumerColumnBootstrapReviewedInvocation).Assembly) { throw Invalid(); }
        CurrentAuthRepairCapacity.Require(admission: true);
        string acceptedCommit = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        var acceptance = ConsumerColumnBootstrapRehearsalAcceptance.Read(completion);
        var input = await MigrationConsole.ReadConsumerBootstrapProtectedAsync<ConsumerColumnBootstrapOperationalConfiguration>(inputPath,
            "consumer_bootstrap_reviewed_input_unprotected", ct).ConfigureAwait(false);
        if (input.Kind != "consumer-column-bootstrap-reviewed-input-v1" || input.SourceConnectionPath is null) { throw Invalid(); }
        using var heldBinding = SecureLocalFile.OpenReadShared(input.RunBindingPath);
        if (heldBinding.Length is < 1 or > 65536) { throw Invalid(); }
        byte[] bindingBytes = new byte[checked((int)heldBinding.Length)]; heldBinding.ReadExactly(bindingBytes);
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(bindingBytes);
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        T Read<T>(string path)
        {
            return MigrationConsole.DecodeAuthRepair<T>(files.Read(path, sharedReader: true, maximumBytes: 12 * 1024 * 1024));
        }

        if (JsonSerializer.Serialize(Read<ConsumerColumnBootstrapOperationalConfiguration>(inputPath)) != JsonSerializer.Serialize(input) ||
            !files.Read(input.RunBindingPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bindingBytes)) { throw Invalid(); }
        var template = Read<ConsumerColumnBootstrapOperationalScope>(input.ScopePath);
        var oldSource = Read<FreshSchemaPlan>(input.SourcePath);
        ConsumerColumnBootstrapOperationalContract.RequireScope(template, oldSource, DateTimeOffset.UtcNow);
        if (template.Mode != ConsumerColumnBootstrapOperationalMode.PersistentReviewed || template.SourceCommitSha != acceptedCommit ||
            template.RunBindingSha256 != binding.ComputeSha256()) { throw Invalid(); }
        string sourceConnection = Encoding.UTF8.GetString(files.Read(input.SourceConnectionPath, sharedReader: true, maximumBytes: 65536)).Trim();
        var source = await ConsumerColumnBootstrapProofSourceCapture.CaptureAsync(sourceConnection, template.SourceIdentitySha256, acceptedCommit, ct).ConfigureAwait(false);
        // Keep both full captures. Only the independently reviewed definition excludes capture
        // clocks/identity counters; neither full source object is restamped or rewritten.
        if (SourceCatalogDefinitionFingerprintV1.Compute(oldSource, acceptedCommit, template.SourceIdentitySha256, DateTimeOffset.UtcNow) !=
            SourceCatalogDefinitionFingerprintV1.Compute(source.Plan, acceptedCommit, source.SourceIdentitySha256, DateTimeOffset.UtcNow)) { throw Invalid(); }
        var contract = ConsumerColumnBootstrapContract.Create(source.Plan, acceptedCommit, DateTimeOffset.UtcNow);
        var target = Read<CurrentAppOwnedRepairTargetPins>(input.TargetPinsPath);
        var baseline = Read<CurrentAppOwnedDatabaseSnapshot[]>(input.BeforeFleetPath);
        if (baseline.Length != template.BeforeDatabaseSha256.Count || baseline.Select(snapshot => snapshot.Database).Distinct(StringComparer.Ordinal).Count() != baseline.Length ||
            baseline.Any(snapshot => !template.BeforeDatabaseSha256.TryGetValue(snapshot.Database, out string? hash) || snapshot.Sha256 != hash)) { throw Invalid(); }
        string connectionString = Encoding.UTF8.GetString(files.Read(input.OperatorConnectionPath, sharedReader: true, maximumBytes: 65536)).Trim();
        string ordinary = Encoding.UTF8.GetString(files.Read(input.RejectedOrdinaryConnectionPath, sharedReader: true, maximumBytes: 65536)).Trim();
        var endpoint = new NpgsqlConnectionStringBuilder(connectionString);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 || endpoint.Username != template.Maintenance.Role ||
            string.IsNullOrWhiteSpace(endpoint.Password) || !string.IsNullOrEmpty(endpoint.Options)) { throw Invalid(); }
        using var targetObserver = new ConsumerColumnBootstrapPersistentTarget(target, files, binding.ArtifactRootCanonicalPath);
        await targetObserver.RequireAsync(template, endpoint.Port, ct).ConfigureAwait(false);
        // This observation environment has no permit. It can only enforce the fixed existing
        // target/role policy while fresh review data is collected; no DDL is reachable here.
        using var observer = await ConsumerColumnBootstrapOperationalEnvironment.CreateReviewObserverAsync(authority, files, template,
            oldSource, target, connectionString, ordinary, input, ct).ConfigureAwait(false);
        var nativePins = new List<ConsumerColumnBootstrapNativePreimagePin>(); var pending = new List<string>();
        var completed = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string database in template.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(connectionString) { Database = database, Pooling = false }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction)) { _ = await readOnly.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
            await observer.RequirePolicyAsync(connection, transaction, template, ct).ConfigureAwait(false);
            if (ConsumerColumnBootstrapOperationalContract.Databases.Contains(database, StringComparer.Ordinal))
            {
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                string shape = await inspector.InspectSchemaAsync(contract.After(database), ct).ConfigureAwait(false);
                if (shape == contract.After(database).TargetSchemaSha256) { completed.Add(database, template.BeforeDatabaseSha256[database]); }
                else
                {
                    if (await inspector.InspectSchemaAsync(contract.Before(database), ct).ConfigureAwait(false) != contract.Before(database).TargetSchemaSha256) { throw Invalid(); }
                    var native = await ConsumerColumnBootstrapNativePreservation.CaptureAsync(connection, transaction, contract, database, false, ct).ConfigureAwait(false);
                    var provider = await ConsumerColumnBootstrapProviderCapture.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
                    nativePins.Add(ConsumerColumnBootstrapNativePreimage.Pin(native, provider, DateTimeOffset.UtcNow)); pending.Add(database);
                }
            }
            var actual = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
            if (actual.Sha256 != template.BeforeDatabaseSha256[database]) { throw Invalid(); }
            await transaction.RollbackAsync(ct).ConfigureAwait(false);
        }
        // Unexpected partial state is a new review input, never silently adopted. The input must
        // explicitly identify the same missing operands and full already-complete snapshots.
        if (!pending.SequenceEqual(template.PendingDatabases, StringComparer.Ordinal) || completed.Count != template.PreviouslyCompletedDatabaseSha256.Count ||
            completed.Any(pair => !template.PreviouslyCompletedDatabaseSha256.TryGetValue(pair.Key, out string? hash) || hash != pair.Value)) { throw Invalid(); }
        var scope = template with
        {
            OperationId = Guid.NewGuid(),
            LogicalSourcePlanSha256 = source.FullPlanSha256,
            ContractSha256 = contract.ComputeSha256(),
            NativePreimages = nativePins,
            NativeCharacterizationSha256 = acceptance.EvidenceSha256
        };
        ConsumerColumnBootstrapOperationalContract.RequireScope(scope, source.Plan, DateTimeOffset.UtcNow);
        string stem = "bootstrap-reviewed-" + scope.OperationId.ToString("N") + "-";
        var secrets = new List<(string Path, string Identity)>();
        var invocation = new ConsumerColumnBootstrapReviewedInvocation(source, acceptance, sourceConnection,
            Path.Combine(binding.ArtifactRootCanonicalPath, stem + "configuration.json"), binding, secrets);
        try
        {
            var keyReferences = new List<DeltaTrustedKeyReference>(); var material = new List<(string Id, string Fingerprint, string Path)>();
            foreach (string role in new[] { "review", "authorization", "receipt" })
            {
                using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                string keyId = "bootstrap-" + role + "-" + Guid.NewGuid().ToString("N");
                using var signer = new P256MigrationEvidenceSigner(keyId, key.ExportPkcs8PrivateKeyPem());
                string privatePath = Path.Combine(binding.ArtifactRootCanonicalPath, stem + role + ".pem");
                if (File.Exists(privatePath)) { throw Invalid(); }
                int secretIndex = secrets.Count; secrets.Add((privatePath, string.Empty));
                string identity = await ConsumerColumnBootstrapWindowsSecretCustody.CreateAsync(binding, files, privatePath, Encoding.UTF8.GetBytes(key.ExportPkcs8PrivateKeyPem()), ct).ConfigureAwait(false);
                secrets[secretIndex] = (privatePath, identity);
                string publicPath = await Store(role + "-public.txt", Encoding.UTF8.GetBytes(Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()))).ConfigureAwait(false);
                keyReferences.Add(new(keyId, publicPath)); material.Add((keyId, signer.PublicKeyFingerprintSha256, privatePath));
            }
            var pins = new CurrentAppOwnedRepairSigningPins(material[0].Id, material[0].Fingerprint, material[1].Id, material[1].Fingerprint, material[2].Id, material[2].Fingerprint);
            acceptance.Require(scope, source.Plan, pins, DateTimeOffset.UtcNow);
            byte[] evidenceBytes = JsonSerializer.SerializeToUtf8Bytes(completion.ReadEvidence());
            if (ConsumerColumnBootstrapOperationalContract.Hash(evidenceBytes) != acceptance.EvidenceSha256) { throw Invalid(); }
            string evidencePath = await Store("rehearsal-evidence.json", evidenceBytes).ConfigureAwait(false);
            RequireReference(input.RecoveryPreparation, template.RecoveryReviewSha256);
            RequireReference(input.RolePreparation, template.RoleTransitionReviewSha256);
            var config = input with
            {
                Kind = "consumer-column-bootstrap-reviewed-configuration-v1",
                SourcePath = await Store("source.json", JsonSerializer.SerializeToUtf8Bytes(source.Plan)).ConfigureAwait(false),
                ScopePath = await Store("scope.json", JsonSerializer.SerializeToUtf8Bytes(scope)).ConfigureAwait(false),
                ReviewPath = Path.Combine(binding.ArtifactRootCanonicalPath, stem + "review.json"),
                AuthorizationPath = Path.Combine(binding.ArtifactRootCanonicalPath, stem + "authorization.json"),
                SigningPinsPath = await Store("signing-pins.json", JsonSerializer.SerializeToUtf8Bytes(pins)).ConfigureAwait(false),
                TrustedKeys = keyReferences,
                NativePreparation = new(evidencePath, acceptance.EvidenceSha256),
                ReviewPrivateKeyPath = material[0].Path,
                AuthorizationPrivateKeyPath = material[1].Path,
                ReceiptPrivateKeyPath = material[2].Path,
            };
            _ = await Store("source-capture.json", JsonSerializer.SerializeToUtf8Bytes(source)).ConfigureAwait(false);
            _ = await Store("configuration.json", JsonSerializer.SerializeToUtf8Bytes(config)).ConfigureAwait(false);
            return invocation;

            async Task<string> Store(string name, byte[] bytes)
            {
                string path = Path.Combine(binding.ArtifactRootCanonicalPath, stem + name); await files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false); return path;
            }
            void RequireReference(CurrentAppOwnedRepairArtifact original, string expected)
            {
                byte[] retained = files.Read(original.Path, sharedReader: true, maximumBytes: 12 * 1024 * 1024);
                if (original.Sha256 != expected || ConsumerColumnBootstrapOperationalContract.Hash(retained) != expected) { throw Invalid(); }
                // Preserve the original path/bytes and bind the same reference hash in the
                // fresh signed scope. No restore/role acceptance is created by this reference.
            }
        }
        catch (Exception primary)
        {
            invocation._sourceConnection = null;
            try
            {
                observer.Dispose(); targetObserver.Dispose(); files.Dispose(); authority.Dispose();
                invocation.ClearSecrets();
            }
            catch (Exception cleanup) { throw new AggregateException("Reviewed preparation and owned signing-file cleanup failed.", primary, cleanup); }
            throw;
        }
    }

    public void Dispose()
    {
        if (_sourceConnection is null) { return; }
        try { ClearSecrets(); }
        finally { _sourceConnection = null; }
    }

    private void ClearSecrets()
    {
        ConsumerColumnBootstrapWindowsSecretCustody.RemoveDetached(_binding, _secrets, _createdAfterUtc); _secrets.Clear();
    }
    private static MigrationExecutionException Invalid()
    {
        return ConsumerColumnBootstrapOperationalContract.Invalid();
    }
}
