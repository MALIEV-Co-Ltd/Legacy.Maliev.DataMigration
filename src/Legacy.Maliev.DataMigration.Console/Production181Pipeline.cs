using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static class Production181Pipeline
{
    internal static async Task<Production181PipelineResult> RunAsync(Production181PipelineConfiguration configuration, string originalConfigurationPath, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: true); // Before source/native input reads and root population.
        using var inputs = new Production181PipelineInputs(configuration, originalConfigurationPath);
        string[] fresh = [configuration.FreshBundleRoot, configuration.FreshDefinitionRoot, configuration.FreshProviderRoot, configuration.FreshMaintenanceRoot];
        foreach (string path in fresh) { Production181ProtectedBundle.RequireFreshPath(path, [.. inputs.RootPaths, .. fresh.Where(x => x != path)]); }
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct); lease.CancelAfter(TimeSpan.FromMinutes(225));
        using var bundle = await Production181ProtectedBundle.CreateAsync(inputs, configuration, lease.Token).ConfigureAwait(false);
        var definition = await RunPhase("definition", configuration.FreshDefinitionRoot, null).ConfigureAwait(false);
        var provider = await RunPhase("provider", configuration.FreshProviderRoot, definition).ConfigureAwait(false);
        var maintenance = await RunPhase("maintenance", configuration.FreshMaintenanceRoot, definition).ConfigureAwait(false);
        inputs.Require(); bundle.Require();
        // Reopen original roots independently after all phases; no initial acceptance is cached.
        RequireOriginal(definition); RequireOriginal(provider); RequireOriginal(maintenance);
        return new("current-production181-actual-component-pipeline-v1", inputs.Subject, definition, provider, maintenance, DateTimeOffset.UtcNow,
            "actual disposable compatibility components only; not production or closed Console authority");

        async Task<Production181PhaseResult> RunPhase(string phase, string requestedRoot, Production181PhaseResult? originalDefinition)
        {
            CurrentCustomerSequenceCapacity.Require(admission: true);
            await Task.Delay(TimeSpan.FromSeconds(30), lease.Token).ConfigureAwait(false);
            CurrentCustomerSequenceCapacity.Require(admission: true); inputs.Require(); bundle.Require();
            SecureSnapshotFileCreation.CreateRestrictedDirectory(requestedRoot);
            using var authority = WindowsLocalRunAuthority.AcquireFresh(requestedRoot); using var files = new CurrentAppOwnedRepairCustody(authority);
            string root = authority.Binding.ArtifactRootCanonicalPath, bindingPath = Path.Combine(root, "production181-case-root-binding.json");
            await files.WriteNewAsync(bindingPath, JsonSerializer.SerializeToUtf8Bytes(authority.Binding), lease.Token).ConfigureAwait(false);
            await files.WriteNewAsync(Path.Combine(root, "intended-subject.json"), inputs.Read(configuration.Subject), lease.Token).ConfigureAwait(false);
            await ImportInput(configuration.Catalog, "actual-source-catalog.json").ConfigureAwait(false);
            // Flat held current DLL artifact; SourcePath in assembled proof remains the TRUE executed copied bundle path.
            var bundleFiles = bundle.FilesFor(bundle.TestAssembly);
            var heldTest = await Production181CustomerDefinitionAssembler.ImportActualAsync(bundleFiles, files, bundle.TestAssembly, Path.Combine(root, "actual-executed-tests.dll"), lease.Token).ConfigureAwait(false);
            string prerequisitePath = Path.Combine(root, "actual-prerequisites.json");
            Production181PrerequisitePaths? originalPaths = null; CustomerDefinitionArtifact? importedDefinition = null;
            ReceiptAttestationTrustStore? originalTrust = null;
            if (originalDefinition is null)
            {
                await files.WriteNewAsync(prerequisitePath, JsonSerializer.SerializeToUtf8Bytes(new
                {
                    kind = "current-production181-held-intended-inputs-v1",
                    subject = inputs.Subject,
                    sourceCatalog = configuration.Catalog,
                    sourceSchema = configuration.Schema,
                    source = configuration.Source,
                    owner = configuration.Owner,
                    nativeBefore = configuration.NativeBefore,
                    target = configuration.TargetPins,
                    intendedBinding = configuration.IntendedBinding,
                    testAssembly = bundle.TestSha256
                }), lease.Token).ConfigureAwait(false);
            }
            else
            {
                // Hold original only during import/validation. Release before parent host / fixture reacquire it.
                using (var originalAuthority = WindowsLocalRunAuthority.AcquireResume(originalDefinition.Binding.ArtifactRootCanonicalPath, originalDefinition.Binding))
                using (var originalFiles = new CurrentAppOwnedRepairCustody(originalAuthority))
                {
                    originalTrust = Trust(originalFiles, originalDefinition);
                    var originalEnvelope = MigrationConsole.DecodeCustomerSequence<Production181SemanticEnvelope>(Read(originalFiles, originalDefinition.SemanticEnvelope));
                    _ = Production181SemanticEnvelopeReader.Require(originalFiles, originalEnvelope, inputs.Subject, originalTrust, originalDefinition.KeyId, originalDefinition.Fingerprint, DateTimeOffset.UtcNow);
                    importedDefinition = await Production181CustomerDefinitionAssembler.ImportActualAsync(originalFiles, files, originalDefinition.Component.Path, Path.Combine(root, "actual-original-definition.json"), lease.Token).ConfigureAwait(false);
                    originalPaths = new(Path.Combine(originalDefinition.Binding.ArtifactRootCanonicalPath, "actual-source-catalog.json"), originalDefinition.Component.Path,
                        originalDefinition.PublicKey.Path, originalDefinition.KeyId, originalDefinition.Fingerprint, originalDefinition.BindingPath, originalDefinition.Binding.ComputeSha256(), originalDefinition.SemanticEnvelope);
                }
                await files.WriteNewAsync(prerequisitePath, JsonSerializer.SerializeToUtf8Bytes(originalPaths), lease.Token).ConfigureAwait(false);
            }
            string group = phase switch { "definition" => "definition-component", "provider" => "native-component", "maintenance" => "maintenance-component", _ => throw Invalid() };
            var hostConfiguration = new Production181HostConfiguration(root, bundle.TestAssembly, bundle.TestSha256, inputs.Subject.ConsoleAssemblySha256, inputs.Subject.CoreAssemblySha256,
                prerequisitePath, CurrentCustomerSequenceRepairPermit.Hash(files.Read(prerequisitePath, sharedReader: true, maximumBytes: 65536)), bindingPath, authority.Binding.ComputeSha256(), group);
            var host = await Production181HostLauncher.RunAsync(files, hostConfiguration, inputs.Subject, originalTrust ?? new ReceiptAttestationTrustStore([]), originalDefinition?.KeyId ?? string.Empty,
                originalDefinition?.Fingerprint ?? string.Empty, lease.Token).ConfigureAwait(false);
            files.Require(); inputs.Require(); bundle.Require();
            DateTimeOffset began = ObservedBegin(files, root), completed = host.CompletedAtUtc, expires = began.AddHours(12), now = DateTimeOffset.UtcNow;
            string keyId = "production181-" + phase + "-" + Guid.NewGuid().ToString("N");
            CustomerDefinitionProof? definitionUnsigned = null; Production181GuardedBootstrapProof? guardedUnsigned = null;
            if (phase == "definition")
            {
                definitionUnsigned = Production181CustomerDefinitionAssembler.AssembleAfterActualRun(files, inputs.Subject, host.Trx.Path, heldTest.Path, root, keyId, began, completed, expires, now, bundle.TestAssembly);
                Production181CustomerDefinitionReader.RequireBody(files, definitionUnsigned, inputs.Subject, now);
            }
            else
            {
                guardedUnsigned = Production181CustomerGuardedAssembler.AssembleAfterActualRun(files, group, inputs.Subject, importedDefinition ?? throw Invalid(), originalPaths ?? throw Invalid(), host.Trx, host.HostExit, root,
                    heldTest.Path, began, completed, expires, originalDefinition!.KeyId, originalDefinition.Fingerprint, keyId, originalTrust ?? throw Invalid(), now, bundle.TestAssembly);
                Production181CustomerGuardedReader.RequireBody(files, guardedUnsigned, inputs.Subject, originalTrust!, originalDefinition.KeyId, originalDefinition.Fingerprint, now);
            }
            // Fresh phase key is created ONLY after genuine completed native body validation. Never persist private bytes.
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); byte[] privateBytes = key.ExportPkcs8PrivateKey(); char[] privatePem = PemEncoding.Write("PRIVATE KEY", privateBytes);
            try
            {
                using var signer = new P256MigrationEvidenceSigner(keyId, privatePem); byte[] spki = signer.ExportSubjectPublicKeyInfo();
                var entries = new List<TrustedAttestationKey> { new(keyId, spki) };
                if (originalDefinition is not null)
                {
                    using var originalAuthority = WindowsLocalRunAuthority.AcquireResume(originalDefinition.Binding.ArtifactRootCanonicalPath, originalDefinition.Binding);
                    using var originalFiles = new CurrentAppOwnedRepairCustody(originalAuthority); entries.Add(new(originalDefinition.KeyId, Read(originalFiles, originalDefinition.PublicKey)));
                }
                var trust = new ReceiptAttestationTrustStore(entries); string fingerprint = signer.PublicKeyFingerprintSha256;
                string publicPath = Path.Combine(root, "actual-proof-public.spki"); await files.WriteNewAsync(publicPath, spki, lease.Token).ConfigureAwait(false);
                CustomerDefinitionArtifact publicArtifact = Artifact(files, publicPath);
                if (publicArtifact.Sha256 != fingerprint) { throw Invalid(); }
                string componentPath = Path.Combine(root, "actual-" + phase + "-component.json");
                byte[] componentBytes = phase == "definition"
                    ? JsonSerializer.SerializeToUtf8Bytes(Production181CustomerDefinitionAssembler.SignAfterReadback(files, definitionUnsigned!, inputs.Subject, signer, trust, fingerprint, DateTimeOffset.UtcNow))
                    : JsonSerializer.SerializeToUtf8Bytes(Production181CustomerGuardedAssembler.SignAfterActualReadback(files, guardedUnsigned!, inputs.Subject, signer, trust, fingerprint, DateTimeOffset.UtcNow));
                await files.WriteNewAsync(componentPath, componentBytes, lease.Token).ConfigureAwait(false); var component = Artifact(files, componentPath);
                if (!files.Read(componentPath, sharedReader: true, maximumBytes: 8_000_000).AsSpan().SequenceEqual(componentBytes)) { throw Invalid(); }
                var unsignedEnvelope = Production181SemanticAssembler.Assemble(files, phase, inputs.Subject, component, host.HostExit, root, trust, keyId, fingerprint, DateTimeOffset.UtcNow);
                string envelopePath = Path.Combine(root, "actual-" + phase + "-semantic-envelope.json");
                _ = await Production181SemanticAssembler.SignRetainAndReadbackAsync(files, unsignedEnvelope, inputs.Subject, signer, trust, fingerprint, envelopePath, DateTimeOffset.UtcNow, lease.Token).ConfigureAwait(false);
                files.Require(); return new(phase, authority.Binding, bindingPath, component, Artifact(files, envelopePath), publicArtifact, keyId, fingerprint, host.HostExit);
            }
            finally { CryptographicOperations.ZeroMemory(privateBytes); CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(privatePem.AsSpan())); }
            async Task ImportInput(Production181Input input, string name)
            { _ = inputs.Read(input); _ = await Production181CustomerDefinitionAssembler.ImportActualAsync(inputs.Files(input), files, inputs.PathOf(input), Path.Combine(root, name), lease.Token).ConfigureAwait(false); }
        }
        void RequireOriginal(Production181PhaseResult phase)
        {
            using var authority = WindowsLocalRunAuthority.AcquireResume(phase.Binding.ArtifactRootCanonicalPath, phase.Binding); using var files = new CurrentAppOwnedRepairCustody(authority);
            _ = Trust(files, phase); var envelope = MigrationConsole.DecodeCustomerSequence<Production181SemanticEnvelope>(Read(files, phase.SemanticEnvelope));
            var entries = new List<TrustedAttestationKey> { new(phase.KeyId, Read(files, phase.PublicKey)) };
            if (phase.Phase != "definition")
            {
                using var originalAuthority = WindowsLocalRunAuthority.AcquireResume(definition.Binding.ArtifactRootCanonicalPath, definition.Binding);
                using var originalFiles = new CurrentAppOwnedRepairCustody(originalAuthority);
                entries.Add(new(definition.KeyId, Read(originalFiles, definition.PublicKey)));
            }
            _ = Production181SemanticEnvelopeReader.Require(files, envelope, inputs.Subject, new ReceiptAttestationTrustStore(entries), phase.KeyId, phase.Fingerprint, DateTimeOffset.UtcNow); files.Require();
        }
    }
    private static DateTimeOffset ObservedBegin(CurrentAppOwnedRepairCustody files, string root)
    {
        var starts = new List<DateTimeOffset>();
        foreach (string path in Directory.EnumerateFiles(root, "*-attempt.json", SearchOption.TopDirectoryOnly))
        { using var document = JsonDocument.Parse(files.Read(path, sharedReader: true, maximumBytes: 65536)); if (document.RootElement.TryGetProperty("run", out _) && document.RootElement.TryGetProperty("began", out var value)) { starts.Add(value.GetDateTimeOffset()); } }
        return starts.Count == 0 ? throw Invalid() : starts.Min();
    }
    private static ReceiptAttestationTrustStore Trust(CurrentAppOwnedRepairCustody files, Production181PhaseResult result)
    {
        var trust = new ReceiptAttestationTrustStore([new(result.KeyId, Read(files, result.PublicKey))]);
        return !trust.TryGetPublicKeyFingerprintSha256(result.KeyId, out string actual) || actual != result.Fingerprint
            ? throw Invalid()
            : trust;
    }
    private static byte[] Read(CurrentAppOwnedRepairCustody files, CustomerDefinitionArtifact artifact)
    { byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: 8_000_000); return CurrentCustomerSequenceRepairPermit.Hash(bytes) == artifact.Sha256 ? bytes : throw Invalid(); }
    private static CustomerDefinitionArtifact Artifact(CurrentAppOwnedRepairCustody files, string path)
    {
        return new(path, CurrentCustomerSequenceRepairPermit.Hash(files.Read(path, sharedReader: true, maximumBytes: 8_000_000)));
    }

    private static MigrationExecutionException Invalid()
    {
        return CurrentCustomerSequenceRepairPermit.Invalid();
    }
}
