using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair : ICurrentAuthArchiveGenuineExecutionLease
{
    private CurrentAuthArchiveGenuineExecutionCase? _executionCase;
    private CurrentAuthArchiveGenuineHelperClaims? _executionClaims;
    private bool _executionEnvironmentClosed;

    internal static Task<ICurrentAuthArchiveGenuineExecutionLease> OpenExecutionLeaseAsync(CurrentAuthArchiveGenuineHostConfiguration request,
        CurrentAuthArchiveGenuineExecutionCase expectedCase, CancellationToken ct)
    { return OpenExecutionCoreAsync(request, expectedCase, null, ct); }

    internal static Task<ICurrentAuthArchiveGenuineExecutionLease> OpenFinal6ExecutionLeaseAsync(CurrentAuthArchiveFinal6CaseContext context,
        CurrentAuthArchiveGenuineExecutionCase expectedCase, CancellationToken ct)
    {
        return CurrentAuthArchiveGeneratedCasesV2.Execution(context.Case) != expectedCase
            ? throw CurrentAuthArchiveFinal6Source.Invalid()
            : OpenExecutionCoreAsync(context.Request, expectedCase, context, ct);
    }

    private static async Task<ICurrentAuthArchiveGenuineExecutionLease> OpenExecutionCoreAsync(CurrentAuthArchiveGenuineHostConfiguration request,
        CurrentAuthArchiveGenuineExecutionCase expectedCase, CurrentAuthArchiveFinal6CaseContext? final6Case, CancellationToken ct)
    {
        CurrentAuthArchiveGenuineExecutionInputContract.Require(new(CurrentAuthArchiveGenuineExecutionInputContract.Kind, request), expectedCase);
        var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(Path.GetDirectoryName(request.Inputs.TestImage.Path)!, ct);
        CurrentAuthArchiveComponentReadback? inputs = null;
        CurrentAuthArchiveGenuineOwnedPair? pair = null;
        try
        {
            bundle.Require();
            inputs = final6Case is not null ? await CurrentAuthArchiveComponentReadback.OpenFinal6InitialAsync(request.Inputs, final6Case, ct) :
                await CurrentAuthArchiveComponentReadback.OpenGenuineExecutionInitialAsync(request.Inputs, expectedCase, ct);
            var seed = await inputs.ReadSeedAsync(ct);
            CurrentAuthArchiveGenuineExecutionSeed.RequireInitial(seed, inputs.Pins, inputs.TrustStore, expectedCase, DateTimeOffset.UtcNow);
            pair = new(inputs, bundle, seed, ct) { _executionCase = expectedCase };
            await pair.CreateOwnedAsync(request, pair._lease.Token);
            await pair.FreezeExecutionEnvironmentAsync(pair._lease.Token);
            _ = await ((ICurrentAuthArchiveGenuineExecutionLease)pair).AttestExecutionAsync(true, pair._lease.Token);
            return pair;
        }
        catch (Exception primary)
        {
            if (pair is not null)
            {
                try { await pair.DisposeAsync(); }
                catch (Exception cleanup) { primary.Data["execution_factory_cleanup_failure"] = cleanup.GetType().Name; }
            }
            else
            {
                try { inputs?.Dispose(); }
                catch (Exception cleanup) { primary.Data["execution_input_cleanup_failure"] = cleanup.GetType().Name; }
                try { bundle.Dispose(); }
                catch (Exception cleanup) { primary.Data["execution_factory_bundle_cleanup_failure"] = cleanup.GetType().Name; }
            }
            throw;
        }
    }

    private async Task FreezeExecutionEnvironmentAsync(CancellationToken ct)
    {
        await RequireAsync(ct);
        if (_environment is null || _firstFiles is null || _secondFiles is null || _firstAuthority is null || _secondAuthority is null ||
            _firstPolicy is null || _secondPolicy is null || _dualDeviceProof is null || _executionClaims is not null) { throw Invalid(); }
        var native = await _environment.CaptureDualHelperNativeEvidenceAsync(Scope, _firstPolicy.HbaFile, _firstPolicy.RawRules,
            _secondPolicy.HbaFile, _secondPolicy.RawRules, ct);
        using var reviewer = DualSigner(_inputs.Pins.ReviewKeyId, CurrentAuthArchiveGenuineDualInputContract.ReviewKeyName, _inputs.Pins.ReviewFingerprint);
        using var authorizer = DualSigner(_inputs.Pins.AuthorizationKeyId, CurrentAuthArchiveGenuineDualInputContract.AuthorizationKeyName, _inputs.Pins.AuthorizationFingerprint);
        var review = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReviewDomain, Scope, reviewer);
        var permission = new CurrentAuthArchiveAuthorization(Scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(review), DateTimeOffset.UtcNow, Scope.ExpiresAtUtc);
        var authorization = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain, permission, authorizer);
        // No capability exists yet. The final concrete Env is constructed only after actual signed authorization exists.
        var old = _environment; _environment = null; old.Dispose();
        _environment = new(_firstFiles, _secondFiles, _firstAuthority, _secondAuthority, Scope, _inputs.Source, native.LocalTarget, native.ComparisonTarget,
            Connection(_firstFiles, _firstPolicy.OperatorConnectionPath), Connection(_secondFiles, _secondPolicy.OperatorConnectionPath),
            Connection(_firstFiles, _firstPolicy.OrdinaryConnectionPath), Connection(_secondFiles, _secondPolicy.OrdinaryConnectionPath),
            _dualDeviceProof, _inputs.TrustStore, _inputs.Pins, CurrentAuthLocalSessionArchivePolicy.Hash(authorization));
        _inputs.BindFinal6Environment(_environment);
        _executionClaims = new(review, authorization);
        await RequireAsync(ct);

        static string Connection(CurrentAppOwnedRepairCustody files, string path)
        {
            return Encoding.UTF8.GetString(files.Read(path, maximumBytes: 65536));
        }
    }

    async Task<CurrentAuthArchiveGenuineExecutionAttestation> ICurrentAuthArchiveGenuineExecutionLease.AttestExecutionAsync(bool baseline, CancellationToken ct)
    {
        await RequireExecutionLiveAsync(baseline, ct);
        var (Phase, CaseId) = CurrentAuthArchiveGenuineExecutionCases.Identity(_executionCase ?? throw Invalid());
        var owned = new CurrentAuthArchiveGenuineAttestation(Phase, CaseId, Scope, Subject, _inputs.Source,
            typeof(CurrentAuthArchiveGenuineOwnedPair).Assembly.Location, typeof(MigrationConsole).Assembly.Location,
            typeof(CurrentAuthLocalSessionArchivePermit).Assembly.Location, _inputs.Pins, _inputs.TrustStore, _environment!);
        return new(_executionCase.Value, owned, _executionClaims!, CurrentAuthLocalSessionArchivePolicy.Hash(_executionClaims!.Authorization));
    }

    private async Task RequireExecutionLiveAsync(bool baseline, CancellationToken ct)
    {
        if (_executionCase is null || _executionClaims is null || _executionEnvironmentClosed || _environment is null ||
            _disposed || _first is null || _second is null || _firstAuthority is null || _secondAuthority is null ||
            _scope is null || DateTimeOffset.UtcNow >= _scope.ExpiresAtUtc) { throw Invalid(); }
        CurrentAuthArchiveGenuineExecutionCases.RequireImplemented(_executionCase.Value);
        if (baseline) { await RequireAsync(ct); return; }
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct, _lease.Token, _first.Token, _second.Token);
        _bundle.Require(); await _inputs.RequireAsync(lease.Token);
        await _first.RequireHealthyHeldAsync(_firstAuthority, lease.Token);
        await _second.RequireHealthyHeldAsync(_secondAuthority, lease.Token);
        await _environment.RequireAcceptedSourceOwnerCustodyAndTargetsAsync(Scope, lease.Token);
        _bundle.Require();
    }

    async Task<string> ICurrentAuthArchiveGenuineExecutionLease.ReadExecutionConnectionAsync(CancellationToken ct)
    {
        await RequireExecutionLiveAsync(false, ct);
        if (_firstFiles is null || _firstPolicy is null) { throw Invalid(); }
        var endpoint = new NpgsqlConnectionStringBuilder(Encoding.UTF8.GetString(_firstFiles.Read(_firstPolicy.OperatorConnectionPath, maximumBytes: 65536)))
        { Database = "Auth", Pooling = false, Options = "", IncludeErrorDetail = false };
        return endpoint.Host != "127.0.0.1" || endpoint.Database != "Auth" || endpoint.Username != Scope.LocalObservationPolicy.Maintenance.Role ||
            endpoint.Port is < 1 or > 65535 || string.IsNullOrWhiteSpace(endpoint.Password)
            ? throw Invalid()
            : endpoint.ConnectionString;
    }

    async Task<P256MigrationEvidenceSigner> ICurrentAuthArchiveGenuineExecutionLease.CreateExecutionSignerAsync(CancellationToken ct)
    {
        await RequireExecutionLiveAsync(false, ct);
        return DualSigner(_inputs.Pins.EvidenceKeyId, CurrentAuthArchiveGenuineDualInputContract.EvidenceKeyName, _inputs.Pins.EvidenceFingerprint);
    }

    Task<CurrentAuthArchiveGenuineDualArtifacts> ICurrentAuthArchiveGenuineExecutionLease.RetainExecutionAsync(
        CurrentAuthArchiveGenuineExecutionFacts facts, CancellationToken ct)
    {
        return RetainExecutionCoreAsync(facts, null, null, null, null, ct);
    }

    private async Task<CurrentAuthArchiveGenuineDualArtifacts> RetainExecutionCoreAsync(CurrentAuthArchiveGenuineExecutionFacts facts,
        CurrentAuthArchiveGenuinePublicationFailureFacts? failure, CurrentAuthArchiveGenuineFailureObservation? failureObservation,
        CurrentAuthArchiveGenuineCommitFailureFacts? commitFailure, CurrentAuthArchiveGenuineCommitFailureObservation? commitObservation, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) { throw Invalid(); }
        bool failed = failure is not null || commitFailure is not null;
        if (failure is not null && commitFailure is not null) { throw Invalid(); }
        if (!failed) { await RequireExecutionLiveAsync(false, ct); }
        if (_environment is null || _firstFiles is null || _secondFiles is null || _firstPolicy is null || _secondPolicy is null ||
            _dualDeviceProof is null || facts.Case != _executionCase || facts.Claims != _executionClaims || facts.BeganAtUtc > facts.ReturnedAtUtc ||
            facts.ReturnedAtUtc > DateTimeOffset.UtcNow) { throw Invalid(); }
        if (!failed) { _environment.RequireTerminal(facts.Terminal ?? throw Invalid()); }
        var native = failureObservation?.Native ?? commitObservation?.Native ?? await _environment.CaptureDualHelperNativeEvidenceAsync(Scope, _firstPolicy.HbaFile, _firstPolicy.RawRules,
            _secondPolicy.HbaFile, _secondPolicy.RawRules, ct);
        if (facts.Case == CurrentAuthArchiveGenuineExecutionCase.PreparedPublication)
        { CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(facts.LocalAfter.Auth, facts.LocalBefore.Auth); }
        else { CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(facts.LocalBefore.Auth, facts.LocalAfter.Auth); }
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(facts.LocalBefore, Scope.LocalObservationPolicy, DateTimeOffset.UtcNow);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(facts.LocalAfter, Scope.LocalObservationPolicy, DateTimeOffset.UtcNow,
            allowEmptyLocalSessions: facts.Case != CurrentAuthArchiveGenuineExecutionCase.PreparedPublication);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(facts.ComparisonBefore, Scope.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(facts.ComparisonAfter, Scope.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
        CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(facts.ComparisonAfter.Auth, facts.ComparisonBefore.Auth);
        var artifacts = new Dictionary<string, CurrentAuthArchiveGenuineArtifact>(StringComparer.Ordinal);
        string root = _inputs.ParentAuthority.Binding.ArtifactRootCanonicalPath;
        string prefix = $"genuine-execution-{Scope.OperationId:N}";
        _ = await JsonAsync("scope", Scope); _ = await JsonAsync("source", _inputs.Source); _ = await JsonAsync("review", facts.Claims.Review);
        _ = await JsonAsync("authorization", facts.Claims.Authorization); _ = await JsonAsync("device-proof", _dualDeviceProof);
        _ = await JsonAsync("local-before", facts.LocalBefore.Databases); _ = await JsonAsync("local-after", facts.LocalAfter.Databases);
        _ = await JsonAsync("comparison-before", facts.ComparisonBefore.Databases); _ = await JsonAsync("comparison-after", facts.ComparisonAfter.Databases);
        _ = await JsonAsync("local-before-catalogs", facts.LocalBefore.Catalogs); _ = await JsonAsync("local-after-catalogs", facts.LocalAfter.Catalogs);
        _ = await JsonAsync("comparison-before-catalogs", facts.ComparisonBefore.Catalogs); _ = await JsonAsync("comparison-after-catalogs", facts.ComparisonAfter.Catalogs);
        _ = await JsonAsync("local-before-native-v2", CurrentAuthArchiveNativeCommitmentV2.Capture(facts.LocalBefore.Auth.Native));
        _ = await JsonAsync("local-after-native-v2", CurrentAuthArchiveNativeCommitmentV2.Capture(facts.LocalAfter.Auth.Native));
        _ = await JsonAsync("comparison-before-native-v2", CurrentAuthArchiveNativeCommitmentV2.Capture(facts.ComparisonBefore.Auth.Native));
        _ = await JsonAsync("comparison-after-native-v2", CurrentAuthArchiveNativeCommitmentV2.Capture(facts.ComparisonAfter.Auth.Native));
        _ = await JsonAsync("local-before-sessions", facts.LocalBefore.Auth.Sessions); _ = await JsonAsync("local-after-sessions", facts.LocalAfter.Auth.Sessions);
        _ = await JsonAsync("comparison-before-sessions", facts.ComparisonBefore.Auth.Sessions); _ = await JsonAsync("comparison-after-sessions", facts.ComparisonAfter.Auth.Sessions);
        _ = await JsonAsync("rows", facts.LocalBefore.Auth.Sessions); _ = await JsonAsync("local-target", native.LocalTarget);
        _ = await JsonAsync("comparison-target", native.ComparisonTarget); _ = await JsonAsync("local-container", native.LocalContainer);
        _ = await JsonAsync("local-volume", native.LocalVolume); _ = await JsonAsync("comparison-container", native.ComparisonContainer); _ = await JsonAsync("comparison-volume", native.ComparisonVolume);
        _ = await JsonAsync("native-ownership-v2", new { native.LocalVolumeConsumers, native.ComparisonVolumeConsumers, native.ObservedAtUtc });
        var localHba = await CopyAsync("local-hba", _firstFiles, _firstPolicy.HbaFile);
        var localRules = await CopyAsync("local-hba-rules", _firstFiles, _firstPolicy.RawRules);
        var comparisonHba = await CopyAsync("comparison-hba", _secondFiles, _secondPolicy.HbaFile);
        var comparisonRules = await CopyAsync("comparison-hba-rules", _secondFiles, _secondPolicy.RawRules);
        _ = await JsonAsync("local-policy", native.LocalPolicy with { HbaFile = AsProof(localHba), RawRules = AsProof(localRules) });
        _ = await JsonAsync("comparison-policy", native.ComparisonPolicy with { HbaFile = AsProof(comparisonHba), RawRules = AsProof(comparisonRules) });
        // Read actual held recovery bytes before closing the concrete Env. Copies never change original domain claims.
        await RecoveryAsync("first-ciphertext", true, Scope.Paths.FirstCiphertext, 12 * 1024 * 1024);
        await RecoveryAsync("second-ciphertext", false, Scope.Paths.SecondCiphertext, 12 * 1024 * 1024);
        await RecoveryAsync("first-recovery-key", true, Scope.Paths.RecoveryPrivateKey, 65536);
        await RecoveryAsync("second-recovery-key", false, Scope.Paths.SecondRecoveryPrivateKey, 65536);
        string[] expectedNames = !failed ? ["operation-start", "recovery-manifest", "prepared", "committed-readback"] :
            facts.Case == CurrentAuthArchiveGenuineExecutionCase.PreparedPublication ? ["operation-start", "recovery-manifest", "failed-or-uncertain"] :
            ["operation-start", "recovery-manifest", "prepared", "failed-or-uncertain"];
        string[] expectedFiles = expectedNames.Select(name => $"{Scope.OperationId:D}-Auth-session-archive-{name}.json").Order(StringComparer.Ordinal).ToArray();
        RequireClosedJournalInventory();
        // Final native captures are complete. No Env/capability operation is allowed after this close.
        _executionEnvironmentClosed = true;
        var environment = _environment; _environment = null; environment.Dispose();
        RequireClosedJournalInventory();
        var journals = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (string name in expectedNames)
        {
            string original = Path.Combine(_firstAuthority!.Binding.ArtifactRootCanonicalPath, $"{Scope.OperationId:D}-Auth-session-archive-{name}.json");
            byte[] bytes = _firstFiles.Read(original, sharedReader: true, maximumBytes: 65536);
            using var held = SecureLocalFile.OpenReadShared(original);
            var identity = WindowsRunFileIdentity.Observe(held.SafeFileHandle);
            if (!SecureLocalFile.HandleResolvesToApprovedPath(held, original) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(original)) || held.Length != bytes.Length)
            { throw Invalid(); }
            var observed = new byte[bytes.Length]; held.ReadExactly(observed);
            if (!observed.AsSpan().SequenceEqual(bytes) || WindowsRunFileIdentity.Observe(held.SafeFileHandle) != identity) { throw Invalid(); }
            journals.Add(name, bytes); _ = await WriteAsync(name, bytes); _ = await JsonAsync(name + "-native-file", new { OriginalPath = original, Identity = identity, Sha256 = CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) });
        }
        var receipts = failure is not null ? RequireFailureJournal(journals, Scope, facts, failure, failureObservation?.Witness ?? throw Invalid(), _inputs.Pins, _inputs.TrustStore) :
            commitFailure is not null ? RequireCommitFailureJournal(journals, Scope, facts, commitFailure, _inputs.Pins, _inputs.TrustStore) :
            RequireExecutionJournal(journals, Scope, facts.Claims, facts.Terminal ?? throw Invalid(),
            facts.LocalBefore.Auth.Native.Snapshot.Sha256, facts.LocalAfter.Auth.Native.Snapshot.Sha256,
            facts.BeganAtUtc, facts.ReturnedAtUtc, _inputs.Pins, _inputs.TrustStore);
        var retainedManifest = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveRecoveryManifest>(
            MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(journals["recovery-manifest"]),
            CurrentAuthLocalSessionArchivePolicy.RecoveryDomain, _inputs.Pins.EvidenceKeyId, _inputs.Pins.EvidenceFingerprint, _inputs.TrustStore);
        await CurrentAuthLocalSessionArchiveCrypto.VerifyAsync(new ExecutionProofCopyStorage(_inputs.ParentFiles, Scope.Paths, artifacts),
            Scope, retainedManifest, facts.LocalBefore.Auth.Sessions, ct);
        if (failure is not null) { _ = await JsonAsync("publication-failure", failure); _ = await JsonAsync("slot-witness", failureObservation!.Witness); }
        if (commitFailure is not null)
        {
            if (commitObservation is null) { throw Invalid(); }
            _ = await JsonAsync("commit-failure", commitFailure);
            _ = await WriteAsync("proxy-created", commitObservation.Created); _ = await WriteAsync("proxy-disposed", commitObservation.Disposed);
        }
        var scenario = new CurrentAuthArchiveProofScenario(commitFailure is not null ? "commit-ack-lost" : failure is null ? "complete" :
            facts.Case == CurrentAuthArchiveGenuineExecutionCase.PreparedPublication ? "prepared-publication-before-ack" : "terminal-publication",
            failure?.ActualExceptionType ?? commitFailure?.ActualExceptionType,
            facts.Case is not (CurrentAuthArchiveGenuineExecutionCase.PreparedPublication or CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost),
            true, false, false, DateTimeOffset.UtcNow,
            expectedNames.Where(name => name is "prepared" or "committed-readback" or "failed-or-uncertain")
                .Select(name => new CurrentAuthArchiveProofSlot(AsProof(artifacts[name]), true)).ToArray());
        CurrentAuthArchiveProofReader.RequireEffects(_seed.CaseId, scenario, receipts, facts.LocalBefore.Auth.Native.Snapshot, facts.LocalAfter.Auth.Native.Snapshot);
        _ = await JsonAsync("scenario", scenario);
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(typeof(CurrentAuthArchiveGenuineOwnedPair).Assembly.Location), root)) { throw Invalid(); }
        artifacts.Add("test-assembly", new(typeof(CurrentAuthArchiveGenuineOwnedPair).Assembly.Location, _seed.TestAssemblySha256));
        await _inputs.RequireAsync(ct); _bundle.Require();
        RequireClosedJournalInventory();
        DateTimeOffset ended = DateTimeOffset.UtcNow;
        var stage = await WriteAsync("incomplete-precleanup-stage", JsonSerializer.SerializeToUtf8Bytes(new
        {
            Kind = "current-auth-genuine-execution-incomplete-precleanup-v1",
            _seed.CaseId,
            CurrentAuthArchiveGenuineExecutionCases.Identity(facts.Case).Phase,
            Scope.OperationId,
            facts.BeganAtUtc,
            EndedAtUtc = ended,
            NativeObservedAtUtc = native.ObservedAtUtc,
            native.LocalPort,
            native.ComparisonPort,
            ProxyPort = commitObservation?.Proxy.Port,
            Artifacts = artifacts,
            Receipts = expectedNames.Where(name => name is "prepared" or "committed-readback" or "failed-or-uncertain").Select(name => artifacts[name]).ToArray(),
            CleanupVerified = false,
            PhaseProofComplete = false,
            ProviderExitCode = (int?)null,
        }));
        return new(stage, facts.BeganAtUtc, ended);

        Task<CurrentAuthArchiveGenuineArtifact> JsonAsync<T>(string name, T value)
        {
            return value is IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> snapshots
                ? BaselineAsync(name, snapshots)
                : WriteAsync(name, JsonSerializer.SerializeToUtf8Bytes(value));
        }
        async Task<CurrentAuthArchiveGenuineArtifact> BaselineAsync(string name, IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> snapshots)
        {
            var artifact = await CurrentAuthArchiveStreamedBaselineV2.RetainAsync(_inputs.ParentFiles, Path.Combine(root, prefix + "-" + name + ".json"), snapshots, ct);
            artifacts.Add(name, artifact); return artifact;
        }

        async Task<CurrentAuthArchiveGenuineArtifact> WriteAsync(string name, byte[] bytes)
        {
            string path = Path.Combine(root, name is "prepared" or "committed-readback" or "failed-or-uncertain"
                ? $"{Scope.OperationId:D}-Auth-session-archive-{name}.json" : prefix + "-" + name + ".json");
            await _inputs.ParentFiles.WriteNewAsync(path, bytes, ct);
            if (!_inputs.ParentFiles.Read(path, sharedReader: true, maximumBytes: 12 * 1024 * 1024).AsSpan().SequenceEqual(bytes)) { throw Invalid(); }
            var result = new CurrentAuthArchiveGenuineArtifact(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
            if (name != "incomplete-precleanup-stage") { artifacts.Add(name, result); }
            return result;
        }
        async Task<CurrentAuthArchiveGenuineArtifact> CopyAsync(string name, CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofArtifact artifact)
        {
            byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: 65536);
            return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != artifact.Sha256 ? throw Invalid() : await WriteAsync(name, bytes);
        }
        async Task RecoveryAsync(string name, bool first, string path, int maximum)
        {
            byte[] bytes = await _environment!.RecoveryStorage.ReadDomainHeldAsync(first, path, maximum, ct);
            try { _ = await WriteAsync(name, bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        static CurrentAuthArchiveProofArtifact AsProof(CurrentAuthArchiveGenuineArtifact value)
        {
            return new(value.Path, value.Sha256);
        }

        void RequireClosedJournalInventory()
        {
            string journalPrefix = Scope.OperationId.ToString("D") + "-";
            string[] names = Directory.EnumerateFileSystemEntries(_firstAuthority!.Binding.ArtifactRootCanonicalPath)
                .Select(Path.GetFileName).Where(name => name is not null && name.StartsWith(journalPrefix, StringComparison.OrdinalIgnoreCase))
                .Select(name => name!).Order(StringComparer.Ordinal).ToArray();
            if (!names.SequenceEqual(expectedFiles, StringComparer.Ordinal) || Directory.EnumerateFileSystemEntries(_secondAuthority!.Binding.ArtifactRootCanonicalPath)
                .Select(Path.GetFileName).Any(name => name is not null && name.StartsWith(journalPrefix, StringComparison.OrdinalIgnoreCase))) { throw Invalid(); }
            _firstFiles.Require(); _secondFiles.Require();
        }
    }

    internal static CurrentAuthArchiveReceipt[] RequireExecutionJournal(IReadOnlyDictionary<string, byte[]> journal,
        CurrentAuthArchiveScope scope, CurrentAuthArchiveGenuineHelperClaims claims, CurrentAuthArchiveReceipt expectedTerminal,
        string beforeAuth, string afterAuth, DateTimeOffset began, DateTimeOffset returned,
        CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust)
    {
        if (journal.Count != 4 || !journal.ContainsKey("operation-start") || !journal.ContainsKey("recovery-manifest") ||
            !journal.ContainsKey("prepared") || !journal.ContainsKey("committed-readback")) { throw Invalid(); }
        using var reservation = JsonDocument.Parse(journal["operation-start"]);
        if (reservation.RootElement.GetProperty("Domain").GetString() != "current-auth-session-archive-reservation-v1" ||
            reservation.RootElement.GetProperty("OperationId").GetGuid() != scope.OperationId ||
            reservation.RootElement.GetProperty("AuthorizationSha256").GetString() != CurrentAuthLocalSessionArchivePolicy.Hash(claims.Authorization)) { throw Invalid(); }
        var manifestClaim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(journal["recovery-manifest"]);
        var manifest = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveRecoveryManifest>(manifestClaim,
            CurrentAuthLocalSessionArchivePolicy.RecoveryDomain, pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
        if (manifest.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(scope) || manifest.AuthorizationSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(claims.Authorization) ||
            expectedTerminal.RecoveryManifestSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(manifest)) { throw Invalid(); }
        var preparedClaim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(journal["prepared"]);
        var terminalClaim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(journal["committed-readback"]);
        CurrentAuthArchiveReceipt Decode(CurrentAuthArchiveClaim claim)
        {
            return CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveReceipt>(claim,
            CurrentAuthLocalSessionArchivePolicy.ReceiptDomain, pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
        }

        var prepared = Decode(preparedClaim); var terminal = Decode(terminalClaim);
        return prepared.Classification != CurrentAppOwnedCommitClassification.Prepared || terminal.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback ||
            terminal != expectedTerminal || prepared.OperationId != scope.OperationId ||
            terminal.OperationId != scope.OperationId || prepared.AuthorizationSha256 != manifest.AuthorizationSha256 || terminal.AuthorizationSha256 != manifest.AuthorizationSha256 ||
            prepared.PreviousSha256 != new string('0', 64) || terminal.PreviousSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(preparedClaim) ||
            prepared.BeforeAuthSha256 != beforeAuth || terminal.BeforeAuthSha256 != prepared.BeforeAuthSha256 ||
            prepared.AfterAuthSha256 != afterAuth || terminal.AfterAuthSha256 != prepared.AfterAuthSha256 ||
            prepared.RecoveryManifestSha256 != terminal.RecoveryManifestSha256 || prepared.ObservedAtUtc < began ||
            prepared.ObservedAtUtc > terminal.ObservedAtUtc || terminal.ObservedAtUtc > returned
            ? throw Invalid()
            : [prepared, terminal];
    }

    private sealed class ExecutionProofCopyStorage(CurrentAppOwnedRepairCustody files, CurrentAuthArchivePaths paths,
        IReadOnlyDictionary<string, CurrentAuthArchiveGenuineArtifact> artifacts) : ICurrentAuthLocalSessionArchiveStorage
    {
        public Task RequireFreshIndependentRecoveryPathsAsync(CurrentAuthArchivePaths value, CancellationToken ct)
        {
            throw Invalid();
        }

        public Task WriteCreateNewDurableAsync(string path, byte[] bytes, CancellationToken ct)
        {
            throw Invalid();
        }

        public Task RequireCustodyAsync(CancellationToken ct) { ct.ThrowIfCancellationRequested(); files.Require(); return Task.CompletedTask; }
        public Task<byte[]> ReadHeldAsync(string path, int maximumBytes, CancellationToken ct)
        {
            throw Invalid();
        }

        public Task<byte[]> ReadDomainHeldAsync(bool firstDomain, string path, int maximumBytes, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); files.Require();
            string name = (firstDomain, path) switch
            {
                (true, var value) when value == paths.FirstCiphertext => "first-ciphertext",
                (false, var value) when value == paths.SecondCiphertext => "second-ciphertext",
                (true, var value) when value == paths.RecoveryPrivateKey => "first-recovery-key",
                (false, var value) when value == paths.SecondRecoveryPrivateKey => "second-recovery-key",
                _ => throw Invalid(),
            };
            var artifact = artifacts[name];
            byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: maximumBytes);
            return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != artifact.Sha256 ? throw Invalid() : Task.FromResult(bytes);
        }
    }
}
