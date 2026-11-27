using System.Data;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CompanyStorageNativeFaultConfiguration(string TemplateConfigurationPath, string SuiteRoot);
internal sealed record CompanyStorageActualInvocation(bool MethodReturned, string? ExceptionType, int? ActualHResult, DateTimeOffset BeganAtUtc, DateTimeOffset EndedAtUtc);
internal sealed record CompanyStorageNativeFaultResult(CompanyStorageFaultCase Case, ConsumerColumnBootstrapSourceCapture FirstSource,
    ConsumerColumnBootstrapSourceCapture ForwardSource, CompanyStorageActualInvocation First, CompanyStorageActualInvocation? Replay, CompanyStorageActualInvocation Forward,
    string BeforeNativeSha256, string AfterFirstNativeSha256, string AfterForwardNativeSha256, string FirstRunSha256, string ForwardRunSha256,
    int PublicationDenials, int PublicationHResult, int DroppedCommits, string? ReplayRefusalSha256,
    IReadOnlyDictionary<string, string> RetainedOldArtifacts, string ContainerId, string Volume, bool CleanupVerified,
    ConsumerColumnBootstrapProxyCleanup? ProxyCleanup);

internal sealed partial class CompanyStorageRuntime
{
    private static readonly CompanyStorageFaultCase[] NativeCases = [CompanyStorageFaultCase.PreparedPublication, CompanyStorageFaultCase.LostCommitAcknowledgement,
        CompanyStorageFaultCase.TerminalPublication, CompanyStorageFaultCase.ReplayReservation, CompanyStorageFaultCase.FreshReconciliation];

    internal static async Task RunNativeFaultSuiteAsync(CompanyStorageNativeFaultConfiguration configuration, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows() || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly ||
            !Path.IsPathFullyQualified(configuration.SuiteRoot) || Directory.Exists(configuration.SuiteRoot)) { throw Invalid(); }
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct); CurrentAuthRepairCapacity.Require(admission: true);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromMinutes(45)); ct = deadline.Token;
        using var template = CompanyStorageRepairInputs.Open(configuration.TemplateConfigurationPath);
        if (template.Intent.SourceCommitSha != accepted) { throw Invalid(); }
        SecureSnapshotFileCreation.CreateRestrictedDirectory(configuration.SuiteRoot);
        using var authority = WindowsLocalRunAuthority.AcquireFresh(configuration.SuiteRoot); using var files = new CurrentAppOwnedRepairCustody(authority);
        var results = new List<CompanyStorageNativeFaultResult>();
        foreach (var @case in NativeCases)
        {
            var source = await FreshSourceAsync(template, accepted, ct);
            results.Add(await RunNativeCaseAsync(@case, source, template, configuration.SuiteRoot, ct));
        }
        if (results.Count != 5 || !results.Select(x => x.Case).SequenceEqual(NativeCases) || results.Any(x => !x.CleanupVerified) ||
            results.Select(x => x.ContainerId).Distinct(StringComparer.Ordinal).Count() != 5 ||
            await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != accepted) { throw Invalid(); }
        using var process = System.Diagnostics.Process.GetCurrentProcess(); var pins = template.Configuration.SigningPins;
        using var code = CompanyStorageAcceptedCodeCustody.Acquire();
        using var signer = template.Signer(template.Configuration.EvidencePrivateKey, pins.ReceiptKeyId, pins.ReceiptFingerprint);
        var report = CurrentAuthLocalSessionArchivePolicy.Sign("Legacy.Maliev.CompanyStorage.FiveActualFaults.v1", new
        {
            Kind = "company-storage-five-actual-owned-faults-v1",
            SourceCommitSha = accepted,
            code.RunnerDigestSha256,
            Results = results,
            Method = "fixed accepted Console same-process runtime",
            ProcessId = process.Id,
            ProcessStartedAtUtc = process.StartTime.ToUniversalTime(),
            ExecutableSha256 = CurrentAuthTypedHostProducer.ImageHash(Environment.ProcessPath!),
            CompletedAtUtc = DateTimeOffset.UtcNow,
            PositiveRehearsalAcceptance = false,
            OperatingSystemChildExitCode = (int?)null,
        }, signer);
        await files.WriteNewAsync(Path.Combine(configuration.SuiteRoot, "five-actual-native-faults.json"), JsonSerializer.SerializeToUtf8Bytes(report), ct);
    }

    private static async Task<CompanyStorageNativeFaultResult> RunNativeCaseAsync(CompanyStorageFaultCase @case, ConsumerColumnBootstrapSourceCapture source,
        CompanyStorageRepairInputs template, string parent, CancellationToken ct)
    {
        CompanyStorageOwnedSession? session = null; CompanyStorageFaultControl? control = null;
        CompanyStorageNativeFaultResult? result = null; Exception? primary = null, cleanup = null;
        var owned = new List<CompanyStorageOwnedConfiguration>();
        try
        {
            session = await CompanyStorageOwnedSession.CreateAsync(template, source, parent, ct);
            var contract = ApprovedCustomerCompanyStorageRepair.Create(source.Plan.Databases.Single(x => x.Database == "Customer"), source.Plan.SourceCommitSha,
                source.Plan.SourceCommitSha, await OwnerAsync(template, ct), DateTimeOffset.UtcNow);
            var original = await CompanyStorageOwnedInputs.CreateAsync(session, template, source, contract, Path.Combine(parent, "company-case-" + (int)@case + "-first"), ct); owned.Add(original);
            control = await CompanyStorageFaultControl.CreateAsync(session, @case, original, ct);
            CompanyStorageActualInvocation first; JsonElement firstRun; CompanyStorageArtifact firstRunArtifact;
            CompanyStorageNativeWitness? candidateBeforeRollback;
            using (var inputs = CompanyStorageRepairInputs.OpenOwned(original.Path, session))
            using (var runtime = await OpenOwnedAsync(inputs, source, session, control, ct))
            {
                first = await InvokeAsync(runtime, ct);
                candidateBeforeRollback = runtime._candidateReadback;
                (firstRun, firstRunArtifact) = ReadRun(inputs, completed: @case == CompanyStorageFaultCase.FreshReconciliation);
            }
            bool firstCommitted = @case is CompanyStorageFaultCase.LostCommitAcknowledgement or CompanyStorageFaultCase.TerminalPublication or CompanyStorageFaultCase.FreshReconciliation;
            if (first.MethodReturned != (@case == CompanyStorageFaultCase.FreshReconciliation) ||
                (@case is CompanyStorageFaultCase.PreparedPublication or CompanyStorageFaultCase.TerminalPublication or CompanyStorageFaultCase.ReplayReservation &&
                    (control.PublicationDenials != 1 || first.ActualHResult != control.PublicationHResult)) ||
                (@case == CompanyStorageFaultCase.LostCommitAcknowledgement && control.DroppedCommits != 1)) { throw Invalid(); }
            var current = await CaptureOwnedNativeAsync(session, contract, firstCommitted, ct);
            if (firstCommitted) { CompanyStorageNativeWitness.RequirePreserved(original.Before, current, contract); }
            else { RequireRolledBack(original.Before, current, candidateBeforeRollback ?? throw Invalid()); }
            var afterFirstFleet = await session.Lease.CaptureFleetAsync(ct);
            RequireOwnedFleet(original, current, afterFirstFleet);
            if (!firstRun.GetProperty("Completed").GetBoolean() && firstRun.GetProperty("Outcome").GetString() != "Unfinished") { throw Invalid(); }
            if (firstRun.GetProperty("IndependentlyObservedCommit").GetBoolean() != (@case is CompanyStorageFaultCase.TerminalPublication or CompanyStorageFaultCase.FreshReconciliation)) { throw Invalid(); }
            control.ReleaseDenial();
            var oldArtifacts = ArtifactHashes(original.Binding.ArtifactRootCanonicalPath);
            CompanyStorageActualInvocation? replay = null; string? replayRefusal = null;
            if (@case == CompanyStorageFaultCase.ReplayReservation)
            {
                // Reopen original signed files and construct a genuinely NEW runtime from the same old intent.
                using var inputs = CompanyStorageRepairInputs.OpenOwned(original.Path, session);
                using var runtime = await OpenOwnedAsync(inputs, source, session, control, ct);
                replay = await InvokeAsync(runtime, ct);
                if (replay.MethodReturned || replay.ActualHResult is null) { throw Invalid(); }
                string refusalPath = Directory.GetFiles(original.Binding.ArtifactRootCanonicalPath, "*-Company-storage-replay-refused.json").Single();
                var claim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(inputs.Files.Read(refusalPath, sharedReader: true, maximumBytes: 65536));
                var pin = inputs.Configuration.SigningPins;
                var refusal = CurrentAuthLocalSessionArchivePolicy.Verify<JsonElement>(claim, CompanyStorageRepairProtocol.ReceiptDomain, pin.ReceiptKeyId, pin.ReceiptFingerprint, inputs.Trust);
                if (refusal.GetProperty("ActualHResult").GetInt32() != replay.ActualHResult || refusal.GetProperty("MutationAttempted").GetBoolean() ||
                    refusal.GetProperty("IntentId").GetGuid() != inputs.Intent.IntentId) { throw Invalid(); }
                replayRefusal = CompanyStorageRepairProtocol.Hash(claim);
                var unchanged = await CaptureOwnedNativeAsync(session, contract, false, ct);
                if (unchanged.Sha256 != current.Sha256) { throw Invalid(); }
                RequireArtifacts(oldArtifacts, original.Binding.ArtifactRootCanonicalPath);
            }
            var forwardSource = await FreshSourceAsync(template, source.Plan.SourceCommitSha, ct);
            var forwardContract = ApprovedCustomerCompanyStorageRepair.Create(forwardSource.Plan.Databases.Single(x => x.Database == "Customer"), forwardSource.Plan.SourceCommitSha,
                forwardSource.Plan.SourceCommitSha, await OwnerAsync(template, ct), DateTimeOffset.UtcNow);
            var fresh = await CompanyStorageOwnedInputs.CreateAsync(session, template, forwardSource, forwardContract, Path.Combine(parent, "company-case-" + (int)@case + "-fresh"), ct); owned.Add(fresh);
            CompanyStorageActualInvocation forward; JsonElement forwardRun; CompanyStorageArtifact forwardRunArtifact;
            using (var inputs = CompanyStorageRepairInputs.OpenOwned(fresh.Path, session))
            using (var runtime = await OpenOwnedAsync(inputs, forwardSource, session, null, ct))
            {
                if (inputs.Intent.SchemaAlreadyCorrect != firstCommitted || inputs.Intent.IntentId == original.IntentId) { throw Invalid(); }
                forward = await InvokeAsync(runtime, ct); (forwardRun, forwardRunArtifact) = ReadRun(inputs, completed: true);
            }
            if (!forward.MethodReturned || forwardRun.GetProperty("RuntimeOperationCount").GetInt32() != (firstCommitted ? 0 : 1) ||
                forwardRun.GetProperty("Outcome").GetString() != (firstCommitted ? "SchemaAlreadyCorrectNoMutation" : "CommittedAndReadback")) { throw Invalid(); }
            var final = await CaptureOwnedNativeAsync(session, forwardContract, true, ct);
            if (firstCommitted) { if (final.Sha256 != current.Sha256) { throw Invalid(); } }
            else { CompanyStorageNativeWitness.RequirePreserved(fresh.Before, final, forwardContract); }
            RequireArtifacts(oldArtifacts, original.Binding.ArtifactRootCanonicalPath);
            RequireOwnedFleet(fresh, final, await session.Lease.CaptureFleetAsync(ct));
            result = new(@case, source, forwardSource, first, replay, forward, original.Before.Sha256, current.Sha256, final.Sha256,
                firstRunArtifact.Sha256, forwardRunArtifact.Sha256, control.PublicationDenials, control.PublicationHResult, control.DroppedCommits, replayRefusal,
                oldArtifacts, session.Lease.ContainerId, session.Lease.Volume, false, null);
        }
        catch (Exception failure) { primary = failure; }
        finally
        {
            try { if (control is not null) { await control.DisposeAsync(); } }
            catch (Exception failure) { cleanup = failure; }
            try { if (session is not null) { await session.DisposeAsync(); } }
            catch (Exception failure) { cleanup = cleanup is null ? failure : new AggregateException(cleanup, failure); }
            foreach (var configuration in owned)
            {
                try { CompanyStorageOwnedInputs.ClearSecrets(configuration); }
                catch (Exception failure) { cleanup = cleanup is null ? failure : new AggregateException(cleanup, failure); }
            }
        }
        if (cleanup is not null) { throw new AggregateException("Company fault/owned cleanup failed.", primary is null ? [cleanup] : [primary, cleanup]); }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
        return (result ?? throw Invalid()) with { CleanupVerified = true, ProxyCleanup = control?.ProxyCleanup };
    }

    private static async Task<ConsumerColumnBootstrapSourceCapture> FreshSourceAsync(CompanyStorageRepairInputs template, string accepted, CancellationToken ct)
    {
        var source = await ConsumerColumnBootstrapProofSourceCapture.CaptureAsync(template.Secret(template.Configuration.SourceCredential), template.Intent.SourceIdentitySha256, accepted, ct);
        return SourceCatalogDefinitionFingerprintV1.Compute(source.Plan, accepted, source.SourceIdentitySha256, DateTimeOffset.UtcNow) != template.Intent.SourceDefinitionSha256
            ? throw Invalid()
            : source;
    }
    private static async Task<CompanyStorageActualInvocation> InvokeAsync(CompanyStorageRuntime runtime, CancellationToken ct)
    {
        DateTimeOffset began = DateTimeOffset.UtcNow;
        try { await runtime.ExecuteAsync(ct); return new(true, null, null, began, DateTimeOffset.UtcNow); }
        catch (Exception failure) { return new(false, failure.GetType().FullName, failure.HResult, began, DateTimeOffset.UtcNow); }
    }
    private static async Task<CompanyStorageNativeWitness> CaptureOwnedNativeAsync(CompanyStorageOwnedSession session, ApprovedCustomerCompanyStorageRepair contract, bool after, CancellationToken ct)
    {
        await session.RequireAsync(ct); await using var connection = new NpgsqlConnection(session.Lease.ConnectionString); await connection.OpenAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await ReadOnlyAsync(connection, tx, ct);
        await RequirePolicyAsync(connection, tx, session.Lease.Maintenance, session.Lease.Target, ct);
        var witness = await CompanyStorageNativeWitness.CaptureAsync(connection, tx, contract, after, ct); await tx.RollbackAsync(ct); return witness;
    }
    private static void RequireRolledBack(CompanyStorageNativeWitness before, CompanyStorageNativeWitness after, CompanyStorageNativeWitness validatedCandidate)
    {
        if (before.Observation.After || after.Observation.After || !validatedCandidate.Observation.After ||
            before.Observation.ContractSha256 != after.Observation.ContractSha256 || before.Observation.ContractSha256 != validatedCandidate.Observation.ContractSha256 ||
            before.Observation.Native.Snapshot.Sha256 != after.Observation.Native.Snapshot.Sha256 || before.OwnerName != after.OwnerName ||
            !before.Heaps.OrderBy(x => x.Key, StringComparer.Ordinal).SequenceEqual(after.Heaps.OrderBy(x => x.Key, StringComparer.Ordinal))) { throw Invalid(); }
        foreach (string catalog in CompanyStorageRepairProtocol.CatalogNames)
        {
            if (!before.Observation.Native.Read(catalog).Select(x => x.ToJsonString()).Order(StringComparer.Ordinal)
                .SequenceEqual(after.Observation.Native.Read(catalog).Select(x => x.ToJsonString()).Order(StringComparer.Ordinal), StringComparer.Ordinal)) { throw Invalid(); }
        }
        var candidateIndexes = validatedCandidate.Observation.Native.Read("pg_index").Select(x => x["indexrelid"]!.ToString()).ToHashSet(StringComparer.Ordinal);
        foreach (var index in before.Observation.Native.Read("pg_index"))
        {
            string id = index["indexrelid"]!.ToString();
            var (FileNode, Blocks) = candidateIndexes.Contains(id) ? validatedCandidate.Observation.Native.Storage(id) : before.Observation.Native.Storage(id);
            var restored = after.Observation.Native.Storage(id);
            if (restored.FileNode != FileNode || restored.Blocks != Blocks) { throw Invalid(); }
        }
    }
    private static (JsonElement Value, CompanyStorageArtifact Artifact) ReadRun(CompanyStorageRepairInputs inputs, bool completed)
    {
        string path = Directory.GetFiles(inputs.Authority.Binding.ArtifactRootCanonicalPath, "*-Company-storage-run-" + (completed ? "completed" : "unfinished") + ".json").Single();
        byte[] bytes = inputs.Files.Read(path, sharedReader: true, maximumBytes: 65536);
        var claim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(bytes); var pin = inputs.Configuration.SigningPins;
        var run = CurrentAuthLocalSessionArchivePolicy.Verify<JsonElement>(claim, CompanyStorageRepairProtocol.ReceiptDomain, pin.ReceiptKeyId, pin.ReceiptFingerprint, inputs.Trust);
        Guid operation = run.GetProperty("OperationId").GetGuid(); string root = inputs.Authority.Binding.ArtifactRootCanonicalPath;
        string slot(string name)
        {
            return Path.Combine(root, $"{operation:D}-Company-storage-{name}.json");
        }

        var review = ReadClaim(slot("review"));
        var scope = CurrentAuthLocalSessionArchivePolicy.Verify<CompanyStorageRepairScope>(review, CompanyStorageRepairProtocol.ReviewDomain, pin.ReviewKeyId, pin.ReviewFingerprint, inputs.Trust);
        var authorizationClaim = ReadClaim(slot("authorization"));
        var authorization = CurrentAuthLocalSessionArchivePolicy.Verify<CompanyStorageRepairAuthorization>(authorizationClaim, CompanyStorageRepairProtocol.AuthorizationDomain,
            pin.AuthorizationKeyId, pin.AuthorizationFingerprint, inputs.Trust);
        string scopeHash = CompanyStorageRepairProtocol.Hash(scope), authHash = CompanyStorageRepairProtocol.Hash(authorizationClaim);
        var source = MigrationConsole.DecodeAuthRepair<ConsumerColumnBootstrapSourceCapture>(inputs.Files.Read(slot("source-capture"), sharedReader: true, maximumBytes: 32 * 1024 * 1024));
        using var code = CompanyStorageAcceptedCodeCustody.Acquire();
        DateTimeOffset observed = run.GetProperty("ObservedAtUtc").GetDateTimeOffset();
        if (run.EnumerateObject().Count() != 16 || run.GetProperty("Kind").GetString() != "current-company-storage-run-v1" ||
            run.GetProperty("Completed").GetBoolean() != completed || run.GetProperty("ProofOperationCount").GetInt32() != 1 ||
            scope.Kind != CompanyStorageRepairProtocol.OwnedScopeKind || scope.OperationId != operation || authorization.OperationId != operation ||
            authorization.ReviewSha256 != CompanyStorageRepairProtocol.Hash(review) || run.GetProperty("AuthorizationSha256").GetString() != authHash ||
            run.GetProperty("ScopeSha256").GetString() != scopeHash || scope.IntentSha256 != CompanyStorageRepairProtocol.Hash(inputs.IntentClaim) ||
            CompanyStorageRepairProtocol.Hash(scope.Intent) != CompanyStorageRepairProtocol.Hash(inputs.Intent) ||
            scope.ActualDisposableProofSha256 != run.GetProperty("ActualDisposableProofSha256").GetString() ||
            scope.RunnerDigestSha256 != code.RunnerDigestSha256 ||
            source.FullPlanSha256 != scope.FreshSourceFullSha256 || SchemaPlanCanonicalizer.ComputeSha256(source.Plan) != source.FullPlanSha256 ||
            SourceCatalogDefinitionFingerprintV1.Compute(source.Plan, scope.Intent.SourceCommitSha, scope.Intent.SourceIdentitySha256, scope.IssuedAtUtc) != scope.SourceDefinitionSha256 ||
            source.SourceIdentitySha256 != inputs.Intent.SourceIdentitySha256 || observed < source.BeganAtUtc || observed - source.BeganAtUtc > TimeSpan.FromMinutes(5) ||
            scope.IssuedAtUtc > observed || observed > scope.ExpiresAtUtc || authorization.IssuedAtUtc != scope.IssuedAtUtc || authorization.ExpiresAtUtc != scope.ExpiresAtUtc ||
            run.GetProperty("RuntimeOperationCount").GetInt32() != (inputs.Intent.SchemaAlreadyCorrect ? 0 : 1)) { throw Invalid(); }
        string proofPath = Directory.GetFiles(root, "*-Company-storage-disposable-proof.json").Single();
        byte[] proofBytes = inputs.Files.Read(proofPath, sharedReader: true, maximumBytes: 65536);
        var proof = CurrentAuthLocalSessionArchivePolicy.Verify<JsonElement>(MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(proofBytes), CompanyStorageRepairProtocol.ProofDomain,
            pin.ReceiptKeyId, pin.ReceiptFingerprint, inputs.Trust);
        if (CompanyStorageRepairProtocol.Hash(proofBytes) != scope.ActualDisposableProofSha256 || !proof.GetProperty("CleanupVerified").GetBoolean() ||
            !proof.GetProperty("IndependentCommittedReadback").GetBoolean() || !proof.GetProperty("RollbackReadback").GetBoolean() ||
            proof.GetProperty("SourceFullSha256").GetString() != source.FullPlanSha256 || proof.GetProperty("SourceDefinitionSha256").GetString() != scope.SourceDefinitionSha256 ||
            proof.GetProperty("CandidateSha256").GetString() != CompanyStorageRepairProtocol.CandidateSha256 ||
            proof.GetProperty("RunnerDigestSha256").GetString() != scope.RunnerDigestSha256 ||
            proof.GetProperty("SystemIdentifierSha256").GetString() == inputs.Intent.Target.SystemIdentifierSha256) { throw Invalid(); }
        string previous = new('0', 64);
        if (!inputs.Intent.SchemaAlreadyCorrect)
        {
            string prepared = slot("prepared");
            if (File.Exists(prepared) && new FileInfo(prepared).Length > 0) { previous = CheckReceipt(prepared, CurrentAppOwnedCommitClassification.Prepared, previous); }
            if (completed)
            { previous = CheckReceipt(slot("committed-readback"), CurrentAppOwnedCommitClassification.CommittedAndReadback, previous); }
            else
            {
                var failedClaim = ReadClaim(slot("failed-or-uncertain"));
                var failed = CurrentAuthLocalSessionArchivePolicy.Verify<CompanyStorageRepairReceipt>(failedClaim, CompanyStorageRepairProtocol.ReceiptDomain,
                    pin.ReceiptKeyId, pin.ReceiptFingerprint, inputs.Trust);
                var expected = run.GetProperty("CommitStarted").GetBoolean() ? CurrentAppOwnedCommitClassification.Uncertain : CurrentAppOwnedCommitClassification.RolledBackBeforeCommit;
                previous = CheckReceipt(slot("failed-or-uncertain"), expected, previous);
                if (failed.Classification != expected) { throw Invalid(); }
            }
        }
        return run.GetProperty("PreviousSha256").GetString() != previous
            ? throw Invalid()
            : ((JsonElement Value, CompanyStorageArtifact Artifact))(run, new(path, CompanyStorageRepairProtocol.Hash(bytes)));
        CurrentAuthArchiveClaim ReadClaim(string file)
        {
            return MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(inputs.Files.Read(file, sharedReader: true, maximumBytes: 65536));
        }

        string CheckReceipt(string file, CurrentAppOwnedCommitClassification classification, string parent)
        {
            var signed = ReadClaim(file); var receipt = CurrentAuthLocalSessionArchivePolicy.Verify<CompanyStorageRepairReceipt>(signed, CompanyStorageRepairProtocol.ReceiptDomain,
                pin.ReceiptKeyId, pin.ReceiptFingerprint, inputs.Trust);
            return receipt.Kind != "current-company-storage-receipt-v1" || receipt.OperationId != operation || receipt.ScopeSha256 != scopeHash ||
                receipt.AuthorizationSha256 != authHash || receipt.PreviousSha256 != parent || receipt.BeforeNativeSha256 != inputs.Intent.NativePreimageSha256 ||
                receipt.ActualDisposableProofSha256 != scope.ActualDisposableProofSha256 || receipt.Classification != classification ||
                receipt.ObservedAtUtc < scope.IssuedAtUtc || receipt.ObservedAtUtc > observed
                ? throw Invalid()
                : CompanyStorageRepairProtocol.Hash(signed);
        }
    }
    private static Dictionary<string, string> ArtifactHashes(string root)
    {
        return Directory.GetFiles(root, "*.json", SearchOption.TopDirectoryOnly)
        .ToDictionary(x => Path.GetFileName(x), CurrentAuthTypedHostProducer.ImageHash, StringComparer.Ordinal);
    }

    private static void RequireArtifacts(IReadOnlyDictionary<string, string> expected, string root)
    { if (expected.Any(x => CurrentAuthTypedHostProducer.ImageHash(Path.Combine(root, x.Key)) != x.Value)) { throw Invalid(); } }
    private static void RequireOwnedFleet(CompanyStorageOwnedConfiguration before, CompanyStorageNativeWitness after, IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> actual)
    {
        if (actual.Count != before.BeforeDatabaseSha256.Count || actual.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != actual.Count ||
            actual.Any(x => !before.BeforeDatabaseSha256.TryGetValue(x.Database, out string? expected) || x.Sha256 != (x.Database == "Customer" ? after.Observation.Native.Snapshot.Sha256 : expected))) { throw Invalid(); }
    }
}
