using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record SourceOrderOwnerIsoFaultConfiguration(string TemplateConfigurationPath, string SuiteRoot);
internal sealed record SourceOrderOwnerIsoInvocation(bool Returned, string? ExceptionType, int? HResult, DateTimeOffset BeganAtUtc, DateTimeOffset EndedAtUtc);

internal sealed partial class SourceOrderOwnerIsoRuntime
{
    private static readonly SourceOrderOwnerIsoFaultCase[] FaultCases = [SourceOrderOwnerIsoFaultCase.PreparedPublication,
        SourceOrderOwnerIsoFaultCase.LostCommitAcknowledgement, SourceOrderOwnerIsoFaultCase.TerminalPublication,
        SourceOrderOwnerIsoFaultCase.PartialSecondDatabase, SourceOrderOwnerIsoFaultCase.FinalFleet];
    internal static async Task RunNativeFaultsAsync(SourceOrderOwnerIsoFaultConfiguration config, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly ||
            !Path.IsPathFullyQualified(config.SuiteRoot) || Directory.Exists(config.SuiteRoot)) { throw Invalid(); }
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct); CurrentAuthRepairCapacity.Require(admission: true);
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct); limit.CancelAfter(TimeSpan.FromMinutes(45)); ct = limit.Token;
        using var template = SourceOrderOwnerIsoInputs.Open(config.TemplateConfigurationPath);
        if (template.Intent.SourceCommitSha != accepted) { throw Invalid(); }
        SecureSnapshotFileCreation.CreateRestrictedDirectory(config.SuiteRoot);
        using var authority = WindowsLocalRunAuthority.AcquireFresh(config.SuiteRoot); using var files = new CurrentAppOwnedRepairCustody(authority);
        var results = new List<object>();
        foreach (var fault in FaultCases) { results.Add(await NativeCaseAsync(fault, template, config.SuiteRoot, accepted, ct)); }
        using var code = CompanyStorageAcceptedCodeCustody.Acquire(); var pin = template.Configuration.SigningPins;
        using var signer = template.Signer(template.Configuration.EvidencePrivateKey, pin.ReceiptKeyId, pin.ReceiptFingerprint);
        using var process = System.Diagnostics.Process.GetCurrentProcess();
        await files.WriteNewAsync(Path.Combine(config.SuiteRoot, "five-actual-source-order-iso-faults.json"), JsonSerializer.SerializeToUtf8Bytes(
            CurrentAuthLocalSessionArchivePolicy.Sign("Legacy.Maliev.SourceOrderOwnerIso.FiveActualFaults.v1", new
            {
                Kind = "source-order-iso-five-actual-owned-faults-v1",
                SourceCommitSha = accepted,
                code.RunnerDigestSha256,
                Results = results,
                ProcessId = process.Id,
                ProcessStartedAtUtc = process.StartTime.ToUniversalTime(),
                ExecutableSha256 = CurrentAuthTypedHostProducer.ImageHash(Environment.ProcessPath!),
                ActualMethod = "accepted Console same-process fixed owned runtime",
                OperatingSystemChildExitCode = (int?)null,
                PositiveAcceptanceToken = false,
                CompletedAtUtc = DateTimeOffset.UtcNow,
            }, signer)), ct);
    }
    private static async Task<object> NativeCaseAsync(SourceOrderOwnerIsoFaultCase fault, SourceOrderOwnerIsoInputs template,
        string parent, string accepted, CancellationToken ct)
    {
        SourceOrderOwnerIsoOwnedSession? session = null; SourceOrderOwnerIsoFaultControl? control = null;
        var configs = new List<SourceOrderOwnerIsoOwnedConfiguration>(); object? result = null; Exception? primary = null, cleanup = null;
        try
        {
            var source = await FreshSourceAsync(template, accepted, ct); var owners = await OwnersAsync(template, ct);
            var contract = SourceOrderOwnerIsoContract.Create(source.Plan, accepted, template.Intent.CompanyAlreadyApplied, owners, DateTimeOffset.UtcNow);
            session = await SourceOrderOwnerIsoOwnedSession.CreateAsync(template, source, parent, ct);
            var original = await SourceOrderOwnerIsoOwnedIssuer.CreateAsync(session, template, source, contract, owners,
                Path.Combine(parent, "iso-case-" + (int)fault + "-original"), ct); configs.Add(original);
            if (original.Selected.Values.Any(x => x)) { throw Invalid(); }
            control = await SourceOrderOwnerIsoFaultControl.CreateAsync(session, fault, original, ct);
            SourceOrderOwnerIsoInvocation first; CompanyStorageArtifact firstRun;
            using (var input = SourceOrderOwnerIsoInputs.OpenOwned(original.Path, session))
            using (var runtime = await OpenOwnedAsync(input, source, session, control, ct))
            {
                first = await InvokeAsync(runtime, ct); firstRun = ReadRun(input, false);
            }
            if (first.Returned || (fault is SourceOrderOwnerIsoFaultCase.PreparedPublication or SourceOrderOwnerIsoFaultCase.TerminalPublication or SourceOrderOwnerIsoFaultCase.PartialSecondDatabase &&
                control.PublicationDenials != 1) || (fault == SourceOrderOwnerIsoFaultCase.LostCommitAcknowledgement && control.DroppedCommits != 1)) { throw Invalid(); }
            var selected = SourceOrderOwnerIsoProtocol.Databases.ToDictionary(x => x,
                x => fault == SourceOrderOwnerIsoFaultCase.FinalFleet || (x == "Country" && fault != SourceOrderOwnerIsoFaultCase.PreparedPublication), StringComparer.Ordinal);
            var current = new Dictionary<string, SourceOrderOwnerIsoNativeWitness>(StringComparer.Ordinal);
            foreach (string database in SourceOrderOwnerIsoProtocol.Databases)
            {
                var witness = await CaptureOwnedAsync(session, contract, database, selected[database], ct); current.Add(database, witness);
                if (selected[database]) { SourceOrderOwnerIsoNativeWitness.RequirePreserved(original.Native[database], witness, contract); }
                else { RequireExactRollback(original.Native[database], witness); }
            }
            var firstFleet = await session.Lease.CaptureFleetAsync(ct);
            var expectedFleet = original.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
            if (fault == SourceOrderOwnerIsoFaultCase.FinalFleet)
            {
                var before = control.UploadBefore ?? throw Invalid(); var after = control.UploadAfter ?? throw Invalid();
                ConsumerColumnBootstrapUploadFaultPreservation.Require(before, after, 1);
                if (before.Snapshot.Sha256 != original.BeforeDatabaseSha256["Upload"]) { throw Invalid(); }
                expectedFleet["Upload"] = after.Snapshot.Sha256;
            }
            RequireOwnedFleet(expectedFleet, current, firstFleet); control.ReleaseDenial();
            var retained = Artifacts(original.Binding.ArtifactRootCanonicalPath); SourceOrderOwnerIsoInvocation replay;
            using (var input = SourceOrderOwnerIsoInputs.OpenOwned(original.Path, session))
            using (var runtime = await OpenOwnedAsync(input, source, session, control, ct))
            {
                replay = await InvokeAsync(runtime, ct);
                if (replay.Returned || replay.HResult is null) { throw Invalid(); }
                string path = Directory.GetFiles(original.Binding.ArtifactRootCanonicalPath, "*-SourceOrderIso-replay-refused.json").Single();
                var pin = input.Configuration.SigningPins;
                var claim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(input.Files.Read(path, sharedReader: true, maximumBytes: 65536));
                var refusal = CurrentAuthLocalSessionArchivePolicy.Verify<JsonElement>(claim, SourceOrderOwnerIsoProtocol.ReceiptDomain, pin.ReceiptKeyId, pin.ReceiptFingerprint, input.Trust);
                if (refusal.GetProperty("IntentId").GetGuid() != original.IntentId || refusal.GetProperty("MutationAttempted").GetBoolean() ||
                    refusal.GetProperty("HResult").GetInt32() != replay.HResult) { throw Invalid(); }
            }
            foreach (string database in SourceOrderOwnerIsoProtocol.Databases)
            { if ((await CaptureOwnedAsync(session, contract, database, selected[database], ct)).Sha256 != current[database].Sha256) { throw Invalid(); } }
            var freshSource = await FreshSourceAsync(template, accepted, ct); var freshOwners = await OwnersAsync(template, ct);
            var freshContract = SourceOrderOwnerIsoContract.Create(freshSource.Plan, accepted, template.Intent.CompanyAlreadyApplied, freshOwners, DateTimeOffset.UtcNow);
            var fresh = await SourceOrderOwnerIsoOwnedIssuer.CreateAsync(session, template, freshSource, freshContract, freshOwners,
                Path.Combine(parent, "iso-case-" + (int)fault + "-forward"), ct); configs.Add(fresh);
            if (fresh.IntentId == original.IntentId || fresh.Selected.Any(x => x.Value != selected[x.Key])) { throw Invalid(); }
            SourceOrderOwnerIsoInvocation forward; CompanyStorageArtifact forwardRun;
            using (var input = SourceOrderOwnerIsoInputs.OpenOwned(fresh.Path, session))
            using (var runtime = await OpenOwnedAsync(input, freshSource, session, null, ct))
            { forward = await InvokeAsync(runtime, ct); if (!forward.Returned) { throw Invalid(); } forwardRun = ReadRun(input, true); }
            var final = new Dictionary<string, SourceOrderOwnerIsoNativeWitness>(StringComparer.Ordinal);
            foreach (string database in SourceOrderOwnerIsoProtocol.Databases)
            {
                var witness = await CaptureOwnedAsync(session, freshContract, database, true, ct); final.Add(database, witness);
                if (selected[database]) { if (witness.Sha256 != current[database].Sha256) { throw Invalid(); } }
                else { SourceOrderOwnerIsoNativeWitness.RequirePreserved(fresh.Native[database], witness, freshContract); }
            }
            RequireOwnedFleet(fresh.BeforeDatabaseSha256, final, await session.Lease.CaptureFleetAsync(ct));
            if (retained.Any(x => CurrentAuthTypedHostProducer.ImageHash(Path.Combine(original.Binding.ArtifactRootCanonicalPath, x.Key)) != x.Value)) { throw Invalid(); }
            result = new
            {
                Case = fault,
                FirstSource = source,
                ForwardSource = freshSource,
                First = first,
                Replay = replay,
                Forward = forward,
                FirstRun = firstRun.Sha256,
                ForwardRun = forwardRun.Sha256,
                BeforeNative = original.Native.ToDictionary(x => x.Key, x => x.Value.Sha256, StringComparer.Ordinal),
                AfterFirstNative = current.ToDictionary(x => x.Key, x => x.Value.Sha256, StringComparer.Ordinal),
                AfterForwardNative = final.ToDictionary(x => x.Key, x => x.Value.Sha256, StringComparer.Ordinal),
                RetainedOriginalArtifacts = retained,
                RuntimeForwardOperations = selected.Count(x => !x.Value),
                ProofOperations = 2,
                control.PublicationDenials,
                control.PublicationHResult,
                control.DroppedCommits,
                session.Lease.ContainerId,
                session.Lease.Volume,
            };
        }
        catch (Exception failure) { primary = failure; }
        finally
        {
            try { if (control is not null) { await control.DisposeAsync(); } } catch (Exception failure) { cleanup = failure; }
            try { if (session is not null) { await session.DisposeAsync(); } } catch (Exception failure) { cleanup = cleanup is null ? failure : new AggregateException(cleanup, failure); }
            foreach (var item in configs)
            { try { SourceOrderOwnerIsoOwnedIssuer.ClearSecrets(item); } catch (Exception failure) { cleanup = cleanup is null ? failure : new AggregateException(cleanup, failure); } }
        }
        if (cleanup is not null) { throw new AggregateException("Source-order ISO owned cleanup failed.", primary is null ? [cleanup] : [primary, cleanup]); }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
        return new { Facts = result ?? throw Invalid(), CleanupVerified = true, control?.ProxyCleanup };
    }
    private static async Task<ConsumerColumnBootstrapSourceCapture> FreshSourceAsync(SourceOrderOwnerIsoInputs input, string accepted, CancellationToken ct)
    {
        var source = await ConsumerColumnBootstrapProofSourceCapture.CaptureAsync(input.Secret(input.Configuration.SourceCredential), input.Intent.SourceIdentitySha256, accepted, ct);
        return SourceCatalogDefinitionFingerprintV1.Compute(source.Plan, accepted, source.SourceIdentitySha256, DateTimeOffset.UtcNow) != input.Intent.SourceDefinitionSha256
            ? throw Invalid()
            : source;
    }
    private static async Task<SourceOrderOwnerIsoInvocation> InvokeAsync(SourceOrderOwnerIsoRuntime runtime, CancellationToken ct)
    {
        DateTimeOffset began = DateTimeOffset.UtcNow;
        try { await runtime.ExecuteAsync(ct); return new(true, null, null, began, DateTimeOffset.UtcNow); }
        catch (Exception failure) { return new(false, failure.GetType().FullName, failure.HResult, began, DateTimeOffset.UtcNow); }
    }
    private static Dictionary<string, string> Artifacts(string root)
    {
        return Directory.GetFiles(root, "*.json")
        .ToDictionary(x => Path.GetFileName(x), CurrentAuthTypedHostProducer.ImageHash, StringComparer.Ordinal);
    }
}
