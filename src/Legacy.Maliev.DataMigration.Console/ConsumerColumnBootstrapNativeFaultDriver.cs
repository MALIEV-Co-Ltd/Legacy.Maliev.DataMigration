using System.Data;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record ConsumerColumnBootstrapNativeFaultConfiguration(string SourceConnectionPath, string ExpectedSourceIdentitySha256, string SuiteRoot);
internal sealed record ConsumerColumnBootstrapActualInvocation(int? ReturnCode, string? ExceptionType, DateTimeOffset BeganAtUtc, DateTimeOffset EndedAtUtc);
internal sealed record ConsumerColumnBootstrapNativeFaultResult(ConsumerColumnBootstrapNativeFaultCase Case, Guid OperationId,
    ConsumerColumnBootstrapSourceCapture Source, ConsumerColumnBootstrapActualInvocation FirstApply, ConsumerColumnBootstrapActualInvocation? Replay,
    ConsumerColumnBootstrapActualInvocation? Forward, int PublicationDenials, int PublicationHResult, int ReservationDenials, int ReservationHResult,
    int DroppedCommitAcknowledgements, bool ActualFinalFleetMutation, ConsumerColumnBootstrapOperationalRunReceipt Unfinished,
    ConsumerColumnBootstrapOperationalRunReceipt? ForwardCompleted, IReadOnlyDictionary<string, string> AfterFirstFleet,
    IReadOnlyDictionary<string, string>? AfterForwardFleet, ConsumerColumnBootstrapCleanupEvidence Cleanup, int? ProxyPort, bool ProxyAbsent)
{
    public ConsumerColumnBootstrapProxyCleanup? ProxyCleanup { get; init; }
}

internal static partial class ConsumerColumnBootstrapRehearsalProducer
{
    private static readonly string[] FaultPreparationSteps = ["review-consumer-column-bootstrap-proof", "authorize-consumer-column-bootstrap-proof"];
    private static readonly ConsumerColumnBootstrapNativeFaultCase[] FaultCases =
        [ConsumerColumnBootstrapNativeFaultCase.PreparedPublication, ConsumerColumnBootstrapNativeFaultCase.LostCommitAcknowledgement,
         ConsumerColumnBootstrapNativeFaultCase.TerminalPublication, ConsumerColumnBootstrapNativeFaultCase.PartialThenForwardRecovery, ConsumerColumnBootstrapNativeFaultCase.FinalFleet];

    internal static async Task RunNativeFaultSuiteAsync(ConsumerColumnBootstrapNativeFaultConfiguration config, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || System.Reflection.Assembly.GetEntryAssembly() != typeof(ConsumerColumnBootstrapRehearsalProducer).Assembly ||
            !Path.IsPathFullyQualified(config.SuiteRoot) || Directory.Exists(config.SuiteRoot)) { throw Invalid(); }
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        CurrentAuthRepairCapacity.Require(admission: true);
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct); lifetime.CancelAfter(TimeSpan.FromMinutes(45)); ct = lifetime.Token;
        using var held = SecureLocalFile.OpenReadShared(config.SourceConnectionPath);
        if (held.Length is < 1 or > 65536) { throw Invalid(); }
        using var reader = new StreamReader(held, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        string sourceConnection = await reader.ReadToEndAsync(ct).ConfigureAwait(false);
        SecureLocalFile.EnsureOwnerOnlyDirectory(config.SuiteRoot);
        using var suiteAuthority = WindowsLocalRunAuthority.AcquireFresh(config.SuiteRoot);
        using var suiteFiles = new CurrentAppOwnedRepairCustody(suiteAuthority);
        var results = new List<ConsumerColumnBootstrapNativeFaultResult>();
        foreach (var @case in FaultCases)
        {
            // Each case has its own actual source windows and resource/receipt roots. No
            // assertion of an atomic source capture across the suite is made.
            var source = await ConsumerColumnBootstrapProofSourceCapture.CaptureAsync(sourceConnection, config.ExpectedSourceIdentitySha256, accepted, ct).ConfigureAwait(false);
            results.Add(await RunNativeFaultCaseAsync(@case, source, config.SuiteRoot, ct).ConfigureAwait(false));
        }
        if (results.Count != 5 || !results.Select(result => result.Case).SequenceEqual(FaultCases)) { throw Invalid(); }
        if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != accepted) { throw Invalid(); }
        using var code = ConsumerColumnBootstrapAcceptedCodeCustody.Acquire(typeof(ConsumerColumnBootstrapOperationalEnvironment), TimeProvider.System);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            Kind = "consumer-column-bootstrap-five-actual-native-faults-v1",
            SourceCommitSha = accepted,
            code.RunnerDigestSha256,
            Cohort = ConsumerColumnBootstrapProofCohort.PostgreSql184,
            Results = results,
            CompletedAtUtc = DateTimeOffset.UtcNow,
            PositiveRehearsalAcceptance = false,
        });
        using var signing = new SignerMaterial("bootstrap-native-fault-suite-");
        await suiteFiles.WriteNewAsync(Path.Combine(config.SuiteRoot, "native-fault-suite.json"), bytes, ct).ConfigureAwait(false);
        await suiteFiles.WriteNewAsync(Path.Combine(config.SuiteRoot, "native-fault-suite-attestation.json"), JsonSerializer.SerializeToUtf8Bytes(new
        {
            Kind = "consumer-column-bootstrap-native-fault-suite-attestation-v1",
            signing.Signer.KeyId,
            signing.Signer.PublicKeyFingerprintSha256,
            PublicKey = Convert.ToBase64String(signing.Signer.ExportSubjectPublicKeyInfo()),
            EvidenceSha256 = ConsumerColumnBootstrapOperationalContract.Hash(bytes),
            Signature = Convert.ToBase64String(signing.Signer.Sign([.. "Legacy.Maliev.ConsumerColumnBootstrap.NativeFaultSuite.v1\0"u8, .. bytes])),
        }), ct).ConfigureAwait(false);
    }

    private static async Task<ConsumerColumnBootstrapNativeFaultResult> RunNativeFaultCaseAsync(ConsumerColumnBootstrapNativeFaultCase @case,
        ConsumerColumnBootstrapSourceCapture source, string suiteRoot, CancellationToken ct)
    {
        string issuerRoot = Path.Combine(suiteRoot, "case-" + (int)@case + "-issuer"), executionRoot = Path.Combine(suiteRoot, "case-" + (int)@case + "-execution");
        SecureLocalFile.EnsureOwnerOnlyDirectory(issuerRoot); SecureLocalFile.EnsureOwnerOnlyDirectory(executionRoot);
        using var issuer = WindowsLocalRunAuthority.AcquireFresh(issuerRoot); using var issuerFiles = new CurrentAppOwnedRepairCustody(issuer);
        LocalExecutionBinding binding;
        using (var execution = WindowsLocalRunAuthority.AcquireFresh(executionRoot)) { binding = execution.Binding; }
        Guid operation = Guid.NewGuid();
        using var review = new SignerMaterial("native-fault-review-"); using var authorization = new SignerMaterial("native-fault-authorization-"); using var receipt = new SignerMaterial("native-fault-receipt-");
        var keys = new Keys(review, authorization, receipt);
        var fixture = await ConsumerColumnBootstrapProofFixture.CreateAsync(operation, ConsumerColumnBootstrapProofCohort.PostgreSql184,
            issuer, binding, issuerFiles, source, source.SourceIdentitySha256, source.Plan.SourceCommitSha, ct).ConfigureAwait(false);
        ConsumerColumnBootstrapNativeFaultControl? control = null; Exception? primary = null, cleanup = null;
        var directReadbacks = new List<ConsumerColumnBootstrapNativeWitness>();
        ConsumerColumnBootstrapUploadFaultWitness? uploadReadback = null;
        var forwardSecrets = new List<(string Path, string Identity)>();
        ConsumerColumnBootstrapNativeFaultResult? result = null;
        try
        {
            var config = await PrepareAsync(fixture, source, binding, keys, ct).ConfigureAwait(false);
            string configPath = Path.Combine(executionRoot, "configuration.json");
            var scope = ReadFault<ConsumerColumnBootstrapOperationalScope>(binding, config.ScopePath);
            string op = ReadFaultSecret(binding, config.OperatorConnectionPath);
            using (var execution = WindowsLocalRunAuthority.AcquireResume(executionRoot, binding))
            using (var files = new CurrentAppOwnedRepairCustody(execution))
            { control = await ConsumerColumnBootstrapNativeFaultControl.CreateAsync(fixture, @case, files, executionRoot, ct).ConfigureAwait(false); }
            fixture.BindFaultOperator(op);
            await PrepareFaultClaimsAsync(configPath, fixture, ct).ConfigureAwait(false);
            var first = await InvokeFaultApplyAsync(configPath, fixture, ct).ConfigureAwait(false);
            if (first.ReturnCode == 0) { throw Invalid(); }
            var run = ReadFault<ConsumerColumnBootstrapOperationalRunReceipt>(binding, Path.Combine(executionRoot, $"consumer-bootstrap-{operation:N}-run-unfinished.json"));
            RequireFaultRun(run, scope, keys, completed: false);
            var contract = ConsumerColumnBootstrapContract.Create(source.Plan, source.Plan.SourceCommitSha, DateTimeOffset.UtcNow);
            var actual = await CaptureFaultFleetAsync(op, scope, ct).ConfigureAwait(false);
            string[] changed = @case == ConsumerColumnBootstrapNativeFaultCase.PreparedPublication ? [] :
                @case == ConsumerColumnBootstrapNativeFaultCase.FinalFleet ? ["CustomerIdentity", "Quotation"] : ["CustomerIdentity"];
            foreach (string database in scope.BeforeDatabaseSha256.Keys)
            {
                if (changed.Contains(database, StringComparer.Ordinal))
                {
                    var before = control.Observation(operation, database, ConsumerColumnBootstrapNativePhase.LockedBefore);
                    var after = await CaptureFaultOperandAsync(op, contract, database, after: true, ct).ConfigureAwait(false);
                    ConsumerColumnBootstrapNativePreservation.RequirePreserved(before, after, contract);
                    directReadbacks.Add(ConsumerColumnBootstrapNativeWitness.Capture(ConsumerColumnBootstrapNativePhase.IndependentReadback, after));
                    if (actual[database] != after.Native.Snapshot.Sha256) { throw Invalid(); }
                }
                else if (@case == ConsumerColumnBootstrapNativeFaultCase.FinalFleet && database == "Upload")
                {
                    var uploadBefore = control.UploadBefore ?? throw Invalid(); var uploadAfter = control.UploadAfter ?? throw Invalid();
                    if (uploadBefore.Snapshot.Sha256 != scope.BeforeDatabaseSha256["Upload"] || uploadAfter.Snapshot.Sha256 != actual["Upload"]) { throw Invalid(); }
                    ConsumerColumnBootstrapUploadFaultPreservation.Require(uploadBefore, uploadAfter, control.FinalFleetAffectedRows);
                    uploadReadback = await CaptureFaultUploadAsync(op, ct).ConfigureAwait(false);
                    ConsumerColumnBootstrapUploadFaultPreservation.Require(uploadBefore, uploadReadback, control.FinalFleetAffectedRows);
                    if (uploadReadback.Snapshot.Sha256 != actual["Upload"]) { throw Invalid(); }
                }
                else if (actual[database] != scope.BeforeDatabaseSha256[database]) { throw Invalid(); }
            }
            int acknowledged = @case is ConsumerColumnBootstrapNativeFaultCase.PartialThenForwardRecovery ? 1 : @case == ConsumerColumnBootstrapNativeFaultCase.FinalFleet ? 2 : 0;
            int independentlyVerified = @case == ConsumerColumnBootstrapNativeFaultCase.TerminalPublication ? 1 : acknowledged;
            if (run.CommittedDatabaseSha256.Count != acknowledged || run.IndependentlyVerifiedReadbackSha256.Count != independentlyVerified) { throw Invalid(); }
            if (@case == ConsumerColumnBootstrapNativeFaultCase.LostCommitAcknowledgement ? control.DroppedCommits != 1 :
                @case == ConsumerColumnBootstrapNativeFaultCase.FinalFleet ? !control.FinalFleetMutationExecuted || actual["Upload"] == scope.BeforeDatabaseSha256["Upload"] : control.PublicationDenials != 1)
            { throw Invalid(); }
            if (@case != ConsumerColumnBootstrapNativeFaultCase.FinalFleet)
            {
                string failedDatabase = @case == ConsumerColumnBootstrapNativeFaultCase.PartialThenForwardRecovery ? "Quotation" : "CustomerIdentity";
                var failed = ReadFault<ConsumerColumnBootstrapOperationalReceipt>(binding, Path.Combine(executionRoot, $"consumer-bootstrap-{operation:N}-{failedDatabase}-failed-or-uncertain.json"));
                var expected = @case is ConsumerColumnBootstrapNativeFaultCase.PreparedPublication or ConsumerColumnBootstrapNativeFaultCase.PartialThenForwardRecovery
                    ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.Uncertain;
                if (failed.Classification != expected) { throw Invalid(); }
                RequireFaultSignature(failed.KeyId, failed.Signature, PostgreSqlConsumerColumnBootstrapRepair.ReceiptPayload(failed), keys);
            }
            ConsumerColumnBootstrapActualInvocation? replay = null, forward = null; ConsumerColumnBootstrapOperationalRunReceipt? forwardRun = null;
            IReadOnlyDictionary<string, string>? afterForward = null;
            if (@case == ConsumerColumnBootstrapNativeFaultCase.PreparedPublication)
            {
                // New Console invocation constructs a NEW environment and permit from the same
                // old signed claims. Its unchanged physical baseline reaches the durable reserve.
                control.ReleasePublicationDenial(); var beforeReplay = await CaptureFaultFleetAsync(op, scope, ct).ConfigureAwait(false);
                string reservationPath = Path.Combine(executionRoot, $"consumer-bootstrap-{operation:N}-execution-reservation.json");
                string reservationHash = ConsumerColumnBootstrapOperationalContract.Hash(ReadFaultBytes(binding, reservationPath));
                replay = await InvokeFaultApplyAsync(configPath, fixture, ct).ConfigureAwait(false);
                if (replay.ReturnCode == 0 || control.ReservationDenials != 1 || (control.LastReservationHResult & 0xffff) is not (80 or 183) ||
                    ConsumerColumnBootstrapOperationalContract.Hash(ReadFaultBytes(binding, reservationPath)) != reservationHash ||
                    !SameFleet(beforeReplay, await CaptureFaultFleetAsync(op, scope, ct).ConfigureAwait(false))) { throw Invalid(); }
            }
            else if (@case == ConsumerColumnBootstrapNativeFaultCase.PartialThenForwardRecovery)
            {
                control.ReleasePublicationDenial();
                var originals = CaptureOldFaultArtifacts(binding, operation);
                replay = await InvokeFaultApplyAsync(configPath, fixture, ct).ConfigureAwait(false);
                if (replay.ReturnCode == 0 || !SameFleet(actual, await CaptureFaultFleetAsync(op, scope, ct).ConfigureAwait(false))) { throw Invalid(); }
                var completedBefore = await CaptureFaultOperandAsync(op, contract, "CustomerIdentity", true, ct).ConfigureAwait(false);
                directReadbacks.Add(ConsumerColumnBootstrapNativeWitness.Capture(ConsumerColumnBootstrapNativePhase.IndependentReadback, completedBefore));
                var forwardConfig = await PrepareFaultForwardAsync(fixture, control, source, binding, config, actual, forwardSecrets, ct).ConfigureAwait(false);
                await PrepareFaultClaimsAsync(forwardConfig, fixture, ct).ConfigureAwait(false);
                forward = await InvokeFaultApplyAsync(forwardConfig, fixture, ct).ConfigureAwait(false);
                if (forward.ReturnCode != 0 || forward.ExceptionType is not null) { throw Invalid(); }
                var forwardConfiguration = ReadFault<ConsumerColumnBootstrapOperationalConfiguration>(binding, forwardConfig);
                var forwardScope = ReadFault<ConsumerColumnBootstrapOperationalScope>(binding, forwardConfiguration.ScopePath);
                forwardRun = ReadFault<ConsumerColumnBootstrapOperationalRunReceipt>(binding, Path.Combine(executionRoot, $"consumer-bootstrap-{forwardScope.OperationId:N}-run-completed.json"));
                // Forward keys are retained as public material in the new configuration; the
                // real publisher already verifies every signature against those distinct pins.
                if (!forwardRun.Completed || forwardRun.CommittedDatabaseSha256.Count != 1 || !forwardRun.CommittedDatabaseSha256.ContainsKey("Quotation") ||
                    forwardScope.Mode != ConsumerColumnBootstrapOperationalMode.OwnedForwardRecoveryCharacterization || forwardScope.PendingDatabases.Count != 1)
                { throw Invalid(); }
                afterForward = await CaptureFaultFleetAsync(op, forwardScope, ct).ConfigureAwait(false);
                foreach (string database in actual.Keys.Where(database => database != "Quotation")) { if (actual[database] != afterForward[database]) { throw Invalid(); } }
                var completedAfter = await CaptureFaultOperandAsync(op, contract, "CustomerIdentity", true, ct).ConfigureAwait(false);
                directReadbacks.Add(ConsumerColumnBootstrapNativeWitness.Capture(ConsumerColumnBootstrapNativePhase.IndependentReadback, completedAfter));
                if (FaultPhysicalHash(completedBefore) != FaultPhysicalHash(completedAfter)) { throw Invalid(); }
                var quotationBefore = control.Observation(forwardScope.OperationId, "Quotation", ConsumerColumnBootstrapNativePhase.LockedBefore);
                var quotationAfter = await CaptureFaultOperandAsync(op, contract, "Quotation", true, ct).ConfigureAwait(false);
                ConsumerColumnBootstrapNativePreservation.RequirePreserved(quotationBefore, quotationAfter, contract);
                directReadbacks.Add(ConsumerColumnBootstrapNativeWitness.Capture(ConsumerColumnBootstrapNativePhase.IndependentReadback, quotationAfter));
                foreach (var artifact in originals) { if (ConsumerColumnBootstrapOperationalContract.Hash(ReadFaultBytes(binding, artifact.Key)) != artifact.Value) { throw Invalid(); } }
            }
            result = new(@case, operation, source, first, replay, forward, control.PublicationDenials, control.LastPublicationHResult,
                control.ReservationDenials, control.LastReservationHResult, control.DroppedCommits, control.FinalFleetMutationExecuted,
                run, forwardRun, actual, afterForward, null!, control.ProxyPort, false);
            // Retain the full measured metadata before deleting the disposable storage. This
            // stage deliberately is not a completed cleanup receipt or positive rehearsal.
            await issuerFiles.WriteNewAsync(Path.Combine(issuerRoot, "measured-before-cleanup.json"), JsonSerializer.SerializeToUtf8Bytes(new
            {
                Kind = "consumer-bootstrap-fault-measured-stage-not-proof-v1",
                Result = result,
                Native = control.RetainedNativeFacts(),
                DirectReadbacks = directReadbacks,
                control.UploadBefore,
                control.UploadAfter,
                UploadReadback = uploadReadback,
                control.FinalFleetAffectedRows,
                keys.PublicKeys,
                SigningPins = keys.Pins,
                CleanupObserved = false,
                PositiveRehearsalAcceptance = false
            }), ct).ConfigureAwait(false);
        }
        catch (Exception failure) { primary = failure; }
        finally
        {
            try { if (control is not null) { await control.DisposeAsync().ConfigureAwait(false); } } catch (Exception failure) { cleanup = failure; }
            try { await fixture.DisposeAsync().ConfigureAwait(false); } catch (Exception failure) { cleanup = cleanup is null ? failure : new AggregateException(cleanup, failure); }
            try { ClearSecrets(executionRoot, binding, fixture.BeganAtUtc); ClearForwardFaultSecrets(binding, forwardSecrets); } catch (Exception failure) { cleanup = cleanup is null ? failure : new AggregateException(cleanup, failure); }
        }
        if (cleanup is not null) { throw primary is null ? new AggregateException("Native fault cleanup failed.", cleanup) : new AggregateException(primary, cleanup); }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
        if (result is null || control is null) { throw Invalid(); }
        bool proxyAbsent = control.ProxyPort is not { } port || !System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(endpoint => endpoint.Port == port);
        if (!proxyAbsent) { throw Invalid(); }
        if (control.ProxyPort is not null && (control.ProxyCleanup is not { WorkerJoined: true } observed || observed.Sessions.Count == 0 ||
            observed.Sessions.Any(session => !session.ClientHandleClosed || !session.BackendHandleClosed || (session.RelaysStarted && !session.RelaysJoined)) ||
            observed.RemainingOwnedConnections.Any(connection => connection.State is not ("TimeWait" or "Closed")))) { throw Invalid(); }
        var finished = result with { Cleanup = fixture.ReadFaultCleanup(), ProxyAbsent = proxyAbsent, ProxyCleanup = control.ProxyCleanup };
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            Kind = "consumer-column-bootstrap-actual-native-fault-case-v1",
            Result = finished,
            Native = control.RetainedNativeFacts(),
            DirectReadbacks = directReadbacks,
            control.UploadBefore,
            control.UploadAfter,
            UploadReadback = uploadReadback,
            control.FinalFleetAffectedRows,
            keys.PublicKeys,
            SigningPins = keys.Pins
        });
        await issuerFiles.WriteNewAsync(Path.Combine(issuerRoot, "actual-native-fault-result.json"), bytes, ct).ConfigureAwait(false);
        await issuerFiles.WriteNewAsync(Path.Combine(issuerRoot, "actual-native-fault-attestation.json"), JsonSerializer.SerializeToUtf8Bytes(new
        {
            receipt.Signer.KeyId,
            receipt.Signer.PublicKeyFingerprintSha256,
            EvidenceSha256 = ConsumerColumnBootstrapOperationalContract.Hash(bytes),
            Signature = Convert.ToBase64String(receipt.Signer.Sign([.. "Legacy.Maliev.ConsumerColumnBootstrap.NativeFaultCase.v1\0"u8, .. bytes]))
        }), ct).ConfigureAwait(false);
        return finished;
    }

    private static async Task PrepareFaultClaimsAsync(string config, ConsumerColumnBootstrapProofFixture fixture, CancellationToken ct)
    {
        foreach (string command in FaultPreparationSteps)
        { if (await MigrationConsole.RunConsumerColumnBootstrapOperationalAsync(command, config, TextWriter.Null, TextWriter.Null, ct, fixture).ConfigureAwait(false) != 0) { throw Invalid(); } }
    }
    private static async Task<ConsumerColumnBootstrapActualInvocation> InvokeFaultApplyAsync(string path, ConsumerColumnBootstrapProofFixture fixture, CancellationToken ct)
    {
        DateTimeOffset began = DateTimeOffset.UtcNow;
        try { int code = await MigrationConsole.RunConsumerColumnBootstrapOperationalAsync("apply-consumer-column-bootstrap-proof", path, TextWriter.Null, TextWriter.Null, ct, fixture).ConfigureAwait(false); return new(code, null, began, DateTimeOffset.UtcNow); }
        catch (Exception failure) when (failure is IOException or NpgsqlException or AggregateException or MigrationExecutionException)
        { return new(null, failure.GetType().FullName, began, DateTimeOffset.UtcNow); }
    }
    private static T ReadFault<T>(LocalExecutionBinding binding, string path)
    {
        return MigrationConsole.DecodeAuthRepair<T>(ReadFaultBytes(binding, path));
    }

    private static string ReadFaultSecret(LocalExecutionBinding binding, string path)
    {
        return Encoding.UTF8.GetString(ReadFaultBytes(binding, path)).Trim();
    }

    private static byte[] ReadFaultBytes(LocalExecutionBinding binding, string path)
    {
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding); using var files = new CurrentAppOwnedRepairCustody(authority);
        return files.Read(path, sharedReader: true, maximumBytes: 64 * 1024 * 1024);
    }
    private static async Task<IReadOnlyDictionary<string, string>> CaptureFaultFleetAsync(string direct, ConsumerColumnBootstrapOperationalScope scope, CancellationToken ct)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string database in scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(direct) { Database = database, Pooling = false }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false); await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ExecuteAsync(connection, transaction, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
            result.Add(database, (await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false)).Sha256);
            await transaction.RollbackAsync(ct).ConfigureAwait(false);
        }
        return result;
    }
    private static async Task<ConsumerColumnBootstrapPreservationObservation> CaptureFaultOperandAsync(string direct, ConsumerColumnBootstrapContract contract, string database, bool after, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(direct) { Database = database, Pooling = false }.ConnectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false); await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
        var result = await ConsumerColumnBootstrapNativePreservation.CaptureAsync(connection, transaction, contract, database, after, ct).ConfigureAwait(false);
        await transaction.RollbackAsync(ct).ConfigureAwait(false); return result;
    }
    private static async Task<ConsumerColumnBootstrapUploadFaultWitness> CaptureFaultUploadAsync(string direct, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(direct) { Database = "Upload", Pooling = false }.ConnectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false); await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
        await ExecuteAsync(connection, transaction, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
        var result = await ConsumerColumnBootstrapUploadFaultPreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
        await transaction.RollbackAsync(ct).ConfigureAwait(false); return result;
    }
    private static bool SameFleet(IReadOnlyDictionary<string, string> left, IReadOnlyDictionary<string, string> right)
    {
        return left.Count == right.Count && left.All(pair => right.GetValueOrDefault(pair.Key) == pair.Value);
    }

    private static string FaultPhysicalHash(ConsumerColumnBootstrapPreservationObservation observation)
    {
        return ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(new
        {
            observation.Native.Snapshot.Sha256,
            observation.OriginalRows,
            Heaps = observation.HeapStorage.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, pair.Value.File, pair.Value.Blocks }).ToArray(),
            Indexes = observation.Native.Read("pg_class").Where(row => row["relkind"]?.ToString() == "i").Select(row => row["oid"]!.ToString()).Order(StringComparer.Ordinal)
                .Select(oid => new { Oid = oid, observation.Native.Storage(oid).FileNode, observation.Native.Storage(oid).Blocks }).ToArray(),
        }));
    }

    private static void RequireFaultRun(ConsumerColumnBootstrapOperationalRunReceipt run, ConsumerColumnBootstrapOperationalScope scope, Keys keys, bool completed)
    {
        if (run.Completed != completed || run.OperationId != scope.OperationId || run.ContractSha256 != scope.ContractSha256 || run.LogicalSourcePlanSha256 != scope.LogicalSourcePlanSha256 ||
            (!completed && run.FinalFleetSha256 is not null)) { throw Invalid(); }
        RequireFaultSignature(run.KeyId, run.Signature, PostgreSqlConsumerColumnBootstrapRepair.RunReceiptPayload(run), keys);
    }
    private static void RequireFaultSignature(string keyId, string? signature, byte[] payload, Keys keys)
    {
        var trust = new ReceiptAttestationTrustStore(keys.PublicKeys);
        if (keyId != keys.Receipt.KeyId || signature is null || !trust.Verify(keyId, payload, Convert.FromBase64String(signature))) { throw Invalid(); }
    }
    private static Dictionary<string, string> CaptureOldFaultArtifacts(LocalExecutionBinding binding, Guid operation)
    {
        return Directory.GetFiles(binding.ArtifactRootCanonicalPath, $"consumer-bootstrap-{operation:N}-*.json").ToDictionary(path => path, path => ConsumerColumnBootstrapOperationalContract.Hash(ReadFaultBytes(binding, path)), StringComparer.Ordinal);
    }
}
