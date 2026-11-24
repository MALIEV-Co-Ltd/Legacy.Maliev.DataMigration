using System.Data;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair
{
    private int _driftMutationStarted;
    private CurrentAuthArchiveGenuineDriftApplied? _appliedDrift;

    async Task<CurrentAuthArchiveGenuineDriftApplied> ICurrentAuthArchiveGenuineExecutionLease.ApplyDriftAsync(CancellationToken ct)
    {
        if (_executionCase is not { } value || !CurrentAuthArchiveGenuineDrift.IsCase(value) ||
            Interlocked.CompareExchange(ref _driftMutationStarted, 1, 0) != 0) { throw Invalid(); }
        await RequireExecutionLiveAsync(true, ct);
        if (_environment is null || _firstFiles is null || _secondFiles is null || _firstPolicy is null || _secondPolicy is null) { throw Invalid(); }
        var localBefore = await _environment.CaptureLocalFleetAsync(Scope, ct);
        var comparisonBefore = await _environment.CaptureProductionFleetAsync(Scope, ct);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(localBefore, Scope.LocalObservationPolicy, DateTimeOffset.UtcNow);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(comparisonBefore, Scope.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
        RequireNoDriftArchiveArtifacts();
        // The last normal full identity/preimage check precedes the one fixed owned mutation.
        await RequireExecutionLiveAsync(true, ct);
        bool comparison = CurrentAuthArchiveGenuineDrift.Comparison(value);
        var files = comparison ? _secondFiles : _firstFiles;
        var policy = comparison ? _secondPolicy : _firstPolicy;
        var endpoint = new NpgsqlConnectionStringBuilder(Encoding.UTF8.GetString(files.Read(policy.OperatorConnectionPath, maximumBytes: 65536)))
        { Database = "Auth", Pooling = false, Options = "", IncludeErrorDetail = false, Timeout = 5, CommandTimeout = 30 };
        var installed = comparison ? Scope.ProductionObservationPolicy : Scope.LocalObservationPolicy;
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 || endpoint.Username != installed.Maintenance.Role || string.IsNullOrWhiteSpace(endpoint.Password)) { throw Invalid(); }
        string? beforeRow = null, afterRow = null; long? beforeSequence = null, afterSequence = null; bool? beforeCalled = null, afterCalled = null;
        int affected;
        DateTimeOffset began = DateTimeOffset.UtcNow;
        await using (var connection = new NpgsqlConnection(endpoint.ConnectionString))
        {
            await connection.OpenAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct);
            await PostgreSqlCurrentAuthRepair.RequireInstalledPolicyAsync(connection, transaction, installed, ct);
            if (value == CurrentAuthArchiveGenuineExecutionCase.SequenceDrift)
            {
                var initial = await SequenceAsync(connection, transaction, ct);
                beforeSequence = initial.Item1; beforeCalled = initial.Item2;
                _ = checked(initial.Item1 + 1);
                await using var mutation = new NpgsqlCommand(CurrentAuthArchiveGenuineDrift.MutationSql(value), connection, transaction);
                if (await mutation.ExecuteScalarAsync(ct) is not long result || result != initial.Item1 + 1) { throw Invalid(); }
                (afterSequence, afterCalled) = await SequenceAsync(connection, transaction, ct); affected = 1;
            }
            else
            {
                beforeRow = await RowAsync(connection, transaction, value, ct);
                await using var mutation = new NpgsqlCommand(CurrentAuthArchiveGenuineDrift.MutationSql(value), connection, transaction);
                affected = await mutation.ExecuteNonQueryAsync(ct);
                afterRow = await RowAsync(connection, transaction, value, ct);
            }
            await transaction.CommitAsync(ct);
        }
        var witness = new CurrentAuthArchiveGenuineDriftMutation(value,
            CurrentAuthLocalSessionArchivePolicy.HashBytes(Encoding.UTF8.GetBytes(CurrentAuthArchiveGenuineDrift.MutationSql(value))), affected,
            beforeRow, afterRow, beforeSequence, afterSequence, beforeCalled, afterCalled, began, DateTimeOffset.UtcNow);
        CurrentAuthArchiveGenuineDrift.RequireMutation(witness);
        // Only ordinary read-only capture follows the mutation. No baseline is rewritten or re-admitted.
        var localFault = await _environment.CaptureLocalFleetAsync(Scope, ct);
        var comparisonFault = await _environment.CaptureProductionFleetAsync(Scope, ct);
        var applied = new CurrentAuthArchiveGenuineDriftApplied(value, localBefore, localFault, comparisonBefore, comparisonFault, witness);
        CurrentAuthArchiveGenuineDrift.RequireApplied(Scope, applied, DateTimeOffset.UtcNow); RequireNoDriftArchiveArtifacts();
        _appliedDrift = applied; return applied;

        static async Task<string> RowAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CurrentAuthArchiveGenuineExecutionCase selected, CancellationToken token)
        {
            await using var command = new NpgsqlCommand(CurrentAuthArchiveGenuineDrift.RowSql(selected), connection, transaction);
            return await command.ExecuteScalarAsync(token) is string row && row.Length is > 0 and <= 65536 ? row : throw Invalid();
        }
        static async Task<(long, bool)> SequenceAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken token)
        {
            await using var command = new NpgsqlCommand("SELECT last_value,is_called FROM private.allocation;", connection, transaction);
            await using var reader = await command.ExecuteReaderAsync(token);
            if (!await reader.ReadAsync(token)) { throw Invalid(); }
            var result = (reader.GetInt64(0), reader.GetBoolean(1));
            return await reader.ReadAsync(token) ? throw Invalid() : result;
        }
    }

    async Task<CurrentAuthArchiveGenuineDualArtifacts> ICurrentAuthArchiveGenuineExecutionLease.RetainDriftFailureAsync(
        CurrentAuthArchiveGenuineDriftFailure failure, CancellationToken ct)
    {
        if (_executionCase != failure.Case || !CurrentAuthArchiveGenuineDrift.IsCase(failure.Case) || failure.Claims != _executionClaims ||
            !ReferenceEquals(failure.Applied, _appliedDrift) || failure.ActualExceptionType != typeof(MigrationExecutionException).FullName ||
            failure.ActualCode != "current_auth_local_archive_invalid" || failure.BeganAtUtc.Offset != TimeSpan.Zero || failure.FailedAtUtc.Offset != TimeSpan.Zero ||
            failure.BeganAtUtc > failure.Applied.Mutation.BeganAtUtc || failure.FailedAtUtc < failure.Applied.Mutation.CommittedAtUtc || failure.FailedAtUtc > DateTimeOffset.UtcNow) { throw Invalid(); }
        // The original engine stopped only its permit before reservation. A failed Env is not bypassed here.
        await RequireExecutionLiveAsync(false, ct);
        if (_environment is null || _firstFiles is null || _secondFiles is null || _firstPolicy is null || _secondPolicy is null || _dualDeviceProof is null) { throw Invalid(); }
        RequireNoDriftArchiveArtifacts();
        var localAfter = await _environment.CaptureLocalFleetAsync(Scope, ct);
        var comparisonAfter = await _environment.CaptureProductionFleetAsync(Scope, ct);
        CurrentAuthArchiveGenuineDrift.RequireUnchanged(failure.Applied.LocalFault, localAfter);
        CurrentAuthArchiveGenuineDrift.RequireUnchanged(failure.Applied.ComparisonFault, comparisonAfter);
        CurrentAuthArchiveGenuineDrift.RequireWindows(localAfter, Scope.LocalObservationPolicy, false, DateTimeOffset.UtcNow);
        CurrentAuthArchiveGenuineDrift.RequireWindows(comparisonAfter, Scope.ProductionObservationPolicy, true, DateTimeOffset.UtcNow);
        CurrentAuthArchiveGenuineDrift.RequireApplied(Scope, failure.Applied, DateTimeOffset.UtcNow);
        var native = await _environment.CaptureDualHelperNativeEvidenceAsync(Scope, _firstPolicy.HbaFile, _firstPolicy.RawRules,
            _secondPolicy.HbaFile, _secondPolicy.RawRules, ct);
        await _inputs.RequireAsync(ct); _bundle.Require(); RequireNoDriftArchiveArtifacts();
        _executionEnvironmentClosed = true; var environment = _environment; _environment = null; environment.Dispose();
        RequireNoDriftArchiveArtifacts();
        string root = _inputs.ParentAuthority.Binding.ArtifactRootCanonicalPath, prefix = $"genuine-drift-{Scope.OperationId:N}";
        var artifacts = new Dictionary<string, CurrentAuthArchiveGenuineArtifact>(StringComparer.Ordinal);
        _ = await JsonAsync("scope", Scope); _ = await JsonAsync("source", _inputs.Source); _ = await JsonAsync("review", failure.Claims.Review);
        _ = await JsonAsync("authorization", failure.Claims.Authorization); _ = await JsonAsync("device-proof", _dualDeviceProof);
        _ = await JsonAsync("failure", failure); _ = await JsonAsync("mutation", failure.Applied.Mutation);
        await FleetAsync("local-before", failure.Applied.LocalBefore); await FleetAsync("local-fault", failure.Applied.LocalFault); await FleetAsync("local-after", localAfter);
        await FleetAsync("comparison-before", failure.Applied.ComparisonBefore); await FleetAsync("comparison-fault", failure.Applied.ComparisonFault); await FleetAsync("comparison-after", comparisonAfter);
        _ = await JsonAsync("local-target", native.LocalTarget); _ = await JsonAsync("comparison-target", native.ComparisonTarget);
        _ = await JsonAsync("local-container", native.LocalContainer); _ = await JsonAsync("local-volume", native.LocalVolume);
        _ = await JsonAsync("comparison-container", native.ComparisonContainer); _ = await JsonAsync("comparison-volume", native.ComparisonVolume);
        var localHba = await CopyAsync("local-hba", _firstFiles, _firstPolicy.HbaFile); var localRules = await CopyAsync("local-hba-rules", _firstFiles, _firstPolicy.RawRules);
        var comparisonHba = await CopyAsync("comparison-hba", _secondFiles, _secondPolicy.HbaFile); var comparisonRules = await CopyAsync("comparison-hba-rules", _secondFiles, _secondPolicy.RawRules);
        _ = await JsonAsync("local-policy", native.LocalPolicy with { HbaFile = new(localHba.Path, localHba.Sha256), RawRules = new(localRules.Path, localRules.Sha256) });
        _ = await JsonAsync("comparison-policy", native.ComparisonPolicy with { HbaFile = new(comparisonHba.Path, comparisonHba.Sha256), RawRules = new(comparisonRules.Path, comparisonRules.Sha256) });
        _ = await JsonAsync("archive-slot-absence", new
        {
            Scope.OperationId,
            ObservedAtUtc = DateTimeOffset.UtcNow,
            LocalBinding = _firstAuthority!.Binding.ComputeSha256(),
            ComparisonBinding = _secondAuthority!.Binding.ComputeSha256(),
            LocalOriginalNames = Array.Empty<string>(),
            ComparisonOriginalNames = Array.Empty<string>(),
            ReservationAbsent = true,
            ReceiptsAbsent = true,
            RecoveryFilesAbsent = true,
        });
        // Compatibility effect checks compare engine input AFTER the controlled fault with actual post-rejection observations.
        var (Phase, CaseId) = CurrentAuthArchiveGenuineExecutionCases.Identity(failure.Case);
        var targetBefore = CurrentAuthArchiveGenuineDrift.Comparison(failure.Case) ? failure.Applied.ComparisonBefore : failure.Applied.LocalBefore;
        var targetFault = CurrentAuthArchiveGenuineDrift.Comparison(failure.Case) ? failure.Applied.ComparisonFault : failure.Applied.LocalFault;
        CurrentAuthArchiveProofReader.RequireFault(CaseId, targetBefore.Auth.Native.Snapshot, targetFault.Auth.Native.Snapshot);
        if (failure.Case == CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift) { CurrentAuthArchiveProofReader.RequireCasFaultRows(targetBefore.Auth.Sessions, targetFault.Auth.Sessions); }
        var effectBefore = CurrentAuthArchiveGenuineDrift.Comparison(failure.Case) ? failure.Applied.LocalBefore.Auth.Native.Snapshot : failure.Applied.LocalFault.Auth.Native.Snapshot;
        var scenario = new CurrentAuthArchiveProofScenario(failure.Case == CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift ? "cas-preflight" : "fleet-preflight",
            failure.ActualCode, false, false, false, false, DateTimeOffset.UtcNow, []);
        CurrentAuthArchiveProofReader.RequireEffects(CaseId, scenario, [], effectBefore, localAfter.Auth.Native.Snapshot);
        _ = await JsonAsync("scenario", scenario);
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(typeof(CurrentAuthArchiveGenuineOwnedPair).Assembly.Location), root)) { throw Invalid(); }
        artifacts.Add("test-assembly", new(typeof(CurrentAuthArchiveGenuineOwnedPair).Assembly.Location, _seed.TestAssemblySha256));
        RequireNoDriftArchiveArtifacts(); await _inputs.RequireAsync(ct); _bundle.Require();
        DateTimeOffset ended = DateTimeOffset.UtcNow;
        var stage = await WriteAsync("incomplete-precleanup-stage", JsonSerializer.SerializeToUtf8Bytes(new
        {
            Kind = "current-auth-genuine-execution-incomplete-precleanup-v1",
            Phase,
            CaseId,
            Scope.OperationId,
            failure.BeganAtUtc,
            EndedAtUtc = ended,
            NativeObservedAtUtc = native.ObservedAtUtc,
            native.LocalPort,
            native.ComparisonPort,
            Artifacts = artifacts,
            Receipts = Array.Empty<CurrentAuthArchiveGenuineArtifact>(),
            ActualBoundary = "before-reservation",
            CleanupVerified = false,
            PhaseProofComplete = false,
            ProviderExitCode = (int?)null,
        }));
        return new(stage, failure.BeganAtUtc, ended);

        async Task FleetAsync(string name, CurrentAuthArchiveFleet fleet)
        { _ = await JsonAsync(name, fleet.Databases); _ = await JsonAsync(name + "-catalogs", fleet.Catalogs); _ = await JsonAsync(name + "-sessions", fleet.Auth.Sessions); }
        Task<CurrentAuthArchiveGenuineArtifact> JsonAsync<T>(string name, T value)
        {
            return WriteAsync(name, JsonSerializer.SerializeToUtf8Bytes(value));
        }

        async Task<CurrentAuthArchiveGenuineArtifact> WriteAsync(string name, byte[] bytes)
        {
            string path = Path.Combine(root, prefix + "-" + name + ".json"); await _inputs.ParentFiles.WriteNewAsync(path, bytes, ct);
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
    }

    private void RequireNoDriftArchiveArtifacts()
    {
        if (_firstAuthority is null || _secondAuthority is null || _firstFiles is null || _secondFiles is null) { throw Invalid(); }
        foreach (var authority in new[] { _firstAuthority, _secondAuthority })
        {
            authority.ValidateHeld();
            if (Directory.EnumerateFileSystemEntries(authority.Binding.ArtifactRootCanonicalPath).Select(Path.GetFileName)
                .Any(name => name is not null && name.StartsWith(Scope.OperationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase))) { throw Invalid(); }
        }
        foreach (string path in new[] { Scope.Paths.FirstCiphertext, Scope.Paths.SecondCiphertext, Scope.Paths.RecoveryPrivateKey, Scope.Paths.SecondRecoveryPrivateKey })
        { if (File.Exists(path) || Directory.Exists(path)) { throw Invalid(); } }
        _firstFiles.Require(); _secondFiles.Require();
    }

}
