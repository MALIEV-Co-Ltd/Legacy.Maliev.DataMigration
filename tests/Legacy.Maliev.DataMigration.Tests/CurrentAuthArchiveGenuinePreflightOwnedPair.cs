using System.Data;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair
{
    private CurrentAuthArchiveGenuinePreflightCase? _preflightCase;
    private int _preflightStarted;

    internal static async Task<CurrentAuthArchiveGenuineOwnedPair> CreatePreflightAsync(CurrentAuthArchiveGenuineHostConfiguration request,
        CurrentAuthArchiveGenuinePreflightCase expected, CancellationToken ct)
    {
        CurrentAuthArchiveGenuinePreflightInputContract.Require(new(CurrentAuthArchiveGenuinePreflightInputContract.Kind, request), expected);
        var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(Path.GetDirectoryName(request.Inputs.TestImage.Path)!, ct);
        CurrentAuthArchiveComponentReadback? inputs = null; CurrentAuthArchiveGenuineOwnedPair? pair = null;
        try
        {
            bundle.Require();
            inputs = await CurrentAuthArchiveComponentReadback.OpenGenuinePreflightInitialAsync(request.Inputs, expected, ct);
            var seed = await inputs.ReadSeedAsync(ct);
            CurrentAuthArchiveGenuinePreflight.RequireSeed(seed, inputs.Pins, inputs.TrustStore, expected, DateTimeOffset.UtcNow);
            pair = new(inputs, bundle, seed, ct) { _preflightCase = expected };
            await pair.CreateOwnedAsync(request, pair._lease.Token);
            await pair.RequireAsync(pair._lease.Token);
            return pair;
        }
        catch (Exception primary)
        {
            if (pair is not null)
            { try { await pair.DisposeAsync(); } catch (Exception cleanup) { primary.Data["preflight_cleanup_failure"] = cleanup.GetType().Name; } }
            else
            {
                try { inputs?.Dispose(); } catch (Exception cleanup) { primary.Data["preflight_input_cleanup_failure"] = cleanup.GetType().Name; }
                try { bundle.Dispose(); } catch (Exception cleanup) { primary.Data["preflight_bundle_cleanup_failure"] = cleanup.GetType().Name; }
            }
            throw;
        }
    }

    internal async Task<CurrentAuthArchiveGenuinePreflightMethodResult> RunPreflightAsync(CancellationToken ct)
    {
        if (_preflightCase is not { } selected || Interlocked.CompareExchange(ref _preflightStarted, 1, 0) != 0 ||
            _executionCase is not null || _executionClaims is not null) { throw Invalid(); }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, _lease.Token); ct = deadline.Token;
        await RequireAsync(ct);
        if (_environment is null || _first is null || _second is null || _firstAuthority is null || _secondAuthority is null || _firstFiles is null || _secondFiles is null || _firstPolicy is null || _secondPolicy is null || _dualDeviceProof is null) { throw Invalid(); }
        DateTimeOffset began = DateTimeOffset.UtcNow;
        var artifacts = new Dictionary<string, CurrentAuthArchiveGenuineArtifact>(StringComparer.Ordinal);
        await RetainAsync("scope", Scope); await RetainAsync("source", _inputs.Source); await RetainAsync("device-proof", _dualDeviceProof);
        var localBefore = await _environment.CaptureLocalFleetAsync(Scope, ct);
        var comparisonBefore = await _environment.CaptureProductionFleetAsync(Scope, ct);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(localBefore, Scope.LocalObservationPolicy, DateTimeOffset.UtcNow);
        CurrentAuthLocalSessionArchivePolicy.RequireFleet(comparisonBefore, Scope.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
        var nativeBefore = await _environment.CaptureDualHelperNativeEvidenceAsync(Scope, _firstPolicy.HbaFile, _firstPolicy.RawRules, _secondPolicy.HbaFile, _secondPolicy.RawRules, ct);
        var policyBefore = await ObservePreflightPolicyAsync(false, Scope.OperationId, ct);
        var comparisonPolicyBefore = await ObservePreflightPolicyAsync(true, Scope.OperationId, ct);
        if (!policyBefore.Ordinary.Login || policyBefore.Unprobed is not null) { throw Invalid(); }
        await RetainAsync("native-safe", nativeBefore); await RetainAsync("local-policy-before", policyBefore); await RetainAsync("comparison-policy-before", comparisonPolicyBefore);
        await FleetAsync("local-before", localBefore); await FleetAsync("comparison-before", comparisonBefore);
        RequireNoPreflightArchiveArtifacts(); await RequireAsync(ct);
        // No healthy environment or issuer survives into the deliberately unsafe interval.
        var healthy = _environment; _environment = null; healthy.Dispose();
        CurrentAuthArchiveGenuinePreflightRole? created = null;
        if (selected == CurrentAuthArchiveGenuinePreflightCase.HostUnprobedSdk)
        {
            await CreateUnprobedRoleAsync(ct);
            created = (await ObservePreflightPolicyAsync(false, Scope.OperationId, ct)).Unprobed ?? throw Invalid();
        }
        var blocked = selected == CurrentAuthArchiveGenuinePreflightCase.LocalTrust ?
            await _first.ProbeLocalPreflightRoleAsync(_firstAuthority, ct) : await ProbeUnprobedTcpAsync(ct);
        if (blocked.Connected) { throw Invalid(); }
        await RetainAsync("created-role", created); await RetainAsync("blocked-probe", blocked);
        await InstallUnsafePreflightHbaAsync(selected, policyBefore.HbaText, ct);
        CurrentAuthArchiveGenuinePreflightProbe allowed;
        DateTimeOffset waitUntil = DateTimeOffset.UtcNow.AddSeconds(5);
        do
        {
            allowed = selected == CurrentAuthArchiveGenuinePreflightCase.LocalTrust ?
                await _first.ProbeLocalPreflightRoleAsync(_firstAuthority, ct) : await ProbeUnprobedTcpAsync(ct);
            if (!allowed.Connected) { await Task.Delay(50, ct); }
        } while (!allowed.Connected && DateTimeOffset.UtcNow < waitUntil);
        if (!allowed.Connected) { throw Invalid(); }
        await RetainAsync("allowed-probe", allowed);
        var policyAfter = await ObservePreflightPolicyAsync(false, Scope.OperationId, ct);
        var comparisonPolicyAfter = await ObservePreflightPolicyAsync(true, Scope.OperationId, ct);
        await RetainAsync("local-policy-after", policyAfter); await RetainAsync("comparison-policy-after", comparisonPolicyAfter);
        if (comparisonPolicyBefore with { ObservedAtUtc = comparisonPolicyAfter.ObservedAtUtc } != comparisonPolicyAfter) { throw Invalid(); }
        var rejection = await ObservePreflightRejectionAsync(ct);
        await RetainAsync("actual-rejection", rejection);
        CurrentAuthArchiveGenuinePreflight.RequireTransition(selected, Scope, policyBefore, policyAfter, blocked, allowed, rejection, created, DateTimeOffset.UtcNow);
        var localAfter = await CapturePreflightFleetAsync(false, ct);
        var comparisonAfter = await CapturePreflightFleetAsync(true, ct);
        await FleetAsync("local-after", localAfter); await FleetAsync("comparison-after", comparisonAfter);
        await RetainAsync("local-custody-after", await _first.ObservePreflightCustodyAsync(_firstAuthority, ct));
        await RetainAsync("comparison-custody-after", await _second.ObservePreflightCustodyAsync(_secondAuthority, ct));
        var deviceAfter = await CurrentAuthLocalSessionArchiveDeviceProcess.ObserveAsync(Scope, _first.Root, _second.Root, _firstFiles, _secondFiles, ct);
        CurrentAuthLocalSessionArchiveRecoveryDevices.RequireProof(_dualDeviceProof, Scope, deviceAfter, DateTimeOffset.UtcNow);
        await RetainAsync("device-proof-after", deviceAfter);
        CurrentAuthArchiveGenuinePreflight.RequireDataPreserved(localBefore.Databases, localAfter.Databases, created);
        CurrentAuthArchiveGenuinePreflight.RequireDataPreserved(comparisonBefore.Databases, comparisonAfter.Databases, null);
        RequirePreflightNative(localBefore.Auth.Native, localAfter.Auth.Native, created);
        CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(comparisonAfter.Auth, comparisonBefore.Auth);
        CurrentAuthLocalSessionArchivePolicy.RequireRows(localBefore.Auth.Sessions, localAfter.Auth.Sessions);
        RequireNoPreflightArchiveArtifacts(); await RequireOwnedPreflightAsync(ct);
        await RetainAsync("archive-slot-absence", new { Scope.OperationId, ObservedAtUtc = DateTimeOffset.UtcNow, ReservationAbsent = true, ReceiptSlotsAbsent = true, RecoveryFilesAbsent = true });
        RequireNoPreflightArchiveArtifacts(); DateTimeOffset ended = DateTimeOffset.UtcNow;
        var stage = await WriteAsync("incomplete-precleanup-stage", JsonSerializer.SerializeToUtf8Bytes(new
        {
            Kind = "current-auth-genuine-preflight-incomplete-precleanup-v1",
            Phase = "native",
            CaseId = CurrentAuthArchiveGenuinePreflight.CaseId(selected),
            Scope.OperationId,
            BeganAtUtc = began,
            EndedAtUtc = ended,
            nativeBefore.LocalPort,
            nativeBefore.ComparisonPort,
            Artifacts = artifacts,
            ActualBoundary = "before-issuer-mint",
            CleanupVerified = false,
            PhaseProofComplete = false,
            ProviderExitCode = (int?)null,
        }));
        return new(1, began, DateTimeOffset.UtcNow, new(stage, began, ended));

        async Task FleetAsync(string name, CurrentAuthArchiveFleet fleet)
        {
            await RetainAsync(name, fleet.Databases); await RetainAsync(name + "-catalogs", fleet.Catalogs); await RetainAsync(name + "-sessions", fleet.Auth.Sessions);
            // Digest each complete tuple rather than publishing role password verifiers or private catalog values.
            await RetainAsync(name + "-native", new
            {
                Tuples = fleet.Auth.Native.CopyTuples().ToDictionary(pair => pair.Key, pair => pair.Value.Select(text => CurrentAuthLocalSessionArchivePolicy.HashBytes(Encoding.UTF8.GetBytes(text))).Order(StringComparer.Ordinal).ToArray(), StringComparer.Ordinal),
                Storage = fleet.Auth.Native.CopyStorage().ToDictionary(pair => pair.Key, pair => new CurrentAuthProofStorage(pair.Value.FileNode, pair.Value.Blocks), StringComparer.Ordinal),
                Expressions = fleet.Auth.Native.CopyExpressions(),
            });
        }
        async Task RetainAsync<T>(string name, T value)
        {
            if (value is IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> snapshots)
            {
                string path = Path.Combine(_inputs.ParentAuthority.Binding.ArtifactRootCanonicalPath, $"genuine-preflight-{Scope.OperationId:N}-{name}.json");
                artifacts.Add(name, await CurrentAuthArchiveStreamedBaselineV2.RetainAsync(_inputs.ParentFiles, path, snapshots, ct));
            }
            else { artifacts.Add(name, await WriteAsync(name, JsonSerializer.SerializeToUtf8Bytes(value))); }
        }
        async Task<CurrentAuthArchiveGenuineArtifact> WriteAsync(string name, byte[] bytes)
        {
            string path = Path.Combine(_inputs.ParentAuthority.Binding.ArtifactRootCanonicalPath, $"genuine-preflight-{Scope.OperationId:N}-{name}.json");
            await _inputs.ParentFiles.WriteNewAsync(path, bytes, ct);
            return !_inputs.ParentFiles.Read(path, sharedReader: true, maximumBytes: 32 * 1024 * 1024).AsSpan().SequenceEqual(bytes)
                ? throw Invalid()
                : new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
        }
    }

    private async Task CreateUnprobedRoleAsync(CancellationToken ct)
    {
        await RequireOwnedPreflightAsync(ct);
        await using var connection = PreflightConnection(false, "Auth"); await connection.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct);
        await PostgreSqlCurrentAuthRepair.RequireInstalledPolicyAsync(connection, transaction, Scope.LocalObservationPolicy, ct);
        string role = CurrentAuthArchiveGenuinePreflight.UnprobedRole(Scope.OperationId);
        DateTimeOffset expires = new(Scope.ExpiresAtUtc.Ticks - (Scope.ExpiresAtUtc.Ticks % 10), TimeSpan.Zero);
        await using var command = new NpgsqlCommand("CREATE ROLE " + role + " LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS VALID UNTIL '" + expires.ToString("O", CultureInfo.InvariantCulture) + "';", connection, transaction);
        _ = await command.ExecuteNonQueryAsync(ct); await transaction.CommitAsync(ct);
    }
    private async Task InstallUnsafePreflightHbaAsync(CurrentAuthArchiveGenuinePreflightCase selected, string before, CancellationToken ct)
    {
        await RequireOwnedPreflightAsync(ct);
        string hba = CurrentAuthArchiveGenuinePreflight.UnsafeHba(selected, Scope.OperationId, before);
        if (Scope.LocalObservationPolicy.Maintenance.HbaPath != "/var/lib/postgresql/18/docker/pg_hba.conf") { throw Invalid(); }
        await using var connection = PreflightConnection(false, "Auth"); await connection.OpenAsync(ct);
        string values = string.Join(',', hba.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => "('" + line.Replace("'", "''", StringComparison.Ordinal) + "')"));
        await using var command = new NpgsqlCommand("COPY (SELECT * FROM (VALUES " + values + ") AS h(line)) TO '/var/lib/postgresql/18/docker/pg_hba.conf';", connection);
        _ = await command.ExecuteNonQueryAsync(ct);
        await using var reload = new NpgsqlCommand("SELECT pg_reload_conf();", connection);
        if (await reload.ExecuteScalarAsync(ct) is not true) { throw Invalid(); }
    }
    private async Task<CurrentAuthArchiveGenuinePreflightProbe> ProbeUnprobedTcpAsync(CancellationToken ct)
    {
        await RequireOwnedPreflightAsync(ct); DateTimeOffset began = DateTimeOffset.UtcNow;
        await using var original = PreflightConnection(false, "Auth");
        string role = CurrentAuthArchiveGenuinePreflight.UnprobedRole(Scope.OperationId);
        var endpoint = new NpgsqlConnectionStringBuilder(original.ConnectionString) { Username = role, Password = "unused-fixed-preflight-probe", Timeout = 3, CommandTimeout = 3 };
        await using var connection = new NpgsqlConnection(endpoint.ConnectionString);
        try
        {
            await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct); await PreflightReadOnlyAsync(connection, tx, ct);
            await using var query = new NpgsqlCommand("SELECT current_user;", connection, tx);
            string current = await query.ExecuteScalarAsync(ct) as string ?? throw Invalid(); await tx.RollbackAsync(ct);
            return new(role, "loopback-tcp", true, current, null, null, null, "", "", began, DateTimeOffset.UtcNow);
        }
        catch (PostgresException failure) when (failure.SqlState == "28000")
        { return new(role, "loopback-tcp", false, null, failure.SqlState, null, null, "", "", began, DateTimeOffset.UtcNow); }
    }
    private async Task<CurrentAuthArchiveGenuinePreflightRejection> ObservePreflightRejectionAsync(CancellationToken ct)
    {
        await RequireOwnedPreflightAsync(ct);
        await using var connection = PreflightConnection(false, "Auth"); await connection.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct); await PreflightReadOnlyAsync(connection, transaction, ct);
        await using var check = new NpgsqlCommand("SHOW transaction_read_only;", connection, transaction);
        if (await check.ExecuteScalarAsync(ct) is not "on") { throw Invalid(); }
        DateTimeOffset began = DateTimeOffset.UtcNow;
        try { await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, transaction, Scope.LocalObservationPolicy.Maintenance.Role, DeltaTargetAuthorityKind.LocalAspire, ct); }
        catch (MigrationExecutionException failure) when (failure.Code == CurrentAuthArchiveGenuinePreflight.SemanticCode)
        {
            DateTimeOffset ended = DateTimeOffset.UtcNow; await transaction.RollbackAsync(ct);
            return new(failure.GetType().FullName!, failure.Code, began, ended, true);
        }
        throw Invalid();
    }
    private static void RequirePreflightNative(CurrentAuthNativeObservation before, CurrentAuthNativeObservation after, CurrentAuthArchiveGenuinePreflightRole? created)
    {
        var tuples = after.CopyTuples();
        if (created is not null)
        {
            var rows = tuples["pg_authid"]; var added = rows.Where(text => JsonNode.Parse(text)?["oid"]?.ToString() == created.Oid.ToString(CultureInfo.InvariantCulture)).ToArray();
            if (added.Length != 1 || CurrentAuthLocalSessionArchivePolicy.HashBytes(Encoding.UTF8.GetBytes(added[0])) != created.NativeTupleSha256) { throw Invalid(); }
            tuples["pg_authid"] = rows.Where(text => !added.Contains(text, StringComparer.Ordinal)).ToArray();
        }
        static string TupleKey(Dictionary<string, string[]> value)
        {
            return JsonSerializer.Serialize(value.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, Values = pair.Value.Order(StringComparer.Ordinal) }));
        }

        if (TupleKey(before.CopyTuples()) != TupleKey(tuples) ||
            JsonSerializer.Serialize(before.CopyStorage().OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, pair.Value.FileNode, pair.Value.Blocks })) !=
            JsonSerializer.Serialize(after.CopyStorage().OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, pair.Value.FileNode, pair.Value.Blocks })) ||
            JsonSerializer.Serialize(before.CopyExpressions().OrderBy(pair => pair.Key, StringComparer.Ordinal)) != JsonSerializer.Serialize(after.CopyExpressions().OrderBy(pair => pair.Key, StringComparer.Ordinal))) { throw Invalid(); }
    }
    private void RequireNoPreflightArchiveArtifacts()
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
