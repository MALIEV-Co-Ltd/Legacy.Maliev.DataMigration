using System.Data;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveGenuineDualNativeEvidence(CurrentAppOwnedRepairTargetPins LocalTarget,
    CurrentAppOwnedRepairTargetPins ComparisonTarget, JsonElement LocalContainer, JsonElement LocalVolume,
    JsonElement ComparisonContainer, JsonElement ComparisonVolume, int LocalPort, int ComparisonPort,
    CurrentAuthArchiveProofPolicy LocalPolicy, CurrentAuthArchiveProofPolicy ComparisonPolicy, DateTimeOffset ObservedAtUtc,
    IReadOnlyList<string>? LocalVolumeConsumers = null, IReadOnlyList<string>? ComparisonVolumeConsumers = null);

internal sealed partial class CurrentAuthLocalSessionArchiveEnvironment
{
    internal Task<CurrentAuthArchiveGenuineDualNativeEvidence> CaptureDualHelperNativeEvidenceAsync(
        CurrentAuthArchiveScope scope, CurrentAuthArchiveProofArtifact localHba, CurrentAuthArchiveProofArtifact localRules,
        CurrentAuthArchiveProofArtifact comparisonHba, CurrentAuthArchiveProofArtifact comparisonRules, CancellationToken ct)
    {
        return CaptureNativeCoreAsync(scope, localHba, localRules, comparisonHba, comparisonRules, null, null, ct);
    }

    private async Task<CurrentAuthArchiveGenuineDualNativeEvidence> CaptureNativeCoreAsync(
        CurrentAuthArchiveScope scope, CurrentAuthArchiveProofArtifact localHba, CurrentAuthArchiveProofArtifact localRules,
        CurrentAuthArchiveProofArtifact comparisonHba, CurrentAuthArchiveProofArtifact comparisonRules, CurrentAuthArchiveGenuineExecutionIssuer.SlotDenial? observation, OwnedCommitProxy? proxy, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            RequireObservationCustody(observation, proxy); Match(scope);
            var targets = await RequireTargetsAsync(ct);
            var comparison = targets.Comparison ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid();
            var firstPolicy = await PolicyAsync(true, localHba, localRules);
            var secondPolicy = await PolicyAsync(false, comparisonHba, comparisonRules);
            return new(_localTarget, _productionTarget, Container(targets.Local), Volume(targets.Local),
                Container(comparison), Volume(comparison), RequireEndpoint(_localConnection, scope.LocalObservationPolicy).Port,
                RequireEndpoint(_productionConnection, scope.ProductionObservationPolicy).Port, firstPolicy, secondPolicy, DateTimeOffset.UtcNow,
                targets.Local.VolumeConsumers ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid(), comparison.VolumeConsumers ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid());
        }
        finally { _ = _gate.Release(); }

        async Task<CurrentAuthArchiveProofPolicy> PolicyAsync(bool local, CurrentAuthArchiveProofArtifact hba, CurrentAuthArchiveProofArtifact rules)
        {
            var policy = local ? scope.LocalObservationPolicy : scope.ProductionObservationPolicy;
            var files = local ? _localFiles : _productionFiles;
            if (hba.Sha256 != policy.Maintenance.HbaSha256 || rules.Sha256 != policy.Maintenance.HbaRulesSha256 ||
                CurrentAuthLocalSessionArchivePolicy.HashBytes(files.Read(hba.Path, sharedReader: true, maximumBytes: 65536)) != hba.Sha256 ||
                CurrentAuthLocalSessionArchivePolicy.HashBytes(files.Read(rules.Path, sharedReader: true, maximumBytes: 65536)) != rules.Sha256)
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            await using var connection = Connection(local, "Auth"); await connection.OpenAsync(ct);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await ReadOnlyAsync(connection, tx, ct);
            // Reuse the installed-policy native validator, including the actual
            // role flags, HBA bytes/rules, system ID and server startup/config IDs.
            await RequireReadPolicyAsync(connection, tx, policy, ct);
            await using var command = new NpgsqlCommand("SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid();", connection, tx);
            long clients = (long)(await command.ExecuteScalarAsync(ct) ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid());
            if (clients != 0) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            DateTimeOffset observed = DateTimeOffset.UtcNow;
            await tx.RollbackAsync(ct);
            // Every listed fixed flag/count was just proved by the native
            // validator above; OtherClients is the separate actual observation.
            return new(policy.Maintenance, policy.Target.SystemIdentifierSha256, true, true, false, false, false, false,
                true, 0, 0, clients, 0, 0, true, observed, hba, rules);
        }

        static JsonElement Container(ObservedDocker value)
        {
            var item = JsonNode.Parse(value.Container)!.AsArray().Single()!.DeepClone().AsObject();
            var config = item["Config"]!.AsObject();
            _ = config.Remove("Env"); config["PgData"] = value.Target.PgData;
            return JsonSerializer.SerializeToElement(item);
        }

        static JsonElement Volume(ObservedDocker value)
        {
            using var parsed = JsonDocument.Parse(value.Volume); return parsed.RootElement[0].Clone();
        }
    }
}
