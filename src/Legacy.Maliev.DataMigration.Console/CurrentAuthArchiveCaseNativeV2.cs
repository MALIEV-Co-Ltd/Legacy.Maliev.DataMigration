using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CurrentAuthArchiveCaseReadbackV2
{
    private void RequireNativeOwnershipAndPolicyV2(bool setup)
    {
        CurrentAuthArchiveGenuineDualNativeEvidence native;
        if (setup) { native = Value<CurrentAuthArchiveGenuineDualNativeEvidence>("setup-native-policy"); }
        else
        {
            using var ownership = JsonDocument.Parse(Bytes("native-ownership-v2", 65536));
            native = new(Value<CurrentAppOwnedRepairTargetPins>("local-target"), Value<CurrentAppOwnedRepairTargetPins>("comparison-target"),
                Value<JsonElement>("local-container"), Value<JsonElement>("local-volume"), Value<JsonElement>("comparison-container"), Value<JsonElement>("comparison-volume"),
                _stage.GetProperty("LocalPort").GetInt32(), _stage.GetProperty("ComparisonPort").GetInt32(), Value<CurrentAuthArchiveProofPolicy>("local-policy"),
                Value<CurrentAuthArchiveProofPolicy>("comparison-policy"), ownership.RootElement.GetProperty("ObservedAtUtc").GetDateTimeOffset(),
                ownership.RootElement.GetProperty("LocalVolumeConsumers").EnumerateArray().Select(item => item.GetString()!).ToArray(),
                ownership.RootElement.GetProperty("ComparisonVolumeConsumers").EnumerateArray().Select(item => item.GetString()!).ToArray());
        }
        RequireOwnedNativeV2(native);
        RequirePolicyV2(native.LocalPolicy, Scope.LocalObservationPolicy); RequirePolicyV2(native.ComparisonPolicy, Scope.ProductionObservationPolicy);
        var devices = Value<CurrentAuthArchiveDeviceProof>(setup ? "original-device" : "device-proof");
        if (CurrentAuthLocalSessionArchivePolicy.Hash(devices) != Scope.RecoveryDeviceProofSha256 || devices.OperationId != Scope.OperationId || devices.Paths != Scope.Paths ||
            devices.LocalRunBindingSha256 != Scope.LocalObservationPolicy.RunBindingSha256 || devices.ProductionRunBindingSha256 != Scope.ProductionObservationPolicy.RunBindingSha256 ||
            devices.ObservedAtUtc > Method.StartedAtUtc || Method.StartedAtUtc - devices.ObservedAtUtc > TimeSpan.FromMinutes(5)) { throw Invalid(); }
        CurrentAuthLocalSessionArchiveRecoveryDevices.RequireIndependent(devices.First, devices.Second);
    }
    private void RequireOwnedNativeV2(CurrentAuthArchiveGenuineDualNativeEvidence native)
    {
        if (native.ObservedAtUtc < Method.StartedAtUtc || native.ObservedAtUtc > Method.ReturnedAtUtc || native.LocalPort == native.ComparisonPort ||
            native.LocalVolumeConsumers is null || native.ComparisonVolumeConsumers is null ||
            !native.LocalVolumeConsumers.SequenceEqual([Scope.ComponentSubject!.Local.ContainerId], StringComparer.Ordinal) ||
            !native.ComparisonVolumeConsumers.SequenceEqual([Scope.ComponentSubject.Comparison.ContainerId], StringComparer.Ordinal)) { throw Invalid(); }
        Check(native.LocalTarget, native.LocalContainer, native.LocalVolume, Scope.LocalObservationPolicy, native.LocalPort, false);
        Check(native.ComparisonTarget, native.ComparisonContainer, native.ComparisonVolume, Scope.ProductionObservationPolicy, native.ComparisonPort, true);
        void Check(CurrentAppOwnedRepairTargetPins target, JsonElement container, JsonElement volume, CurrentAuthRepairScope policy, int port, bool comparison)
        {
            if (CurrentAuthLocalSessionArchivePolicy.Hash(target) != policy.TargetObservationSha256 || target.CloudOptions is not null || target.CloudObservation is not null ||
                container.GetProperty("Id").GetString() != target.DockerContainerId || container.GetProperty("Image").GetString() != target.DockerImageId ||
                container.GetProperty("Config").GetProperty("Image").GetString() != CurrentAuthArchiveHelperHost.Image || target.DockerImageReference != CurrentAuthArchiveHelperHost.Image ||
                container.GetProperty("Config").GetProperty("Labels").EnumerateObject().Count() != 3 || volume.GetProperty("Labels").EnumerateObject().Count() != 3 ||
                volume.GetProperty("Driver").GetString() != "local" || volume.GetProperty(nameof(Scope)).GetString() != "local" ||
                container.GetProperty("HostConfig").GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 ||
                container.GetProperty("HostConfig").GetProperty("MemorySwap").GetInt64() != 512L * 1024 * 1024 ||
                container.GetProperty("HostConfig").GetProperty("NanoCpus").GetInt64() != 750_000_000) { throw Invalid(); }
            CurrentAuthLocalSessionArchiveTarget.RequireDisposable(container, volume, Scope.OperationId, policy.RunBindingSha256, Method.ReturnedAtUtc, comparison);
            string pgData = container.GetProperty("Config").GetProperty("PgData").GetString()!;
            var projected = JsonSerializer.SerializeToElement(new
            {
                Id = container.GetProperty("Id"),
                Name = container.GetProperty("Name"),
                State = container.GetProperty("State"),
                Created = container.GetProperty("Created"),
                Mounts = container.GetProperty("Mounts"),
                NetworkSettings = container.GetProperty("NetworkSettings"),
                Config = new { Env = new[] { "PGDATA=" + pgData } }
            });
            var observed = DockerLocalTargetObservation.Parse("[" + projected.GetRawText() + "]", "[" + volume.GetRawText() + "]", target.DockerContainerId!, target.DockerVolume!, port, false);
            if (LocalDockerGenerationGuard.ComposeGeneration(observed) != policy.TargetGeneration || observed.PgData != pgData ||
                target.HbaPath != pgData.TrimEnd('/') + "/pg_hba.conf") { throw Invalid(); }
        }
    }
    private void RequirePolicyV2(CurrentAuthArchiveProofPolicy value, CurrentAuthRepairScope policy)
    {
        if (value.Maintenance != policy.Maintenance || value.SystemIdentifierSha256 != policy.Target.SystemIdentifierSha256 || !value.Superuser || !value.Login ||
            value.CreateRole || value.CreateDatabase || value.Replication || value.BypassRls || !value.Scram || value.Memberships != 0 || value.DefaultAcls != 0 || value.OtherClients != 0 ||
            value.PreparedTransactions != 0 || value.EventTriggers != 0 || !value.Primary || value.ObservedAtUtc < Method.StartedAtUtc || value.ObservedAtUtc > Method.ReturnedAtUtc ||
            value.HbaFile.Sha256 != policy.Maintenance.HbaSha256 || value.RawRules.Sha256 != policy.Maintenance.HbaRulesSha256) { throw Invalid(); }
        byte[] hba = _roots.Read(new(value.HbaFile.Path, value.HbaFile.Sha256), 65536);
        byte[] rules = _roots.Read(new(value.RawRules.Path, value.RawRules.Sha256), 65536);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(hba) != value.HbaFile.Sha256 || CurrentAuthLocalSessionArchivePolicy.HashBytes(rules) != value.RawRules.Sha256) { throw Invalid(); }
        CurrentAppOwnedMaintenanceHba.Require(CurrentAuthArchiveGenuinePreflight.Rules(Encoding.UTF8.GetString(rules)), value.Maintenance.Role, policy.Target.Kind);
    }
    private void RequirePreflightV2(CurrentAuthArchiveRetainedFleetV2 before, CurrentAuthArchiveRetainedFleetV2 after,
        CurrentAuthArchiveRetainedFleetV2 comparisonBefore, CurrentAuthArchiveRetainedFleetV2 comparisonAfter)
    {
        var native = Value<CurrentAuthArchiveGenuineDualNativeEvidence>("native-safe"); RequireOwnedNativeV2(native);
        RequirePolicyV2(native.LocalPolicy, Scope.LocalObservationPolicy); RequirePolicyV2(native.ComparisonPolicy, Scope.ProductionObservationPolicy);
        var selected = CurrentAuthArchiveGeneratedCasesV2.Preflight(Run.Generated.Case);
        var first = Value<CurrentAuthArchiveGenuinePreflightPolicy>("local-policy-before"); var changed = Value<CurrentAuthArchiveGenuinePreflightPolicy>("local-policy-after");
        var created = Value<CurrentAuthArchiveGenuinePreflightRole?>("created-role");
        CurrentAuthArchiveGenuinePreflight.RequireTransition(selected, Scope, first, changed, Value<CurrentAuthArchiveGenuinePreflightProbe>("blocked-probe"),
            Value<CurrentAuthArchiveGenuinePreflightProbe>("allowed-probe"), Value<CurrentAuthArchiveGenuinePreflightRejection>("actual-rejection"), created, Method.ReturnedAtUtc);
        CurrentAuthArchiveRetainedFleetV2.RequireRoleOnly(before, after, created); CurrentAuthArchiveRetainedFleetV2.RequireExact(comparisonBefore, comparisonAfter);
        var otherBefore = Value<CurrentAuthArchiveGenuinePreflightPolicy>("comparison-policy-before"); var otherAfter = Value<CurrentAuthArchiveGenuinePreflightPolicy>("comparison-policy-after");
        if (otherBefore with { ObservedAtUtc = otherAfter.ObservedAtUtc } != otherAfter || _stage.GetProperty("ActualBoundary").GetString() != "before-issuer-mint") { throw Invalid(); }
        var deviceBefore = Value<CurrentAuthArchiveDeviceProof>("device-proof");
        var deviceAfter = Value<CurrentAuthArchiveDeviceProof>("device-proof-after");
        CurrentAuthLocalSessionArchiveRecoveryDevices.RequireProof(deviceBefore, Scope, deviceAfter, Method.ReturnedAtUtc);
        if (deviceAfter.ObservedAtUtc < changed.ObservedAtUtc) { throw Invalid(); }
        foreach (bool comparison in new[] { false, true })
        {
            var custody = Value<JsonElement>(comparison ? "comparison-custody-after" : "local-custody-after");
            var target = comparison ? Scope.ComponentSubject!.Comparison : Scope.ComponentSubject!.Local;
            var policy = comparison ? Scope.ProductionObservationPolicy : Scope.LocalObservationPolicy;
            var observed = custody.GetProperty("ObservedAtUtc").GetDateTimeOffset();
            if (custody.GetProperty("Operation").GetGuid() != Scope.OperationId || custody.GetProperty("Comparison").GetBoolean() != comparison ||
                custody.GetProperty("RunBindingSha256").GetString() != policy.RunBindingSha256 ||
                custody.GetProperty("Container").GetProperty("Id").GetString() != target.ContainerId ||
                custody.GetProperty("Container").GetProperty("Image").GetString() != target.ImageId ||
                custody.GetProperty("Volume").GetProperty("Name").GetString() != target.VolumeName ||
                observed < changed.ObservedAtUtc || observed > Method.ReturnedAtUtc) { throw Invalid(); }
            CurrentAuthLocalSessionArchiveTarget.RequireDisposable(custody.GetProperty("Container"), custody.GetProperty("Volume"),
                Scope.OperationId, policy.RunBindingSha256, observed, comparison);
        }
        RequireSlotAbsenceV2(true);
        if (_artifacts.ContainsKey("review") || _artifacts.ContainsKey("authorization") || _artifacts.ContainsKey("operation-start") || _artifacts.ContainsKey("recovery-manifest")) { throw Invalid(); }
    }
}
