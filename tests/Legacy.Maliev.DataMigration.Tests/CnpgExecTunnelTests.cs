using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CnpgExecTunnelTests
{
    private static readonly CnpgExecTunnelConfiguration Valid = new(
        "gke_maliev-website_us-central1-a_web-production-cluster",
        "11111111-2222-3333-4444-555555555555",
        4,
        "legacy-postgres-main-2",
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        15438);

    [Fact]
    public void Validate_AcceptsOnlyPinnedContextIdentityAndLoopbackPort()
    {
        CnpgExecTunnel.Validate(Valid);
        foreach (CnpgExecTunnelConfiguration invalid in new[]
        {
            Valid with { Context = "another-cluster" },
            Valid with { ClusterUid = "" },
            Valid with { ClusterGeneration = 0 },
            Valid with { PrimaryPod = "" },
            Valid with { PrimaryPodUid = "" },
            Valid with { ListenPort = 543 },
            Valid with { ListenPort = 65536 },
        })
        {
            MigrationConsoleException exception = Assert.Throws<MigrationConsoleException>(() =>
                CnpgExecTunnel.Validate(invalid));
            Assert.Equal("cnpg_exec_tunnel_config_invalid", exception.Code);
        }
    }

    [Fact]
    public async Task Console_RejectsTunnelWhenDeploymentGateIsNotFalseBeforeReadingConfig()
    {
        using var error = new StringWriter();
        int exitCode = await MigrationConsole.RunAsync(
            ["cnpg-exec-tunnel", "--config", "nonexistent.json"],
            TextWriter.Null,
            error,
            _ => "true",
            CancellationToken.None);

        Assert.Equal(65, exitCode);
        Assert.Equal("cnpg_exec_tunnel_deploy_gate_invalid", error.ToString().Trim());
    }

    [Fact]
    public async Task Console_RejectsMissingConfigWithoutKubernetesAccess()
    {
        using var error = new StringWriter();
        int exitCode = await MigrationConsole.RunAsync(
            ["cnpg-exec-tunnel", "--config", "nonexistent.json"],
            TextWriter.Null,
            error,
            name => name == "LEGACY_DEPLOY_ENABLED" ? "false" : null,
            CancellationToken.None);

        Assert.Equal(65, exitCode);
        Assert.Equal("cnpg_exec_tunnel_config_invalid", error.ToString().Trim());
    }

    [Fact]
    public void Observation_RejectsPrimaryOrArchivingDrift()
    {
        const string clusterJson = """
            {"metadata":{"uid":"11111111-2222-3333-4444-555555555555","generation":4},
             "status":{"phase":"Cluster in healthy state","readyInstances":2,"instances":2,
                       "currentPrimary":"legacy-postgres-main-2",
                       "conditions":[{"type":"ContinuousArchiving","status":"True"}]}}
            """;
        const string podJson = """
            {"metadata":{"uid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                         "labels":{"cnpg.io/instanceRole":"primary"}},"status":{"phase":"Running"}}
            """;
        using JsonDocument cluster = JsonDocument.Parse(clusterJson);
        using JsonDocument pod = JsonDocument.Parse(podJson);
        CnpgExecTunnel.ValidateObservation(Valid, cluster.RootElement, pod.RootElement);

        foreach (string drift in new[]
        {
            clusterJson.Replace("11111111-2222-3333-4444-555555555555", "other", StringComparison.Ordinal),
            clusterJson.Replace("\"generation\":4", "\"generation\":5", StringComparison.Ordinal),
            clusterJson.Replace("\"readyInstances\":2", "\"readyInstances\":1", StringComparison.Ordinal),
            clusterJson.Replace("\"status\":\"True\"", "\"status\":\"False\"", StringComparison.Ordinal),
            clusterJson.Replace("legacy-postgres-main-2", "legacy-postgres-main-1", StringComparison.Ordinal),
        })
        {
            using JsonDocument badCluster = JsonDocument.Parse(drift);
            MigrationConsoleException failure = Assert.Throws<MigrationConsoleException>(() =>
                CnpgExecTunnel.ValidateObservation(Valid, badCluster.RootElement, pod.RootElement));
            Assert.Equal("cnpg_exec_tunnel_cluster_drift", failure.Code);
        }

        foreach (string drift in new[]
        {
            podJson.Replace("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "other", StringComparison.Ordinal),
            podJson.Replace("\"primary\"", "\"replica\"", StringComparison.Ordinal),
            podJson.Replace("\"Running\"", "\"Pending\"", StringComparison.Ordinal),
        })
        {
            using JsonDocument badPod = JsonDocument.Parse(drift);
            MigrationConsoleException failure = Assert.Throws<MigrationConsoleException>(() =>
                CnpgExecTunnel.ValidateObservation(Valid, cluster.RootElement, badPod.RootElement));
            Assert.Equal("cnpg_exec_tunnel_pod_drift", failure.Code);
        }
    }
}
