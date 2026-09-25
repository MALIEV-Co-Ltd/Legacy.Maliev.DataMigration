Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../../scripts/production-exec-tunnel-admission.ps1')

function New-Observation {
    $config = [pscustomobject]@{
        context = 'gke_maliev-website_us-central1-a_web-production-cluster'
        clusterUid = 'cluster-uid'
        clusterGeneration = 4
        primaryPod = 'legacy-postgres-main-2'
        primaryPodUid = 'pod-uid'
        listenPort = 15438
    }
    $cluster = [pscustomobject]@{
        metadata = [pscustomobject]@{ uid = 'cluster-uid'; generation = 4 }
        status = [pscustomobject]@{ currentPrimary = 'legacy-postgres-main-2' }
    }
    $pod = [pscustomobject]@{ metadata = [pscustomobject]@{ uid = 'pod-uid' } }
    $process = [pscustomobject]@{
        Name = 'dotnet.exe'
        CommandLine = 'dotnet "C:\runner\DataMigration.Console.dll" cnpg-exec-tunnel --config "C:\run\cnpg-exec-tunnel.json"'
    }
    return [pscustomobject]@{ Config = $config; Cluster = $cluster; Pod = $pod; Process = $process }
}

function Invoke-Admit($observation) {
    Assert-ProductionExecTunnelIdentity -Config $observation.Config -Cluster $observation.Cluster `
        -Pod $observation.Pod -Process $observation.Process `
        -Assembly 'C:\runner\DataMigration.Console.dll' `
        -ConfigPath 'C:\run\cnpg-exec-tunnel.json' -Port 15438
}

function Assert-Rejected($observation, [string]$expectedCode) {
    try { Invoke-Admit $observation; throw 'test_expected_rejection' }
    catch {
        if ($_.Exception.Message -cne $expectedCode) { throw }
    }
}

Invoke-Admit (New-Observation)
$observation = New-Observation; $observation.Config.clusterUid = 'other'; Assert-Rejected $observation 'production_delta_exec_target_drift'
$observation = New-Observation; $observation.Config.clusterGeneration = 5; Assert-Rejected $observation 'production_delta_exec_target_drift'
$observation = New-Observation; $observation.Config.primaryPod = 'legacy-postgres-main-1'; Assert-Rejected $observation 'production_delta_exec_target_drift'
$observation = New-Observation; $observation.Config.primaryPodUid = 'other'; Assert-Rejected $observation 'production_delta_exec_target_drift'
$observation = New-Observation; $observation.Config.listenPort = 15439; Assert-Rejected $observation 'production_delta_exec_target_drift'
$observation = New-Observation; $observation.Process.Name = 'kubectl.exe'; Assert-Rejected $observation 'production_delta_tunnel_identity_invalid'
$observation = New-Observation; $observation.Process.CommandLine = 'dotnet other.dll cnpg-exec-tunnel --config "C:\run\cnpg-exec-tunnel.json"'; Assert-Rejected $observation 'production_delta_tunnel_identity_invalid'
$observation = New-Observation; $observation.Process.CommandLine = 'dotnet "C:\runner\DataMigration.Console.dll" cnpg-exec-tunnel --config other.json'; Assert-Rejected $observation 'production_delta_tunnel_identity_invalid'
Write-Output 'production_exec_tunnel_admission_tests_passed=9'
