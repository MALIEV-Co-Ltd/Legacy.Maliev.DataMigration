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

$databases = @(1..23 | ForEach-Object { "Database$_" })
$script:queried = @()
$query = {
    param([string]$database)
    $script:queried += $database
    return [pscustomobject]@{ ExitCode = 0; Lines = @('123456789') }
}
Assert-ProductionExecTunnelDurability -Databases $databases `
    -ExpectedSystemIdentifier '123456789' -Query $query
if ($script:queried.Count -ne 23 -or
    [string]::Join('|', $script:queried) -cne [string]::Join('|', $databases)) {
    throw 'production_exec_durability_did_not_query_23_distinct_databases'
}

function Assert-DurabilityRejected([string[]]$Names, [scriptblock]$Query,
    [string]$ExpectedCode) {
    try {
        Assert-ProductionExecTunnelDurability -Databases $Names `
            -ExpectedSystemIdentifier '123456789' -Query $Query
        throw 'test_expected_rejection'
    }
    catch {
        if ($_.Exception.Message -cne $ExpectedCode) { throw }
    }
}

Assert-DurabilityRejected $databases[0..21] $query 'production_delta_tunnel_preflight_invalid'
Assert-DurabilityRejected @($databases[0..21] + $databases[0]) $query 'production_delta_tunnel_preflight_invalid'
$script:queried = @()
$resetAfterOne = {
    param([string]$database)
    $script:queried += $database
    if ($script:queried.Count -eq 2) { throw 'synthetic_connection_reset' }
    return [pscustomobject]@{ ExitCode = 0; Lines = @('123456789') }
}
Assert-DurabilityRejected $databases $resetAfterOne 'production_delta_tunnel_durability_failed'
if ($script:queried.Count -ne 2) { throw 'production_exec_reset_not_reproduced' }
$wrongIdentity = { [pscustomobject]@{ ExitCode = 0; Lines = @('987654321') } }
Assert-DurabilityRejected $databases $wrongIdentity 'production_delta_tunnel_durability_failed'
$failedQuery = { [pscustomobject]@{ ExitCode = 1; Lines = @() } }
Assert-DurabilityRejected $databases $failedQuery 'production_delta_tunnel_durability_failed'
Write-Output 'production_exec_tunnel_durability_tests_passed=6'

# A stale operator invocation without the reviewed exec config must stop before
# Kubernetes observation, credential projection, or any target output.
if ($IsWindows) {
    $previousDeploy = $env:LEGACY_DEPLOY_ENABLED
    $env:LEGACY_DEPLOY_ENABLED = 'false'
    try {
        try {
            & (Join-Path $PSScriptRoot '../../scripts/new-production-delta-template.ps1') `
                -RunDirectory 'C:\does-not-exist' -SchemaPlanPath 'C:\does-not-exist' `
                -RunnerAssemblyPath 'C:\does-not-exist' `
                -ExpectedSourceCommitSha ('a' * 40) -BackupManifestSha256 ('b' * 64) `
                -BackupKeyFingerprintSha256 ('c' * 64) | Out-Null
            throw 'test_expected_rejection'
        }
        catch {
            if ($_.Exception.Message -cne 'production_delta_parameters_invalid') { throw }
        }
    }
    finally {
        if ($null -eq $previousDeploy) { Remove-Item Env:LEGACY_DEPLOY_ENABLED -ErrorAction SilentlyContinue }
        else { $env:LEGACY_DEPLOY_ENABLED = $previousDeploy }
    }
    Write-Output 'production_exec_tunnel_missing_config_rejected=1'
}
