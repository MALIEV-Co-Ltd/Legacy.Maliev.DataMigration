param(
    [Parameter(Mandatory = $true)][string]$RunDirectory,
    [int]$Port = 15438
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $env:LEGACY_DEPLOY_ENABLED -cne 'false') {
    throw 'production_exec_host_or_deploy_gate_invalid'
}
if ($Port -lt 1024 -or $Port -gt 65535) { throw 'production_exec_port_invalid' }
if ((kubectl config current-context).Trim() -cne 'gke_maliev-website_us-central1-a_web-production-cluster') {
    throw 'production_exec_context_invalid'
}

$root = (Resolve-Path -LiteralPath $RunDirectory).Path
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = Get-Acl -LiteralPath $root
$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if ($acl.GetOwner([Security.Principal.SecurityIdentifier]) -ne $owner -or
    @($rules | Where-Object { $_.IdentityReference -ne $owner -or $_.AccessControlType -ne 'Allow' }).Count -gt 0) {
    throw 'production_exec_owner_only_root_required'
}
$path = Join-Path $root 'cnpg-exec-tunnel.json'
if (Test-Path -LiteralPath $path) { throw 'production_exec_config_exists' }
if (@(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $Port -State Listen -ErrorAction SilentlyContinue).Count -ne 0) {
    throw 'production_exec_port_in_use'
}

$cluster = kubectl -n maliev-legacy get cluster legacy-postgres-main -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $cluster.status.phase -cne 'Cluster in healthy state' -or
    $cluster.status.readyInstances -ne 2 -or $cluster.status.instances -ne 2 -or
    @($cluster.status.conditions | Where-Object { $_.type -eq 'ContinuousArchiving' -and $_.status -eq 'True' }).Count -ne 1) {
    throw 'production_exec_cluster_unhealthy'
}
$primary = [string]$cluster.status.currentPrimary
$pod = kubectl -n maliev-legacy get pod $primary -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $pod.status.phase -cne 'Running' -or
    $pod.metadata.labels.'cnpg.io/instanceRole' -cne 'primary') {
    throw 'production_exec_primary_invalid'
}
$service = kubectl -n maliev-legacy get service legacy-postgres-main-rw -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $service.spec.ports[0].port -ne 5432) {
    throw 'production_exec_service_invalid'
}

$config = [ordered]@{
    context = 'gke_maliev-website_us-central1-a_web-production-cluster'
    clusterUid = [string]$cluster.metadata.uid
    clusterGeneration = [int64]$cluster.metadata.generation
    primaryPod = $primary
    primaryPodUid = [string]$pod.metadata.uid
    listenPort = $Port
}
$bytes = [Text.Encoding]::UTF8.GetBytes(($config | ConvertTo-Json -Compress) + [Environment]::NewLine)
try {
    $stream = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes); $stream.Flush($true) }
    finally { $stream.Dispose() }
}
finally { [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes) }
Write-Output 'production_exec_tunnel_config_ready'
