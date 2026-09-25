param(
    [Parameter(Mandatory = $true)][string]$RunDirectory,
    [Parameter(Mandatory = $true)][string]$SchemaPlanPath,
    [Parameter(Mandatory = $true)][string]$RunnerAssemblyPath,
    [Parameter(Mandatory = $true)][string]$ExpectedSourceCommitSha,
    [Parameter(Mandatory = $true)][string]$BackupManifestSha256,
    [Parameter(Mandatory = $true)][string]$BackupKeyFingerprintSha256,
    [int]$Port = 15438
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $env:LEGACY_DEPLOY_ENABLED -cne 'false') {
    throw 'production_delta_host_or_deploy_gate_invalid'
}
if ($Port -lt 1024 -or $Port -gt 65535 -or
    $ExpectedSourceCommitSha -cnotmatch '^[0-9a-f]{40}$' -or
    $BackupManifestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $BackupKeyFingerprintSha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw 'production_delta_parameters_invalid'
}
if ((kubectl config current-context).Trim() -cne 'gke_maliev-website_us-central1-a_web-production-cluster') {
    throw 'production_delta_context_invalid'
}

$root = (Resolve-Path -LiteralPath $RunDirectory).Path
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = Get-Acl -LiteralPath $root
$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if ($acl.GetOwner([Security.Principal.SecurityIdentifier]) -ne $owner -or
    @($rules | Where-Object { $_.IdentityReference -ne $owner -or $_.AccessControlType -ne 'Allow' }).Count -gt 0) {
    throw 'production_delta_owner_only_root_required'
}
$manifest = Get-Content -LiteralPath (Join-Path $root 'public-manifest.json') -Raw | ConvertFrom-Json
$schema = (Resolve-Path -LiteralPath $SchemaPlanPath).Path
$assembly = (Resolve-Path -LiteralPath $RunnerAssemblyPath).Path
$schemaPlan = Get-Content -LiteralPath $schema -Raw | ConvertFrom-Json
if ($schemaPlan.schemaVersion -cne '2.0' -or
    $schemaPlan.sourceCommitSha -cne $ExpectedSourceCommitSha -or
    @($schemaPlan.databases).Count -ne 23) {
    throw 'production_delta_schema_plan_invalid'
}
if (-not (Test-Path -LiteralPath (Join-Path $root 'source.connection') -PathType Leaf)) {
    throw 'production_delta_source_connection_missing'
}
foreach ($name in @('target-production.connection', 'production-template.json')) {
    if (Test-Path -LiteralPath (Join-Path $root $name)) { throw 'production_delta_output_exists' }
}
foreach ($role in @('plan', 'authorization', 'evidence')) {
    if (-not (Test-Path -LiteralPath $manifest.roles.$role.publicKeyPath -PathType Leaf)) {
        throw 'production_delta_trust_key_missing'
    }
}

$cluster = kubectl -n maliev-legacy get cluster legacy-postgres-main -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $cluster.status.phase -cne 'Cluster in healthy state' -or
    $cluster.status.readyInstances -ne 2 -or $cluster.status.instances -ne 2 -or
    @($cluster.status.conditions | Where-Object { $_.type -eq 'ContinuousArchiving' -and $_.status -eq 'True' }).Count -ne 1) {
    throw 'production_delta_cluster_unhealthy'
}
$primaryName = [string]$cluster.status.currentPrimary
$pod = kubectl -n maliev-legacy get pod $primaryName -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $pod.status.phase -cne 'Running' -or
    $pod.metadata.labels.'cnpg.io/instanceRole' -cne 'primary') {
    throw 'production_delta_primary_invalid'
}
$capacity = @(kubectl -n maliev-legacy exec $primaryName -- df -Pk /var/lib/postgresql/data 2>$null)
if ($LASTEXITCODE -ne 0 -or $capacity.Count -lt 2) { throw 'production_delta_capacity_unavailable' }
$fields = @($capacity[-1] -split '\s+' | Where-Object { $_ })
if ($fields.Count -lt 5 -or [int64]$fields[3] -lt 10485760) {
    throw 'production_delta_capacity_insufficient'
}
$service = kubectl -n maliev-legacy get service legacy-postgres-main-rw -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $service.spec.ports[0].port -ne 5432) {
    throw 'production_delta_service_invalid'
}
$listener = @(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
if ($listener.Count -ne 1) { throw 'production_delta_loopback_tunnel_missing' }
$process = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener[0].OwningProcess)"
if ($null -eq $process -or $process.Name -cnotmatch '^kubectl(\.exe)?$' -or
    $process.CommandLine -cnotmatch '[ -]-n maliev-legacy port-forward svc/legacy-postgres-main-rw ' -or
    $process.CommandLine -cnotmatch " $($Port):5432 --address 127\.0\.0\.1") {
    throw 'production_delta_tunnel_identity_invalid'
}

$secret = kubectl -n maliev-legacy get secret legacy-postgres-superuser -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $secret.data.username -or -not $secret.data.password) {
    throw 'production_delta_target_credential_missing'
}
$username = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($secret.data.username))
$password = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($secret.data.password))
if ($username -cne 'postgres' -or [string]::IsNullOrWhiteSpace($password)) {
    throw 'production_delta_target_role_invalid'
}
$oldPassword = $env:PGPASSWORD
$env:PGPASSWORD = $password
try {
    $psql = 'C:\Program Files\PostgreSQL\18\bin\psql.exe'
    $systemIds = @(& $psql -h 127.0.0.1 -p $Port -U $username -d postgres -w -Atc 'SELECT system_identifier::text FROM pg_control_system();')
    if ($LASTEXITCODE -ne 0 -or $systemIds.Count -ne 1 -or $systemIds[0] -cnotmatch '^\d+$') {
        throw 'production_delta_target_identity_unavailable'
    }
    $databases = @(& $psql -h 127.0.0.1 -p $Port -U $username -d postgres -w -Atc "SELECT datname FROM pg_database WHERE datistemplate=false AND datname<>'postgres' ORDER BY datname;")
    if ($LASTEXITCODE -ne 0) { throw 'production_delta_target_inventory_unavailable' }
}
finally {
    if ($null -eq $oldPassword) { Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue }
    else { $env:PGPASSWORD = $oldPassword }
}
$expected = @('ContactRequest','Country','Currency','Customer','CustomerIdentity','DataProtectionKeys',
    'DataProtectionKeysEmployee','Employee','EmployeeIdentity','Invoice','JobOffers','LocationData',
    'Material','Message','Order','OrderStatus','Payment','PurchaseOrder','Quotation','QuotationRequest',
    'Receipt','Supplier','Upload')
foreach ($name in $expected) {
    if (@($databases | Where-Object { $_ -ceq $name }).Count -ne 1) {
        throw 'production_delta_canonical_database_missing'
    }
}
for ($index = 0; $index -lt $expected.Count; $index++) {
    if ($schemaPlan.databases[$index].database -cne $expected[$index]) {
        throw 'production_delta_schema_inventory_invalid'
    }
}

function Write-OwnerNewFile([string]$Path, [string]$Text) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    try {
        $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes); $stream.Flush($true) }
        finally { $stream.Dispose() }
    }
    finally { [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes) }
}
$connection = [System.Data.Common.DbConnectionStringBuilder]::new()
$connection['Host'] = '127.0.0.1'
$connection['Port'] = $Port
$connection['Database'] = 'postgres'
$connection['Username'] = $username
$connection['Password'] = $password
$connection['Ssl Mode'] = 'Disable'
Write-OwnerNewFile (Join-Path $root 'target-production.connection') $connection.ConnectionString
$systemHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
    [Text.Encoding]::ASCII.GetBytes($systemIds[0]))).ToLowerInvariant()
$observedAt = [DateTimeOffset]::UtcNow.ToString('o')
$observation = [ordered]@{
    clusterUid = $cluster.metadata.uid
    clusterGeneration = $cluster.metadata.generation
    primaryPodUid = $pod.metadata.uid
    systemIdentifierSha256 = $systemHash
    databases = $databases
    observedAtUtc = $observedAt
} | ConvertTo-Json -Compress -Depth 5
$observationHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
    [Text.Encoding]::UTF8.GetBytes($observation))).ToLowerInvariant()
$runnerHash = (Get-FileHash -LiteralPath $assembly -Algorithm SHA256).Hash.ToLowerInvariant()
$config = [ordered]@{ delta = [ordered]@{
    schemaPlanPath = $schema
    outputPath = (Join-Path $root 'pending.json')
    sourceConnectionFile = (Join-Path $root 'source.connection')
    targetConnectionFile = (Join-Path $root 'target-production.connection')
    planKey = [ordered]@{ keyId = $manifest.roles.plan.keyId; subjectPublicKeyInfoPath = $manifest.roles.plan.publicKeyPath }
    authorizationKey = [ordered]@{ keyId = $manifest.roles.authorization.keyId; subjectPublicKeyInfoPath = $manifest.roles.authorization.publicKeyPath }
    evidenceKey = [ordered]@{ keyId = $manifest.roles.evidence.keyId; subjectPublicKeyInfoPath = $manifest.roles.evidence.publicKeyPath }
    backupKeyFingerprintSha256 = $BackupKeyFingerprintSha256
    sourceCutoffUtc = $observedAt
    backupManifestSha256 = $BackupManifestSha256
    runnerDigestSha256 = $runnerHash
    targetNamespace = 'maliev-legacy'
    targetCluster = 'legacy-postgres-main'
    targetGeneration = "cnpg:$($cluster.metadata.uid):$($cluster.metadata.generation):$($pod.metadata.uid)"
    targetObservationSha256 = $observationHash
    targetAuthority = [ordered]@{
        kind = 'production-cloudnativepg'
        authorityId = "gke://maliev-website/us-central1-a/maliev-legacy/legacy-postgres-main/$($cluster.metadata.uid)"
        systemIdentifierSha256 = $systemHash
    }
    allowPlanSigning = $true
    allowAuthorizationSigning = $false
    allowExecution = $false
    sourceMode = 'live-readonly-comparison'
} }
Write-OwnerNewFile (Join-Path $root 'production-template.json') (($config | ConvertTo-Json -Depth 12 -Compress) + [Environment]::NewLine)
Write-Output "production_template_ready active_databases=$($expected.Count) system_sha256=$systemHash cluster_uid=$($cluster.metadata.uid)"
