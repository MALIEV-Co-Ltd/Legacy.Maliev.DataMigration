param(
    [Parameter(Mandatory)][ValidateSet('Create', 'Cleanup')][string]$Action,
    [Parameter(Mandatory)][string]$RunDirectory,
    [Parameter(Mandatory)][string]$Name,
    [string]$SourceContainerId,
    [string]$ExpectedSourceSystemIdentifierSha256,
    [string]$SourceConnectionFile,
    [string]$ImageReference,
    [string]$PgBinDirectory = 'C:\Program Files\PostgreSQL\18\bin'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'QuotationDisposableCopy.Guards.psm1') -Force
if (-not $IsWindows) { throw 'quotation_copy_windows_host_required' }
Assert-QuotationCopyName $Name
$root = (Resolve-Path -LiteralPath $RunDirectory).Path
$runId = $Name.Substring('legacy-quotation-proof-'.Length)
$receiptPath = Join-Path $root 'quotation-copy-receipt.json'
$dumpPath = Join-Path $root 'quotation-copy.dump'
$connectionPath = Join-Path $root 'target-quotation-disposable.connection'
$environmentPath = Join-Path $root 'quotation-copy-container.env'

function Assert-OwnerOnly([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.LinkType -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'quotation_copy_link_invalid'
    }
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $Path
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]) -ne $owner -or
        @($rules | Where-Object { $_.IdentityReference -ne $owner -or
            $_.AccessControlType -ne 'Allow' }).Count -gt 0) {
        throw 'quotation_copy_owner_only_required'
    }
}

function Write-NewOwnerText([string]$Path, [string]$Value) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    try {
        $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes); $stream.Flush($true) }
        finally { $stream.Dispose() }
        Assert-OwnerOnly $Path
    }
    finally { [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes) }
}

function Invoke-DockerJson([string[]]$Arguments) {
    $raw = & docker @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'quotation_copy_docker_observation_failed' }
    return @($raw | ConvertFrom-Json)
}

function Get-SystemHash([string]$HostName, [int]$Port, [string]$User,
    [string]$Password, [string]$Database) {
    $previous = $env:PGPASSWORD
    $env:PGPASSWORD = $Password
    try {
        $value = & (Join-Path $PgBinDirectory 'psql.exe') -X -w -h $HostName -p $Port -U $User -d $Database -Atc `
            'SELECT system_identifier::text FROM pg_control_system();' 2>$null
        if ($LASTEXITCODE -ne 0 -or @($value).Count -ne 1 -or $value -cnotmatch '^\d+$') {
            throw 'quotation_copy_system_identity_unavailable'
        }
        return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes([string]$value))).ToLowerInvariant()
    }
    finally {
        if ($null -eq $previous) { Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue }
        else { $env:PGPASSWORD = $previous }
    }
}

Assert-OwnerOnly $root
if ($Action -eq 'Cleanup') {
    Assert-OwnerOnly $receiptPath
    $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    if ($receipt.schemaVersion -cne '1.0' -or $receipt.state -cne 'copy-complete' -or
        $receipt.name -cne $Name -or $receipt.runId -cne $runId -or
        $receipt.containerId -cnotmatch '^[0-9a-f]{64}$' -or
        $receipt.nonce -cnotmatch '^[0-9a-f]{32}$' -or
        $receipt.sourceContainerId -ceq $receipt.containerId) {
        throw 'quotation_copy_receipt_invalid'
    }
    $container = @(Invoke-DockerJson @('inspect', $receipt.containerId))
    if ($container.Count -ne 1) { throw 'quotation_copy_container_identity_invalid' }
    Assert-QuotationCopyContainer $container[0] $Name $Name $runId $receipt.nonce $receipt.containerId
    $volume = @(Invoke-DockerJson @('volume', 'inspect', $Name))
    if ($volume.Count -ne 1) { throw 'quotation_copy_volume_identity_invalid' }
    Assert-QuotationCopyVolume $volume[0] $Name $runId $receipt.nonce
    $users = @(docker ps -a --filter "volume=$Name" --format '{{.ID}}' 2>$null)
    if ($LASTEXITCODE -ne 0 -or $users.Count -ne 1 -or
        -not $receipt.containerId.StartsWith([string]$users[0], [StringComparison]::Ordinal)) {
        throw 'quotation_copy_volume_shared'
    }
    # Never remove the protected dump or receipt automatically; preserve them for owner review.
    & docker rm -f -- $receipt.containerId 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'quotation_copy_container_cleanup_failed' }
    & docker volume rm -- $Name 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'quotation_copy_volume_cleanup_failed' }
    if (Test-Path -LiteralPath $environmentPath) {
        Remove-QuotationCopyContainerEnvFile $root $environmentPath $receipt.containerId $container[0].Id
    }
    Write-Output 'quotation_copy_resources_removed_protected_artifacts_retained'
    return
}

if ($SourceContainerId -cnotmatch '^[0-9a-f]{64}$' -or
    $ExpectedSourceSystemIdentifierSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $ImageReference -cnotmatch '^postgres:18@sha256:[0-9a-f]{64}$' -or
    [string]::IsNullOrWhiteSpace($SourceConnectionFile)) {
    throw 'quotation_copy_inputs_invalid'
}
Assert-OwnerOnly $SourceConnectionFile
foreach ($path in @($receiptPath, $dumpPath, $connectionPath, $environmentPath)) {
    if (Test-Path -LiteralPath $path) { throw 'quotation_copy_output_exists' }
}
$source = [System.Data.Common.DbConnectionStringBuilder]::new()
$source.ConnectionString = Get-Content -LiteralPath $SourceConnectionFile -Raw
if ([string]$source['Host'] -cne '127.0.0.1' -or
    [string]$source['Database'] -cne 'postgres' -or
    [string]::IsNullOrWhiteSpace([string]$source['Username']) -or
    [string]::IsNullOrWhiteSpace([string]$source['Password'])) {
    throw 'quotation_copy_source_connection_invalid'
}
$sourceContainer = @(Invoke-DockerJson @('inspect', $SourceContainerId))
if ($sourceContainer.Count -ne 1) { throw 'quotation_copy_persistent_source_invalid' }
Assert-QuotationCopySourceContainer $sourceContainer[0] $SourceContainerId
$sourcePort = Assert-QuotationCopyPort ((docker port $SourceContainerId 5432/tcp) | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]$source['Port'] -cne [string]$sourcePort) {
    throw 'quotation_copy_source_port_invalid'
}
$sourceHash = Get-SystemHash '127.0.0.1' $sourcePort ([string]$source['Username']) `
    ([string]$source['Password']) 'postgres'
if ($sourceHash -cne $ExpectedSourceSystemIdentifierSha256) {
    throw 'quotation_copy_source_identity_changed'
}
$version = & (Join-Path $PgBinDirectory 'pg_dump.exe') --version 2>$null
if ($LASTEXITCODE -ne 0 -or $version -cnotmatch '^pg_dump \(PostgreSQL\) 18\.') {
    throw 'quotation_copy_pg18_required'
}
$version = & (Join-Path $PgBinDirectory 'pg_restore.exe') --version 2>$null
if ($LASTEXITCODE -ne 0 -or $version -cnotmatch '^pg_restore \(PostgreSQL\) 18\.') {
    throw 'quotation_copy_pg18_required'
}
& docker volume inspect $Name 1>$null 2>$null
if ($LASTEXITCODE -eq 0) { throw 'quotation_copy_volume_exists' }
& docker inspect $Name 1>$null 2>$null
if ($LASTEXITCODE -eq 0) { throw 'quotation_copy_container_exists' }

# The dump is an owner-only, run-local sensitive artifact; never stream it to logs.
Write-NewOwnerText $dumpPath ''
$previousPassword = $env:PGPASSWORD
$previousOptions = $env:PGOPTIONS
$env:PGPASSWORD = [string]$source['Password']
$env:PGOPTIONS = '-c default_transaction_read_only=on'
try {
    & (Join-Path $PgBinDirectory 'pg_dump.exe') -w -h 127.0.0.1 -p $sourcePort `
        -U ([string]$source['Username']) -d Quotation -F c --serializable-deferrable `
        --no-owner --no-acl -f $dumpPath 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'quotation_copy_dump_failed' }
}
finally {
    if ($null -eq $previousPassword) { Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue }
    else { $env:PGPASSWORD = $previousPassword }
    if ($null -eq $previousOptions) { Remove-Item Env:PGOPTIONS -ErrorAction SilentlyContinue }
    else { $env:PGOPTIONS = $previousOptions }
}
if ((Get-Item -LiteralPath $dumpPath).Length -eq 0) { throw 'quotation_copy_dump_empty' }
Assert-OwnerOnly $dumpPath
if ((Get-SystemHash '127.0.0.1' $sourcePort ([string]$source['Username']) `
    ([string]$source['Password']) 'postgres') -cne $sourceHash) {
    throw 'quotation_copy_source_identity_changed'
}

$passwordBytes = [byte[]]::new(48)
[Security.Cryptography.RandomNumberGenerator]::Fill($passwordBytes)
$copyPassword = [Convert]::ToHexString($passwordBytes).ToLowerInvariant()
[Security.Cryptography.CryptographicOperations]::ZeroMemory($passwordBytes)
$nonce = [Guid]::NewGuid().ToString('N')
Write-NewOwnerText $environmentPath "POSTGRES_USER=postgres`nPOSTGRES_PASSWORD=$copyPassword`n"
& docker volume create --name $Name --label "maliev.quotation-copy.run-id=$runId" `
    --label "maliev.quotation-copy.name=$Name" --label "maliev.quotation-copy.nonce=$nonce" 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw 'quotation_copy_volume_create_failed' }
$volume = @(Invoke-DockerJson @('volume', 'inspect', $Name))
if ($volume.Count -ne 1) { throw 'quotation_copy_volume_identity_invalid' }
Assert-QuotationCopyVolume $volume[0] $Name $runId $nonce
$containerId = (& docker run -d --name $Name --label "maliev.quotation-copy.run-id=$runId" `
    --label "maliev.quotation-copy.name=$Name" --label "maliev.quotation-copy.nonce=$nonce" `
    --mount "type=volume,source=$Name,target=/var/lib/postgresql" `
    --publish '127.0.0.1::5432' --env-file $environmentPath $ImageReference 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $containerId -cnotmatch '^[0-9a-f]{64}$') {
    throw 'quotation_copy_container_create_failed'
}
$container = @(Invoke-DockerJson @('inspect', $containerId))
Assert-QuotationCopyContainer $container[0] $Name $Name $runId $nonce $containerId
if ($container[0].Config.Image -cne $ImageReference) {
    throw 'quotation_copy_image_identity_invalid'
}
# The Docker env file is needed only until the exact new container is verified.
# Preserve it on an uncertain create; the protected target connection remains the only
# run-owned credential file after successful creation.
Remove-QuotationCopyContainerEnvFile $root $environmentPath $containerId $container[0].Id
$copyPort = Assert-QuotationCopyPort ((docker port $containerId 5432/tcp) | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw 'quotation_copy_loopback_required' }
$ready = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    & (Join-Path $PgBinDirectory 'pg_isready.exe') -h 127.0.0.1 -p $copyPort -U postgres -d postgres 1>$null 2>$null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ready) { throw 'quotation_copy_not_ready' }
$copyHash = Get-SystemHash '127.0.0.1' $copyPort 'postgres' $copyPassword 'postgres'
Assert-QuotationCopyIdentity $sourceHash $copyHash
$env:PGPASSWORD = $copyPassword
try {
    & (Join-Path $PgBinDirectory 'psql.exe') -X -w -h 127.0.0.1 -p $copyPort -U postgres `
        -d postgres -v ON_ERROR_STOP=1 -c 'CREATE DATABASE "Quotation";' 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'quotation_copy_database_create_failed' }
    & (Join-Path $PgBinDirectory 'pg_restore.exe') -w -h 127.0.0.1 -p $copyPort -U postgres `
        -d Quotation --exit-on-error --no-owner --no-acl $dumpPath 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'quotation_copy_restore_failed' }
}
finally {
    if ($null -eq $previousPassword) { Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue }
    else { $env:PGPASSWORD = $previousPassword }
}
if ((Get-SystemHash '127.0.0.1' $copyPort 'postgres' $copyPassword 'Quotation') -cne $copyHash) {
    throw 'quotation_copy_identity_changed'
}
Write-NewOwnerText $connectionPath `
    "Host=127.0.0.1;Port=$copyPort;Username=postgres;Password=$copyPassword;Database=postgres;SSL Mode=Disable;Pooling=False"
Write-NewOwnerText $receiptPath (([ordered]@{
    schemaVersion = '1.0'; state = 'copy-complete'; name = $Name; runId = $runId; nonce = $nonce
    sourceContainerId = $SourceContainerId; sourceSystemIdentifierSha256 = $sourceHash
    containerId = $containerId; systemIdentifierSha256 = $copyHash
    dumpSha256 = (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
    completedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
} | ConvertTo-Json -Compress) + [Environment]::NewLine)
Write-Output "quotation_copy_complete source_system_sha256=$sourceHash copy_system_sha256=$copyHash"
