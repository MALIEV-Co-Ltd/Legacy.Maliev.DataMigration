param(
    [Parameter(Mandatory)][ValidateSet('Create', 'Cleanup')][string]$Action,
    [Parameter(Mandatory)][string]$RunDirectory,
    [Parameter(Mandatory)][string]$Name,
    [string]$SourceContainerId,
    [string]$ExpectedSourceSystemIdentifierSha256,
    [string]$SourceConnectionFile,
    [string]$ImageReference,
    [string]$SyntheticSourceVolumeName,
    [string]$PgBinDirectory = 'C:\Program Files\PostgreSQL\18\bin'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Exact23DisposableCopy.Guards.psm1') -Force

function Fail([string]$Code) { throw $Code }

function Assert-OwnerOnly([string]$Path, [bool]$Directory) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -ne $Directory -or $item.LinkType -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Fail 'exact23_copy_protected_path_invalid'
    }
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $Path
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]) -ne $owner -or
        @($rules | Where-Object { $_.IdentityReference -ne $owner -or
            $_.AccessControlType -ne 'Allow' }).Count -gt 0) {
        Fail 'exact23_copy_owner_only_required'
    }
}

function Assert-NoLinkAncestors([string]$Path) {
    $current = [IO.Directory]::GetParent([IO.Path]::GetFullPath($Path))
    while ($null -ne $current) {
        $item = Get-Item -LiteralPath $current.FullName -Force -ErrorAction Stop
        if ($item.LinkType -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            Fail 'exact23_copy_linked_ancestor_invalid'
        }
        $current = $current.Parent
    }
}

function Write-OwnerText([string]$Path, [string]$Value) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    try {
        $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes); $stream.Flush($true) }
        finally { $stream.Dispose() }
        Assert-OwnerOnly $Path $false
    }
    finally { [Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes) }
}

function Invoke-DockerJson([string[]]$Arguments) {
    $raw = & docker @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) { Fail 'exact23_copy_docker_observation_failed' }
    return @($raw | ConvertFrom-Json)
}

function Invoke-PgQuery([string]$Password, [int]$Port, [string]$Database,
    [string]$Query, [string]$Username = 'postgres') {
    $previousPassword = $env:PGPASSWORD
    $previousOptions = $env:PGOPTIONS
    $env:PGPASSWORD = $Password
    $env:PGOPTIONS = '-c default_transaction_read_only=on'
    try {
        $value = & (Join-Path $PgBinDirectory 'psql.exe') -X -w -h 127.0.0.1 -p $Port `
            -U $Username -d $Database -At -F '|' -v ON_ERROR_STOP=1 -c $Query 2>$null
        if ($LASTEXITCODE -ne 0) { Fail 'exact23_copy_pg_observation_failed' }
        return @($value)
    }
    finally {
        if ($null -eq $previousPassword) { Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue }
        else { $env:PGPASSWORD = $previousPassword }
        if ($null -eq $previousOptions) { Remove-Item Env:PGOPTIONS -ErrorAction SilentlyContinue }
        else { $env:PGOPTIONS = $previousOptions }
    }
}

function Get-SystemHash([string]$Password, [int]$Port, [string]$Username = 'postgres') {
    $value = @(Invoke-PgQuery $Password $Port 'postgres' `
        'SELECT system_identifier::text FROM pg_control_system();' -Username $Username)
    if ($value.Count -ne 1 -or $value[0] -cnotmatch '^\d+$') {
        Fail 'exact23_copy_system_identity_unavailable'
    }
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes([string]$value[0]))).ToLowerInvariant()
}

function Get-PhysicalSchemaHash([string]$ConnectionString, [string]$Database) {
    $options = [Legacy.Maliev.DataMigration.PostgreSqlDeltaReconciliationInspectorOptions]::new(
        $ConnectionString)
    $inspector = [Legacy.Maliev.DataMigration.PostgreSqlDeltaReconciliationInspector]::new($options)
    $tables = [Legacy.Maliev.DataMigration.TableCopyPlan[]]@()
    $plan = [Legacy.Maliev.DataMigration.DatabaseSchemaPlan]::new(
        $Database, '1.0', ('a' * 64), ('b' * 64), $tables)
    return $inspector.InspectSchemaAsync($plan, [Threading.CancellationToken]::None).
        GetAwaiter().GetResult()
}

function Get-Inventory([string]$Password, [int]$Port, [string]$Username = 'postgres',
    [switch]$Source) {
    $lines = @(Invoke-PgQuery $Password $Port 'postgres' `
        "SELECT datname, pg_database_size(oid) FROM pg_database WHERE datallowconn AND NOT datistemplate AND datname <> 'postgres' ORDER BY datname;" -Username $Username)
    $names = @()
    [long]$bytes = 0
    foreach ($line in $lines) {
        if ($line -cnotmatch '^([A-Za-z][A-Za-z0-9_]*)\|([0-9]+)$') {
            Fail 'exact23_copy_inventory_unparseable'
        }
        $names += $Matches[1]
        $size = [long]::Parse($Matches[2], [Globalization.CultureInfo]::InvariantCulture)
        if ((Get-Exact23CopyDatabases) -ccontains $Matches[1]) {
            if ($size -gt [long]::MaxValue - $bytes) { Fail 'exact23_copy_inventory_size_overflow' }
            $bytes += $size
        }
    }
    if ($Source) { Assert-Exact23CopySourceInventory $names $Username }
    else { Assert-Exact23CopyInventory $names }
    return [pscustomobject]@{ Names = $names; Bytes = $bytes }
}

function Assert-ProtectedMain {
    $head = (& git -C $repository rev-parse HEAD).Trim()
    $remote = ((& git -C $repository ls-remote origin refs/heads/main) -split '\s+')[0]
    if ((& git -C $repository branch --show-current).Trim() -cne 'main' -or
        $head -cne $remote -or @(& git -C $repository status --porcelain=v1).Count -gt 0) {
        Fail 'exact23_copy_protected_main_required'
    }
    $ci = & gh api 'repos/MALIEV-Co-Ltd/Legacy.Maliev.DataMigration/actions/workflows/ci-main.yml/runs?branch=main&per_page=10' `
        --jq '.workflow_runs[] | [.head_sha, .status, .conclusion] | @tsv'
    if ($LASTEXITCODE -ne 0 -or -not @($ci | Where-Object { $_ -ceq "$head`tcompleted`tsuccess" }).Count) {
        Fail 'exact23_copy_exact_main_ci_required'
    }
}

function Invoke-PlainDump([string]$Password, [int]$Port, [string]$Database,
    [string]$OutputPath, [string]$Username = 'postgres') {
    $previousPassword = $env:PGPASSWORD
    $previousOptions = $env:PGOPTIONS
    $env:PGPASSWORD = $Password
    $env:PGOPTIONS = '-c default_transaction_read_only=on'
    try {
        & (Join-Path $PgBinDirectory 'pg_dump.exe') -w -h 127.0.0.1 -p $Port `
            -U $Username -d $Database -F p --serializable-deferrable `
            --no-owner --no-acl --no-comments "--restrict-key=$runId" `
            -f $OutputPath 1>$null 2>$null
        if ($LASTEXITCODE -ne 0) { Fail 'exact23_copy_dump_failed' }
    }
    finally {
        if ($null -eq $previousPassword) { Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue }
        else { $env:PGPASSWORD = $previousPassword }
        if ($null -eq $previousOptions) { Remove-Item Env:PGOPTIONS -ErrorAction SilentlyContinue }
        else { $env:PGOPTIONS = $previousOptions }
    }
    if ((Get-Item -LiteralPath $OutputPath).Length -eq 0) { Fail 'exact23_copy_dump_empty' }
    Assert-OwnerOnly $OutputPath $false
    return Get-Exact23CopyCanonicalDumpDigest $OutputPath
}

function Invoke-TargetPsql([string]$Password, [int]$Port, [string]$Database,
    [string[]]$Arguments) {
    $previousPassword = $env:PGPASSWORD
    $previousOptions = $env:PGOPTIONS
    $env:PGPASSWORD = $Password
    Remove-Item Env:PGOPTIONS -ErrorAction SilentlyContinue
    try {
        & (Join-Path $PgBinDirectory 'psql.exe') -X -w -h 127.0.0.1 -p $Port `
            -U postgres -d $Database -v ON_ERROR_STOP=1 @Arguments 1>$null 2>$null
        if ($LASTEXITCODE -ne 0) { Fail 'exact23_copy_restore_failed' }
    }
    finally {
        if ($null -eq $previousPassword) { Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue }
        else { $env:PGPASSWORD = $previousPassword }
        if ($null -eq $previousOptions) { Remove-Item Env:PGOPTIONS -ErrorAction SilentlyContinue }
        else { $env:PGOPTIONS = $previousOptions }
    }
}

if (-not $IsWindows -or $env:LEGACY_DEPLOY_ENABLED -cne 'false' -or
    $env:LEGACY_MIGRATION_CALLER -cne 'owner') {
    Fail 'exact23_copy_owner_local_gate_required'
}
Assert-Exact23CopyName $Name
$root = (Resolve-Path -LiteralPath $RunDirectory).Path
Assert-NoLinkAncestors $root
Assert-OwnerOnly $root $true
$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if (-not [IO.Path]::IsPathFullyQualified($root) -or $root -cnotmatch '^[A-Za-z]:\\' -or
    $root.StartsWith($repository.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
    $repository.StartsWith($root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    Fail 'exact23_copy_run_directory_invalid'
}
$runId = $Name.Substring('legacy-delta-proof-'.Length)
$receiptPath = Join-Path $root 'exact23-copy-receipt.json'
$connectionPath = Join-Path $root 'target-disposable.connection'
$environmentPath = Join-Path $root 'exact23-copy-container.env'

if ($Action -eq 'Cleanup') {
    Assert-OwnerOnly $receiptPath $false
    $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    if ($receipt.schemaVersion -cne '1.0' -or $receipt.state -cne 'copy-complete' -or
        $receipt.name -cne $Name -or $receipt.runId -cne $runId -or
        $receipt.containerId -cnotmatch '^[0-9a-f]{64}$' -or
        $receipt.nonce -cnotmatch '^[0-9a-f]{32}$' -or
        $receipt.systemIdentifierSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $receipt.imageReference -cnotmatch '^postgres:18@sha256:[0-9a-f]{64}$' -or
        $receipt.databaseCount -ne 23 -or @($receipt.databases).Count -ne 23 -or
        $receipt.sourceContainerId -ceq $receipt.containerId) {
        Fail 'exact23_copy_receipt_invalid'
    }
    $container = @(Invoke-DockerJson @('inspect', $receipt.containerId))
    $volume = @(Invoke-DockerJson @('volume', 'inspect', $Name))
    if ($container.Count -ne 1 -or $volume.Count -ne 1) { Fail 'exact23_copy_cleanup_identity_invalid' }
    Assert-Exact23CopyContainer $container[0] $Name $runId $receipt.nonce `
        $receipt.containerId $receipt.imageReference
    Assert-Exact23CopyVolume $volume[0] $Name $runId $receipt.nonce
    $users = @(docker ps -a --filter "volume=$Name" --format '{{.ID}}' 2>$null)
    if ($LASTEXITCODE -ne 0 -or $users.Count -ne 1 -or
        -not $receipt.containerId.StartsWith([string]$users[0], [StringComparison]::Ordinal)) {
        Fail 'exact23_copy_volume_shared'
    }
    Assert-OwnerOnly $connectionPath $false
    $copyConnection = [System.Data.Common.DbConnectionStringBuilder]::new()
    $copyConnection.set_ConnectionString((Get-Content -LiteralPath $connectionPath -Raw))
    $actualPort = Assert-Exact23CopyPort ((docker port $receipt.containerId 5432/tcp) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]$copyConnection['Host'] -cne '127.0.0.1' -or
        [string]$copyConnection['Database'] -cne 'postgres' -or
        [string]$copyConnection['Username'] -cne 'postgres' -or
        [int]$copyConnection['Port'] -ne $actualPort -or
        (Get-SystemHash ([string]$copyConnection['Password']) $actualPort) -cne
            $receipt.systemIdentifierSha256) {
        Fail 'exact23_copy_cleanup_target_changed'
    }
    & docker rm -f -- $receipt.containerId 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) { Fail 'exact23_copy_container_cleanup_failed' }
    & docker volume rm -- $Name 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) { Fail 'exact23_copy_volume_cleanup_failed' }
    if (Test-Path -LiteralPath $environmentPath) {
        Assert-OwnerOnly $environmentPath $false
        Remove-Item -LiteralPath $environmentPath -Force
    }
    Write-Output 'exact23_copy_resources_removed_protected_artifacts_retained'
    return
}

$syntheticOnly = -not [string]::IsNullOrWhiteSpace($SyntheticSourceVolumeName)
if ($syntheticOnly) {
    if ($env:LEGACY_MIGRATION_SYNTHETIC_TEST_ONLY -cne 'true' -or
        $SyntheticSourceVolumeName -cnotmatch '^legacy-delta-synthetic-source-[a-z0-9]{12,32}$') {
        Fail 'exact23_copy_synthetic_gate_invalid'
    }
}
else { Assert-ProtectedMain }

$consoleProject = Join-Path $repository 'src\Legacy.Maliev.DataMigration.Console\Legacy.Maliev.DataMigration.Console.csproj'
& dotnet build $consoleProject -c Release -warnaserror 1>$null
if ($LASTEXITCODE -ne 0) { Fail 'exact23_copy_release_build_failed' }
$assemblyDirectory = Join-Path $repository 'src\Legacy.Maliev.DataMigration.Console\bin\Release\net10.0'
Add-Type -Path (Join-Path $assemblyDirectory 'Npgsql.dll')
Add-Type -Path (Join-Path $assemblyDirectory 'Legacy.Maliev.DataMigration.dll')

if ($SourceContainerId -cnotmatch '^[0-9a-f]{64}$' -or
    $ExpectedSourceSystemIdentifierSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $ImageReference -cnotmatch '^postgres:18@sha256:[0-9a-f]{64}$' -or
    [string]::IsNullOrWhiteSpace($SourceConnectionFile)) {
    Fail 'exact23_copy_inputs_invalid'
}
Assert-NoLinkAncestors $SourceConnectionFile
Assert-OwnerOnly $SourceConnectionFile $false
foreach ($path in @($receiptPath, $connectionPath, $environmentPath)) {
    if (Test-Path -LiteralPath $path) { Fail 'exact23_copy_output_exists' }
}
$dumpRoot = Join-Path $root 'dumps'
if (Test-Path -LiteralPath $dumpRoot) { Fail 'exact23_copy_output_exists' }
$sourceString = Get-Content -LiteralPath $SourceConnectionFile -Raw
$source = [System.Data.Common.DbConnectionStringBuilder]::new()
$source.set_ConnectionString($sourceString)
if ([string]$source['Host'] -cne '127.0.0.1' -or
    [string]$source['Database'] -cne 'postgres' -or
    [string]::IsNullOrWhiteSpace([string]$source['Password']) -or
    [string]$source['Port'] -cnotmatch '^[1-9][0-9]{0,4}$') {
    Fail 'exact23_copy_source_connection_invalid'
}
$sourceContainer = @(Invoke-DockerJson @('inspect', $SourceContainerId))
if ($sourceContainer.Count -ne 1) { Fail 'exact23_copy_persistent_source_invalid' }
if ($syntheticOnly) {
    Assert-Exact23CopySyntheticSourceContainer $sourceContainer[0] $SourceContainerId $SyntheticSourceVolumeName
}
else { Assert-Exact23CopySourceContainer $sourceContainer[0] $SourceContainerId }
$sourceUser = [string]$source['Username']
Assert-Exact23CopySourceRole $sourceContainer[0] $sourceUser
$sourcePort = Assert-Exact23CopyPort ((docker port $SourceContainerId 5432/tcp) | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [int]$source['Port'] -ne $sourcePort) {
    Fail 'exact23_copy_source_port_invalid'
}
$sourcePassword = [string]$source['Password']
$sourceHash = Get-SystemHash $sourcePassword $sourcePort -Username $sourceUser
if ($sourceHash -cne $ExpectedSourceSystemIdentifierSha256) {
    Fail 'exact23_copy_source_identity_changed'
}
foreach ($tool in @('pg_dump.exe', 'psql.exe')) {
    $version = & (Join-Path $PgBinDirectory $tool) --version 2>$null
    if ($LASTEXITCODE -ne 0 -or $version -cnotmatch '18\.') { Fail 'exact23_copy_pg18_required' }
}
$sourceVersion = @(Invoke-PgQuery $sourcePassword $sourcePort 'postgres' 'SHOW server_version_num;' -Username $sourceUser)
if ($sourceVersion.Count -ne 1 -or $sourceVersion[0] -cnotmatch '^18[0-9]{4}$') {
    Fail 'exact23_copy_pg18_required'
}
$beforeInventory = Get-Inventory $sourcePassword $sourcePort -Username $sourceUser -Source
$requiredBytes = [long](3 * $beforeInventory.Bytes + 10GB)
$driveName = [IO.Path]::GetPathRoot($root).Substring(0, 1)
if ((Get-PSDrive -Name $driveName).Free -lt $requiredBytes) {
    Fail 'exact23_copy_run_disk_capacity_insufficient'
}
& docker volume inspect $Name 1>$null 2>$null
if ($LASTEXITCODE -eq 0) { Fail 'exact23_copy_volume_exists' }
& docker inspect $Name 1>$null 2>$null
if ($LASTEXITCODE -eq 0) { Fail 'exact23_copy_container_exists' }

$null = New-Item -ItemType Directory -Path $dumpRoot
Set-Acl -LiteralPath $dumpRoot -AclObject (Get-Acl -LiteralPath $root)
Assert-OwnerOnly $dumpRoot $true
$beforeDigests = [ordered]@{}
$beforeRows = [ordered]@{}
$beforeSchemas = [ordered]@{}
foreach ($database in Get-Exact23CopyDatabases) {
    $beforeSchemas[$database] = Get-PhysicalSchemaHash $sourceString $database
    $path = Join-Path $dumpRoot "$database-before.sql"
    $beforeDigests[$database] = Invoke-PlainDump $sourcePassword $sourcePort $database $path -Username $sourceUser
    $beforeRows[$database] = Get-Exact23CopyRowCount $path
}
if ((Get-SystemHash $sourcePassword $sourcePort -Username $sourceUser) -cne $sourceHash) {
    Fail 'exact23_copy_source_identity_changed'
}
$passwordBytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(48)
try { $copyPassword = [Convert]::ToHexString($passwordBytes).ToLowerInvariant() }
finally { [Security.Cryptography.CryptographicOperations]::ZeroMemory($passwordBytes) }
$nonce = [Guid]::NewGuid().ToString('N')
Write-OwnerText $environmentPath "POSTGRES_USER=postgres`nPOSTGRES_PASSWORD=$copyPassword`n"
& docker volume create --name $Name --label "maliev.exact23-copy.run-id=$runId" `
    --label "maliev.exact23-copy.name=$Name" --label "maliev.exact23-copy.nonce=$nonce" 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { Fail 'exact23_copy_volume_create_failed' }
$volume = @(Invoke-DockerJson @('volume', 'inspect', $Name))
if ($volume.Count -ne 1) { Fail 'exact23_copy_volume_identity_invalid' }
Assert-Exact23CopyVolume $volume[0] $Name $runId $nonce
$containerId = (& docker run -d --name $Name --label "maliev.exact23-copy.run-id=$runId" `
    --label "maliev.exact23-copy.name=$Name" --label "maliev.exact23-copy.nonce=$nonce" `
    --mount "type=volume,source=$Name,target=/var/lib/postgresql" `
    --publish '127.0.0.1::5432' --env-file $environmentPath $ImageReference 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $containerId -cnotmatch '^[0-9a-f]{64}$') {
    Fail 'exact23_copy_container_create_failed'
}
$container = @(Invoke-DockerJson @('inspect', $containerId))
Assert-Exact23CopyContainer $container[0] $Name $runId $nonce $containerId $ImageReference
$copyPort = Assert-Exact23CopyPort ((docker port $containerId 5432/tcp) | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { Fail 'exact23_copy_loopback_required' }
$ready = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    & (Join-Path $PgBinDirectory 'pg_isready.exe') -h 127.0.0.1 -p $copyPort -U postgres -d postgres 1>$null 2>$null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ready) { Fail 'exact23_copy_not_ready' }
$copyHash = Get-SystemHash $copyPassword $copyPort
Assert-Exact23CopyIdentity $sourceHash $copyHash
$disk = @(docker exec $containerId df -Pk /var/lib/postgresql 2>$null)
if ($LASTEXITCODE -ne 0 -or $disk.Count -lt 2 -or
    $disk[-1] -cnotmatch '^\S+\s+\d+\s+\d+\s+(\d+)\s+') {
    Fail 'exact23_copy_volume_capacity_unavailable'
}
if ([long]$Matches[1] * 1024 -lt [long]($beforeInventory.Bytes + 10GB)) {
    Fail 'exact23_copy_volume_capacity_insufficient'
}
foreach ($database in Get-Exact23CopyDatabases) {
    Invoke-TargetPsql $copyPassword $copyPort 'postgres' @('-c', "CREATE DATABASE `"$database`";")
    Invoke-TargetPsql $copyPassword $copyPort $database @('-f', (Join-Path $dumpRoot "$database-before.sql"))
}
$null = Get-Inventory $copyPassword $copyPort
$null = Get-Inventory $sourcePassword $sourcePort -Username $sourceUser -Source
if ((Get-SystemHash $sourcePassword $sourcePort -Username $sourceUser) -cne $sourceHash -or
    (Get-SystemHash $copyPassword $copyPort) -cne $copyHash) {
    Fail 'exact23_copy_identity_changed'
}
$databaseReceipts = @()
$copyConnectionString = "Host=127.0.0.1;Port=$copyPort;Username=postgres;Password=$copyPassword;Database=postgres;SSL Mode=Disable;Pooling=False"
foreach ($database in Get-Exact23CopyDatabases) {
    $afterPath = Join-Path $dumpRoot "$database-source-after.sql"
    $copyPath = Join-Path $dumpRoot "$database-copy.sql"
    $afterDigest = Invoke-PlainDump $sourcePassword $sourcePort $database $afterPath -Username $sourceUser
    $copyDigest = Invoke-PlainDump $copyPassword $copyPort $database $copyPath
    Assert-Exact23CopyDigest $beforeDigests[$database] $afterDigest $copyDigest
    $afterSchema = Get-PhysicalSchemaHash $sourceString $database
    $copySchema = Get-PhysicalSchemaHash $copyConnectionString $database
    if ($beforeSchemas[$database] -cne $afterSchema -or
        $beforeSchemas[$database] -cne $copySchema) {
        Fail 'exact23_copy_physical_schema_changed'
    }
    $afterRows = Get-Exact23CopyRowCount $afterPath
    $copyRows = Get-Exact23CopyRowCount $copyPath
    if ($beforeRows[$database] -ne $afterRows -or $beforeRows[$database] -ne $copyRows) {
        Fail 'exact23_copy_row_count_changed'
    }
    $databaseReceipts += [ordered]@{
        database = $database; logicalSchemaAndDataSha256 = $beforeDigests[$database]
        physicalSchemaSha256 = $beforeSchemas[$database]; copyRowCount = $copyRows
    }
}
if ((Get-SystemHash $sourcePassword $sourcePort -Username $sourceUser) -cne $sourceHash -or
    (Get-SystemHash $copyPassword $copyPort) -cne $copyHash) {
    Fail 'exact23_copy_identity_changed'
}
$null = Get-Inventory $sourcePassword $sourcePort -Username $sourceUser -Source
$null = Get-Inventory $copyPassword $copyPort
Write-OwnerText $connectionPath $copyConnectionString
# Retain the protected environment file until the receipt is complete. Cleanup removes it
# only after re-observing exact ownership; uncertain outcomes preserve all artifacts.
Write-OwnerText $receiptPath (([ordered]@{
    schemaVersion = '1.0'; state = 'copy-complete'; name = $Name; runId = $runId; nonce = $nonce
    imageReference = $ImageReference; sourceContainerId = $SourceContainerId
    sourceSystemIdentifierSha256 = $sourceHash; containerId = $containerId
    systemIdentifierSha256 = $copyHash; databaseCount = 23; databases = $databaseReceipts
    syntheticOnly = $syntheticOnly
    completedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 10 -Compress) + [Environment]::NewLine)
Write-Output "exact23_copy_complete source_system_sha256=$sourceHash copy_system_sha256=$copyHash"
