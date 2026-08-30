[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ProtectedConfigPath,
    [Parameter(Mandatory)] [string] $RepositoryRoot,
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($env:LEGACY_SQLSERVER_ADMIN_CONNECTION)) {
    throw 'LEGACY_SQLSERVER_ADMIN_CONNECTION must reference the disposable SQL Server 2022 instance.'
}

$inventoryPath = Join-Path $RepositoryRoot 'database-disposition.json'
$inventory = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json
$expected = @($inventory.databases | Where-Object disposition -eq 'Migrate' | ForEach-Object database | Sort-Object)
$configPath = (Resolve-Path -LiteralPath $ProtectedConfigPath).Path
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
if ($null -eq $config.restoreManifest -or [string]::IsNullOrWhiteSpace([string]$config.restoreManifest.outputPath)) {
    throw 'Protected configuration must define restoreManifest.outputPath.'
}
$project = Join-Path $RepositoryRoot 'src\Legacy.Maliev.DataMigration.Console\Legacy.Maliev.DataMigration.Console.csproj'
& dotnet run --project $project --configuration $Configuration --no-build -- verify-backup --config $configPath
if ($LASTEXITCODE -ne 0) { throw 'Signed backup verification failed.' }
$manifestPath = (Resolve-Path -LiteralPath ([string]$config.restoreManifest.outputPath)).Path
$state = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ([string]$state.schemaVersion -cne '1.0') { throw 'Restore manifest schema is not approved.' }
$artifacts = @($state.artifacts)
$observed = @($artifacts | ForEach-Object database | Sort-Object)
if (($expected -join "`n") -cne ($observed -join "`n") -or $observed.Count -ne 25 -or @($observed | Select-Object -Unique).Count -ne 25) {
    throw 'Backup state must cover exactly the 25 approved migrate databases.'
}

foreach ($artifact in $artifacts | Sort-Object database) {
    $database = [string]$artifact.database
    if ($database -cnotmatch '^[A-Za-z][A-Za-z0-9_]{0,127}$') {
        throw 'Backup state contains an invalid database name.'
    }
    $backupPath = (Resolve-Path -LiteralPath ([string]$artifact.localPath)).Path
    if ((Get-Item -LiteralPath $backupPath).Length -ne [long]$artifact.byteLength -or
        (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$artifact.sha256) {
        throw "Verified restore artifact changed for $database."
    }
    $quotedBackup = $backupPath.Replace("'", "''")
    $quotedDatabase = $database.Replace(']', ']]')

    Invoke-Sqlcmd -ConnectionString $env:LEGACY_SQLSERVER_ADMIN_CONNECTION -AbortOnError -Query "RESTORE VERIFYONLY FROM DISK = N'$quotedBackup';"
    $files = @(Invoke-Sqlcmd -ConnectionString $env:LEGACY_SQLSERVER_ADMIN_CONNECTION -AbortOnError -Query "RESTORE FILELISTONLY FROM DISK = N'$quotedBackup';")
    if ($files.Count -lt 2 -or @($files | Where-Object Type -eq 'D').Count -eq 0 -or @($files | Where-Object Type -eq 'L').Count -eq 0) {
        throw "Backup file layout is incomplete for $database."
    }

    $exists = Invoke-Sqlcmd -ConnectionString $env:LEGACY_SQLSERVER_ADMIN_CONNECTION -AbortOnError -Query "SELECT DB_ID(N'$($database.Replace("'", "''"))') AS DatabaseId;"
    if ($null -ne $exists.DatabaseId) {
        throw "Disposable restore target already contains $database."
    }

    $moves = foreach ($file in $files) {
        $logical = ([string]$file.LogicalName).Replace("'", "''")
        $extension = if ($file.Type -eq 'L') { '.ldf' } else { '.mdf' }
        $suffix = if ($file.Type -eq 'L') { 'log' } else { "data-$($file.FileId)" }
        $target = "C:\sqlserver-data\$database-$suffix$extension".Replace("'", "''")
        "MOVE N'$logical' TO N'$target'"
    }
    $moveClause = $moves -join ', '
    Invoke-Sqlcmd -ConnectionString $env:LEGACY_SQLSERVER_ADMIN_CONNECTION -AbortOnError -Query "RESTORE DATABASE [$quotedDatabase] FROM DISK = N'$quotedBackup' WITH MOVE $moveClause, RECOVERY; ALTER DATABASE [$quotedDatabase] SET ALLOW_SNAPSHOT_ISOLATION ON;"
    $snapshot = Invoke-Sqlcmd -ConnectionString $env:LEGACY_SQLSERVER_ADMIN_CONNECTION -AbortOnError -Query "SELECT snapshot_isolation_state AS SnapshotIsolationState FROM sys.databases WHERE name = N'$($database.Replace("'", "''"))';"
    if ([int]$snapshot.SnapshotIsolationState -ne 1) { throw "Snapshot isolation is not enabled for $database." }
    Invoke-Sqlcmd -ConnectionString $env:LEGACY_SQLSERVER_ADMIN_CONNECTION -AbortOnError -Query "ALTER DATABASE [$quotedDatabase] SET READ_ONLY WITH ROLLBACK IMMEDIATE;"
}
