[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ProtectedConfigPath,
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:LEGACY_DEPLOY_ENABLED -ne 'false') {
    throw 'LEGACY_DEPLOY_ENABLED must be explicitly false for shadow migration preparation.'
}

$config = (Resolve-Path -LiteralPath $ProtectedConfigPath).Path
$repository = Join-Path $PSScriptRoot '..'
$project = Join-Path $repository 'src\Legacy.Maliev.DataMigration.Console\Legacy.Maliev.DataMigration.Console.csproj'

& dotnet run --project $project --configuration $Configuration --no-build -- backup-full --config $config
if ($LASTEXITCODE -ne 0) { throw 'Exact-24 full backup preparation failed.' }

& (Join-Path $PSScriptRoot 'restore-verified-sqlserver-backups.ps1') `
    -ProtectedConfigPath $config -RepositoryRoot $repository -Configuration $Configuration

& dotnet run --project $project --configuration $Configuration --no-build -- plan --config $config
if ($LASTEXITCODE -ne 0) { throw 'Fresh schema plan preparation failed.' }

& dotnet run --project $project --configuration $Configuration --no-build -- plan-digest --config $config
if ($LASTEXITCODE -ne 0) { throw 'Fresh schema plan digest failed.' }

Write-Host 'Preparation complete. STOP: independently review the fresh plan digest before running the approved execution phase.'
