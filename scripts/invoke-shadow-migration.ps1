[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ProtectedConfigPath,
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:LEGACY_DEPLOY_ENABLED -ne 'false') {
    throw 'LEGACY_DEPLOY_ENABLED must be explicitly false for local shadow validation.'
}

$config = (Resolve-Path -LiteralPath $ProtectedConfigPath).Path
$project = Join-Path $PSScriptRoot '..\src\Legacy.Maliev.DataMigration.Console\Legacy.Maliev.DataMigration.Console.csproj'
$primaryFailure = $null
$cleanupFailure = $null
$restoreReady = $false
try {
    & (Join-Path $PSScriptRoot 'restore-verified-sqlserver-backups.ps1') -ProtectedConfigPath $config -RepositoryRoot (Join-Path $PSScriptRoot '..') -Configuration $Configuration
    $restoreReady = $true
    foreach ($stage in @('plan', 'execute-shadow', 'export-local-snapshot')) {
        & dotnet run --project $project --configuration $Configuration --no-build -- $stage --config $config
        if ($LASTEXITCODE -ne 0) {
            throw "Shadow migration stage failed: $stage"
        }
    }
}
catch {
    $primaryFailure = $_.Exception
}
finally {
    if ($restoreReady) {
        try {
            & dotnet run --project $project --configuration $Configuration --no-build -- cleanup-restore --config $config
            if ($LASTEXITCODE -ne 0) {
                throw 'Verified restore cleanup failed.'
            }
        }
        catch {
            $cleanupFailure = $_.Exception
        }
    }
}

if ($null -ne $primaryFailure -and $null -ne $cleanupFailure) {
    throw [AggregateException]::new(
        'Shadow migration failed and the verified restore resources could not be fully removed.',
        [Exception[]]@($primaryFailure, $cleanupFailure))
}
if ($null -ne $primaryFailure) { throw $primaryFailure }
if ($null -ne $cleanupFailure) { throw $cleanupFailure }

& dotnet run --project $project --configuration $Configuration --no-build -- evidence --config $config
if ($LASTEXITCODE -ne 0) {
    throw 'Shadow migration evidence stage failed.'
}
