[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ProtectedConfigPath,
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:LEGACY_DEPLOY_ENABLED -ne 'false') {
    throw 'LEGACY_DEPLOY_ENABLED must be explicitly false for shadow migration finalization.'
}

$config = (Resolve-Path -LiteralPath $ProtectedConfigPath).Path
$project = Join-Path $PSScriptRoot '..\src\Legacy.Maliev.DataMigration.Console\Legacy.Maliev.DataMigration.Console.csproj'

$snapshotFailure = $null
$cleanupFailure = $null
try {
    & dotnet run --project $project --configuration $Configuration --no-build -- export-local-snapshot --config $config
    if ($LASTEXITCODE -ne 0) { throw 'Authenticated local snapshot export failed.' }
    & dotnet run --project $project --configuration $Configuration --no-build -- cleanup-shadows --config $config
    if ($LASTEXITCODE -ne 0) { throw 'Signed fenced post-export shadow cleanup failed.' }
}
catch {
    $snapshotFailure = $_.Exception
}
finally {
    try {
        & dotnet run --project $project --configuration $Configuration --no-build -- cleanup-restore --config $config
        if ($LASTEXITCODE -ne 0) { throw 'Verified restore cleanup failed.' }
    }
    catch {
        $cleanupFailure = $_.Exception
    }
}

if ($null -ne $snapshotFailure -and $null -ne $cleanupFailure) {
    throw [AggregateException]::new(
        'Snapshot export failed and the verified restore resources could not be fully removed.',
        [Exception[]]@($snapshotFailure, $cleanupFailure))
}
if ($null -ne $snapshotFailure) { throw $snapshotFailure }
if ($null -ne $cleanupFailure) { throw $cleanupFailure }

& dotnet run --project $project --configuration $Configuration --no-build -- sign-provenance --config $config
if ($LASTEXITCODE -ne 0) { throw 'Migration provenance signing failed.' }

& dotnet run --project $project --configuration $Configuration --no-build -- evidence --config $config
if ($LASTEXITCODE -ne 0) { throw 'Final migration evidence production failed.' }
