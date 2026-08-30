[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ProtectedConfigPath,
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:LEGACY_DEPLOY_ENABLED -ne 'false') {
    throw 'LEGACY_DEPLOY_ENABLED must be explicitly false for approved shadow execution.'
}

$config = (Resolve-Path -LiteralPath $ProtectedConfigPath).Path
$project = Join-Path $PSScriptRoot '..\src\Legacy.Maliev.DataMigration.Console\Legacy.Maliev.DataMigration.Console.csproj'

& dotnet run --project $project --configuration $Configuration --no-build -- authorize-shadow --config $config
if ($LASTEXITCODE -ne 0) { throw 'Reviewed shadow authorization failed.' }

& dotnet run --project $project --configuration $Configuration --no-build -- execute-shadow --config $config
if ($LASTEXITCODE -ne 0) { throw 'Approved shadow execution failed.' }
