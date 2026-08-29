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
foreach ($stage in @('receipt', 'plan', 'execute-shadow', 'evidence', 'export-local-snapshot')) {
    & dotnet run --project $project --configuration $Configuration --no-build -- $stage --config $config
    if ($LASTEXITCODE -ne 0) {
        throw "Shadow migration stage failed: $stage"
    }
}
