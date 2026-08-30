[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ProtectedConfigPath,
    [Parameter(Mandatory)] [string] $RepositoryRoot,
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$configPath = (Resolve-Path -LiteralPath $ProtectedConfigPath).Path
$project = Join-Path $RepositoryRoot 'src\Legacy.Maliev.DataMigration.Console\Legacy.Maliev.DataMigration.Console.csproj'
& dotnet run --project $project --configuration $Configuration --no-build -- restore-backups --config $configPath
if ($LASTEXITCODE -ne 0) {
    throw 'Signed backup restore failed.'
}
