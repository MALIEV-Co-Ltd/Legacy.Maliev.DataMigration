[CmdletBinding()]
param([string] $DependencyDirectory = 'TestResults/.dependencies/consumer-owner-ef')

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$boundary = [IO.Path]::GetFullPath((Join-Path $root 'TestResults/.dependencies'))
$dependencies = [IO.Path]::GetFullPath((Join-Path $root $DependencyDirectory))
if (!$dependencies.StartsWith($boundary + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Owner proof dependencies must remain inside this workspace private dependency directory.'
}
# The pinned owners have no root editorconfig. Preserve their standalone analyzer
# graph rather than inheriting DataMigration's unrelated ancestor rules.
$null = New-Item -ItemType Directory -Path $dependencies -Force
$editorBoundary = Join-Path $dependencies '.editorconfig'
if (Test-Path -LiteralPath $editorBoundary) {
    if ((Get-Content -LiteralPath $editorBoundary -Raw).Trim() -ne 'root = true') {
        throw 'Owner proof analyzer boundary is not the reviewed root-only definition.'
    }
} else {
    Set-Content -LiteralPath $editorBoundary -Value 'root = true'
}
function Checked([string] $Command, [string[]] $Arguments) {
    & $Command @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Owner proof preparation command failed.' }
}
function Owner([string] $Repository, [string] $Sha) {
    $path = Join-Path $dependencies $Repository
    $origin = "https://github.com/MALIEV-Co-Ltd/$Repository.git"
    if (!(Test-Path -LiteralPath (Join-Path $path '.git'))) {
        Checked git @('-c', 'core.longpaths=true', 'clone', '--no-checkout', $origin, $path)
        Checked git @('-c', 'core.longpaths=true', '-C', $path, 'fetch', '--depth=1', 'origin', $Sha)
        Checked git @('-c', 'core.longpaths=true', '-C', $path, 'checkout', '--detach', $Sha)
    }
    $actualOrigin = & git -c core.longpaths=true -C $path remote get-url origin
    if ($LASTEXITCODE -ne 0 -or $actualOrigin -ne $origin) { throw 'Owner proof origin is not the reviewed repository.' }
    $status = & git -c core.longpaths=true -C $path status --porcelain
    if ($LASTEXITCODE -ne 0 -or $status) { throw 'Owner proof checkout is not clean.' }
    $head = & git -c core.longpaths=true -C $path rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $head -ne $Sha) { throw 'Owner proof checkout is not the reviewed immutable pin.' }
    return $path
}
$accounting = Owner 'Legacy.Maliev.AccountingService' '1913979fa67e1d5864d1469ac1e9e768548af4ba'
$auth = Owner 'Legacy.Maliev.AuthService' '51afbbd6e2829382a3431338abedccf339de33b1'
Checked dotnet @('build', (Join-Path $root 'tools/ConsumerOwnerMigrationProof/ConsumerOwnerMigrationProof.csproj'), '-c', 'Release', '--nologo', '-warnaserror', '-p:TreatWarningsAsErrors=true', '-p:UseSharedCompilation=false', "-p:OwnerAccountingRoot=$accounting", "-p:OwnerAuthRoot=$auth")
$dll = Join-Path $root 'tools/ConsumerOwnerMigrationProof/bin/Release/net10.0/ConsumerOwnerMigrationProof.dll'
if (!(Test-Path -LiteralPath $dll)) { throw 'Owner proof output is missing.' }
$env:MALIEV_CONSUMER_OWNER_EF_PROOF_DLL = $dll
if ($env:GITHUB_ENV) { Add-Content -LiteralPath $env:GITHUB_ENV -Value "MALIEV_CONSUMER_OWNER_EF_PROOF_DLL=$dll" }
Write-Host 'Pinned owner EF proof binary prepared; no database was migrated.'
