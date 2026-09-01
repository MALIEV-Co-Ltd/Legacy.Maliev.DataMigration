[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $DotNetSdkImage,
    [Parameter(Mandatory)] [string] $DotNetRuntimeImage,
    [Parameter(Mandatory)] [string] $LocalImageTag
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$digestReference = '^[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+)?@sha256:[0-9a-f]{64}$'
foreach ($reference in @($DotNetSdkImage, $DotNetRuntimeImage)) {
    if ($reference -cnotmatch $digestReference) {
        throw "Runner base images must be lowercase registry references pinned by sha256: $reference"
    }
}
if ([string]::IsNullOrWhiteSpace($LocalImageTag) -or $LocalImageTag.Contains('@')) {
    throw 'LocalImageTag must be a non-empty local build tag, not a digest reference.'
}

$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$dockerfile = Join-Path $repository 'deploy\exact24-shadow-runner.Dockerfile'
& docker build --file $dockerfile `
    --build-arg "DOTNET_SDK_IMAGE=$DotNetSdkImage" `
    --build-arg "DOTNET_RUNTIME_IMAGE=$DotNetRuntimeImage" `
    --tag $LocalImageTag $repository
if ($LASTEXITCODE -ne 0) {
    throw 'Exact-24 runner image build failed.'
}
