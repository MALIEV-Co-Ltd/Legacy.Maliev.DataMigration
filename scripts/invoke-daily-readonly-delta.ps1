param(
    [Parameter(Mandatory = $true)][string]$TemplatePath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string]$Code) { throw $Code }

function Assert-NoLinkAncestors([string]$Path) {
    $current = [IO.Directory]::GetParent([IO.Path]::GetFullPath($Path))
    while ($null -ne $current) {
        $item = Get-Item -LiteralPath $current.FullName -ErrorAction Stop
        if ($item.LinkType -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            Fail 'daily_delta_linked_ancestor_invalid'
        }
        $current = $current.Parent
    }
}

function Assert-OwnerOnlyDirectory([string]$Path) {
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if (-not $item.PSIsContainer -or $item.LinkType -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Fail 'daily_delta_directory_invalid'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]) -ne $identity) { Fail 'daily_delta_directory_owner_invalid' }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if (@($rules | Where-Object { $_.IdentityReference -ne $identity -or $_.AccessControlType -ne 'Allow' }).Count -gt 0 -or
        @($rules | Where-Object { ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
                [Security.AccessControl.FileSystemRights]::FullControl }).Count -eq 0) {
        Fail 'daily_delta_directory_acl_invalid'
    }
}

function Assert-OwnerOnlyFile([string]$Path) {
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or $item.LinkType -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Fail 'daily_delta_template_invalid'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $Path
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]) -ne $identity -or
        @($rules | Where-Object { $_.IdentityReference -ne $identity -or $_.AccessControlType -ne 'Allow' }).Count -gt 0 -or
        @($rules | Where-Object { ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0 }).Count -eq 0) {
        Fail 'daily_delta_template_acl_invalid'
    }
}

function Write-ProtectedConfig([string]$Path, [object]$Config) {
    $json = ConvertTo-Json -InputObject $Config -Depth 100 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes); $stream.Flush($true) } finally { $stream.Dispose() }
}

function Invoke-GuardedCommand([string]$Command, [string]$ConfigPath) {
    & dotnet run --project $consoleProject -c Release --no-build -- $Command --config $ConfigPath
    if ($LASTEXITCODE -ne 0) { Fail "daily_delta_${Command}_failed" }
}

if (-not $IsWindows) { Fail 'daily_delta_windows_host_required' }
if ($env:LEGACY_DEPLOY_ENABLED -cne 'false') { Fail 'daily_delta_deploy_gate_invalid' }
if ($env:LEGACY_MIGRATION_CALLER -notin @('owner', 'operator')) { Fail 'daily_delta_caller_invalid' }
if ($Execute -and $env:LEGACY_MIGRATION_CALLER -cne 'owner') { Fail 'daily_delta_execution_requires_owner' }

$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$template = (Resolve-Path -LiteralPath $TemplatePath).Path
$root = (Resolve-Path -LiteralPath $OutputRoot).Path
Assert-NoLinkAncestors $template
Assert-NoLinkAncestors $root
if ($root.StartsWith($repository.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
    $repository.StartsWith($root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    Fail 'daily_delta_output_must_be_outside_repository'
}
Assert-OwnerOnlyDirectory $root
Assert-OwnerOnlyFile $template

$branch = (& git -C $repository branch --show-current).Trim()
$head = (& git -C $repository rev-parse HEAD).Trim()
$remote = ((& git -C $repository ls-remote origin refs/heads/main) -split '\s+')[0]
if ($branch -cne 'main' -or $head -cne $remote -or
    @(& git -C $repository status --porcelain=v1).Count -gt 0) {
    Fail 'daily_delta_protected_main_required'
}
$ci = & gh api "repos/MALIEV-Co-Ltd/Legacy.Maliev.DataMigration/actions/workflows/ci-main.yml/runs?branch=main&per_page=10" --jq '.workflow_runs[] | [.head_sha, .status, .conclusion] | @tsv'
if ($LASTEXITCODE -ne 0 -or -not @($ci | Where-Object { $_ -ceq "$head`tcompleted`tsuccess" }).Count) {
    Fail 'daily_delta_exact_main_ci_required'
}

$config = Get-Content -LiteralPath $template -Raw | ConvertFrom-Json -AsHashtable
if (-not $config.ContainsKey('delta') -or $config.delta.sourceMode -cne 'live-readonly-comparison' -or
    $config.delta.allowPlanSigning -ne $true) {
    Fail 'daily_delta_template_not_approved_for_live_comparison'
}
$targetKind = $config.delta.targetAuthority.kind
if ($targetKind -notin @('local-aspire', 'production-cloudnativepg')) { Fail 'daily_delta_target_invalid' }
if ($Execute -and $targetKind -eq 'production-cloudnativepg') {
    Fail 'daily_delta_production_requires_separate_plan_review'
}
if ($Execute -and ($config.delta.allowAuthorizationSigning -ne $true -or $config.delta.allowExecution -ne $true)) {
    Fail 'daily_delta_local_execution_not_authorized'
}
$runId = [Guid]::NewGuid().ToString('N')
$runDirectory = Join-Path $root "daily-delta-$runId"
$null = New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop
$acl = Get-Acl -LiteralPath $root
Set-Acl -LiteralPath $runDirectory -AclObject $acl
Assert-OwnerOnlyDirectory $runDirectory

$consoleProject = Join-Path $repository 'src\Legacy.Maliev.DataMigration.Console\Legacy.Maliev.DataMigration.Console.csproj'
& dotnet build $consoleProject -c Release -warnaserror
if ($LASTEXITCODE -ne 0) { Fail 'daily_delta_release_build_failed' }

$planPath = Join-Path $runDirectory 'plan.json'
$authorizationPath = Join-Path $runDirectory 'authorization.json'
function New-PhaseConfig([string]$Phase) {
    $phaseConfig = ($config | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable)
    $phaseConfig.delta.outputPath = Join-Path $runDirectory "$Phase-result.json"
    $phaseConfig.delta.planPath = $planPath
    $phaseConfig.delta.authorizationPath = $authorizationPath
    if ($Phase -eq 'plan') { $phaseConfig.delta.outputPath = $planPath }
    if ($Phase -eq 'authorize') {
        $phaseConfig.delta.outputPath = $authorizationPath
        $phaseConfig.delta.authorizationExpiresAtUtc = [DateTimeOffset]::UtcNow.AddMinutes(15).ToString('o')
    }
    Write-ProtectedConfig (Join-Path $runDirectory "$Phase-config.json") $phaseConfig
}

New-PhaseConfig 'plan'
Invoke-GuardedCommand 'plan-delta' (Join-Path $runDirectory 'plan-config.json')
$plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
if ($plan.schemaVersion -cne '1.2' -or $plan.sourceMode -cne 'live-readonly-comparison' -or
    $plan.sourceObservationSha256 -notmatch '^[0-9a-f]{64}$') {
    Fail 'daily_delta_live_plan_invalid'
}
if (-not $Execute) {
    Write-Output "daily_delta_plan_ready_for_review:$runId"
    return
}

if (@($plan.databases | ForEach-Object { $_.tables } | Where-Object { $_.deleteCount -gt 0 }).Count -gt 0) {
    Fail 'daily_delta_delete_review_required'
}

# The same protected template and distinct short-lived key produce a per-run authorization.
# Production and local targets require separate templates and invocations.
New-PhaseConfig 'authorize'
Invoke-GuardedCommand 'authorize-delta' (Join-Path $runDirectory 'authorize-config.json')
$applyCommand = switch ($targetKind) {
    'local-aspire' { 'apply-delta-local' }
    'production-cloudnativepg' { 'apply-delta-production' }
    default { Fail 'daily_delta_target_invalid' }
}
New-PhaseConfig 'apply'
Invoke-GuardedCommand $applyCommand (Join-Path $runDirectory 'apply-config.json')
New-PhaseConfig 'reconcile'
Invoke-GuardedCommand 'reconcile-delta' (Join-Path $runDirectory 'reconcile-config.json')
Write-Output "daily_delta_reconciled:$runId"
