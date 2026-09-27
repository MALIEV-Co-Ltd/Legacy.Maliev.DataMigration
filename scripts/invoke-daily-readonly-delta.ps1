param(
    [Parameter(Mandatory = $true)][string]$TemplatePath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [switch]$Execute,
    [switch]$PlanPaired,
    [switch]$ExecutePairedLocal
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

function Write-ProtectedRawJson([string]$Path, [string]$Json) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Json)
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes); $stream.Flush($true) } finally { $stream.Dispose() }
}

function Invoke-GuardedCommand([string]$Command, [string]$ConfigPath) {
    & dotnet run --project $consoleProject -c Release --no-build -- $Command --config $ConfigPath
    if ($LASTEXITCODE -ne 0) { Fail "daily_delta_${Command}_failed" }
}

function Invoke-GuardedWithPersistentSigner([string]$Command, [string]$ConfigPath,
    [string]$DisposableVariable, [string]$PersistentVariable) {
    $original = [Environment]::GetEnvironmentVariable($DisposableVariable, 'Process')
    $persistent = [Environment]::GetEnvironmentVariable($PersistentVariable, 'Process')
    if ([string]::IsNullOrWhiteSpace($original) -or [string]::IsNullOrWhiteSpace($persistent) -or
        [string]::Equals($original, $persistent, [StringComparison]::OrdinalIgnoreCase)) {
        Fail 'daily_delta_persistent_signer_projection_invalid'
    }
    try {
        [Environment]::SetEnvironmentVariable($DisposableVariable, $persistent, 'Process')
        Invoke-GuardedCommand $Command $ConfigPath
    }
    finally {
        [Environment]::SetEnvironmentVariable($DisposableVariable, $original, 'Process')
    }
}

if (-not $IsWindows) { Fail 'daily_delta_windows_host_required' }
if ($env:LEGACY_DEPLOY_ENABLED -cne 'false') { Fail 'daily_delta_deploy_gate_invalid' }
if ($env:LEGACY_MIGRATION_CALLER -notin @('owner', 'operator')) { Fail 'daily_delta_caller_invalid' }
if ($Execute -and $env:LEGACY_MIGRATION_CALLER -cne 'owner') { Fail 'daily_delta_execution_requires_owner' }
if ($PlanPaired -and $Execute) { Fail 'daily_delta_paired_plan_only' }
if ($ExecutePairedLocal -and ($Execute -or $PlanPaired)) { Fail 'daily_delta_paired_mode_conflict' }
if (($PlanPaired -or $ExecutePairedLocal) -and $env:LEGACY_MIGRATION_CALLER -cne 'owner') {
    Fail 'daily_delta_paired_requires_owner'
}

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
if ($config.delta.ContainsKey('useCapturedSource') -and $config.delta.useCapturedSource -isnot [bool]) {
    Fail 'daily_delta_capture_mode_invalid'
}
$useCapturedSource = $config.delta.ContainsKey('useCapturedSource') -and $config.delta.useCapturedSource -eq $true
if ($config.delta.ContainsKey('useQuotationPhysicalTransition') -and
    $config.delta.useQuotationPhysicalTransition -isnot [bool]) {
    Fail 'daily_delta_quotation_transition_mode_invalid'
}
$useQuotationPhysicalTransition = $config.delta.ContainsKey('useQuotationPhysicalTransition') -and
    $config.delta.useQuotationPhysicalTransition -eq $true
$targetKind = $config.delta.targetAuthority.kind
if ($targetKind -notin @('local-aspire', 'production-cloudnativepg')) { Fail 'daily_delta_target_invalid' }
if (($PlanPaired -or $ExecutePairedLocal) -and (-not $useCapturedSource -or
    $targetKind -cne 'local-aspire' -or
    -not $config.delta.targetAuthority.authorityId.StartsWith(
        'aspire://legacy-postgres-main-local/disposable-', [StringComparison]::Ordinal) -or
    -not $config.delta.ContainsKey('pairedPersistentTarget'))) {
    Fail 'daily_delta_paired_request_invalid'
}
if (-not $PlanPaired -and -not $ExecutePairedLocal -and $config.delta.ContainsKey('pairedPersistentTarget')) {
    Fail 'daily_delta_paired_command_required'
}
if ($ExecutePairedLocal -and (-not $useQuotationPhysicalTransition -or
    $config.delta.allowAuthorizationSigning -ne $true -or $config.delta.allowExecution -ne $true -or
    $config.delta.pairedPersistentTarget.targetAuthority.kind -cne 'local-aspire' -or
    -not $config.delta.pairedPersistentTarget.targetAuthority.authorityId.StartsWith(
        'aspire://legacy-postgres-main-local/persistent-', [StringComparison]::Ordinal))) {
    Fail 'daily_delta_paired_local_execution_invalid'
}
if ($useQuotationPhysicalTransition -and
    (-not $useCapturedSource -or $targetKind -cne 'local-aspire' -or
     -not $config.delta.targetAuthority.authorityId.StartsWith(
        'aspire://legacy-postgres-main-local/disposable-', [StringComparison]::Ordinal))) {
    Fail 'daily_delta_quotation_transition_disposable_only'
}
if ($Execute -and $targetKind -eq 'production-cloudnativepg') {
    Fail 'daily_delta_production_requires_separate_plan_review'
}
if ($Execute -and ($config.delta.allowAuthorizationSigning -ne $true -or $config.delta.allowExecution -ne $true)) {
    Fail 'daily_delta_local_execution_not_authorized'
}
$disposableCaptureExecution = $Execute -and $useCapturedSource -and
    $targetKind -eq 'local-aspire' -and
    $config.delta.targetAuthority.authorityId.StartsWith(
        'aspire://legacy-postgres-main-local/disposable-', [StringComparison]::Ordinal)
if ($Execute -and $useCapturedSource -and -not $disposableCaptureExecution) {
    Fail 'daily_delta_captured_execution_not_proven'
}
$runId = [Guid]::NewGuid().ToString('N')
$runDirectory = Join-Path $root "daily-delta-$runId"
$null = New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop
$acl = Get-Acl -LiteralPath $root
Set-Acl -LiteralPath $runDirectory -AclObject $acl
Assert-OwnerOnlyDirectory $runDirectory

if ($useCapturedSource) {
    if (-not [string]::IsNullOrWhiteSpace($config.delta.captureDirectory) -or
        -not [string]::IsNullOrWhiteSpace($config.delta.captureKeyFile)) {
        Fail 'daily_delta_stale_capture_material_invalid'
    }
    $captureDirectory = Join-Path $runDirectory 'captures'
    $null = New-Item -ItemType Directory -Path $captureDirectory -ErrorAction Stop
    Set-Acl -LiteralPath $captureDirectory -AclObject $acl
    Assert-OwnerOnlyDirectory $captureDirectory
    $captureKeyFile = Join-Path $runDirectory 'capture-key.bin'
    $captureKey = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    try {
        $keyStream = [IO.FileStream]::new($captureKeyFile, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $keyStream.Write($captureKey); $keyStream.Flush($true) } finally { $keyStream.Dispose() }
    }
    finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($captureKey)
    }
    Assert-OwnerOnlyFile $captureKeyFile
    $config.delta.captureDirectory = $captureDirectory
    $config.delta.captureKeyFile = $captureKeyFile
}

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
if ($PlanPaired -or $ExecutePairedLocal) {
    Invoke-GuardedCommand 'plan-paired-delta' (Join-Path $runDirectory 'plan-config.json')
    Assert-OwnerOnlyFile $planPath
    $pair = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
    $pairedVersion = if ($useQuotationPhysicalTransition) { '1.4' } else { '1.3' }
    if ($pair.disposable.schemaVersion -cne $pairedVersion -or
        $pair.persistent.schemaVersion -cne $pairedVersion -or
        @($pair.disposable.databases | ForEach-Object { $_.tables } |
            Where-Object { $_.deleteCount -gt 0 }).Count -gt 0 -or
        @($pair.persistent.databases | ForEach-Object { $_.tables } |
            Where-Object { $_.deleteCount -gt 0 }).Count -gt 0) {
        Fail 'daily_delta_paired_plan_invalid'
    }
    if ($PlanPaired) {
        Write-Output "daily_delta_paired_plans_ready_for_review:$runId"
        return
    }

    # The exact signed pair remains the sole capture authority for both targets.
    # Every phase has a new protected config/output and the local phase begins
    # only after the independent disposable reconciliation has been published.
    $disposablePlanPath = Join-Path $runDirectory 'disposable-plan.json'
    $disposableAuthorizationPath = Join-Path $runDirectory 'disposable-authorization.json'
    $disposableProofPath = Join-Path $runDirectory 'disposable-proof.json'
    $localAuthorizationPath = Join-Path $runDirectory 'local-authorization.json'
    $pairDocument = [Text.Json.JsonDocument]::Parse((Get-Content -LiteralPath $planPath -Raw))
    try {
        Write-ProtectedRawJson $disposablePlanPath $pairDocument.RootElement.GetProperty('disposable').GetRawText()
    }
    finally { $pairDocument.Dispose() }
    Assert-OwnerOnlyFile $disposablePlanPath

    function New-PairedPhaseConfig([string]$Phase) {
        $phaseConfig = ($config | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable)
        $null = $phaseConfig.delta.Remove('pairedPersistentTarget')
        $phaseConfig.delta.allowPlanSigning = $false
        $phaseConfig.delta.allowAuthorizationSigning = $Phase -in @('disposable-authorize', 'local-authorize')
        $phaseConfig.delta.allowExecution = $Phase -in @('disposable-apply', 'local-apply')
        $phaseConfig.delta.outputPath = Join-Path $runDirectory "$Phase-result.json"
        if ($Phase.StartsWith('disposable-', [StringComparison]::Ordinal)) {
            $phaseConfig.delta.planPath = $disposablePlanPath
            $phaseConfig.delta.authorizationPath = $disposableAuthorizationPath
        }
        else {
            $persistent = $config.delta.pairedPersistentTarget
            foreach ($field in @('targetConnectionFile', 'targetNamespace', 'targetCluster',
                    'targetGeneration', 'targetObservationSha256', 'targetAuthority',
                    'planKey', 'authorizationKey', 'evidenceKey')) {
                $phaseConfig.delta[$field] = $persistent[$field]
            }
            $phaseConfig.delta.disposableProofPairPath = $planPath
            $phaseConfig.delta.disposableProofResultPath = $disposableProofPath
            $phaseConfig.delta.disposableProofPlanKey = $config.delta.planKey
            $phaseConfig.delta.disposableProofEvidenceKey = $config.delta.evidenceKey
            $phaseConfig.delta.authorizationPath = $localAuthorizationPath
        }
        switch ($Phase) {
            'disposable-authorize' {
                $phaseConfig.delta.outputPath = $disposableAuthorizationPath
                $phaseConfig.delta.authorizationExpiresAtUtc = [DateTimeOffset]::UtcNow.AddMinutes(15).ToString('o')
            }
            'disposable-reconcile' { $phaseConfig.delta.outputPath = $disposableProofPath }
            'local-authorize' {
                $phaseConfig.delta.outputPath = $localAuthorizationPath
                $phaseConfig.delta.authorizationExpiresAtUtc = [DateTimeOffset]::UtcNow.AddMinutes(15).ToString('o')
            }
        }
        $path = Join-Path $runDirectory "$Phase-config.json"
        Write-ProtectedConfig $path $phaseConfig
        Assert-OwnerOnlyFile $path
        return $path
    }

    $phasePath = New-PairedPhaseConfig 'disposable-authorize'
    Invoke-GuardedCommand 'authorize-delta' $phasePath
    Assert-OwnerOnlyFile $disposableAuthorizationPath
    $phasePath = New-PairedPhaseConfig 'disposable-apply'
    Invoke-GuardedCommand 'apply-delta-local' $phasePath
    Assert-OwnerOnlyFile (Join-Path $runDirectory 'disposable-apply-result.json')
    $phasePath = New-PairedPhaseConfig 'disposable-reconcile'
    Invoke-GuardedCommand 'reconcile-delta' $phasePath
    Assert-OwnerOnlyFile $disposableProofPath
    $phasePath = New-PairedPhaseConfig 'local-authorize'
    Invoke-GuardedWithPersistentSigner 'authorize-paired-local-transition' $phasePath `
        'LEGACY_MIGRATION_DELTA_AUTHORIZATION_SIGNING_KEY_FILE' `
        'LEGACY_MIGRATION_PERSISTENT_DELTA_AUTHORIZATION_SIGNING_KEY_FILE'
    Assert-OwnerOnlyFile $localAuthorizationPath
    $phasePath = New-PairedPhaseConfig 'local-preflight'
    Invoke-GuardedCommand 'preflight-paired-local-transition' $phasePath
    Assert-OwnerOnlyFile (Join-Path $runDirectory 'local-preflight-result.json')
    $phasePath = New-PairedPhaseConfig 'local-apply'
    Invoke-GuardedWithPersistentSigner 'apply-paired-local-transition' $phasePath `
        'LEGACY_MIGRATION_DELTA_EVIDENCE_SIGNING_KEY_FILE' `
        'LEGACY_MIGRATION_PERSISTENT_DELTA_EVIDENCE_SIGNING_KEY_FILE'
    Assert-OwnerOnlyFile (Join-Path $runDirectory 'local-apply-result.json')
    Write-Output "daily_delta_paired_local_signed_result_ready_for_review:$runId"
    return
}
Invoke-GuardedCommand 'plan-delta' (Join-Path $runDirectory 'plan-config.json')
$plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
$expectedVersion = if ($useQuotationPhysicalTransition) { '1.4' } elseif ($useCapturedSource) { '1.3' } else { '1.2' }
if ($plan.schemaVersion -cne $expectedVersion -or $plan.sourceMode -cne 'live-readonly-comparison' -or
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

if (-not $disposableCaptureExecution) {
    if ([string]::IsNullOrWhiteSpace($config.delta.disposableProofPlanPath) -or
        [string]::IsNullOrWhiteSpace($config.delta.disposableProofResultPath)) {
        Fail 'daily_delta_disposable_proof_required'
    }
    New-PhaseConfig 'proof'
    Invoke-GuardedCommand 'verify-disposable-delta-proof' (Join-Path $runDirectory 'proof-config.json')
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
