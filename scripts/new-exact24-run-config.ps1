[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $OutputRoot,
    [Parameter(Mandatory)] [ValidatePattern('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')] [string] $SourceNamespace,
    [Parameter(Mandatory)] [ValidatePattern('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')] [string] $ExpectedPodName,
    [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')] [string] $ExpectedPodUid,
    [Parameter(Mandatory)] [ValidatePattern('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')] [string] $ContainerName,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{40}$')] [string] $ReviewedSourceCommitSha,
    [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{2,61}$')] [string] $GcsBucket,
    [Parameter(Mandatory)] [ValidatePattern('^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$')] [string] $StagingImage,
    [Parameter(Mandatory)] [ValidatePattern('^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$')] [string] $SqlServerImage,
    [Parameter(Mandatory)] [ValidatePattern('^sha256:[0-9a-f]{64}$')] [string] $SqlServerImageId,
    [Parameter(Mandatory)] [string] $PgDumpPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-AbsolutePath([string] $Value, [string] $Name) {
    if (-not [System.IO.Path]::IsPathFullyQualified($Value)) {
        throw "$Name must be an absolute path."
    }
}

function Assert-NoLinkAncestors([string] $Path) {
    $current = [System.IO.DirectoryInfo]::new([System.IO.Path]::GetFullPath($Path))
    while ($null -ne $current) {
        $current.Refresh()
        if ($current.Exists -and ($null -ne $current.LinkTarget -or (($current.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0))) {
            throw "The bootstrap path contains a symbolic link or reparse point: $($current.FullName)"
        }
        $current = $current.Parent
    }
}

function New-OwnerOnlyDirectory([string] $Path) {
    if ([System.IO.Directory]::Exists($Path) -or [System.IO.File]::Exists($Path)) {
        throw "Refusing to overwrite existing path: $Path"
    }

    if ($IsWindows) {
        $owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        if ($null -eq $owner) { throw 'The current Windows owner identity is unavailable.' }
        $security = [System.Security.AccessControl.DirectorySecurity]::new()
        $security.SetOwner($owner)
        $security.SetAccessRuleProtection($true, $false)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $owner,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
        [System.IO.FileSystemAclExtensions]::Create([System.IO.DirectoryInfo]::new($Path), $security)
        return
    }

    [System.IO.Directory]::CreateDirectory(
        $Path,
        [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite -bor [System.IO.UnixFileMode]::UserExecute) | Out-Null
}

function Assert-OwnerOnlyDirectory([string] $Path) {
    if (-not [System.IO.Directory]::Exists($Path)) { throw "Owner-only directory is missing: $Path" }
    if ($IsWindows) {
        $owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $security = [System.IO.FileSystemAclExtensions]::GetAccessControl([System.IO.DirectoryInfo]::new($Path))
        if ($null -eq $owner -or -not $owner.Equals($security.GetOwner([System.Security.Principal.SecurityIdentifier])) -or -not $security.AreAccessRulesProtected) {
            throw "Directory is not protected for the current owner: $Path"
        }
        $rules = $security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        foreach ($rule in $rules) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Deny -and -not $owner.Equals($rule.IdentityReference)) {
                throw "Directory grants access to a non-owner identity: $Path"
            }
        }
        return
    }
    $mode = [System.IO.File]::GetUnixFileMode($Path)
    $expected = [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite -bor [System.IO.UnixFileMode]::UserExecute
    if ($mode -ne $expected) { throw "Directory mode must be 0700: $Path" }
}

function Write-NewOwnerOnlyText([string] $Path, [string] $Value) {
    $options = [System.IO.FileStreamOptions]::new()
    $options.Mode = [System.IO.FileMode]::CreateNew
    $options.Access = [System.IO.FileAccess]::Write
    $options.Share = [System.IO.FileShare]::None
    $options.Options = [System.IO.FileOptions]::WriteThrough
    if (-not $IsWindows) {
        $options.UnixCreateMode = [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
    }
    $stream = [System.IO.FileStream]::new($Path, $options)
    try {
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false), 1024, $true)
        try { $writer.Write($Value); $writer.Flush(); $stream.Flush($true) }
        finally { $writer.Dispose() }
    }
    finally { $stream.Dispose() }
}

function New-SigningRole([string] $Role, [string] $KeysDirectory, [string] $RunId) {
    $keyId = "$RunId-$Role"
    $privatePath = Join-Path $KeysDirectory "$Role.private.pem"
    $publicPath = Join-Path $KeysDirectory "$Role.public.spki.b64"
    $curve = [System.Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7')
    $key = [System.Security.Cryptography.ECDsa]::Create($curve)
    try {
        $privatePem = $key.ExportPkcs8PrivateKeyPem()
        $publicBytes = $key.ExportSubjectPublicKeyInfo()
        try {
            Write-NewOwnerOnlyText $privatePath ($privatePem + [Environment]::NewLine)
            Write-NewOwnerOnlyText $publicPath ([Convert]::ToBase64String($publicBytes) + [Environment]::NewLine)
            $fingerprint = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($publicBytes)).ToLowerInvariant()
            return [ordered]@{ keyId = $keyId; privateKeyPath = $privatePath; publicKeyPath = $publicPath; fingerprint = $fingerprint }
        }
        finally { [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($publicBytes) }
    }
    finally { $key.Dispose() }
}

Assert-AbsolutePath $OutputRoot 'OutputRoot'
Assert-AbsolutePath $PgDumpPath 'PgDumpPath'
Assert-NoLinkAncestors $OutputRoot

$root = [System.IO.Path]::GetFullPath($OutputRoot)
if (-not [System.IO.Directory]::Exists($root)) {
    $parent = [System.IO.Path]::GetDirectoryName($root)
    if ([string]::IsNullOrWhiteSpace($parent) -or -not [System.IO.Directory]::Exists($parent)) {
        throw 'OutputRoot parent must already exist and must not be a link.'
    }
    New-OwnerOnlyDirectory $root
}
Assert-NoLinkAncestors $root
Assert-OwnerOnlyDirectory $root

$issuedAt = [DateTimeOffset]::UtcNow
$runGuid = [Guid]::NewGuid()
$runId = 'exact24-' + $issuedAt.ToString('yyyyMMddHHmmss', [Globalization.CultureInfo]::InvariantCulture) + '-' + $runGuid.ToString('N')
$runDirectory = Join-Path $root $runId
New-OwnerOnlyDirectory $runDirectory

try {
    $keysDirectory = Join-Path $runDirectory 'keys'
    $artifactsDirectory = Join-Path $runDirectory 'artifacts'
    New-OwnerOnlyDirectory $keysDirectory
    New-OwnerOnlyDirectory $artifactsDirectory
    foreach ($name in @('backup-work', 'restore', 'plan', 'authorization', 'execution', 'cleanup', 'provenance')) {
        New-OwnerOnlyDirectory (Join-Path $artifactsDirectory $name)
    }
    New-OwnerOnlyDirectory (Join-Path (Join-Path $artifactsDirectory 'cleanup') 'failures')

    $roles = [ordered]@{}
    foreach ($role in @('backup', 'authorization', 'execution', 'provenance', 'final-evidence')) {
        $roles[$role] = New-SigningRole $role $keysDirectory $runId
    }
    if (($roles.Values.fingerprint | Sort-Object -Unique).Count -ne 5) {
        throw 'Generated signing roles are not pairwise distinct.'
    }

    $snapshotKeyPath = Join-Path $keysDirectory 'snapshot-root-key.b64'
    $snapshotKey = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($snapshotKey)
    try { Write-NewOwnerOnlyText $snapshotKeyPath ([Convert]::ToBase64String($snapshotKey) + [Environment]::NewLine) }
    finally { [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($snapshotKey) }

    function PublicReference([System.Collections.IDictionary] $Role) { [ordered]@{ keyId = $Role.keyId; subjectPublicKeyInfoPath = $Role.publicKeyPath } }
    $backupTrust = @(PublicReference $roles.backup)
    $authorizationTrust = @(PublicReference $roles.authorization)
    $executionTrust = @(PublicReference $roles.execution)
    $provenanceTrust = @(PublicReference $roles.provenance)

    $backupWorkingDirectory = Join-Path $artifactsDirectory 'backup-work'
    $backupPublicationDirectory = Join-Path $artifactsDirectory 'backup-receipt'
    $restoreDirectory = Join-Path $artifactsDirectory 'restore'
    $planPath = Join-Path (Join-Path $artifactsDirectory 'plan') 'schema-plan.json'
    $authorizationPath = Join-Path (Join-Path $artifactsDirectory 'authorization') 'execution-authorization.json'
    $executionPath = Join-Path (Join-Path $artifactsDirectory 'execution') 'execution-result.json'
    $snapshotDirectory = Join-Path $artifactsDirectory 'snapshot'
    $snapshotManifestPath = Join-Path $snapshotDirectory 'manifest.json'
    $cleanupAuthorizationPath = Join-Path (Join-Path $artifactsDirectory 'authorization') 'cleanup-authorization.json'
    $cleanupReceiptPath = Join-Path (Join-Path $artifactsDirectory 'cleanup') 'shadow-cleanup-receipt.json'
    $provenancePath = Join-Path (Join-Path $artifactsDirectory 'provenance') 'migration-provenance.json'
    $verifiedRestorePath = Join-Path $restoreDirectory 'verified-restore-receipt.json'
    $finalRestorePath = Join-Path $restoreDirectory 'final-verified-restore-receipt.json'
    $receiptPath = Join-Path $backupPublicationDirectory 'backup-receipt.json'
    $reviewRequired = 'REVIEW_REQUIRED_AFTER_FRESH_PLAN'
    $evidenceId = [Guid]::NewGuid()
    $leaseId = [Guid]::NewGuid()

    $config = [ordered]@{
        plan = [ordered]@{ outputPath = $planPath; sourceCommitSha = $ReviewedSourceCommitSha }
        executeShadow = [ordered]@{
            receiptPath = $receiptPath; planPath = $planPath; authorizationPath = $authorizationPath; outputPath = $executionPath
            receiptTrustedKeys = $backupTrust; authorizationTrustedKeys = $authorizationTrust; evidenceKeyId = $roles.execution.keyId
            expectedControlRole = 'legacy_migration_control'; expectedShadowAdminRole = 'legacy_migration_shadow'
        }
        evidence = [ordered]@{
            executionResultPath = $executionPath; provenancePath = $provenancePath; receiptPath = $receiptPath; planPath = $planPath
            authorizationPath = $authorizationPath; cleanupReceiptPath = $cleanupReceiptPath
            publicationDirectory = (Join-Path $artifactsDirectory 'evidence'); sourceSnapshotId = $reviewRequired; backupUri = $reviewRequired
            backupObjectGeneration = $reviewRequired; restoreId = $runId; evidenceId = $evidenceId; leaseId = $leaseId
            leaseAcquiredAtUtc = $issuedAt; leaseExpiresAtUtc = $issuedAt
            backupTrustedKeys = $backupTrust; authorizationTrustedKeys = $authorizationTrust; executionTrustedKeys = $executionTrust
            provenanceTrustedKeys = $provenanceTrust; evidenceKeyId = $roles.'final-evidence'.keyId; verifiedRestoreReceiptPath = $finalRestorePath
        }
        exportLocalSnapshot = [ordered]@{ executionResultPath = $executionPath; outputDirectory = $snapshotDirectory; pgDumpPath = [System.IO.Path]::GetFullPath($PgDumpPath) }
        cleanupShadows = [ordered]@{
            executionResultPath = $executionPath; receiptPath = $receiptPath; planPath = $planPath
            cleanupAuthorizationPath = $cleanupAuthorizationPath; snapshotManifestPath = $snapshotManifestPath
            outputPath = $cleanupReceiptPath; failurePublicationDirectory = (Join-Path (Join-Path $artifactsDirectory 'cleanup') 'failures')
            receiptTrustedKeys = $backupTrust; authorizationTrustedKeys = $authorizationTrust
            evidenceKeyId = $roles.execution.keyId; expectedShadowAdminRole = 'legacy_migration_shadow'
        }
        fullBackup = [ordered]@{
            namespace = $SourceNamespace; expectedPodName = $ExpectedPodName; expectedPodUid = $ExpectedPodUid; containerName = $ContainerName
            gcsPrefix = "gs://$GcsBucket/database/full/$($issuedAt.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture))/$runId/"
            localWorkingDirectory = $backupWorkingDirectory; runId = $runId; approvedRunUtc = $issuedAt; maximumTransportAttempts = 3
            publicationDirectory = $backupPublicationDirectory; keyId = $roles.backup.keyId; allowSourceBackup = $false
        }
        restoreBackups = [ordered]@{
            receiptPath = $receiptPath; recoveryDirectory = $restoreDirectory; sqlServerDataDirectory = '/var/opt/mssql/data'
            sqlServerVisibleRecoveryDirectory = '/var/opt/mssql/recovery'; stagingVolumeName = "legacy-restore-$($runGuid.ToString('N'))"
            stagingImage = $StagingImage; sqlServerContainerName = "legacy-sqlrestore-$($runGuid.ToString('N').Substring(0, 20))"
            sqlServerImageId = $SqlServerImageId; sqlServerImage = $SqlServerImage; runBinding = $runGuid.ToString('D')
            maximumReceiptAgeMinutes = 180; receiptTrustedKeys = $backupTrust; verifiedRestoreReceiptPath = $verifiedRestorePath
            finalVerifiedRestoreReceiptPath = $finalRestorePath; provenanceKeyId = $roles.provenance.keyId; provenanceTrustedKeys = $provenanceTrust
        }
        authorizeShadow = [ordered]@{
            receiptPath = $receiptPath; planPath = $planPath; outputPath = $authorizationPath; expectedSourceCommitSha = $ReviewedSourceCommitSha
            reviewedSchemaPlanSha256 = $reviewRequired; issuedAtUtc = $issuedAt; expiresAtUtc = $issuedAt; keyId = $roles.authorization.keyId
            receiptTrustedKeys = $backupTrust; maximumReceiptAgeMinutes = 180; allowShadowAuthorization = $false
        }
        authorizeCleanup = [ordered]@{
            executionResultPath = $executionPath; snapshotManifestPath = $snapshotManifestPath; outputPath = $cleanupAuthorizationPath
            issuedAtUtc = $issuedAt; expiresAtUtc = $issuedAt; keyId = $roles.authorization.keyId; allowCleanupAuthorization = $false
        }
        signProvenance = [ordered]@{
            outputPath = $provenancePath; reviewedSchemaPlanSha256 = $reviewRequired; issuedAtUtc = $issuedAt
            keyId = $roles.provenance.keyId; allowProvenanceSigning = $false
        }
        quotationSchemaBaseline = $null
        quotationPostgreSqlSnapshot = $null
        signingRoles = [ordered]@{
            backup = PublicReference $roles.backup; authorization = PublicReference $roles.authorization
            execution = PublicReference $roles.execution; provenance = PublicReference $roles.provenance
            finalEvidence = PublicReference $roles.'final-evidence'
        }
    }

    $configPath = Join-Path $runDirectory 'run-config.json'
    Write-NewOwnerOnlyText $configPath (($config | ConvertTo-Json -Depth 20) + [Environment]::NewLine)
    [pscustomobject]@{
        runId = $runId
        runDirectory = $runDirectory
        configPath = $configPath
        snapshotKeyPath = $snapshotKeyPath
        signingKeyPaths = [ordered]@{
            backup = $roles.backup.privateKeyPath; authorization = $roles.authorization.privateKeyPath
            execution = $roles.execution.privateKeyPath; provenance = $roles.provenance.privateKeyPath
            finalEvidence = $roles.'final-evidence'.privateKeyPath
        }
    } | ConvertTo-Json -Depth 5
}
catch {
    # The unique directory was never published before creation and is owned only by
    # this operator. Remove an incomplete bootstrap so it cannot be mistaken for a
    # reviewable run. No pre-existing path is ever removed.
    if ([System.IO.Directory]::Exists($runDirectory)) {
        [System.IO.Directory]::Delete($runDirectory, $true)
    }
    throw
}
