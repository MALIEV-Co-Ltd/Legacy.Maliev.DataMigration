Set-StrictMode -Version Latest

function ConvertTo-QuotationCopyConnection([string]$Value) {
    $builder = [System.Data.Common.DbConnectionStringBuilder]::new()
    # PowerShell's dynamic member binder can create a "ConnectionString" key
    # instead of assigning the CLR property; call the setter explicitly.
    $builder.set_ConnectionString($Value)
    return $builder
}

function Assert-QuotationCopyName([string]$Name) {
    if ($Name -cnotmatch '^legacy-quotation-proof-[a-z0-9]{12,32}$') {
        throw 'quotation_copy_name_invalid'
    }
}

function Assert-QuotationCopyIdentity([string]$SourceHash, [string]$CopyHash) {
    if ($SourceHash -cnotmatch '^[0-9a-f]{64}$' -or
        $CopyHash -cnotmatch '^[0-9a-f]{64}$' -or
        $SourceHash -ceq $CopyHash) {
        throw 'quotation_copy_identity_invalid'
    }
}

function Assert-QuotationCopyPort([string]$Binding) {
    if ($Binding -cnotmatch '^127\.0\.0\.1:([1-9][0-9]{0,4})$' -or
        [int]$Matches[1] -gt 65535) {
        throw 'quotation_copy_loopback_required'
    }
    return [int]$Matches[1]
}

function Assert-QuotationCopySourceContainer($Container, [string]$ExpectedId) {
    if ($null -eq $Container -or $Container.Id -cne $ExpectedId -or
        $Container.State.Running -ne $true -or
        @($Container.Mounts | Where-Object {
            $_.Type -ceq 'volume' -and $_.Name -ceq 'legacy-maliev-exact23-postgres-data'
        }).Count -ne 1) {
        throw 'quotation_copy_persistent_source_invalid'
    }
}

function Assert-QuotationCopyContainer($Container, [string]$Name, [string]$Volume,
    [string]$RunId, [string]$Nonce, [string]$ExpectedId) {
    if ($null -eq $Container -or $Container.Id -cne $ExpectedId -or
        $Container.Name -cne "/$Name" -or $Container.State.Running -ne $true -or
        $Container.Config.Labels.'maliev.quotation-copy.run-id' -cne $RunId -or
        $Container.Config.Labels.'maliev.quotation-copy.name' -cne $Name -or
        $Container.Config.Labels.'maliev.quotation-copy.nonce' -cne $Nonce -or
        @($Container.Mounts | Where-Object {
            $_.Type -ceq 'volume' -and $_.Name -ceq $Volume -and
            $_.Destination -ceq '/var/lib/postgresql'
        }).Count -ne 1) {
        throw 'quotation_copy_container_identity_invalid'
    }
}

function Assert-QuotationCopyVolume($Volume, [string]$Name, [string]$RunId, [string]$Nonce) {
    if ($null -eq $Volume -or $Volume.Name -cne $Name -or
        $Volume.Labels.'maliev.quotation-copy.run-id' -cne $RunId -or
        $Volume.Labels.'maliev.quotation-copy.name' -cne $Name -or
        $Volume.Labels.'maliev.quotation-copy.nonce' -cne $Nonce) {
        throw 'quotation_copy_volume_identity_invalid'
    }
}

function Remove-QuotationCopyContainerEnvFile([string]$RunDirectory, [string]$Path,
    [string]$ExpectedContainerId, [string]$VerifiedContainerId) {
    $expectedPath = Join-Path $RunDirectory 'quotation-copy-container.env'
    if ($Path -cne $expectedPath -or
        $ExpectedContainerId -cnotmatch '^[0-9a-f]{64}$' -or
        $VerifiedContainerId -cne $ExpectedContainerId) {
        throw 'quotation_copy_env_cleanup_unverified'
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.LinkType -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'quotation_copy_env_cleanup_link_invalid'
    }
    Remove-Item -LiteralPath $Path -Force
}

Export-ModuleMember -Function ConvertTo-QuotationCopyConnection,
    Assert-QuotationCopyName, Assert-QuotationCopyIdentity,
    Assert-QuotationCopyPort, Assert-QuotationCopySourceContainer,
    Assert-QuotationCopyContainer, Assert-QuotationCopyVolume,
    Remove-QuotationCopyContainerEnvFile
