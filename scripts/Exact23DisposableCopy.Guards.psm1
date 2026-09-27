Set-StrictMode -Version Latest

$script:CanonicalDatabases = @(
    'ContactRequest', 'Country', 'Currency', 'Customer', 'CustomerIdentity',
    'DataProtectionKeys', 'DataProtectionKeysEmployee', 'Employee', 'EmployeeIdentity',
    'Invoice', 'JobOffers', 'LocationData', 'Material', 'Message', 'Order',
    'OrderStatus', 'Payment', 'PurchaseOrder', 'Quotation', 'QuotationRequest',
    'Receipt', 'Supplier', 'Upload'
)

function Get-Exact23CopyDatabases { return @($script:CanonicalDatabases) }

function Assert-Exact23CopyInventory([string[]]$Names) {
    $ordered = @($Names | Sort-Object -CaseSensitive)
    if ($ordered.Count -ne $script:CanonicalDatabases.Count -or
        [string]::Join("`n", $ordered) -cne [string]::Join("`n", $script:CanonicalDatabases)) {
        throw 'exact23_copy_inventory_invalid'
    }
}

function Assert-Exact23CopyName([string]$Name) {
    if ($Name -cnotmatch '^legacy-delta-proof-[a-z0-9]{12,32}$') {
        throw 'exact23_copy_name_invalid'
    }
}

function Assert-Exact23CopyIdentity([string]$SourceHash, [string]$CopyHash) {
    if ($SourceHash -cnotmatch '^[0-9a-f]{64}$' -or
        $CopyHash -cnotmatch '^[0-9a-f]{64}$' -or $SourceHash -ceq $CopyHash) {
        throw 'exact23_copy_identity_invalid'
    }
}

function Assert-Exact23CopyPort([string]$Binding) {
    if ($Binding -cnotmatch '^127\.0\.0\.1:([1-9][0-9]{0,4})$' -or
        [int]$Matches[1] -gt 65535) {
        throw 'exact23_copy_loopback_required'
    }
    return [int]$Matches[1]
}

function Assert-Exact23CopySourceContainer($Container, [string]$ExpectedId) {
    if ($null -eq $Container -or $Container.Id -cne $ExpectedId -or
        $Container.State.Running -ne $true -or
        @($Container.Mounts | Where-Object {
            $_.Type -ceq 'volume' -and $_.Name -ceq 'legacy-maliev-exact23-postgres-data' -and
            $_.Destination -ceq '/var/lib/postgresql'
        }).Count -ne 1) {
        throw 'exact23_copy_persistent_source_invalid'
    }
}

function Assert-Exact23CopySyntheticSourceContainer($Container, [string]$ExpectedId,
    [string]$VolumeName) {
    if ($VolumeName -cnotmatch '^legacy-delta-synthetic-source-[a-z0-9]{12,32}$' -or
        $null -eq $Container -or $Container.Id -cne $ExpectedId -or
        $Container.State.Running -ne $true -or
        $Container.Config.Labels.'maliev.exact23-copy.synthetic-source' -cne 'true' -or
        @($Container.Mounts | Where-Object { $_.Type -ceq 'volume' }).Count -ne 1 -or
        @($Container.Mounts | Where-Object {
            $_.Type -ceq 'volume' -and $_.Name -ceq $VolumeName -and
            $_.Destination -ceq '/var/lib/postgresql'
        }).Count -ne 1) {
        throw 'exact23_copy_synthetic_source_invalid'
    }
}

function Assert-Exact23CopyContainer($Container, [string]$Name, [string]$RunId,
    [string]$Nonce, [string]$ExpectedId, [string]$ImageReference) {
    if ($null -eq $Container -or $Container.Id -cne $ExpectedId -or
        $Container.Name -cne "/$Name" -or $Container.State.Running -ne $true -or
        $Container.Config.Image -cne $ImageReference -or
        $Container.Config.Labels.'maliev.exact23-copy.run-id' -cne $RunId -or
        $Container.Config.Labels.'maliev.exact23-copy.name' -cne $Name -or
        $Container.Config.Labels.'maliev.exact23-copy.nonce' -cne $Nonce -or
        @($Container.Mounts | Where-Object {
            $_.Type -ceq 'volume' -and $_.Name -ceq $Name -and
            $_.Destination -ceq '/var/lib/postgresql'
        }).Count -ne 1) {
        throw 'exact23_copy_container_identity_invalid'
    }
}

function Assert-Exact23CopyVolume($Volume, [string]$Name, [string]$RunId, [string]$Nonce) {
    if ($null -eq $Volume -or $Volume.Name -cne $Name -or
        $Volume.Labels.'maliev.exact23-copy.run-id' -cne $RunId -or
        $Volume.Labels.'maliev.exact23-copy.name' -cne $Name -or
        $Volume.Labels.'maliev.exact23-copy.nonce' -cne $Nonce) {
        throw 'exact23_copy_volume_identity_invalid'
    }
}

function Assert-Exact23CopyDigest([string]$Before, [string]$After, [string]$Copy) {
    if ($Before -cnotmatch '^[0-9a-f]{64}$' -or $After -cnotmatch '^[0-9a-f]{64}$' -or
        $Copy -cnotmatch '^[0-9a-f]{64}$' -or $Before -cne $After -or $Before -cne $Copy) {
        throw 'exact23_copy_preimage_changed'
    }
}

function Get-Exact23CopyRowCount([string]$DumpPath) {
    $reader = [IO.StreamReader]::new($DumpPath)
    try {
        [long]$count = 0
        $insideCopy = $false
        while ($null -ne ($line = $reader.ReadLine())) {
            if ($insideCopy) {
                if ($line -ceq '\.') { $insideCopy = $false }
                else {
                    if ($count -eq [long]::MaxValue) { throw 'exact23_copy_row_count_overflow' }
                    $count++
                }
            }
            elseif ($line -cmatch '^COPY .+ FROM stdin;$') { $insideCopy = $true }
        }
        if ($insideCopy) { throw 'exact23_copy_dump_incomplete' }
        return $count
    }
    finally { $reader.Dispose() }
}

Export-ModuleMember -Function Get-Exact23CopyDatabases, Assert-Exact23CopyInventory,
    Assert-Exact23CopyName, Assert-Exact23CopyIdentity, Assert-Exact23CopyPort,
    Assert-Exact23CopySourceContainer, Assert-Exact23CopySyntheticSourceContainer,
    Assert-Exact23CopyContainer,
    Assert-Exact23CopyVolume, Assert-Exact23CopyDigest, Get-Exact23CopyRowCount
