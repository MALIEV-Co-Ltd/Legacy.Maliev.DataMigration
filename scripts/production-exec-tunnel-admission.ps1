function Assert-ProductionExecTunnelIdentity {
    param(
        [Parameter(Mandatory = $true)][psobject]$Config,
        [Parameter(Mandatory = $true)][psobject]$Cluster,
        [Parameter(Mandatory = $true)][psobject]$Pod,
        [Parameter(Mandatory = $true)][psobject]$Process,
        [Parameter(Mandatory = $true)][string]$Assembly,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][int]$Port
    )

    if ($Config.context -cne 'gke_maliev-website_us-central1-a_web-production-cluster' -or
        $Config.clusterUid -cne $Cluster.metadata.uid -or
        $Config.clusterGeneration -ne $Cluster.metadata.generation -or
        $Config.primaryPod -cne $Cluster.status.currentPrimary -or
        $Config.primaryPodUid -cne $Pod.metadata.uid -or
        $Config.listenPort -ne $Port) {
        throw 'production_delta_exec_target_drift'
    }
    if ($Process.Name -cnotmatch '^dotnet(\.exe)?$' -or
        $Process.CommandLine -cnotmatch [regex]::Escape($Assembly) -or
        $Process.CommandLine -cnotmatch ' cnpg-exec-tunnel --config ' -or
        $Process.CommandLine -cnotmatch [regex]::Escape($ConfigPath)) {
        throw 'production_delta_tunnel_identity_invalid'
    }
}

function Assert-ProductionExecTunnelDurability {
    param(
        [Parameter(Mandatory = $true)][string[]]$Databases,
        [Parameter(Mandatory = $true)][string]$ExpectedSystemIdentifier,
        [Parameter(Mandatory = $true)][scriptblock]$Query
    )

    if ($Databases.Count -ne 23 -or
        @($Databases | Select-Object -Unique).Count -ne 23 -or
        $ExpectedSystemIdentifier -cnotmatch '^\d+$') {
        throw 'production_delta_tunnel_preflight_invalid'
    }
    foreach ($database in $Databases) {
        try { $result = & $Query $database }
        catch { throw 'production_delta_tunnel_durability_failed' }
        if ($null -eq $result -or $result.ExitCode -ne 0 -or
            @($result.Lines).Count -ne 1 -or
            [string]$result.Lines[0] -cne $ExpectedSystemIdentifier) {
            throw 'production_delta_tunnel_durability_failed'
        }
    }
}
