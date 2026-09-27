$module = Join-Path $PSScriptRoot '../scripts/Exact23DisposableCopy.Guards.psm1'
Import-Module $module -Force

function Test-Throws([scriptblock]$Action) {
    try { & $Action | Out-Null; return $false }
    catch { return $true }
}

Describe 'Exact-23 disposable copy guards' {
    It 'requires the exact canonical database set with no extra or duplicate' {
        $names = @(Get-Exact23CopyDatabases)
        $names.Count | Should Be 23
        (Test-Throws { Assert-Exact23CopyInventory $names }) | Should Be $false
        (Test-Throws { Assert-Exact23CopyInventory $names[0..21] }) | Should Be $true
        (Test-Throws { Assert-Exact23CopyInventory @($names + 'Unknown') }) | Should Be $true
        (Test-Throws { Assert-Exact23CopyInventory @($names[0..21] + $names[0]) }) | Should Be $true
    }

    It 'admits only exact-23 plus Auth and the observed source role database' {
        $names = @(Get-Exact23CopyDatabases)
        (Test-Throws { Assert-Exact23CopySourceInventory @($names + 'Auth' + 'legacy_local') 'legacy_local' }) | Should Be $false
        (Test-Throws { Assert-Exact23CopySourceInventory @($names + 'Unknown') 'legacy_local' }) | Should Be $true
        (Test-Throws { Assert-Exact23CopySourceInventory @($names[0..21] + 'Auth') 'legacy_local' }) | Should Be $true
    }

    It 'accepts only unique run-owned names and independent identities' {
        (Test-Throws { Assert-Exact23CopyName 'legacy-delta-proof-abcdef123456' }) | Should Be $false
        (Test-Throws { Assert-Exact23CopyName 'legacy-maliev-exact23-postgres-data' }) | Should Be $true
        (Test-Throws { Assert-Exact23CopyName 'legacy-delta-proof-ABCDEF123456' }) | Should Be $true
        (Test-Throws { Assert-Exact23CopyIdentity ('a' * 64) ('b' * 64) }) | Should Be $false
        (Test-Throws { Assert-Exact23CopyIdentity ('a' * 64) ('a' * 64) }) | Should Be $true
    }

    It 'accepts one loopback binding only' {
        (Assert-Exact23CopyPort '127.0.0.1:5432') | Should Be 5432
        (Test-Throws { Assert-Exact23CopyPort '0.0.0.0:5432' }) | Should Be $true
        (Test-Throws { Assert-Exact23CopyPort "127.0.0.1:5432`n[::]:5432" }) | Should Be $true
    }

    It 'binds the source login to the container role without requiring postgres' {
        $source = [pscustomobject]@{ Config = [pscustomobject]@{
            Env = @('POSTGRES_USER=legacy_local', 'POSTGRES_PASSWORD=synthetic-only')
        } }
        (Test-Throws { Assert-Exact23CopySourceRole $source 'legacy_local' }) | Should Be $false
        (Test-Throws { Assert-Exact23CopySourceRole $source 'postgres' }) | Should Be $true
        $source.Config.Env += 'POSTGRES_USER=legacy_local'
        (Test-Throws { Assert-Exact23CopySourceRole $source 'legacy_local' }) | Should Be $true
    }

    It 'requires exact persistent source and run-owned target resources' {
        $name = 'legacy-delta-proof-abcdef123456'
        $run = 'abcdef123456'
        $nonce = '1' * 32
        $id = 'a' * 64
        $image = 'postgres:18@sha256:' + ('b' * 64)
        $source = [pscustomobject]@{
            Id = $id; State = [pscustomobject]@{ Running = $true }
            Mounts = @([pscustomobject]@{ Type = 'volume'; Name = 'legacy-maliev-exact23-postgres-data'
                Destination = '/var/lib/postgresql' })
        }
        (Test-Throws { Assert-Exact23CopySourceContainer $source $id }) | Should Be $false
        $source.Mounts[0].Name = $name
        (Test-Throws { Assert-Exact23CopySourceContainer $source $id }) | Should Be $true
        $labels = [pscustomobject]@{
            'maliev.exact23-copy.run-id' = $run
            'maliev.exact23-copy.name' = $name
            'maliev.exact23-copy.nonce' = $nonce
        }
        $container = [pscustomobject]@{
            Id = $id; Name = "/$name"; State = [pscustomobject]@{ Running = $true }
            Config = [pscustomobject]@{ Image = $image; Labels = $labels }
            Mounts = @([pscustomobject]@{ Type = 'volume'; Name = $name
                Destination = '/var/lib/postgresql' })
        }
        $volume = [pscustomobject]@{ Name = $name; Labels = $labels }
        (Test-Throws { Assert-Exact23CopyContainer $container $name $run $nonce $id $image }) | Should Be $false
        (Test-Throws { Assert-Exact23CopyVolume $volume $name $run $nonce }) | Should Be $false
        $container.Mounts[0].Name = 'legacy-maliev-exact23-postgres-data'
        (Test-Throws { Assert-Exact23CopyContainer $container $name $run $nonce $id $image }) | Should Be $true
        $volume.Labels.'maliev.exact23-copy.nonce' = 'different'
        (Test-Throws { Assert-Exact23CopyVolume $volume $name $run $nonce }) | Should Be $true
    }

    It 'fails closed on source churn or changed copy and counts only COPY rows' {
        (Test-Throws { Assert-Exact23CopyDigest ('a' * 64) ('a' * 64) ('a' * 64) }) | Should Be $false
        (Test-Throws { Assert-Exact23CopyDigest ('a' * 64) ('b' * 64) ('a' * 64) }) | Should Be $true
        (Test-Throws { Assert-Exact23CopyDigest ('a' * 64) ('a' * 64) ('b' * 64) }) | Should Be $true
        $dump = Join-Path $TestDrive 'synthetic.sql'
        [IO.File]::WriteAllText($dump, 'COPY public."Probe" ("ID") FROM stdin;' +
            "`n1`n2`n" + '\.' + "`n")
        (Get-Exact23CopyRowCount $dump) | Should Be 2
        [IO.File]::AppendAllText($dump, 'COPY public."Incomplete" FROM stdin;' + "`n1`n")
        (Test-Throws { Get-Exact23CopyRowCount $dump }) | Should Be $true
    }
}
