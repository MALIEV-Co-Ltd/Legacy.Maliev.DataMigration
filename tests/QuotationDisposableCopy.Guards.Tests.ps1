$module = Join-Path $PSScriptRoot '../scripts/QuotationDisposableCopy.Guards.psm1'
Import-Module $module -Force

function Test-Throws([scriptblock]$Action) {
    try { & $Action | Out-Null; return $false }
    catch { return $true }
}

Describe 'Quotation disposable copy guards' {
    It 'accepts only run-owned names' {
        (Test-Throws { Assert-QuotationCopyName 'legacy-quotation-proof-abcdef123456' }) | Should Be $false
        (Test-Throws { Assert-QuotationCopyName 'legacy-maliev-exact23-postgres-data' }) | Should Be $true
        (Test-Throws { Assert-QuotationCopyName 'legacy-quotation-proof-ABCDEF123456' }) | Should Be $true
    }

    It 'requires a distinct PostgreSQL cluster identity' {
        (Test-Throws { Assert-QuotationCopyIdentity ('a' * 64) ('b' * 64) }) | Should Be $false
        (Test-Throws { Assert-QuotationCopyIdentity ('a' * 64) ('a' * 64) }) | Should Be $true
        (Test-Throws { Assert-QuotationCopyIdentity 'unknown' ('b' * 64) }) | Should Be $true
    }

    It 'accepts only one loopback binding' {
        (Assert-QuotationCopyPort '127.0.0.1:5432') | Should Be 5432
        (Test-Throws { Assert-QuotationCopyPort '0.0.0.0:5432' }) | Should Be $true
        (Test-Throws { Assert-QuotationCopyPort '[::]:5432' }) | Should Be $true
        (Test-Throws { Assert-QuotationCopyPort "127.0.0.1:5432`n0.0.0.0:5432" }) | Should Be $true
    }

    It 'verifies exact labelled volume and container before cleanup' {
        $name = 'legacy-quotation-proof-abcdef123456'
        $run = 'abcdef123456'
        $nonce = '1' * 32
        $id = 'a' * 64
        $container = [pscustomobject]@{
            Id = $id; Name = "/$name"; State = [pscustomobject]@{ Running = $true }
            Config = [pscustomobject]@{ Labels = [pscustomobject]@{
                'maliev.quotation-copy.run-id' = $run
                'maliev.quotation-copy.name' = $name
                'maliev.quotation-copy.nonce' = $nonce
            } }
            Mounts = @([pscustomobject]@{ Type = 'volume'; Name = $name
                Destination = '/var/lib/postgresql' })
        }
        $volume = [pscustomobject]@{ Name = $name; Labels = $container.Config.Labels }
        (Test-Throws { Assert-QuotationCopyContainer $container $name $name $run $nonce $id }) | Should Be $false
        (Test-Throws { Assert-QuotationCopyVolume $volume $name $run $nonce }) | Should Be $false
        $container.Mounts[0].Name = 'legacy-maliev-exact23-postgres-data'
        (Test-Throws { Assert-QuotationCopyContainer $container $name $name $run $nonce $id }) | Should Be $true
        $volume.Labels.'maliev.quotation-copy.run-id' = 'different'
        (Test-Throws { Assert-QuotationCopyVolume $volume $name $run $nonce }) | Should Be $true
    }

    It 'accepts only the exact running persistent-volume source' {
        $id = 'f' * 64
        $container = [pscustomobject]@{
            Id = $id; State = [pscustomobject]@{ Running = $true }
            Mounts = @([pscustomobject]@{ Type = 'volume'
                Name = 'legacy-maliev-exact23-postgres-data' })
        }
        (Test-Throws { Assert-QuotationCopySourceContainer $container $id }) | Should Be $false
        (Test-Throws { Assert-QuotationCopySourceContainer $container ('e' * 64) }) | Should Be $true
        $container.Mounts[0].Name = 'legacy-quotation-proof-abcdef123456'
        (Test-Throws { Assert-QuotationCopySourceContainer $container $id }) | Should Be $true
    }
}
