$helper = Join-Path $PSScriptRoot '../scripts/new-exact23-disposable-copy.ps1'
$guards = Join-Path $PSScriptRoot '../scripts/Exact23DisposableCopy.Guards.psm1'
Import-Module $guards -Force

if ($IsWindows) {
    Describe 'Exact-23 disposable copy on synthetic PostgreSQL 18' {
        It 'copies all 23 databases into a distinct run-owned target and cleans only that target' {
            $runId = [Guid]::NewGuid().ToString('N').Substring(0, 12)
            $sourceName = "legacy-delta-synthetic-source-$runId"
            $targetName = "legacy-delta-proof-$runId"
            $root = Join-Path $env:TEMP "legacy-delta-copy-test-$runId"
            $null = New-Item -ItemType Directory -Path $root
            $acl = Get-Acl -LiteralPath $root
            $acl.SetAccessRuleProtection($true, $false)
            $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($owner,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow)
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $root -AclObject $acl
            $environmentPath = Join-Path $root 'synthetic-source.env'
            $connectionPath = Join-Path $root 'synthetic-source.connection'
            $password = 'synthetic-only-' + $runId
            [IO.File]::WriteAllText($environmentPath, "POSTGRES_USER=postgres`nPOSTGRES_PASSWORD=$password`n")
            $imageDigest = @(docker image inspect postgres:18 --format '{{json .RepoDigests}}' |
                ConvertFrom-Json)[0]
            $image = 'postgres:18@sha256:' + ($imageDigest -split '@sha256:')[1]
            $sourceId = $null
            $targetCompleted = $false
            $previousPassword = $env:PGPASSWORD
            $previousDeploy = $env:LEGACY_DEPLOY_ENABLED
            $previousCaller = $env:LEGACY_MIGRATION_CALLER
            $previousSynthetic = $env:LEGACY_MIGRATION_SYNTHETIC_TEST_ONLY
            try {
                & docker volume create --name $sourceName 1>$null 2>$null
                if ($LASTEXITCODE -ne 0) { throw 'synthetic_source_volume_failed' }
                $sourceId = (& docker run -d --name $sourceName `
                    --label 'maliev.exact23-copy.synthetic-source=true' `
                    --mount "type=volume,source=$sourceName,target=/var/lib/postgresql" `
                    --publish '127.0.0.1::5432' --env-file $environmentPath $image 2>$null | Out-String).Trim()
                if ($LASTEXITCODE -ne 0 -or $sourceId -cnotmatch '^[0-9a-f]{64}$') {
                    throw 'synthetic_source_container_failed'
                }
                $binding = ((docker port $sourceId 5432/tcp) | Out-String).Trim()
                $port = Assert-Exact23CopyPort $binding
                $env:PGPASSWORD = $password
                $ready = $false
                for ($attempt = 0; $attempt -lt 30; $attempt++) {
                    & 'C:\Program Files\PostgreSQL\18\bin\pg_isready.exe' -h 127.0.0.1 -p $port `
                        -U postgres -d postgres 1>$null 2>$null
                    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
                    Start-Sleep -Seconds 1
                }
                if (-not $ready) { throw 'synthetic_source_not_ready' }
                foreach ($database in Get-Exact23CopyDatabases) {
                    & 'C:\Program Files\PostgreSQL\18\bin\psql.exe' -X -w -h 127.0.0.1 -p $port `
                        -U postgres -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE `"$database`";" 1>$null 2>$null
                    if ($LASTEXITCODE -ne 0) { throw 'synthetic_database_create_failed' }
                }
                & 'C:\Program Files\PostgreSQL\18\bin\psql.exe' -X -w -h 127.0.0.1 -p $port `
                    -U postgres -d Country -v ON_ERROR_STOP=1 -c `
                    'CREATE TABLE public."Probe" ("ID" integer PRIMARY KEY, "Value" text); INSERT INTO public."Probe" VALUES (1, ''synthetic-only'');' `
                    1>$null 2>$null
                if ($LASTEXITCODE -ne 0) { throw 'synthetic_row_create_failed' }
                [IO.File]::WriteAllText($connectionPath,
                    "Host=127.0.0.1;Port=$port;Username=postgres;Password=$password;Database=postgres;Pooling=False")
                $systemId = (& 'C:\Program Files\PostgreSQL\18\bin\psql.exe' -X -w `
                    -h 127.0.0.1 -p $port -U postgres -d postgres -Atc `
                    'SELECT system_identifier::text FROM pg_control_system();').Trim()
                $systemHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
                    [Text.Encoding]::UTF8.GetBytes($systemId))).ToLowerInvariant()
                $env:LEGACY_DEPLOY_ENABLED = 'false'
                $env:LEGACY_MIGRATION_CALLER = 'owner'
                $env:LEGACY_MIGRATION_SYNTHETIC_TEST_ONLY = 'true'
                & $helper -Action Create -RunDirectory $root -Name $targetName `
                    -SourceContainerId $sourceId -ExpectedSourceSystemIdentifierSha256 $systemHash `
                    -SourceConnectionFile $connectionPath -ImageReference $image `
                    -SyntheticSourceVolumeName $sourceName | Out-Null
                $receipt = Get-Content -LiteralPath (Join-Path $root 'exact23-copy-receipt.json') -Raw |
                    ConvertFrom-Json
                $receipt.state | Should Be 'copy-complete'
                $receipt.syntheticOnly | Should Be $true
                @($receipt.databases).Count | Should Be 23
                $receipt.systemIdentifierSha256 | Should Not Be $receipt.sourceSystemIdentifierSha256
                (@($receipt.databases | Where-Object { $_.database -eq 'Country' })[0].copyRowCount) | Should Be 1
                & $helper -Action Cleanup -RunDirectory $root -Name $targetName | Out-Null
                $targetCompleted = $true
                @((docker volume ls --filter "name=$targetName" --format '{{.Name}}') |
                    Where-Object { $_ -ceq $targetName }).Count | Should Be 0
                @(docker inspect $sourceId 2>$null).Count | Should BeGreaterThan 0
            }
            finally {
                if ($null -eq $previousPassword) { Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue }
                else { $env:PGPASSWORD = $previousPassword }
                if ($null -eq $previousDeploy) { Remove-Item Env:LEGACY_DEPLOY_ENABLED -ErrorAction SilentlyContinue }
                else { $env:LEGACY_DEPLOY_ENABLED = $previousDeploy }
                if ($null -eq $previousCaller) { Remove-Item Env:LEGACY_MIGRATION_CALLER -ErrorAction SilentlyContinue }
                else { $env:LEGACY_MIGRATION_CALLER = $previousCaller }
                if ($null -eq $previousSynthetic) { Remove-Item Env:LEGACY_MIGRATION_SYNTHETIC_TEST_ONLY -ErrorAction SilentlyContinue }
                else { $env:LEGACY_MIGRATION_SYNTHETIC_TEST_ONLY = $previousSynthetic }
                if ($sourceId -cmatch '^[0-9a-f]{64}$') {
                    $observed = @(docker inspect $sourceId 2>$null | ConvertFrom-Json)
                    if ($observed.Count -eq 1) {
                        Assert-Exact23CopySyntheticSourceContainer $observed[0] $sourceId $sourceName
                        & docker rm -f -- $sourceId 1>$null 2>$null
                    }
                }
                if ($targetCompleted) {
                    & docker volume rm -- $sourceName 1>$null 2>$null
                    if ($root.StartsWith([IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\',
                        [StringComparison]::OrdinalIgnoreCase)) {
                        Remove-Item -LiteralPath $root -Recurse -Force
                    }
                }
            }
        }
    }
}
