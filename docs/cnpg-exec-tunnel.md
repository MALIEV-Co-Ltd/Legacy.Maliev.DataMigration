# CNPG exec transport diagnostic

`cnpg-exec-tunnel` is a loopback-only PostgreSQL transport for the existing
`maliev-legacy/legacy-postgres-main` primary. It is not an alternate
authorization path for the exact-23 migration runner. The production template
helper admits it only for a fresh **plan-only** target observation after
matching the owner-only config, listener process, exact runner assembly,
cluster/pod identities, and SQL system identifier. It cannot sign an execution
authorization or apply rows.

`scripts/new-production-exec-tunnel-config.ps1` creates the config once in a
fresh owner-only run directory. Start the exact protected-main Release console
assembly with `cnpg-exec-tunnel --config <absolute-config-path>` and
`LEGACY_DEPLOY_ENABLED=false`; a background Windows process must be hidden.
Then pass the same path through `-ExecTunnelConfigPath` to
`scripts/new-production-delta-template.ps1`. Use absolute paths so its
process-command-line guard can bind the live listener to those exact files.
Do not reuse an older config, listener, template, or target observation.

The command accepts a protected JSON config file with `context`, `clusterUid`,
`clusterGeneration`, `primaryPod`, `primaryPodUid`, and `listenPort`. It contains
no password or connection string. Set `LEGACY_DEPLOY_ENABLED=false`. It binds
only `127.0.0.1`, rechecks context, healthy CNPG cluster, continuous archiving,
primary role and immutable UIDs for each accepted connection, and sends one raw
PostgreSQL stream over a separate `kubectl exec -i` session to pod-local
`127.0.0.1:5432`. It never prints PostgreSQL bytes or kubectl stderr. Target
drift stops the listener. The caller remains responsible for independent
credential projection and SQL-level system-identifier checks.

The 2026-09-26 read-only diagnostic completed 23/23 authenticated `SELECT 1`
connections against the canonical databases through this transport. It did
not compare rows, alter schemas, or refresh PostgreSQL data. Before using the
transport for a guarded production apply, prove disposable 23-database
planning/reconciliation, validate failure and failover behavior, and pass
protected-main CI with a fresh production-specific signed plan. Never
replace the signed plan, authorization, or reconciliation gates with this
transport test.
