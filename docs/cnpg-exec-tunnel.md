# CNPG exec transport diagnostic

`cnpg-exec-tunnel` is a loopback-only PostgreSQL transport diagnostic for the
existing `maliev-legacy/legacy-postgres-main` primary. It is not an alternate
authorization path for the exact-23 migration runner. The production template
helper still requires its reviewed `kubectl port-forward` transport; this
diagnostic cannot publish a target connection, sign a delta, or apply rows.

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
transport for guarded migration, add exact-identity admission to the protected
production template, prove disposable 23-database planning/reconciliation,
validate failure and failover behavior, and pass protected-main CI. Never
replace the signed plan, authorization, or reconciliation gates with this
transport test.
