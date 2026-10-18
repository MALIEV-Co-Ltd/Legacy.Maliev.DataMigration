using Docker.DotNet.Models;

namespace Legacy.Maliev.DataMigration.Console;

// Pure SDK parameter adapter. It creates no container, volume or permission.
// Production181OwnedHarness performs actual bounded creation, exact inventories and finally cleanup.
// This parameter builder itself grants no authority and performs no SDK call.
internal static class Production181DisposablePlans
{
    internal static CreateContainerParameters Initializer(Guid run, string bindingSha256)
    {
        var plan = Base(run, bindingSha256);
        plan.Name += "-initialize"; plan.User = "0:0";
        plan.Entrypoint = ["bash", "-ceu"];
        plan.Cmd = ["set -euo pipefail; umask 077; test ! -e /var/lib/postgresql/18; install -d -m 0700 -o 26 -g 102 /var/lib/postgresql/18; test ! -e /var/lib/postgresql/18/docker; stat -c '%u:%g:%a' /var/lib/postgresql/18 | grep -Fx '26:102:700'"];
        // No PostgreSQL, credentials, port or arbitrary command in this initializer.
        return plan;
    }
    internal static CreateContainerParameters Database(Guid run, string bindingSha256)
    {
        var plan = Base(run, bindingSha256); plan.User = "26:102";
        plan.Entrypoint = ["bash", "-ceu"];
        plan.Cmd = [Bootstrap];
        plan.ExposedPorts = new Dictionary<string, EmptyStruct> { ["5432/tcp"] = default };
        var host = plan.HostConfig ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        host.PortBindings = new Dictionary<string, IList<PortBinding>> { ["5432/tcp"] = [new() { HostIP = "127.0.0.1", HostPort = "" }] };
        return plan;
    }
    internal static CreateContainerParameters Checksum(Guid run, string bindingSha256)
    {
        var plan = Base(run, bindingSha256); plan.Name += "-checksum"; plan.User = "26:102"; plan.StopSignal = "SIGINT";
        plan.Entrypoint = ["bash", "-ceu"]; plan.Cmd = ["export LC_ALL=C; exec /usr/lib/postgresql/18/bin/pg_checksums --check --pgdata=/var/lib/postgresql/18/docker"];
        return plan;
    }
    private static CreateContainerParameters Base(Guid run, string bindingSha256)
    {
        if (!CurrentCustomerSequenceRepairPermit.HashShape(bindingSha256)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        string name = Production181EngineContract.Name(run);
        return new()
        {
            Image = Production181EngineContract.Image,
            Name = name,
            StopSignal = "SIGINT",
            Labels = new Dictionary<string, string>
            {
                ["codex.repair.purpose"] = Production181EngineContract.Purpose,
                ["codex.repair.operation"] = run.ToString("D"),
                ["codex.repair.run"] = run.ToString("D"),
                ["codex.repair.run-binding"] = bindingSha256
            },
            HostConfig = new()
            {
                Memory = 512L * 1024 * 1024,
                MemorySwap = 512L * 1024 * 1024,
                NanoCPUs = 750000000,
                Mounts = [new Mount { Type = "volume", Source = name, Target = "/var/lib/postgresql", ReadOnly = false, VolumeOptions = new VolumeOptions { NoCopy = true } }],
                AutoRemove = false,
                RestartPolicy = new RestartPolicy { Name = RestartPolicyKind.No }
            }
        };
    }
    internal const string Bootstrap = """
        set -euo pipefail
        umask 077
        readonly pgdata=/var/lib/postgresql/18/docker
        readonly bindir=/usr/lib/postgresql/18/bin
        [ "$(id -u)" = 26 ] && [ "$(id -g)" = 102 ]
        [ "$(stat -c '%u:%g:%a' /var/lib/postgresql/18)" = '26:102:700' ]
        [ ! -e "$pgdata" ]
        [ "$("$bindir/postgres" --version)" = 'postgres (PostgreSQL) 18.1 (Debian 18.1-1.pgdg12+2)' ]
        "$bindir/initdb" --pgdata="$pgdata" --username=postgres --encoding=UTF8 --locale=C --data-checksums --auth-local=trust --auth-host=trust --no-instructions
        exec "$bindir/postgres" -D "$pgdata" -c autovacuum=off -c port=5432 -c listen_addresses='*' -c unix_socket_directories=/var/lib/postgresql/18
        """;
}
