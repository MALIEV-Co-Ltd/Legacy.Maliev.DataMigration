namespace Legacy.Maliev.DataMigration.Console;

// Engine compatibility is not CNPG runtime identity or persistent operation authority.
internal static class Production181EngineContract
{
    internal const string Image = "ghcr.io/cloudnative-pg/postgresql:18.1-standard-bookworm@sha256:4d7755c0460bdac6143f49e5d16ba4865aeb61368fe773adfea8696380a69b7a";
    internal const string Platform = "sha256:13fdf131bee337141a4f3b4167699ea92fb861b00e2facd50160b9610a59953a";
    internal const string Config = "sha256:22476154356554a8957dcaa4684a8307ef8897c579b1664c1769602b9b6bde2d";
    internal const string BinaryVersion = "postgres (PostgreSQL) 18.1 (Debian 18.1-1.pgdg12+2)";
    internal const string Bin = "/usr/lib/postgresql/18/bin";
    internal const string Data = "/var/lib/postgresql/18/docker";
    internal const string Purpose = "current-production181-engine-proof";
    internal const int ServerVersion = 180001;
    internal static string Name(Guid run)
    {
        return run != Guid.Empty ? "legacy-production181-proof-" + run.ToString("N") : throw CurrentCustomerSequenceRepairPermit.Invalid();
    }

    internal static IReadOnlyList<string> RequiredCases(string phase)
    {
        return phase switch
        {
            "definition" => Array.AsReadOnly(["start-1-false-1", "start-1-false-9", "start-69831-true-1", "start-69831-true-9", "start-2000000000-true-1", "start-2000000000-true-9", "start-2000000000-false-1", "start-2000000000-false-9", "reject-increment", "reject-cache", "reject-start", "reject-generated", "reject-owner"]),
            "provider" => Array.AsReadOnly(["complete", "prepared-publication", "commit-ack-lost", "terminal-publication", "final-fleet", "replay"]),
            "maintenance" => Array.AsReadOnly(["unsafe-host", "local-trust", "ordinary-all26", "exclusive-policy"]),
            _ => throw CurrentCustomerSequenceRepairPermit.Invalid()
        };
    }
}
