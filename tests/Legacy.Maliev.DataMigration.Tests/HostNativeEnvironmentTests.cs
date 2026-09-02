namespace Legacy.Maliev.DataMigration.Tests;

[CollectionDefinition("Host native environment", DisableParallelization = true)]
public sealed class HostNativeEnvironmentGroup;

[Collection("Host native environment")]
public sealed class HostNativeEnvironmentTests
{
    [Fact]
    public void NativeDump_ScrubsAmbientRoutingAuthenticationAndSessionSettings()
    {
        string[] names = ["PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE", "PGPASSFILE", "PGOPTIONS", "PGSSLNEGOTIATION", "PGSSLCERT", "PGSSLKEY", "PGSSLCRL", "PGGSSENCMODE", "PGREQUIRESSL"];
        var prior = names.ToDictionary(name => name, Environment.GetEnvironmentVariable);
        try
        {
            foreach (string name in names) { Environment.SetEnvironmentVariable(name, "untrusted"); }
            var start = PgDumpSource.BuildStartInfo("C:/tools/pg_dump.exe", "Host=localhost;Database=postgres;Username=fixture;Password=secret;SSL Mode=Disable",
                "legacy_shadow_order_0123456789abcdef0123456789abcdef");
            foreach (string name in names)
            {
                if (name == "PGGSSENCMODE") { Assert.Equal("disable", start.Environment[name]); }
                else if (name == "PGPASSFILE") { Assert.NotEqual("untrusted", start.Environment[name]); }
                else { Assert.False(start.Environment.ContainsKey(name), name); }
            }
        }
        finally { foreach (var item in prior) { Environment.SetEnvironmentVariable(item.Key, item.Value); } }
    }
}
