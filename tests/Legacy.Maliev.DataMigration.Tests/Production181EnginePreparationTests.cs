using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Production181EnginePreparationTests
{
    [Fact]
    public void Fixed_digests_and_server_version_do_not_accept_official_local_eighteen_four()
    {
        Assert.Equal(180001, Production181EngineContract.ServerVersion);
        Assert.StartsWith("ghcr.io/cloudnative-pg/postgresql:18.1-standard-bookworm@sha256:", Production181EngineContract.Image);
        Assert.NotEqual("postgres:18.4-bookworm", Production181EngineContract.Image);
        Assert.Equal(13, Production181EngineContract.RequiredCases("definition").Count);
        Assert.Equal(6, Production181EngineContract.RequiredCases("provider").Count);
        Assert.Equal(4, Production181EngineContract.RequiredCases("maintenance").Count);
    }
    [Theory]
    [InlineData("production")]
    [InlineData("closed-console")]
    [InlineData("native")]
    public void No_alias_turns_raw_engine_cases_into_operational_acceptance(string phase)
    { _ = Assert.Throws<MigrationExecutionException>(() => Production181EngineContract.RequiredCases(phase)); }
    [Fact]
    public void Exact_owned_initialization_is_separate_from_database_and_has_no_port()
    {
        Guid run = Guid.NewGuid(); string binding = new('a', 64);
        var init = Production181DisposablePlans.Initializer(run, binding); var database = Production181DisposablePlans.Database(run, binding);
        Assert.Equal(Production181EngineContract.Name(run) + "-initialize", init.Name); Assert.Equal("0:0", init.User);
        var initHost = init.HostConfig ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        var databaseHost = database.HostConfig ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        var mounts = databaseHost.Mounts ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        var ports = databaseHost.PortBindings ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        Assert.Null(initHost.PortBindings); Assert.Null(init.ExposedPorts);
        Assert.Equal("26:102", database.User); _ = Assert.Single(mounts);
        Assert.Equal(Production181EngineContract.Name(run), mounts[0].Source);
        Assert.Equal(512L * 1024 * 1024, databaseHost.Memory); Assert.Equal(750000000, databaseHost.NanoCPUs);
        Assert.Equal("127.0.0.1", ports["5432/tcp"].Single().HostIP);
        Assert.Contains("--data-checksums", Production181DisposablePlans.Bootstrap);
        Assert.DoesNotContain("POSTGRES_PASSWORD", Production181DisposablePlans.Bootstrap);
    }
    [Fact]
    public void Empty_run_or_non_digest_binding_fails_before_resource_parameters()
    {
        _ = Assert.Throws<MigrationExecutionException>(() => Production181DisposablePlans.Database(Guid.Empty, new('a', 64)));
        _ = Assert.Throws<MigrationExecutionException>(() => Production181DisposablePlans.Database(Guid.NewGuid(), "marker"));
    }
}
