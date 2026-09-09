using System.Reflection;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SqlServerAdapterAssemblyDependencyTests
{
    [Fact]
    public void Adapter_owns_SQL_Client_and_implements_the_provider_neutral_factory()
    {
        Assembly adapter = typeof(SqlServerMigrationSource).Assembly;

        Assert.NotEqual(typeof(DeltaSynchronizationPlan).Assembly, adapter);
        Assert.Contains(adapter.GetReferencedAssemblies(), reference => reference.Name == "Microsoft.Data.SqlClient");
        _ = Assert.IsType<IMigrationSourceFactory>(new SqlServerMigrationSourceFactory(), exactMatch: false);
        _ = Assert.IsType<IRestoredMigrationSourceObserver>(
            new DockerSqlRestoredSourceObserver(new ReceiptAttestationTrustStore([])), exactMatch: false);
    }
}
